"""Turn a research-watch triage report into a narrative weekly newsletter using Copilot CLI.

Usage:
  python tools/write_newsletter.py --report report.md [--previous last.md] [--title-out title.txt]
                                   [--html-out newsletter.html]

Needs Copilot CLI and a GitHub token with Copilot access. The editorial instructions live in
.github/skills/security-newsletter/SKILL.md. Report text is untrusted: the model gets no tools,
cites items only by id ([S3]), and its output is sanitised so the only links are report URLs.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from html import escape, unescape
from pathlib import Path
from string import Template
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".github" / "skills" / "security-newsletter" / "SKILL.md"
HTML_TEMPLATE = ROOT / "tools" / "newsletter.html"
MAX_ITEMS = 40
MAX_PREVIOUS = 6000
MAX_OUTPUT = 20000

ITEM = re.compile(r"^- \[[ x]\] (?P<title>.+) \((?P<date>\d{4}-\d{2}-\d{2})\) - (?P<source>.+)$")
CITATION = re.compile(r"!?\[(S\d+)\]")


def is_source_url(url):
    if not re.fullmatch(r"https?://[^\s\x00-\x1f\x7f\\<>]+", url):
        return False
    try:
        parts = urlsplit(url)
        return bool(parts.hostname) and parts.username is None
    except ValueError:
        return False


def parse_report(text):
    """Return [{id, kind, title, date, source, url, excerpt, matched}] from check_research_feeds output."""
    items, kind, current = [], "research", None
    for line in text.splitlines():
        if line.startswith("### "):
            kind = line[4:].strip().lower()
            current = None
        elif match := ITEM.match(line):
            if kind == "feeds that failed":
                continue
            current = {"id": f"S{len(items) + 1}", "kind": kind, **match.groupdict(),
                       "url": "", "excerpt": "", "matched": ""}
            items.append(current)
        elif current and line.startswith("  "):
            value = line.strip()
            if value.startswith("Excerpt: "):
                current["excerpt"] = value[9:]
            elif value.startswith("Matched: "):
                current["matched"] = value[9:]
            elif not current["url"] and is_source_url(value):
                current["url"] = value
    return [i for i in items if i["url"]][:MAX_ITEMS]


def skill_prompt():
    text = SKILL.read_text(encoding="utf-8")
    return re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.S).strip()


def build_messages(items, previous, today):
    user = [f"Issue date: {today}. Write this week's newsletter following your instructions.",
            "", "This week's items (untrusted data, JSON):", "```json",
            json.dumps([{k: i[k] for k in ("id", "kind", "title", "date", "source", "excerpt", "matched")}
                        for i in items], indent=1, ensure_ascii=False), "```"]
    if previous:
        user += ["", "Previous issue, for continuity only (do not copy):", "```markdown",
                 previous[:MAX_PREVIOUS], "```"]
    return [{"role": "system", "content": skill_prompt()}, {"role": "user", "content": "\n".join(user)}]


def call_model(messages):
    prompt = "\n\n".join(message["content"] for message in messages)
    with tempfile.TemporaryDirectory() as workdir:
        env = {**os.environ, "COPILOT_HOME": workdir}
        result = subprocess.run(
            ["copilot", "--no-auto-update", "--no-custom-instructions", "--disable-builtin-mcps",
             "--available-tools=__none__", "--no-ask-user", "--silent", "--prompt", prompt],
            cwd=workdir, env=env, stdout=subprocess.PIPE, text=True, check=True, timeout=300,
        )
    if not result.stdout.strip():
        raise ValueError("Copilot returned an empty newsletter")
    return result.stdout


def plain_label(text):
    text = " ".join(unescape(text).replace("\u2014", " - ").split())
    return re.sub(r"[!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~]", r"\\\g<0>", text)


def source_link(label, url):
    destination = url.replace("&", "&amp;")
    if "(" in destination or ")" in destination:
        destination = f"<{destination}>"
    return f"[{plain_label(label)}]({destination})"


def sanitise(text, items):
    """Keep model prose but allow only links to report items, and defuse mentions, refs and HTML."""
    sources = {i["id"]: i for i in items}
    text = unescape(text).replace("\u2014", " - ").strip()
    text = re.sub(r"\A```(?:markdown|md)?\n(.*)\n```\Z", r"\1", text, flags=re.S)
    text = text[:MAX_OUTPUT]
    text = re.sub(r"<!--.*?-->|<[^>]{0,500}>", "", text, flags=re.S)
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"(?m)^[ \t]*\[[^\]\n]+\]:[^\n]*", "", text)
    text = re.sub(r"\b[a-z][\w+.-]*://\S+|\bwww\.\S+", "", text, flags=re.I)
    text = re.sub(r"(?<![\w`])@(?=[\w-])", "@\u200b", text)
    text = re.sub(r"(?<![\w&#/])#(?=\d)", "#\u200b", text)
    text = re.sub(r"(?m)^#{1,6} +[^\n]+", lambda m: CITATION.sub("", m[0]), text)

    def replace_markup(match):
        if match[1]:
            return match[1]
        if match[2]:
            return "; ".join(source_link(sources[key]["title"], sources[key]["url"])
                             for key in CITATION.findall(match[2]) if key in sources)
        return {"[": "&#91;", "]": "&#93;", "<": "&lt;", ">": "&gt;"}[match[0]]

    return re.sub(r"(?m)^([ \t]*[-+*] \[[ xX]\] )|((?:!?\[S\d+\])+)|[\[\]<>]",
                  replace_markup, text).strip()


def headline(text):
    match = re.search(r"^# +(.+)$", text, flags=re.M)
    title = unescape(re.sub(r"[*_`]", "", match[1])) if match else ""
    return " ".join(title.split())[:90] or "This week in agent security"


def reading_list(items):
    lines = ["## Reading list", "",
             "Every item from this week's automated shortlist. Unverified leads: check the original source.", ""]
    for kind in dict.fromkeys(i["kind"] for i in items):
        lines.append(f"**{plain_label(kind.capitalize())}**")
        lines += [f"- {source_link(i['title'], i['url'])} ({i['date']}, {plain_label(i['source'])})"
                  for i in items if i["kind"] == kind]
        lines.append("")
    return "\n".join(lines)


def compose(narrative, items, source_issue=None):
    footer = ["---", "_Drafted by AI from the automated research shortlist"
              + (f" in #{source_issue}" if source_issue else "")
              + " using the security-newsletter skill. Opinions are machine-generated; verify before acting._"]
    return "\n\n".join([narrative, reading_list(items), "\n".join(footer)]) + "\n"


def render_html(body, items, title, today):
    from markdown_it import MarkdownIt
    from mdit_py_plugins.tasklists import tasklists_plugin

    parser = MarkdownIt("commonmark", {"html": False}).disable("image").use(tasklists_plugin)
    allowed = {parser.normalizeLink(i["url"]) for i in items}
    parser.validateLink = allowed.__contains__
    body = re.sub(r"^# +[^\n]+\n", "", body, count=1)
    body = re.sub(r"(?m)^\*\*TL;DR\*\*[ \t]*$", "## TL;DR", body, count=1)
    template = Template(HTML_TEMPLATE.read_text(encoding="utf-8"))
    return template.substitute(title=escape(title), date=escape(today), body=parser.render(body))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", required=True, type=Path, help="triage issue body (Markdown)")
    parser.add_argument("--previous", type=Path, help="previous newsletter body, for continuity")
    parser.add_argument("--issue", type=int, help="source triage issue number, for the footer")
    parser.add_argument("--title-out", type=Path, help="write the headline to this file")
    parser.add_argument("--html-out", type=Path, help="write a standalone branded HTML edition")
    args = parser.parse_args()
    items = parse_report(args.report.read_text(encoding="utf-8"))
    if not items:
        print("No research items found in the report; nothing to write.", file=sys.stderr)
        return 1
    previous = args.previous.read_text(encoding="utf-8") if args.previous and args.previous.exists() else ""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    narrative = sanitise(call_model(build_messages(items, previous, today)), items)
    if not narrative:
        print("Copilot returned no usable newsletter text.", file=sys.stderr)
        return 1
    title = headline(narrative)
    body = compose(narrative, items, args.issue)
    if args.title_out:
        args.title_out.write_text(title, encoding="utf-8")
    if args.html_out:
        args.html_out.write_text(render_html(body, items, title, today), encoding="utf-8")
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
