"""Turn a research-watch triage report into a narrative weekly newsletter using Copilot CLI.

Usage:
  python tools/write_newsletter.py --report report.md [--previous last.md] [--title-out title.txt]

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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".github" / "skills" / "security-newsletter" / "SKILL.md"
MAX_ITEMS = 40
MAX_PREVIOUS = 6000
MAX_OUTPUT = 20000

ITEM = re.compile(r"^- \[[ x]\] (?P<title>.+) \((?P<date>\d{4}-\d{2}-\d{2})\) - (?P<source>.+)$")


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
            elif re.match(r"https?://\S+$", value) and not current["url"]:
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


def sanitise(text, items):
    """Keep model prose but allow only links to report items, and defuse mentions, refs and HTML."""
    urls = {i["id"]: i["url"] for i in items}
    text = text.strip()
    text = re.sub(r"\A```(?:markdown|md)?\n(.*)\n```\Z", r"\1", text, flags=re.S)
    text = re.sub(r"<!--.*?-->|<[^>]{0,500}>", "", text, flags=re.S)
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\b[a-z][\w+.-]*://\S+|\bwww\.\S+", "", text, flags=re.I)
    text = re.sub(r"(?<![\w`])@(?=[\w-])", "@\u200b", text)
    text = re.sub(r"(?<![\w&#/])#(?=\d)", "#\u200b", text)
    text = re.sub(r"\[(S\d+)\](?!\()", lambda m: f"[{m[1]}]({urls[m[1]]})" if m[1] in urls else "", text)
    return text[:MAX_OUTPUT].strip()


def headline(text):
    match = re.search(r"^# +(.+)$", text, flags=re.M)
    title = re.sub(r"\[(S\d+)\]\([^)]*\)|[*_`\[\]]", "", match[1] if match else "").strip()
    return " ".join(title.split())[:90] or "This week in agent security"


def reading_list(items):
    lines = ["## Reading list", "",
             "Every item from this week's automated shortlist. Unverified leads: check the original source.", ""]
    for kind in dict.fromkeys(i["kind"] for i in items):
        lines.append(f"**{kind.capitalize()}**")
        lines += [f"- [{i['id']}]({i['url']}) {i['title']} ({i['date']}, {i['source']})"
                  for i in items if i["kind"] == kind]
        lines.append("")
    return "\n".join(lines)


def compose(narrative, items, source_issue=None):
    footer = ["---", "_Drafted by AI from the automated research shortlist"
              + (f" in #{source_issue}" if source_issue else "")
              + " using the security-newsletter skill. Opinions are machine-generated; verify before acting._"]
    return "\n\n".join([narrative, reading_list(items), "\n".join(footer)]) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", required=True, type=Path, help="triage issue body (Markdown)")
    parser.add_argument("--previous", type=Path, help="previous newsletter body, for continuity")
    parser.add_argument("--issue", type=int, help="source triage issue number, for the footer")
    parser.add_argument("--title-out", type=Path, help="write the headline to this file")
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
    if args.title_out:
        args.title_out.write_text(headline(narrative), encoding="utf-8")
    print(compose(narrative, items, args.issue))
    return 0


if __name__ == "__main__":
    sys.exit(main())
