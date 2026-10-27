"""Find new agent-security articles that are not yet in SOURCES.md.

Usage:
  python tools/check_research_feeds.py                  # check the feeds in tools/research_feeds.json
  python tools/check_research_feeds.py --days 30        # widen the look-back window

Exit code 0 means nothing new, 1 means a Markdown triage report was printed, 2 means every feed failed.
Feed text is untrusted: titles are reduced to plain text and links are limited to http(s) URLs, so the
report is safe to post as a GitHub issue. Do not hand the report to an agent that has tool access.
"""
import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tools" / "research_feeds.json"
MAX_BYTES = 5 * 1024 * 1024
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATOM = "{http://www.w3.org/2005/Atom}"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "SkillVenom-research-watch"})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response too large")
    return data


def parse_date(value):
    if not value:
        return None
    value = value.strip()
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def plain(text, limit=200):
    text = re.sub(r"<[^>]*>", " ", text or "")
    text = re.sub(r"\b[a-z][\w+.-]*://[^\s)\]>]+|\bwww\.[^\s)\]>]+", "link", text, flags=re.I)
    text = re.sub(r"[\[\]`*_<>|#@\\]", " ", text)
    text = " ".join(text.split())
    return text[:limit] + ("…" if len(text) > limit else "")


def safe_url(url):
    url = (url or "").strip()
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc or any(c in url for c in " <>()[]\"'`"):
        return ""
    return url


def parse_feed(data):
    """Return [{title, url, date, summary}] for RSS 2.0 or Atom bytes."""
    if b"<!ENTITY" in data:
        raise ValueError("feed declares XML entities")
    root = ET.fromstring(data)
    items = []
    for entry in root.iter(f"{ATOM}entry"):
        link = next((l.get("href") for l in entry.findall(f"{ATOM}link") if l.get("rel", "alternate") == "alternate"), None)
        items.append({
            "title": entry.findtext(f"{ATOM}title", ""),
            "url": link or entry.findtext(f"{ATOM}id", ""),
            "date": parse_date(entry.findtext(f"{ATOM}published") or entry.findtext(f"{ATOM}updated")),
            "summary": entry.findtext(f"{ATOM}summary", "") or entry.findtext(f"{ATOM}content", ""),
        })
    for entry in root.iter("item"):
        items.append({
            "title": entry.findtext("title", ""),
            "url": entry.findtext("link", ""),
            "date": parse_date(entry.findtext("pubDate")),
            "summary": entry.findtext("description", ""),
        })
    return items


def nvd_items(keywords, since, now):
    items = []
    for index, keyword in enumerate(keywords):
        if index:
            time.sleep(6.5)  # NVD allows 5 unauthenticated requests per 30 seconds
        query = urllib.parse.urlencode({
            "keywordSearch": keyword, "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"), "resultsPerPage": 50,
        })
        for vuln in json.loads(fetch(f"{NVD}?{query}")).get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            summary = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            items.append({
                "title": f"{cve.get('id', '')}: {summary}", "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                "date": parse_date(cve.get("published")), "summary": summary,
            })
    return items


def known_sources():
    text = (ROOT / "SOURCES.md").read_text(encoding="utf-8")
    urls = {normalise(u) for u in re.findall(r"https?://[^\s|)]+", text)}
    titles = {" ".join(row.split("|")[2].lower().split()) for row in text.splitlines() if re.match(r"\|\s*\d+\s*\|", row)}
    return urls, titles


def normalise(url):
    parts = urllib.parse.urlsplit(url.strip())
    return (parts.netloc.lower().removeprefix("www.") + parts.path.rstrip("/")).lower()


def matches(item, config, security):
    text = f"{item['title']} {item['summary']}".lower()
    subjects = sorted({t for t in config["subject_terms"] if re.search(rf"(?<![\w.-]){re.escape(t)}(?![\w-])", text)})
    risks = sorted({t for t in config["risk_terms"] if t in text})
    if subjects and (security or risks):
        return subjects + risks
    return []


def collect(config, now, fetcher=fetch, nvd=nvd_items):
    since = now - timedelta(days=config["lookback_days"])
    urls, titles = known_sources()
    found, errors, seen = [], [], set()
    for feed in config["feeds"]:
        try:
            items = nvd(feed["keywords"], since, now) if feed["type"] == "nvd" else parse_feed(fetcher(feed["url"]))
        except Exception as error:  # one broken feed must not hide the others
            errors.append(f"{feed['name']}: {type(error).__name__}")
            continue
        for item in items:
            url = safe_url(item["url"])
            title = plain(item["title"])
            key = normalise(url) if url else title.lower()
            if not url or not title or key in seen or (item["date"] and item["date"] < since):
                continue
            if normalise(url) in urls or " ".join(title.lower().split()) in titles:
                continue
            terms = matches(item, config, feed.get("security", False))
            if terms:
                seen.add(key)
                found.append({"feed": feed["name"], "title": title, "url": url, "date": item["date"], "terms": terms})
    return found, errors


def report(found, errors, config):
    lines = [f"## Agent-security research to triage (last {config['lookback_days']} days)", "",
             "Titles come from external feeds and are untrusted. Review each item; add relevant ones to SOURCES.md,",
             "turn new attack patterns into test samples, then into rules (see README: Keeping detection current).", ""]
    for feed in dict.fromkeys(item["feed"] for item in found):
        lines.append(f"### {feed}")
        for item in sorted((i for i in found if i["feed"] == feed), key=lambda i: i["date"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True):
            date = item["date"].strftime("%Y-%m-%d") if item["date"] else "undated"
            lines.append(f"- [ ] {item['title']} ({date}), {item['url']}, matched: {', '.join(item['terms'][:6])}")
        lines.append("")
    if errors:
        lines += ["### Feeds that failed", *[f"- {e}" for e in errors], ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--days", type=int, help="override lookback_days")
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    if args.days:
        config["lookback_days"] = args.days
    found, errors = collect(config, datetime.now(timezone.utc))
    if len(errors) == len(config["feeds"]):
        print("Every research feed failed:\n" + "\n".join(errors), file=sys.stderr)
        return 2
    if not found:
        print("No new agent-security research found." + (f" Failed feeds: {'; '.join(errors)}" if errors else ""))
        return 0
    print(report(found, errors, config))
    return 1


if __name__ == "__main__":
    sys.exit(main())
