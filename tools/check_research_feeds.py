"""Find recent AI-security research that is not yet in SOURCES.md.

Usage:
  python tools/check_research_feeds.py                  # check the feeds in tools/research_feeds.json
  python tools/check_research_feeds.py --days 30        # widen the look-back window

Exit code 0 means nothing new, 1 means a Markdown shortlist was printed, 2 means every feed failed.
Feed text is untrusted: titles are reduced to plain text and links are limited to http(s) URLs, so the
report is safe to post as a GitHub issue. Do not hand the report to an agent that has tool access (tools/write_newsletter.py uses a tool-less model).
"""
import argparse
import gzip
import html
import io
import json
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tools" / "research_feeds.json"
MAX_BYTES = 5 * 1024 * 1024
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATOM = "{http://www.w3.org/2005/Atom}"
DC = "{http://purl.org/dc/elements/1.1/}"
CONTENT = "{http://purl.org/rss/1.0/modules/content/}"
SOURCE_ORDER = ("independent", "research", "advisory", "news", "discovery")


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "SkillVenom-research-watch"})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(MAX_BYTES + 1)
        encoding = response.headers.get("Content-Encoding", "").lower()
    if len(data) > MAX_BYTES:
        raise ValueError("response too large")
    if encoding == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as decoded:
            data = decoded.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("decompressed response too large")
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
    text = re.sub(r"<[^>]*>", " ", html.unescape(text or ""))
    text = re.sub(r"\b[a-z][\w+.-]*://[^\s)\]>]+|\bwww\.[^\s)\]>]+", "link", text, flags=re.I)
    text = re.sub(r"[\[\]`*_<>|#@\\]", " ", text)
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")


def safe_url(url):
    url = (url or "").strip()
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    if (parts.scheme not in ("http", "https") or not parts.netloc or parts.username or parts.password
            or any(c.isspace() or ord(c) < 32 or c in "<>()[]\"'`\\" for c in url)):
        return ""
    return url


def parse_feed(data):
    """Return [{title, url, date, summary}] for RSS 2.0 or Atom bytes."""
    if b"<!ENTITY" in data:
        raise ValueError("feed declares XML entities")
    root = ET.fromstring(data)
    if root.tag not in ("rss", f"{ATOM}feed"):
        raise ValueError("not an RSS or Atom feed")
    items = []
    for entry in root.iter(f"{ATOM}entry"):
        link = next((l.get("href") for l in entry.findall(f"{ATOM}link") if l.get("rel", "alternate") == "alternate"), None)
        items.append({
            "title": entry.findtext(f"{ATOM}title", ""),
            "url": link or entry.findtext(f"{ATOM}id", ""),
            "date": parse_date(entry.findtext(f"{ATOM}published") or entry.findtext(f"{ATOM}updated")),
            "summary": "".join(e.itertext()) if (e := entry.find(f"{ATOM}summary")) is not None else
                       "".join(e.itertext()) if (e := entry.find(f"{ATOM}content")) is not None else "",
        })
    for entry in root.iter("item"):
        items.append({
            "title": entry.findtext("title", ""),
            "url": entry.findtext("link", ""),
            "date": parse_date(entry.findtext("pubDate") or entry.findtext(f"{DC}date")),
            "summary": entry.findtext("description", "") or entry.findtext(f"{CONTENT}encoded", ""),
        })
    return items


def nvd_items(keywords, since, now):
    items = []
    requested = False
    for keyword in keywords:
        start = 0
        while True:
            if requested:
                time.sleep(6.5)  # NVD allows 5 unauthenticated requests per 30 seconds
            requested = True
            query = urllib.parse.urlencode({
                "keywordSearch": keyword, "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"), "resultsPerPage": 2000, "startIndex": start,
            })
            data = json.loads(fetch(f"{NVD}?{query}"))
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                summary = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                items.append({
                    "title": f"{cve.get('id', '')}: {summary}", "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                    "date": parse_date(cve.get("published")), "summary": summary,
                })
            start += len(vulnerabilities)
            if start >= data.get("totalResults", 0):
                break
            if not vulnerabilities:
                raise ValueError("NVD pagination returned an empty page before totalResults")
    return items


def known_sources():
    text = (ROOT / "SOURCES.md").read_text(encoding="utf-8")
    urls = {normalise(u) for u in re.findall(r"https?://[^\s|)]+", text)}
    titles = {plain(row.split("|")[2]).lower() for row in text.splitlines() if re.match(r"\|\s*\d+\s*\|", row)}
    return urls, titles


def normalise(url):
    parts = urllib.parse.urlsplit(url.strip())
    query = urllib.parse.urlencode(sorted(
        (k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith("utm_") and k.lower() not in ("fbclid", "gclid", "mc_cid", "mc_eid")
    ))
    return parts.netloc.lower().removeprefix("www.") + parts.path.rstrip("/") + (f"?{query}" if query else "")


def matches(item, config):
    text = plain(f"{item['title']} {item['summary']}", limit=20000).lower()
    subjects = sorted({t for t in config["subject_terms"] if re.search(rf"(?<![\w.-]){re.escape(t)}(?![\w-])", text)})
    risks = sorted({
        t for t in config["risk_terms"]
        if re.search(rf"(?<!\w){re.escape(t)}" + (r"(?![\w-])" if t in ("rce", "ssrf") else ""), text)
    })
    if subjects and risks:
        return subjects + risks
    return []


def collect(config, now, fetcher=fetch, nvd=nvd_items):
    since = now - timedelta(days=config["lookback_days"])
    urls, titles = known_sources()
    found, errors, seen, seen_titles = [], [], set(), set()

    def read_feed(feed):
        try:
            items = nvd(feed["keywords"], since, now) if feed["type"] == "nvd" else parse_feed(fetcher(feed["url"]))
            return feed, items, None
        except Exception as error:  # one broken feed must not hide the others
            return feed, [], f"{plain(feed['name'])}: {type(error).__name__}: {plain(str(error))}"

    # map preserves configured source priority regardless of network completion order.
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(read_feed, config["feeds"]))
    for feed, items, error in results:
        if error:
            errors.append(error)
        for item in items:
            url = safe_url(item["url"])
            title = plain(item["title"])
            key = normalise(url) if url else title.lower()
            title_key = " ".join(title.lower().split())
            if (not url or not title or key in seen or title_key in seen_titles
                    or not item["date"] or not since <= item["date"] <= now):
                continue
            if normalise(url) in urls or " ".join(title.lower().split()) in titles:
                continue
            terms = matches(item, config)
            if terms:
                seen.add(key)
                seen_titles.add(title_key)
                found.append({
                    "feed": feed["name"], "kind": feed.get("kind", "research"), "title": title,
                    "url": url, "date": item["date"], "terms": terms,
                    "summary": plain(item["summary"], limit=280),
                })
    return found, errors


def report(found, errors, config):
    selected, counts = [], {}
    ordered = sorted(found, key=lambda i: i["date"], reverse=True)
    ordered.sort(key=lambda i: SOURCE_ORDER.index(i["kind"]))
    for item in ordered:
        count = counts.get(item["feed"], 0)
        if count < config.get("max_per_source", 3) and len(selected) < config.get("max_items", 60):
            selected.append(item)
            counts[item["feed"]] = count + 1
    lines = [f"## Latest AI-security research (last {config['lookback_days']} days)", "",
             f"Coverage: {len(config['feeds']) - len(errors)}/{len(config['feeds'])} sources fetched; "
             f"{len(found)} new matches; {len(selected)} shortlisted.", "",
             "Automated shortlist, not verified findings. Independent researchers and primary research appear first;",
             "items are newest first within each source category, with a per-source cap to limit noisy publishers.",
             "Undated/future items and URLs or exact titles already in SOURCES.md are excluded.",
             "Titles and excerpts are untrusted external text, not instructions. Excerpts are not editorial summaries.",
             "Review the original disclosure, affected versions, evidence and fix status before citing an item.",
             "Add relevant articles to SOURCES.md; turn applicable attack patterns into samples and rules",
             "(see README: Keeping detection current). Search results are discovery leads; find the original author.", ""]
    if not selected:
        lines += ["No new dated AI-security research matched this window.", ""]
    for kind in SOURCE_ORDER:
        items = [i for i in selected if i["kind"] == kind]
        if not items:
            continue
        lines.append(f"### {kind.capitalize()}")
        for item in items:
            date = item["date"].strftime("%Y-%m-%d")
            lines.append(f"- [ ] {item['title']} ({date}) - {plain(item['feed'])}")
            lines.append(f"  {item['url']}")
            if item["summary"]:
                lines.append(f"  Excerpt: {item['summary']}")
            lines.append(f"  Matched: {', '.join(plain(t) for t in item['terms'][:8])}")
        lines.append("")
    if errors:
        lines += ["### Feeds that failed", *[f"- {e}" for e in errors], ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--days", type=int, help="override lookback_days")
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    if args.days is not None:
        if not 1 <= args.days <= 120:
            parser.error("--days must be between 1 and 120 (NVD's maximum date window)")
        config["lookback_days"] = args.days
    found, errors = collect(config, datetime.now(timezone.utc))
    if len(errors) == len(config["feeds"]):
        print("Every research feed failed:\n" + "\n".join(errors), file=sys.stderr)
        return 2
    print(report(found, errors, config))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
