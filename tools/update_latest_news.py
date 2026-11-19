"""Refresh the public index from the configured research feeds."""

import json
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from tools.check_research_feeds import CONFIG, ROOT, collect, normalise, plain

LIMIT = 100


def merge(curated: list[dict], existing: list[dict], found: list[dict]) -> list[dict]:
    urls = {normalise(item["url"]) for item in curated}
    titles = {item["title"].casefold() for item in curated}
    rows = []
    for item in existing:
        key, title = normalise(item["url"]), item["title"].casefold()
        if key not in urls and title not in titles:
            rows.append(item)
            urls.add(key)
            titles.add(title)
    for item in sorted(found, key=lambda row: row["date"], reverse=True):
        headline = plain(item["title"]).replace("\u2014", " - ")
        key, title = normalise(item["url"]), headline.casefold()
        if not title or key in urls or title in titles:
            continue
        rows.append({
            "id": "research-" + sha256(key.encode()).hexdigest(),
            "title": headline,
            "date": item["date"].date().isoformat(),
            "source": plain(item["feed"]).replace("\u2014", " - "),
            "url": item["url"],
            "summary": "Automatically indexed from the source. Read the original for details.",
        })
        urls.add(key)
        titles.add(title)
    return sorted(rows, key=lambda row: row["date"], reverse=True)[:LIMIT]


def main(web: Path = ROOT / "web") -> int:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config["feeds"] = [feed for feed in config["feeds"] if feed.get("kind") != "discovery"]
    found, errors = collect(config, datetime.now(timezone.utc))
    for error in errors:
        print(f"Research feed failed: {error}", file=sys.stderr)
    if len(errors) == len(config["feeds"]):
        print("No research feeds available; leaving the public index unchanged.", file=sys.stderr)
        return 1
    target = web / "latest-research.json"
    curated = json.loads((web / "publications.json").read_text(encoding="utf-8"))["news"]
    previous = json.loads(target.read_text(encoding="utf-8"))
    updated = merge(curated, previous, found)
    if updated != previous:
        target.write_text(json.dumps(updated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
