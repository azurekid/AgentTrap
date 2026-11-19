"""Add a generated newsletter to the AgentLens site catalog without replacing past editions."""

import argparse
import json
from datetime import date
from html import escape
from pathlib import Path

SITE_ROOT = Path(__file__).resolve().parents[1] / "web"


def publish(root: Path, issue: int, title: str, day: date, html: str) -> None:
    if issue < 1 or not title.strip() or "\n" in title or "\r" in title:
        raise ValueError("Expected a positive issue number and a single-line headline")
    if f"<h1>{escape(title)}</h1>" not in html or f'<time datetime="{day}">' not in html:
        raise ValueError("Newsletter HTML does not match the issue headline and date")

    manifest = root / "publications.json"
    catalog = json.loads(manifest.read_text(encoding="utf-8"))
    snapshot = root / "static" / f"newsletter-issue-{issue}.html"
    edition = {
        "issue": issue,
        "title": title,
        "date": day.isoformat(),
        "summary": "This week's top agent security stories and practical steps for defenders.",
    }
    existing = [entry for entry in catalog["editions"] if entry["issue"] == issue]
    if existing:
        if existing == [edition] and snapshot.is_file() and snapshot.read_text(encoding="utf-8") == html:
            return
        raise ValueError(f"Refusing to overwrite published newsletter #{issue}")
    if snapshot.exists():
        raise ValueError(f"Refusing to overwrite an existing snapshot for newsletter #{issue}")

    catalog["editions"].append(edition)
    snapshot.write_text(html, encoding="utf-8")
    manifest.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("issue", type=int)
    parser.add_argument("title")
    parser.add_argument("date", type=date.fromisoformat)
    parser.add_argument("html", type=Path)
    args = parser.parse_args()
    try:
        publish(SITE_ROOT, args.issue, args.title, args.date, args.html.read_text(encoding="utf-8"))
    except ValueError as exc:
        parser.exit(1, f"Newsletter was not published: {exc}\n")


if __name__ == "__main__":
    main()
