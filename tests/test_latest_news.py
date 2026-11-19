from datetime import datetime, timezone

from tools.update_latest_news import merge


def test_refresh_deduplicates_and_keeps_previously_indexed_items():
    day = datetime(2026, 11, 19, tzinfo=timezone.utc)
    curated = [{"title": "Editorial title", "url": "https://example.org/curated"}]
    old = {"title": "Previous headline", "url": "https://example.org/previous", "date": "2026-11-18"}
    found = [
        {"title": "Duplicate", "url": "https://www.example.org/curated/?utm_source=rss", "date": day},
        {"title": "<b>New research</b>", "url": "https://example.org/new", "date": day, "feed": "Source"},
    ]
    result = merge(curated, [old], found)
    assert [item["title"] for item in result] == ["New research", "Previous headline"]
    assert result[0]["id"].startswith("research-")
    assert merge(curated, result, found) == result
