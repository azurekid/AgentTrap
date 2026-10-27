"""Parse SOURCES.md tables into structured research references for the research page."""
import re
from functools import lru_cache
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "SOURCES.md"
URL = re.compile(r"https?://[^\s;|)]+")


@lru_cache(maxsize=1)
def load() -> dict:
    title, intro, sections, current, columns = "", [], [], None, []
    for line in PATH.read_text("utf-8").splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
        elif line.startswith("## "):
            current = {"heading": line[3:].strip(), "sources": []}
            sections.append(current)
            columns = []
        elif line.startswith("|") and current is not None:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not columns:
                columns = [c.lower() for c in cells]
            elif not all(set(c) <= set("-: ") for c in cells) and len(cells) == len(columns):
                row = dict(zip(columns, cells))
                url_cell = row.get("url", "")
                current["sources"].append({
                    "id": row.get("#", ""), "title": row.get("title", ""),
                    "author": row.get("publisher/author", ""), "date": row.get("date", ""),
                    "type": row.get("type", ""), "urls": URL.findall(url_cell),
                    "note": "" if URL.search(url_cell) else url_cell,
                })
        elif line.strip() and not sections:
            intro.append(line.strip())
    return {"title": title, "intro": " ".join(intro), "sections": sections}
