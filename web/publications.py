import os
import re
from base64 import b64encode
from datetime import date, datetime, time, timezone
from email.utils import format_datetime
from hashlib import sha256
from html import escape
from pathlib import Path
from string import Template
from xml.etree import ElementTree as ET

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, TypeAdapter

ROOT = Path(__file__).resolve().parent
SITE = (os.getenv("AGENTLENS_SITE_URL") or
        f"https://{os.getenv('WEBSITE_HOSTNAME', 'app-skillvenom-bb6uknnp.azurewebsites.net')}").rstrip("/")
FEED_PATH = "/rss.xml"
PAGE = Template((ROOT / "static" / "publications.html").read_text(encoding="utf-8"))


class Publication(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1)
    date: date
    summary: str = Field(min_length=1)


class Edition(Publication):
    issue: int = Field(strict=True, gt=0)

    @property
    def path(self) -> str:
        return f"/newsletter/{self.issue}"


class NewsLink(Publication):
    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    source: str = Field(min_length=1)
    url: HttpUrl


class Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid")
    editions: list[Edition]
    news: list[NewsLink]


def load_catalog(root: Path) -> tuple[Catalog, dict[str, tuple[Path, bytes]]]:
    catalog = Catalog.model_validate_json((root / "publications.json").read_bytes())
    if len({item.id for item in catalog.news}) != len(catalog.news):
        raise ValueError("Duplicate news ID in publications.json")
    snapshots = {}
    for edition in catalog.editions:
        if edition.path in snapshots:
            raise ValueError(f"Duplicate newsletter issue {edition.issue}")
        file = root / "static" / f"newsletter-issue-{edition.issue}.html"
        # Match the generated HTML format. Text mode normalizes CRLF just as HTML parsing does.
        styles = re.findall(r"<style>(.*?)</style>", file.read_text(encoding="utf-8"), re.DOTALL)
        if len(styles) != 1:
            raise ValueError(f"{file.name} must contain one embedded stylesheet")
        digest = b64encode(sha256(styles[0].encode("utf-8")).digest())
        snapshots[edition.path] = (file, b"'sha256-" + digest + b"'")
    return catalog, snapshots


CATALOG, SNAPSHOTS = load_catalog(ROOT)
LATEST_RESEARCH = TypeAdapter(list[NewsLink]).validate_json((ROOT / "latest-research.json").read_bytes())


def ordered(archive: bool = False) -> list[Edition | NewsLink]:
    entries: list[Edition | NewsLink] = [*CATALOG.editions]
    if not archive:
        entries.extend(CATALOG.news)
        entries.extend(LATEST_RESEARCH)
    return sorted(entries, key=lambda item: item.date, reverse=True)


def render_page(*, archive: bool) -> str:
    title, intro = (
        ("Newsletter archive", "Browse past editions of Agent Security Weekly.")
        if archive else
        ("Latest News", "Security research from monitored sources, curated links, and Agent Security Weekly.")
    )
    rows = []
    for item in ordered(archive):
        if isinstance(item, Edition):
            href, label = item.path, f"Newsletter · Issue {item.issue}"
        else:
            href = str(item.url)
            label = f"{item.source} · Automated" if item.id.startswith("research-") else item.source
        day = item.date.isoformat()
        rows.append(
            '<li class="publication-item">'
            f'<p class="publication-meta"><time datetime="{day}">{day}</time>'
            f' <span aria-hidden="true">//</span> {escape(label)}</p>'
            f'<h2><a href="{escape(href)}">{escape(item.title)}</a></h2>'
            f'<p>{escape(item.summary)}</p></li>'
        )
    content = f'<ul class="publication-list">{"".join(rows)}</ul>' if rows else "<p>No publications yet.</p>"
    current = ' aria-current="page"'
    return PAGE.substitute(title=title, intro=intro, content=content, feed=FEED_PATH,
                           news_current="" if archive else current,
                           archive_current=current if archive else "")


def render_rss() -> bytes:
    root = ET.Element("rss", {"version": "2.0", "xmlns:atom": "http://www.w3.org/2005/Atom"})
    channel = ET.SubElement(root, "channel")
    ET.SubElement(channel, "title").text = "AgentLens Latest News"
    ET.SubElement(channel, "link").text = f"{SITE}/news"
    ET.SubElement(channel, "description").text = "Agent security research, curated news, and Agent Security Weekly editions."
    ET.SubElement(channel, "language").text = "en"
    ET.SubElement(channel, "atom:link", {"href": SITE + FEED_PATH, "rel": "self", "type": "application/rss+xml"})
    for item in ordered():
        node = ET.SubElement(channel, "item")
        ET.SubElement(node, "title").text = item.title
        ET.SubElement(node, "description").text = escape(item.summary, quote=False)
        ET.SubElement(node, "pubDate").text = format_datetime(
            datetime.combine(item.date, time.min, timezone.utc), usegmt=True)
        if isinstance(item, Edition):
            link = SITE + item.path
            ET.SubElement(node, "guid", {"isPermaLink": "true"}).text = link
            ET.SubElement(node, "category").text = "Newsletter"
        else:
            link = str(item.url)
            ET.SubElement(node, "guid", {"isPermaLink": "false"}).text = f"urn:agentlens:news:{item.id}"
            ET.SubElement(node, "category").text = (
                "Automated research" if item.id.startswith("research-") else "Curated news")
        ET.SubElement(node, "link").text = link
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
