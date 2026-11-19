import os
import re
from base64 import b64encode
from datetime import date, datetime, time, timedelta, timezone
from email.utils import format_datetime
from hashlib import sha256
from html import escape
from pathlib import Path
from string import Template
from xml.etree import ElementTree as ET

from azure.storage.blob import BlobServiceClient
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, HttpUrl, TypeAdapter

from web.navigation import render_header

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
    indexed_at: AwareDatetime | None = None


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
NEWS_LINKS = TypeAdapter(list[NewsLink])
LATEST_RESEARCH = NEWS_LINKS.validate_json((ROOT / "latest-research.json").read_bytes())

NEWS_TOPICS = {
    "editions": "Agent Security Weekly",
    "vulnerabilities": "Vulnerabilities & CVEs",
    "threats": "Attacks & incidents",
    "defenses": "Defenses & guidance",
    "papers": "Research papers",
    "other": "Other security news",
}


def news_topic(item: Edition | NewsLink) -> str:
    if isinstance(item, Edition):
        return "editions"
    text = f"{item.title} {item.summary}".casefold()
    if item.source == "NVD CVEs" or re.search(r"\b(?:cve-\d{4}-\d+|vulnerabilit(?:y|ies)|security flaw)\b", text):
        return "vulnerabilities"
    host = item.url.host or ""
    if host == "arxiv.org" or host.endswith(".arxiv.org"):
        return "papers"
    if re.search(r"\b(?:sandboxes?|sandboxing|hardening|mitigat(?:e|es|ion|ions)|checklists?|best practices|how to)\b", text):
        return "defenses"
    if re.search(r"\b(?:prompt injection|jailbreaks?|attacks?|incidents?|breach(?:es)?|malware|ransomware|phishing|"
                 r"take(?:s)? over|hijack(?:ed|ing)?|stolen|credential theft)\b", text):
        return "threats"
    return "other"


def load_latest_research(storage_service: BlobServiceClient | None = None) -> list[NewsLink]:
    backend = os.getenv("LATEST_NEWS_BACKEND", "local")
    if backend == "local":
        return LATEST_RESEARCH
    if backend != "azure":
        raise RuntimeError("LATEST_NEWS_BACKEND must be local or azure.")
    if storage_service is None:
        raise RuntimeError("Azure latest-news storage is not available.")
    container = os.getenv("AZURE_NEWS_CONTAINER")
    if not container:
        raise RuntimeError("AZURE_NEWS_CONTAINER is required for Azure latest news.")
    payload = storage_service.get_blob_client(container, "latest-research.json").download_blob(
        timeout=15).readall()
    items = NEWS_LINKS.validate_json(payload)
    if len({item.id for item in items}) != len(items):
        raise ValueError("Duplicate news ID in latest-research.json")
    return items


def ordered(
    archive: bool = False, *, storage_service: BlobServiceClient | None = None
) -> list[Edition | NewsLink]:
    entries: list[Edition | NewsLink] = [*CATALOG.editions]
    if not archive:
        entries.extend(CATALOG.news)
        entries.extend(load_latest_research(storage_service))
    return sorted(entries, key=lambda item: item.date, reverse=True)


def render_list(entries: list[Edition | NewsLink], *, archive: bool) -> str:
    heading = "h2" if archive else "h3"
    rows = []
    for item in entries:
        if isinstance(item, Edition):
            href, label = item.path, f"Newsletter · Issue {item.issue}"
            link_id = f"publication-newsletter-{item.issue}"
        else:
            href = str(item.url)
            label = f"{item.source} · Automated" if item.id.startswith("research-") else item.source
            link_id = f"publication-{item.id}"
        day = item.date.isoformat()
        rows.append(
            '<li class="publication-item">'
            f'<p class="publication-meta"><time datetime="{day}">{day}</time>'
            f' <span aria-hidden="true">//</span> {escape(label)}</p>'
            f'<{heading}><a id="{escape(link_id)}" href="{escape(href)}">{escape(item.title)}</a></{heading}>'
            f'<p>{escape(item.summary)}</p></li>'
        )
    return f'<ul class="publication-list">{"".join(rows)}</ul>' if rows else "<p>No publications yet.</p>"


def render_topics(entries: list[Edition | NewsLink]) -> str:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=1)
    groups: dict[str, list[Edition | NewsLink]] = {key: [] for key in NEWS_TOPICS}
    for item in entries:
        if isinstance(item, Edition) or (item.indexed_at is not None and cutoff <= item.indexed_at <= now):
            groups[news_topic(item)].append(item)
    links, sections = [], []
    for key, items in groups.items():
        if not items:
            continue
        label = escape(NEWS_TOPICS[key])
        links.append(f'<li><a href="#{key}">{label} <span>({len(items)})</span></a></li>')
        sections.append(
            f'<section class="news-topic" id="{key}" aria-labelledby="{key}-heading">'
            f'<h2 id="{key}-heading">{label}</h2>{render_list(items, archive=False)}</section>'
        )
    nav = f'<nav class="news-topics" aria-label="News topics"><ul>{"".join(links)}</ul></nav>' if links else ""
    empty = "" if any(groups[key] for key in groups if key != "editions") else (
        f'<p>No news links indexed in the last hour. <a href="{FEED_PATH}">Browse the RSS feed</a> for older links.</p>'
    )
    return f'{nav}{"".join(sections)}{empty}'


def render_page(*, archive: bool, storage_service: BlobServiceClient | None = None) -> str:
    title, intro = (
        ("Newsletter archive", "Browse past editions of Agent Security Weekly.")
        if archive else
        ("Latest News", "Agent Security Weekly and security news indexed in the last hour.")
    )
    entries = ordered(archive, storage_service=storage_service)
    content = render_list(entries, archive=True) if archive else render_topics(entries)
    return PAGE.substitute(title=title, intro=intro, content=content, feed=FEED_PATH,
                           site_header=render_header("/newsletter" if archive else "/news"))


def render_rss(*, storage_service: BlobServiceClient | None = None) -> bytes:
    root = ET.Element("rss", {"version": "2.0", "xmlns:atom": "http://www.w3.org/2005/Atom"})
    channel = ET.SubElement(root, "channel")
    ET.SubElement(channel, "title").text = "AgentLens Latest News"
    ET.SubElement(channel, "link").text = f"{SITE}/news"
    ET.SubElement(channel, "description").text = "Agent security research, curated news, and Agent Security Weekly editions."
    ET.SubElement(channel, "language").text = "en"
    ET.SubElement(channel, "atom:link", {"href": SITE + FEED_PATH, "rel": "self", "type": "application/rss+xml"})
    for item in ordered(storage_service=storage_service):
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
