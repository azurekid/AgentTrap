from html import escape
from pathlib import Path
from string import Template
from urllib.parse import urlencode

STATIC = Path(__file__).resolve().parent / "static"
HEADER = Template((STATIC / "site-header.html").read_text(encoding="utf-8"))
SHARE = Template((STATIC / "newsletter-share.html").read_text(encoding="utf-8"))
DESTINATIONS = ("/#scanner", "/news", "/newsletter", "/fingerprints", "/coverage", "/samples", "/sources")


def render_header(current: str = "") -> str:
    return HEADER.substitute({
        f"current_{index}": ' aria-current="page"' if path == current else ""
        for index, path in enumerate(DESTINATIONS)
    })


def render_static_page(name: str, current: str = "") -> str:
    page = (STATIC / name).read_text(encoding="utf-8")
    return page.replace("<!-- site-header -->", render_header(current), 1)


def render_edition(
    snapshot: Path, sidebar: str, *, title: str, description: str, url: str, image_url: str
) -> str:
    page = snapshot.read_text(encoding="utf-8")
    social_metadata = "\n".join((
        f'<link rel="canonical" href="{escape(url, quote=True)}">',
        '<meta property="og:type" content="article">',
        f'<meta property="og:title" content="{escape(title, quote=True)}">',
        f'<meta property="og:description" content="{escape(description, quote=True)}">',
        f'<meta property="og:url" content="{escape(url, quote=True)}">',
        '<meta property="og:site_name" content="Agent Security Weekly">',
        f'<meta property="og:image" content="{escape(image_url, quote=True)}">',
        '<meta property="og:image:width" content="1200">',
        '<meta property="og:image:height" content="630">',
        '<meta property="og:image:type" content="image/jpeg">',
        '<meta property="og:image:alt" content="AgentLens Newsletter - Agent Security Weekly, with a radar graphic">',
        '<meta name="twitter:card" content="summary_large_image">',
        f'<meta name="twitter:title" content="{escape(title, quote=True)}">',
        f'<meta name="twitter:description" content="{escape(description, quote=True)}">',
        f'<meta name="twitter:image" content="{escape(image_url, quote=True)}">',
    ))
    share_text = f"{title}\n{url}"
    share_links = {
        "linkedin": "https://www.linkedin.com/sharing/share-offsite/?" + urlencode({"url": url}),
        "whatsapp": "https://api.whatsapp.com/send?" + urlencode({"text": share_text}),
        "x": "https://twitter.com/intent/tweet?" + urlencode({"text": title, "url": url}),
        "bluesky": "https://bsky.app/intent/compose?" + urlencode({"text": share_text}),
    }
    share = SHARE.substitute({key: escape(link, quote=True) for key, link in share_links.items()})
    return page.replace(
        "<style>", f'{social_metadata}\n<style>', 1
    ).replace(
        "</head>", '<link rel="stylesheet" href="/assets/site-nav.css">\n</head>', 1
    ).replace(
        "<body>", "<body>\n" + render_header("/newsletter") + '<div class="newsletter-layout">', 1
    ).replace(
        "<main>", '<a href="#newsletter-previous" class="newsletter-sidebar-jump">Previous editions</a>\n<main>\n' + share, 1
    ).replace(
        "</body>", sidebar + "</div>\n</body>", 1
    ).replace(
        'href="/newsletter">Newsletter archive</a>', 'href="/newsletter/archive">Newsletter archive</a>', 1
    )
