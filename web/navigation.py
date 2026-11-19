from pathlib import Path
from string import Template

STATIC = Path(__file__).resolve().parent / "static"
HEADER = Template((STATIC / "site-header.html").read_text(encoding="utf-8"))
DESTINATIONS = ("/#scanner", "/news", "/newsletter", "/fingerprints", "/coverage", "/samples", "/sources")


def render_header(current: str = "") -> str:
    return HEADER.substitute({
        f"current_{index}": ' aria-current="page"' if path == current else ""
        for index, path in enumerate(DESTINATIONS)
    })


def render_static_page(name: str, current: str = "") -> str:
    page = (STATIC / name).read_text(encoding="utf-8")
    return page.replace("<!-- site-header -->", render_header(current), 1)


def render_edition(snapshot: Path) -> str:
    page = snapshot.read_text(encoding="utf-8")
    return page.replace(
        "</head>", '<link rel="stylesheet" href="/assets/site-nav.css">\n</head>', 1
    ).replace("<body>", "<body>\n" + render_header("/newsletter"), 1)
