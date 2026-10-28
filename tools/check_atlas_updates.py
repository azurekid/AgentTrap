"""Report MITRE ATLAS changes that AgentLens has not reviewed yet.

Usage:
  python tools/check_atlas_updates.py                 # compare with the latest atlas-data release
  python tools/check_atlas_updates.py --stix FILE     # compare with a local stix-atlas.json

Exit code 0 means nothing to review, 1 means a Markdown report was printed, 2 means the check failed.
Reviewed case studies live in tools/atlas_case_studies.json; the pinned release is VERSION in
tools/build_atlas_mapping.py, and mapped techniques come from web/atlas.json.
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASES = "https://api.github.com/repos/mitre-atlas/atlas-data/releases/latest"
ASSET = "stix-atlas.json"
MAX_BYTES = 50 * 1024 * 1024


def fetch(url, accept="application/octet-stream"):
    headers = {"Accept": accept, "User-Agent": "AgentLens-atlas-check"}
    if os.environ.get("GITHUB_TOKEN") and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url} exceeds {MAX_BYTES} bytes")
    return data


def latest_release():
    release = json.loads(fetch(RELEASES, "application/vnd.github+json"))
    asset = next((a for a in release.get("assets", []) if a.get("name") == ASSET), None)
    if not asset:
        raise ValueError(f"release {release.get('tag_name')} has no {ASSET} asset")
    return release["tag_name"], json.loads(fetch(asset["browser_download_url"]))


def pinned_version():
    text = (ROOT / "tools" / "build_atlas_mapping.py").read_text(encoding="utf-8")
    return re.search(r'^VERSION = "([^"]+)"', text, re.M).group(1)


def external_id(obj):
    return next((r["external_id"] for r in obj.get("external_references", []) if r.get("external_id")), None)


def review(bundle, tag, pinned):
    objects = bundle.get("objects", [])
    studies = {external_id(o): o for o in objects if o.get("type") == "campaign" and external_id(o)}
    techniques = {external_id(o): o for o in objects if o.get("type") == "attack-pattern" and external_id(o)}
    classified = json.loads((ROOT / "tools" / "atlas_case_studies.json").read_text(encoding="utf-8"))["case_studies"]
    mapped = json.loads((ROOT / "web" / "atlas.json").read_text(encoding="utf-8"))["techniques"]

    new_studies = sorted(set(studies) - set(classified))
    stale = []
    for tid in sorted(mapped):
        obj = techniques.get(tid)
        if obj is None:
            stale.append(f"`{tid}` no longer exists")
        elif obj.get("revoked") or obj.get("x_mitre_deprecated"):
            stale.append(f"`{tid}` is revoked or deprecated")

    sections = []
    if tag != pinned:
        sections.append(f"ATLAS release **{tag}** is available; AgentLens is pinned to **{pinned}**.")
    if new_studies:
        rows = "\n".join(
            f"- [{cid}: {studies[cid].get('name', '')}](https://atlas.mitre.org/studies/{cid})" for cid in new_studies
        )
        sections.append(f"### Unreviewed case studies\n\n{rows}")
    if stale:
        sections.append("### Mapped techniques to remap\n\n" + "\n".join(f"- {line}" for line in stale))
    return sections


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stix", type=Path, help="local stix-atlas.json instead of the latest release")
    parser.add_argument("--tag", help="release tag of --stix (defaults to the pinned version)")
    args = parser.parse_args()
    pinned = pinned_version()
    try:
        if args.stix:
            tag, bundle = args.tag or pinned, json.loads(args.stix.read_text(encoding="utf-8"))
        else:
            tag, bundle = latest_release()
        sections = review(bundle, tag, pinned)
    except (OSError, ValueError, KeyError) as error:
        print(f"ATLAS update check failed: {error}", file=sys.stderr)
        return 2
    if not sections:
        print(f"AgentLens is current with MITRE ATLAS {tag}.")
        return 0
    print("## MITRE ATLAS changes to review\n\n" + "\n\n".join(sections))
    print("\nFollow the update process in README.md (Keeping detection current).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
