"""Validate, render and materialise the SkillVenom use-case catalogue under use-cases/.

Each use case is a folder use-cases/<category-slug>/<ID>/ with a use-case.json, a complete
defanged payload file and an optional benign look-alike. Artifacts are stored under their real
agent-file names (payload/<scan_as>, benign/<scan_as>) so they can be inspected as-is.

Usage:
  python tools/use_cases.py validate            # schema + referential checks, exit 1 on error
  python tools/use_cases.py render               # (re)write per-case README.md and CATALOG.md
  python tools/use_cases.py render --check       # fail if rendered docs are stale
  python tools/use_cases.py materialize DEST     # copy payloads to DEST under their scan_as paths
"""
import json
import re
import shutil
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CATALOG = ROOT / "use-cases"
SEVERITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

from web.repository import is_target  # noqa: E402
from scan_agents_md import UNTRUSTED_DIRS  # noqa: E402


def _discoverable(scan_as, workflows):
    if is_target(scan_as.lstrip("/"), workflows=workflows):
        return True
    return bool(UNTRUSTED_DIRS.search("/" + scan_as.lstrip("/")))


def taxonomy():
    return json.loads((CATALOG / "taxonomy.json").read_text(encoding="utf-8"))


def load_cases():
    """Return a list of (directory, case dict) sorted by id."""
    cases = []
    for path in sorted(CATALOG.rglob("use-case.json")):
        if "_template" in path.parts:
            continue
        cases.append((path.parent, json.loads(path.read_text(encoding="utf-8"))))
    return sorted(cases, key=lambda item: item[1]["id"])


def real_scan_path(scan_as):
    """scan_as is already the real path used for discovery/scanning (e.g. .claude/settings.json)."""
    return scan_as


def stored_path(kind, scan_as):
    """Artifacts live under their real name: payload/.claude/settings.json, benign/AGENTS.md."""
    return f"{kind}/{scan_as.lstrip('/')}"


def artifact_text(directory, artifact):
    return (directory / artifact["path"]).read_text(encoding="utf-8")


def _slug_for(case, tax):
    by_code = {c["code"]: c for c in tax["categories"]}
    return by_code[case["category"]]["slug"]


def validate():
    tax = taxonomy()
    codes = {c["code"] for c in tax["categories"]}
    slugs = {c["code"]: c["slug"] for c in tax["categories"]}
    platforms = {p["id"] for p in tax["platforms"]}
    errors = []
    seen = set()
    for directory, case in load_cases():
        cid = case.get("id", "?")
        where = directory.relative_to(ROOT)
        if cid in seen:
            errors.append(f"{cid}: duplicate id")
        seen.add(cid)
        if case["category"] not in codes:
            errors.append(f"{cid}: unknown category {case['category']}")
            continue
        if not cid.startswith(case["category"] + "-"):
            errors.append(f"{cid}: id prefix must match category {case['category']}")
        if directory.parent.name != slugs[case["category"]]:
            errors.append(f"{cid}: stored under {where.parent}, expected {slugs[case['category']]}/")
        if directory.name != cid:
            errors.append(f"{cid}: folder name must equal id (got {directory.name})")
        for platform in case["platforms"]:
            if platform not in platforms:
                errors.append(f"{cid}: unknown platform {platform}")
        workflows = "github-actions" in case["platforms"]
        for artifact in case["artifacts"]:
            if not (directory / artifact["path"]).is_file():
                errors.append(f"{cid}: missing artifact {artifact['path']}")
            if artifact["path"] != stored_path("payload", artifact["scan_as"]):
                errors.append(f"{cid}: artifact {artifact['path']} must be stored as "
                              f"{stored_path('payload', artifact['scan_as'])}")
            if not _discoverable(artifact["scan_as"], workflows):
                errors.append(f"{cid}: scan_as {artifact['scan_as']} is not discovered by the scanner")
        benign = case.get("benign")
        if benign:
            if not (directory / benign["path"]).is_file():
                errors.append(f"{cid}: missing benign artifact {benign['path']}")
            elif benign["path"] != stored_path("benign", benign["scan_as"]):
                errors.append(f"{cid}: benign artifact {benign['path']} must be stored as "
                              f"{stored_path('benign', benign['scan_as'])}")
    if errors:
        print("\n".join(errors))
    return errors


def render_case_readme(directory, case, tax):
    cat = next(c for c in tax["categories"] if c["code"] == case["category"])
    lines = [f"# {case['id']}: {case['title']}", "", f"> {case['summary']}", ""]
    lines += [f"- **Category:** {case['category']} · {cat['title']}",
              f"- **Platforms:** {', '.join(case['platforms'])}",
              f"- **Severity:** {case['severity']}",
              f"- **Status:** {case['status']}",
              f"- **Expected rules:** {', '.join('`' + r + '`' for r in case['expected']['rules'])}"]
    if case.get("mitre_atlas"):
        lines.append(f"- **MITRE ATLAS:** {', '.join(case['mitre_atlas'])}")
    if case.get("owasp_asi"):
        lines.append(f"- **OWASP ASI:** {', '.join(case['owasp_asi'])}")
    if case["expected"].get("artifact_kind"):
        expected = case["expected"]
        lines += [f"- **Expected artifact:** {expected['artifact_kind']}",
                  f"- **Complete supported package (pinned repository flow):** {expected['package_complete']}",
                  "- **Uploads:** snapshot only; never proof of package completeness"]
        if expected.get("name"):
            lines.append(f"- **Expected self-declared frontmatter name:** {expected['name']}")
    if case["expected"].get("signature_status"):
        lines += [f"- **Expected OMS signature:** {case['expected']['signature_status']}",
                  "- **Test trust only:** Configure `use-cases/signature-test-root.pem` explicitly in an isolated test trust store. Never trust this root in production.",
                  "- **Scope:** Upload the whole payload folder. This is not an NVIDIA-signed artifact and reputation is not assessed."]
    lines += ["", "## Why it works", "", case["why_it_works"], "", "## Mitigations", ""]
    lines += [f"- {m}" for m in case["mitigations"]]
    lines += ["", "## Artifacts", ""]
    for artifact in case["artifacts"]:
        note = f", {artifact['note']}" if artifact.get("note") else ""
        lines.append(f"- `{artifact['path']}` → scanned as `{artifact['scan_as']}`{note}")
    if case.get("benign"):
        lines += ["", "## Benign look-alike", "",
                  f"- `{case['benign']['path']}` → scanned as `{case['benign']['scan_as']}`"
                  + (f", {case['benign'].get('note')}" if case['benign'].get('note') else "")]
    if case.get("false_positives"):
        lines += ["", "## False positives", "", case["false_positives"]]
    if case.get("references"):
        lines += ["", "## References", ""] + [f"- {r}" for r in case["references"]]
    lines += ["", "> Payloads are **defanged** and for defensive testing only. Do not run them.", ""]
    return "\n".join(lines)


def render_catalog(cases, tax):
    by_code = {c["code"]: c for c in tax["categories"]}
    total = len(cases)
    lines = ["# SkillVenom use-case catalogue", "",
             f"{total} defensive use cases, each a defanged agent-file payload with the SkillVenom "
             "rules it should trigger. Generated by `tools/use_cases.py render`, do not edit by hand.",
             "", "> Every payload is defanged and for testing detection only. Never run one.", "",
             "## By category", ""]
    for cat in tax["categories"]:
        members = [c for _, c in cases if c["category"] == cat["code"]]
        if not members:
            continue
        lines += [f"### {cat['code']} · {cat['title']}", "", f"_{cat['description']}_", "",
                  "| ID | Title | Platforms | Severity | Rules |", "|----|----|----|----|----|"]
        for case in sorted(members, key=lambda c: c["id"]):
            slug = by_code[case["category"]]["slug"]
            link = f"[{case['id']}]({slug}/{case['id']}/)"
            rules = ", ".join("`" + r + "`" for r in case["expected"]["rules"])
            lines.append(f"| {link} | {case['title']} | {', '.join(case['platforms'])} "
                         f"| {case['severity']} | {rules} |")
        lines.append("")
    lines += ["## By platform", ""]
    for platform in tax["platforms"]:
        members = [(d, c) for d, c in cases if platform["id"] in c["platforms"]]
        if not members:
            continue
        ids = ", ".join(f"[{c['id']}]({by_code[c['category']]['slug']}/{c['id']}/)"
                        for _, c in sorted(members, key=lambda m: m[1]["id"]))
        lines.append(f"- **{platform['title']}** (`{platform['id']}`): {ids}")
    lines.append("")
    return "\n".join(lines)


def render(check=False):
    tax = taxonomy()
    cases = load_cases()
    stale = []
    for directory, case in cases:
        target = directory / "README.md"
        new = render_case_readme(directory, case, tax)
        if check:
            if not target.exists() or target.read_text(encoding="utf-8") != new:
                stale.append(str(target.relative_to(ROOT)))
        else:
            target.write_text(new, encoding="utf-8")
    catalog = render_catalog(cases, tax)
    catalog_path = CATALOG / "CATALOG.md"
    if check:
        if not catalog_path.exists() or catalog_path.read_text(encoding="utf-8") != catalog:
            stale.append(str(catalog_path.relative_to(ROOT)))
        if stale:
            print("Stale (run python tools/use_cases.py render):\n" + "\n".join(stale))
        return stale
    catalog_path.write_text(catalog, encoding="utf-8")
    print(f"Rendered {len(cases)} case READMEs and CATALOG.md")
    return []


def materialize(dest):
    dest = Path(dest).resolve()
    if dest == ROOT or ROOT in dest.parents:
        raise ValueError("materialize outside the repository so agents here never load the payloads")
    written = []
    for directory, case in load_cases():
        items = list(case["artifacts"]) + ([case["benign"]] if case.get("benign") else [])
        for artifact in items:
            scan_as = artifact["scan_as"].lstrip("/")
            target = dest / scan_as
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / artifact["path"], target)
            written.append(target)
    return written


def main(argv):
    if not argv:
        sys.exit(__doc__)
    cmd = argv[0]
    if cmd == "validate":
        return 1 if validate() else 0
    if cmd == "render":
        return 1 if render(check="--check" in argv) else 0
    if cmd == "materialize":
        if len(argv) < 2:
            sys.exit("materialize needs a destination")
        for path in materialize(argv[1]):
            print(path)
        return 0
    sys.exit(f"unknown command: {cmd}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
