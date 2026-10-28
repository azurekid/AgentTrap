"""Build web/samples.json for the portal Sample library from the use-case catalogue.

Samples come from use-cases/ (defanged payloads, scanned by the real detectors) plus the
runtime-generated synthetic credential shapes. Snippets are the scanner's own redacted output, so
credential values are never published. A test fails when this file is out of date.

Usage: python tools/build_sample_catalog.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(ROOT / "tools")]

from use_cases import load_cases, taxonomy  # noqa: E402
from scan_agents_md import DEFAULT_ALLOW, scan_file  # noqa: E402
from synthetic_secrets import SECRETS  # noqa: E402

OUTPUT = ROOT / "web" / "samples.json"
SEVERITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
GITHUB_TREE = "https://github.com/azurekid/AgentTrap/tree/main/use-cases"


def build():
    atlas = json.loads((ROOT / "web" / "atlas.json").read_text(encoding="utf-8"))
    atlas_rules = atlas["rules"]
    asi_rules = atlas["owasp_asi"]["rules"]
    tax = taxonomy()
    slugs = {c["code"]: c["slug"] for c in tax["categories"]}
    cat_titles = {c["code"]: c["title"] for c in tax["categories"]}

    rules = {}
    cases_out = []
    for directory, case in load_cases():
        slug = slugs[case["category"]]
        card = {
            "id": case["id"], "title": case["title"], "summary": case["summary"],
            "category": case["category"], "category_title": cat_titles[case["category"]],
            "platforms": case["platforms"], "severity": case["severity"], "status": case["status"],
            "source": case["source"], "why": case["why_it_works"], "mitigations": case["mitigations"],
            "mitre_atlas": case.get("mitre_atlas", []), "owasp_asi": case.get("owasp_asi", []),
            "references": case.get("references", []),
            "url": f"{GITHUB_TREE}/{slug}/{case['id']}", "rules": case["expected"]["rules"],
            "findings": [],
        }
        if case["expected"].get("artifact_kind"):
            card["artifact_validation"] = {key: value for key, value in case["expected"].items() if key != "rules"}
        if case["expected"].get("signature_status"):
            card["signature_validation"] = case["expected"]["signature_status"]
        for artifact in case["artifacts"]:
            if artifact["scan_as"].endswith("/skill.oms.sig"):
                continue
            text = (directory / artifact["path"]).read_text(encoding="utf-8")
            for finding in scan_file(artifact["scan_as"], text, DEFAULT_ALLOW):
                entry = {"rule": finding["rule"], "severity": finding["severity"],
                         "line": finding["line"], "snippet": finding["snippet"],
                         "scan_as": artifact["scan_as"]}
                if entry not in card["findings"]:
                    card["findings"].append(entry)
                bucket = rules.setdefault(finding["rule"], {
                    "rule": finding["rule"], "severity": finding["severity"],
                    "message": finding["message"], "ref": finding.get("ref", ""),
                    "atlas": [m["technique"] for m in atlas_rules.get(finding["rule"], [])],
                    "owasp_asi": asi_rules.get(finding["rule"], []),
                    "samples": [],
                })
                if SEVERITY[finding["severity"]] < SEVERITY[bucket["severity"]]:
                    bucket["severity"] = finding["severity"]
                sample = {"origin": case["id"], "label": case["title"], "url": card["url"],
                          "file": artifact["scan_as"], "line": finding["line"],
                          "snippet": finding["snippet"]}
                if sample not in bucket["samples"]:
                    bucket["samples"].append(sample)
        card["findings"].sort(key=lambda f: (SEVERITY[f["severity"]], f["line"]))
        cases_out.append(card)

    for rule, shape, value in SECRETS:
        for finding in scan_file("AGENTS.md", value + "\n", DEFAULT_ALLOW):
            if finding["rule"] != rule:
                continue
            bucket = rules.setdefault(rule, {
                "rule": rule, "severity": finding["severity"], "message": finding["message"],
                "ref": finding.get("ref", ""),
                "atlas": [m["technique"] for m in atlas_rules.get(rule, [])],
                "owasp_asi": asi_rules.get(rule, []), "samples": [],
            })
            sample = {"origin": "Synthetic credential", "label": shape, "url": "",
                      "file": "AGENTS.md", "line": finding["line"], "snippet": finding["snippet"]}
            if sample not in bucket["samples"]:
                bucket["samples"].append(sample)

    ordered_rules = sorted(rules.values(), key=lambda r: (SEVERITY[r["severity"]], r["rule"]))
    ordered_cases = sorted(cases_out, key=lambda c: (c["category"], c["id"]))
    categories = [{"code": c["code"], "slug": c["slug"], "title": c["title"],
                   "description": c["description"]} for c in tax["categories"]]
    return {
        "note": "Generated by tools/build_sample_catalog.py from use-cases/ and synthetic secrets. "
                "Payloads are defanged; credentials are synthetic and redacted.",
        "catalog_url": GITHUB_TREE,
        "categories": categories,
        "platforms": tax["platforms"],
        "owasp_risks": atlas["owasp_asi"]["risks"],
        "owasp_url": atlas["owasp_asi"]["url"],
        "cases": ordered_cases,
        "rules": ordered_rules,
    }


def render(catalog):
    return json.dumps(catalog, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    catalog = build()
    OUTPUT.write_text(render(catalog), encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)} "
          f"({len(catalog['cases'])} cases, {len(catalog['rules'])} rules, "
          f"{sum(len(r['samples']) for r in catalog['rules'])} samples)")
