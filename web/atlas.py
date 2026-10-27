"""Map scanner findings to MITRE ATLAS tactics, techniques, and mitigations (data in atlas.json)."""
import json
from pathlib import Path

DATA = json.loads((Path(__file__).resolve().parent / "atlas.json").read_text("utf-8"))

# ATLAS matrix order, limited to tactics observable in static agent files.
TACTIC_ORDER = ["initial-access", "execution", "persistence", "defense-evasion", "credential-access",
                "discovery", "collection", "command-and-control", "exfiltration", "impact"]


def annotate(files: list[dict]) -> dict:
    """Attach technique IDs to each finding and return the report-level ATLAS summary."""
    tactic_hits = {t: 0 for t in TACTIC_ORDER}
    techniques: dict[str, dict] = {}
    unmapped = set()
    for file in files:
        for finding in file["findings"]:
            pairs = DATA["rules"].get(finding["rule"])
            if not pairs:
                unmapped.add(finding["rule"])
                finding["atlas"] = []
                continue
            finding["atlas"] = list(dict.fromkeys(p["technique"] for p in pairs))
            for tactic in {p["tactic"] for p in pairs}:
                tactic_hits[tactic] += 1
            for pair in pairs:
                tech = techniques.setdefault(pair["technique"], {"findings": 0, "tactics": [], "rules": []})
                if pair["tactic"] not in tech["tactics"]:
                    tech["tactics"].append(pair["tactic"])
                if finding["rule"] not in tech["rules"]:
                    tech["rules"].append(finding["rule"])
            for tid in finding["atlas"]:
                techniques[tid]["findings"] += 1
    detail = []
    for tid, hit in sorted(techniques.items(), key=lambda item: (-item[1]["findings"], item[0])):
        info = DATA["techniques"][tid]
        detail.append({
            "id": tid, "name": info["name"], "parent": info.get("parent"), "url": info["url"],
            "findings": hit["findings"], "rules": hit["rules"],
            "tactics": [t for t in TACTIC_ORDER if t in hit["tactics"]],
            "mitigations": [{"id": m, **DATA["mitigations"][m]} for m in info["mitigations"]],
            "guidance": info.get("guidance"),
        })
    return {
        "source": DATA["source"],
        "tactics": [{"key": t, "id": DATA["tactics"][t]["id"], "name": DATA["tactics"][t]["name"], "findings": tactic_hits[t]}
                    for t in TACTIC_ORDER],
        "techniques": detail,
        "unmapped_rules": sorted(unmapped),
    }
