"""Build web/atlas.json from the official MITRE ATLAS STIX release.

Usage: python tools/build_atlas_mapping.py path/to/stix-atlas.json
Download: https://github.com/mitre-atlas/atlas-data/releases (asset stix-atlas.json)

Technique, tactic, and mitigation names and the technique-to-mitigation links come
from ATLAS. The rule-to-technique mapping below is AgentTrap's own analyst judgement.
"""
import json
import sys
from pathlib import Path

VERSION = "v2026.09"

# rule -> [(technique, tactic shortname)]; the tactic must be one ATLAS lists for that technique.
EXEC, EVADE, PERSIST, CRED, EXFIL, COLLECT = "execution", "defense-evasion", "persistence", "credential-access", "exfiltration", "collection"
INIT, C2, IMPACT, DISCOVER = "initial-access", "command-and-control", "impact", "discovery"
SECRET = [("AML.T0083", CRED), ("AML.T0055", CRED)]
RULES = {
    "PROMPT-INJECTION": [("AML.T0051.001", EXEC)],
    "FAKE-SYSTEM-TAG": [("AML.T0051.001", EXEC), ("AML.T0054", EVADE)],
    "HIDDEN-UNICODE": [("AML.T0068", EVADE), ("AML.T0051.001", EXEC)],
    "UNICODE-TAG-SMUGGLING": [("AML.T0068", EVADE), ("AML.T0051.001", EXEC)],
    "VARIATION-SELECTOR-SMUGGLING": [("AML.T0068", EVADE), ("AML.T0051.001", EXEC)],
    "HIDDEN-COMMENT": [("AML.T0068", EVADE), ("AML.T0051.001", EXEC)],
    "OBFUSCATION": [("AML.T0123", EVADE), ("AML.T0050", EXEC)],
    "BASE64-PAYLOAD": [("AML.T0123", EVADE), ("AML.T0068", EVADE)],
    "BASE64-BLOB": [("AML.T0123", EVADE)],
    "PIPE-TO-SHELL": [("AML.T0050", EXEC), ("AML.T0053", EXEC)],
    "NPM-INSTALL": [("AML.T0011.001", EXEC)],
    "INSTALL-FROM-URL": [("AML.T0011.001", EXEC), ("AML.T0010.001", INIT)],
    "NPX-YES": [("AML.T0011.001", EXEC), ("AML.T0053", EXEC)],
    "INSTALL-SCRIPTS": [("AML.T0011.001", EXEC)],
    "AUTHORITATIVE-INSTALL": [("AML.T0011.001", EXEC), ("AML.T0010.001", INIT)],
    "REGISTRY-REDIRECT": [("AML.T0010.001", INIT)],
    "TRAFFIC-REDIRECT": [("AML.T0081", PERSIST), ("AML.T0072", C2)],
    "TUNNEL-OAST": [("AML.T0072", C2), ("AML.T0025", EXFIL)],
    "EXFIL-ENV": [("AML.T0086", EXFIL), ("AML.T0037", COLLECT)],
    "AUTH-HEADER": SECRET,
    "CRED-FILES": [("AML.T0055", CRED), ("AML.T0037", COLLECT)],
    "OAUTH-TOKEN": [("AML.T0055", CRED)],
    "MCP-CONFIG": [("AML.T0081", PERSIST), ("AML.T0010.005", INIT)],
    "DISABLE-SAFEGUARDS": [("AML.T0054", EVADE), ("AML.T0081", EVADE)],
    "PERSISTENCE": [("AML.T0081", PERSIST)],
    "DESTRUCTIVE": [("AML.T0101", IMPACT)],
    "WIPER-INSTRUCTION": [("AML.T0101", IMPACT), ("AML.T0112.000", IMPACT)],
    "CLAUDE-HOOKS": [("AML.T0081", PERSIST), ("AML.T0050", EXEC)],
    "CLAUDE-APIKEYHELPER": [("AML.T0081", PERSIST), ("AML.T0098", CRED)],
    "PERMISSION-WILDCARD": [("AML.T0081", EVADE)],
    "CODEX-FULL-ACCESS": [("AML.T0081", EVADE)],
    "GEMINI-TRUST-OFF": [("AML.T0081", EVADE)],
    "VSCODE-AUTOAPPROVE": [("AML.T0081", EVADE), ("AML.T0053", EXEC)],
    "VSCODE-TASK-AUTORUN": [("AML.T0011", EXEC), ("AML.T0081", PERSIST)],
    "AI-CLI-SAFETY-BYPASS": [("AML.T0053", EXEC), ("AML.T0054", EVADE)],
    "GH-CLI-EXFIL": [("AML.T0086", EXFIL), ("AML.T0036", COLLECT)],
    "DNS-EXFIL": [("AML.T0025", EXFIL), ("AML.T0086", EXFIL)],
    "ANSI-ESCAPE-EXFIL": [("AML.T0077", EXFIL)],
    "MARKDOWN-IMAGE-EXFIL": [("AML.T0077", EXFIL)],
    "CLOUD-METADATA": [("AML.T0055", CRED), ("AML.T0089", DISCOVER)],
    "WORM-PROPAGATION": [("AML.T0061", PERSIST)],
    "CI-WORKFLOW-WRITE": [("AML.T0053", EXEC), ("AML.T0081", PERSIST)],
    "CI-SECRET-LEAK": [("AML.T0055", CRED), ("AML.T0086", EXFIL)],
    "EXEC-HIJACK": [("AML.T0050", EXEC)],
    "WALLET-BROWSER-THEFT": [("AML.T0113", CRED), ("AML.T0037", COLLECT)],
    "KNOWN-IOC": [("AML.T0010", INIT)],
    "UNTRUSTED-LOCATION": [("AML.T0078", INIT), ("AML.T0051.001", EXEC)],
    "URL-CREDENTIALS": SECRET,
    "RAW-IP-URL": [("AML.T0072", C2)],
    "PLAIN-HTTP": [("AML.T0072", C2)],
    "SUSPICIOUS-TLD": [("AML.T0072", C2)],
    "UNLISTED-DOMAIN": [("AML.T0072", C2)],
}
for rule in ("GITHUB", "AWS", "AI-API", "SLACK", "NPM", "GOOGLE", "JWT", "PRIVATE-KEY", "ASSIGNMENT", "URL", "AUTH-VALUE"):
    RULES[f"SECRET-{rule}"] = SECRET

# Agent-specific controls first; at most four ATLAS mitigations per technique are shown.
PREFERENCE = ["AML.M0033", "AML.M0030", "AML.M0029", "AML.M0026", "AML.M0027", "AML.M0028", "AML.M0032",
              "AML.M0020", "AML.M0021", "AML.M0011", "AML.M0014", "AML.M0013", "AML.M0023", "AML.M0016",
              "AML.M0018", "AML.M0005", "AML.M0031", "AML.M0024", "AML.M0022", "AML.M0035"]

# Shown when ATLAS publishes no mitigation for a technique; labelled as AgentTrap guidance in the UI.
GUIDANCE = {
    "AML.T0055": "Remove credentials from agent-readable files; use a secret manager and short-lived tokens, then rotate anything exposed.",
    "AML.T0083": "Never store secrets in agent instructions or configuration; reference environment or vault lookups and rotate exposed values.",
    "AML.T0077": "Disable automatic rendering of remote images and links in agent output, or restrict them to an allowlist.",
    "AML.T0072": "Restrict agent network egress to an allowlist and review every external endpoint referenced in instructions.",
    "AML.T0123": "Reject encoded or obfuscated content in instruction files; decode and review it before use.",
    "AML.T0037": "Scope agent file access to the workspace and deny reads of credential stores and home-directory secrets.",
    "AML.T0036": "Limit agent tokens to least privilege and require approval before creating repos, gists, or reading secrets.",
    "AML.T0089": "Block instance-metadata endpoints from agent sandboxes and require IMDSv2 or equivalent.",
    "AML.T0113": "Deny agents access to browser profiles, keychains, and wallet stores.",
    "AML.T0098": "Avoid credential helpers that execute scripts; supply keys through a vetted secret manager.",
    "AML.T0081": "Treat agent configuration as code: review changes, pin settings centrally, and keep approvals and sandboxing enabled.",
    "AML.T0112.000": "Run agents in disposable sandboxes with backups and deny destructive commands without human approval.",
}


def external_id(obj):
    return next((r["external_id"] for r in obj.get("external_references", []) if r.get("external_id", "").startswith("AML")), None)


def url(obj):
    return next((r.get("url") for r in obj.get("external_references", []) if r.get("external_id", "").startswith("AML")), None)


def main(path):
    objects = json.loads(Path(path).read_text())["objects"]
    live = [o for o in objects if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_ref = {o["id"]: o for o in live}
    tactics = {o["x_mitre_shortname"]: {"id": external_id(o), "name": o["name"]} for o in live if o["type"] == "x-mitre-tactic"}
    techniques = {external_id(o): o for o in live if o["type"] == "attack-pattern"}
    mitigations = {external_id(o): o for o in live if o["type"] == "course-of-action"}
    links = {}
    for rel in live:
        if rel["type"] == "relationship" and rel["relationship_type"] == "mitigates":
            source, target = by_ref.get(rel["source_ref"]), by_ref.get(rel["target_ref"])
            if source and target:
                links.setdefault(external_id(target), set()).add(external_id(source))
    used = sorted({tech for pairs in RULES.values() for tech, _ in pairs})
    out_tech, used_mitigations = {}, set()
    for tech in used:
        obj = techniques[tech]
        allowed = [p["phase_name"] for p in obj["kill_chain_phases"]]
        candidates = links.get(tech, set()) | links.get(tech.split(".")[0] + "." + tech.split(".")[1], set())
        chosen = [m for m in PREFERENCE if m in candidates][:4]
        used_mitigations.update(chosen)
        out_tech[tech] = {"name": obj["name"], "tactics": allowed, "mitigations": chosen, "url": url(obj)}
        if tech in GUIDANCE:
            out_tech[tech]["guidance"] = GUIDANCE[tech]
        if not chosen and tech not in GUIDANCE:
            raise SystemExit(f"{tech} has no ATLAS mitigation and no guidance")
    for tech in used:
        parent = tech.rsplit(".", 1)[0] if tech.count(".") == 2 else None
        if parent:
            out_tech[tech]["parent"] = techniques[parent]["name"]
    for rule, pairs in RULES.items():
        for tech, tactic in pairs:
            if tactic not in out_tech[tech]["tactics"]:
                raise SystemExit(f"{rule}: {tactic} is not an ATLAS tactic of {tech}")
    data = {
        "source": f"MITRE ATLAS {VERSION}",
        "tactics": tactics,
        "techniques": out_tech,
        "mitigations": {m: {"name": mitigations[m]["name"], "url": url(mitigations[m])} for m in sorted(used_mitigations)},
        "rules": {rule: [{"technique": t, "tactic": a} for t, a in pairs] for rule, pairs in sorted(RULES.items())},
    }
    target = Path(__file__).resolve().parents[1] / "web" / "atlas.json"
    target.write_text(json.dumps(data, indent=1) + "\n")
    print(f"Wrote {target} ({len(out_tech)} techniques, {len(used_mitigations)} mitigations, {len(RULES)} rules)")


if __name__ == "__main__":
    main(sys.argv[1])
