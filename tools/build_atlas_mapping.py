"""Build web/atlas.json from the official MITRE ATLAS STIX release.

Usage: python tools/build_atlas_mapping.py path/to/stix-atlas.json
Download: https://github.com/mitre-atlas/atlas-data/releases (asset stix-atlas.json)

Technique, tactic, and mitigation names and the technique-to-mitigation links come
from ATLAS. The rule-to-technique mapping below is AgentLens's own analyst judgement.
"""
import json
import sys
from pathlib import Path

VERSION = "v2026.09"

# rule -> [(technique, tactic shortname)]; the tactic must be one ATLAS lists for that technique.
EXEC, EVADE, PERSIST, CRED, EXFIL, COLLECT = "execution", "defense-evasion", "persistence", "credential-access", "exfiltration", "collection"
INIT, C2, IMPACT, DISCOVER = "initial-access", "command-and-control", "impact", "discovery"
PRIVESC = "privilege-escalation"
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
    "PUNYCODE": [("AML.T0073", EVADE), ("AML.T0072", C2)],
    "MEMORY-POISONING": [("AML.T0080.000", PERSIST), ("AML.T0051.001", EXEC)],
    "FILE-EXFIL": [("AML.T0086", EXFIL), ("AML.T0025", EXFIL)],
    "REMOTE-COMMANDS": [("AML.T0108", C2), ("AML.T0051.001", EXEC)],
    "CLICKFIX": [("AML.T0100", EXEC), ("AML.T0053", EXEC)],
    "OFFENSIVE-TASKING": [("AML.T0103", EXEC), ("AML.T0054", EVADE)],
    "AI-PREFILL-LINK": [("AML.T0131", INIT), ("AML.T0080.000", PERSIST)],
    "REVERSE-SHELL": [("AML.T0072", C2), ("AML.T0050", EXEC)],
    "JAILBREAK-PERSONA": [("AML.T0054", EVADE), ("AML.T0051.001", EXEC)],
    "CREDENTIAL-PROMPT": [("AML.T0055", CRED), ("AML.T0073", EVADE)],
    # ATLAS has no indicator-removal technique; clearing history/logs is destruction through the agent's shell tool.
    "ANTI-FORENSICS": [("AML.T0101", IMPACT), ("AML.T0050", EXEC)],
    "HIDDEN-HTML-TEXT": [("AML.T0068", EVADE), ("AML.T0051.001", EXEC)],
    "PRIVILEGE-ESCALATION": [("AML.T0053", PRIVESC), ("AML.T0050", EXEC)],
    "REVIEW-BYPASS": [("AML.T0073", EVADE), ("AML.T0051.001", EXEC)],
    "TOOL-EXFIL": [("AML.T0086", EXFIL), ("AML.T0053", EXEC)],
    "PRIVILEGE-GRANT": [("AML.T0053", PRIVESC), ("AML.T0012", PRIVESC)],
    "SKILL-TRIGGER-HIJACK": [("AML.T0110", PERSIST), ("AML.T0051.001", EXEC)],
    "TOOL-SHADOWING": [("AML.T0110", PERSIST), ("AML.T0053", EXEC)],
}

# OWASP Top 10 for Agentic Applications 2026 (SOURCES.md #68). Rule -> ASI ids is AgentLens's own judgement.
OWASP_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
ASI = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
ASI_RULES = {
    "PROMPT-INJECTION": ["ASI01"], "FAKE-SYSTEM-TAG": ["ASI01"], "JAILBREAK-PERSONA": ["ASI01"],
    "HIDDEN-UNICODE": ["ASI01"], "UNICODE-TAG-SMUGGLING": ["ASI01"], "VARIATION-SELECTOR-SMUGGLING": ["ASI01"],
    "HIDDEN-COMMENT": ["ASI01"], "HIDDEN-HTML-TEXT": ["ASI01"], "UNTRUSTED-LOCATION": ["ASI01"],
    "OFFENSIVE-TASKING": ["ASI01", "ASI02"], "REMOTE-COMMANDS": ["ASI01", "ASI05"],
    "AI-PREFILL-LINK": ["ASI06", "ASI09"], "MEMORY-POISONING": ["ASI06"],
    "OBFUSCATION": ["ASI05", "ASI01"], "BASE64-PAYLOAD": ["ASI05", "ASI01"], "BASE64-BLOB": ["ASI01"],
    "PIPE-TO-SHELL": ["ASI05"], "REVERSE-SHELL": ["ASI05"], "CLAUDE-HOOKS": ["ASI05"],
    "VSCODE-TASK-AUTORUN": ["ASI05"], "AI-CLI-SAFETY-BYPASS": ["ASI05", "ASI03"], "EXEC-HIJACK": ["ASI05"],
    "CI-WORKFLOW-WRITE": ["ASI05", "ASI04"], "CLICKFIX": ["ASI09", "ASI05"],
    "NPM-INSTALL": ["ASI04"], "INSTALL-FROM-URL": ["ASI04"], "NPX-YES": ["ASI04"], "INSTALL-SCRIPTS": ["ASI04"],
    "AUTHORITATIVE-INSTALL": ["ASI04"], "REGISTRY-REDIRECT": ["ASI04"], "MCP-CONFIG": ["ASI04"],
    "KNOWN-IOC": ["ASI04"], "TRAFFIC-REDIRECT": ["ASI04", "ASI02"],
    "TUNNEL-OAST": ["ASI02"], "EXFIL-ENV": ["ASI02", "ASI03"], "FILE-EXFIL": ["ASI02"], "DNS-EXFIL": ["ASI02"],
    "GH-CLI-EXFIL": ["ASI02", "ASI03"], "TOOL-EXFIL": ["ASI02"], "MARKDOWN-IMAGE-EXFIL": ["ASI02"],
    "ANSI-ESCAPE-EXFIL": ["ASI02"], "CI-SECRET-LEAK": ["ASI02", "ASI03"],
    "DESTRUCTIVE": ["ASI02"], "WIPER-INSTRUCTION": ["ASI02", "ASI10"], "ANTI-FORENSICS": ["ASI10", "ASI02"],
    "PERSISTENCE": ["ASI10"], "WORM-PROPAGATION": ["ASI08", "ASI10"],
    "AUTH-HEADER": ["ASI03"], "CRED-FILES": ["ASI03"], "OAUTH-TOKEN": ["ASI03"], "URL-CREDENTIALS": ["ASI03"],
    "CLAUDE-APIKEYHELPER": ["ASI03"], "CLOUD-METADATA": ["ASI03"], "WALLET-BROWSER-THEFT": ["ASI03"],
    "CREDENTIAL-PROMPT": ["ASI09", "ASI03"], "PRIVILEGE-ESCALATION": ["ASI03"], "PRIVILEGE-GRANT": ["ASI03", "ASI02"],
    "PERMISSION-WILDCARD": ["ASI03"], "DISABLE-SAFEGUARDS": ["ASI03", "ASI09"], "CODEX-FULL-ACCESS": ["ASI03"],
    "GEMINI-TRUST-OFF": ["ASI03"], "VSCODE-AUTOAPPROVE": ["ASI03", "ASI05"], "REVIEW-BYPASS": ["ASI09"],
    "RAW-IP-URL": ["ASI02"], "PLAIN-HTTP": ["ASI02"], "SUSPICIOUS-TLD": ["ASI02"], "UNLISTED-DOMAIN": ["ASI02"],
    "PUNYCODE": ["ASI09"], "SKILL-TRIGGER-HIJACK": ["ASI01", "ASI04"], "TOOL-SHADOWING": ["ASI02", "ASI04"],
}
for rule in ("GITHUB", "AWS", "AI-API", "SLACK", "NPM", "GOOGLE", "JWT", "PRIVATE-KEY", "ASSIGNMENT", "URL", "AUTH-VALUE"):
    RULES[f"SECRET-{rule}"] = SECRET
    ASI_RULES[f"SECRET-{rule}"] = ["ASI03"]

# Agent-specific controls first; at most four ATLAS mitigations per technique are shown.
PREFERENCE = ["AML.M0033", "AML.M0030", "AML.M0029", "AML.M0026", "AML.M0027", "AML.M0028", "AML.M0032",
              "AML.M0020", "AML.M0021", "AML.M0011", "AML.M0014", "AML.M0013", "AML.M0023", "AML.M0016",
              "AML.M0018", "AML.M0005", "AML.M0031", "AML.M0024", "AML.M0022", "AML.M0035"]

# Shown when ATLAS publishes no mitigation for a technique; labelled as AgentLens guidance in the UI.
GUIDANCE = {
    "AML.T0110": "Pin skills and MCP servers to reviewed versions, review tool descriptions for instructions aimed at the agent, and alert when a tool or skill changes after approval.",
    "AML.T0073": "Treat claims of prior approval, trusted authorship or look-alike domains in instructions as untrusted; verify out of band and keep human approval for sensitive actions.",
    "AML.T0012": "Give agents dedicated least-privilege identities and require human approval for any change to roles, group membership or collaborators.",
    "AML.T0131": "Do not embed pre-filled AI assistant links in docs or instructions; strip query prompts and review memory changes after clicking such links.",
    "AML.T0100": "Block agents from following on-page 'verify you are human' steps that move text into a shell; require human approval for shell commands.",
    "AML.T0108": "Deny agents arbitrary egress and never execute content fetched from remote endpoints without review.",
    "AML.T0080.000": "Review and prune assistant memories regularly and require confirmation before memories are created from untrusted content.",
    "AML.T0103": "Constrain agent tool use to the declared task, deny offensive tooling and scanning by default, and log and review tool invocations.",
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
    if set(ASI_RULES) != set(RULES):
        raise SystemExit(f"OWASP ASI mapping differs from rules: {sorted(set(ASI_RULES) ^ set(RULES))}")
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
        "owasp_asi": {
            "source": "OWASP Top 10 for Agentic Applications 2026",
            "url": OWASP_URL,
            "risks": ASI,
            "rules": {rule: ASI_RULES[rule] for rule in sorted(RULES)},
        },
    }
    target = Path(__file__).resolve().parents[1] / "web" / "atlas.json"
    target.write_text(json.dumps(data, indent=1) + "\n")
    print(f"Wrote {target} ({len(out_tech)} techniques, {len(used_mitigations)} mitigations, {len(RULES)} rules)")


if __name__ == "__main__":
    main(sys.argv[1])
