"""Versioned, evidence-based summaries. Signal scores are not safety probabilities."""
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from scan_agents_md import SEV
from web.atlas import DATA

VERSION = "signal-risk-v1"
WEIGHTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 5, "LOW": 1}
ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = [
    {
        "id": "instruction-control", "name": "Instruction control",
        "guidance": "Review instruction priority, hidden text and tool descriptions. Remove overrides and require explicit user intent for sensitive actions.",
        "rules": "PROMPT-INJECTION FAKE-SYSTEM-TAG JAILBREAK-PERSONA HIDDEN-COMMENT HIDDEN-HTML-TEXT "
                 "SKILL-TRIGGER-HIJACK TOOL-SHADOWING REVIEW-BYPASS MEMORY-POISONING OFFENSIVE-TASKING",
    },
    {
        "id": "credentials", "name": "Credentials and identity",
        "guidance": "If a credential is real, revoke and rotate it, remove it from files and history, and review access logs. Use scoped secret injection instead of embedded values.",
        "rules": "AUTH-HEADER CRED-FILES CREDENTIAL-PROMPT OAUTH-TOKEN URL-CREDENTIALS WALLET-BROWSER-THEFT "
                 "SECRET-AI-API SECRET-ASSIGNMENT SECRET-AUTH-VALUE SECRET-AWS SECRET-GITHUB SECRET-GOOGLE "
                 "SECRET-JWT SECRET-NPM SECRET-PRIVATE-KEY SECRET-SLACK SECRET-URL",
    },
    {
        "id": "data-egress", "name": "Data egress",
        "guidance": "Trace which data leaves the machine and where it goes. Remove unapproved destinations and require consent before transmitting files, credentials or environment variables.",
        "rules": "EXFIL-ENV FILE-EXFIL DNS-EXFIL GH-CLI-EXFIL TOOL-EXFIL MARKDOWN-IMAGE-EXFIL "
                 "AI-PREFILL-LINK ANSI-ESCAPE-EXFIL CI-SECRET-LEAK CLOUD-METADATA",
    },
    {
        "id": "execution", "name": "Execution and persistence",
        "guidance": "Do not execute the submitted content to investigate it. Inspect hooks and scripts, remove destructive or persistent actions, and pin and review downloaded code before use.",
        "rules": "PIPE-TO-SHELL REVERSE-SHELL DESTRUCTIVE WIPER-INSTRUCTION PERSISTENCE WORM-PROPAGATION "
                 "REMOTE-COMMANDS EXEC-HIJACK CLICKFIX CLAUDE-HOOKS CLAUDE-APIKEYHELPER VSCODE-TASK-AUTORUN "
                 "INSTALL-FROM-URL INSTALL-SCRIPTS NPM-INSTALL NPX-YES AUTHORITATIVE-INSTALL",
    },
    {
        "id": "permissions", "name": "Permissions and safeguards",
        "guidance": "Restore approval prompts and safety controls. Limit command, filesystem and MCP access to the minimum needed; verify the effective agent configuration.",
        "rules": "AI-CLI-SAFETY-BYPASS CODEX-FULL-ACCESS DISABLE-SAFEGUARDS GEMINI-TRUST-OFF "
                 "MCP-CONFIG PERMISSION-WILDCARD PRIVILEGE-ESCALATION PRIVILEGE-GRANT VSCODE-AUTOAPPROVE "
                 "CI-WORKFLOW-WRITE ANTI-FORENSICS",
    },
    {
        "id": "obfuscation", "name": "Obfuscation",
        "guidance": "Decode suspicious content as data, never as commands. Inspect invisible characters and encoded instructions alongside the original text.",
        "rules": "BASE64-BLOB BASE64-PAYLOAD HIDDEN-UNICODE OBFUSCATION UNICODE-TAG-SMUGGLING "
                 "VARIATION-SELECTOR-SMUGGLING",
    },
    {
        "id": "supply-chain", "name": "Supply chain and destinations",
        "guidance": "Verify source ownership, dependency provenance and network destinations. A listed domain or package is a review signal, not proof of maliciousness.",
        "rules": "KNOWN-IOC PLAIN-HTTP PUNYCODE RAW-IP-URL REGISTRY-REDIRECT SUSPICIOUS-TLD "
                 "TRAFFIC-REDIRECT TUNNEL-OAST UNLISTED-DOMAIN UNTRUSTED-LOCATION",
    },
]
RULE_CATEGORY = {rule: category["id"] for category in CATEGORIES for rule in category["rules"].split()}
if set(RULE_CATEGORY) != set(DATA["rules"]):
    raise ValueError("Evaluation categories must cover every detector exactly.")
if sum(len(c["rules"].split()) for c in CATEGORIES) != len(RULE_CATEGORY):
    raise ValueError("Each detector must belong to exactly one evaluation category.")


@lru_cache(maxsize=1)
def detector_fingerprint() -> str:
    digest = hashlib.sha256()
    for name in ("scan_agents_md.py", "credential_rules.json", "allowlist.json", "web/atlas.json",
                 "web/evaluation.py", "web/mcp.py", "web/decoding.py", "web/artifacts.py", "web/scan_worker.py", "web/repository.py", "web/signatures.py"):
        content = (ROOT / name).read_bytes()
        digest.update(name.encode() + b"\0" + str(len(content)).encode() + b"\0" + content)
    return digest.hexdigest()


def methodology() -> dict:
    return {
        "version": VERSION,
        "detector_sha256": detector_fingerprint(),
        "score": {
            "name": "Signal risk score", "range": [0, 100], "higher_is": "more detected rule evidence",
            "weights": WEIGHTS,
            "formula": "min(100, sum(weight of highest severity per distinct rule across all inspected files))",
            "unavailable_when": ["partial", "no_targets"],
            "limitations": "Not a probability, malware classification, trust rating or safety certification. "
                           "Repeated hits of one rule do not increase the score. Scores are comparable only "
                           "with the same methodology, detector fingerprint and scan scope.",
        },
        "categories": [{**category, "rules": category["rules"].split()} for category in CATEGORIES],
        "checks": [
            {"id": "static", "name": "Static pattern analysis", "performed": True},
            {"id": "secrets", "name": "Embedded-secret pattern detection (not provider validation)", "performed": True},
            {"id": "mcp", "name": "Decoded JSON MCP tool-definition inspection (when applicable)", "performed": True},
            {"id": "decoding", "name": "Bounded encoded-text inspection (base64, hex and percent encodings)", "performed": True},
            {"id": "execution", "name": "Sandbox or runtime execution", "performed": False},
            {"id": "publisher", "name": "Publisher certificate identity verification (when applicable)", "performed": False},
            {"id": "reputation", "name": "Publisher reputation assessment", "performed": False},
            {"id": "signatures", "name": "NVIDIA-style OMS skill signature verification (when applicable)", "performed": False},
            {"id": "dependencies", "name": "Installed dependency or remote-content inspection", "performed": False},
        ],
        "hash_scope": "SHA256 of inspected text re-encoded as UTF-8 after removal of an optional UTF-8 BOM; "
                      "not a raw-download hash or a signed attestation.",
    }


def inspection_checks(files: list[dict]) -> list[dict]:
    signatures = [file["signature"] for file in files if file.get("signature")]
    results = []
    for check in methodology()["checks"]:
        key = check["id"]
        state, detail = "not_supported", "This inspection does not perform this check."
        if key in ("static", "secrets", "decoding"):
            state = "performed" if files else "not_applicable"
            detail = "Inspected submitted files." if files else "No files were inspected."
            if key == "decoding" and any(file.get("decoding", {}).get("status") == "incomplete" for file in files):
                state, detail = "incomplete", "Encoded-text inspection ran but coverage limits were reached."
        elif key == "mcp":
            mcp = [file["mcp"] for file in files if file.get("mcp", {}).get("status") in ("complete", "incomplete")]
            state = "incomplete" if any(item["status"] == "incomplete" for item in mcp) else "performed" if mcp else "not_applicable"
            detail = "Saved MCP tool definitions inspected; no running server contacted." if mcp else "No saved MCP tool definitions detected."
        elif key in ("publisher", "signatures"):
            present = [item for item in signatures if item["status"] != "unsigned"]
            if not present:
                state, detail = "not_applicable", "No supported skill.oms.sig bundle is available for a skill package."
            else:
                performed = sum(bool(item.get("performed")) for item in present)
                state = "blocked" if not performed else "incomplete"
                if performed == len(present) and all(item["status"] != "not_verifiable" for item in present):
                    state = "performed"
                outcomes = ", ".join(sorted({item["status"].replace("_", " ") for item in present}))
                detail = f"Bundle outcomes: {outcomes}. " + " ".join(dict.fromkeys(item["message"] for item in present))
        results.append({**check, "performed": state in ("performed", "incomplete"),
                        "status": state, "detail": detail})
    return results


def evaluate(files: list[dict], documents: list[dict[str, str]], status: str) -> tuple[dict, dict]:
    grouped: dict[str, list[dict]] = {c["id"]: [] for c in CATEGORIES}
    rule_severities: dict[str, str] = {}
    for file in files:
        for finding in file["findings"]:
            category = RULE_CATEGORY[finding["rule"]]
            finding["category"] = category
            grouped[category].append(finding)
            rule = finding["rule"]
            if rule not in rule_severities or SEV[finding["severity"]] > SEV[rule_severities[rule]]:
                rule_severities[rule] = finding["severity"]
    categories = []
    for category in CATEGORIES:
        hits = grouped[category["id"]]
        categories.append({
            "id": category["id"], "name": category["name"], "guidance": category["guidance"],
            "findings": len(hits), "rules": sorted({f["rule"] for f in hits}),
            "highest_severity": max((f["severity"] for f in hits), key=SEV.get, default=None),
        })
    assessment = {
        "version": VERSION,
        "score": min(100, sum(WEIGHTS[s] for s in rule_severities.values())) if status == "complete" else None,
        "highest_severity": max(rule_severities.values(), key=SEV.get, default=None),
        "decision": "incomplete" if status != "complete" else ("review_required" if rule_severities else "no_signals"),
        "categories": categories,
        "checks": inspection_checks(files),
        "methodology_url": "/api/methodology",
    }
    manifest = []
    for document in sorted(documents, key=lambda d: d["path"]):
        content = document["text"].encode("utf-8")
        manifest.append({"path": document["path"], "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    provenance = {
        "detector_sha256": detector_fingerprint(),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "hash_scope": methodology()["hash_scope"], "files": manifest,
    }
    return assessment, provenance
