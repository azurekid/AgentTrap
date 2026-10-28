import hashlib
import json

import pytest

from web.atlas import DATA
from web.evaluation import CATEGORIES, RULE_CATEGORY, VERSION, WEIGHTS, evaluate, methodology


def finding(rule="PROMPT-INJECTION", severity="HIGH"):
    return {"rule": rule, "severity": severity, "line": 1, "message": "Test signal", "snippet": "text"}


def test_categories_cover_all_detectors_without_duplicates():
    rules = [rule for c in CATEGORIES for rule in c["rules"].split()]
    assert len(set(rules)) == len(rules)
    assert set(rules) == set(DATA["rules"])


def test_score_deduplicates_rule_across_lines_and_files():
    files = [
        {"path": "SKILL.md", "findings": [finding(), finding(), finding("SECRET-AWS", "CRITICAL")]},
        {"path": "AGENTS.md", "findings": [finding()]},
    ]
    evaluation, _ = evaluate(files, [], "complete")
    assert evaluation["score"] == WEIGHTS["HIGH"] + WEIGHTS["CRITICAL"]
    assert evaluation["decision"] == "review_required"
    assert evaluation["highest_severity"] == "CRITICAL"
    categories = {c["id"]: c for c in evaluation["categories"]}
    assert categories["instruction-control"]["findings"] == 3
    assert categories["credentials"]["rules"] == ["SECRET-AWS"]
    assert categories["data-egress"]["highest_severity"] is None
    assert files[0]["findings"][0]["category"] == "instruction-control"


def test_score_uses_highest_rule_severity_and_caps_at_100():
    files = [{"path": "SKILL.md", "findings": [
        finding(severity="LOW"), finding(severity="CRITICAL"),
        finding("SECRET-AWS", "CRITICAL"), finding("REVERSE-SHELL", "CRITICAL"),
    ]}]
    assert evaluate(files, [], "complete")[0]["score"] == 100
    for severity in WEIGHTS:
        files[0]["findings"] = [finding(severity=severity)]
        result = evaluate(files, [], "complete")[0]
        assert result["score"] == WEIGHTS[severity]
        assert result["decision"] == "review_required"


@pytest.mark.parametrize("status", ["partial", "no_targets"])
@pytest.mark.parametrize("findings", [[], [finding()]])
def test_incomplete_evaluations_never_get_a_score(status, findings):
    evaluation, _ = evaluate([{"path": "SKILL.md", "findings": findings}], [], status)
    assert evaluation["score"] is None
    assert evaluation["decision"] == "incomplete"


def test_zero_is_not_a_safety_verdict():
    evaluation, _ = evaluate([{"path": "SKILL.md", "findings": []}], [], "complete")
    assert evaluation["score"] == 0
    assert evaluation["decision"] == "no_signals"
    assert evaluation["highest_severity"] is None
    assert all(c["findings"] == 0 for c in evaluation["categories"])
    checks = {c["id"]: c["performed"] for c in evaluation["checks"]}
    assert checks == {"static": True, "secrets": True, "execution": False, "reputation": False, "publisher": False,
                      "signatures": False, "dependencies": False, "mcp": False, "decoding": True}


def test_manifest_is_order_independent_and_content_bound():
    docs = [{"path": "SKILL.md", "text": "Hi \u00e9\r\n"}, {"path": "config.json", "text": "{}"}]
    _, provenance = evaluate([], docs, "complete")
    assert provenance == evaluate([], list(reversed(docs)), "complete")[1]
    assert provenance["files"][0] == {
        "path": "SKILL.md", "bytes": len(docs[0]["text"].encode("utf-8")),
        "sha256": hashlib.sha256(docs[0]["text"].encode("utf-8")).hexdigest(),
    }
    original = provenance["manifest_sha256"]
    docs[0]["text"] += "changed"
    assert evaluate([], docs, "complete")[1]["manifest_sha256"] != original
    docs[0]["text"] = "Hi \u00e9\r\n"
    docs[0]["path"] = "renamed.md"
    assert evaluate([], docs, "complete")[1]["manifest_sha256"] != original
    assert "not a raw-download hash" in provenance["hash_scope"]
    assert len(provenance["detector_sha256"]) == 64


def test_methodology_exposes_all_rule_assignments():
    method = methodology()
    assert method["version"] == VERSION
    assert method["score"]["weights"] == WEIGHTS
    assert {rule: c["id"] for c in method["categories"] for rule in c["rules"]} == RULE_CATEGORY
    assert "safety certification" in method["score"]["limitations"]
    assert "partial" in method["score"]["unavailable_when"]
    assert len(json.dumps(method)) > 0


def test_empty_scan_does_not_claim_checks_were_performed():
    evaluation, _ = evaluate([], [], "no_targets")
    assert not any(check["performed"] for check in evaluation["checks"])


@pytest.mark.parametrize("signature_status,performed,expected", [
    ("verified", True, "performed"), ("invalid", True, "performed"),
    ("untrusted", False, "blocked"), ("not_verifiable", False, "blocked"),
    ("not_verifiable", True, "incomplete"), ("unsupported", False, "blocked"),
    ("unsigned", False, "not_applicable"),
])
def test_signature_coverage_reports_execution_not_trust_verdict(signature_status, performed, expected):
    files = [{"path": "SKILL.md", "findings": [], "signature": {
        "status": signature_status, "performed": performed, "message": "Explicit signature outcome",
    }}]
    checks = {check["id"]: check for check in evaluate(files, [], "complete")[0]["checks"]}
    for key in ("signatures", "publisher"):
        assert checks[key]["status"] == expected
        assert checks[key]["performed"] is performed
    for key in ("reputation", "execution", "dependencies"):
        assert checks[key]["status"] == "not_supported"
    assert checks["mcp"]["status"] == "not_applicable"


def test_mixed_signature_and_partial_mcp_coverage_are_not_reported_as_unchecked():
    files = [
        {"path": "one/SKILL.md", "findings": [], "signature": {
            "status": "verified", "performed": True, "message": "Verified bytes"}},
        {"path": "two/SKILL.md", "findings": [], "signature": {
            "status": "untrusted", "performed": False, "message": "No configured certificate"}},
        {"path": "mcp.json", "findings": [], "mcp": {"status": "incomplete"}},
    ]
    checks = {check["id"]: check for check in evaluate(files, [], "partial")[0]["checks"]}
    for key in ("signatures", "publisher", "mcp"):
        assert checks[key]["status"] == "incomplete"
        assert checks[key]["performed"] is True
    assert "No configured certificate" in checks["signatures"]["detail"]


def test_complete_mcp_definitions_are_reported_as_checked():
    checks = evaluate([{"path": "mcp.json", "findings": [], "mcp": {"status": "complete"}}], [], "complete")[0]["checks"]
    mcp = next(check for check in checks if check["id"] == "mcp")
    assert mcp["status"] == "performed"
    assert mcp["performed"] is True
