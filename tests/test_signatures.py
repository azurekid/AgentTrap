import json
from pathlib import Path

import pytest

from web.repository import decode_document
from web.signatures import inspect_signatures, publishers

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def trust_store(tmp_path, monkeypatch):
    trust = tmp_path / "publishers.json"
    trust.write_text(json.dumps([{"publisher": "AgentLens Fixture Publisher (TEST ONLY)",
                                 "certificate": str(ROOT / "use-cases/signature-test-root.pem")}]))
    monkeypatch.setenv("SKILL_TRUST_STORE", str(trust))
    return trust


def sample_documents(case_id):
    directory = ROOT / "use-cases/supply-chain" / case_id
    case = json.loads((directory / "use-case.json").read_text())
    docs = []
    import hashlib
    for artifact in case["artifacts"]:
        content = (directory / artifact["path"]).read_bytes()
        doc = decode_document(artifact["scan_as"], content)
        doc["raw_sha256"] = hashlib.sha256(content).hexdigest()
        docs.append(doc)
    return docs


@pytest.mark.parametrize("case_id,expected", [
    ("SC-014", "verified"), ("SC-015", "invalid"), ("SC-016", "invalid"),
    ("SC-017", "not_verifiable"), ("SC-018", "unsigned"), ("SC-019", "invalid"),
])
def test_oms_use_cases(trust_store, case_id, expected):
    results = inspect_signatures(sample_documents(case_id))
    outcome = results["skills/oms-review/SKILL.md"]
    assert outcome["status"] == expected, outcome
    assert outcome["identity_verified"] == (expected == "verified")
    assert outcome["reputation"] == "not_assessed"
    assert "Revocation" in outcome["limitations"]
    if expected == "verified":
        assert outcome["publisher"] == "AgentLens Fixture Publisher (TEST ONLY)"
        assert len(outcome["signer_sha256"]) == 64


def test_submitted_certificate_is_never_a_trust_anchor(monkeypatch):
    monkeypatch.delenv("SKILL_TRUST_STORE", raising=False)
    outcome = next(iter(inspect_signatures(sample_documents("SC-014")).values()))
    assert outcome["status"] == "untrusted"
    assert outcome["identity_verified"] is False
    assert outcome["performed"] is False


def test_incomplete_repository_scope_cannot_verify(trust_store):
    docs = sample_documents("SC-014")
    next(doc for doc in docs if doc["path"].endswith("SKILL.md"))["signature_scope_complete"] = "false"
    assert next(iter(inspect_signatures(docs).values()))["status"] == "not_verifiable"


def test_raw_bytes_including_bom_are_verified(trust_store):
    docs = sample_documents("SC-014")
    skill = next(doc for doc in docs if doc["path"].endswith("SKILL.md"))
    import hashlib
    skill["raw_sha256"] = hashlib.sha256(("\ufeff" + skill["text"]).encode()).hexdigest()
    assert next(iter(inspect_signatures(docs).values()))["status"] == "invalid"


def test_untrusted_root_rejects_bundle(trust_store, tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timezone
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated Test Root")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(42).not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2036, 1, 1, tzinfo=timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA384()))
    root = tmp_path / "unrelated.pem"
    root.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    trust_store.write_text(json.dumps([{"publisher": "Wrong publisher", "certificate": str(root)}]))
    assert next(iter(inspect_signatures(sample_documents("SC-014")).values()))["status"] == "invalid"


def test_bad_operator_configuration_fails_explicitly(trust_store):
    trust_store.write_text('{"not":"a list"}')
    with pytest.raises(ValueError, match="publisher entries"):
        publishers()


def test_missing_raw_byte_evidence_prevents_verified_label(trust_store):
    docs = sample_documents("SC-014")
    docs[0].pop("raw_sha256")
    assert next(iter(inspect_signatures(docs).values()))["status"] == "not_verifiable"


def test_expired_certificates_do_not_use_issuance_time(trust_store, monkeypatch):
    import web.signatures as module
    from datetime import datetime, timezone
    class FutureDate(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2037, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(module, "datetime", FutureDate)
    outcome = next(iter(inspect_signatures(sample_documents("SC-014")).values()))
    assert outcome["status"] == "invalid"
    assert "expired" in outcome["message"]


def test_verification_policy_changes_evaluation_not_content(trust_store):
    from web.artifacts import identify
    docs = sample_documents("SC-014")
    def artifacts():
        signatures = inspect_signatures(docs)
        files = [{"path": doc["path"], "findings": [], **({"signature": signatures[doc["path"]]} if doc["path"] in signatures else {})}
                 for doc in docs]
        return identify(files, docs, "a" * 64, False, {})[0]
    original = artifacts()
    trust = json.loads(trust_store.read_text())
    trust[0]["publisher"] = "New operator publisher policy"
    trust_store.write_text(json.dumps(trust))
    changed = artifacts()
    assert changed["content_id"] == original["content_id"]
    assert changed["evaluation_id"] != original["evaluation_id"]


def test_certificate_verification_makes_no_network_connections(trust_store, monkeypatch):
    import socket
    def deny_network(*args, **kwargs):
        raise AssertionError("Offline verification attempted a network connection")
    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    assert next(iter(inspect_signatures(sample_documents("SC-014")).values()))["status"] == "verified"


def test_single_line_oms_bundles_are_bounded_by_file_limit_not_prompt_line_limit(trust_store):
    docs = sample_documents("SC-014")
    signature = next(doc for doc in docs if doc["path"].endswith("skill.oms.sig"))
    content = (" " * 9000 + json.dumps(json.loads(signature["text"]), separators=(",", ":"))).encode()
    signature.update(decode_document(signature["path"], content))
    assert next(iter(inspect_signatures(docs).values()))["status"] == "verified"
    from web.repository import MAX_FILE, ScanInputError
    with pytest.raises(ScanInputError, match="256 KiB"):
        decode_document(signature["path"], b" " * (MAX_FILE + 1))


def test_forged_manifest_with_matching_package_hashes_cannot_verify(trust_store):
    import base64
    import hashlib
    docs = sample_documents("SC-014")
    signature = next(doc for doc in docs if doc["path"].endswith("skill.oms.sig"))
    bundle = json.loads(signature["text"])
    payload = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    skill = next(doc for doc in docs if doc["path"].endswith("SKILL.md"))
    skill["text"] += "\nChanged after signing.\n"
    skill["raw_sha256"] = hashlib.sha256(skill["text"].encode()).hexdigest()
    resources = payload["predicate"]["resources"]
    next(resource for resource in resources if resource["name"] == "SKILL.md")["digest"] = skill["raw_sha256"]
    payload["subject"][0]["digest"]["sha256"] = hashlib.sha256(b"".join(bytes.fromhex(r["digest"]) for r in resources)).hexdigest()
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    signature["text"] = json.dumps(bundle)
    outcome = next(iter(inspect_signatures(docs).values()))
    assert outcome["status"] == "invalid"
    assert "signature or certificate chain" in outcome["message"]


@pytest.mark.parametrize("replacement", [
    "../outside", "/absolute", "references/../outside", "SKILL.md",
])
def test_manifest_paths_and_duplicates_are_rejected(trust_store, replacement):
    import base64
    docs = sample_documents("SC-014")
    signature = next(doc for doc in docs if doc["path"].endswith("skill.oms.sig"))
    bundle = json.loads(signature["text"])
    payload = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    payload["predicate"]["resources"][1]["name"] = replacement
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    signature["text"] = json.dumps(bundle)
    assert next(iter(inspect_signatures(docs).values()))["status"] == "invalid"
