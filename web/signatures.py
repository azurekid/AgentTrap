"""Offline NVIDIA-style OMS verification against operator-provisioned certificates."""
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from OpenSSL import crypto

from web.repository import MAX_FILES, safe_path

SIGNATURE_NAME = "skill.oms.sig"


def publishers() -> list[dict]:
    location = os.environ.get("SKILL_TRUST_STORE")
    if not location:
        return []
    path = Path(location)
    if not path.is_absolute() or path.stat().st_size > 64 * 1024:
        raise ValueError("SKILL_TRUST_STORE must be a bounded, absolute operator configuration path.")
    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        raise ValueError("SKILL_TRUST_STORE must contain 1 to 16 publisher entries.")
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {"publisher", "certificate"}
                or not isinstance(entry["publisher"], str) or not 1 <= len(entry["publisher"]) <= 160
                or any(ord(char) < 32 for char in entry["publisher"])
                or not isinstance(entry["certificate"], str)):
            raise ValueError("Invalid trusted publisher entry.")
        certificate = Path(entry["certificate"])
        if not certificate.is_absolute() or certificate.stat().st_size > 64 * 1024:
            raise ValueError("Publisher certificate must be a bounded absolute path.")
        if not x509.load_pem_x509_certificates(certificate.read_bytes()):
            raise ValueError("Publisher certificate file is empty.")
    return entries


def result(status: str, message: str, *, performed: bool = False, publisher: str | None = None,
           signer_sha256: str | None = None) -> dict:
    return {"format": "NVIDIA-style OMS", "status": status, "message": message,
            "performed": performed, "publisher": publisher, "signer_sha256": signer_sha256,
            "identity_verified": status == "verified", "reputation": "not_assessed",
            "scope": "Submitted package bytes; file modes and runtime behavior are not attested.",
            "limitations": "Offline certificate verification. Revocation, timestamp and publisher reputation are not checked. A signature is not a safety certification."}


def verify_skill(documents: list[dict], complete: bool, trust: list[dict]) -> dict:
    signature = next((doc for doc in documents if doc["relative_path"] == SIGNATURE_NAME), None)
    if signature is None:
        return result("unsigned", "No skill.oms.sig was submitted for this skill.")
    if not complete:
        return result("not_verifiable", "The repository package listing is incomplete or contains files outside inspection support. Submit all package files.")
    if not trust:
        return result("untrusted", "A signature is present, but no operator-trusted publisher certificates are configured.")
    # model-signing 1.1.1 exposes authenticated manifests through this pinned adapter.
    from model_signing._signing.sign_certificate import Verifier
    from model_signing._signing.sign_sigstore_pb import Signature
    from sigstore_models.bundle import v1 as bundle

    try:
        parsed = json.loads(signature["text"])
        envelope = parsed["dsseEnvelope"]
        payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
        if (payload.get("predicateType") != "https://model_signing/signature/v1.0"
                or payload.get("_type") != "https://in-toto.io/Statement/v1"):
            return result("unsupported", "Only OMS v1.0 in-toto certificate bundles are supported.")
        serialization = payload["predicate"]["serialization"]
        if (serialization.get("method") != "files" or serialization.get("hash_type") != "sha256"
                or serialization.get("allow_symlinks") is not False):
            return result("unsupported", "Only file-level SHA256 OMS bundles without symlinks are supported.")
        resources = payload["predicate"]["resources"]
        if not isinstance(resources, list) or not 1 <= len(resources) <= MAX_FILES:
            raise ValueError("Invalid resource count")
        expected = {}
        for resource in resources:
            name = safe_path(resource["name"])
            digest = resource["digest"]
            if (name in expected or resource["algorithm"] != "sha256"
                    or not isinstance(digest, str) or len(bytes.fromhex(digest)) != 32):
                raise ValueError("Invalid resource")
            expected[name] = digest.lower()
        material = parsed["verificationMaterial"]["x509CertificateChain"]["certificates"]
        if not isinstance(material, list) or not 1 <= len(material) <= 8:
            raise ValueError("Invalid certificate chain")
        certificates = [x509.load_der_x509_certificate(base64.b64decode(item["rawBytes"], validate=True))
                        for item in material]
        now = datetime.now(timezone.utc)
        if any(not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc for certificate in certificates):
            return result("invalid", "The signing certificate chain is expired or not yet valid.", performed=True)
        signer_sha256 = certificates[0].fingerprint(hashes.SHA256()).hex()
        parsed["verificationMaterial"].setdefault("tlogEntries", [])
        oms_signature = Signature(bundle.Bundle.from_dict(parsed))
        trusted = None
        for entry in trust:
            try:
                # The pinned OMS verifier uses certificate issuance time. Also validate
                # the chain at current time, with no network or submitted trust anchors.
                store = crypto.X509Store()
                for certificate in x509.load_pem_x509_certificates(Path(entry["certificate"]).read_bytes()):
                    store.add_cert(crypto.X509.from_cryptography(certificate))
                crypto.X509StoreContext(store, crypto.X509.from_cryptography(certificates[0]),
                                        [crypto.X509.from_cryptography(cert) for cert in certificates[1:]]).verify_certificate()
                Verifier([Path(entry["certificate"])]).verify(oms_signature)
                trusted = entry["publisher"]
                break
            except (crypto.X509StoreContextError, InvalidSignature, ValueError):
                continue
        if trusted is None:
            return result("invalid", "The OMS signature or certificate chain could not be verified against configured publishers.",
                          performed=True, signer_sha256=signer_sha256)
        actual = {}
        for doc in documents:
            if doc is signature:
                continue
            name = doc["relative_path"]
            if name in actual:
                raise ValueError("Duplicate submitted package path")
            if not doc.get("raw_sha256"):
                return result("not_verifiable", "Exact raw-byte hashes are unavailable for part of this package.",
                              performed=True, signer_sha256=signer_sha256)
            actual[name] = doc["raw_sha256"]
        if set(expected) - set(actual):
            return result("not_verifiable", "Files listed in the signed manifest are missing from the submitted package.",
                          performed=True, signer_sha256=signer_sha256)
        if set(actual) - set(expected):
            return result("invalid", "Additional unsigned files were submitted. Strict verification rejects unsigned additions.",
                          performed=True, signer_sha256=signer_sha256)
        if expected != actual:
            return result("invalid", "Package bytes do not match the signed manifest.",
                          performed=True, signer_sha256=signer_sha256)
        return result("verified", "All submitted package files match the authenticated OMS manifest and operator-trusted certificate chain.",
                      performed=True, publisher=trusted, signer_sha256=signer_sha256)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, RecursionError, crypto.Error) as exc:
        return result("invalid", f"Malformed or invalid OMS bundle ({type(exc).__name__}).", performed=True)


def inspect_signatures(documents: list[dict]) -> dict[str, dict]:
    roots = {str(PurePosixPath(doc["path"]).parent): doc for doc in documents
             if PurePosixPath(doc["path"]).name.lower() == "skill.md"}
    results = {}
    trust = publishers()
    policy = hashlib.sha256(json.dumps([
        {"publisher": entry["publisher"], "certificate_sha256": hashlib.sha256(Path(entry["certificate"]).read_bytes()).hexdigest()}
        for entry in trust
    ], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    for root, skill in roots.items():
        members = []
        for doc in documents:
            parents = [candidate for candidate in roots if candidate == "." or doc["path"].startswith(candidate + "/")]
            if not parents or max(parents, key=len) != root:
                continue
            relative = str(PurePosixPath(doc["path"]).relative_to(root)) if root != "." else doc["path"]
            members.append({**doc, "relative_path": relative})
        complete = skill.get("signature_scope_complete", "true") == "true"
        results[skill["path"]] = {**verify_skill(members, complete, trust), "verification_policy_sha256": policy}
    return results
