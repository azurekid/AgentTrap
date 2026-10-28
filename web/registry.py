"""Central fingerprints and public, sanitized assessment summaries. Never stores original content."""
from collections import Counter
import json
import os
import re
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from azure.core import MatchConditions
from azure.core.exceptions import AzureError, ResourceExistsError, ResourceModifiedError, ResourceNotFoundError

from web.evaluation import evaluate
from web.atlas import TACTIC_ORDER, annotate
from scan_agents_md import SECRET_RULES

METRICS = ("skill_snapshots", "complete_skill_versions", "mcp_snapshots", "agent_files", "evaluations", "findings")
SHARDS = "0123456789abcdef"
MAX_SHARD_BYTES = 2 * 1024 * 1024
MAX_HASH_MATCHES = 64
MAX_PUBLIC_EXCERPTS = 24
DIGEST = re.compile(r"[0-9a-f]{64}")


class RegistryError(RuntimeError):
    pass


class Registry:
    def __init__(self, archive):
        self.container = archive.container
        self.directory = archive.directory / "uniqueness-v1"
        self.lock = threading.RLock()
        self.cached = None
        self.cached_at = 0.0
        if self.container is None:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            for shard in SHARDS:
                self._merge(shard, {}, prune=True)
        except (OSError, AzureError, ValueError, TypeError) as exc:
            raise RegistryError("Historical fingerprint cleanup failed.") from exc

    @staticmethod
    def _qualifies(summary: dict) -> bool:
        return any(summary["severities"][severity] > 0 for severity in ("HIGH", "CRITICAL"))

    @staticmethod
    def _empty() -> dict:
        return {"since": datetime.now(timezone.utc).isoformat(), "sets": {key: [] for key in METRICS}}

    @staticmethod
    def _decode(payload: bytes) -> dict:
        if len(payload) > MAX_SHARD_BYTES:
            raise RegistryError("Uniqueness storage shard exceeds its supported capacity.")
        data = json.loads(payload)
        if (not isinstance(data, dict) or not {"since", "sets"} <= set(data)
                or set(data) - {"since", "sets", "reports", "text_hashes", "file_hashes"}
                or not isinstance(data["since"], str) or not isinstance(data["sets"], dict)
                or set(data["sets"]) != set(METRICS)):
            raise RegistryError("Invalid uniqueness record.")
        datetime.fromisoformat(data["since"])
        for values in data["sets"].values():
            if not isinstance(values, list) or any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in values):
                raise RegistryError("Invalid uniqueness digest.")
            if len(values) != len(set(values)):
                raise RegistryError("Duplicate uniqueness digest in storage.")
        if "reports" in data and (
            not isinstance(data["reports"], dict)
            or any(not DIGEST.fullmatch(key) or not isinstance(value, dict)
                   for key, value in data["reports"].items())
        ):
            raise RegistryError("Invalid stored fingerprint reports.")
        for digest, summary in data.get("reports", {}).items():
            if (set(summary) - {"name", "name_source", "evidence", "atlas", "signature"} != {"content_id", "kind", "evaluation_id", "package_complete", "inspection_status",
                                 "first_seen", "last_seen", "detector_sha256", "file_count", "assessment",
                                 "findings", "severities", "rules"}
                    or summary["content_id"] != digest or summary["kind"] not in ("skill_snapshot", "mcp_snapshot", "agent_file")
                    or not isinstance(summary["assessment"], dict)
                    or set(summary["assessment"]) != {"version", "score", "highest_severity", "decision", "categories", "checks", "methodology_url"}
                    or not isinstance(summary["severities"], dict)
                    or set(summary["severities"]) != {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
                    or any(type(value) is not int or value < 0 for value in summary["severities"].values())
                    or summary["findings"] != sum(summary["severities"].values())):
                raise RegistryError("Invalid stored fingerprint assessment.")
            if summary.get("name") is not None and (not isinstance(summary["name"], str) or len(summary["name"]) > 160):
                raise RegistryError("Invalid stored frontmatter name.")
            if summary.get("signature") is not None:
                signature = summary["signature"]
                if (not isinstance(signature, dict)
                        or set(signature) != {"format", "status", "message", "performed", "publisher", "signer_sha256",
                                              "identity_verified", "reputation", "scope", "limitations", "verification_policy_sha256"}
                        or signature["status"] not in ("verified", "invalid", "unsigned", "untrusted", "not_verifiable", "unsupported")
                        or any(not isinstance(signature[key], str) or len(signature[key]) > 1024
                               for key in ("format", "message", "scope", "limitations"))
                        or type(signature["performed"]) is not bool
                        or type(signature["identity_verified"]) is not bool
                        or signature["identity_verified"] != (signature["status"] == "verified")
                        or signature["reputation"] != "not_assessed"
                        or (signature["publisher"] is not None and
                            (not isinstance(signature["publisher"], str) or len(signature["publisher"]) > 160))
                        or any(not isinstance(signature[key], str) or not DIGEST.fullmatch(signature[key])
                               for key in ("verification_policy_sha256",))
                        or (signature["signer_sha256"] is not None and
                            (not isinstance(signature["signer_sha256"], str) or not DIGEST.fullmatch(signature["signer_sha256"])))):
                    raise RegistryError("Invalid stored signature metadata.")
            if "atlas" in summary:
                atlas = summary["atlas"]
                if (not isinstance(atlas, dict) or set(atlas) != {"source", "tactics", "technique_count"}
                        or not isinstance(atlas["source"], str) or type(atlas["technique_count"]) is not int
                        or atlas["technique_count"] < 0 or not isinstance(atlas["tactics"], list)
                        or len(atlas["tactics"]) != len(TACTIC_ORDER)):
                    raise RegistryError("Invalid stored ATLAS summary.")
                for key, tactic in zip(TACTIC_ORDER, atlas["tactics"]):
                    if (not isinstance(tactic, dict) or set(tactic) != {"key", "id", "name", "findings"}
                            or tactic["key"] != key or not isinstance(tactic["id"], str)
                            or not isinstance(tactic["name"], str) or type(tactic["findings"]) is not int
                            or not 0 <= tactic["findings"] <= summary["findings"]):
                        raise RegistryError("Invalid stored ATLAS tactic counts.")
            if "evidence" in summary:
                evidence = summary["evidence"]
                if (not isinstance(evidence, dict) or set(evidence) != {"excerpts", "omitted"}
                        or not isinstance(evidence["excerpts"], list) or len(evidence["excerpts"]) > MAX_PUBLIC_EXCERPTS
                        or type(evidence["omitted"]) is not int or evidence["omitted"] < 0):
                    raise RegistryError("Invalid stored finding excerpts.")
                for excerpt in evidence["excerpts"]:
                    if (not isinstance(excerpt, dict) or set(excerpt) != {"rule", "severity", "snippet", "source", "line"}
                            or not isinstance(excerpt["snippet"], str) or len(excerpt["snippet"]) > 160):
                        raise RegistryError("Invalid stored finding excerpt.")
            datetime.fromisoformat(summary["first_seen"])
            datetime.fromisoformat(summary["last_seen"])
        for index in ("text_hashes", "file_hashes"):
            aliases = data.get(index, {})
            if (not isinstance(aliases, dict) or any(
                    not DIGEST.fullmatch(key) or not isinstance(values, list)
                    or not 1 <= len(values) <= MAX_HASH_MATCHES
                    or any(not isinstance(value, str) or not DIGEST.fullmatch(value) for value in values)
                    or len(values) != len(set(values)) for key, values in aliases.items())):
                raise RegistryError("Invalid file hash index.")
        return data

    def _load(self, shard: str) -> tuple[dict, str | None]:
        if self.container is None:
            path = self.directory / f"{shard}.json"
            try:
                if path.stat().st_size > MAX_SHARD_BYTES:
                    raise RegistryError("Uniqueness storage shard exceeds its supported capacity.")
                return self._decode(path.read_bytes()), None
            except FileNotFoundError:
                return self._empty(), None
        blob = self.container.get_blob_client(f"uniqueness-v1/{shard}.json")
        try:
            download = blob.download_blob(offset=0, length=MAX_SHARD_BYTES + 1)
            return self._decode(download.readall()), download.properties.etag
        except ResourceNotFoundError:
            return self._empty(), None

    def _merge(self, shard: str, additions: dict[str, set[str]],
               summaries: dict[str, dict] | None = None,
               text_hashes: dict[str, set[str]] | None = None, *,
               file_hashes: dict[str, set[str]] | None = None, prune: bool = False) -> dict[str, set[str]]:
        for _ in range(8):
            record, etag = self._load(shard)
            existing = {key: set(record["sets"][key]) & values for key, values in additions.items()}
            changed = False
            if prune and (any(record["sets"].values()) or record.get("reports") or record.get("text_hashes") or record.get("file_hashes")):
                before = json.dumps(record, sort_keys=True)
                reports = {digest: summary for digest, summary in record.get("reports", {}).items()
                           if self._qualifies(summary)}
                record["reports"] = reports
                for metric in ("skill_snapshots", "complete_skill_versions", "mcp_snapshots", "agent_files"):
                    record["sets"][metric] = [digest for digest in record["sets"][metric] if digest in reports]
                targets = {digest[0] for index in ("text_hashes", "file_hashes")
                           for values in record.get(index, {}).values() for digest in values}
                target_records = {key: self._load(key)[0] for key in targets - {shard}}
                target_records[shard] = record
                retained = {digest for target in target_records.values()
                            for digest, summary in target.get("reports", {}).items() if self._qualifies(summary)}
                for index in ("text_hashes", "file_hashes"):
                    record[index] = {digest: [value for value in values if value in retained]
                                     for digest, values in record.get(index, {}).items()
                                     if any(value in retained for value in values)}
                changed = before != json.dumps(record, sort_keys=True)
            for index, entries in (("text_hashes", text_hashes), ("file_hashes", file_hashes)):
                for digest, values in (entries or {}).items():
                    aliases = record.setdefault(index, {})
                    merged = sorted(set(aliases.get(digest, [])) | values)
                    if len(merged) > MAX_HASH_MATCHES:
                        raise RegistryError("File hash match capacity reached. No matches were silently dropped.")
                    changed |= aliases.get(digest) != merged
                    aliases[digest] = merged
            for digest, summary in (summaries or {}).items():
                reports = record.setdefault("reports", {})
                previous = reports.get(digest)
                reports[digest] = {**summary, "first_seen": previous["first_seen"] if previous else summary["last_seen"]}
                changed |= previous != reports[digest]
            for key, values in additions.items():
                merged = set(record["sets"][key]) | values
                changed |= len(merged) != len(record["sets"][key])
                record["sets"][key] = sorted(merged)
            if not changed:
                return existing
            payload = json.dumps(record, separators=(",", ":")).encode()
            if len(payload) > MAX_SHARD_BYTES:
                raise RegistryError("Uniqueness capacity reached. Existing counters were not reset or approximated.")
            if self.container is None:
                fd, temp = tempfile.mkstemp(prefix=".registry-", dir=self.directory)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temp, self.directory / f"{shard}.json")
                except BaseException:
                    os.unlink(temp)
                    raise
                return existing
            blob = self.container.get_blob_client(f"uniqueness-v1/{shard}.json")
            try:
                if etag is None:
                    blob.upload_blob(payload, overwrite=False)
                else:
                    blob.upload_blob(payload, overwrite=True, etag=etag, match_condition=MatchConditions.IfNotModified)
                return existing
            except (ResourceExistsError, ResourceModifiedError):
                continue
        raise RegistryError("Uniqueness update contention exceeded retry limit.")

    def add(self, report: dict) -> dict[str, bool | None]:
        additions: dict[str, dict[str, set[str]]] = {}
        summaries: dict[str, dict[str, dict]] = {}
        text_hashes: dict[str, dict[str, set[str]]] = {}
        file_hashes: dict[str, dict[str, set[str]]] = {}
        provenance = {file["path"]: file["sha256"] for file in report.get("provenance", {}).get("files", [])}

        def add(key: str, digest: str) -> None:
            if not DIGEST.fullmatch(digest):
                raise RegistryError("Invalid report identity.")
            additions.setdefault(digest[0], {}).setdefault(key, set()).add(digest)

        for artifact in report["artifacts"]:
            metric = {"skill_snapshot": "skill_snapshots", "mcp_snapshot": "mcp_snapshots", "agent_file": "agent_files"}[artifact["kind"]]
            paths = {
                (entry["path"] if artifact["root"] == "." else f"{artifact['root']}/{entry['path']}")
                if artifact["kind"] == "skill_snapshot" else artifact["root"]
                for entry in artifact["files"]
            }
            files = [file for file in report["files"] if file["path"] in paths]
            hits = [hit for file in files for hit in file["findings"]]
            counts = Counter(hit["severity"] for hit in hits)
            if not (counts["HIGH"] or counts["CRITICAL"]):
                continue
            add(metric, artifact["content_id"])
            if artifact["package_complete"]:
                add("complete_skill_versions", artifact["content_id"])
            add("evaluations", artifact["evaluation_id"])
            for hit in hits:
                if hit["severity"] in ("HIGH", "CRITICAL"):
                    add("findings", hit["id"])
            rules = Counter((hit["rule"], hit["severity"]) for hit in hits)
            assessment, _ = evaluate(files, [], report.get("status", "unknown"))
            atlas = annotate(files)
            excerpts = []
            seen = set()
            for file in files:
                credential_file = any(hit["rule"].startswith("SECRET-") for hit in file["findings"])
                for hit in file["findings"]:
                    if hit["id"] in seen:
                        continue
                    seen.add(hit["id"])
                    if len(excerpts) >= MAX_PUBLIC_EXCERPTS:
                        continue
                    snippet = hit.get("snippet", "")
                    if credential_file or any(rx.search(snippet) for _, _, _, rx in SECRET_RULES):
                        snippet = "[REDACTED: file contains potential credential]"
                    excerpts.append({
                        "rule": hit["rule"], "severity": hit["severity"], "snippet": snippet[:160],
                        "source": hit.get("evidence_source", "raw"), "line": hit["line"],
                    })
            summary = {
                "signature": artifact.get("signature"),
                "atlas": {"source": atlas["source"], "tactics": atlas["tactics"],
                          "technique_count": len(atlas["techniques"])},
                "name": artifact.get("name"), "name_source": artifact.get("name_source"),
                "evidence": {"excerpts": excerpts, "omitted": max(0, len(seen) - len(excerpts))},
                "content_id": artifact["content_id"], "kind": artifact["kind"],
                "evaluation_id": artifact["evaluation_id"], "package_complete": artifact["package_complete"],
                "inspection_status": report.get("status", "unknown"),
                "last_seen": report.get("created_at", datetime.now(timezone.utc).isoformat()),
                "detector_sha256": report.get("provenance", {}).get("detector_sha256"),
                "file_count": len(artifact["files"]),
                "assessment": assessment,
                "findings": sum(counts.values()),
                "severities": {severity: counts[severity] for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
                "rules": [{"rule": rule, "severity": severity, "count": count}
                          for (rule, severity), count in sorted(rules.items())],
            }
            summaries.setdefault(artifact["content_id"][0], {})[artifact["content_id"]] = summary
            for file in files:
                if not any(hit["severity"] in ("HIGH", "CRITICAL") for hit in file["findings"]):
                    continue
                raw_digest = file.get("content_sha256")
                if raw_digest is not None:
                    if not DIGEST.fullmatch(raw_digest):
                        raise RegistryError("Invalid raw file hash.")
                    file_hashes.setdefault(raw_digest[0], {}).setdefault(raw_digest, set()).add(artifact["content_id"])
                digest = provenance.get(file["path"])
                if digest is not None:
                    if not DIGEST.fullmatch(digest):
                        raise RegistryError("Invalid inspected-text hash.")
                    text_hashes.setdefault(digest[0], {}).setdefault(digest, set()).add(artifact["content_id"])
        try:
            with self.lock:
                self.cached = None
                if self.container is None:
                    results = [self._merge(shard, values, summaries.get(shard), text_hashes.get(shard),
                                           file_hashes=file_hashes.get(shard))
                               for shard, values in additions.items()]
                else:
                    with ThreadPoolExecutor(max_workers=4) as pool:
                        results = list(pool.map(lambda item: self._merge(item[0], item[1], summaries.get(item[0]),
                                                                        text_hashes.get(item[0]),
                                                                        file_hashes=file_hashes.get(item[0])), additions.items()))
                for shard in (text_hashes.keys() | file_hashes.keys()) - additions.keys():
                    self._merge(shard, {}, text_hashes=text_hashes.get(shard), file_hashes=file_hashes.get(shard))
                known = set()
                for result in results:
                    for metric in ("skill_snapshots", "mcp_snapshots", "agent_files"):
                        known.update(result.get(metric, set()))
                registered = {digest for values in summaries.values() for digest in values}
                return {artifact["content_id"]: artifact["content_id"] in known
                        if artifact["content_id"] in registered else None for artifact in report["artifacts"]}
        except (OSError, AzureError, ValueError, TypeError) as exc:
            raise RegistryError("Uniqueness update failed.") from exc

    def lookup(self, digest: str) -> dict | None:
        if not DIGEST.fullmatch(digest):
            raise ValueError("A full lowercase SHA256 content fingerprint is required.")
        try:
            with self.lock:
                record, _ = self._load(digest[0])
                kind = next((metric for metric in ("skill_snapshots", "mcp_snapshots", "agent_files")
                             if digest in record["sets"][metric]), None)
                if kind is None:
                    content_ids = record.get("file_hashes", {}).get(digest, [])
                    match_type = "file_content" if content_ids else "inspected_text"
                    if not content_ids:
                        content_ids = record.get("text_hashes", {}).get(digest, [])
                    if not content_ids:
                        return None
                    records = {digest[0]: record}
                    for shard in {content_id[0] for content_id in content_ids} - records.keys():
                        records[shard], _ = self._load(shard)
                    matches = [self._content_result(content_id, records[content_id[0]]) for content_id in content_ids]
                    return {"queried_hash": digest, "match_type": match_type, "matches": matches}
                return self._content_result(digest, record)
        except (OSError, AzureError, ValueError, TypeError) as exc:
            raise RegistryError("Fingerprint lookup unavailable.") from exc

    @staticmethod
    def _content_result(digest: str, record: dict) -> dict:
        kind = next((metric for metric in ("skill_snapshots", "mcp_snapshots", "agent_files")
                     if digest in record["sets"][metric]), None)
        if kind is None:
            raise RegistryError("Inspected-text hash references an unavailable snapshot.")
        return {"content_id": digest, "recorded": True, "kind": kind.removesuffix("s"),
                "report": record.get("reports", {}).get(digest),
                "disclaimer": "Latest recorded snapshot assessment, not a safety certification or a file-only assessment. "
                              "Lookup retrieves stored assessment metadata and redacted excerpts only, never full files or repository contents. "
                              "Only snapshots with HIGH or CRITICAL findings are registered. "
                              "Private-scan fingerprints, self-declared names and redacted finding excerpts are public. "
                              "Source paths and repository URLs are omitted. Excerpts may contain submitter-controlled text; never execute them."}

    def read(self) -> dict:
        try:
            with self.lock:
                if self.cached is not None and time.monotonic() - self.cached_at < 60:
                    return self.cached
                with ThreadPoolExecutor(max_workers=4) as pool:
                    records = list(pool.map(self._load, SHARDS))
                populated = [r for r, _ in records if any(r["sets"].values())]
                result = {
                    "version": "uniqueness-v1",
                    "since": min((r["since"] for r in populated), default=None),
                    "as_of": datetime.now(timezone.utc).isoformat(),
                    "counts": {key: sum(len(r["sets"][key]) for r, _ in records) for key in METRICS},
                    "scope": "Only snapshots with HIGH or CRITICAL findings are registered, including private-token scans. "
                             "New unique finding counts include only HIGH/CRITICAL findings. Historical finding/evaluation "
                             "digests and counters are preserved and may include lower severities. Unclassifiable legacy snapshot digests are removed. "
                             "Content versions, not unique people or publishers.",
                    "consistency": "Shard snapshot, cached up to 60 seconds; in-flight or failed submissions can be partially recorded. Retries are idempotent.",
                }
                self.cached, self.cached_at = result, time.monotonic()
                return result
        except (OSError, AzureError, ValueError, TypeError) as exc:
            raise RegistryError("Uniqueness counters unavailable.") from exc
