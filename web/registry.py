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

METRICS = ("skill_snapshots", "complete_skill_versions", "mcp_snapshots", "agent_files", "evaluations", "findings")
SHARDS = "0123456789abcdef"
MAX_SHARD_BYTES = 2 * 1024 * 1024
MAX_HASH_MATCHES = 64
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

    @staticmethod
    def _empty() -> dict:
        return {"since": datetime.now(timezone.utc).isoformat(), "sets": {key: [] for key in METRICS}}

    @staticmethod
    def _decode(payload: bytes) -> dict:
        if len(payload) > MAX_SHARD_BYTES:
            raise RegistryError("Uniqueness storage shard exceeds its supported capacity.")
        data = json.loads(payload)
        if (not isinstance(data, dict) or not {"since", "sets"} <= set(data)
                or set(data) - {"since", "sets", "reports", "text_hashes"}
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
            if (set(summary) != {"content_id", "kind", "evaluation_id", "package_complete", "inspection_status",
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
            datetime.fromisoformat(summary["first_seen"])
            datetime.fromisoformat(summary["last_seen"])
        aliases = data.get("text_hashes", {})
        if (not isinstance(aliases, dict) or any(
                not DIGEST.fullmatch(key) or not isinstance(values, list)
                or not 1 <= len(values) <= MAX_HASH_MATCHES
                or any(not isinstance(value, str) or not DIGEST.fullmatch(value) for value in values)
                or len(values) != len(set(values)) for key, values in aliases.items())):
            raise RegistryError("Invalid inspected-text hash index.")
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
               text_hashes: dict[str, set[str]] | None = None) -> dict[str, set[str]]:
        for _ in range(8):
            record, etag = self._load(shard)
            existing = {key: set(record["sets"][key]) & values for key, values in additions.items()}
            changed = False
            for digest, values in (text_hashes or {}).items():
                aliases = record.setdefault("text_hashes", {})
                merged = sorted(set(aliases.get(digest, [])) | values)
                if len(merged) > MAX_HASH_MATCHES:
                    raise RegistryError("Inspected-text hash match capacity reached. No matches were silently dropped.")
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

    def add(self, report: dict) -> dict[str, bool]:
        additions: dict[str, dict[str, set[str]]] = {}
        summaries: dict[str, dict[str, dict]] = {}
        text_hashes: dict[str, dict[str, set[str]]] = {}
        provenance = {file["path"]: file["sha256"] for file in report.get("provenance", {}).get("files", [])}

        def add(key: str, digest: str) -> None:
            if not DIGEST.fullmatch(digest):
                raise RegistryError("Invalid report identity.")
            additions.setdefault(digest[0], {}).setdefault(key, set()).add(digest)

        for artifact in report["artifacts"]:
            metric = {"skill_snapshot": "skill_snapshots", "mcp_snapshot": "mcp_snapshots", "agent_file": "agent_files"}[artifact["kind"]]
            add(metric, artifact["content_id"])
            if artifact["package_complete"]:
                add("complete_skill_versions", artifact["content_id"])
            add("evaluations", artifact["evaluation_id"])
            paths = {
                (entry["path"] if artifact["root"] == "." else f"{artifact['root']}/{entry['path']}")
                if artifact["kind"] == "skill_snapshot" else artifact["root"]
                for entry in artifact["files"]
            }
            files = [file for file in report["files"] if file["path"] in paths]
            hits = [hit for file in files for hit in file["findings"]]
            counts = Counter(hit["severity"] for hit in hits)
            rules = Counter((hit["rule"], hit["severity"]) for hit in hits)
            assessment, _ = evaluate(files, [], report.get("status", "unknown"))
            # Only fixed detector metadata and aggregates are published, never submitter-controlled text.
            summary = {
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
                digest = provenance.get(file["path"])
                if digest is not None:
                    if not DIGEST.fullmatch(digest):
                        raise RegistryError("Invalid inspected-text hash.")
                    text_hashes.setdefault(digest[0], {}).setdefault(digest, set()).add(artifact["content_id"])
        for file in report["files"]:
            for finding in file["findings"]:
                add("findings", finding["id"])
        try:
            with self.lock:
                self.cached = None
                if self.container is None:
                    results = [self._merge(shard, values, summaries.get(shard), text_hashes.get(shard))
                               for shard, values in additions.items()]
                else:
                    with ThreadPoolExecutor(max_workers=4) as pool:
                        results = list(pool.map(lambda item: self._merge(*item, summaries.get(item[0]),
                                                                        text_hashes.get(item[0])), additions.items()))
                for shard in text_hashes.keys() - additions.keys():
                    self._merge(shard, {}, text_hashes=text_hashes[shard])
                known = set()
                for result in results:
                    for metric in ("skill_snapshots", "mcp_snapshots", "agent_files"):
                        known.update(result.get(metric, set()))
                return {artifact["content_id"]: artifact["content_id"] in known for artifact in report["artifacts"]}
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
                    content_ids = record.get("text_hashes", {}).get(digest, [])
                    if not content_ids:
                        return None
                    records = {digest[0]: record}
                    for shard in {content_id[0] for content_id in content_ids} - records.keys():
                        records[shard], _ = self._load(shard)
                    matches = [self._content_result(content_id, records[content_id[0]]) for content_id in content_ids]
                    return {"queried_hash": digest, "match_type": "inspected_text", "matches": matches}
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
                              "Private-scan fingerprints are discoverable. No source paths, URLs or content are published."}

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
                    "scope": "Automatically recorded submissions, including private-token scans. Content versions, not unique people or publishers. Historical opt-outs are not backfilled.",
                    "consistency": "Shard snapshot, cached up to 60 seconds; in-flight or failed submissions can be partially recorded. Retries are idempotent.",
                }
                self.cached, self.cached_at = result, time.monotonic()
                return result
        except (OSError, AzureError, ValueError, TypeError) as exc:
            raise RegistryError("Uniqueness counters unavailable.") from exc
