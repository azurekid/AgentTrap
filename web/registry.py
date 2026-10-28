"""Central exact fingerprint registry. Stores digest sets, never scan content."""
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

METRICS = ("skill_snapshots", "complete_skill_versions", "mcp_snapshots", "agent_files", "evaluations", "findings")
SHARDS = "0123456789abcdef"
MAX_SHARD_BYTES = 2 * 1024 * 1024
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
        if (not isinstance(data, dict) or set(data) != {"since", "sets"}
                or not isinstance(data["since"], str) or not isinstance(data["sets"], dict)
                or set(data["sets"]) != set(METRICS)):
            raise RegistryError("Invalid uniqueness record.")
        datetime.fromisoformat(data["since"])
        for values in data["sets"].values():
            if not isinstance(values, list) or any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in values):
                raise RegistryError("Invalid uniqueness digest.")
            if len(values) != len(set(values)):
                raise RegistryError("Duplicate uniqueness digest in storage.")
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

    def _merge(self, shard: str, additions: dict[str, set[str]]) -> dict[str, set[str]]:
        for _ in range(8):
            record, etag = self._load(shard)
            existing = {key: set(record["sets"][key]) & values for key, values in additions.items()}
            changed = False
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
        for file in report["files"]:
            for finding in file["findings"]:
                add("findings", finding["id"])
        try:
            with self.lock:
                self.cached = None
                if self.container is None:
                    results = [self._merge(shard, values) for shard, values in additions.items()]
                else:
                    with ThreadPoolExecutor(max_workers=4) as pool:
                        results = list(pool.map(lambda item: self._merge(*item), additions.items()))
                known = set()
                for result in results:
                    for metric in ("skill_snapshots", "mcp_snapshots", "agent_files"):
                        known.update(result.get(metric, set()))
                return {artifact["content_id"]: artifact["content_id"] in known for artifact in report["artifacts"]}
        except (OSError, AzureError, ValueError, TypeError) as exc:
            raise RegistryError("Uniqueness update failed.") from exc

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
