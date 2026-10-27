"""Persistent aggregate counters; no scan content or identifying metadata."""
import json
import os
import tempfile
import threading

from azure.core import MatchConditions
from azure.core.exceptions import AzureError, ResourceExistsError, ResourceModifiedError, ResourceNotFoundError

from web.archive import Archive


class StatisticsError(RuntimeError):
    pass


class Statistics:
    def __init__(self, archive: Archive) -> None:
        self.container = archive.container
        # Kept outside the archive's top-level *.json investigation records.
        self.path = archive.directory / "statistics" / "totals.json"
        self.lock = threading.Lock()
        if self.container is None:
            self.path.parent.mkdir(mode=0o700, exist_ok=True)

    def _read_local(self) -> dict[str, int]:
        try:
            return self._validate(json.loads(self.path.read_text("utf-8")))
        except FileNotFoundError:
            return {"files": 0, "findings": 0}

    def _write_local(self, totals: dict[str, int]) -> None:
        fd, temp = tempfile.mkstemp(dir=self.path.parent, prefix=".statistics-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(totals, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
        except BaseException:
            os.unlink(temp)
            raise

    @staticmethod
    def _validate(value: dict) -> dict[str, int]:
        if not isinstance(value, dict) or set(value) != {"files", "findings"}:
            raise StatisticsError("Invalid statistics record.")
        if any(type(n) is not int or n < 0 for n in value.values()):
            raise StatisticsError("Invalid statistics counters.")
        return value

    def read(self) -> dict[str, int]:
        try:
            if self.container is not None:
                try:
                    data = self.container.get_blob_client("statistics/totals.json").download_blob()
                except ResourceNotFoundError:
                    return {"files": 0, "findings": 0}
                return self._validate(json.loads(data.readall()))
            with self.lock:
                return self._read_local()
        except (OSError, AzureError, ValueError) as exc:
            raise StatisticsError("Statistics read failed.") from exc

    def add(self, files: int, findings: int) -> None:
        self._validate({"files": files, "findings": findings})
        try:
            if self.container is None:
                with self.lock:
                    totals = self._read_local()
                    self._write_local({"files": totals["files"] + files, "findings": totals["findings"] + findings})
                return
            blob = self.container.get_blob_client("statistics/totals.json")
            for _ in range(8):
                try:
                    data = blob.download_blob()
                    totals = self._validate(json.loads(data.readall()))
                    etag = data.properties.etag
                except ResourceNotFoundError:
                    totals, etag = {"files": 0, "findings": 0}, None
                totals = {"files": totals["files"] + files, "findings": totals["findings"] + findings}
                try:
                    if etag is None:
                        blob.upload_blob(json.dumps(totals), overwrite=False)
                    else:
                        blob.upload_blob(
                            json.dumps(totals), overwrite=True,
                            etag=etag, match_condition=MatchConditions.IfNotModified,
                        )
                    return
                except (ResourceExistsError, ResourceModifiedError):
                    continue
            raise StatisticsError("Statistics update contention exceeded retry limit.")
        except (OSError, AzureError, ValueError) as exc:
            raise StatisticsError("Statistics update failed.") from exc
