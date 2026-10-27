"""Private investigation archive. No content is exposed through the public API."""
import hashlib
import json
import os
import re
import time
from threading import RLock
from pathlib import Path
from uuid import uuid4

from azure.core.exceptions import AzureError
from azure.identity import ManagedIdentityCredential
from azure.storage.blob import BlobServiceClient, ContentSettings

RETENTION_DAYS = 30


class ArchiveError(RuntimeError):
    pass


class Archive:
    def __init__(self) -> None:
        self.lock = RLock()
        self.mode = os.getenv("ARCHIVE_BACKEND", "local")
        if self.mode not in ("local", "azure"):
            raise RuntimeError("ARCHIVE_BACKEND must be local or azure.")
        self.directory = Path(os.getenv("ARCHIVE_DIRECTORY", ".archive")).resolve()
        self.quota = int(os.getenv("ARCHIVE_MAX_BYTES", str(256 * 1024 * 1024)))
        self.service = None
        self.credential = None
        self.container = None
        if self.mode == "azure":
            if os.getenv("AZURE_ARCHIVE_RETENTION_CONFIRMED") != "true":
                raise RuntimeError("Configure the 30-day Blob lifecycle policy, then set AZURE_ARCHIVE_RETENTION_CONFIRMED=true.")
            account = os.environ["AZURE_STORAGE_ACCOUNT"]
            if not re.fullmatch(r"[a-z0-9]{3,24}", account):
                raise RuntimeError("Invalid Azure storage account name.")
            container = os.getenv("AZURE_STORAGE_CONTAINER", "skillvenom-investigations")
            self.credential = ManagedIdentityCredential()
            self.service = BlobServiceClient(
                f"https://{account}.blob.core.windows.net", credential=self.credential,
                connection_timeout=5, read_timeout=10, retry_total=1,
            )
            self.container = self.service.get_container_client(container)
            properties = self.container.get_container_properties()
            if properties.get("public_access"):
                raise RuntimeError("Investigation archive container must not allow public access.")
        else:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.directory.chmod(0o700)

    def close(self) -> None:
        if self.service is not None:
            self.service.close()
        if self.credential is not None:
            self.credential.close()

    def prune(self) -> int:
        with self.lock:
            return self._prune()

    def _prune(self) -> int:
        if self.mode != "local":
            return 0
        total = 0
        cutoff = time.time() - RETENTION_DAYS * 86400
        for entry in self.directory.glob("*.json"):
            if entry.is_symlink():
                raise ArchiveError("Archive directory contains an unexpected symlink.")
            if entry.stat().st_mtime < cutoff:
                entry.unlink()
            else:
                total += entry.stat().st_size
        return total

    def store(self, documents: list[dict[str, str]], report: dict) -> int:
        try:
            with self.lock:
                return self._store(documents, report)
        except (OSError, AzureError) as exc:
            raise ArchiveError("Investigation archive write failed.") from exc

    def _store(self, documents: list[dict[str, str]], report: dict) -> int:
        risky = {file["path"]: file for file in report["files"]
                 if any(f["severity"] in ("HIGH", "CRITICAL") for f in file["findings"])}
        if not risky:
            return 0
        record = {
            "id": uuid4().hex, "created_at": report["created_at"],
            "retention_days": RETENTION_DAYS, "source": report["source"],
            "commit": report.get("commit"),
            "files": [{"path": doc["path"], "text": doc["text"],
                       "sha256": hashlib.sha256(doc["text"].encode()).hexdigest(),
                       "findings": risky[doc["path"]]["findings"]}
                      for doc in documents if doc["path"] in risky],
        }
        payload = json.dumps(record, ensure_ascii=True).encode()
        if self.container is not None:
            self.container.upload_blob(
                name=f"investigations/{record['id']}.json", data=payload, overwrite=False,
                content_settings=ContentSettings(content_type="application/octet-stream"),
                timeout=15,
            )
        else:
            if self.prune() + len(payload) > self.quota:
                raise ArchiveError("Investigation archive quota exceeded.")
            path = self.directory / f"{record['id']}.json"
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
            except OSError:
                path.unlink(missing_ok=True)
                raise
        return len(risky)

    def store_feedback(self, record: dict) -> str:
        """Persist a false-positive report under feedback/, outside the 30-day investigation lifecycle rule."""
        record_id = uuid4().hex
        payload = json.dumps({**record, "id": record_id}, ensure_ascii=True).encode()
        try:
            with self.lock:
                if self.container is not None:
                    self.container.upload_blob(
                        name=f"feedback/{record_id}.json", data=payload, overwrite=False,
                        content_settings=ContentSettings(content_type="application/octet-stream"),
                        timeout=15,
                    )
                else:
                    folder = self.directory / "feedback"
                    folder.mkdir(mode=0o700, exist_ok=True)
                    if sum(1 for _ in folder.glob("*.json")) >= 5000:
                        raise ArchiveError("Feedback store is full.")
                    fd = os.open(folder / f"{record_id}.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(payload)
        except (OSError, AzureError) as exc:
            raise ArchiveError("Feedback write failed.") from exc
        return record_id
