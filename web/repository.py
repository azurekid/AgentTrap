"""Allowlisted GitHub retrieval; never clone, extract, or run repository content."""
import gzip
import io
import json
import re
import tarfile
import time
from pathlib import PurePosixPath

import httpx

from scan_agents_md import NAMES, PATHS, WORKFLOWS

MAX_FILE = 256 * 1024
MAX_TOTAL = 2 * 1024 * 1024
MAX_FILES = 100
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024


class ScanInputError(ValueError):
    """A rejected or incomplete scan must never look like a clean result."""


def safe_path(value: str) -> str:
    if not value or len(value) > 400 or "\\" in value or any(ord(c) < 32 for c in value):
        raise ScanInputError("Invalid file path.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("", ".", "..") for p in value.split("/")):
        raise ScanInputError("Absolute paths and traversal are not accepted.")
    return value


def is_target(path: str, workflows: bool = False) -> bool:
    full = "/" + path
    return bool(NAMES.search(PurePosixPath(path).name) or PATHS.search(full)
                or (workflows and WORKFLOWS.search(full)))


def decode_document(path: str, data: bytes) -> dict[str, str]:
    if len(data) > MAX_FILE:
        raise ScanInputError(f"File exceeds 256 KiB: {path}")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ScanInputError(f"File is not UTF-8 text: {path}") from exc
    if "\x00" in text:
        raise ScanInputError(f"Binary content is not supported: {path}")
    if any(len(line) > 8192 for line in text.splitlines()):
        raise ScanInputError(f"Line exceeds 8,192 characters: {path}")
    return {"path": path, "text": text}


def parse_repository(url: str) -> tuple[str, str]:
    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})/?",
        url.strip(),
    )
    if not match:
        raise ScanInputError("Use a public https://github.com/owner/repository URL without credentials, query, or branch path.")
    owner, repo = match.groups()
    repo = repo.removesuffix(".git")
    if repo in ("", ".", ".."):
        raise ScanInputError("Invalid repository name.")
    return owner, repo


def fetch_bytes(client: httpx.Client, url: str, limit: int, deadline: float) -> bytes:
    with client.stream("GET", url) as response:
        if response.status_code == 404:
            raise ScanInputError("Repository not found or not public.")
        if response.status_code in (403, 429):
            raise ScanInputError("GitHub rate limit reached. Try later or upload files instead.")
        if response.status_code != 200:
            raise ScanInputError(f"GitHub retrieval failed (HTTP {response.status_code}).")
        chunks = bytearray()
        for chunk in response.iter_bytes(chunk_size=65536):
            if time.monotonic() > deadline:
                raise ScanInputError("Repository download exceeded the 40-second deadline.")
            if len(chunks) + len(chunk) > limit:
                raise ScanInputError("Repository download exceeds the size limit. Upload selected files instead.")
            chunks.extend(chunk)
        return bytes(chunks)


def read_archive(data: bytes, workflows: bool) -> tuple[list[dict[str, str]], list[str]]:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            expanded = compressed.read(MAX_EXPANDED + 1)
        if len(expanded) > MAX_EXPANDED:
            raise ScanInputError("Repository exceeds the 64 MiB expanded archive limit.")
        documents, skipped = [], []
        total, entries = 0, 0
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for member in archive:
                entries += 1
                if entries > 10000:
                    raise ScanInputError("Repository exceeds the 10,000 archive entry limit.")
                parts = member.name.split("/", 1)
                if len(parts) != 2 or not parts[1] or member.isdir():
                    continue
                path = safe_path(parts[1])
                if ".git" in PurePosixPath(path).parts or "node_modules" in PurePosixPath(path).parts:
                    continue
                if not is_target(path, workflows):
                    continue
                if not member.isfile():
                    skipped.append(path + " (link or non-regular file)")
                    continue
                if len(documents) >= MAX_FILES or member.size > MAX_FILE or total + member.size > MAX_TOTAL:
                    raise ScanInputError("Repository target files exceed limits (100 files, 256 KiB/file, 2 MiB total). Upload a smaller selection.")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ScanInputError("Unable to read a selected archive member.")
                with stream:
                    content = stream.read(MAX_FILE + 1)
                documents.append(decode_document(path, content))
                total += len(content)
        return documents, skipped
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ScanInputError("GitHub returned an unreadable repository archive.") from exc


def fetch_repository(url: str, workflows: bool) -> tuple[list[dict[str, str]], list[str], str]:
    owner, repo = parse_repository(url)
    deadline = time.monotonic() + 40
    # Environment proxies and redirects are disabled; all outbound hosts are fixed.
    with httpx.Client(timeout=httpx.Timeout(10, connect=5), follow_redirects=False,
                      trust_env=False, headers={"User-Agent": "AgentTrap/1.0"}) as client:
        metadata = fetch_bytes(client, f"https://api.github.com/repos/{owner}/{repo}/commits/HEAD", 65536, deadline)
        try:
            sha = json.loads(metadata)["sha"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ScanInputError("GitHub returned invalid commit metadata.") from exc
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
            raise ScanInputError("GitHub returned an invalid commit ID.")
        data = fetch_bytes(client, f"https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}", MAX_ARCHIVE, deadline)
    documents, skipped = read_archive(data, workflows)
    return documents, skipped, sha
