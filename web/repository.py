"""Allowlisted GitHub retrieval; never clone, extract, or run repository content."""
import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from pathlib import PurePosixPath

import httpx

from scan_agents_md import NAMES, PATHS, WORKFLOWS

MAX_FILE = 256 * 1024
MAX_TOTAL = 2 * 1024 * 1024
MAX_FILES = 100
MAX_TREE = 16 * 1024 * 1024
SHA = re.compile(r"[a-f0-9]{40}")
LIMITS = "Repository target files exceed limits (100 files, 256 KiB/file, 2 MiB total). Upload a smaller selection."


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


def fetch_bytes(client: httpx.Client, url: str, limit: int, deadline: float,
                too_large: str = "GitHub response exceeds the size limit.",
                headers: dict[str, str] | None = None) -> bytes:
    with client.stream("GET", url, headers=headers) as response:
        if response.status_code == 404:
            raise ScanInputError("Repository not found or not public.")
        if response.status_code in (403, 429):
            raise ScanInputError("GitHub rate limit reached. Try later or upload files instead.")
        if response.status_code != 200:
            raise ScanInputError(f"GitHub retrieval failed (HTTP {response.status_code}).")
        chunks = bytearray()
        for chunk in response.iter_bytes(chunk_size=65536):
            if time.monotonic() > deadline:
                raise ScanInputError("Repository retrieval exceeded the 40-second deadline.")
            if len(chunks) + len(chunk) > limit:
                raise ScanInputError(too_large)
            chunks.extend(chunk)
        return bytes(chunks)


def select_targets(tree: dict, workflows: bool) -> tuple[list[dict], list[str]]:
    """Pick supported agent files from a git tree listing without downloading anything."""
    entries = tree.get("tree") if isinstance(tree, dict) else None
    if not isinstance(entries, list):
        raise ScanInputError("GitHub returned an invalid repository tree.")
    selected, skipped, total = [], [], 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ScanInputError("GitHub returned an invalid repository tree.")
        path = safe_path(entry["path"])
        parts = PurePosixPath(path).parts
        if ".git" in parts or "node_modules" in parts or entry.get("type") == "tree":
            continue
        if not is_target(path, workflows):
            continue
        if entry.get("type") != "blob" or entry.get("mode") not in ("100644", "100755"):
            skipped.append(path + " (link or non-regular file)")
            continue
        size, sha = entry.get("size"), entry.get("sha")
        if not isinstance(size, int) or size < 0 or not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise ScanInputError("GitHub returned an invalid repository tree.")
        total += size
        if len(selected) >= MAX_FILES or size > MAX_FILE or total > MAX_TOTAL:
            raise ScanInputError(LIMITS)
        selected.append({"path": path, "size": size, "sha": sha})
    if tree.get("truncated"):
        skipped.append("Repository tree truncated by GitHub; some files were not inspected (upload them instead)")
    return selected, skipped


def fetch_repository(url: str, workflows: bool) -> tuple[list[dict[str, str]], list[str], str]:
    owner, repo = parse_repository(url)
    deadline = time.monotonic() + 40
    api = f"https://api.github.com/repos/{owner}/{repo}"
    # Environment proxies and redirects are disabled; all outbound hosts are fixed.
    with httpx.Client(timeout=httpx.Timeout(10, connect=5), follow_redirects=False,
                      trust_env=False, headers={"User-Agent": "SkillVenom/1.0"}) as client:
        sha = fetch_bytes(client, f"{api}/commits/HEAD", 128, deadline,
                          headers={"Accept": "application/vnd.github.sha"}).decode("ascii", "replace").strip()
        if not SHA.fullmatch(sha):
            raise ScanInputError("GitHub returned an invalid commit ID.")
        listing = fetch_bytes(client, f"{api}/git/trees/{sha}?recursive=1", MAX_TREE, deadline,
                              "Repository file tree exceeds the 16 MiB listing limit. Upload selected files instead.",
                              headers={"Accept": "application/vnd.github+json"})
        try:
            tree = json.loads(listing)
        except ValueError as exc:
            raise ScanInputError("GitHub returned an invalid repository tree.") from exc
        selected, skipped = select_targets(tree, workflows)

        def download(entry: dict) -> dict[str, str]:
            raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{quote(entry['path'], safe='/')}"
            content = fetch_bytes(client, raw, MAX_FILE, deadline, LIMITS)
            blob = hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()
            if blob != entry["sha"]:
                raise ScanInputError(f"Downloaded content did not match the pinned commit: {entry['path']}")
            return decode_document(entry["path"], content)

        with ThreadPoolExecutor(max_workers=6) as pool:
            documents = list(pool.map(download, selected))
    return documents, skipped, sha
