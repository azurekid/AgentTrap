"""Allowlisted GitHub, GitLab and Azure DevOps retrieval; never clone, extract, or run repository content."""
import base64
import hashlib
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit
from pathlib import PurePosixPath

import httpx

from scan_agents_md import NAMES, PATHS, WORKFLOWS

MAX_FILE = 256 * 1024
MAX_TOTAL = 2 * 1024 * 1024
MAX_FILES = 100
MAX_TREE = 16 * 1024 * 1024
SHA = re.compile(r"[a-f0-9]{40}")
UNSUPPORTED = ("Use an https:// repository URL on github.com, gitlab.com or dev.azure.com (or a host your operator configured), "
               "without credentials, query, port or branch path.")
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


PROVIDERS = {"github": "GitHub", "gitlab": "GitLab", "azuredevops": "Azure DevOps"}
SEGMENT = re.compile(r"[A-Za-z0-9_.-]{1,100}")
AZDO_SEGMENT = re.compile(r"[A-Za-z0-9_. -]{1,100}")
HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
TOKEN = re.compile(r"[\x21-\x7e]{8,256}")
MAX_TREE_PAGES = 50


@dataclass(frozen=True)
class Ref:
    provider: str
    host: str
    path: tuple[str, ...]  # GitHub/GitLab: namespace + project. Azure DevOps: collection prefix + project + repository.


def configured_hosts(name: str) -> set[str]:
    """Self-managed hosts are operator-configured, never user-supplied, so users cannot aim the server elsewhere."""
    values = {item.strip().lower() for item in os.environ.get(name, "").split(",")}
    return {value for value in values if HOST.fullmatch(value)}


def parse_repository(url: str) -> Ref:
    try:
        parsed = urlsplit(url.strip())
        host, port = (parsed.hostname or "").lower(), parsed.port
    except ValueError as exc:
        raise ScanInputError(UNSUPPORTED) from exc
    if (parsed.scheme != "https" or port or parsed.netloc.lower() != host or parsed.query or parsed.fragment
            or not host):
        raise ScanInputError(UNSUPPORTED)
    raw = parsed.path.strip("/").split("/")
    segments = [unquote(item) for item in raw]
    gitlab, azdo = host == "gitlab.com" or host in configured_hosts("SCM_GITLAB_HOSTS"), \
        host == "dev.azure.com" or host in configured_hosts("SCM_AZDO_HOSTS")
    if host == "github.com":
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})", "/".join(raw))
        if not match:
            raise ScanInputError(UNSUPPORTED)
        owner, repo = match.group(1), match.group(2).removesuffix(".git")
        if repo in ("", ".", ".."):
            raise ScanInputError("Invalid repository name.")
        return Ref("github", host, (owner, repo))
    if gitlab:
        segments[-1] = segments[-1].removesuffix(".git")
        if (not 2 <= len(segments) <= 10 or "-" in segments
                or not all(SEGMENT.fullmatch(item) and item not in (".", "..") for item in segments)):
            raise ScanInputError(UNSUPPORTED)
        return Ref("gitlab", host, tuple(segments))
    if azdo and "_git" in segments:
        index = segments.index("_git")
        prefix_ok = index == 2 if host == "dev.azure.com" else index >= 2
        if (prefix_ok and len(segments) == index + 2
                and all(AZDO_SEGMENT.fullmatch(item) and item not in (".", "..") and item == item.strip()
                        for item in segments)):
            return Ref("azuredevops", host, tuple(segments[:index] + segments[index + 1:]))
    raise ScanInputError(UNSUPPORTED)


def auth_headers(provider: str, token: str | None) -> dict[str, str]:
    if not token:
        return {}
    if provider == "gitlab":
        return {"PRIVATE-TOKEN": token}
    if provider == "azuredevops":
        return {"Authorization": "Basic " + base64.b64encode(f":{token}".encode()).decode()}
    return {"Authorization": f"Bearer {token}"}


def fetch_response(client: httpx.Client, url: str, limit: int, deadline: float,
                   too_large: str = "GitHub response exceeds the size limit.",
                   headers: dict[str, str] | None = None, who: str = "GitHub",
                   authed: bool = False) -> tuple[bytes, httpx.Headers]:
    with client.stream("GET", url, headers=headers) as response:
        status = response.status_code
        if status == 404:
            raise ScanInputError("Repository not found, or the token cannot read it." if authed else
                                 "Repository not found, or it is private. For private repositories add a read-only access token.")
        if status in (401, 203):  # Azure DevOps answers unauthenticated requests with 203
            raise ScanInputError(f"{who} rejected the access token." if authed else
                                 "Repository requires authentication. Add a read-only access token.")
        if status in (403, 429):
            raise ScanInputError(f"{who} denied access or rate limit reached. Check the token's read scope or try later."
                                 if authed else f"{who} rate limit reached. Try later or upload files instead.")
        if status != 200:
            raise ScanInputError(f"{who} retrieval failed (HTTP {status}).")
        chunks = bytearray()
        for chunk in response.iter_bytes(chunk_size=65536):
            if time.monotonic() > deadline:
                raise ScanInputError("Repository retrieval exceeded the 40-second deadline.")
            if len(chunks) + len(chunk) > limit:
                raise ScanInputError(too_large)
            chunks.extend(chunk)
        return bytes(chunks), response.headers


def fetch_bytes(client: httpx.Client, url: str, limit: int, deadline: float,
                too_large: str = "GitHub response exceeds the size limit.",
                headers: dict[str, str] | None = None, who: str = "GitHub", authed: bool = False) -> bytes:
    return fetch_response(client, url, limit, deadline, too_large, headers, who, authed)[0]


def select_targets(tree: dict, workflows: bool) -> tuple[list[dict], list[str]]:
    """Pick supported agent files from a git tree listing without downloading anything."""
    entries = tree.get("tree") if isinstance(tree, dict) else None
    if not isinstance(entries, list):
        raise ScanInputError("The repository host returned an invalid repository tree.")
    selected, skipped, total = [], [], 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ScanInputError("The repository host returned an invalid repository tree.")
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
            raise ScanInputError("The repository host returned an invalid repository tree.")
        total += size
        if len(selected) >= MAX_FILES or size > MAX_FILE or total > MAX_TOTAL:
            raise ScanInputError(LIMITS)
        selected.append({"path": path, "size": size, "sha": sha})
    if tree.get("truncated"):
        skipped.append("Repository tree truncated by the repository host; some files were not inspected (upload them instead)")
    return selected, skipped


def json_value(data: bytes, what: str):
    try:
        return json.loads(data)
    except ValueError as exc:
        raise ScanInputError(f"{what} returned invalid data.") from exc


def blob_entry(path: object, sha: object) -> dict:
    if not isinstance(path, str) or not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ScanInputError("The repository host returned an invalid repository tree.")
    return {"path": path.lstrip("/"), "type": "blob", "mode": "100644", "size": 0, "sha": sha}


def gitlab_listing(ref: Ref, get, get_page) -> tuple[str, dict, object]:
    api = f"https://{ref.host}/api/v4/projects/{quote('/'.join(ref.path), safe='')}"
    commits = json_value(get(f"{api}/repository/commits?per_page=1", 64 * 1024), "GitLab")
    sha = commits[0].get("id") if isinstance(commits, list) and commits and isinstance(commits[0], dict) else None
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ScanInputError("GitLab returned an invalid commit ID.")
    entries, truncated = [], True
    for page in range(1, MAX_TREE_PAGES + 1):
        data, headers = get_page(f"{api}/repository/tree?recursive=true&per_page=100&ref={sha}&page={page}", MAX_TREE)
        items = json_value(data, "GitLab")
        if not isinstance(items, list):
            raise ScanInputError("The repository host returned an invalid repository tree.")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise ScanInputError("The repository host returned an invalid repository tree.")
            if item.get("type") == "tree":
                continue
            entry = blob_entry(item["path"], item.get("id"))
            entry["type"], entry["mode"] = item.get("type"), item.get("mode")
            entries.append(entry)
        if not headers.get("x-next-page"):
            truncated = False
            break
    return sha, {"tree": entries, "truncated": truncated}, \
        lambda entry: get(f"{api}/repository/blobs/{entry['sha']}/raw", MAX_FILE, LIMITS)


def azure_devops_listing(ref: Ref, get, get_page) -> tuple[str, dict, object]:
    segments = "/".join(quote(item, safe="") for item in ref.path[:-1])
    api = f"https://{ref.host}/{segments}/_apis/git/repositories/{quote(ref.path[-1], safe='')}"
    info = json_value(get(f"{api}?api-version=7.1", 64 * 1024), "Azure DevOps")
    branch = info.get("defaultBranch") if isinstance(info, dict) else None
    if not isinstance(branch, str) or not branch.startswith("refs/heads/"):
        raise ScanInputError("Repository has no default branch to inspect.")
    refs = json_value(get(f"{api}/refs?filter={quote(branch.removeprefix('refs/'), safe='/')}&api-version=7.1",
                          1024 * 1024), "Azure DevOps")
    values = refs.get("value") if isinstance(refs, dict) else None
    sha = next((item.get("objectId") for item in values or []
                if isinstance(item, dict) and item.get("name") == branch), None)
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ScanInputError("Azure DevOps returned an invalid commit ID.")
    listing = json_value(get(
        f"{api}/items?scopePath=/&recursionLevel=Full&versionDescriptor.version={sha}"
        "&versionDescriptor.versionType=commit&api-version=7.1", MAX_TREE,
        "Repository file tree exceeds the 16 MiB listing limit. Upload selected files instead."), "Azure DevOps")
    items = listing.get("value") if isinstance(listing, dict) else None
    if not isinstance(items, list):
        raise ScanInputError("The repository host returned an invalid repository tree.")
    entries = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ScanInputError("The repository host returned an invalid repository tree.")
        if item.get("gitObjectType") == "blob":
            entries.append(blob_entry(item["path"], item.get("objectId")))
    return sha, {"tree": entries, "truncated": False}, lambda entry: get(
        f"{api}/blobs/{entry['sha']}?$format=octetstream&api-version=7.1", MAX_FILE, LIMITS,
        {"Accept": "application/octet-stream"})


def github_listing(ref: Ref, get, authed: bool) -> tuple[str, dict, object]:
    owner, repo = ref.path
    api = f"https://api.github.com/repos/{owner}/{repo}"
    sha = get(f"{api}/commits/HEAD", 128, headers={"Accept": "application/vnd.github.sha"}).decode("ascii", "replace").strip()
    if not SHA.fullmatch(sha):
        raise ScanInputError("GitHub returned an invalid commit ID.")
    listing = get(f"{api}/git/trees/{sha}?recursive=1", MAX_TREE,
                  "Repository file tree exceeds the 16 MiB listing limit. Upload selected files instead.",
                  {"Accept": "application/vnd.github+json"})
    tree = json_value(listing, "GitHub")

    def blob(entry: dict) -> bytes:
        if authed:  # keep the token on api.github.com only
            return get(f"{api}/git/blobs/{entry['sha']}", MAX_FILE, LIMITS, {"Accept": "application/vnd.github.raw"})
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{quote(entry['path'], safe='/')}"
        return get(raw, MAX_FILE, LIMITS)
    return sha, tree, blob


def fetch_repository(url: str, workflows: bool, token: str | None = None) -> tuple[list[dict[str, str]], list[str], str]:
    ref = parse_repository(url)
    token = (token or "").strip() or None
    if token and not TOKEN.fullmatch(token):
        raise ScanInputError("Access token format is invalid.")
    deadline = time.monotonic() + 40
    who, auth = PROVIDERS[ref.provider], auth_headers(ref.provider, token)
    # Environment proxies and redirects are disabled; outbound hosts are fixed or operator-configured.
    with httpx.Client(timeout=httpx.Timeout(10, connect=5), follow_redirects=False,
                      trust_env=False, headers={"User-Agent": "SkillVenom/1.0"}) as client:
        def get_page(url: str, limit: int, too_large: str = "The repository host response exceeds the size limit.",
                     headers: dict[str, str] | None = None):
            return fetch_response(client, url, limit, deadline, too_large, {**(headers or {}), **auth}, who, bool(token))

        def get(*args, **kwargs) -> bytes:
            return get_page(*args, **kwargs)[0]

        if ref.provider == "github":
            sha, tree, blob = github_listing(ref, get, bool(token))
        elif ref.provider == "gitlab":
            sha, tree, blob = gitlab_listing(ref, get, get_page)
        else:
            sha, tree, blob = azure_devops_listing(ref, get, get_page)
        selected, skipped = select_targets(tree, workflows)

        def download(entry: dict) -> dict[str, str]:
            content = blob(entry)
            digest = hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()
            if digest != entry["sha"]:
                raise ScanInputError(f"Downloaded content did not match the pinned commit: {entry['path']}")
            return decode_document(entry["path"], content)

        with ThreadPoolExecutor(max_workers=6) as pool:
            documents = list(pool.map(download, selected))
    if sum(len(item["text"].encode()) for item in documents) > MAX_TOTAL:
        raise ScanInputError(LIMITS)
    return documents, skipped, sha
