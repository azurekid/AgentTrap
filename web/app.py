import asyncio
import json
import logging
import subprocess
import sys
import time
from collections import Counter, defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from scan_agents_md import SEV
from web.archive import Archive, ArchiveError
from web.repository import (
    MAX_FILE, MAX_FILES, MAX_TOTAL, ScanInputError, decode_document,
    fetch_repository, is_target, safe_path,
)

ROOT = Path(__file__).resolve().parent
LOG = logging.getLogger("agenttrap")
MAX_BODY = 3 * 1024 * 1024
POLICY = {
    "archive": "Files with HIGH or CRITICAL findings are automatically retained for security investigation. "
               "Original content, including any credentials it contains, is kept in a private archive for 30 days. "
               "Do not submit content you are not authorized to share.",
    "retention_days": 30, "max_files": MAX_FILES, "max_file_bytes": MAX_FILE,
    "max_total_bytes": MAX_TOTAL,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.archive = await run_in_threadpool(Archive)
    app.state.archive.prune()
    async def cleanup() -> None:
        while True:
            await asyncio.sleep(3600)
            try:
                await run_in_threadpool(app.state.archive.prune)
            except (OSError, ArchiveError):
                LOG.error("Archive retention cleanup failed")
    task = asyncio.create_task(cleanup())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        app.state.archive.close()


app = FastAPI(title="AgentTrap", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


class PublicGuard:
    """Bound bodies before multipart parsing; rate-limit without trusting forwarded IPs."""
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.visitors: dict[str, deque[float]] = defaultdict(deque)
        self.global_requests: deque[float] = deque()
        self.active = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        is_scan = path.startswith("/api/scan")
        headers = dict(scope["headers"])
        if is_scan:
            if scope["method"] != "POST":
                return await JSONResponse({"detail": "POST required."}, 405)(scope, receive, send)
            host = headers.get(b"host", b"").decode("latin-1")
            origin = headers.get(b"origin")
            if origin and origin.decode("latin-1") not in (f"https://{host}", f"http://{host}"):
                return await JSONResponse({"detail": "Cross-origin scan requests are not accepted."}, 403)(scope, receive, send)
            now = time.monotonic()
            for key in list(self.visitors):
                if not self.visitors[key] or now - self.visitors[key][-1] > 600:
                    del self.visitors[key]
            client = scope.get("client")
            key = client[0] if client else "unknown"
            if key not in self.visitors and len(self.visitors) >= 5000:
                return await JSONResponse({"detail": "Service is busy. Try later."}, 429)(scope, receive, send)
            window = self.visitors[key]
            for queue in (window, self.global_requests):
                while queue and now - queue[0] > 600:
                    queue.popleft()
            if len(window) >= 10 or len(self.global_requests) >= 60 or self.active >= 2:
                return await JSONResponse({"detail": "Scan limit reached. Try again later."}, 429,
                                          headers={"Retry-After": "600"})(scope, receive, send)
            window.append(now)
            self.global_requests.append(now)
            self.active += 1
        async def secured_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] += [
                    (b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"), (b"cache-control", b"no-store"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ]
            await send(message)
        try:
            if is_scan:
                body = bytearray()
                deadline = time.monotonic() + 15
                while True:
                    message = await asyncio.wait_for(receive(), timeout=max(0.001, deadline - time.monotonic()))
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > MAX_BODY:
                        return await JSONResponse({"detail": "Request exceeds 3 MiB."}, 413)(scope, receive, secured_send)
                    body.extend(chunk)
                    if not message.get("more_body"):
                        break
                delivered = False
                async def bounded_receive() -> Message:
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await receive()
                await self.app(scope, bounded_receive, secured_send)
            else:
                await self.app(scope, receive, secured_send)
        except TimeoutError:
            await JSONResponse({"detail": "Request body timed out."}, 408)(scope, receive, secured_send)
        finally:
            if is_scan:
                self.active -= 1


app.add_middleware(PublicGuard)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # FastAPI's default errors include input values, which may contain secrets.
    return JSONResponse({"detail": "Invalid scan request. Check the URL and workflow option."}, 422)


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/assets/{name}")
def asset(name: str):
    if name not in ("app.js", "style.css"):
        raise HTTPException(404)
    return FileResponse(ROOT / "static" / name)


@app.get("/api/policy")
def policy():
    return POLICY


@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/sources")
def sources():
    return FileResponse(ROOT.parent / "SOURCES.md", media_type="text/plain")


def scan_documents(documents: list[dict[str, str]]) -> list[dict]:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "web.scan_worker"], input=json.dumps(documents),
            capture_output=True, text=True, timeout=15, cwd=ROOT.parent, check=True,
        )
        output = json.loads(result.stdout)
    except subprocess.TimeoutExpired as exc:
        raise ScanInputError("Scanner exceeded its 15-second time limit. Scan fewer files.") from exc
    except (subprocess.CalledProcessError, ValueError) as exc:
        raise RuntimeError("Scanner process failed.") from exc
    if "error" in output:
        raise ScanInputError(output["error"])
    return output["files"]


def make_report(documents: list[dict[str, str]], source: str, skipped: list[str], commit: str | None, archive: Archive) -> dict:
    files = scan_documents(documents)
    counts = Counter(f["severity"] for file in files for f in file["findings"])
    worst = max((SEV[s] for s in counts), default=0)
    verdict = "REVIEW REQUIRED" if worst >= SEV["HIGH"] else "NO HIGH-RISK SIGNALS DETECTED"
    if skipped:
        verdict = "INCOMPLETE SCAN - REVIEW REQUIRED"
    elif not files:
        verdict = "NO TARGET FILES"
    report = {
        "id": uuid4().hex, "created_at": datetime.now(timezone.utc).isoformat(),
        "source": source, "commit": commit, "files": files, "skipped": skipped,
        "status": "partial" if skipped else ("complete" if files else "no_targets"),
        "summary": {"files": len(files), "findings": sum(counts.values()),
                    "severities": {s: counts[s] for s in reversed(SEV)},
                    "verdict": verdict},
        "disclaimer": "Static heuristics, not a safety certification. False positives and missed threats are possible. "
                      "Secret values are not validated with providers. Revoke and rotate real exposed credentials.",
    }
    try:
        count = archive.store(documents, report)
        report["archive"] = {"status": "stored" if count else "not_required", "files": count, "retention_days": 30}
    except ArchiveError:
        LOG.error("Investigation archive write failed; scan_id=%s", report["id"])
        report["archive"] = {"status": "failed", "files": 0, "retention_days": 30,
                             "message": "Scan completed, but investigation archiving failed. Contact the operator."}
    return report


async def execute(documents: list[dict[str, str]], source: str, skipped: list[str], commit: str | None, request: Request):
    try:
        return await run_in_threadpool(make_report, documents, source, skipped, commit, request.app.state.archive)
    except ScanInputError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        LOG.error("Scanner process failed")
        raise HTTPException(500, "Scanner failed. No complete result is available.") from exc


@app.post("/api/scan/files")
async def scan_uploads(request: Request):
    try:
        async with request.form(max_files=MAX_FILES, max_fields=2, max_part_size=MAX_FILE) as form:
            workflows_value = form.get("include_workflows", "false")
            if workflows_value not in ("true", "false"):
                raise ScanInputError("Invalid workflow option.")
            workflows = workflows_value == "true"
            discover_value = form.get("discover", "false")
            if discover_value not in ("true", "false"):
                raise ScanInputError("Invalid discovery option.")
            discover = discover_value == "true"
            documents, seen = [], set()
            total = 0
            for key, upload in form.multi_items():
                if key in ("include_workflows", "discover"):
                    continue
                if key != "files" or not isinstance(upload, UploadFile):
                    raise ScanInputError("Use the files field for uploads.")
                path = safe_path(upload.filename or "")
                if path in seen:
                    raise ScanInputError("Duplicate file paths are not accepted.")
                seen.add(path)
                if discover and not is_target(path, workflows):
                    continue
                suffix = Path(path).suffix.lower()
                if not (is_target(path, workflows) or suffix in (".md", ".mdc", ".json", ".toml")):
                    raise ScanInputError("Upload Markdown, JSON, TOML, or supported agent rule/config files.")
                content = await upload.read(MAX_FILE + 1)
                total += len(content)
                if total > MAX_TOTAL or len(documents) >= MAX_FILES:
                    raise ScanInputError("Upload limit exceeded (100 files, 2 MiB total).")
                documents.append(decode_document(path, content))
            if not documents and not discover:
                raise ScanInputError("Select at least one file to inspect.")
    except ScanInputError as exc:
        raise HTTPException(422, str(exc)) from exc
    return await execute(documents, "File upload", [], None, request)


class RepositoryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=240)
    include_workflows: bool = False


@app.post("/api/scan/repository")
async def scan_repository(payload: RepositoryRequest, request: Request):
    try:
        documents, skipped, sha = await run_in_threadpool(fetch_repository, payload.url, payload.include_workflows)
    except ScanInputError as exc:
        raise HTTPException(422, str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, "GitHub is unavailable or timed out. Upload selected files or try later.") from exc
    return await execute(documents, payload.url.strip(), skipped, sha, request)
