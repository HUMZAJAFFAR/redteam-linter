"""FastAPI server for the RedTeam Linter web console.

Responsibilities
----------------
*   Serve the single-page UI from ``webapp/static``.
*   Expose a small JSON API (health, rules, scan, report).
*   Hold the OpSec boundary: findings never leave the process until
    :class:`reporter.ReportGenerator` has redacted them, so a raw secret cannot
    reach the browser (and therefore cannot appear in devtools or a saved page).

Run it with::

    .venv/bin/python -m uvicorn webapp.server:app --host 0.0.0.0 --port 8000

or simply::

    .venv/bin/python webapp/server.py
"""

from __future__ import annotations

import logging
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
if str(PROJECT_ROOT) not in sys.path:  # make reporter/config_loader importable
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from config_loader import DEFAULT_SINKS, load_sink_config
from reporter import ReportGenerator
from webapp.assistant import ask_assistant
from webapp.assistant import assistant_status as assistant_mode
from webapp.engine import scan_files
from webapp.security import apply_security

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
LOGGER = logging.getLogger("redteam.web")

SINK_CONFIG_PATH = PROJECT_ROOT / "sinks.yaml"
MAX_FILES = 25
MAX_TOTAL_BYTES = 2 * 1024 * 1024
STATIC_DIR = BASE_DIR / "static"
SITE_DIR = STATIC_DIR / "site"
APP_DIR = STATIC_DIR / "app"
VERSION = "0.2.0"

app = FastAPI(title="RedTeam Linter", docs_url=None, redoc_url=None, openapi_url=None)

# CSP, nosniff, origin guard, body cap and per-route rate limits.
apply_security(app)


# ---------------------------------------------------------------------------
# Rule set is loaded once at startup; the UI surfaces its provenance.
# ---------------------------------------------------------------------------
def _load_rules() -> "tuple[List[Dict[str, Any]], str]":
    """Return the sink rules and a human-readable source label."""
    rules = load_sink_config(str(SINK_CONFIG_PATH))
    if not SINK_CONFIG_PATH.exists():
        return rules, "built-in fallback"
    try:
        import yaml

        with SINK_CONFIG_PATH.open("r", encoding="utf-8") as handle:
            yaml.safe_load(handle)
    except Exception:
        return rules, "built-in fallback"
    if [rule.get("name") for rule in rules] == [rule.get("name") for rule in DEFAULT_SINKS]:
        # Identical to the seed table: either the file mirrors it or parsing
        # failed silently.  Either way the UI shows the file it was configured with.
        return rules, "sinks.yaml (baseline)"
    return rules, "sinks.yaml"


RULES, RULE_SOURCE = _load_rules()


class SourceFile(BaseModel):
    """One document submitted for scanning."""

    path: str = Field(default="untitled.py", max_length=400)
    content: str = Field(default="", max_length=MAX_TOTAL_BYTES)


class ScanRequest(BaseModel):
    """Payload accepted by ``/api/scan`` and ``/api/report``."""

    files: List[SourceFile] = Field(default_factory=list)


def _validate(request: ScanRequest) -> List[Dict[str, str]]:
    """Enforce upload limits and normalize paths."""
    if not request.files:
        raise HTTPException(status_code=422, detail="Add at least one Python file to scan.")
    if len(request.files) > MAX_FILES:
        raise HTTPException(status_code=422, detail=f"Too many files (max {MAX_FILES}).")

    total = sum(len(file.content.encode("utf-8")) for file in request.files)
    if total > MAX_TOTAL_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large (max 2 MB).")

    documents: List[Dict[str, str]] = []
    seen: Dict[str, int] = {}
    for file in request.files:
        path = (file.path or "untitled.py").strip().replace("\\", "/")
        path = "/".join(part for part in path.split("/") if part not in ("", ".", ".."))
        if not path:
            path = "untitled.py"
        if not path.endswith(".py"):
            path += ".py"
        if path in seen:
            seen[path] += 1
            stem, dot, suffix = path.rpartition(".")
            path = f"{stem}-{seen[path]}{dot}{suffix}"
        else:
            seen[path] = 1
        if not file.content.strip():
            raise HTTPException(status_code=422, detail=f"{path} is empty.")
        documents.append({"path": path, "content": file.content})
    return documents


def _run_scan(request: ScanRequest) -> "tuple[Dict[str, Any], ReportGenerator]":
    """Scan documents and return the redacted payload plus the generator."""
    documents = _validate(request)
    started = time.perf_counter()
    try:
        findings, scanned, skipped = scan_files(documents, RULES)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.exception("scan failed")
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    generator = ReportGenerator(findings, files_scanned=len(scanned))
    payload = generator.build_payload()
    payload["meta"] = {
        "engine": "embedded-ast",
        "rules_loaded": len(RULES),
        "rule_source": RULE_SOURCE,
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "files_scanned": scanned,
        "files_skipped": skipped,
        "redacted": True,
    }
    return payload, generator


@app.get("/api/health")
def health() -> Dict[str, Any]:
    """Liveness probe used by the UI status pill."""
    return {
        "status": "ok",
        "version": VERSION,
        "rules": len(RULES),
        "rule_source": RULE_SOURCE,
        "engine": "embedded-ast",
    }


@app.get("/api/rules")
def rules() -> Dict[str, Any]:
    """Sink rules currently in force, for the rule inspector in the UI."""
    return {
        "source": RULE_SOURCE,
        "count": len(RULES),
        "rules": [
            {
                "name": rule.get("name"),
                "category": rule.get("category"),
                "requires_shell_true": bool(rule.get("requires_shell_true")),
                "description": rule.get("description", ""),
            }
            for rule in RULES
        ],
    }


@app.post("/api/scan")
def scan(request: ScanRequest) -> JSONResponse:
    """Scan submitted sources and return a redacted findings payload."""
    payload, _ = _run_scan(request)
    return JSONResponse(payload)


@app.post("/api/report")
def report(request: ScanRequest) -> Response:
    """Scan and return the redacted JSON report as a download.

    The serialization goes through :meth:`ReportGenerator.export_to_json`, so
    the downloaded artifact is byte-identical to the CLI's JSON mode.
    """
    _, generator = _run_scan(request)
    with tempfile.TemporaryDirectory() as tmp:
        destination = Path(tmp) / "redteam-report.json"
        generator.export_to_json(str(destination))
        content = destination.read_bytes()
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="redteam-report.json"'},
    )


class AssistantRequest(BaseModel):
    """Question submitted to the in-app assistant."""

    question: str = Field(default="", max_length=600)
    finding: Optional[Dict[str, Any]] = None


@app.get("/api/assistant/status")
def assistant_status_route() -> Dict[str, Any]:
    """Report which assistant backend is active (never exposes the API key)."""
    return assistant_mode()


@app.post("/api/assistant")
def assistant(request: AssistantRequest) -> Dict[str, Any]:
    """Answer a question about a finding or about using the linter.

    Only whitelisted, already-redacted finding fields are forwarded to the
    provider; the API key stays in this process.
    """
    question = (request.question or "").strip()
    if not question:
        raise HTTPException(status_code=422, detail="Ask a question first.")
    return ask_assistant(question, request.finding)


def _page(directory: Path, filename: str) -> HTMLResponse:
    """Read one static page into an HTML response."""
    page = directory / filename
    if not page.exists():  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Missing page: {filename}")
    return HTMLResponse(page.read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def landing() -> HTMLResponse:
    """Marketing landing page."""
    return _page(SITE_DIR, "index.html")


@app.get("/app", response_class=HTMLResponse)
def console() -> HTMLResponse:
    """The console shell; its views are hash-routed in the browser."""
    return _page(APP_DIR, "index.html")


@app.get("/docs", response_class=HTMLResponse)
def docs_page() -> HTMLResponse:
    """Documentation page."""
    return _page(SITE_DIR, "docs.html")


@app.get("/security", response_class=HTMLResponse)
def security_page() -> HTMLResponse:
    """Security model and disclosure policy."""
    return _page(SITE_DIR, "security.html")


@app.get("/changelog", response_class=HTMLResponse)
def changelog_page() -> HTMLResponse:
    """Release history."""
    return _page(SITE_DIR, "changelog.html")


@app.get("/about", response_class=HTMLResponse)
def about_page() -> HTMLResponse:
    """About the project and its deliberate limits."""
    return _page(SITE_DIR, "about.html")


@app.exception_handler(StarletteHTTPException)
def http_error(request: Request, exc: StarletteHTTPException) -> Response:
    """Serve the styled 404 for pages and plain JSON for the API."""
    if exc.status_code == 404 and not request.url.path.startswith("/api"):
        page = SITE_DIR / "404.html"
        if page.exists():
            return HTMLResponse(page.read_text(encoding="utf-8"), status_code=404)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


# Sample targets are served so the UI (and a reviewer) can fetch a known-vulnerable
# file to scan without uploading anything.
app.mount("/samples", StaticFiles(directory=str(PROJECT_ROOT / "samples")), name="samples")

# Static assets last so /api/* keeps priority.
app.mount("/", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "webapp.server:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        server_header=False,  # do not advertise the stack
    )
