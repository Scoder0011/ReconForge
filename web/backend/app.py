from __future__ import annotations

from urllib.parse import urlsplit
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from web.backend.routes.config import router as config_router
from web.backend.routes.export import router as export_router
from web.backend.routes.results import router as results_router
from web.backend.routes.scans import router as scans_router
from web.backend.routes.tools import router as tools_router
from web.backend.websocket import router as websocket_router

app = FastAPI(title="ReconForge local API", version="0.1.0")
app.include_router(scans_router)
app.include_router(results_router)
app.include_router(export_router)
app.include_router(config_router)
app.include_router(tools_router)
app.include_router(websocket_router)
_FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")

_LOCAL_HOSTS = {"127.0.0.1", "localhost"}


def _is_local_host(value: str | None) -> bool:
    if not value:
        return False
    try:
        return (urlsplit("//" + value).hostname or "").lower() in _LOCAL_HOSTS
    except ValueError:
        return False


@app.middleware("http")
async def restrict_to_local_clients(request: Request, call_next):
    """Reject non-loopback Host and Origin headers; CORS is intentionally not enabled."""
    if not _is_local_host(request.headers.get("host")):
        return JSONResponse({"detail": "Localhost access only"}, status_code=403)
    origin = request.headers.get("origin")
    if origin and not _is_local_host(urlsplit(origin).netloc):
        return JSONResponse({"detail": "Localhost Origin required"}, status_code=403)
    return await call_next(request)
