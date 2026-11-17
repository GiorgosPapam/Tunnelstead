import asyncio
import contextlib
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__
from .config import get_settings
from .routers import auth, firewall, ops, system, updates, users, vpn

BODY_LIMIT = 1024 * 1024            # 1 MB for every JSON API call
UPLOAD_LIMIT = 520 * 1024 * 1024    # backup uploads (backup.MAX_SIZE plus headroom)

# Same-origin only: no CORS middleware is installed, so browsers block cross-origin API calls.
HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                               "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                               "form-action 'self'; object-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Cache-Control": "no-store",
}


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    task = None
    if get_settings().background_jobs:
        from . import db
        from .collector import run_forever
        from .helper_client import Helper
        task = asyncio.create_task(run_forever(lambda: next(db.get_db()), Helper))
    yield
    if task:
        task.cancel()


def create_app() -> FastAPI:
    app = FastAPI(title="Tunnelstead API", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json" if os.environ.get("TUNNELSTEAD_DEV") == "1" else None, lifespan=lifespan)

    @app.middleware("http")
    async def body_limit(request: Request, call_next):
        """Second line of defence behind Caddy's limits: refuse oversized bodies before anything reads them."""
        limit = UPLOAD_LIMIT if request.url.path == "/api/backups/upload" else BODY_LIMIT
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > limit):
            return JSONResponse({"detail": "Request body is too large"}, status_code=413)
        streamed = length is None and request.headers.get("transfer-encoding")  # chunked: size unknown up front
        if streamed and request.method in ("POST", "PUT", "PATCH") and request.url.path != "/api/backups/upload":
            return JSONResponse({"detail": "Send a Content-Length header"}, status_code=411)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    # firewall before vpn: its specific /instances/{id}/routing must win over the generic /instances/{id}/{action}
    for r in (auth.router, users.router, system.router, ops.router, updates.router, firewall.router, vpn.router):
        app.include_router(r)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
