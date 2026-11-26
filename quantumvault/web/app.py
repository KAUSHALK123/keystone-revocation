"""QuantumVault Security Operations Center — FastAPI Application."""
import html
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from quantumvault.web.authentication import OPERATOR_COOKIE_NAME, get_operator_token
from quantumvault.web.routes.cluster import router as cluster_router
from quantumvault.web.routes.demo import router as demo_router
from quantumvault.web.routes.detection import router as detection_router
from quantumvault.web.routes.lab import router as lab_router
from quantumvault.web.routes.messaging import router as messaging_router
from quantumvault.web.routes.status import router as status_router

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="QUANTUMVAULT SOC",
    description="Zero-Trust Post-Quantum Security Operations Center",
    version="2.0.0",
)

# Restrictive CORS for local operator environment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Operator-Token", "X-Requested-With"],
)


ALLOWED_HOSTS = {"localhost", "127.0.0.1", "testserver", "::1", "[::1]"}
ALLOWED_ORIGINS = {"http://localhost:8000", "http://127.0.0.1:8000", "http://testserver"}


def _extract_hostname(host_header: str) -> str:
    h = host_header.strip().lower()
    if h.startswith("["):
        end = h.find("]")
        return h[: end + 1] if end != -1 else h
    return h.split(":", 1)[0]


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    host_hdr = request.headers.get("host", "")
    if host_hdr and _extract_hostname(host_hdr) not in ALLOWED_HOSTS:
        return JSONResponse(status_code=403, content={"detail": "Disallowed Host header"})

    origin_hdr = request.headers.get("origin")
    if request.method.upper() not in {"GET", "HEAD", "OPTIONS"} and origin_hdr:
        if origin_hdr.rstrip("/") not in ALLOWED_ORIGINS:
            return JSONResponse(status_code=403, content={"detail": "Cross-origin state change rejected"})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none';"
    )
    return response


# Register route modules
app.include_router(status_router)
app.include_router(cluster_router)
app.include_router(detection_router)
app.include_router(messaging_router)
app.include_router(lab_router)
app.include_router(demo_router)

# Mount static asset directory
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serve the primary Security Operations Center dashboard with injected runtime operator token."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        token = get_operator_token()
        raw_html = index_file.read_text(encoding="utf-8")
        meta_tag = f'<meta name="qv-operator-token" content="{html.escape(token, quote=True)}">'
        if "</head>" in raw_html:
            injected = raw_html.replace("</head>", f"  {meta_tag}\n</head>", 1)
        else:
            injected = meta_tag + raw_html
        resp = HTMLResponse(content=injected)
        resp.set_cookie(
            key=OPERATOR_COOKIE_NAME,
            value=token,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return resp
    return JSONResponse({
        "app": "QUANTUMVAULT SOC",
        "status": "online",
        "docs_url": "/docs",
        "api_prefix": "/api/v1",
    })


def main():
    """CLI launcher for local web dashboard execution."""
    import uvicorn
    print("================================================================================")
    print("  QUANTUMVAULT — Zero-Trust Post-Quantum Security Operations Center")
    print("  Local SOC Address: http://127.0.0.1:8000")
    print("  API Documentation: http://127.0.0.1:8000/docs")
    print("================================================================================")
    uvicorn.run("quantumvault.web.app:app", host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
