"""QuantumVault Security Operations Center — FastAPI Application."""
from __future__ import annotations

import sys
if sys.version_info < (3, 11):
    sys.exit("QuantumVault requires Python 3.11 or newer (detected Python %d.%d.%d)." % sys.version_info[:3])

import html
import hmac
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from quantumvault.web.authentication import (
    OPERATOR_COOKIE_NAME,
    get_operator_token,
    rotate_operator_token,
)
from quantumvault.web.routes.cluster import router as cluster_router
from quantumvault.web.routes.demo import router as demo_router
from quantumvault.web.routes.detection import router as detection_router
from quantumvault.web.routes.injector import router as injector_router
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


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
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
app.include_router(injector_router)
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


ALLOWED_ORIGINS = {"http://localhost:8000", "http://127.0.0.1:8000"}


@app.post("/api/v1/auth/rotate")
async def rotate_auth_token(request: Request):
    """Rotate runtime operator token with strict origin and token validation."""
    origin = request.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Untrusted origin rejected")

    token = request.headers.get("x-operator-token") or request.cookies.get(OPERATOR_COOKIE_NAME)
    current = get_operator_token()
    if not token or not hmac.compare_digest(token.strip(), current):
        raise HTTPException(status_code=401, detail="Invalid operator token")

    new_token = rotate_operator_token()
    resp = JSONResponse(content={"status": "rotated", "token": new_token})
    resp.set_cookie(
        key=OPERATOR_COOKIE_NAME,
        value=new_token,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return resp


@app.post("/api/v1/auth/logout")
async def logout_auth_token(request: Request):
    """Invalidate active operator session."""
    rotate_operator_token()
    resp = JSONResponse(content={"status": "logged_out"})
    resp.delete_cookie(key=OPERATOR_COOKIE_NAME)
    return resp


def main():
    """CLI launcher for local web dashboard execution with flexible port binding."""
    import argparse
    import socket
    import uvicorn

    parser = argparse.ArgumentParser(description="QuantumVault SOC Web Dashboard")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    args = parser.parse_args()

    port = args.port

    def is_port_in_use(p: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(("127.0.0.1", p)) == 0

    if is_port_in_use(port):
        for candidate in [8001, 8080, 8088, 8888]:
            if not is_port_in_use(candidate):
                print(f"[!] Warning: Port {port} is occupied by another process. Automatically switching to http://{args.host}:{candidate}")
                port = candidate
                break

    print("================================================================================")
    print("  QUANTUMVAULT — Zero-Trust Post-Quantum Security Operations Center")
    print(f"  Local SOC Address: http://{args.host}:{port}")
    print(f"  API Documentation: http://{args.host}:{port}/docs")
    print("================================================================================")
    uvicorn.run("quantumvault.web.app:app", host=args.host, port=port, log_level="info")


if __name__ == "__main__":
    main()
