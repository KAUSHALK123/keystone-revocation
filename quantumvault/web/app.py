"""QuantumVault Security Operations Center — FastAPI Application."""
import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from quantumvault.web.routes.cluster import router as cluster_router
from quantumvault.web.routes.detection import router as detection_router
from quantumvault.web.routes.lab import router as lab_router
from quantumvault.web.routes.messaging import router as messaging_router
from quantumvault.web.routes.status import router as status_router

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="QUANTUMVAULT SOC",
    description="Zero-Trust Post-Quantum Security Operations Center",
    version="1.0.0"
)

# Restrictive CORS for local operator environment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Register route modules
app.include_router(status_router)
app.include_router(cluster_router)
app.include_router(detection_router)
app.include_router(messaging_router)
app.include_router(lab_router)

# Mount static asset directory
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serve the primary Security Operations Center dashboard."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "app": "QUANTUMVAULT SOC",
        "status": "online",
        "docs_url": "/docs",
        "api_prefix": "/api/v1"
    }


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
