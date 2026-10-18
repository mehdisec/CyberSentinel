"""Main FastAPI application entrypoint for CyberSentinel Security Daemon."""
import os
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from backend.app.core.config import settings
from backend.app.api.endpoints import router as api_router, auth_router
from backend.app.api.websocket import ws_router, hub

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cybersentinel.main")

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: starts background live broadcaster and reapers."""
    logger.info("Initializing CyberSentinel Security Daemon...")
    broadcaster_task = asyncio.create_task(hub.start_broadcaster())
    yield
    logger.info("Shutting down CyberSentinel Security Daemon...")
    broadcaster_task.cancel()
    try:
        await broadcaster_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="CyberSentinel Linux Security Panel",
    description="Production-grade Linux Cybersecurity Monitoring & Defense Panel",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API and WebSocket routes
app.include_router(auth_router)
app.include_router(api_router)
app.include_router(ws_router)

# Mount frontend static assets
static_path = FRONTEND_DIR / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    """Serves the main Vue 3 Single Page Application with anti-caching headers."""
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        response = FileResponse(str(index_file))
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return {"message": "CyberSentinel Backend Running. Frontend index.html not found."}


if __name__ == "__main__":
    host = settings.host
    port = settings.port
    logger.info(f"Starting CyberSentinel Daemon on {host}:{port}")
    uvicorn.run("backend.app.main:app", host=host, port=port, log_level="info", reload=False)
