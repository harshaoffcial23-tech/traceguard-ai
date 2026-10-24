"""
TraceGuard AI - FastAPI Application Entry Point.
"""

from __future__ import annotations
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.tools.db_init import init_sandbox_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure sandbox SQLite database is initialized
    backend_dir = Path(__file__).resolve().parent.parent
    db_sandbox = backend_dir / "data" / "sandbox" / "sandbox_db.sqlite"
    if not db_sandbox.exists():
        init_sandbox_db(db_sandbox)
    yield


app = FastAPI(
    title="TraceGuard AI — Security Gateway & Testing Platform",
    description="Zero-trust authorization gateway and automated benchmark suite for tool-using AI agents.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(router, prefix="/api")

# Serve prebuilt frontend static files if available
frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if frontend_dist.exists() and (frontend_dist / "index.html").exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
else:
    @app.get("/")
    def root():
        return {
            "platform": "TraceGuard AI",
            "status": "online",
            "docs_url": "/docs",
            "health_check": "/api/health",
        }
