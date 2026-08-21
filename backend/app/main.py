import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import logger
from app.api.v1.router import api_router
from app.db.session import init_db

def create_app() -> FastAPI:
    # Initialize SQLite Database Tables
    init_db()
    logger.info("Database initialized successfully.")

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=(
            "🛡️ Enterprise-Grade Multimodal AI/ML Platform for Automated Detection of Phishing Domains "
            "Impersonating Genuine Brand Visuals & Backend Code. Built for SIH 1454."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )

    # Enable CORS for Chrome Extension & Dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global Exception Handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled server error on {request.url}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error", "error_message": str(exc)}
        )

    # Mount API v1 Router
    app.include_router(api_router, prefix=settings.API_V1_STR)

    # Mount Static Files for Rendered Screenshot Captures
    if os.path.exists(settings.CAPTURES_DIR):
        app.mount("/captures", StaticFiles(directory=settings.CAPTURES_DIR), name="captures")

    # Mount SOC Admin Frontend Dashboard
    frontend_dir = os.path.join(settings.BASE_DIR, "..", "frontend")
    if os.path.exists(frontend_dir):
        app.mount("/dashboard", StaticFiles(directory=frontend_dir, html=True), name="frontend")
        logger.info(f"Mounted SOC Admin Dashboard from: {frontend_dir}")

    return app

app = create_app()
