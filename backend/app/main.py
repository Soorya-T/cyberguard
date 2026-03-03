"""
Main Application Entry Point
============================
Merged: Pod A + Pod B
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Callable

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.core.exceptions import CyberGuardException
from app.core.logging import get_logger
from app.db.session import check_database_connection

# Import models for Alembic detection
from app.models import user, organization

# Import routers (Pod A)
from app.routes import auth_routes, admin_routes
from app.routes.ingestion_routes import router as ingestion_router
from app.api.incidents import router as incidents_router
from app.api.routes.metrics import router as metrics_router

# 🔥 Import Pod B router
from app.api.routes.analyze import router as analyze_router

# Import middleware
from app.middleware.auth_middleware import (
    AuthMiddleware,
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
)

logger = get_logger(__name__)


# =====================================
# Lifespan
# =====================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info(
        "Application starting",
        extra={
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        }
    )

    if not check_database_connection():
        logger.error("Database connection failed on startup")
    else:
        logger.info("Database connection established")

    try:
        yield
    finally:
        logger.info("Application shutdown complete")


# =====================================
# App Initialization
# =====================================

app = FastAPI(
    title=settings.APP_NAME,
    description="CyberGuard Integrated Backend (Pod A + Pod B)",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)


# =====================================
# CORS
# =====================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.cors_methods_list,
    allow_headers=settings.cors_headers_list,
    max_age=3600,
)

# =====================================
# Custom Middleware
# =====================================

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuthMiddleware)


# =====================================
# Exception Handlers
# =====================================

@app.exception_handler(CyberGuardException)
async def cyberguard_exception_handler(request: Request, exc: CyberGuardException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "message": exc.message,
            "details": exc.details,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "message": "Validation error",
            "details": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "message": "Internal Server Error" if settings.ENVIRONMENT == "production" else str(exc)
        },
    )


# =====================================
# Register Routers
# =====================================

# Pod A
app.include_router(auth_routes.router)
app.include_router(admin_routes.router)

app.include_router(
    ingestion_router,
    prefix="/api/v1",
    tags=["Ingestion"]
)

app.include_router(
    incidents_router,
    prefix="/api/v1",
    tags=["Incidents"]
)

app.include_router(
    metrics_router,
    prefix="/api/v1",
    tags=["Metrics"]
)

# 🔥 Pod B
app.include_router(
    analyze_router,
    prefix="/api/v1",
    tags=["Threat Analysis"]
)


# =====================================
# Health
# =====================================

@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health")
def detailed_health_check():
    db_healthy = check_database_connection()

    return {
        "status": "healthy" if db_healthy else "degraded",
        "checks": {
            "database": "healthy" if db_healthy else "unhealthy",
        },
    }