"""
Main Application Entry Point
============================

Responsibilities:
- Initialize FastAPI application
- Configure middleware stack
- Register API routers
- Set up exception handlers
- Provide health check endpoints
- Configure CORS

IMPORTANT:
    Database tables are managed via Alembic migrations.
    Do NOT use Base.metadata.create_all() in production.
"""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from typing import Callable

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.core.exceptions import CyberGuardException, exception_to_http_exception
from app.core.logging import get_logger, request_id_context
from app.db.session import check_database_connection

# Import models for Alembic detection
from app.models import user, organization

# Import routers
from app.routes import auth_routes, admin_routes

# Import middleware
from app.middleware.auth_middleware import (
    AuthMiddleware,
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
)

# Initialize logger
logger = get_logger(__name__)


# =====================================
# Application Lifespan Handler
# =====================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler for startup and shutdown events.
    
    Startup:
    - Log application start
    - Check database connection
    - Initialize any required resources
    
    Shutdown:
    - Log application shutdown
    - Clean up resources
    """
    # Startup
    logger.info(
        "Application starting",
        extra={
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        }
    )
    
    # Check database connection
    if not check_database_connection():
        logger.error("Database connection failed on startup")
    else:
        logger.info("Database connection established")
    
    try:
        yield
    except asyncio.CancelledError:
        # Handle graceful shutdown on Windows with uvicorn reload
        logger.debug("Application shutdown requested (CancelledError caught)")
        raise
    finally:
        # Shutdown
        logger.info("Application shutdown complete")


# =====================================
# FastAPI App Initialization
# =====================================

app = FastAPI(
    title=settings.APP_NAME,
    description="""
    CyberGuard - Multi-Tenant Security Monitoring Backend
    
    ## Features
    
    * **Multi-Tenant Architecture**: Complete data isolation between organizations
    * **Role-Based Access Control**: Granular permissions with role hierarchy
    * **JWT Authentication**: Secure token-based authentication with refresh tokens
    * **Account Security**: Automatic lockout after failed login attempts
    
    ## Authentication
    
    Use the `/auth/login` endpoint to obtain access and refresh tokens.
    Include the access token in the `Authorization` header as `Bearer <token>`.
    
    ## Authorization
    
    Roles (in order of increasing permissions):
    * `READ_ONLY`: View-only access
    * `SECURITY_ANALYST`: Standard analyst operations
    * `ORG_ADMIN`: Organization administrator
    * `SUPER_ADMIN`: Full system administrator
    """,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)


# =====================================
# CORS Configuration
# =====================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.cors_methods_list,
    allow_headers=settings.cors_headers_list,
    max_age=3600,  # Cache preflight requests for 1 hour
)


# =====================================
# Custom Middleware
# =====================================

# Security headers (should be added early)
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting
app.add_middleware(RateLimitMiddleware)

# Authentication middleware
app.add_middleware(AuthMiddleware)


# =====================================
# Exception Handlers
# =====================================

@app.exception_handler(CyberGuardException)
async def cyberguard_exception_handler(request: Request, exc: CyberGuardException):
    """
    Handle custom CyberGuard exceptions.
    
    Converts custom exceptions to proper HTTP responses.
    """
    logger.warning(
        "CyberGuard exception",
        extra={
            "exception_type": type(exc).__name__,
            "message": exc.message,
            "status_code": exc.status_code,
            "path": request.url.path,
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "message": exc.message,
            "details": exc.details,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handle request validation errors.
    
    Provides detailed error messages for invalid requests.
    """
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })
    
    logger.warning(
        "Request validation error",
        extra={
            "path": request.url.path,
            "errors": errors,
        }
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "message": "Validation error",
            "details": {"errors": errors},
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Handle unexpected exceptions.
    
    Logs the error and returns a generic error message.
    """
    logger.error(
        "Unhandled exception",
        extra={
            "exception_type": type(exc).__name__,
            "message": str(exc),
            "path": request.url.path,
            "method": request.method,
        },
        exc_info=True,
    )
    
    # Don't expose internal errors in production
    if settings.ENVIRONMENT == "production":
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "message": "An unexpected error occurred",
                "details": {},
            },
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "message": str(exc),
                "details": {"type": type(exc).__name__},
            },
        )


# =====================================
# Register Routers
# =====================================

app.include_router(auth_routes.router)
app.include_router(admin_routes.router)

# Week 1 A1 – Ingestion Router
from app.routes.ingestion_routes import router as ingestion_router

app.include_router(
    ingestion_router,
    prefix="/api/v1",
    tags=["Ingestion"]
)

# Incidents Router
from app.api.incidents import router as incidents_router

app.include_router(
    incidents_router,
    prefix="/api/v1",
    tags=["Incidents"]
)

# Metrics Router
from app.api.routes.metrics import router as metrics_router

app.include_router(
    metrics_router,
    prefix="/api/v1",
    tags=["Metrics"]
)


# =====================================
# Health Check Endpoints
# =====================================

@app.get(
    "/",
    tags=["Health"],
    summary="Basic Health Check",
    description="Returns basic service status information.",
)
def health_check():
    """
    Basic health check endpoint.
    
    Returns:
        Service status information
    """
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get(
    "/health",
    tags=["Health"],
    summary="Detailed Health Check",
    description="Returns detailed health status including database connectivity.",
)
def detailed_health_check():
    """
    Detailed health check endpoint.
    
    Returns:
        Detailed health status including database status
    """
    db_healthy = check_database_connection()
    
    return {
        "status": "healthy" if db_healthy else "degraded",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "checks": {
            "database": "healthy" if db_healthy else "unhealthy",
        },
    }


@app.get(
    "/ready",
    tags=["Health"],
    summary="Readiness Check",
    description="Returns whether the service is ready to accept requests.",
)
def readiness_check():
    """
    Readiness check for Kubernetes/container orchestration.
    
    Returns:
        200 if ready, 503 if not ready
    """
    db_healthy = check_database_connection()
    
    if not db_healthy:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "reason": "database_unavailable",
            },
        )
    
    return {
        "status": "ready",
    }


@app.get(
    "/db-check",
    tags=["Health"],
    summary="Database Connection Check",
    description="Tests the database connection and returns status.",
)
def database_check():
    """
    Database connection health check endpoint.
    
    Opens a database session and executes SELECT 1 to verify connectivity.
    
    Returns:
        Success: {"status": "Database Connected"}
        Failure: {"status": "Database Connection Failed", "error": "..."}
    """
    from sqlalchemy import text
    from app.db.session import SessionLocal
    
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {"status": "Database Connected"}
    except Exception as e:
        logger.error(
            "Database connection check failed",
            extra={"error": str(e)}
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "Database Connection Failed",
                "error": str(e) if settings.DEBUG else "Unable to connect to database",
            },
        )
    finally:
        db.close()


# =====================================
# Application Info
# =====================================

@app.get(
    "/info",
    tags=["Info"],
    summary="Application Information",
    description="Returns application configuration information (non-sensitive).",
)
def application_info():
    """
    Get application configuration information.
    
    Returns:
        Non-sensitive configuration details
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "features": {
            "multi_tenant": True,
            "rbac": True,
            "jwt_auth": True,
            "rate_limiting": settings.RATE_LIMIT_ENABLED,
        },
        "token_settings": {
            "access_token_expire_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            "refresh_token_expire_days": settings.REFRESH_TOKEN_EXPIRE_DAYS,
        },
    }

