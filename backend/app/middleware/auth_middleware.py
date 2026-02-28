"""
Authentication Middleware Module
================================

Starlette middleware for request processing.

Features:
- JWT token extraction and validation
- Request ID generation for tracing
- Tenant context injection
- Security logging
- Request timing

Note:
    This middleware is lightweight and only extracts token info.
    Full authentication is done in the dependency layer.
"""

import time
import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from jose import jwt, JWTError

from app.core.config import settings
from app.core.logging import get_logger, request_id_context, security_logger

# Initialize logger
logger = get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for request preprocessing.
    
    Responsibilities:
    - Generate unique request ID for tracing
    - Extract JWT from Authorization header
    - Inject tenant_id and user_id into request.state
    - Log request timing
    - Handle CORS preflight requests
    
    Note:
        This middleware does NOT validate tokens fully.
        It only extracts information for later use.
        Full validation happens in the dependency layer.
    """
    
    def __init__(self, app: ASGIApp):
        """
        Initialize middleware.
        
        Args:
            app: ASGI application
        """
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and inject authentication context.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/route handler
            
        Returns:
            HTTP response
        """
        # Generate unique request ID for tracing
        request_id = str(uuid.uuid4())
        request_id_context.set(request_id)
        
        # Initialize request state
        request.state.request_id = request_id
        request.state.user_id = None
        request.state.tenant_id = None
        request.state.authenticated = False
        
        # Skip auth for health check and docs
        if self._is_public_path(request.url.path):
            start_time = time.perf_counter()
            response = await call_next(request)
            process_time = time.perf_counter() - start_time
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = f"{process_time:.4f}"
            return response
        
        # Extract and decode JWT token
        auth_header = request.headers.get("Authorization")
        
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            
            try:
                # Decode token without full validation
                # Full validation happens in dependency
                payload = self._decode_token_unsafe(token)
                
                if payload:
                    request.state.user_id = payload.get("sub")
                    request.state.tenant_id = payload.get("tenant_id")
                    request.state.token_type = payload.get("type")
                    request.state.authenticated = True
                    
            except JWTError as e:
                # Log but don't fail - let dependency handle it
                logger.debug(
                    "Token decode failed in middleware",
                    extra={
                        "error": str(e),
                        "path": request.url.path,
                    }
                )
        
        # Process request and measure time
        start_time = time.perf_counter()
        
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(
                "Request processing error",
                extra={
                    "error": str(e),
                    "path": request.url.path,
                    "method": request.method,
                }
            )
            raise
        
        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        
        # Log request timing
        process_time = time.perf_counter() - start_time
        response.headers["X-Process-Time"] = f"{process_time:.4f}"
        
        # Log completed request
        self._log_request(request, response, process_time)
        
        return response
    
    def _is_public_path(self, path: str) -> bool:
        """
        Check if path is public (doesn't require authentication).
        
        Args:
            path: Request path
            
        Returns:
            True if path is public
        """
        public_paths = {
            "/",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
        }
        
        # Check exact match
        if path in public_paths:
            return True
        
        # Check prefix match for auth routes
        if path.startswith("/auth/login"):
            return True
        
        return False
    
    def _decode_token_unsafe(self, token: str) -> dict:
        """
        Decode token without full validation.
        
        This is used for extracting information only.
        Full validation happens in the dependency layer.
        
        Args:
            token: JWT token string
            
        Returns:
            Token payload or None
        """
        try:
            # Decode without verification for info extraction
            # The dependency layer will verify properly
            return jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,  # Skip for middleware
                    "verify_iss": False,  # Skip for middleware
                },
            )
        except JWTError:
            return None
    
    def _log_request(
        self,
        request: Request,
        response: Response,
        process_time: float,
    ) -> None:
        """
        Log completed request.
        
        Args:
            request: HTTP request
            response: HTTP response
            process_time: Request processing time
        """
        # Don't log health checks
        if request.url.path in ("/", "/health"):
            return
        
        log_data = {
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "process_time_ms": round(process_time * 1000, 2),
            "user_id": getattr(request.state, "user_id", None),
            "tenant_id": getattr(request.state, "tenant_id", None),
            "ip_address": request.client.host if request.client else None,
        }
        
        # Log based on status code
        if response.status_code >= 500:
            logger.error("Request completed with error", extra=log_data)
        elif response.status_code >= 400:
            logger.warning("Request completed with client error", extra=log_data)
        else:
            logger.info("Request completed", extra=log_data)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    
    Headers added:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security (in production)
    - Content-Security-Policy
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    # Paths that serve Swagger / ReDoc UI assets
    _DOCS_PATHS = {"/docs", "/redoc", "/openapi.json"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy
        # Swagger UI and ReDoc load JS/CSS from cdn.jsdelivr.net, so we
        # need a relaxed policy for the documentation paths in debug mode.
        if settings.DEBUG and request.url.path in self._DOCS_PATHS:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://cdn.jsdelivr.net https://fastapi.tiangolo.com; "
                "font-src 'self' https://cdn.jsdelivr.net; "
                "worker-src 'self' blob:; "
                "frame-ancestors 'none';"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "frame-ancestors 'none';"
            )
        
        # HSTS in production
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiting middleware.
    
    Note:
        For production, use Redis-based rate limiting.
        This is a basic implementation for development.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self._requests: dict = {}  # IP -> [timestamps]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting if disabled
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Check rate limit for login endpoint
        if request.url.path == "/auth/login" and request.method == "POST":
            if self._is_rate_limited(
                client_ip,
                settings.LOGIN_RATE_LIMIT,
                60  # 1 minute window
            ):
                security_logger.log_rate_limit_exceeded(
                    ip_address=client_ip,
                    endpoint=request.url.path
                )
                
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=429,
                    content={
                        "message": "Too many login attempts. Please try again later.",
                        "details": {"retry_after_seconds": 60}
                    },
                    headers={"Retry-After": "60"}
                )
        
        return await call_next(request)
    
    def _is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> bool:
        """
        Check if key is rate limited.
        
        Args:
            key: Identifier (usually IP)
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
            
        Returns:
            True if rate limited
        """
        import time
        
        current_time = time.time()
        window_start = current_time - window_seconds
        
        # Get or create request list
        if key not in self._requests:
            self._requests[key] = []
        
        # Remove old requests
        self._requests[key] = [
            ts for ts in self._requests[key]
            if ts > window_start
        ]
        
        # Check limit
        if len(self._requests[key]) >= max_requests:
            return True
        
        # Add current request
        self._requests[key].append(current_time)
        
        return False
