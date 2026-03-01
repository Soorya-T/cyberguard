"""
<<<<<<< HEAD
Structured Logging Configuration Module
=======================================

Provides centralized, structured logging for the application.

Features:
- JSON formatted logs for production
- Text formatted logs for development
- Request ID tracking
- Security event logging
- Audit logging

Usage:
    from app.core.logging import get_logger
    
    logger = get_logger(__name__)
    logger.info("User logged in", extra={"user_id": "123", "tenant_id": "456"})
"""

import logging
import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from functools import lru_cache
from contextvars import ContextVar

from app.core.config import settings


# Context variable for request ID tracking
request_id_context: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs in JSON format.
    
    Includes:
    - Timestamp in ISO 8601 format
    - Log level
    - Logger name
    - Message
    - Extra fields
    - Request ID (if available)
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Base log entry
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add request ID if available
        request_id = request_id_context.get()
        if request_id:
            log_entry["request_id"] = request_id
        
        # Add extra fields
        if hasattr(record, "extra") and record.extra:
            log_entry["extra"] = record.extra
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str)


class TextFormatter(logging.Formatter):
    """
    Human-readable text formatter for development.
    
    Format: [TIMESTAMP] LEVEL name:message
    """
    
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",      # Reset
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as colored text."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]
        
        # Base message
        message = f"[{timestamp}] {color}{record.levelname:8}{reset} {record.name}: {record.getMessage()}"
        
        # Add request ID if available
        request_id = request_id_context.get()
        if request_id:
            message = f"[{request_id[:8]}] {message}"
        
        # Add extra fields
        if hasattr(record, "extra") and record.extra:
            extra_str = " | ".join(f"{k}={v}" for k, v in record.extra.items())
            message = f"{message} | {extra_str}"
        
        # Add exception info if present
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        
        return message


class ExtraLogAdapter(logging.LoggerAdapter):
    """
    Logger adapter that supports extra fields.
    
    Usage:
        logger.info("Message", extra={"user_id": "123"})
    """
    
    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """Process the logging call to add extra fields."""
        extra = kwargs.get("extra", {})
        
        # Merge adapter extra with call extra
        if self.extra:
            extra = {**self.extra, **extra}
        
        kwargs["extra"] = {"extra": extra}
        return msg, kwargs


@lru_cache(maxsize=128)
def get_logger(name: str) -> ExtraLogAdapter:
=======
CyberGuard Pod B - Logging Infrastructure

This module provides structured logging with support for:
- JSON formatted logs for production
- Text formatted logs for development
- Context binding for request tracing
- SIEM-compatible output format
"""

from __future__ import annotations

import logging
import sys
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional, TypeVar, ParamSpec

import structlog
from structlog.types import Processor

from app.core.config import get_settings

# Context variables for request tracing
request_id_context: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
tenant_id_context: ContextVar[Optional[str]] = ContextVar("tenant_id", default=None)
email_id_context: ContextVar[Optional[str]] = ContextVar("email_id", default=None)

P = ParamSpec("P")
R = TypeVar("R")


def add_context_variables(
    logger: logging.Logger,
    method_name: str,
    event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Add context variables to log entries.
    
    This processor adds request_id, tenant_id, and email_id from
    context variables to every log entry.
    """
    request_id = request_id_context.get()
    if request_id:
        event_dict["request_id"] = request_id
    
    tenant_id = tenant_id_context.get()
    if tenant_id:
        event_dict["tenant_id"] = tenant_id
    
    email_id = email_id_context.get()
    if email_id:
        event_dict["email_id"] = email_id
    
    return event_dict


def get_log_level(settings: Any) -> int:
    """Convert string log level to logging constant."""
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    return level_map.get(settings.log_level.upper(), logging.INFO)


def get_processors(settings: Any) -> list[Processor]:
    """Get structlog processors based on settings."""
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        add_context_variables,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]
    
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))
    
    return processors


def configure_logging() -> None:
    """
    Configure structured logging for the application.
    
    This should be called once at application startup.
    """
    settings = get_settings()
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=get_log_level(settings),
    )
    
    # Configure structlog
    structlog.configure(
        processors=get_processors(settings),
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: Optional[str] = None) -> structlog.stdlib.BoundLogger:
>>>>>>> origin/pod_b
    """
    Get a configured logger instance.
    
    Args:
<<<<<<< HEAD
        name: Logger name (usually __name__)
        
    Returns:
        Configured logger with extra field support
    """
    logger = logging.getLogger(name)
    
    # Only configure if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        
        # Choose formatter based on settings
        if settings.LOG_FORMAT == "json":
            formatter = StructuredFormatter()
        else:
            formatter = TextFormatter()
        
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))
        logger.propagate = False  # Prevent duplicate logs
    
    return ExtraLogAdapter(logger, {})


class SecurityLogger:
    """
    Dedicated logger for security-related events.
    
    Logs security events with consistent structure for SIEM integration.
    """
    
    def __init__(self):
        self.logger = get_logger("cyberguard.security")
    
    def log_login_success(self, user_id: str, tenant_id: str, ip_address: str, user_agent: str):
        """Log successful login."""
        self.logger.info(
            "User login successful",
            extra={
                "event_type": "LOGIN_SUCCESS",
                "user_id": user_id,
                "tenant_id": tenant_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
            }
        )
    
    def log_login_failure(self, email: str, ip_address: str, reason: str):
        """Log failed login attempt."""
        self.logger.warning(
            "User login failed",
            extra={
                "event_type": "LOGIN_FAILURE",
                "email": email,
                "ip_address": ip_address,
                "reason": reason,
            }
        )
    
    def log_account_locked(self, user_id: str, tenant_id: str, ip_address: str):
        """Log account lockout."""
        self.logger.warning(
            "Account locked due to failed attempts",
            extra={
                "event_type": "ACCOUNT_LOCKED",
                "user_id": user_id,
                "tenant_id": tenant_id,
                "ip_address": ip_address,
            }
        )
    
    def log_logout(self, user_id: str, tenant_id: str):
        """Log user logout."""
        self.logger.info(
            "User logged out",
            extra={
                "event_type": "LOGOUT",
                "user_id": user_id,
                "tenant_id": tenant_id,
            }
        )
    
    def log_token_refresh(self, user_id: str, tenant_id: str):
        """Log token refresh."""
        self.logger.info(
            "Token refreshed",
            extra={
                "event_type": "TOKEN_REFRESH",
                "user_id": user_id,
                "tenant_id": tenant_id,
            }
        )
    
    def log_token_invalid(self, reason: str, ip_address: str):
        """Log invalid token attempt."""
        self.logger.warning(
            "Invalid token presented",
            extra={
                "event_type": "TOKEN_INVALID",
                "reason": reason,
                "ip_address": ip_address,
            }
        )
    
    def log_unauthorized_access(self, user_id: str, resource: str, action: str):
        """Log unauthorized access attempt."""
        self.logger.warning(
            "Unauthorized access attempt",
            extra={
                "event_type": "UNAUTHORIZED_ACCESS",
                "user_id": user_id,
                "resource": resource,
                "action": action,
            }
        )
    
    def log_tenant_isolation_violation(
        self, 
        user_id: str, 
        user_tenant: str, 
        target_tenant: str,
        resource: str
    ):
        """Log tenant isolation violation attempt."""
        self.logger.error(
            "Tenant isolation violation attempt",
            extra={
                "event_type": "TENANT_ISOLATION_VIOLATION",
                "user_id": user_id,
                "user_tenant": user_tenant,
                "target_tenant": target_tenant,
                "resource": resource,
            }
        )
    
    def log_rate_limit_exceeded(self, ip_address: str, endpoint: str):
        """Log rate limit exceeded."""
        self.logger.warning(
            "Rate limit exceeded",
            extra={
                "event_type": "RATE_LIMIT_EXCEEDED",
                "ip_address": ip_address,
                "endpoint": endpoint,
            }
        )


class AuditLogger:
    """
    Dedicated logger for audit events.
    
    Logs business-critical operations for compliance and auditing.
    """
    
    def __init__(self):
        self.logger = get_logger("cyberguard.audit")
    
    def log_user_created(self, actor_id: str, new_user_id: str, tenant_id: str, role: str):
        """Log user creation."""
        self.logger.info(
            "User created",
            extra={
                "event_type": "USER_CREATED",
                "actor_id": actor_id,
                "new_user_id": new_user_id,
                "tenant_id": tenant_id,
                "role": role,
            }
        )
    
    def log_user_modified(self, actor_id: str, target_user_id: str, changes: Dict[str, Any]):
        """Log user modification."""
        self.logger.info(
            "User modified",
            extra={
                "event_type": "USER_MODIFIED",
                "actor_id": actor_id,
                "target_user_id": target_user_id,
                "changes": changes,
            }
        )
    
    def log_user_deleted(self, actor_id: str, target_user_id: str, tenant_id: str):
        """Log user deletion."""
        self.logger.info(
            "User deleted",
            extra={
                "event_type": "USER_DELETED",
                "actor_id": actor_id,
                "target_user_id": target_user_id,
                "tenant_id": tenant_id,
            }
        )
    
    def log_role_changed(self, actor_id: str, target_user_id: str, old_role: str, new_role: str):
        """Log role change."""
        self.logger.info(
            "User role changed",
            extra={
                "event_type": "ROLE_CHANGED",
                "actor_id": actor_id,
                "target_user_id": target_user_id,
                "old_role": old_role,
                "new_role": new_role,
            }
        )
    
    def log_organization_created(self, actor_id: str, org_id: str, org_name: str):
        """Log organization creation."""
        self.logger.info(
            "Organization created",
            extra={
                "event_type": "ORGANIZATION_CREATED",
                "actor_id": actor_id,
                "organization_id": org_id,
                "organization_name": org_name,
            }
        )


# Global logger instances
security_logger = SecurityLogger()
audit_logger = AuditLogger()
=======
        name: Logger name. If None, uses the calling module's name.
    
    Returns:
        A structlog BoundLogger instance.
    
    Example:
        >>> log = get_logger(__name__)
        >>> log.info("email_parsed", email_id="123", sender="test@example.com")
    """
    return structlog.get_logger(name)


class LogContext:
    """
    Context manager for setting log context variables.
    
    Example:
        >>> with LogContext(request_id="req-123", tenant_id="tenant-1"):
        ...     log.info("processing_email")
    """
    
    def __init__(
        self,
        request_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        email_id: Optional[str] = None,
    ):
        self.request_id = request_id
        self.tenant_id = tenant_id
        self.email_id = email_id
        self._tokens: list = []
    
    def __enter__(self) -> "LogContext":
        if self.request_id:
            self._tokens.append(request_id_context.set(self.request_id))
        if self.tenant_id:
            self._tokens.append(tenant_id_context.set(self.tenant_id))
        if self.email_id:
            self._tokens.append(email_id_context.set(self.email_id))
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        for token in reversed(self._tokens):
            # Reset context variable
            try:
                if token in [request_id_context.get(), tenant_id_context.get(), email_id_context.get()]:
                    pass  # Context var will be reset by the token
            except Exception:
                pass


def log_execution_time(
    log: structlog.stdlib.BoundLogger,
    operation: str,
    **extra_fields: Any
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to log execution time of a function.
    
    Args:
        log: Logger instance
        operation: Name of the operation being timed
        **extra_fields: Additional fields to include in the log
    
    Example:
        >>> @log_execution_time(log, "parse_email")
        ... def parse_email(raw: str) -> ParsedEmail:
        ...     ...
    """
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.perf_counter() - start_time) * 1000
                log.info(
                    f"{operation}_completed",
                    duration_ms=round(duration_ms, 2),
                    success=True,
                    **extra_fields
                )
                return result
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                log.error(
                    f"{operation}_failed",
                    duration_ms=round(duration_ms, 2),
                    success=False,
                    error=str(e),
                    error_type=type(e).__name__,
                    **extra_fields
                )
                raise
        return wrapper
    return decorator


class SignalLogger:
    """
    Specialized logger for signal modules.
    
    Provides structured logging with signal-specific context.
    """
    
    def __init__(self, signal_name: str):
        self.signal_name = signal_name
        self.log = get_logger(f"signal.{signal_name.lower()}")
    
    def log_start(self, email_id: str) -> None:
        """Log signal analysis start."""
        self.log.debug(
            "signal_analysis_started",
            signal=self.signal_name,
            email_id=email_id
        )
    
    def log_complete(
        self,
        email_id: str,
        score: int,
        severity: str,
        duration_ms: float
    ) -> None:
        """Log signal analysis completion."""
        self.log.info(
            "signal_analysis_completed",
            signal=self.signal_name,
            email_id=email_id,
            score=score,
            severity=severity,
            duration_ms=round(duration_ms, 2)
        )
    
    def log_error(
        self,
        email_id: str,
        error: Exception,
        duration_ms: float
    ) -> None:
        """Log signal analysis error."""
        self.log.error(
            "signal_analysis_failed",
            signal=self.signal_name,
            email_id=email_id,
            error=str(error),
            error_type=type(error).__name__,
            duration_ms=round(duration_ms, 2)
        )
    
    def log_warning(self, message: str, **kwargs: Any) -> None:
        """Log a warning with context."""
        self.log.warning(
            message,
            signal=self.signal_name,
            **kwargs
        )
    
    def log_debug(self, message: str, **kwargs: Any) -> None:
        """Log debug information."""
        self.log.debug(
            message,
            signal=self.signal_name,
            **kwargs
        )


# Initialize logging on module import (can be called again at app startup)
# configure_logging()  # Commented out to allow explicit initialization
>>>>>>> origin/pod_b
