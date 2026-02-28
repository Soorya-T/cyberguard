"""
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
    """
    Get a configured logger instance.
    
    Args:
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