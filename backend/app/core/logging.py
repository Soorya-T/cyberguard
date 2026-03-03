"""
CyberGuard - Unified Logging Infrastructure

Combines:
- Structlog-based structured logging (Pod B)
- Security & Audit logging (Pod A)
- Signal logging
- Execution timing decorator
"""

from __future__ import annotations

import logging
import sys
import time
from contextvars import ContextVar
from functools import wraps
from typing import Any, Callable, Dict, Optional, TypeVar, ParamSpec

import structlog
from structlog.types import Processor

from app.core.config import get_settings

# ==============================
# Context Variables
# ==============================

request_id_context: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
tenant_id_context: ContextVar[Optional[str]] = ContextVar("tenant_id", default=None)
email_id_context: ContextVar[Optional[str]] = ContextVar("email_id", default=None)

P = ParamSpec("P")
R = TypeVar("R")


# ==============================
# Log Context Manager
# ==============================

class LogContext:
    """
    Context manager for setting logging context variables.
    
    Usage:
        with LogContext(tenant_id="abc123"):
            log.info("message")  # Will include tenant_id
        
        with LogContext(email_id="email123"):
            log.info("message")  # Will include email_id
    """
    
    def __init__(self, tenant_id: Optional[str] = None, email_id: Optional[str] = None, request_id: Optional[str] = None):
        self.tenant_id = tenant_id
        self.email_id = email_id
        self.request_id = request_id
        self._tokens: list = []
    
    def __enter__(self) -> "LogContext":
        if self.tenant_id is not None:
            token = tenant_id_context.set(self.tenant_id)
            self._tokens.append(("tenant_id", token))
        if self.email_id is not None:
            token = email_id_context.set(self.email_id)
            self._tokens.append(("email_id", token))
        if self.request_id is not None:
            token = request_id_context.set(self.request_id)
            self._tokens.append(("request_id", token))
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        for var_name, token in reversed(self._tokens):
            if var_name == "tenant_id":
                tenant_id_context.reset(token)
            elif var_name == "email_id":
                email_id_context.reset(token)
            elif var_name == "request_id":
                request_id_context.reset(token)


# ==============================
# Core Logging Configuration
# ==============================

def add_context_variables(
    logger: logging.Logger,
    method_name: str,
    event_dict: Dict[str, Any],
) -> Dict[str, Any]:

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
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    return level_map.get(settings.log_level.upper(), logging.INFO)


def get_processors(settings: Any) -> list[Processor]:
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
    settings = get_settings()

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=get_log_level(settings),
    )

    structlog.configure(
        processors=get_processors(settings),
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)


# ==============================
# Execution Time Decorator
# ==============================

def log_execution_time(
    log: structlog.stdlib.BoundLogger,
    operation: str,
    **extra_fields: Any,
) -> Callable[[Callable[P, R]], Callable[P, R]]:

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
                    **extra_fields,
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
                    **extra_fields,
                )
                raise

        return wrapper

    return decorator


# ==============================
# Security Logger (Pod A preserved)
# ==============================

class SecurityLogger:

    def __init__(self):
        self.log = get_logger("cyberguard.security")

    def login_success(self, user_id: str, tenant_id: str, ip: str):
        self.log.info(
            "login_success",
            event_type="LOGIN_SUCCESS",
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip,
        )

    def login_failure(self, email: str, ip: str, reason: str):
        self.log.warning(
            "login_failure",
            event_type="LOGIN_FAILURE",
            email=email,
            ip_address=ip,
            reason=reason,
        )

    def unauthorized_access(self, user_id: str, resource: str, action: str = None):
        self.log.warning(
            "unauthorized_access",
            event_type="UNAUTHORIZED_ACCESS",
            user_id=user_id,
            resource=resource,
            action=action,
        )

    # Alias methods for test compatibility
    def log_login_success(self, user_id: str, tenant_id: str = None, ip: str = None, ip_address: str = None):
        self.login_success(user_id, tenant_id or "", ip or ip_address or "")

    def log_login_failure(self, email: str, ip: str = None, reason: str = None, ip_address: str = None):
        self.login_failure(email, ip or ip_address or "", reason or "unknown")

    def log_token_refresh(self, user_id: str, tenant_id: str = None):
        self.log.info(
            "token_refresh",
            event_type="TOKEN_REFRESH",
            user_id=user_id,
            tenant_id=tenant_id,
        )

    def log_logout(self, user_id: str, tenant_id: str = None):
        self.log.info(
            "logout",
            event_type="LOGOUT",
            user_id=user_id,
            tenant_id=tenant_id,
        )

    def log_token_invalid(self, user_id: str = None, reason: str = None, ip_address: str = None):
        self.log.warning(
            "token_invalid",
            event_type="TOKEN_INVALID",
            user_id=user_id,
            reason=reason,
            ip_address=ip_address,
        )

    def log_tenant_isolation_violation(self, user_id: str = None, user_tenant: str = None, target_tenant: str = None, resource: str = None):
        self.log.warning(
            "tenant_isolation_violation",
            event_type="TENANT_ISOLATION_VIOLATION",
            user_id=user_id,
            user_tenant=user_tenant,
            target_tenant=target_tenant,
            resource=resource,
        )


# ==============================
# Audit Logger (Pod A preserved)
# ==============================

class AuditLogger:

    def __init__(self):
        self.log = get_logger("cyberguard.audit")

    def user_created(self, actor_id: str, new_user_id: str, tenant_id: str):
        self.log.info(
            "user_created",
            event_type="USER_CREATED",
            actor_id=actor_id,
            new_user_id=new_user_id,
            tenant_id=tenant_id,
        )

    def user_deleted(self, actor_id: str, target_user_id: str):
        self.log.info(
            "user_deleted",
            event_type="USER_DELETED",
            actor_id=actor_id,
            target_user_id=target_user_id,
        )

    def user_modified(self, actor_id: str, target_user_id: str, tenant_id: str = None, changes: dict = None):
        self.log.info(
            "user_modified",
            event_type="USER_MODIFIED",
            actor_id=actor_id,
            target_user_id=target_user_id,
            tenant_id=tenant_id,
            changes=changes or {},
        )

    # Alias method for test compatibility
    def log_user_modified(self, actor_id: str, target_user_id: str, tenant_id: str = None, changes: dict = None):
        self.user_modified(actor_id, target_user_id, tenant_id, changes)


# ==============================
# Signal Logger (Pod B preserved)
# ==============================

class SignalLogger:

    def __init__(self, signal_name: str):
        self.signal_name = signal_name
        self.log = get_logger(f"signal.{signal_name.lower()}")

    def start(self, email_id: str):
        self.log.debug(
            "signal_analysis_started",
            signal=self.signal_name,
            email_id=email_id,
        )

    def complete(self, email_id: str, score: int, severity: str, duration_ms: float):
        self.log.info(
            "signal_analysis_completed",
            signal=self.signal_name,
            email_id=email_id,
            score=score,
            severity=severity,
            duration_ms=round(duration_ms, 2),
        )

    def error(self, email_id: str, error: Exception, duration_ms: float):
        self.log.error(
            "signal_analysis_failed",
            signal=self.signal_name,
            email_id=email_id,
            error=str(error),
            error_type=type(error).__name__,
            duration_ms=round(duration_ms, 2),
        )


# Global instances
security_logger = SecurityLogger()
audit_logger = AuditLogger()