"""
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
    """
    Get a configured logger instance.
    
    Args:
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
