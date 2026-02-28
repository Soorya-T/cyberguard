"""
Centralized Exception Handling Module
=====================================

Defines custom exception classes for the application.

Benefits:
- Consistent error responses
- Proper HTTP status codes
- Structured error messages
- Easy to extend

Usage:
    raise AuthenticationError("Invalid credentials")
    raise AuthorizationError("Insufficient permissions")
"""

from typing import Any, Dict, Optional
from fastapi import HTTPException, status


class CyberGuardException(Exception):
    """
    Base exception class for CyberGuard application.
    
    All custom exceptions should inherit from this class.
    """
    
    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


# ==========================
# Authentication Exceptions
# ==========================

class AuthenticationError(CyberGuardException):
    """Raised when authentication fails."""
    
    def __init__(
        self,
        message: str = "Could not validate credentials",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class InvalidCredentialsError(AuthenticationError):
    """Raised when login credentials are invalid."""
    
    def __init__(self):
        super().__init__(message="Invalid email or password")


class TokenExpiredError(AuthenticationError):
    """Raised when a JWT token has expired."""
    
    def __init__(self, token_type: str = "access"):
        super().__init__(
            message=f"{token_type.capitalize()} token has expired",
            details={"token_type": token_type}
        )


class TokenInvalidError(AuthenticationError):
    """Raised when a JWT token is invalid."""
    
    def __init__(self, reason: str = "Invalid token"):
        super().__init__(
            message="Invalid token",
            details={"reason": reason}
        )


class TokenVersionMismatchError(AuthenticationError):
    """Raised when token version doesn't match user's current version."""
    
    def __init__(self):
        super().__init__(
            message="Token has been invalidated. Please log in again."
        )


# ==========================
# Authorization Exceptions
# ==========================

class AuthorizationError(CyberGuardException):
    """Raised when user lacks required permissions."""
    
    def __init__(
        self,
        message: str = "Insufficient permissions",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class RoleNotAuthorizedError(AuthorizationError):
    """Raised when user's role is not authorized for the action."""
    
    def __init__(self, required_roles: list):
        super().__init__(
            message="Your role is not authorized for this action",
            details={"required_roles": required_roles}
        )


class TenantIsolationError(AuthorizationError):
    """Raised when tenant isolation is violated."""
    
    def __init__(self):
        super().__init__(
            message="Access denied: resource belongs to different organization"
        )


# ==========================
# Account Status Exceptions
# ==========================

class AccountError(CyberGuardException):
    """Base exception for account-related issues."""
    
    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_403_FORBIDDEN,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            status_code=status_code,
            details=details,
        )


class AccountLockedError(AccountError):
    """Raised when account is locked due to failed attempts."""
    
    def __init__(self, unlock_after: Optional[str] = None):
        details = {}
        if unlock_after:
            details["unlock_after"] = unlock_after
        super().__init__(
            message="Account is locked due to multiple failed login attempts. "
                    "Please contact your administrator or try again later.",
            details=details,
        )


class AccountDisabledError(AccountError):
    """Raised when account is disabled."""
    
    def __init__(self):
        super().__init__(
            message="Account has been disabled. Please contact your administrator."
        )


class AccountNotActiveError(AccountError):
    """Raised when account is not yet activated."""
    
    def __init__(self):
        super().__init__(
            message="Account is not yet activated. Please check your email."
        )


# ==========================
# Resource Exceptions
# ==========================

class NotFoundError(CyberGuardException):
    """Raised when a resource is not found."""
    
    def __init__(self, resource: str = "Resource", identifier: Optional[str] = None):
        message = f"{resource} not found"
        details = {"resource": resource}
        if identifier:
            details["identifier"] = identifier
        super().__init__(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class UserNotFoundError(NotFoundError):
    """Raised when a user is not found."""
    
    def __init__(self, identifier: Optional[str] = None):
        super().__init__(resource="User", identifier=identifier)


class OrganizationNotFoundError(NotFoundError):
    """Raised when an organization is not found."""
    
    def __init__(self, identifier: Optional[str] = None):
        super().__init__(resource="Organization", identifier=identifier)


# ==========================
# Validation Exceptions
# ==========================

class ValidationError(CyberGuardException):
    """Raised when validation fails."""
    
    def __init__(
        self,
        message: str = "Validation error",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


class PasswordValidationError(ValidationError):
    """Raised when password doesn't meet requirements."""
    
    def __init__(self, requirements: list):
        super().__init__(
            message="Password does not meet security requirements",
            details={"requirements": requirements}
        )


class EmailAlreadyExistsError(ValidationError):
    """Raised when attempting to register with existing email."""
    
    def __init__(self):
        super().__init__(
            message="An account with this email already exists"
        )


class OrganizationNameExistsError(ValidationError):
    """Raised when organization name is already taken."""
    
    def __init__(self):
        super().__init__(
            message="An organization with this name already exists"
        )


# ==========================
# Rate Limiting Exceptions
# ==========================

class RateLimitError(CyberGuardException):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, retry_after: int = 60):
        super().__init__(
            message="Too many requests. Please try again later.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details={"retry_after_seconds": retry_after}
        )


class LoginRateLimitError(RateLimitError):
    """Raised when login rate limit is exceeded."""
    
    def __init__(self, retry_after: int = 60):
        super().__init__(retry_after=retry_after)
        self.message = "Too many login attempts. Please try again later."


# ==========================
# Helper Functions
# ==========================

def exception_to_http_exception(exc: CyberGuardException) -> HTTPException:
    """
    Convert a CyberGuardException to FastAPI HTTPException.
    
    Args:
        exc: CyberGuardException instance
        
    Returns:
        HTTPException with appropriate status code and detail
    """
    return HTTPException(
        status_code=exc.status_code,
        detail={
            "message": exc.message,
            "details": exc.details,
        }
    )