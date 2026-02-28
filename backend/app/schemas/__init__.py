"""
Schemas Package Initialization
==============================

Exports all Pydantic schemas for the application.

Usage:
    from app.schemas import LoginRequest, TokenResponse, UserResponse
"""

# Auth schemas
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    LogoutResponse,
    RegisterRequest,
    RegisterResponse,
    TokenPayload,
    ErrorResponse,
    ValidationErrorResponse,
)

# User schemas
from app.schemas.user import (
    UserBase,
    UserCreate,
    UserUpdate,
    UserResponse,
    UserBriefResponse,
    UserListResponse,
    CurrentUserResponse,
    PasswordChangeRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    AccountStatusResponse,
    AccountUnlockRequest,
    AccountUnlockResponse,
)

# Organization schemas
from app.schemas.organization import (
    OrganizationBase,
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationWithUsersResponse,
    OrganizationListResponse,
    TenantContext,
)

__all__ = [
    # Auth
    "LoginRequest",
    "TokenResponse",
    "RefreshTokenRequest",
    "LogoutResponse",
    "RegisterRequest",
    "RegisterResponse",
    "TokenPayload",
    "ErrorResponse",
    "ValidationErrorResponse",
    # User
    "UserBase",
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "UserBriefResponse",
    "UserListResponse",
    "CurrentUserResponse",
    "PasswordChangeRequest",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "AccountStatusResponse",
    "AccountUnlockRequest",
    "AccountUnlockResponse",
    # Organization
    "OrganizationBase",
    "OrganizationCreate",
    "OrganizationUpdate",
    "OrganizationResponse",
    "OrganizationWithUsersResponse",
    "OrganizationListResponse",
    "TenantContext",
]
