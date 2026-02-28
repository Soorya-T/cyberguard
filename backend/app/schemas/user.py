"""
User Schemas Module
===================

Pydantic models for user-related request/response validation.

Benefits:
- Request validation
- Response serialization
- OpenAPI documentation
- Type safety
- Sensitive data exclusion
"""

from datetime import datetime, UTC
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from app.models.role_enum import Role


# ==========================
# Base Schemas
# ==========================

class UserBase(BaseModel):
    """Base user schema with common fields."""
    
    email: EmailStr = Field(
        ...,
        description="User email address"
    )


class UserCreate(UserBase):
    """Schema for creating a new user (admin use)."""
    
    password: str = Field(
        ...,
        min_length=8,
        description="User password"
    )
    role: Role = Field(
        default=Role.READ_ONLY,
        description="User role"
    )
    tenant_id: UUID = Field(
        ...,
        description="Organization ID"
    )


class UserUpdate(BaseModel):
    """Schema for updating user information."""
    
    email: Optional[EmailStr] = Field(
        default=None,
        description="New email address"
    )
    role: Optional[Role] = Field(
        default=None,
        description="New role"
    )
    is_active: Optional[bool] = Field(
        default=None,
        description="Account active status"
    )


# ==========================
# Response Schemas
# ==========================

class UserResponse(BaseModel):
    """User response schema (excludes sensitive data)."""
    
    id: UUID = Field(
        ...,
        description="User UUID"
    )
    email: str = Field(
        ...,
        description="User email address"
    )
    role: Role = Field(
        ...,
        description="User role"
    )
    tenant_id: UUID = Field(
        ...,
        description="Organization ID"
    )
    is_active: bool = Field(
        ...,
        description="Account active status"
    )
    is_locked: bool = Field(
        ...,
        description="Account locked status"
    )
    created_at: datetime = Field(
        ...,
        description="Account creation timestamp"
    )
    
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "email": "user@example.com",
                "role": "SECURITY_ANALYST",
                "tenant_id": "550e8400-e29b-41d4-a716-446655440001",
                "is_active": True,
                "is_locked": False,
                "created_at": "2024-01-15T10:30:00Z"
            }
        }
    )


class UserBriefResponse(BaseModel):
    """Brief user response for nested references."""
    
    id: UUID
    email: str
    role: Role
    
    model_config = ConfigDict(from_attributes=True)


class UserListResponse(BaseModel):
    """Response schema for user list."""
    
    users: list[UserResponse]
    total: int = Field(
        ...,
        description="Total number of users"
    )
    page: int = Field(
        default=1,
        description="Current page number"
    )
    page_size: int = Field(
        default=20,
        description="Number of users per page"
    )


# ==========================
# Current User Schema
# ==========================

class CurrentUserResponse(BaseModel):
    """
    Current authenticated user response.
    
    Includes tenant information for frontend use.
    """
    
    id: UUID = Field(
        ...,
        description="User UUID"
    )
    email: str = Field(
        ...,
        description="User email address"
    )
    role: Role = Field(
        ...,
        description="User role"
    )
    tenant_id: UUID = Field(
        ...,
        description="Organization ID"
    )
    is_active: bool = Field(
        ...,
        description="Account active status"
    )
    
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "email": "user@example.com",
                "role": "SECURITY_ANALYST",
                "tenant_id": "550e8400-e29b-41d4-a716-446655440001",
                "is_active": True
            }
        }
    )


# ==========================
# Password Schemas
# ==========================

class PasswordChangeRequest(BaseModel):
    """Schema for password change request."""
    
    current_password: str = Field(
        ...,
        min_length=1,
        description="Current password"
    )
    new_password: str = Field(
        ...,
        min_length=8,
        description="New password"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "current_password": "OldP@ss123",
                "new_password": "NewSecureP@ss456"
            }
        }
    )


class PasswordResetRequest(BaseModel):
    """Schema for password reset request."""
    
    email: EmailStr = Field(
        ...,
        description="Email address for password reset"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com"
            }
        }
    )


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation."""
    
    token: str = Field(
        ...,
        description="Password reset token"
    )
    new_password: str = Field(
        ...,
        min_length=8,
        description="New password"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "reset-token-here",
                "new_password": "NewSecureP@ss456"
            }
        }
    )


# ==========================
# Account Status Schemas
# ==========================

class AccountStatusResponse(BaseModel):
    """Schema for account status response."""
    
    is_active: bool
    is_locked: bool
    failed_attempts: int
    token_version: int
    
    model_config = ConfigDict(from_attributes=True)


class AccountUnlockRequest(BaseModel):
    """Schema for account unlock request (admin use)."""
    
    user_id: UUID = Field(
        ...,
        description="User ID to unlock"
    )


class AccountUnlockResponse(BaseModel):
    """Schema for account unlock response."""
    
    message: str = Field(
        default="Account unlocked successfully"
    )
    user_id: UUID
