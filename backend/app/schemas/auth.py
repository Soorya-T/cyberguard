"""
Authentication Schemas Module
=============================

Pydantic models for authentication request/response validation.

Benefits:
- Request validation
- Response serialization
- OpenAPI documentation
- Type safety
"""

from datetime import datetime, UTC
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
import re


# ==========================
# Base Schemas
# ==========================

class BaseResponse(BaseModel):
    """Base response schema with common fields."""
    
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "message": "Success"
            }
        }
    )


# ==========================
# Login Schemas
# ==========================

class LoginRequest(BaseModel):
    """Login request schema."""
    
    email: EmailStr = Field(
        ...,
        description="User email address",
        examples=["user@example.com"]
    )
    password: str = Field(
        ...,
        min_length=1,
        description="User password",
        examples=["SecureP@ss123"]
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecureP@ss123"
            }
        }
    )


class TokenResponse(BaseModel):
    """Token response schema for login/refresh."""
    
    access_token: str = Field(
        ...,
        description="JWT access token"
    )
    refresh_token: str = Field(
        ...,
        description="JWT refresh token"
    )
    token_type: str = Field(
        default="bearer",
        description="Token type"
    )
    expires_in: Optional[int] = Field(
        default=None,
        description="Access token expiration in seconds"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 900
            }
        }
    )


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""
    
    refresh_token: str = Field(
        ...,
        description="Valid refresh token"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }
    )


# ==========================
# Logout Schemas
# ==========================

class LogoutResponse(BaseModel):
    """Logout response schema."""
    
    message: str = Field(
        default="Successfully logged out",
        description="Logout confirmation message"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Successfully logged out"
            }
        }
    )


# ==========================
# Registration Schemas
# ==========================

class RegisterRequest(BaseModel):
    """User registration request schema."""
    
    email: EmailStr = Field(
        ...,
        description="User email address"
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password (min 8 characters)"
    )
    organization_name: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="Organization name"
    )
    
    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements."""
        errors = []
        
        if len(v) < 8:
            errors.append("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", v):
            errors.append("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            errors.append("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            errors.append("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            errors.append("Password must contain at least one special character")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return v
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "newuser@example.com",
                "password": "SecureP@ss123",
                "organization_name": "Acme Corp"
            }
        }
    )


class RegisterResponse(BaseModel):
    """Registration response schema."""
    
    message: str = Field(
        default="User registered successfully",
        description="Registration confirmation message"
    )
    user_id: str = Field(
        ...,
        description="New user's UUID"
    )
    organization_id: str = Field(
        ...,
        description="New organization's UUID"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "User registered successfully",
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "organization_id": "550e8400-e29b-41d4-a716-446655440001"
            }
        }
    )


# ==========================
# Token Payload Schemas
# ==========================

class TokenPayload(BaseModel):
    """JWT token payload schema (for internal use)."""
    
    sub: str  # User ID
    tenant_id: str  # Organization ID
    token_version: int
    type: str  # "access" or "refresh"
    exp: int  # Expiration timestamp
    iat: Optional[int] = None  # Issued at timestamp
    iss: Optional[str] = None  # Issuer
    aud: Optional[str] = None  # Audience


# ==========================
# Error Schemas
# ==========================

class ErrorResponse(BaseModel):
    """Standard error response schema."""
    
    message: str = Field(
        ...,
        description="Error message"
    )
    details: Optional[dict] = Field(
        default=None,
        description="Additional error details"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Invalid credentials",
                "details": {"field": "password"}
            }
        }
    )


class ValidationErrorDetail(BaseModel):
    """Validation error detail schema."""
    
    loc: list = Field(
        ...,
        description="Location of the error"
    )
    msg: str = Field(
        ...,
        description="Error message"
    )
    type: str = Field(
        ...,
        description="Error type"
    )


class ValidationErrorResponse(BaseModel):
    """Validation error response schema."""
    
    detail: list[ValidationErrorDetail] = Field(
        ...,
        description="List of validation errors"
    )
