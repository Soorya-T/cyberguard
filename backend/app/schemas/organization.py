"""
Organization Schemas Module
===========================

Pydantic models for organization-related request/response validation.

Benefits:
- Request validation
- Response serialization
- OpenAPI documentation
- Type safety
"""

from datetime import datetime, UTC
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


# ==========================
# Base Schemas
# ==========================

class OrganizationBase(BaseModel):
    """Base organization schema with common fields."""
    
    name: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="Organization name"
    )


class OrganizationCreate(OrganizationBase):
    """Schema for creating a new organization."""
    
    pass
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Acme Corporation"
            }
        }
    )


class OrganizationUpdate(BaseModel):
    """Schema for updating organization information."""
    
    name: Optional[str] = Field(
        default=None,
        min_length=2,
        max_length=255,
        description="New organization name"
    )


# ==========================
# Response Schemas
# ==========================

class OrganizationResponse(BaseModel):
    """Organization response schema."""
    
    id: UUID = Field(
        ...,
        description="Organization UUID"
    )
    name: str = Field(
        ...,
        description="Organization name"
    )
    created_at: datetime = Field(
        ...,
        description="Creation timestamp"
    )
    
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Acme Corporation",
                "created_at": "2024-01-15T10:30:00Z"
            }
        }
    )


class OrganizationWithUsersResponse(OrganizationResponse):
    """Organization response with user count."""
    
    user_count: int = Field(
        default=0,
        description="Number of users in organization"
    )
    
    model_config = ConfigDict(from_attributes=True)


class OrganizationListResponse(BaseModel):
    """Response schema for organization list."""
    
    organizations: list[OrganizationResponse]
    total: int = Field(
        ...,
        description="Total number of organizations"
    )
    page: int = Field(
        default=1,
        description="Current page number"
    )
    page_size: int = Field(
        default=20,
        description="Number of organizations per page"
    )


# ==========================
# Tenant Context Schema
# ==========================

class TenantContext(BaseModel):
    """
    Tenant context for request processing.
    
    Used internally for tenant isolation validation.
    """
    
    tenant_id: UUID
    organization_name: str
    
    model_config = ConfigDict(from_attributes=True)
