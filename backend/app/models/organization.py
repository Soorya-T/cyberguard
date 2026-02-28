"""
Organization Model
==================

Represents a tenant in the multi-tenant architecture.

Each organization:
- Is isolated from other organizations
- Owns users
- Acts as a security boundary

Database Indexes:
- Primary key: id (UUID)
- Unique index: name
"""

import uuid
from datetime import datetime, UTC
from typing import TYPE_CHECKING, List

from sqlalchemy import (
    Column,
    String,
    DateTime,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class Organization(Base):
    """
    Organization Entity (Tenant Root).
    
    Represents a tenant in the multi-tenant architecture.
    All users belong to exactly one organization.
    
    Security Boundary:
        Organizations provide complete data isolation.
        Users can only access data within their organization.
        Super admins can access data across organizations.
    
    Attributes:
        id: UUID primary key
        name: Unique organization name
        created_at: Creation timestamp
        updated_at: Last update timestamp
        users: Relationship to users (lazy loaded)
    """
    
    __tablename__ = "organizations"
    
    # ==========================
    # Primary Key
    # ==========================
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    
    # ==========================
    # Organization Info
    # ==========================
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )
    
    # ==========================
    # Timestamps
    # ==========================
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    
    # ==========================
    # Relationships
    # ==========================
    users: Mapped[List["User"]] = relationship(
        "User",
        back_populates="organization",
        cascade="all, delete-orphan",
        lazy="selectin",  # Eager load for better performance
    )
    
    # ==========================
    # Indexes
    # ==========================
    # Note: Index is automatically created by unique=True on the name field
    
    # ==========================
    # Methods
    # ==========================
    
    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, name={self.name})>"
    
    @property
    def user_count(self) -> int:
        """
        Get the number of users in this organization.
        
        Returns:
            Number of users
        """
        return len(self.users) if self.users else 0
    
    def to_dict(self) -> dict:
        """
        Convert organization to dictionary.
        
        Returns:
            Dictionary with organization data
        """
        return {
            "id": str(self.id),
            "name": self.name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "user_count": self.user_count,
        }
