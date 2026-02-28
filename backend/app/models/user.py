"""
User Model
==========

Security Features:
- Strict tenant isolation (tenant_id required)
- Account lock after configurable failed attempts
- Token version for JWT invalidation
- Enum-based role enforcement (STRICT MODE)
- Soft delete support via is_active flag

Database Indexes:
- Primary key: id (UUID)
- Unique index: email
- Index: tenant_id (for tenant isolation queries)
"""

import uuid
from datetime import datetime, UTC
from typing import TYPE_CHECKING, List

from sqlalchemy import (
    Column,
    String,
    Boolean,
    Integer,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.db.base import Base
from app.models.role_enum import Role

if TYPE_CHECKING:
    from app.models.organization import Organization


class User(Base):
    """
    User entity representing authenticated system users.
    
    Multi-Tenant Enforcement:
        Every user must belong to an organization (tenant_id is required).
        Tenant isolation is enforced at the application layer.
    
    Security Controls:
        - failed_attempts: Counter for failed login attempts
        - is_locked: Account lock flag
        - token_version: For forced logout/token invalidation
        - is_active: Soft delete flag
    
    Attributes:
        id: UUID primary key
        tenant_id: Foreign key to organization
        email: Unique email address
        hashed_password: Argon2 hashed password
        role: User role (enum)
        is_active: Account active status
        failed_attempts: Failed login counter
        is_locked: Account lock status
        token_version: JWT version for invalidation
        created_at: Account creation timestamp
        updated_at: Last update timestamp
    """
    
    __tablename__ = "users"
    
    def __init__(self, **kwargs):
        """Initialize User with Python-level defaults."""
        # Set Python-level defaults before calling parent __init__
        if 'role' not in kwargs:
            kwargs['role'] = Role.READ_ONLY
        if 'is_active' not in kwargs:
            kwargs['is_active'] = True
        if 'failed_attempts' not in kwargs:
            kwargs['failed_attempts'] = 0
        if 'is_locked' not in kwargs:
            kwargs['is_locked'] = False
        if 'token_version' not in kwargs:
            kwargs['token_version'] = 1
        super().__init__(**kwargs)
    
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
    # Tenant Isolation
    # ==========================
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # Relationship to organization
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="users",
    )
    
    # ==========================
    # Authentication
    # ==========================
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    
    # ==========================
    # Authorization (STRICT ENUM)
    # ==========================
    role: Mapped[Role] = mapped_column(
        String(50),  # Store as string for flexibility
        nullable=False,
        default=Role.READ_ONLY,  # Role is a str enum, so this works
    )
    
    # ==========================
    # Account Status
    # ==========================
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    
    # Lockout Protection
    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    
    is_locked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    
    # JWT Version Control
    token_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
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
    # Indexes
    # ==========================
    # Note: Indexes for tenant_id and email are created automatically by index=True
    __table_args__ = (
        Index("ix_users_role", "role"),
    )
    
    # ==========================
    # Methods
    # ==========================
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated (for FastAPI Depends)."""
        return True
    
    def lock_account(self) -> None:
        """Lock the user account."""
        self.is_locked = True
    
    def unlock_account(self) -> None:
        """Unlock the user account and reset failed attempts."""
        self.is_locked = False
        self.failed_attempts = 0
    
    def increment_failed_attempts(self, max_attempts: int = 5) -> bool:
        """
        Increment failed login attempts.
        
        Args:
            max_attempts: Maximum attempts before lockout
            
        Returns:
            True if account should be locked
        """
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.lock_account()
            return True
        return False
    
    def reset_failed_attempts(self) -> None:
        """Reset failed login attempts counter."""
        self.failed_attempts = 0
    
    def invalidate_tokens(self) -> None:
        """Invalidate all tokens by incrementing version."""
        self.token_version += 1
    
    def to_dict(self) -> dict:
        """
        Convert user to dictionary (excludes sensitive data).
        
        Returns:
            Dictionary with user data
        """
        return {
            "id": str(self.id),
            "email": self.email,
            "role": self.role if isinstance(self.role, str) else self.role.value,
            "tenant_id": str(self.tenant_id),
            "is_active": self.is_active,
            "is_locked": self.is_locked,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
