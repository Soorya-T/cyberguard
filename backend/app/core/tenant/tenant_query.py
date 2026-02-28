"""
Tenant Query Utilities Module
=============================

Provides utilities for multi-tenant data isolation.

Features:
- Automatic tenant filtering for queries
- SUPER_ADMIN bypass for cross-tenant access
- Tenant validation helpers

Security:
- Enforces tenant isolation at the query level
- Logs tenant isolation violations
"""

from typing import TypeVar, Generic, Type
from uuid import UUID

from sqlalchemy.orm import Query, Session
from fastapi import HTTPException, status

from app.models.role_enum import Role
from app.models.user import User
from app.core.logging import get_logger, security_logger

# Initialize logger
logger = get_logger(__name__)

# Generic type for models with tenant_id
T = TypeVar("T")


class TenantQuery:
    """
    Helper class for tenant-isolated database queries.
    
    Provides methods to automatically filter queries by tenant_id
    and validate tenant access.
    
    Usage:
        tenant_query = TenantQuery(db, User, current_user)
        users = tenant_query.filter_by_tenant().all()
    """
    
    def __init__(self, db: Session, model: Type[T], current_user: User):
        """
        Initialize tenant query helper.
        
        Args:
            db: Database session
            model: SQLAlchemy model class
            current_user: Current authenticated user
        """
        self.db = db
        self.model = model
        self.current_user = current_user
        self._base_query = db.query(model)
    
    def filter_by_tenant(self) -> Query:
        """
        Get query filtered by current user's tenant.
        
        SUPER_ADMIN users can access all tenants.
        Other users can only access their own tenant.
        
        Returns:
            Filtered SQLAlchemy query
        """
        if self.current_user.role == Role.SUPER_ADMIN:
            # Super admins can access all tenants
            return self._base_query
        
        # Check if model has tenant_id attribute
        if not hasattr(self.model, 'tenant_id'):
            # Model doesn't have tenant_id (e.g., Organization model)
            # Return base query - tenant isolation doesn't apply
            return self._base_query
        
        # Filter by tenant_id
        return self._base_query.filter(
            self.model.tenant_id == self.current_user.tenant_id
        )
    
    def filter_by_tenant_id(self, tenant_id: UUID) -> Query:
        """
        Get query filtered by specific tenant.
        
        Validates that the user has access to the specified tenant.
        
        Args:
            tenant_id: Tenant UUID to filter by
            
        Returns:
            Filtered SQLAlchemy query
            
        Raises:
            HTTPException: If user doesn't have access to tenant
        """
        # Validate tenant access
        if not self._validate_tenant_access(tenant_id):
            security_logger.log_tenant_isolation_violation(
                user_id=str(self.current_user.id),
                user_tenant=str(self.current_user.tenant_id),
                target_tenant=str(tenant_id),
                resource=self.model.__tablename__,
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: resource belongs to different organization",
            )
        
        return self._base_query.filter(self.model.tenant_id == tenant_id)
    
    def get_by_id(self, resource_id: UUID) -> T:
        """
        Get a resource by ID with tenant validation.
        
        Args:
            resource_id: Resource UUID
            
        Returns:
            Resource instance or None
            
        Raises:
            HTTPException: If resource belongs to different tenant
        """
        resource = self._base_query.filter(self.model.id == resource_id).first()
        
        if resource is None:
            return None
        
        # Validate tenant access
        if hasattr(resource, "tenant_id"):
            if not self._validate_tenant_access(resource.tenant_id):
                security_logger.log_tenant_isolation_violation(
                    user_id=str(self.current_user.id),
                    user_tenant=str(self.current_user.tenant_id),
                    target_tenant=str(resource.tenant_id),
                    resource=self.model.__tablename__,
                )
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: resource belongs to different organization",
                )
        
        return resource
    
    def _validate_tenant_access(self, target_tenant_id: UUID) -> bool:
        """
        Validate that user has access to the target tenant.
        
        Args:
            target_tenant_id: Tenant UUID to check
            
        Returns:
            True if access is allowed
        """
        # Super admins can access all tenants
        if self.current_user.role == Role.SUPER_ADMIN:
            return True
        
        # Check if user belongs to target tenant
        return self.current_user.tenant_id == target_tenant_id


# =====================================
# Convenience Functions
# =====================================

def tenant_query(db: Session, model: Type[T], current_user: User) -> Query:
    """
    Get a tenant-filtered query for a model.
    
    This is a convenience function for simple use cases.
    For more complex queries, use the TenantQuery class.
    
    Args:
        db: Database session
        model: SQLAlchemy model class
        current_user: Current authenticated user
        
    Returns:
        Filtered SQLAlchemy query
        
    Usage:
        users = tenant_query(db, User, current_user).all()
    """
    return TenantQuery(db, model, current_user).filter_by_tenant()


def validate_tenant_access(current_user: User, target_tenant_id: UUID) -> bool:
    """
    Validate that user has access to the target tenant.
    
    Args:
        current_user: Current authenticated user
        target_tenant_id: Tenant UUID to check
        
    Returns:
        True if access is allowed
        
    Raises:
        HTTPException: If access is denied
    """
    # Super admins can access all tenants
    if current_user.role == Role.SUPER_ADMIN:
        return True
    
    # Check if user belongs to target tenant
    if current_user.tenant_id != target_tenant_id:
        security_logger.log_tenant_isolation_violation(
            user_id=str(current_user.id),
            user_tenant=str(current_user.tenant_id),
            target_tenant=str(target_tenant_id),
            resource="validation",
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: resource belongs to different organization",
        )
    
    return True


def get_tenant_filter(current_user: User) -> dict:
    """
    Get tenant filter for dictionary-based filtering.
    
    Useful for filter_by() queries.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Dictionary with tenant_id filter (empty for super admins)
        
    Usage:
        users = db.query(User).filter_by(**get_tenant_filter(current_user)).all()
    """
    if current_user.role == Role.SUPER_ADMIN:
        return {}
    
    return {"tenant_id": current_user.tenant_id}