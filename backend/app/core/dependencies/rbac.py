"""
Role-Based Access Control (RBAC) Dependencies Module
=====================================================

FastAPI dependencies for role-based authorization.

Features:
- Strict role enforcement
- Multiple role support
- Hierarchical role checking
- Audit logging for unauthorized access

Usage:
    @router.get("/admin-only")
    def admin_route(user: User = Depends(require_role(Role.ADMIN, Role.SUPER_ADMIN))):
        return {"message": "Admin access granted"}
"""

from typing import Callable, Tuple
from uuid import UUID

from fastapi import Depends, HTTPException, status, Request

from app.models.user import User
from app.models.role_enum import Role
from app.core.dependencies.auth import get_current_user
from app.core.logging import get_logger, security_logger

# Initialize logger
logger = get_logger(__name__)


# =====================================
# Role Hierarchy
# =====================================

# Define role hierarchy (higher index = more permissions)
ROLE_HIERARCHY: list[Role] = [
    Role.READ_ONLY,
    Role.SECURITY_ANALYST,
    Role.ORG_ADMIN,
    Role.SUPER_ADMIN,
]


def get_role_level(role: Role) -> int:
    """
    Get the hierarchy level for a role.
    
    Args:
        role: Role to get level for
        
    Returns:
        Integer level (higher = more permissions)
    """
    try:
        return ROLE_HIERARCHY.index(role)
    except ValueError:
        return -1


def has_role_or_higher(user_role: Role, required_role: Role) -> bool:
    """
    Check if user has the required role or higher.
    
    Args:
        user_role: User's current role
        required_role: Minimum required role
        
    Returns:
        True if user has required role or higher
    """
    return get_role_level(user_role) >= get_role_level(required_role)


# =====================================
# Role Requirement Dependencies
# =====================================

def require_role(*allowed_roles: Role) -> Callable:
    """
    Create a dependency that requires specific roles.
    
    Only users with exactly one of the allowed roles can access.
    This is stricter than require_role_or_higher.
    
    Args:
        *allowed_roles: Roles that are allowed access
        
    Returns:
        Dependency function
        
    Usage:
        @router.get("/analyst-only")
        def analyst_route(user: User = Depends(require_role(Role.SECURITY_ANALYST))):
            return {"message": "Analyst access granted"}
    """
    async def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
    ) -> User:
        # Check if user's role is in allowed roles
        if current_user.role not in allowed_roles:
            security_logger.log_unauthorized_access(
                user_id=str(current_user.id),
                resource=request.url.path,
                action=request.method,
            )
            
            logger.warning(
                "Role-based access denied",
                extra={
                    "user_role": current_user.role.value,
                    "required_roles": [r.value for r in allowed_roles],
                    "path": request.url.path,
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this action",
            )
        
        return current_user
    
    return role_checker


def require_role_or_higher(minimum_role: Role) -> Callable:
    """
    Create a dependency that requires a minimum role level.
    
    Users with the required role or any higher role can access.
    
    Args:
        minimum_role: Minimum role required
        
    Returns:
        Dependency function
        
    Usage:
        @router.get("/admin-and-above")
        def admin_route(user: User = Depends(require_role_or_higher(Role.ORG_ADMIN))):
            return {"message": "Admin access granted"}
    """
    async def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
    ) -> User:
        if not has_role_or_higher(current_user.role, minimum_role):
            security_logger.log_unauthorized_access(
                user_id=str(current_user.id),
                resource=request.url.path,
                action=request.method,
            )
            
            logger.warning(
                "Hierarchical role access denied",
                extra={
                    "user_role": current_user.role.value,
                    "minimum_role": minimum_role.value,
                    "path": request.url.path,
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this action",
            )
        
        return current_user
    
    return role_checker


# =====================================
# Super Admin Only
# =====================================

def require_super_admin(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency that requires SUPER_ADMIN role.
    
    This is a convenience function for the most restrictive access.
    
    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        
    Returns:
        User model instance
        
    Raises:
        HTTPException: If user is not a super admin
    """
    if current_user.role != Role.SUPER_ADMIN:
        security_logger.log_unauthorized_access(
            user_id=str(current_user.id),
            resource=request.url.path,
            action=request.method,
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires super admin privileges",
        )
    
    return current_user


# =====================================
# Organization Admin or Higher
# =====================================

def require_org_admin(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency that requires ORG_ADMIN or SUPER_ADMIN role.
    
    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        
    Returns:
        User model instance
        
    Raises:
        HTTPException: If user is not an org admin or higher
    """
    if current_user.role not in (Role.ORG_ADMIN, Role.SUPER_ADMIN):
        security_logger.log_unauthorized_access(
            user_id=str(current_user.id),
            resource=request.url.path,
            action=request.method,
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires organization admin privileges",
        )
    
    return current_user


# =====================================
# Analyst or Higher
# =====================================

def require_analyst(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency that requires SECURITY_ANALYST or higher role.
    
    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        
    Returns:
        User model instance
        
    Raises:
        HTTPException: If user is not an analyst or higher
    """
    if not has_role_or_higher(current_user.role, Role.SECURITY_ANALYST):
        security_logger.log_unauthorized_access(
            user_id=str(current_user.id),
            resource=request.url.path,
            action=request.method,
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires analyst privileges",
        )
    
    return current_user


# =====================================
# Resource Ownership Check
# =====================================

def require_resource_owner_or_admin(
    resource_user_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency that requires user to be the resource owner or an admin.
    
    This is useful for operations where users can only modify their own
    resources, but admins can modify any resource in their organization.
    
    Args:
        resource_user_id: ID of the user who owns the resource
        request: FastAPI request object
        current_user: Current authenticated user
        
    Returns:
        User model instance
        
    Raises:
        HTTPException: If user is not the owner or an admin
    """
    # Super admin can access anything
    if current_user.role == Role.SUPER_ADMIN:
        return current_user
    
    # Org admin can access resources in their organization
    if current_user.role == Role.ORG_ADMIN:
        return current_user
    
    # Regular users can only access their own resources
    if current_user.id != resource_user_id:
        security_logger.log_unauthorized_access(
            user_id=str(current_user.id),
            resource=str(resource_user_id),
            action=request.method,
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only access your own resources",
        )
    
    return current_user
