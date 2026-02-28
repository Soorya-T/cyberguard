"""
Admin Routes Module
===================

Administrative endpoints for system management.

Features:
- Super Admin only endpoints
- Organization management
- User management
- System statistics

Security:
- All endpoints require SUPER_ADMIN role
- All actions are audit logged
- Tenant isolation is enforced
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.models.user import User
from app.models.organization import Organization
from app.models.role_enum import Role
from app.core.dependencies.auth import get_current_user
from app.core.dependencies.rbac import require_super_admin, require_org_admin
from app.core.logging import get_logger, audit_logger
from app.core.exceptions import NotFoundError, ValidationError
from app.schemas import (
    UserResponse,
    UserListResponse,
    UserUpdate,
    OrganizationResponse,
    OrganizationListResponse,
    ErrorResponse,
)

# Initialize logger
logger = get_logger(__name__)


# =====================================
# Router Setup
# =====================================

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
    responses={
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)


# =====================================
# Dashboard Endpoint
# =====================================

@router.get(
    "/dashboard",
    summary="Admin Dashboard",
    description="Get system statistics and overview. Requires SUPER_ADMIN role.",
    responses={
        200: {"description": "Dashboard statistics"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
    },
)
def admin_dashboard(
    request: Request,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get admin dashboard statistics.
    
    Requires SUPER_ADMIN role.
    
    Args:
        request: FastAPI request
        current_user: Current authenticated user (must be SUPER_ADMIN)
        db: Database session
        
    Returns:
        Dashboard statistics
    """
    # Get statistics
    total_users = db.query(func.count(User.id)).scalar() or 0
    total_organizations = db.query(func.count(Organization.id)).scalar() or 0
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 0
    locked_users = db.query(func.count(User.id)).filter(User.is_locked == True).scalar() or 0
    
    # Get users by role
    users_by_role = (
        db.query(User.role, func.count(User.id))
        .group_by(User.role)
        .all()
    )
    
    role_counts = {role.value if hasattr(role, 'value') else role: count for role, count in users_by_role}
    
    logger.info(
        "Admin dashboard accessed",
        extra={
            "user_id": str(current_user.id),
            "ip_address": request.client.host if request.client else "unknown",
        }
    )
    
    return {
        "message": "Admin access granted",
        "user": current_user.email,
        "statistics": {
            "total_users": total_users,
            "total_organizations": total_organizations,
            "active_users": active_users,
            "locked_users": locked_users,
            "users_by_role": role_counts,
        },
    }


# =====================================
# User Management Endpoints
# =====================================

@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List All Users",
    description="List all users across all organizations. Requires SUPER_ADMIN role.",
    responses={
        200: {"description": "List of users"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
    },
)
def list_users(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Users per page"),
    role: Optional[Role] = Query(None, description="Filter by role"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    List all users with pagination and filtering.
    
    Requires SUPER_ADMIN role.
    
    Args:
        request: FastAPI request
        page: Page number
        page_size: Users per page
        role: Optional role filter
        is_active: Optional active status filter
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Paginated list of users
    """
    query = db.query(User)
    
    # Apply filters
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * page_size
    users = query.order_by(User.created_at.desc()).offset(offset).limit(page_size).all()
    
    return {
        "users": [
            {
                "id": str(user.id),
                "email": user.email,
                "role": user.role.value if hasattr(user.role, 'value') else user.role,
                "tenant_id": str(user.tenant_id),
                "is_active": user.is_active,
                "is_locked": user.is_locked,
                "created_at": user.created_at,
            }
            for user in users
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get(
    "/users/{user_id}",
    response_model=UserResponse,
    summary="Get User by ID",
    description="Get detailed user information. Requires SUPER_ADMIN role.",
    responses={
        200: {"description": "User details"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
)
def get_user(
    user_id: UUID,
    request: Request,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get user by ID.
    
    Requires SUPER_ADMIN role.
    
    Args:
        user_id: User UUID
        request: FastAPI request
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        User details
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise NotFoundError(resource="User", identifier=str(user_id))
    
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role.value if hasattr(user.role, 'value') else user.role,
        "tenant_id": str(user.tenant_id),
        "is_active": user.is_active,
        "is_locked": user.is_locked,
        "created_at": user.created_at,
    }


@router.patch(
    "/users/{user_id}",
    response_model=UserResponse,
    summary="Update User",
    description="Update user information. Requires SUPER_ADMIN role.",
    responses={
        200: {"description": "User updated"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
)
def update_user(
    user_id: UUID,
    update_data: UserUpdate,
    request: Request,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Update user information.
    
    Requires SUPER_ADMIN role.
    
    Args:
        user_id: User UUID
        update_data: Update data
        request: FastAPI request
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Updated user details
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise NotFoundError(resource="User", identifier=str(user_id))
    
    # Track changes for audit
    changes = {}
    
    if update_data.email is not None and update_data.email != user.email:
        # Check if email is already taken
        existing = db.query(User).filter(User.email == update_data.email).first()
        if existing:
            raise ValidationError(message="Email already in use")
        changes["email"] = {"old": user.email, "new": update_data.email}
        user.email = update_data.email
    
    if update_data.role is not None and update_data.role != user.role:
        old_role = user.role.value if hasattr(user.role, 'value') else user.role
        new_role = update_data.role.value if hasattr(update_data.role, 'value') else update_data.role
        changes["role"] = {"old": old_role, "new": new_role}
        user.role = update_data.role
    
    if update_data.is_active is not None and update_data.is_active != user.is_active:
        changes["is_active"] = {"old": user.is_active, "new": update_data.is_active}
        user.is_active = update_data.is_active
    
    db.commit()
    
    # Audit log
    if changes:
        audit_logger.log_user_modified(
            actor_id=str(current_user.id),
            target_user_id=str(user.id),
            changes=changes,
        )
    
    logger.info(
        "User updated by admin",
        extra={
            "admin_id": str(current_user.id),
            "target_user_id": str(user.id),
            "changes": changes,
        }
    )
    
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role.value if hasattr(user.role, 'value') else user.role,
        "tenant_id": str(user.tenant_id),
        "is_active": user.is_active,
        "is_locked": user.is_locked,
        "created_at": user.created_at,
    }


@router.post(
    "/users/{user_id}/unlock",
    summary="Unlock User Account",
    description="Unlock a locked user account. Requires SUPER_ADMIN role.",
    responses={
        200: {"description": "Account unlocked"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
)
def unlock_user(
    user_id: UUID,
    request: Request,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Unlock a locked user account.
    
    Requires SUPER_ADMIN role.
    
    Args:
        user_id: User UUID
        request: FastAPI request
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Success message
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise NotFoundError(resource="User", identifier=str(user_id))
    
    if not user.is_locked:
        return {"message": "Account is not locked", "user_id": str(user_id)}
    
    user.is_locked = False
    user.failed_attempts = 0
    db.commit()
    
    logger.info(
        "User account unlocked by admin",
        extra={
            "admin_id": str(current_user.id),
            "target_user_id": str(user.id),
        }
    )
    
    return {"message": "Account unlocked successfully", "user_id": str(user_id)}


# =====================================
# Organization Management Endpoints
# =====================================

@router.get(
    "/organizations",
    response_model=OrganizationListResponse,
    summary="List All Organizations",
    description="List all organizations. Requires SUPER_ADMIN role.",
    responses={
        200: {"description": "List of organizations"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
    },
)
def list_organizations(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Organizations per page"),
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    List all organizations with pagination.
    
    Requires SUPER_ADMIN role.
    
    Args:
        request: FastAPI request
        page: Page number
        page_size: Organizations per page
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Paginated list of organizations
    """
    query = db.query(Organization)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * page_size
    organizations = query.order_by(Organization.created_at.desc()).offset(offset).limit(page_size).all()
    
    return {
        "organizations": [
            {
                "id": str(org.id),
                "name": org.name,
                "created_at": org.created_at,
            }
            for org in organizations
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get(
    "/organizations/{org_id}",
    response_model=OrganizationResponse,
    summary="Get Organization by ID",
    description="Get organization details. Requires SUPER_ADMIN role.",
    responses={
        200: {"description": "Organization details"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        404: {"model": ErrorResponse, "description": "Organization not found"},
    },
)
def get_organization(
    org_id: UUID,
    request: Request,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get organization by ID.
    
    Requires SUPER_ADMIN role.
    
    Args:
        org_id: Organization UUID
        request: FastAPI request
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Organization details
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    if not org:
        raise NotFoundError(resource="Organization", identifier=str(org_id))
    
    return {
        "id": str(org.id),
        "name": org.name,
        "created_at": org.created_at,
    }
