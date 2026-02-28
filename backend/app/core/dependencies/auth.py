"""
Authentication Dependencies Module
==================================

FastAPI dependencies for authentication and user extraction.

Features:
- JWT token validation
- User extraction from token
- Tenant context validation
- Account status verification

Usage:
    @router.get("/protected")
    def protected_route(user: User = Depends(get_current_user)):
        return {"user": user.email}
"""

from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    TokenVersionMismatchError,
    AccountLockedError,
    AccountDisabledError,
    TokenInvalidError,
)
from app.core.logging import get_logger, security_logger, request_id_context
from app.db.session import get_db
from app.models.user import User
from app.services.auth_service import AuthService, TokenType

# Initialize logger
logger = get_logger(__name__)


# =====================================
# OAuth2 Scheme
# =====================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
    auto_error=True,
    description="OAuth2 token for authentication",
)


# =====================================
# Optional OAuth2 Scheme (for public endpoints)
# =====================================

class OptionalOAuth2PasswordBearer(OAuth2PasswordBearer):
    """OAuth2 scheme that doesn't raise error if token is missing."""
    
    async def __call__(self, request: Request) -> Optional[str]:
        try:
            return await super().__call__(request)
        except HTTPException:
            return None


optional_oauth2_scheme = OptionalOAuth2PasswordBearer(
    tokenUrl="/auth/login",
    auto_error=False,
)


# =====================================
# Get Current User
# =====================================

def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Validate JWT and return current user from database.
    
    Security checks performed:
    - Token signature validation
    - Token expiration check
    - Token type validation (must be access token)
    - Token version validation (for revocation)
    - Account status check (locked/disabled)
    
    Args:
        request: FastAPI request object
        token: JWT token from Authorization header
        db: Database session
        
    Returns:
        User model instance
        
    Raises:
        HTTPException: If authentication fails
    """
    auth_service = AuthService(db)
    
    try:
        # Validate token and get user
        user = auth_service.validate_access_token(token)
        
        # Set request context for logging
        request.state.user_id = str(user.id)
        request.state.tenant_id = str(user.tenant_id)
        
        return user
        
    except TokenInvalidError as e:
        logger.warning(
            "Invalid token presented",
            extra={"reason": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    except TokenVersionMismatchError:
        security_logger.log_token_invalid(
            reason="token_version_mismatch",
            ip_address=request.client.host if request.client else "unknown"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been invalidated. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    except AccountLockedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked. Please contact your administrator.",
        )
    
    except AccountDisabledError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been disabled. Please contact your administrator.",
        )


# =====================================
# Get Current User (Optional)
# =====================================

def get_current_user_optional(
    request: Request,
    token: Optional[str] = Depends(optional_oauth2_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Get current user if authenticated, otherwise return None.
    
    Useful for endpoints that behave differently for authenticated users
    but don't require authentication.
    
    Args:
        request: FastAPI request object
        token: Optional JWT token
        db: Database session
        
    Returns:
        User model instance or None
    """
    if token is None:
        return None
    
    try:
        auth_service = AuthService(db)
        user = auth_service.validate_access_token(token)
        request.state.user_id = str(user.id)
        request.state.tenant_id = str(user.tenant_id)
        return user
    except Exception:
        return None


# =====================================
# Get Current Active User
# =====================================

def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get current user and verify account is active.
    
    This is a stricter version of get_current_user that also
    checks if the user's account is active.
    
    Args:
        current_user: User from get_current_user dependency
        
    Returns:
        User model instance
        
    Raises:
        HTTPException: If account is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not active",
        )
    return current_user


# =====================================
# Tenant Validation
# =====================================

def validate_tenant_access(
    current_user: User = Depends(get_current_user),
    target_tenant_id: UUID = None,
) -> bool:
    """
    Validate that user has access to the target tenant.
    
    Super admins can access all tenants.
    Other users can only access their own tenant.
    
    Args:
        current_user: Current authenticated user
        target_tenant_id: Tenant ID to check access for
        
    Returns:
        True if access is allowed
        
    Raises:
        HTTPException: If access is denied
    """
    from app.models.role_enum import Role
    
    # Super admins can access all tenants
    if current_user.role == Role.SUPER_ADMIN:
        return True
    
    # Check if user belongs to target tenant
    if current_user.tenant_id != target_tenant_id:
        security_logger.log_tenant_isolation_violation(
            user_id=str(current_user.id),
            user_tenant=str(current_user.tenant_id),
            target_tenant=str(target_tenant_id),
            resource="unknown"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: resource belongs to different organization",
        )
    
    return True


# =====================================
# Request Context Dependency
# =====================================

def get_request_context(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Get request context with user and tenant information.
    
    Useful for logging and audit purposes.
    
    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        
    Returns:
        Dictionary with context information
    """
    return {
        "user_id": str(current_user.id),
        "tenant_id": str(current_user.tenant_id),
        "email": current_user.email,
        "role": current_user.role.value if current_user.role else None,
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "unknown"),
    }
