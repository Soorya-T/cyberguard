"""
Authentication Routes Module
============================

Handles:
- User login with account lockout protection
- Token refresh
- Logout (token invalidation)
- User registration (if enabled)

Security Features:
- Multi-tenant aware
- Account lockout handling
- Token version validation
- Rate limiting
- Security logging
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.services.auth_service import AuthService
from app.core.dependencies.auth import get_current_user
from app.core.exceptions import (
    InvalidCredentialsError,
    AccountLockedError,
    AccountDisabledError,
    TokenInvalidError,
)
from app.core.logging import get_logger, security_logger
from app.schemas import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    LogoutResponse,
    ErrorResponse,
)

# Initialize logger
logger = get_logger(__name__)


# =====================================
# Router Setup
# =====================================

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={
        401: {"model": ErrorResponse, "description": "Authentication failed"},
        403: {"model": ErrorResponse, "description": "Access forbidden"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)


# =====================================
# Login Endpoint
# =====================================

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User Login",
    description="""
    Authenticate user with email and password.
    
    Returns JWT access and refresh tokens on success.
    
    Security features:
    - Account locks after 5 failed attempts
    - Rate limited per IP
    - All attempts are logged
    """,
    responses={
        200: {"description": "Successfully authenticated"},
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        403: {"model": ErrorResponse, "description": "Account locked or disabled"},
        429: {"model": ErrorResponse, "description": "Too many requests"},
    },
)
def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db),
) -> dict:
    """
    Authenticate user and return JWT tokens.
    
    Args:
        request: FastAPI request object
        login_data: Login credentials
        db: Database session
        
    Returns:
        Token response with access and refresh tokens
        
    Raises:
        HTTPException: On authentication failure
    """
    auth_service = AuthService(db)
    
    # Get client IP for logging
    client_ip = request.client.host if request.client else "unknown"
    
    try:
        user, tokens = auth_service.authenticate_user(
            email=login_data.email,
            password=login_data.password,
            ip_address=client_ip,
        )
        
        logger.info(
            "User logged in successfully",
            extra={
                "user_id": str(user.id),
                "tenant_id": str(user.tenant_id),
                "ip_address": client_ip,
            }
        )
        
        return tokens
        
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    except AccountLockedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked due to multiple failed login attempts. "
                   "Please contact your administrator or try again later.",
        )
    
    except AccountDisabledError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been disabled. Please contact your administrator.",
        )


# =====================================
# Refresh Token Endpoint
# =====================================

@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh Access Token",
    description="""
    Refresh access token using a valid refresh token.
    
    The refresh token must be valid and not expired.
    Returns new access and refresh tokens.
    """,
    responses={
        200: {"description": "Tokens refreshed successfully"},
        401: {"model": ErrorResponse, "description": "Invalid or expired token"},
        403: {"model": ErrorResponse, "description": "Account locked or disabled"},
    },
)
def refresh_token(
    request: Request,
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db),
) -> dict:
    """
    Refresh JWT tokens using a valid refresh token.
    
    Args:
        request: FastAPI request object
        refresh_data: Refresh token
        db: Database session
        
    Returns:
        New token response
        
    Raises:
        HTTPException: On invalid token or account issues
    """
    auth_service = AuthService(db)
    
    try:
        tokens = auth_service.refresh_tokens(refresh_data.refresh_token)
        return tokens
        
    except TokenInvalidError as e:
        logger.warning(
            "Token refresh failed",
            extra={
                "reason": str(e),
                "ip_address": request.client.host if request.client else "unknown",
            }
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    except AccountLockedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked",
        )
    
    except AccountDisabledError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been disabled",
        )


# =====================================
# Logout Endpoint
# =====================================

@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="User Logout",
    description="""
    Logout the current user by invalidating all tokens.
    
    This increments the user's token version, making all
    existing tokens invalid.
    """,
    responses={
        200: {"description": "Successfully logged out"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
    },
)
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Logout user by invalidating all tokens.
    
    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Logout confirmation
    """
    auth_service = AuthService(db)
    auth_service.logout(current_user)
    
    logger.info(
        "User logged out",
        extra={
            "user_id": str(current_user.id),
            "tenant_id": str(current_user.tenant_id),
            "ip_address": request.client.host if request.client else "unknown",
        }
    )
    
    return {"message": "Successfully logged out"}


# =====================================
# Verify Token Endpoint
# =====================================

@router.get(
    "/verify",
    summary="Verify Token",
    description="Verify that the current access token is valid.",
    responses={
        200: {"description": "Token is valid"},
        401: {"model": ErrorResponse, "description": "Invalid token"},
    },
)
def verify_token(
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Verify that the current access token is valid.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User info if token is valid
    """
    role_value = current_user.role.value if hasattr(current_user.role, 'value') else current_user.role
    return {
        "valid": True,
        "user_id": str(current_user.id),
        "email": current_user.email,
        "role": role_value,
        "tenant_id": str(current_user.tenant_id),
    }


# =====================================
# Get Current User Endpoint
# =====================================

@router.get(
    "/me",
    summary="Get Current User",
    description="Get the currently authenticated user's information.",
    responses={
        200: {"description": "Current user info"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
    },
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Get current user information.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User information
    """
    # Handle role being either a string or enum
    role_value = current_user.role.value if hasattr(current_user.role, 'value') else current_user.role
    
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "role": role_value,
        "tenant_id": str(current_user.tenant_id),
        "is_active": current_user.is_active,
        "is_locked": current_user.is_locked,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
    }
