"""
Authentication Service Module
=============================

Consolidated authentication service handling:
- Password hashing using Argon2
- JWT Access & Refresh token creation with type discrimination
- Token decoding and validation
- Token version tracking for forced logout
- Account lockout management

Security Features:
- Argon2id password hashing (memory-hard, resistant to GPU attacks)
- Token type discrimination (access vs refresh)
- Issuer and audience validation
- Token version for revocation support
"""

from datetime import datetime, timedelta, timezone, UTC
from typing import Optional, Tuple
from uuid import UUID

from sqlalchemy.orm import Session
from jose import jwt, JWTError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, Argon2Error

from app.models.user import User
from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    TokenExpiredError,
    TokenInvalidError,
    TokenVersionMismatchError,
    AccountLockedError,
    AccountDisabledError,
    InvalidCredentialsError,
)
from app.core.logging import get_logger

# Initialize logger
logger = get_logger(__name__)


# ==========================
# Password Hasher Configuration
# ==========================

# Argon2id with recommended parameters for password hashing
# - time_cost: Number of iterations
# - memory_cost: Memory in KiB
# - parallelism: Number of parallel threads
# - hash_len: Length of the hash in bytes
# - salt_len: Length of the salt in bytes
ph = PasswordHasher(
    time_cost=3,        # Number of passes
    memory_cost=65536,  # 64 MB memory
    parallelism=4,      # 4 parallel threads
    hash_len=32,        # 32-byte hash
    salt_len=16,        # 16-byte salt
)


# ==========================
# Token Types
# ==========================

class TokenType:
    """Token type constants for discrimination."""
    ACCESS = "access"
    REFRESH = "refresh"


# ==========================
# Auth Service Class
# ==========================

class AuthService:
    """
    Authentication service handling all auth-related operations.
    
    Usage:
        auth_service = AuthService(db)
        tokens = auth_service.authenticate_user(email, password)
    """
    
    def __init__(self, db: Session):
        """
        Initialize auth service with database session.
        
        Args:
            db: SQLAlchemy session
        """
        self.db = db
    
    # --------------------------
    # Password Utilities
    # --------------------------
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using Argon2id.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
            
        Note:
            Argon2id is the recommended choice for password hashing:
            - Resistant to GPU-based attacks
            - Memory-hard algorithm
            - Side-channel resistant
        """
        return ph.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: Password to verify
            hashed_password: Stored hash from database
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False
        except Argon2Error as e:
            logger.warning(
                "Password verification error",
                extra={"error": str(e)}
            )
            return False
    
    # --------------------------
    # Token Creation
    # --------------------------
    
    @staticmethod
    def create_access_token(
        user_id: UUID,
        tenant_id: UUID,
        token_version: int,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """
        Create a JWT access token.
        
        Args:
            user_id: User's UUID
            tenant_id: Organization's UUID
            token_version: Current token version for revocation
            expires_delta: Custom expiration time
            
        Returns:
            Encoded JWT access token
        """
        if expires_delta is None:
            expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        now = datetime.now(UTC)
        expire = now + expires_delta
        
        payload = {
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "token_version": token_version,
            "type": TokenType.ACCESS,
            "exp": expire,
            "iat": now,
            "iss": settings.ISSUER,
            "aud": settings.AUDIENCE,
        }
        
        return jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
    
    @staticmethod
    def create_refresh_token(
        user_id: UUID,
        tenant_id: UUID,
        token_version: int,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """
        Create a JWT refresh token.
        
        Args:
            user_id: User's UUID
            tenant_id: Organization's UUID
            token_version: Current token version for revocation
            expires_delta: Custom expiration time
            
        Returns:
            Encoded JWT refresh token
        """
        if expires_delta is None:
            expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        
        now = datetime.now(UTC)
        expire = now + expires_delta
        
        payload = {
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "token_version": token_version,
            "type": TokenType.REFRESH,
            "exp": expire,
            "iat": now,
            "iss": settings.ISSUER,
            "aud": settings.AUDIENCE,
        }
        
        return jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
    
    # --------------------------
    # Token Decoding & Validation
    # --------------------------
    
    @staticmethod
    def decode_token(token: str, expected_type: Optional[str] = None) -> dict:
        """
        Decode and validate a JWT token.
        
        Args:
            token: JWT token string
            expected_type: Expected token type (access/refresh)
            
        Returns:
            Decoded token payload
            
        Raises:
            TokenExpiredError: If token has expired
            TokenInvalidError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                issuer=settings.ISSUER,
                audience=settings.AUDIENCE,
            )
            
            # Validate token type if specified
            if expected_type and payload.get("type") != expected_type:
                raise TokenInvalidError(
                    reason=f"Expected {expected_type} token, got {payload.get('type')}"
                )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError(
                token_type=expected_type or "unknown"
            )
        except JWTError as e:
            logger.warning(
                "Token decode error",
                extra={"error": str(e)}
            )
            raise TokenInvalidError(reason=str(e))
    
    # --------------------------
    # Token Generator Wrapper
    # --------------------------
    
    def get_tokens_for_user(self, user: User) -> dict:
        """
        Generate access and refresh tokens for a user.
        
        Args:
            user: User model instance
            
        Returns:
            Dictionary with access_token, refresh_token, token_type, and expires_in
        """
        access_token = self.create_access_token(
            user_id=user.id,
            tenant_id=user.tenant_id,
            token_version=user.token_version,
        )
        
        refresh_token = self.create_refresh_token(
            user_id=user.id,
            tenant_id=user.tenant_id,
            token_version=user.token_version,
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }
    
    # --------------------------
    # Authentication Methods
    # --------------------------
    
    def authenticate_user(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> Tuple[User, dict]:
        """
        Authenticate a user with email and password.
        
        Args:
            email: User's email
            password: User's password
            ip_address: Client IP for logging
            
        Returns:
            Tuple of (User, tokens dict)
            
        Raises:
            InvalidCredentialsError: If credentials are invalid
            AccountLockedError: If account is locked
            AccountDisabledError: If account is disabled
        """
        from app.core.logging import security_logger
        
        # Find user by email
        user = self.db.query(User).filter(User.email == email.lower()).first()
        
        if not user:
            security_logger.log_login_failure(
                email=email,
                ip_address=ip_address or "unknown",
                reason="user_not_found"
            )
            raise InvalidCredentialsError()
        
        # Check account status
        if user.is_locked:
            security_logger.log_login_failure(
                email=email,
                ip_address=ip_address or "unknown",
                reason="account_locked"
            )
            raise AccountLockedError()
        
        if not user.is_active:
            security_logger.log_login_failure(
                email=email,
                ip_address=ip_address or "unknown",
                reason="account_disabled"
            )
            raise AccountDisabledError()
        
        # Verify password
        if not self.verify_password(password, user.hashed_password):
            # Increment failed attempts
            user.failed_attempts += 1
            
            # Lock account if max attempts reached
            if user.failed_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                user.is_locked = True
                self.db.commit()
                
                security_logger.log_account_locked(
                    user_id=str(user.id),
                    tenant_id=str(user.tenant_id),
                    ip_address=ip_address or "unknown"
                )
            else:
                self.db.commit()
            
            security_logger.log_login_failure(
                email=email,
                ip_address=ip_address or "unknown",
                reason="invalid_password"
            )
            raise InvalidCredentialsError()
        
        # Reset failed attempts on successful login
        user.failed_attempts = 0
        self.db.commit()
        
        # Generate tokens
        tokens = self.get_tokens_for_user(user)
        
        # Log successful login
        security_logger.log_login_success(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            ip_address=ip_address or "unknown",
            user_agent="unknown"  # Should be passed from request
        )
        
        return user, tokens
    
    def refresh_tokens(self, refresh_token: str) -> dict:
        """
        Refresh access token using a valid refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New tokens dict
            
        Raises:
            TokenInvalidError: If token is invalid
            TokenVersionMismatchError: If token version doesn't match
            AccountLockedError: If account is locked
            AccountDisabledError: If account is disabled
        """
        from app.core.logging import security_logger
        
        # Decode refresh token
        payload = self.decode_token(refresh_token, expected_type=TokenType.REFRESH)
        
        user_id = payload.get("sub")
        token_version = payload.get("token_version")
        tenant_id = payload.get("tenant_id")
        
        if not user_id or token_version is None:
            raise TokenInvalidError(reason="Invalid token payload")
        
        # Convert user_id string to UUID
        try:
            user_uuid = UUID(user_id)
        except ValueError:
            raise TokenInvalidError(reason="Invalid user ID format")
        
        # Find user
        user = self.db.query(User).filter(User.id == user_uuid).first()
        
        if not user:
            raise TokenInvalidError(reason="User not found")
        
        # Validate token version
        if user.token_version != token_version:
            security_logger.log_token_invalid(
                reason="token_version_mismatch",
                ip_address="unknown"
            )
            raise TokenVersionMismatchError()
        
        # Check account status
        if user.is_locked:
            raise AccountLockedError()
        
        if not user.is_active:
            raise AccountDisabledError()
        
        # Generate new tokens
        tokens = self.get_tokens_for_user(user)
        
        # Log token refresh
        security_logger.log_token_refresh(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id)
        )
        
        return tokens
    
    def logout(self, user: User) -> None:
        """
        Logout user by invalidating all tokens.
        
        Args:
            user: User model instance
        """
        from app.core.logging import security_logger
        
        # Increment token version to invalidate all existing tokens
        user.token_version += 1
        self.db.commit()
        
        security_logger.log_logout(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id)
        )
    
    def validate_access_token(self, token: str) -> User:
        """
        Validate an access token and return the user.
        
        Args:
            token: Access token
            
        Returns:
            User model instance
            
        Raises:
            TokenInvalidError: If token is invalid
            TokenVersionMismatchError: If token version doesn't match
            AccountLockedError: If account is locked
            AccountDisabledError: If account is disabled
        """
        # Decode access token
        payload = self.decode_token(token, expected_type=TokenType.ACCESS)
        
        user_id = payload.get("sub")
        token_version = payload.get("token_version")
        
        if not user_id or token_version is None:
            raise TokenInvalidError(reason="Invalid token payload")
        
        # Convert user_id string to UUID
        try:
            user_uuid = UUID(user_id)
        except ValueError:
            raise TokenInvalidError(reason="Invalid user ID format")
        
        # Find user
        user = self.db.query(User).filter(User.id == user_uuid).first()
        
        if not user:
            raise TokenInvalidError(reason="User not found")
        
        # Validate token version
        if user.token_version != token_version:
            raise TokenVersionMismatchError()
        
        # Check account status
        if user.is_locked:
            raise AccountLockedError()
        
        if not user.is_active:
            raise AccountDisabledError()
        
        return user
