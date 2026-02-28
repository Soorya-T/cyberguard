"""
Authentication Service Unit Tests
==================================

Tests for the AuthService class covering:
- Password hashing and verification
- Access token creation and validation
- Refresh token creation and validation
- User authentication flow
- Token refresh flow
- Account lockout handling
- Token version validation
"""

import pytest
from datetime import timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from app.services.auth_service import AuthService, TokenType
from app.models.user import User
from app.models.organization import Organization
from app.models.role_enum import Role
from app.core.exceptions import (
    InvalidCredentialsError,
    AccountLockedError,
    AccountDisabledError,
    TokenInvalidError,
    TokenExpiredError,
    TokenVersionMismatchError,
)


pytestmark = pytest.mark.unit


class TestPasswordHashing:
    """Tests for password hashing functionality."""
    
    def test_hash_password_returns_string(self):
        """Test that hash_password returns a string."""
        # Arrange
        auth_service = AuthService(None)
        password = "TestPassword123!"
        
        # Act
        hashed = auth_service.hash_password(password)
        
        # Assert
        assert isinstance(hashed, str)
        assert len(hashed) > 0
    
    def test_hash_password_creates_different_hashes(self):
        """Test that same password creates different hashes (salt)."""
        # Arrange
        auth_service = AuthService(None)
        password = "TestPassword123!"
        
        # Act
        hash1 = auth_service.hash_password(password)
        hash2 = auth_service.hash_password(password)
        
        # Assert
        assert hash1 != hash2
    
    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        # Arrange
        auth_service = AuthService(None)
        password = "TestPassword123!"
        hashed = auth_service.hash_password(password)
        
        # Act
        result = auth_service.verify_password(password, hashed)
        
        # Assert
        assert result is True
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        # Arrange
        auth_service = AuthService(None)
        password = "TestPassword123!"
        wrong_password = "WrongPassword123!"
        hashed = auth_service.hash_password(password)
        
        # Act
        result = auth_service.verify_password(wrong_password, hashed)
        
        # Assert
        assert result is False
    
    def test_verify_password_empty(self):
        """Test password verification with empty password."""
        # Arrange
        auth_service = AuthService(None)
        password = "TestPassword123!"
        hashed = auth_service.hash_password(password)
        
        # Act
        result = auth_service.verify_password("", hashed)
        
        # Assert
        assert result is False


class TestAccessTokenCreation:
    """Tests for access token creation."""
    
    def test_create_access_token_returns_string(self):
        """Test that create_access_token returns a string."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        
        # Act
        token = AuthService.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        
        # Assert
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_create_access_token_contains_correct_payload(self):
        """Test that access token contains correct payload."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        
        # Act
        token = AuthService.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        payload = AuthService.decode_token(token, expected_type=TokenType.ACCESS)
        
        # Assert
        assert payload["sub"] == str(user_id)
        assert payload["tenant_id"] == str(tenant_id)
        assert payload["token_version"] == token_version
        assert payload["type"] == TokenType.ACCESS
    
    def test_create_access_token_with_custom_expiry(self):
        """Test access token creation with custom expiry."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        custom_expiry = timedelta(minutes=5)
        
        # Act
        token = AuthService.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
            expires_delta=custom_expiry,
        )
        payload = AuthService.decode_token(token)
        
        # Assert
        assert "exp" in payload
        assert "iat" in payload


class TestRefreshTokenCreation:
    """Tests for refresh token creation."""
    
    def test_create_refresh_token_returns_string(self):
        """Test that create_refresh_token returns a string."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        
        # Act
        token = AuthService.create_refresh_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        
        # Assert
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_create_refresh_token_contains_correct_type(self):
        """Test that refresh token has correct type."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        
        # Act
        token = AuthService.create_refresh_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        payload = AuthService.decode_token(token, expected_type=TokenType.REFRESH)
        
        # Assert
        assert payload["type"] == TokenType.REFRESH
    
    def test_refresh_and_access_tokens_are_different(self):
        """Test that refresh and access tokens are different."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        
        # Act
        access_token = AuthService.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        refresh_token = AuthService.create_refresh_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        
        # Assert
        assert access_token != refresh_token


class TestTokenDecoding:
    """Tests for token decoding and validation."""
    
    def test_decode_valid_token(self):
        """Test decoding a valid token."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        token = AuthService.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        
        # Act
        payload = AuthService.decode_token(token)
        
        # Assert
        assert payload["sub"] == str(user_id)
        assert payload["tenant_id"] == str(tenant_id)
    
    def test_decode_token_with_expected_type_success(self):
        """Test decoding token with correct expected type."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        token = AuthService.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        
        # Act
        payload = AuthService.decode_token(token, expected_type=TokenType.ACCESS)
        
        # Assert
        assert payload["type"] == TokenType.ACCESS
    
    def test_decode_token_with_wrong_expected_type_raises_error(self):
        """Test decoding token with wrong expected type raises error."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        token_version = 1
        token = AuthService.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            token_version=token_version,
        )
        
        # Act & Assert
        with pytest.raises(TokenInvalidError):
            AuthService.decode_token(token, expected_type=TokenType.REFRESH)
    
    def test_decode_invalid_token_raises_error(self):
        """Test decoding invalid token raises error."""
        # Arrange
        invalid_token = "invalid.token.here"
        
        # Act & Assert
        with pytest.raises(TokenInvalidError):
            AuthService.decode_token(invalid_token)
    
    def test_decode_malformed_token_raises_error(self):
        """Test decoding malformed token raises error."""
        # Arrange
        malformed_token = "not-a-jwt-token"
        
        # Act & Assert
        with pytest.raises(TokenInvalidError):
            AuthService.decode_token(malformed_token)


class TestGetTokensForUser:
    """Tests for get_tokens_for_user method."""
    
    def test_get_tokens_for_user_returns_dict(self, db_session: Session, sample_user: User):
        """Test that get_tokens_for_user returns a dictionary."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act
        tokens = auth_service.get_tokens_for_user(sample_user)
        
        # Assert
        assert isinstance(tokens, dict)
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "token_type" in tokens
        assert tokens["token_type"] == "bearer"
    
    def test_get_tokens_for_user_contains_valid_tokens(self, db_session: Session, sample_user: User):
        """Test that tokens returned are valid and decodable."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act
        tokens = auth_service.get_tokens_for_user(sample_user)
        access_payload = AuthService.decode_token(tokens["access_token"])
        refresh_payload = AuthService.decode_token(tokens["refresh_token"])
        
        # Assert
        assert access_payload["sub"] == str(sample_user.id)
        assert refresh_payload["sub"] == str(sample_user.id)


class TestAuthenticateUser:
    """Tests for user authentication."""
    
    def test_authenticate_user_success(
        self,
        db_session: Session,
        sample_user: User,
    ):
        """Test successful user authentication."""
        # Arrange
        auth_service = AuthService(db_session)
        password = "TestPassword123!"  # This matches the fixture
        
        # Act
        user, tokens = auth_service.authenticate_user(
            email=sample_user.email,
            password=password,
        )
        
        # Assert
        assert user.id == sample_user.id
        assert "access_token" in tokens
        assert "refresh_token" in tokens
    
    def test_authenticate_user_invalid_email(self, db_session: Session):
        """Test authentication with non-existent email."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act & Assert
        with pytest.raises(InvalidCredentialsError):
            auth_service.authenticate_user(
                email="nonexistent@example.com",
                password="SomePassword123!",
            )
    
    def test_authenticate_user_invalid_password(
        self,
        db_session: Session,
        sample_user: User,
    ):
        """Test authentication with wrong password."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act & Assert
        with pytest.raises(InvalidCredentialsError):
            auth_service.authenticate_user(
                email=sample_user.email,
                password="WrongPassword123!",
            )
    
    def test_authenticate_user_locked_account(
        self,
        db_session: Session,
        sample_locked_user: User,
    ):
        """Test authentication with locked account."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act & Assert
        with pytest.raises(AccountLockedError):
            auth_service.authenticate_user(
                email=sample_locked_user.email,
                password="LockedUserPassword123!",
            )
    
    def test_authenticate_user_disabled_account(
        self,
        db_session: Session,
        sample_inactive_user: User,
    ):
        """Test authentication with disabled account."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act & Assert
        with pytest.raises(AccountDisabledError):
            auth_service.authenticate_user(
                email=sample_inactive_user.email,
                password="InactiveUserPassword123!",
            )
    
    def test_authenticate_user_increments_failed_attempts(
        self,
        db_session: Session,
        sample_user: User,
    ):
        """Test that failed login increments failed_attempts."""
        # Arrange
        auth_service = AuthService(db_session)
        initial_attempts = sample_user.failed_attempts
        
        # Act
        try:
            auth_service.authenticate_user(
                email=sample_user.email,
                password="WrongPassword123!",
            )
        except InvalidCredentialsError:
            pass
        
        # Refresh user from DB
        db_session.refresh(sample_user)
        
        # Assert
        assert sample_user.failed_attempts == initial_attempts + 1
    
    def test_authenticate_user_resets_failed_attempts_on_success(
        self,
        db_session: Session,
        sample_user: User,
    ):
        """Test that successful login resets failed_attempts."""
        # Arrange
        auth_service = AuthService(db_session)
        # First, fail a few times
        for _ in range(2):
            try:
                auth_service.authenticate_user(
                    email=sample_user.email,
                    password="WrongPassword123!",
                )
            except InvalidCredentialsError:
                pass
        
        db_session.refresh(sample_user)
        assert sample_user.failed_attempts == 2
        
        # Act - Now login successfully
        auth_service.authenticate_user(
            email=sample_user.email,
            password="TestPassword123!",
        )
        
        # Refresh and assert
        db_session.refresh(sample_user)
        assert sample_user.failed_attempts == 0


class TestRefreshTokens:
    """Tests for token refresh functionality."""
    
    def test_refresh_tokens_success(
        self,
        db_session: Session,
        sample_user: User,
        user_refresh_token: str,
    ):
        """Test successful token refresh."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act
        tokens = auth_service.refresh_tokens(user_refresh_token)
        
        # Assert
        assert "access_token" in tokens
        assert "refresh_token" in tokens
    
    def test_refresh_tokens_invalid_token(self, db_session: Session):
        """Test refresh with invalid token."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act & Assert
        with pytest.raises(TokenInvalidError):
            auth_service.refresh_tokens("invalid.refresh.token")
    
    def test_refresh_tokens_with_access_token_fails(
        self,
        db_session: Session,
        user_access_token: str,
    ):
        """Test that using access token for refresh fails."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act & Assert
        with pytest.raises(TokenInvalidError):
            auth_service.refresh_tokens(user_access_token)
    
    def test_refresh_tokens_locked_account(
        self,
        db_session: Session,
        sample_locked_user: User,
    ):
        """Test refresh with locked account."""
        # Arrange
        auth_service = AuthService(db_session)
        refresh_token = AuthService.create_refresh_token(
            user_id=sample_locked_user.id,
            tenant_id=sample_locked_user.tenant_id,
            token_version=sample_locked_user.token_version,
        )
        
        # Act & Assert
        with pytest.raises(AccountLockedError):
            auth_service.refresh_tokens(refresh_token)
    
    def test_refresh_tokens_disabled_account(
        self,
        db_session: Session,
        sample_inactive_user: User,
    ):
        """Test refresh with disabled account."""
        # Arrange
        auth_service = AuthService(db_session)
        refresh_token = AuthService.create_refresh_token(
            user_id=sample_inactive_user.id,
            tenant_id=sample_inactive_user.tenant_id,
            token_version=sample_inactive_user.token_version,
        )
        
        # Act & Assert
        with pytest.raises(AccountDisabledError):
            auth_service.refresh_tokens(refresh_token)


class TestTokenVersionValidation:
    """Tests for token version validation."""
    
    def test_token_version_mismatch_raises_error(
        self,
        db_session: Session,
        sample_user: User,
    ):
        """Test that token version mismatch raises error."""
        # Arrange
        auth_service = AuthService(db_session)
        # Create token with old version
        old_token = AuthService.create_refresh_token(
            user_id=sample_user.id,
            tenant_id=sample_user.tenant_id,
            token_version=0,  # Old version
        )
        # User's current version is 1
        
        # Act & Assert
        with pytest.raises(TokenVersionMismatchError):
            auth_service.refresh_tokens(old_token)
    
    def test_logout_increments_token_version(
        self,
        db_session: Session,
        sample_user: User,
    ):
        """Test that logout increments token version."""
        # Arrange
        auth_service = AuthService(db_session)
        initial_version = sample_user.token_version
        
        # Act
        auth_service.logout(sample_user)
        
        # Refresh and assert
        db_session.refresh(sample_user)
        assert sample_user.token_version == initial_version + 1


class TestLogout:
    """Tests for logout functionality."""
    
    def test_logout_increments_token_version(
        self,
        db_session: Session,
        sample_user: User,
    ):
        """Test that logout increments token version."""
        # Arrange
        auth_service = AuthService(db_session)
        initial_version = sample_user.token_version
        
        # Act
        auth_service.logout(sample_user)
        
        # Assert
        db_session.refresh(sample_user)
        assert sample_user.token_version == initial_version + 1
    
    def test_logout_invalidates_old_tokens(
        self,
        db_session: Session,
        sample_user: User,
    ):
        """Test that logout invalidates old tokens."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Create token before logout
        old_refresh_token = AuthService.create_refresh_token(
            user_id=sample_user.id,
            tenant_id=sample_user.tenant_id,
            token_version=sample_user.token_version,
        )
        
        # Act
        auth_service.logout(sample_user)
        
        # Assert - Old token should now fail
        with pytest.raises(TokenVersionMismatchError):
            auth_service.refresh_tokens(old_refresh_token)


class TestValidateAccessToken:
    """Tests for access token validation."""
    
    def test_validate_access_token_success(
        self,
        db_session: Session,
        sample_user: User,
        user_access_token: str,
    ):
        """Test successful access token validation."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act
        user = auth_service.validate_access_token(user_access_token)
        
        # Assert
        assert user.id == sample_user.id
    
    def test_validate_access_token_invalid(self, db_session: Session):
        """Test validation with invalid token."""
        # Arrange
        auth_service = AuthService(db_session)
        
        # Act & Assert
        with pytest.raises(TokenInvalidError):
            auth_service.validate_access_token("invalid.token.here")
    
    def test_validate_access_token_expired(self, db_session: Session):
        """Test validation with expired token."""
        # Arrange
        auth_service = AuthService(db_session)
        # Create an already expired token
        expired_token = AuthService.create_access_token(
            user_id=uuid4(),
            tenant_id=uuid4(),
            token_version=1,
            expires_delta=timedelta(seconds=-1),  # Already expired
        )
        
        # Act & Assert
        with pytest.raises((TokenExpiredError, TokenInvalidError)):
            auth_service.validate_access_token(expired_token)
    
    def test_validate_access_token_locked_user(
        self,
        db_session: Session,
        sample_locked_user: User,
    ):
        """Test validation with locked user."""
        # Arrange
        auth_service = AuthService(db_session)
        token = AuthService.create_access_token(
            user_id=sample_locked_user.id,
            tenant_id=sample_locked_user.tenant_id,
            token_version=sample_locked_user.token_version,
        )
        
        # Act & Assert
        with pytest.raises(AccountLockedError):
            auth_service.validate_access_token(token)
    
    def test_validate_access_token_disabled_user(
        self,
        db_session: Session,
        sample_inactive_user: User,
    ):
        """Test validation with disabled user."""
        # Arrange
        auth_service = AuthService(db_session)
        token = AuthService.create_access_token(
            user_id=sample_inactive_user.id,
            tenant_id=sample_inactive_user.tenant_id,
            token_version=sample_inactive_user.token_version,
        )
        
        # Act & Assert
        with pytest.raises(AccountDisabledError):
            auth_service.validate_access_token(token)
