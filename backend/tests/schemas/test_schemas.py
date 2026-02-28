"""
Schema Validation Unit Tests
=============================

Tests for Pydantic schema validation including:
- LoginRequest
- TokenResponse
- RefreshTokenRequest
- RegisterRequest
- UserCreate
- UserUpdate
- UserResponse
- OrganizationCreate
"""

import pytest
from pydantic import ValidationError as PydanticValidationError
from uuid import uuid4

from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    LogoutResponse,
    RegisterRequest,
    TokenPayload,
    ErrorResponse,
)
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
    CurrentUserResponse,
    PasswordChangeRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
)
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    TenantContext,
)
from app.models.role_enum import Role


pytestmark = pytest.mark.schema


class TestLoginRequest:
    """Tests for LoginRequest schema."""
    
    def test_valid_login_request(self):
        """Test valid login request."""
        # Arrange & Act
        login = LoginRequest(
            email="user@example.com",
            password="SecurePassword123!",
        )
        
        # Assert
        assert login.email == "user@example.com"
        assert login.password == "SecurePassword123!"
    
    def test_invalid_email_raises_error(self):
        """Test that invalid email raises validation error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            LoginRequest(
                email="not-an-email",
                password="password123",
            )
    
    def test_empty_password_raises_error(self):
        """Test that empty password raises validation error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            LoginRequest(
                email="user@example.com",
                password="",
            )
    
    def test_missing_email_raises_error(self):
        """Test that missing email raises validation error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            LoginRequest(password="password123")
    
    def test_missing_password_raises_error(self):
        """Test that missing password raises validation error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            LoginRequest(email="user@example.com")


class TestTokenResponse:
    """Tests for TokenResponse schema."""
    
    def test_valid_token_response(self):
        """Test valid token response."""
        # Arrange & Act
        response = TokenResponse(
            access_token="access_token_here",
            refresh_token="refresh_token_here",
            token_type="bearer",
            expires_in=900,
        )
        
        # Assert
        assert response.access_token == "access_token_here"
        assert response.refresh_token == "refresh_token_here"
        assert response.token_type == "bearer"
        assert response.expires_in == 900
    
    def test_token_type_defaults_to_bearer(self):
        """Test that token_type defaults to bearer."""
        # Arrange & Act
        response = TokenResponse(
            access_token="access_token",
            refresh_token="refresh_token",
        )
        
        # Assert
        assert response.token_type == "bearer"
    
    def test_missing_access_token_raises_error(self):
        """Test that missing access_token raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            TokenResponse(refresh_token="refresh_token")


class TestRefreshTokenRequest:
    """Tests for RefreshTokenRequest schema."""
    
    def test_valid_refresh_token_request(self):
        """Test valid refresh token request."""
        # Arrange & Act
        request = RefreshTokenRequest(refresh_token="valid_refresh_token")
        
        # Assert
        assert request.refresh_token == "valid_refresh_token"
    
    def test_missing_token_raises_error(self):
        """Test that missing token raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            RefreshTokenRequest()


class TestLogoutResponse:
    """Tests for LogoutResponse schema."""
    
    def test_default_message(self):
        """Test default logout message."""
        # Arrange & Act
        response = LogoutResponse()
        
        # Assert
        assert response.message == "Successfully logged out"
    
    def test_custom_message(self):
        """Test custom logout message."""
        # Arrange & Act
        response = LogoutResponse(message="Custom message")
        
        # Assert
        assert response.message == "Custom message"


class TestRegisterRequest:
    """Tests for RegisterRequest schema."""
    
    def test_valid_register_request(self):
        """Test valid registration request."""
        # Arrange & Act
        request = RegisterRequest(
            email="newuser@example.com",
            password="SecureP@ss123",
            organization_name="Test Org",
        )
        
        # Assert
        assert request.email == "newuser@example.com"
        assert request.password == "SecureP@ss123"
        assert request.organization_name == "Test Org"
    
    def test_weak_password_raises_error(self):
        """Test that weak password raises validation error."""
        # Act & Assert - Too short
        with pytest.raises(PydanticValidationError):
            RegisterRequest(
                email="user@example.com",
                password="short",
                organization_name="Test Org",
            )
    
    def test_password_without_uppercase_raises_error(self):
        """Test that password without uppercase raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            RegisterRequest(
                email="user@example.com",
                password="lowercase123!",
                organization_name="Test Org",
            )
    
    def test_password_without_lowercase_raises_error(self):
        """Test that password without lowercase raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            RegisterRequest(
                email="user@example.com",
                password="UPPERCASE123!",
                organization_name="Test Org",
            )
    
    def test_password_without_digit_raises_error(self):
        """Test that password without digit raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            RegisterRequest(
                email="user@example.com",
                password="NoDigitsHere!",
                organization_name="Test Org",
            )
    
    def test_password_without_special_char_raises_error(self):
        """Test that password without special char raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            RegisterRequest(
                email="user@example.com",
                password="NoSpecialChar123",
                organization_name="Test Org",
            )
    
    def test_short_organization_name_raises_error(self):
        """Test that short organization name raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            RegisterRequest(
                email="user@example.com",
                password="SecureP@ss123",
                organization_name="A",  # Too short
            )
    
    def test_invalid_email_raises_error(self):
        """Test that invalid email raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            RegisterRequest(
                email="not-an-email",
                password="SecureP@ss123",
                organization_name="Test Org",
            )


class TestUserCreate:
    """Tests for UserCreate schema."""
    
    def test_valid_user_create(self):
        """Test valid user create request."""
        # Arrange & Act
        user = UserCreate(
            email="newuser@example.com",
            password="SecurePassword123!",
            role=Role.READ_ONLY,
            tenant_id=uuid4(),
        )
        
        # Assert
        assert user.email == "newuser@example.com"
        assert user.role == Role.READ_ONLY
    
    def test_default_role_is_read_only(self):
        """Test that default role is READ_ONLY."""
        # Arrange & Act
        user = UserCreate(
            email="user@example.com",
            password="password123",
            tenant_id=uuid4(),
        )
        
        # Assert
        assert user.role == Role.READ_ONLY
    
    def test_short_password_raises_error(self):
        """Test that short password raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            UserCreate(
                email="user@example.com",
                password="short",
                tenant_id=uuid4(),
            )


class TestUserUpdate:
    """Tests for UserUpdate schema."""
    
    def test_partial_update_email_only(self):
        """Test partial update with email only."""
        # Arrange & Act
        update = UserUpdate(email="newemail@example.com")
        
        # Assert
        assert update.email == "newemail@example.com"
        assert update.role is None
        assert update.is_active is None
    
    def test_partial_update_role_only(self):
        """Test partial update with role only."""
        # Arrange & Act
        update = UserUpdate(role=Role.SECURITY_ANALYST)
        
        # Assert
        assert update.email is None
        assert update.role == Role.SECURITY_ANALYST
        assert update.is_active is None
    
    def test_partial_update_is_active_only(self):
        """Test partial update with is_active only."""
        # Arrange & Act
        update = UserUpdate(is_active=False)
        
        # Assert
        assert update.email is None
        assert update.role is None
        assert update.is_active is False
    
    def test_empty_update_is_valid(self):
        """Test that empty update is valid."""
        # Arrange & Act
        update = UserUpdate()
        
        # Assert
        assert update.email is None
        assert update.role is None
        assert update.is_active is None


class TestUserResponse:
    """Tests for UserResponse schema."""
    
    def test_valid_user_response(self):
        """Test valid user response."""
        # Arrange
        user_id = uuid4()
        tenant_id = uuid4()
        
        # Act
        from datetime import datetime, timezone, UTC
        response = UserResponse(
            id=user_id,
            email="user@example.com",
            role=Role.SECURITY_ANALYST,
            tenant_id=tenant_id,
            is_active=True,
            is_locked=False,
            created_at=datetime.now(timezone.utc),
        )
        
        # Assert
        assert response.id == user_id
        assert response.email == "user@example.com"
        assert response.role == Role.SECURITY_ANALYST


class TestPasswordChangeRequest:
    """Tests for PasswordChangeRequest schema."""
    
    def test_valid_password_change(self):
        """Test valid password change request."""
        # Arrange & Act
        request = PasswordChangeRequest(
            current_password="OldPassword123!",
            new_password="NewPassword456!",
        )
        
        # Assert
        assert request.current_password == "OldPassword123!"
        assert request.new_password == "NewPassword456!"
    
    def test_short_new_password_raises_error(self):
        """Test that short new password raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            PasswordChangeRequest(
                current_password="OldPassword123!",
                new_password="short",
            )


class TestPasswordResetRequest:
    """Tests for PasswordResetRequest schema."""
    
    def test_valid_password_reset_request(self):
        """Test valid password reset request."""
        # Arrange & Act
        request = PasswordResetRequest(email="user@example.com")
        
        # Assert
        assert request.email == "user@example.com"
    
    def test_invalid_email_raises_error(self):
        """Test that invalid email raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            PasswordResetRequest(email="not-an-email")


class TestPasswordResetConfirm:
    """Tests for PasswordResetConfirm schema."""
    
    def test_valid_password_reset_confirm(self):
        """Test valid password reset confirmation."""
        # Arrange & Act
        request = PasswordResetConfirm(
            token="reset_token_here",
            new_password="NewSecurePassword123!",
        )
        
        # Assert
        assert request.token == "reset_token_here"
        assert request.new_password == "NewSecurePassword123!"
    
    def test_short_password_raises_error(self):
        """Test that short password raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            PasswordResetConfirm(
                token="reset_token",
                new_password="short",
            )


class TestOrganizationCreate:
    """Tests for OrganizationCreate schema."""
    
    def test_valid_organization_create(self):
        """Test valid organization create request."""
        # Arrange & Act
        org = OrganizationCreate(name="New Organization")
        
        # Assert
        assert org.name == "New Organization"
    
    def test_empty_name_raises_error(self):
        """Test that empty name raises error."""
        # Act & Assert
        with pytest.raises(PydanticValidationError):
            OrganizationCreate(name="")


class TestOrganizationUpdate:
    """Tests for OrganizationUpdate schema."""
    
    def test_partial_update_name_only(self):
        """Test partial update with name only."""
        # Arrange & Act
        update = OrganizationUpdate(name="Updated Name")
        
        # Assert
        assert update.name == "Updated Name"
    
    def test_empty_update_is_valid(self):
        """Test that empty update is valid."""
        # Arrange & Act
        update = OrganizationUpdate()
        
        # Assert
        assert update.name is None


class TestOrganizationResponse:
    """Tests for OrganizationResponse schema."""
    
    def test_valid_organization_response(self):
        """Test valid organization response."""
        # Arrange
        org_id = uuid4()
        
        # Act
        from datetime import datetime, timezone, UTC
        response = OrganizationResponse(
            id=org_id,
            name="Test Organization",
            created_at=datetime.now(timezone.utc),
        )
        
        # Assert
        assert response.id == org_id
        assert response.name == "Test Organization"


class TestTenantContext:
    """Tests for TenantContext schema."""
    
    def test_valid_tenant_context(self):
        """Test valid tenant context."""
        # Arrange
        tenant_id = uuid4()
        
        # Act
        context = TenantContext(
            tenant_id=tenant_id,
            organization_name="Test Organization",
        )
        
        # Assert
        assert context.tenant_id == tenant_id
        assert context.organization_name == "Test Organization"


class TestErrorResponse:
    """Tests for ErrorResponse schema."""
    
    def test_valid_error_response(self):
        """Test valid error response."""
        # Arrange & Act
        response = ErrorResponse(
            message="An error occurred",
            details={"field": "email"},
        )
        
        # Assert
        assert response.message == "An error occurred"
        assert response.details == {"field": "email"}
    
    def test_error_response_without_details(self):
        """Test error response without details."""
        # Arrange & Act
        response = ErrorResponse(message="An error occurred")
        
        # Assert
        assert response.message == "An error occurred"
        assert response.details is None


class TestTokenPayload:
    """Tests for TokenPayload schema."""
    
    def test_valid_token_payload(self):
        """Test valid token payload."""
        # Arrange & Act
        payload = TokenPayload(
            sub=str(uuid4()),
            tenant_id=str(uuid4()),
            token_version=1,
            type="access",
            exp=1234567890,
        )
        
        # Assert
        assert payload.type == "access"
        assert payload.token_version == 1


class TestSchemaEdgeCases:
    """Tests for schema edge cases."""
    
    def test_email_normalization(self):
        """Test that email is validated properly."""
        # Arrange & Act
        login = LoginRequest(
            email="User@Example.COM",
            password="password123",
        )
        
        # Assert - Email validation should work
        assert "@" in login.email
    
    def test_long_password_accepted(self):
        """Test that long passwords are accepted."""
        # Arrange
        long_password = "A" * 100 + "1!a"
        
        # Act
        login = LoginRequest(
            email="user@example.com",
            password=long_password,
        )
        
        # Assert
        assert len(login.password) == 103
    
    def test_special_characters_in_organization_name(self):
        """Test special characters in organization name."""
        # Arrange & Act
        org = OrganizationCreate(name="Test-Org & Co. (Ltd.)")
        
        # Assert
        assert org.name == "Test-Org & Co. (Ltd.)"
    
    def test_unicode_in_fields(self):
        """Test unicode characters in fields."""
        # Arrange & Act
        org = OrganizationCreate(name="测试组织")
        
        # Assert
        assert org.name == "测试组织"
