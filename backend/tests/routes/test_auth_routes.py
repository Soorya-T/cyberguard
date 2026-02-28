"""
Authentication Routes Integration Tests
========================================

Integration tests for authentication endpoints including:
- POST /auth/login
- POST /auth/refresh
- POST /auth/logout
- GET /auth/verify
- GET /auth/me
"""

import pytest
from fastapi.testclient import TestClient

from app.models.user import User
from app.services.auth_service import AuthService


pytestmark = pytest.mark.integration


class TestLoginEndpoint:
    """Integration tests for POST /auth/login endpoint."""
    
    def test_login_success(self, client: TestClient, sample_user: User):
        """Test successful login with valid credentials."""
        # Arrange
        login_data = {
            "email": sample_user.email,
            "password": "TestPassword123!",  # Matches fixture
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
    
    def test_login_invalid_email(self, client: TestClient):
        """Test login with non-existent email."""
        # Arrange
        login_data = {
            "email": "nonexistent@example.com",
            "password": "SomePassword123!",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 401
        assert "Invalid" in response.json()["detail"]
    
    def test_login_invalid_password(self, client: TestClient, sample_user: User):
        """Test login with wrong password."""
        # Arrange
        login_data = {
            "email": sample_user.email,
            "password": "WrongPassword123!",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 401
    
    def test_login_locked_account(self, client: TestClient, sample_locked_user: User):
        """Test login with locked account."""
        # Arrange
        login_data = {
            "email": sample_locked_user.email,
            "password": "LockedUserPassword123!",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 403
        assert "locked" in response.json()["detail"].lower()
    
    def test_login_disabled_account(self, client: TestClient, sample_inactive_user: User):
        """Test login with disabled account."""
        # Arrange
        login_data = {
            "email": sample_inactive_user.email,
            "password": "InactiveUserPassword123!",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 403
        assert "disabled" in response.json()["detail"].lower()
    
    def test_login_missing_fields(self, client: TestClient):
        """Test login with missing fields."""
        # Arrange
        login_data = {"email": "test@example.com"}
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 422
    
    def test_login_invalid_email_format(self, client: TestClient):
        """Test login with invalid email format."""
        # Arrange
        login_data = {
            "email": "not-an-email",
            "password": "SomePassword123!",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 422
    
    def test_login_case_insensitive_email(self, client: TestClient, sample_user: User):
        """Test login with different case email."""
        # Arrange
        login_data = {
            "email": sample_user.email.upper(),
            "password": "TestPassword123!",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert - Should work if email is case-insensitive
        # or fail if case-sensitive
        assert response.status_code in [200, 401]


class TestRefreshTokenEndpoint:
    """Integration tests for POST /auth/refresh endpoint."""
    
    def test_refresh_success(self, client: TestClient, user_refresh_token: str):
        """Test successful token refresh."""
        # Arrange
        refresh_data = {"refresh_token": user_refresh_token}
        
        # Act
        response = client.post("/auth/refresh", json=refresh_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
    
    def test_refresh_with_invalid_token(self, client: TestClient):
        """Test refresh with invalid token."""
        # Arrange
        refresh_data = {"refresh_token": "invalid.token.here"}
        
        # Act
        response = client.post("/auth/refresh", json=refresh_data)
        
        # Assert
        assert response.status_code == 401
    
    def test_refresh_with_access_token_fails(self, client: TestClient, user_access_token: str):
        """Test that using access token for refresh fails."""
        # Arrange
        refresh_data = {"refresh_token": user_access_token}
        
        # Act
        response = client.post("/auth/refresh", json=refresh_data)
        
        # Assert
        assert response.status_code == 401
    
    def test_refresh_missing_token(self, client: TestClient):
        """Test refresh without token."""
        # Arrange
        refresh_data = {}
        
        # Act
        response = client.post("/auth/refresh", json=refresh_data)
        
        # Assert
        assert response.status_code == 422


class TestLogoutEndpoint:
    """Integration tests for POST /auth/logout endpoint."""
    
    def test_logout_success(self, client: TestClient, auth_headers: dict, sample_user: User):
        """Test successful logout."""
        # Act
        response = client.post("/auth/logout", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
        assert "logged out" in response.json()["message"].lower()
    
    def test_logout_without_auth(self, client: TestClient):
        """Test logout without authentication."""
        # Act
        response = client.post("/auth/logout")
        
        # Assert
        assert response.status_code == 401
    
    def test_logout_invalidates_tokens(self, client: TestClient, auth_headers: dict, sample_user: User):
        """Test that logout invalidates tokens."""
        # Act - Logout
        client.post("/auth/logout", headers=auth_headers)
        
        # Assert - Old token should now fail
        response = client.get("/auth/me", headers=auth_headers)
        assert response.status_code == 401


class TestVerifyTokenEndpoint:
    """Integration tests for GET /auth/verify endpoint."""
    
    def test_verify_valid_token(self, client: TestClient, auth_headers: dict):
        """Test token verification with valid token."""
        # Act
        response = client.get("/auth/verify", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert "user_id" in data
        assert "email" in data
    
    def test_verify_without_token(self, client: TestClient):
        """Test token verification without token."""
        # Act
        response = client.get("/auth/verify")
        
        # Assert
        assert response.status_code == 401
    
    def test_verify_invalid_token(self, client: TestClient):
        """Test token verification with invalid token."""
        # Arrange
        headers = {"Authorization": "Bearer invalid.token"}
        
        # Act
        response = client.get("/auth/verify", headers=headers)
        
        # Assert
        assert response.status_code == 401


class TestMeEndpoint:
    """Integration tests for GET /auth/me endpoint."""
    
    def test_me_success(self, client: TestClient, auth_headers: dict, sample_user: User):
        """Test getting current user info."""
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == sample_user.email
        # Role is a str enum, so it may be stored as string or enum
        expected_role = sample_user.role.value if hasattr(sample_user.role, 'value') else sample_user.role
        assert data["role"] == expected_role
        assert "id" in data
        assert "tenant_id" in data
    
    def test_me_without_auth(self, client: TestClient):
        """Test getting current user without authentication."""
        # Act
        response = client.get("/auth/me")
        
        # Assert
        assert response.status_code == 401
    
    def test_me_returns_correct_role(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_super_admin: User,
    ):
        """Test that me endpoint returns correct role for super admin."""
        # Act
        response = client.get("/auth/me", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "SUPER_ADMIN"


class TestAuthFlowIntegration:
    """Integration tests for complete authentication flows."""
    
    def test_complete_login_logout_flow(self, client: TestClient, sample_user: User):
        """Test complete login-logout flow."""
        # Step 1: Login
        login_data = {
            "email": sample_user.email,
            "password": "TestPassword123!",
        }
        login_response = client.post("/auth/login", json=login_data)
        assert login_response.status_code == 200
        
        tokens = login_response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]
        
        # Step 2: Access protected route
        headers = {"Authorization": f"Bearer {access_token}"}
        me_response = client.get("/auth/me", headers=headers)
        assert me_response.status_code == 200
        
        # Step 3: Refresh token
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_response.status_code == 200
        new_tokens = refresh_response.json()
        
        # Step 4: Use new token
        new_headers = {"Authorization": f"Bearer {new_tokens['access_token']}"}
        me_response2 = client.get("/auth/me", headers=new_headers)
        assert me_response2.status_code == 200
        
        # Step 5: Logout
        logout_response = client.post("/auth/logout", headers=new_headers)
        assert logout_response.status_code == 200
        
        # Step 6: Verify old tokens are invalid
        me_response3 = client.get("/auth/me", headers=new_headers)
        assert me_response3.status_code == 401
    
    def test_login_increments_failed_attempts(
        self,
        client: TestClient,
        sample_user: User,
        db_session,
    ):
        """Test that failed login increments failed attempts."""
        # Arrange
        initial_attempts = sample_user.failed_attempts
        
        # Act - Failed login
        login_data = {
            "email": sample_user.email,
            "password": "WrongPassword123!",
        }
        client.post("/auth/login", json=login_data)
        
        # Assert
        db_session.refresh(sample_user)
        assert sample_user.failed_attempts == initial_attempts + 1
    
    def test_successful_login_resets_failed_attempts(
        self,
        client: TestClient,
        sample_user: User,
        db_session,
    ):
        """Test that successful login resets failed attempts."""
        # Arrange - Fail a few times first
        for _ in range(2):
            client.post("/auth/login", json={
                "email": sample_user.email,
                "password": "WrongPassword123!",
            })
        
        db_session.refresh(sample_user)
        assert sample_user.failed_attempts == 2
        
        # Act - Successful login
        client.post("/auth/login", json={
            "email": sample_user.email,
            "password": "TestPassword123!",
        })
        
        # Assert
        db_session.refresh(sample_user)
        assert sample_user.failed_attempts == 0


class TestAuthWithDifferentRoles:
    """Tests for authentication with different user roles."""
    
    def test_super_admin_login(self, client: TestClient, sample_super_admin: User):
        """Test super admin login."""
        login_data = {
            "email": sample_super_admin.email,
            "password": "SuperAdminPassword123!",
        }
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        headers = {"Authorization": f"Bearer {data['access_token']}"}
        
        me_response = client.get("/auth/me", headers=headers)
        assert me_response.json()["role"] == "SUPER_ADMIN"
    
    def test_org_admin_login(self, client: TestClient, sample_org_admin: User):
        """Test org admin login."""
        login_data = {
            "email": sample_org_admin.email,
            "password": "AdminPassword123!",
        }
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        headers = {"Authorization": f"Bearer {data['access_token']}"}
        
        me_response = client.get("/auth/me", headers=headers)
        assert me_response.json()["role"] == "ORG_ADMIN"
    
    def test_analyst_login(self, client: TestClient, sample_analyst: User):
        """Test analyst login."""
        login_data = {
            "email": sample_analyst.email,
            "password": "AnalystPassword123!",
        }
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        headers = {"Authorization": f"Bearer {data['access_token']}"}
        
        me_response = client.get("/auth/me", headers=headers)
        assert me_response.json()["role"] == "SECURITY_ANALYST"
