"""
Protected Routes Integration Tests
==================================

Integration tests for protected route access including:
- Authentication requirement
- Role-based access control
- Token validation
"""

import pytest
from fastapi.testclient import TestClient
from datetime import timedelta
from uuid import uuid4

from app.models.user import User
from app.services.auth_service import AuthService


pytestmark = pytest.mark.integration


class TestAuthenticationRequirement:
    """Tests for authentication requirement on protected routes."""
    
    def test_auth_me_requires_authentication(self, client: TestClient):
        """Test that /auth/me requires authentication."""
        # Act
        response = client.get("/auth/me")
        
        # Assert
        assert response.status_code == 401
    
    def test_auth_verify_requires_authentication(self, client: TestClient):
        """Test that /auth/verify requires authentication."""
        # Act
        response = client.get("/auth/verify")
        
        # Assert
        assert response.status_code == 401
    
    def test_auth_logout_requires_authentication(self, client: TestClient):
        """Test that /auth/logout requires authentication."""
        # Act
        response = client.post("/auth/logout")
        
        # Assert
        assert response.status_code == 401
    
    def test_admin_dashboard_requires_authentication(self, client: TestClient):
        """Test that /admin/dashboard requires authentication."""
        # Act
        response = client.get("/admin/dashboard")
        
        # Assert
        assert response.status_code == 401
    
    def test_admin_users_requires_authentication(self, client: TestClient):
        """Test that /admin/users requires authentication."""
        # Act
        response = client.get("/admin/users")
        
        # Assert
        assert response.status_code == 401


class TestTokenValidation:
    """Tests for token validation on protected routes."""
    
    def test_invalid_token_returns_401(self, client: TestClient):
        """Test that invalid token returns 401."""
        # Arrange
        headers = {"Authorization": "Bearer invalid.token.here"}
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 401
    
    def test_malformed_authorization_header_returns_401(self, client: TestClient):
        """Test that malformed authorization header returns 401."""
        # Arrange
        headers = {"Authorization": "InvalidFormat token"}
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 401
    
    def test_missing_bearer_prefix_returns_401(self, client: TestClient, user_access_token: str):
        """Test that missing Bearer prefix returns 401."""
        # Arrange
        headers = {"Authorization": user_access_token}  # Missing "Bearer "
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 401
    
    def test_expired_token_returns_401(self, client: TestClient):
        """Test that expired token returns 401."""
        # Arrange - Create an expired token
        expired_token = AuthService.create_access_token(
            user_id=uuid4(),
            tenant_id=uuid4(),
            token_version=1,
            expires_delta=timedelta(seconds=-1),
        )
        headers = {"Authorization": f"Bearer {expired_token}"}
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 401
    
    def test_valid_token_allows_access(self, client: TestClient, auth_headers: dict):
        """Test that valid token allows access."""
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200


class TestRoleBasedAccess:
    """Tests for role-based access control."""
    
    def test_read_only_user_can_access_me(self, client: TestClient, auth_headers: dict):
        """Test that read-only user can access /auth/me."""
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
    
    def test_read_only_user_cannot_access_admin_dashboard(
        self,
        client: TestClient,
        auth_headers: dict,
    ):
        """Test that read-only user cannot access admin dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_analyst_cannot_access_admin_dashboard(
        self,
        client: TestClient,
        analyst_auth_headers: dict,
    ):
        """Test that analyst cannot access admin dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=analyst_auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_org_admin_cannot_access_admin_dashboard(
        self,
        client: TestClient,
        org_admin_auth_headers: dict,
    ):
        """Test that org admin cannot access admin dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=org_admin_auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_super_admin_can_access_admin_dashboard(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
    ):
        """Test that super admin can access admin dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200


class TestLockedAccountAccess:
    """Tests for locked account access."""
    
    def test_locked_user_cannot_access_protected_routes(
        self,
        client: TestClient,
        db_session,
        sample_locked_user: User,
    ):
        """Test that locked user cannot access protected routes."""
        # Arrange - Create token for locked user
        token = AuthService.create_access_token(
            user_id=sample_locked_user.id,
            tenant_id=sample_locked_user.tenant_id,
            token_version=sample_locked_user.token_version,
        )
        headers = {"Authorization": f"Bearer {token}"}
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 403


class TestDisabledAccountAccess:
    """Tests for disabled account access."""
    
    def test_disabled_user_cannot_access_protected_routes(
        self,
        client: TestClient,
        sample_inactive_user: User,
    ):
        """Test that disabled user cannot access protected routes."""
        # Arrange - Create token for inactive user
        token = AuthService.create_access_token(
            user_id=sample_inactive_user.id,
            tenant_id=sample_inactive_user.tenant_id,
            token_version=sample_inactive_user.token_version,
        )
        headers = {"Authorization": f"Bearer {token}"}
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 403


class TestTokenVersionValidation:
    """Tests for token version validation."""
    
    def test_old_token_version_invalidated(
        self,
        client: TestClient,
        sample_user: User,
        db_session,
    ):
        """Test that old token version is invalidated after logout."""
        # Arrange - Create token
        token = AuthService.create_access_token(
            user_id=sample_user.id,
            tenant_id=sample_user.tenant_id,
            token_version=sample_user.token_version,
        )
        headers = {"Authorization": f"Bearer {token}"}
        
        # Act 1 - Verify token works
        response1 = client.get("/auth/me", headers=headers)
        assert response1.status_code == 200
        
        # Act 2 - Logout (increments token version)
        client.post("/auth/logout", headers=headers)
        
        # Act 3 - Try to use old token
        response2 = client.get("/auth/me", headers=headers)
        
        # Assert - Old token should now fail
        assert response2.status_code == 401


class TestPublicRoutes:
    """Tests for public routes that don't require authentication."""
    
    def test_health_check_is_public(self, client: TestClient):
        """Test that health check is public."""
        # Act
        response = client.get("/health")
        
        # Assert
        assert response.status_code == 200
    
    def test_root_is_public(self, client: TestClient):
        """Test that root endpoint is public."""
        # Act
        response = client.get("/")
        
        # Assert
        assert response.status_code == 200
    
    def test_login_is_public(self, client: TestClient):
        """Test that login endpoint is public."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "password123",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert - Should get 401 (invalid credentials), not 401 (not authenticated)
        # The endpoint is accessible, just credentials are wrong
        assert response.status_code in [401, 422]
    
    def test_info_is_public(self, client: TestClient):
        """Test that info endpoint is public."""
        # Act
        response = client.get("/info")
        
        # Assert
        assert response.status_code == 200


class TestProtectedRouteResponses:
    """Tests for protected route response formats."""
    
    def test_401_response_format(self, client: TestClient):
        """Test that 401 response has correct format."""
        # Act
        response = client.get("/auth/me")
        
        # Assert
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
    
    def test_403_response_format(self, client: TestClient, auth_headers: dict):
        """Test that 403 response has correct format."""
        # Act
        response = client.get("/admin/dashboard", headers=auth_headers)
        
        # Assert
        assert response.status_code == 403
        data = response.json()
        assert "detail" in data
    
    def test_200_response_format(self, client: TestClient, auth_headers: dict, sample_user: User):
        """Test that 200 response has correct format."""
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert "email" in data
        assert "role" in data
        assert "tenant_id" in data


class TestConcurrentSessions:
    """Tests for concurrent session handling."""
    
    def test_multiple_tokens_for_same_user(
        self,
        client: TestClient,
        sample_user: User,
    ):
        """Test that multiple tokens for same user work."""
        # Arrange - Create two tokens
        token1 = AuthService.create_access_token(
            user_id=sample_user.id,
            tenant_id=sample_user.tenant_id,
            token_version=sample_user.token_version,
        )
        token2 = AuthService.create_access_token(
            user_id=sample_user.id,
            tenant_id=sample_user.tenant_id,
            token_version=sample_user.token_version,
        )
        
        headers1 = {"Authorization": f"Bearer {token1}"}
        headers2 = {"Authorization": f"Bearer {token2}"}
        
        # Act & Assert - Both tokens should work
        response1 = client.get("/auth/me", headers=headers1)
        assert response1.status_code == 200
        
        response2 = client.get("/auth/me", headers=headers2)
        assert response2.status_code == 200
    
    def test_logout_invalidates_all_sessions(
        self,
        client: TestClient,
        sample_user: User,
    ):
        """Test that logout invalidates all sessions."""
        # Arrange - Create two tokens
        token1 = AuthService.create_access_token(
            user_id=sample_user.id,
            tenant_id=sample_user.tenant_id,
            token_version=sample_user.token_version,
        )
        token2 = AuthService.create_access_token(
            user_id=sample_user.id,
            tenant_id=sample_user.tenant_id,
            token_version=sample_user.token_version,
        )
        
        headers1 = {"Authorization": f"Bearer {token1}"}
        headers2 = {"Authorization": f"Bearer {token2}"}
        
        # Act - Logout with first token
        client.post("/auth/logout", headers=headers1)
        
        # Assert - Both tokens should now fail
        response1 = client.get("/auth/me", headers=headers1)
        assert response1.status_code == 401
        
        response2 = client.get("/auth/me", headers=headers2)
        assert response2.status_code == 401
