"""
Admin Routes Integration Tests
==============================

Integration tests for admin endpoints including:
- GET /admin/dashboard
- GET /admin/users
- GET /admin/users/{user_id}
- PATCH /admin/users/{user_id}
- POST /admin/users/{user_id}/unlock
- GET /admin/organizations
- GET /admin/organizations/{org_id}
"""

import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from app.models.user import User
from app.models.organization import Organization
from app.models.role_enum import Role


pytestmark = pytest.mark.integration


class TestAdminDashboardEndpoint:
    """Integration tests for GET /admin/dashboard endpoint."""
    
    def test_dashboard_super_admin_access(self, client: TestClient, super_admin_auth_headers: dict):
        """Test that super admin can access dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "statistics" in data
        assert "total_users" in data["statistics"]
        assert "total_organizations" in data["statistics"]
    
    def test_dashboard_org_admin_denied(self, client: TestClient, org_admin_auth_headers: dict):
        """Test that org admin cannot access dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=org_admin_auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_dashboard_analyst_denied(self, client: TestClient, analyst_auth_headers: dict):
        """Test that analyst cannot access dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=analyst_auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_dashboard_read_only_denied(self, client: TestClient, auth_headers: dict):
        """Test that read-only user cannot access dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_dashboard_unauthenticated_denied(self, client: TestClient):
        """Test that unauthenticated user cannot access dashboard."""
        # Act
        response = client.get("/admin/dashboard")
        
        # Assert
        assert response.status_code == 401


class TestListUsersEndpoint:
    """Integration tests for GET /admin/users endpoint."""
    
    def test_list_users_super_admin_success(self, client: TestClient, super_admin_auth_headers: dict):
        """Test that super admin can list users."""
        # Act
        response = client.get("/admin/users", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
    
    def test_list_users_pagination(self, client: TestClient, super_admin_auth_headers: dict):
        """Test user list pagination."""
        # Act
        response = client.get("/admin/users?page=1&page_size=10", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 10
    
    def test_list_users_filter_by_role(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
    ):
        """Test filtering users by role."""
        # Act
        response = client.get(
            "/admin/users?role=READ_ONLY",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        for user in data["users"]:
            assert user["role"] == "READ_ONLY"
    
    def test_list_users_filter_by_active_status(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
    ):
        """Test filtering users by active status."""
        # Act
        response = client.get(
            "/admin/users?is_active=true",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        for user in data["users"]:
            assert user["is_active"] is True
    
    def test_list_users_org_admin_denied(self, client: TestClient, org_admin_auth_headers: dict):
        """Test that org admin cannot list all users."""
        # Act
        response = client.get("/admin/users", headers=org_admin_auth_headers)
        
        # Assert
        assert response.status_code == 403


class TestGetUserEndpoint:
    """Integration tests for GET /admin/users/{user_id} endpoint."""
    
    def test_get_user_success(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
    ):
        """Test getting user by ID."""
        # Act
        response = client.get(
            f"/admin/users/{sample_user.id}",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(sample_user.id)
        assert data["email"] == sample_user.email
    
    def test_get_user_not_found(self, client: TestClient, super_admin_auth_headers: dict):
        """Test getting non-existent user."""
        # Arrange
        nonexistent_id = uuid4()
        
        # Act
        response = client.get(
            f"/admin/users/{nonexistent_id}",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 404
    
    def test_get_user_invalid_id(self, client: TestClient, super_admin_auth_headers: dict):
        """Test getting user with invalid ID format."""
        # Act
        response = client.get(
            "/admin/users/invalid-uuid",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 422


class TestUpdateUserEndpoint:
    """Integration tests for PATCH /admin/users/{user_id} endpoint."""
    
    def test_update_user_email(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
    ):
        """Test updating user email."""
        # Arrange
        update_data = {"email": "newemail@example.com"}
        
        # Act
        response = client.patch(
            f"/admin/users/{sample_user.id}",
            json=update_data,
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "newemail@example.com"
    
    def test_update_user_role(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
    ):
        """Test updating user role."""
        # Arrange
        update_data = {"role": "SECURITY_ANALYST"}
        
        # Act
        response = client.patch(
            f"/admin/users/{sample_user.id}",
            json=update_data,
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "SECURITY_ANALYST"
    
    def test_update_user_active_status(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
    ):
        """Test updating user active status."""
        # Arrange
        update_data = {"is_active": False}
        
        # Act
        response = client.patch(
            f"/admin/users/{sample_user.id}",
            json=update_data,
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False
    
    def test_update_user_duplicate_email(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
        sample_org_admin: User,
    ):
        """Test updating user with duplicate email."""
        # Arrange
        update_data = {"email": sample_org_admin.email}  # Already exists
        
        # Act
        response = client.patch(
            f"/admin/users/{sample_user.id}",
            json=update_data,
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 422  # Validation error for duplicate email
    
    def test_update_user_not_found(self, client: TestClient, super_admin_auth_headers: dict):
        """Test updating non-existent user."""
        # Arrange
        nonexistent_id = uuid4()
        update_data = {"email": "new@example.com"}
        
        # Act
        response = client.patch(
            f"/admin/users/{nonexistent_id}",
            json=update_data,
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 404
    
    def test_update_user_org_admin_denied(
        self,
        client: TestClient,
        org_admin_auth_headers: dict,
        sample_user: User,
    ):
        """Test that org admin cannot update users."""
        # Arrange
        update_data = {"is_active": False}
        
        # Act
        response = client.patch(
            f"/admin/users/{sample_user.id}",
            json=update_data,
            headers=org_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 403


class TestUnlockUserEndpoint:
    """Integration tests for POST /admin/users/{user_id}/unlock endpoint."""
    
    def test_unlock_locked_user(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_locked_user: User,
    ):
        """Test unlocking a locked user."""
        # Act
        response = client.post(
            f"/admin/users/{sample_locked_user.id}/unlock",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "unlocked" in data["message"].lower()
    
    def test_unlock_already_unlocked_user(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
    ):
        """Test unlocking an already unlocked user."""
        # Act
        response = client.post(
            f"/admin/users/{sample_user.id}/unlock",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "not locked" in data["message"].lower()
    
    def test_unlock_user_not_found(self, client: TestClient, super_admin_auth_headers: dict):
        """Test unlocking non-existent user."""
        # Arrange
        nonexistent_id = uuid4()
        
        # Act
        response = client.post(
            f"/admin/users/{nonexistent_id}/unlock",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 404
    
    def test_unlock_user_org_admin_denied(
        self,
        client: TestClient,
        org_admin_auth_headers: dict,
        sample_locked_user: User,
    ):
        """Test that org admin cannot unlock users."""
        # Act
        response = client.post(
            f"/admin/users/{sample_locked_user.id}/unlock",
            headers=org_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 403


class TestListOrganizationsEndpoint:
    """Integration tests for GET /admin/organizations endpoint."""
    
    def test_list_organizations_success(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_organization: Organization,
    ):
        """Test listing organizations."""
        # Act
        response = client.get("/admin/organizations", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "organizations" in data
        assert "total" in data
        assert data["total"] >= 1
    
    def test_list_organizations_pagination(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
    ):
        """Test organization list pagination."""
        # Act
        response = client.get(
            "/admin/organizations?page=1&page_size=5",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 5
    
    def test_list_organizations_org_admin_denied(
        self,
        client: TestClient,
        org_admin_auth_headers: dict,
    ):
        """Test that org admin cannot list organizations."""
        # Act
        response = client.get("/admin/organizations", headers=org_admin_auth_headers)
        
        # Assert
        assert response.status_code == 403


class TestGetOrganizationEndpoint:
    """Integration tests for GET /admin/organizations/{org_id} endpoint."""
    
    def test_get_organization_success(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_organization: Organization,
    ):
        """Test getting organization by ID."""
        # Act
        response = client.get(
            f"/admin/organizations/{sample_organization.id}",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(sample_organization.id)
        assert data["name"] == sample_organization.name
    
    def test_get_organization_not_found(self, client: TestClient, super_admin_auth_headers: dict):
        """Test getting non-existent organization."""
        # Arrange
        nonexistent_id = uuid4()
        
        # Act
        response = client.get(
            f"/admin/organizations/{nonexistent_id}",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 404


class TestAdminEndpointsAuthorization:
    """Tests for admin endpoints authorization."""
    
    def test_all_admin_endpoints_require_super_admin(
        self,
        client: TestClient,
        auth_headers: dict,
        sample_user: User,
        sample_organization: Organization,
    ):
        """Test that all admin endpoints require super admin role."""
        endpoints = [
            ("GET", "/admin/dashboard"),
            ("GET", "/admin/users"),
            ("GET", f"/admin/users/{sample_user.id}"),
            ("PATCH", f"/admin/users/{sample_user.id}"),
            ("POST", f"/admin/users/{sample_user.id}/unlock"),
            ("GET", "/admin/organizations"),
            ("GET", f"/admin/organizations/{sample_organization.id}"),
        ]
        
        for method, endpoint in endpoints:
            if method == "GET":
                response = client.get(endpoint, headers=auth_headers)
            elif method == "PATCH":
                response = client.patch(endpoint, json={}, headers=auth_headers)
            elif method == "POST":
                response = client.post(endpoint, headers=auth_headers)
            
            assert response.status_code == 403, f"Endpoint {method} {endpoint} should return 403"
    
    def test_all_admin_endpoints_require_authentication(
        self,
        client: TestClient,
        sample_user: User,
        sample_organization: Organization,
    ):
        """Test that all admin endpoints require authentication."""
        endpoints = [
            ("GET", "/admin/dashboard"),
            ("GET", "/admin/users"),
            ("GET", f"/admin/users/{sample_user.id}"),
            ("PATCH", f"/admin/users/{sample_user.id}"),
            ("POST", f"/admin/users/{sample_user.id}/unlock"),
            ("GET", "/admin/organizations"),
            ("GET", f"/admin/organizations/{sample_organization.id}"),
        ]
        
        for method, endpoint in endpoints:
            if method == "GET":
                response = client.get(endpoint)
            elif method == "PATCH":
                response = client.patch(endpoint, json={})
            elif method == "POST":
                response = client.post(endpoint)
            
            assert response.status_code == 401, f"Endpoint {method} {endpoint} should return 401"


class TestAdminDashboardStatistics:
    """Tests for admin dashboard statistics."""
    
    def test_dashboard_shows_correct_user_count(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
        sample_org_admin: User,
        sample_analyst: User,
        sample_super_admin: User,
    ):
        """Test that dashboard shows correct user count."""
        # Act
        response = client.get("/admin/dashboard", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["statistics"]["total_users"] >= 4
    
    def test_dashboard_shows_correct_organization_count(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_organization: Organization,
    ):
        """Test that dashboard shows correct organization count."""
        # Act
        response = client.get("/admin/dashboard", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["statistics"]["total_organizations"] >= 1
    
    def test_dashboard_shows_locked_users_count(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_locked_user: User,
    ):
        """Test that dashboard shows locked users count."""
        # Act
        response = client.get("/admin/dashboard", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["statistics"]["locked_users"] >= 1
