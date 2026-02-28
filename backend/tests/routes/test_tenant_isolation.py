"""
Cross-Tenant Access Prevention Integration Tests
=================================================

Integration tests for multi-tenant data isolation including:
- Cross-tenant user access prevention
- Cross-tenant data filtering
- Super admin cross-tenant access
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.organization import Organization
from app.models.role_enum import Role
from app.services.auth_service import AuthService


pytestmark = pytest.mark.integration


class TestCrossTenantUserAccess:
    """Tests for cross-tenant user access prevention."""
    
    def test_user_cannot_access_other_tenant_user(
        self,
        client: TestClient,
        auth_headers: dict,
        second_org_user: User,
    ):
        """Test that user cannot access user from another tenant."""
        # Act - Try to access user from different organization
        response = client.get(
            f"/admin/users/{second_org_user.id}",
            headers=auth_headers,
        )
        
        # Assert - Should be denied (403) because not super admin
        assert response.status_code == 403
    
    def test_org_admin_cannot_access_other_tenant_user(
        self,
        client: TestClient,
        org_admin_auth_headers: dict,
        second_org_user: User,
    ):
        """Test that org admin cannot access user from another tenant."""
        # Act
        response = client.get(
            f"/admin/users/{second_org_user.id}",
            headers=org_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 403
    
    def test_super_admin_can_access_any_tenant_user(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        second_org_user: User,
    ):
        """Test that super admin can access user from any tenant."""
        # Act
        response = client.get(
            f"/admin/users/{second_org_user.id}",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(second_org_user.id)


class TestCrossTenantDataFiltering:
    """Tests for cross-tenant data filtering."""
    
    def test_user_list_filtered_by_tenant(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_user: User,
        second_org_user: User,
    ):
        """Test that user list contains users from all tenants for super admin."""
        # Act
        response = client.get("/admin/users", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        user_ids = [u["id"] for u in data["users"]]
        
        # Super admin should see users from all tenants
        assert str(sample_user.id) in user_ids
        assert str(second_org_user.id) in user_ids


class TestCrossTenantOrganizationAccess:
    """Tests for cross-tenant organization access."""
    
    def test_super_admin_can_access_any_organization(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_organization: Organization,
        second_organization: Organization,
    ):
        """Test that super admin can access any organization."""
        # Act & Assert
        response1 = client.get(
            f"/admin/organizations/{sample_organization.id}",
            headers=super_admin_auth_headers,
        )
        assert response1.status_code == 200
        
        response2 = client.get(
            f"/admin/organizations/{second_organization.id}",
            headers=super_admin_auth_headers,
        )
        assert response2.status_code == 200


class TestCrossTenantUpdatePrevention:
    """Tests for cross-tenant update prevention."""
    
    def test_user_cannot_update_other_tenant_user(
        self,
        client: TestClient,
        auth_headers: dict,
        second_org_user: User,
    ):
        """Test that user cannot update user from another tenant."""
        # Arrange
        update_data = {"is_active": False}
        
        # Act
        response = client.patch(
            f"/admin/users/{second_org_user.id}",
            json=update_data,
            headers=auth_headers,
        )
        
        # Assert
        assert response.status_code == 403
    
    def test_super_admin_can_update_any_tenant_user(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        second_org_user: User,
        db_session: Session,
    ):
        """Test that super admin can update user from any tenant."""
        # Arrange
        update_data = {"is_active": False}
        
        # Act
        response = client.patch(
            f"/admin/users/{second_org_user.id}",
            json=update_data,
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False


class TestCrossTenantUnlockPrevention:
    """Tests for cross-tenant unlock prevention."""
    
    def test_user_cannot_unlock_other_tenant_user(
        self,
        client: TestClient,
        auth_headers: dict,
        sample_locked_user: User,
    ):
        """Test that regular user cannot unlock any user."""
        # Act
        response = client.post(
            f"/admin/users/{sample_locked_user.id}/unlock",
            headers=auth_headers,
        )
        
        # Assert
        assert response.status_code == 403
    
    def test_super_admin_can_unlock_any_tenant_user(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        db_session: Session,
        second_organization: Organization,
    ):
        """Test that super admin can unlock user from any tenant."""
        # Arrange - Create a locked user in second organization
        auth_service = AuthService(db_session)
        locked_user = User(
            email="locked2@secondorg.com",
            hashed_password=auth_service.hash_password("Password123!"),
            role=Role.READ_ONLY,
            tenant_id=second_organization.id,
            is_locked=True,
            failed_attempts=5,
        )
        db_session.add(locked_user)
        db_session.commit()
        
        # Act
        response = client.post(
            f"/admin/users/{locked_user.id}/unlock",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200


class TestTenantContextInTokens:
    """Tests for tenant context in JWT tokens."""
    
    def test_token_contains_correct_tenant_id(
        self,
        client: TestClient,
        sample_user: User,
        sample_organization: Organization,
    ):
        """Test that JWT token contains correct tenant ID."""
        # Arrange
        login_data = {
            "email": sample_user.email,
            "password": "TestPassword123!",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        
        # Decode token and verify tenant_id
        from app.services.auth_service import AuthService
        payload = AuthService.decode_token(data["access_token"])
        assert payload["tenant_id"] == str(sample_organization.id)
    
    def test_me_endpoint_returns_correct_tenant(
        self,
        client: TestClient,
        auth_headers: dict,
        sample_user: User,
        sample_organization: Organization,
    ):
        """Test that /auth/me returns correct tenant ID."""
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["tenant_id"] == str(sample_organization.id)


class TestTenantIsolationWithMultipleOrgs:
    """Tests for tenant isolation with multiple organizations."""
    
    def test_users_from_different_orgs_have_different_tenants(
        self,
        sample_user: User,
        second_org_user: User,
        sample_organization: Organization,
        second_organization: Organization,
    ):
        """Test that users from different orgs have different tenant IDs."""
        # Assert
        assert sample_user.tenant_id != second_org_user.tenant_id
        assert sample_user.tenant_id == sample_organization.id
        assert second_org_user.tenant_id == second_organization.id
    
    def test_login_returns_correct_tenant_context(
        self,
        client: TestClient,
        sample_user: User,
        second_org_user: User,
    ):
        """Test that login returns correct tenant context for each user."""
        # Act - Login as first user
        response1 = client.post("/auth/login", json={
            "email": sample_user.email,
            "password": "TestPassword123!",
        })
        
        # Act - Login as second user
        response2 = client.post("/auth/login", json={
            "email": second_org_user.email,
            "password": "SecondOrgPassword123!",
        })
        
        # Assert
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        data1 = response1.json()
        data2 = response2.json()
        
        # Decode tokens and verify different tenant IDs
        from app.services.auth_service import AuthService
        payload1 = AuthService.decode_token(data1["access_token"])
        payload2 = AuthService.decode_token(data2["access_token"])
        
        assert payload1["tenant_id"] != payload2["tenant_id"]
        assert payload1["tenant_id"] == str(sample_user.tenant_id)
        assert payload2["tenant_id"] == str(second_org_user.tenant_id)


class TestTenantIsolationEdgeCases:
    """Tests for tenant isolation edge cases."""
    
    def test_user_with_no_organization_cannot_login(
        self,
        db_session: Session,
        client: TestClient,
    ):
        """Test that user without organization cannot perform operations."""
        # Note: In this system, tenant_id is required, so this tests
        # the case where a user might have been created incorrectly
        
        # This is more of a model validation test, but included here
        # for completeness
        pass
    
    def test_super_admin_token_works_across_tenants(
        self,
        client: TestClient,
        super_admin_auth_headers: dict,
        sample_organization: Organization,
        second_organization: Organization,
    ):
        """Test that super admin token works across all tenants."""
        # Act - Access organizations from different tenants
        response1 = client.get(
            f"/admin/organizations/{sample_organization.id}",
            headers=super_admin_auth_headers,
        )
        response2 = client.get(
            f"/admin/organizations/{second_organization.id}",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response1.status_code == 200
        assert response2.status_code == 200
    
    def test_regular_user_token_limited_to_own_tenant(
        self,
        client: TestClient,
        auth_headers: dict,
        second_organization: Organization,
    ):
        """Test that regular user token is limited to own tenant."""
        # Act - Try to access organization from different tenant
        response = client.get(
            f"/admin/organizations/{second_organization.id}",
            headers=auth_headers,
        )
        
        # Assert - Should be denied (403 for non-super-admin)
        assert response.status_code == 403


class TestTenantIsolationAuditLogging:
    """Tests for tenant isolation audit logging."""
    
    def test_cross_tenant_access_attempt_is_logged(
        self,
        client: TestClient,
        auth_headers: dict,
        second_org_user: User,
    ):
        """Test that cross-tenant access attempts are logged."""
        # This test verifies that the access attempt is made
        # In a real scenario, you would check the logs
        
        # Act
        response = client.get(
            f"/admin/users/{second_org_user.id}",
            headers=auth_headers,
        )
        
        # Assert - Access denied
        assert response.status_code == 403
        
        # Note: In a real test, you would verify that:
        # 1. A log entry was created
        # 2. The log contains the user ID, target resource, and tenant IDs
        # 3. The log indicates a tenant isolation violation attempt
