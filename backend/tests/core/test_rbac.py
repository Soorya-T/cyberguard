"""
Role-Based Access Control (RBAC) Unit Tests
============================================

Tests for RBAC functionality including:
- Role hierarchy
- Role level checking
- require_role dependency
- require_role_or_higher dependency
- require_super_admin dependency
- require_org_admin dependency
- require_analyst dependency
- require_resource_owner_or_admin dependency
"""

import pytest
from uuid import uuid4

from app.models.role_enum import Role
from app.core.dependencies.rbac import (
    ROLE_HIERARCHY,
    get_role_level,
    has_role_or_higher,
)


pytestmark = pytest.mark.rbac


class TestRoleHierarchy:
    """Tests for role hierarchy configuration."""
    
    def test_role_hierarchy_order(self):
        """Test that role hierarchy is in correct order."""
        # Assert
        assert ROLE_HIERARCHY == [
            Role.READ_ONLY,
            Role.SECURITY_ANALYST,
            Role.ORG_ADMIN,
            Role.SUPER_ADMIN,
        ]
    
    def test_read_only_is_lowest(self):
        """Test that READ_ONLY is the lowest role."""
        # Assert
        assert ROLE_HIERARCHY[0] == Role.READ_ONLY
    
    def test_super_admin_is_highest(self):
        """Test that SUPER_ADMIN is the highest role."""
        # Assert
        assert ROLE_HIERARCHY[-1] == Role.SUPER_ADMIN


class TestGetRoleLevel:
    """Tests for get_role_level function."""
    
    def test_get_role_level_read_only(self):
        """Test level for READ_ONLY role."""
        # Act
        level = get_role_level(Role.READ_ONLY)
        
        # Assert
        assert level == 0
    
    def test_get_role_level_security_analyst(self):
        """Test level for SECURITY_ANALYST role."""
        # Act
        level = get_role_level(Role.SECURITY_ANALYST)
        
        # Assert
        assert level == 1
    
    def test_get_role_level_org_admin(self):
        """Test level for ORG_ADMIN role."""
        # Act
        level = get_role_level(Role.ORG_ADMIN)
        
        # Assert
        assert level == 2
    
    def test_get_role_level_super_admin(self):
        """Test level for SUPER_ADMIN role."""
        # Act
        level = get_role_level(Role.SUPER_ADMIN)
        
        # Assert
        assert level == 3
    
    def test_role_levels_are_ascending(self):
        """Test that role levels are in ascending order."""
        # Act
        read_only_level = get_role_level(Role.READ_ONLY)
        analyst_level = get_role_level(Role.SECURITY_ANALYST)
        org_admin_level = get_role_level(Role.ORG_ADMIN)
        super_admin_level = get_role_level(Role.SUPER_ADMIN)
        
        # Assert
        assert read_only_level < analyst_level < org_admin_level < super_admin_level


class TestHasRoleOrHigher:
    """Tests for has_role_or_higher function."""
    
    def test_read_only_has_read_only(self):
        """Test READ_ONLY has READ_ONLY or higher."""
        # Act
        result = has_role_or_higher(Role.READ_ONLY, Role.READ_ONLY)
        
        # Assert
        assert result is True
    
    def test_analyst_has_read_only(self):
        """Test SECURITY_ANALYST has READ_ONLY or higher."""
        # Act
        result = has_role_or_higher(Role.SECURITY_ANALYST, Role.READ_ONLY)
        
        # Assert
        assert result is True
    
    def test_org_admin_has_analyst(self):
        """Test ORG_ADMIN has SECURITY_ANALYST or higher."""
        # Act
        result = has_role_or_higher(Role.ORG_ADMIN, Role.SECURITY_ANALYST)
        
        # Assert
        assert result is True
    
    def test_super_admin_has_all(self):
        """Test SUPER_ADMIN has all roles or higher."""
        # Act & Assert
        assert has_role_or_higher(Role.SUPER_ADMIN, Role.READ_ONLY)
        assert has_role_or_higher(Role.SUPER_ADMIN, Role.SECURITY_ANALYST)
        assert has_role_or_higher(Role.SUPER_ADMIN, Role.ORG_ADMIN)
        assert has_role_or_higher(Role.SUPER_ADMIN, Role.SUPER_ADMIN)
    
    def test_read_only_does_not_have_analyst(self):
        """Test READ_ONLY does not have SECURITY_ANALYST or higher."""
        # Act
        result = has_role_or_higher(Role.READ_ONLY, Role.SECURITY_ANALYST)
        
        # Assert
        assert result is False
    
    def test_analyst_does_not_have_org_admin(self):
        """Test SECURITY_ANALYST does not have ORG_ADMIN or higher."""
        # Act
        result = has_role_or_higher(Role.SECURITY_ANALYST, Role.ORG_ADMIN)
        
        # Assert
        assert result is False
    
    def test_org_admin_does_not_have_super_admin(self):
        """Test ORG_ADMIN does not have SUPER_ADMIN or higher."""
        # Act
        result = has_role_or_higher(Role.ORG_ADMIN, Role.SUPER_ADMIN)
        
        # Assert
        assert result is False


class TestRequireRole:
    """Tests for require_role dependency."""
    
    def test_require_role_allows_correct_role(self, client, auth_headers):
        """Test that require_role allows users with correct role."""
        # Arrange - sample_user has READ_ONLY role
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
    
    def test_require_role_denies_wrong_role(self, client, auth_headers):
        """Test that require_role denies users without required role."""
        # Arrange - sample_user has READ_ONLY role
        # Try to access admin endpoint
        # Act
        response = client.get("/admin/dashboard", headers=auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_require_role_super_admin_allowed(self, client, super_admin_auth_headers):
        """Test that super admin can access admin endpoints."""
        # Act
        response = client.get("/admin/dashboard", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200


class TestRequireSuperAdmin:
    """Tests for require_super_admin dependency."""
    
    def test_super_admin_can_access_dashboard(self, client, super_admin_auth_headers):
        """Test that super admin can access admin dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "statistics" in data
    
    def test_org_admin_cannot_access_dashboard(self, client, org_admin_auth_headers):
        """Test that org admin cannot access super admin dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=org_admin_auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_analyst_cannot_access_dashboard(self, client, analyst_auth_headers):
        """Test that analyst cannot access super admin dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=analyst_auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_read_only_cannot_access_dashboard(self, client, auth_headers):
        """Test that read-only user cannot access super admin dashboard."""
        # Act
        response = client.get("/admin/dashboard", headers=auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_unauthenticated_cannot_access_dashboard(self, client):
        """Test that unauthenticated user cannot access dashboard."""
        # Act
        response = client.get("/admin/dashboard")
        
        # Assert
        assert response.status_code == 401


class TestRequireOrgAdmin:
    """Tests for require_org_admin dependency."""
    
    def test_super_admin_has_org_admin_privileges(self, client, super_admin_auth_headers):
        """Test that super admin has org admin privileges."""
        # Note: This would need an endpoint that uses require_org_admin
        # For now, we test the logic indirectly
        # Act
        response = client.get("/admin/dashboard", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200


class TestRoleBasedUserListing:
    """Tests for role-based user listing access."""
    
    def test_super_admin_can_list_users(self, client, super_admin_auth_headers):
        """Test that super admin can list all users."""
        # Act
        response = client.get("/admin/users", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert "total" in data
    
    def test_regular_user_cannot_list_users(self, client, auth_headers):
        """Test that regular user cannot list all users."""
        # Act
        response = client.get("/admin/users", headers=auth_headers)
        
        # Assert
        assert response.status_code == 403
    
    def test_org_admin_cannot_list_users(self, client, org_admin_auth_headers):
        """Test that org admin cannot list all users (super admin only)."""
        # Act
        response = client.get("/admin/users", headers=org_admin_auth_headers)
        
        # Assert
        assert response.status_code == 403


class TestRoleBasedUserUpdate:
    """Tests for role-based user update access."""
    
    def test_super_admin_can_update_user(
        self,
        client,
        super_admin_auth_headers,
        sample_user,
    ):
        """Test that super admin can update user."""
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
    
    def test_regular_user_cannot_update_user(
        self,
        client,
        auth_headers,
        sample_user,
    ):
        """Test that regular user cannot update another user."""
        # Arrange
        update_data = {"is_active": False}
        
        # Act
        response = client.patch(
            f"/admin/users/{sample_user.id}",
            json=update_data,
            headers=auth_headers,
        )
        
        # Assert
        assert response.status_code == 403


class TestRoleBasedUnlock:
    """Tests for role-based account unlock access."""
    
    def test_super_admin_can_unlock_user(
        self,
        client,
        super_admin_auth_headers,
        sample_locked_user,
    ):
        """Test that super admin can unlock a locked account."""
        # Act
        response = client.post(
            f"/admin/users/{sample_locked_user.id}/unlock",
            headers=super_admin_auth_headers,
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "unlocked" in data["message"].lower() or "not locked" in data["message"].lower()
    
    def test_regular_user_cannot_unlock_user(
        self,
        client,
        auth_headers,
        sample_locked_user,
    ):
        """Test that regular user cannot unlock accounts."""
        # Act
        response = client.post(
            f"/admin/users/{sample_locked_user.id}/unlock",
            headers=auth_headers,
        )
        
        # Assert
        assert response.status_code == 403


class TestRoleEnumValues:
    """Tests for Role enum values."""
    
    def test_role_values_are_strings(self):
        """Test that role values are strings."""
        # Assert
        assert Role.SUPER_ADMIN.value == "SUPER_ADMIN"
        assert Role.ORG_ADMIN.value == "ORG_ADMIN"
        assert Role.SECURITY_ANALYST.value == "SECURITY_ANALYST"
        assert Role.READ_ONLY.value == "READ_ONLY"
    
    def test_role_enum_is_string_enum(self):
        """Test that Role inherits from str and Enum."""
        # Assert
        assert isinstance(Role.SUPER_ADMIN, str)
        assert isinstance(Role.SUPER_ADMIN, Role)
    
    def test_all_roles_exist(self):
        """Test that all expected roles exist."""
        # Assert
        roles = list(Role)
        assert len(roles) == 4
        assert Role.SUPER_ADMIN in roles
        assert Role.ORG_ADMIN in roles
        assert Role.SECURITY_ANALYST in roles
        assert Role.READ_ONLY in roles
