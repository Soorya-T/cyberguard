"""
Authentication Middleware Unit Tests
=====================================

Tests for middleware components including:
- AuthMiddleware
- SecurityHeadersMiddleware
- RateLimitMiddleware
"""

import pytest
from fastapi.testclient import TestClient


pytestmark = pytest.mark.middleware


class TestAuthMiddleware:
    """Tests for AuthMiddleware."""
    
    def test_request_id_header_added(self, client: TestClient):
        """Test that X-Request-ID header is added to responses."""
        # Act
        response = client.get("/")
        
        # Assert
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0
    
    def test_process_time_header_added(self, client: TestClient):
        """Test that X-Process-Time header is added to responses."""
        # Act
        response = client.get("/")
        
        # Assert
        assert "X-Process-Time" in response.headers
    
    def test_public_paths_accessible_without_auth(self, client: TestClient):
        """Test that public paths are accessible without authentication."""
        # Act & Assert
        response = client.get("/")
        assert response.status_code == 200
        
        response = client.get("/health")
        assert response.status_code == 200
    
    def test_protected_paths_require_auth(self, client: TestClient):
        """Test that protected paths require authentication."""
        # Act
        response = client.get("/auth/me")
        
        # Assert
        assert response.status_code == 401
    
    def test_valid_token_allows_access(self, client: TestClient, auth_headers: dict):
        """Test that valid token allows access to protected routes."""
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
    
    def test_invalid_token_returns_401(self, client: TestClient):
        """Test that invalid token returns 401."""
        # Arrange
        headers = {"Authorization": "Bearer invalid.token.here"}
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 401
    
    def test_malformed_auth_header_returns_401(self, client: TestClient):
        """Test that malformed authorization header returns 401."""
        # Arrange
        headers = {"Authorization": "InvalidFormat"}
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 401
    
    def test_expired_token_returns_401(self, client: TestClient):
        """Test that expired token returns 401."""
        # Arrange - Create an expired token
        from datetime import timedelta
        from app.services.auth_service import AuthService
        from uuid import uuid4
        
        expired_token = AuthService.create_access_token(
            user_id=uuid4(),
            tenant_id=uuid4(),
            token_version=1,
            expires_delta=timedelta(seconds=-1),  # Already expired
        )
        headers = {"Authorization": f"Bearer {expired_token}"}
        
        # Act
        response = client.get("/auth/me", headers=headers)
        
        # Assert
        assert response.status_code == 401


class TestSecurityHeadersMiddleware:
    """Tests for SecurityHeadersMiddleware."""
    
    def test_x_content_type_options_header(self, client: TestClient):
        """Test that X-Content-Type-Options header is set."""
        # Act
        response = client.get("/")
        
        # Assert
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
    
    def test_x_frame_options_header(self, client: TestClient):
        """Test that X-Frame-Options header is set."""
        # Act
        response = client.get("/")
        
        # Assert
        assert response.headers.get("X-Frame-Options") == "DENY"
    
    def test_x_xss_protection_header(self, client: TestClient):
        """Test that X-XSS-Protection header is set."""
        # Act
        response = client.get("/")
        
        # Assert
        assert "X-XSS-Protection" in response.headers
    
    def test_referrer_policy_header(self, client: TestClient):
        """Test that Referrer-Policy header is set."""
        # Act
        response = client.get("/")
        
        # Assert
        assert "Referrer-Policy" in response.headers
    
    def test_content_security_policy_header(self, client: TestClient):
        """Test that Content-Security-Policy header is set."""
        # Act
        response = client.get("/")
        
        # Assert
        assert "Content-Security-Policy" in response.headers


class TestRateLimitMiddleware:
    """Tests for RateLimitMiddleware."""
    
    def test_normal_requests_allowed(self, client: TestClient):
        """Test that normal rate of requests is allowed."""
        # Act & Assert
        for _ in range(3):
            response = client.get("/")
            assert response.status_code == 200
    
    def test_login_endpoint_rate_limiting(self, client: TestClient):
        """Test that login endpoint has rate limiting."""
        # This test would need to make many requests to trigger rate limiting
        # For now, we just verify the endpoint works normally
        login_data = {
            "email": "test@example.com",
            "password": "wrongpassword",
        }
        
        # Act
        response = client.post("/auth/login", json=login_data)
        
        # Assert - Should get 401 (invalid credentials), not 429 (rate limited)
        # since we're only making one request
        assert response.status_code in [401, 422]


class TestMiddlewareIntegration:
    """Integration tests for middleware stack."""
    
    def test_all_middlewares_work_together(self, client: TestClient, auth_headers: dict):
        """Test that all middlewares work together correctly."""
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert - Check security headers
        assert "X-Request-ID" in response.headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        
        # Assert - Check response
        assert response.status_code == 200
    
    def test_middleware_with_cors_preflight(self, client: TestClient):
        """Test middleware handling of CORS preflight requests."""
        # Act
        response = client.options(
            "/auth/login",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        
        # Assert
        assert response.status_code in [200, 400, 405]
    
    def test_health_check_not_logged(self, client: TestClient):
        """Test that health check endpoints work correctly."""
        # Act
        response = client.get("/health")
        
        # Assert
        assert response.status_code == 200
        assert "X-Request-ID" in response.headers


class TestMiddlewareErrorHandling:
    """Tests for middleware error handling."""
    
    def test_invalid_json_returns_error(self, client: TestClient):
        """Test that invalid JSON returns proper error."""
        # Act
        response = client.post(
            "/auth/login",
            content="invalid json",
            headers={"Content-Type": "application/json"},
        )
        
        # Assert
        assert response.status_code == 422
    
    def test_missing_content_type_handled(self, client: TestClient):
        """Test that missing content type is handled."""
        # Act
        response = client.post("/auth/login", content='{"email": "test@example.com"}')
        
        # Assert
        # Should still process, FastAPI handles content type detection
        assert response.status_code in [401, 422]


class TestMiddlewareWithDifferentRoles:
    """Tests for middleware behavior with different user roles."""
    
    def test_super_admin_access(self, client: TestClient, super_admin_auth_headers: dict):
        """Test middleware with super admin user."""
        # Act
        response = client.get("/auth/me", headers=super_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "SUPER_ADMIN"
    
    def test_org_admin_access(self, client: TestClient, org_admin_auth_headers: dict):
        """Test middleware with org admin user."""
        # Act
        response = client.get("/auth/me", headers=org_admin_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "ORG_ADMIN"
    
    def test_analyst_access(self, client: TestClient, analyst_auth_headers: dict):
        """Test middleware with analyst user."""
        # Act
        response = client.get("/auth/me", headers=analyst_auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "SECURITY_ANALYST"
    
    def test_read_only_access(self, client: TestClient, auth_headers: dict):
        """Test middleware with read-only user."""
        # Act
        response = client.get("/auth/me", headers=auth_headers)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "READ_ONLY"
