"""
A3 – Dockerfile, Environment Loader & Security Configuration Tests
===================================================================

Tests for:
- Dockerfile structure and best practices
- Environment variable loading (.env via pydantic-settings)
- JWT secret key handling and validation
- Database connection configuration via environment
- docker-compose.yml service definitions
"""

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings


# Resolve project paths
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent  # backend/
PROJECT_ROOT = BACKEND_DIR.parent  # cyberguard/


# =============================================
# Dockerfile Tests
# =============================================


class TestDockerfile:
    """Validate the backend Dockerfile structure and best practices."""

    @pytest.fixture(autouse=True)
    def load_dockerfile(self):
        """Load Dockerfile content once for all tests in this class."""
        dockerfile_path = BACKEND_DIR / "Dockerfile"
        assert dockerfile_path.exists(), "Dockerfile must exist in backend/"
        self.content = dockerfile_path.read_text(encoding="utf-8")
        self.lines = [line.strip() for line in self.content.splitlines() if line.strip()]

    def test_dockerfile_exists(self):
        """Dockerfile should exist in the backend directory."""
        assert (BACKEND_DIR / "Dockerfile").exists()

    def test_uses_python_base_image(self):
        """Dockerfile should use a Python base image."""
        from_lines = [l for l in self.lines if l.startswith("FROM")]
        assert len(from_lines) >= 1
        assert "python" in from_lines[0].lower()

    def test_uses_slim_image(self):
        """Dockerfile should use a slim variant for smaller image size."""
        from_lines = [l for l in self.lines if l.startswith("FROM")]
        assert any("slim" in l.lower() for l in from_lines), \
            "Should use python:*-slim for smaller image"

    def test_sets_workdir(self):
        """Dockerfile should set a WORKDIR."""
        assert any(l.startswith("WORKDIR") for l in self.lines)

    def test_copies_requirements_first(self):
        """requirements.txt should be copied before application code (layer caching)."""
        copy_lines = [l for l in self.lines if l.startswith("COPY")]
        req_copy_idx = None
        app_copy_idx = None
        for i, line in enumerate(copy_lines):
            if "requirements" in line.lower():
                req_copy_idx = i
            if line.strip() == "COPY . .":
                app_copy_idx = i
        if req_copy_idx is not None and app_copy_idx is not None:
            assert req_copy_idx < app_copy_idx, \
                "requirements.txt should be copied before application code for layer caching"

    def test_installs_dependencies(self):
        """Dockerfile should install Python dependencies via pip."""
        assert any("pip install" in l for l in self.lines)

    def test_exposes_port(self):
        """Dockerfile should EXPOSE a port (8000)."""
        expose_lines = [l for l in self.lines if l.startswith("EXPOSE")]
        assert len(expose_lines) >= 1
        assert "8000" in expose_lines[0]

    def test_has_cmd_or_entrypoint(self):
        """Dockerfile should define CMD or ENTRYPOINT to run the app."""
        has_cmd = any(l.startswith("CMD") for l in self.lines)
        has_entrypoint = any(l.startswith("ENTRYPOINT") for l in self.lines)
        assert has_cmd or has_entrypoint, "Dockerfile must have CMD or ENTRYPOINT"

    def test_runs_uvicorn(self):
        """CMD should run uvicorn to serve the FastAPI app."""
        assert "uvicorn" in self.content.lower()

    def test_disables_bytecode(self):
        """PYTHONDONTWRITEBYTECODE should be set to avoid .pyc files."""
        assert "PYTHONDONTWRITEBYTECODE" in self.content

    def test_unbuffered_output(self):
        """PYTHONUNBUFFERED should be set for real-time log output."""
        assert "PYTHONUNBUFFERED" in self.content

    def test_installs_libpq(self):
        """Dockerfile should install libpq-dev for PostgreSQL support."""
        assert "libpq" in self.content.lower()


# =============================================
# .env / .env.example Tests
# =============================================


class TestEnvFiles:
    """Validate .env.example structure and .env loading."""

    @pytest.fixture(autouse=True)
    def load_env_example(self):
        """Load .env.example content."""
        env_example_path = BACKEND_DIR / ".env.example"
        assert env_example_path.exists(), ".env.example must exist"
        self.content = env_example_path.read_text(encoding="utf-8")

    def test_env_example_exists(self):
        """A .env.example file should exist as a template."""
        assert (BACKEND_DIR / ".env.example").exists()

    def test_env_example_has_database_url(self):
        """DATABASE_URL should be documented in .env.example."""
        assert "DATABASE_URL" in self.content

    def test_env_example_has_secret_key(self):
        """SECRET_KEY should be documented in .env.example."""
        assert "SECRET_KEY" in self.content

    def test_env_example_has_algorithm(self):
        """ALGORITHM should be documented in .env.example."""
        assert "ALGORITHM" in self.content

    def test_env_example_has_access_token_expire(self):
        """ACCESS_TOKEN_EXPIRE_MINUTES should be documented."""
        assert "ACCESS_TOKEN_EXPIRE_MINUTES" in self.content

    def test_env_example_has_refresh_token_expire(self):
        """REFRESH_TOKEN_EXPIRE_DAYS should be documented."""
        assert "REFRESH_TOKEN_EXPIRE_DAYS" in self.content

    def test_env_example_has_environment(self):
        """ENVIRONMENT should be documented in .env.example."""
        assert "ENVIRONMENT" in self.content

    def test_env_example_has_cors_origins(self):
        """CORS_ORIGINS should be documented in .env.example."""
        assert "CORS_ORIGINS" in self.content

    def test_env_example_has_rate_limit(self):
        """RATE_LIMIT_ENABLED should be documented in .env.example."""
        assert "RATE_LIMIT_ENABLED" in self.content

    def test_env_example_has_log_level(self):
        """LOG_LEVEL should be documented in .env.example."""
        assert "LOG_LEVEL" in self.content

    def test_gitignore_excludes_env(self):
        """The .gitignore should exclude .env files (not .env.example)."""
        gitignore_path = PROJECT_ROOT / ".gitignore"
        if gitignore_path.exists():
            gitignore = gitignore_path.read_text(encoding="utf-8")
            assert ".env" in gitignore


# =============================================
# JWT Secret Key Handling Tests
# =============================================


class TestJWTSecretHandling:
    """Validate JWT secret key configuration and security."""

    def test_settings_has_secret_key_field(self):
        """Settings should have a SECRET_KEY field."""
        assert hasattr(Settings, "model_fields")
        assert "SECRET_KEY" in Settings.model_fields

    def test_settings_has_algorithm_field(self):
        """Settings should have an ALGORITHM field."""
        assert "ALGORITHM" in Settings.model_fields

    def test_settings_has_access_token_expire(self):
        """Settings should have ACCESS_TOKEN_EXPIRE_MINUTES."""
        assert "ACCESS_TOKEN_EXPIRE_MINUTES" in Settings.model_fields

    def test_settings_has_refresh_token_expire(self):
        """Settings should have REFRESH_TOKEN_EXPIRE_DAYS."""
        assert "REFRESH_TOKEN_EXPIRE_DAYS" in Settings.model_fields

    def test_default_algorithm_is_hs256(self):
        """Default JWT algorithm should be HS256."""
        s = Settings(
            ENVIRONMENT="testing",
            SECRET_KEY="test-key-at-least-32-characters-long!",
            DATABASE_URL="sqlite:///:memory:",
        )
        assert s.ALGORITHM == "HS256"

    def test_default_access_token_expire_is_15_minutes(self):
        """Default access token expiration should be 15 minutes."""
        s = Settings(
            ENVIRONMENT="testing",
            SECRET_KEY="test-key-at-least-32-characters-long!",
            DATABASE_URL="sqlite:///:memory:",
        )
        assert s.ACCESS_TOKEN_EXPIRE_MINUTES == 15

    def test_default_refresh_token_expire_is_7_days(self):
        """Default refresh token expiration should be 7 days."""
        s = Settings(
            ENVIRONMENT="testing",
            SECRET_KEY="test-key-at-least-32-characters-long!",
            DATABASE_URL="sqlite:///:memory:",
        )
        assert s.REFRESH_TOKEN_EXPIRE_DAYS == 7

    def test_production_requires_secret_key(self):
        """In production, an empty SECRET_KEY should raise ValueError."""
        with pytest.raises(Exception):
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY="",
                DATABASE_URL="postgresql://localhost/db",
            )

    def test_production_requires_long_secret_key(self):
        """In production, SECRET_KEY shorter than 32 chars should raise ValueError."""
        with pytest.raises(Exception):
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY="short",
                DATABASE_URL="postgresql://localhost/db",
            )

    def test_production_accepts_long_secret_key(self):
        """In production, a 32+ char SECRET_KEY should be accepted."""
        s = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="a" * 32,
            DATABASE_URL="postgresql://localhost/db",
        )
        assert len(s.SECRET_KEY) >= 32

    def test_development_auto_generates_secret_key(self):
        """In development, empty SECRET_KEY should be auto-generated."""
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            s = Settings(
                ENVIRONMENT="development",
                SECRET_KEY="",
                DATABASE_URL="sqlite:///:memory:",
            )
        assert len(s.SECRET_KEY) > 0

    def test_settings_has_issuer(self):
        """Settings should have an ISSUER field for JWT tokens."""
        assert "ISSUER" in Settings.model_fields

    def test_settings_has_audience(self):
        """Settings should have an AUDIENCE field for JWT tokens."""
        assert "AUDIENCE" in Settings.model_fields


# =============================================
# Database Connection Configuration Tests
# =============================================


class TestDatabaseConfig:
    """Validate database connection configuration via environment."""

    def test_settings_has_database_url(self):
        """Settings should have a DATABASE_URL field."""
        assert "DATABASE_URL" in Settings.model_fields

    def test_settings_has_db_pool_size(self):
        """Settings should have DB_POOL_SIZE."""
        assert "DB_POOL_SIZE" in Settings.model_fields

    def test_settings_has_db_max_overflow(self):
        """Settings should have DB_MAX_OVERFLOW."""
        assert "DB_MAX_OVERFLOW" in Settings.model_fields

    def test_settings_has_db_pool_timeout(self):
        """Settings should have DB_POOL_TIMEOUT."""
        assert "DB_POOL_TIMEOUT" in Settings.model_fields

    def test_settings_has_db_pool_recycle(self):
        """Settings should have DB_POOL_RECYCLE."""
        assert "DB_POOL_RECYCLE" in Settings.model_fields

    def test_default_pool_size_is_5(self):
        """Default DB pool size should be 5."""
        s = Settings(
            ENVIRONMENT="testing",
            SECRET_KEY="test-key-at-least-32-characters-long!",
            DATABASE_URL="sqlite:///:memory:",
        )
        assert s.DB_POOL_SIZE == 5

    def test_default_max_overflow_is_10(self):
        """Default DB max overflow should be 10."""
        s = Settings(
            ENVIRONMENT="testing",
            SECRET_KEY="test-key-at-least-32-characters-long!",
            DATABASE_URL="sqlite:///:memory:",
        )
        assert s.DB_MAX_OVERFLOW == 10

    def test_database_url_overridable_via_env(self):
        """DATABASE_URL should be overridable via environment variable."""
        custom_url = "postgresql://user:pass@dbhost:5432/mydb"
        s = Settings(
            ENVIRONMENT="testing",
            SECRET_KEY="test-key-at-least-32-characters-long!",
            DATABASE_URL=custom_url,
        )
        assert s.DATABASE_URL == custom_url

    def test_settings_loads_from_env_file(self):
        """Settings should be configured to load from .env file."""
        config = Settings.model_config
        assert config.get("env_file") == ".env"

    def test_settings_case_sensitive(self):
        """Settings should use case-sensitive env var matching."""
        config = Settings.model_config
        assert config.get("case_sensitive") is True

    def test_settings_ignores_extra_env_vars(self):
        """Settings should ignore extra/unknown environment variables."""
        config = Settings.model_config
        assert config.get("extra") == "ignore"


# =============================================
# Environment Validation Tests
# =============================================


class TestEnvironmentValidation:
    """Validate environment value constraints."""

    def test_valid_environments(self):
        """development, staging, production, testing should all be accepted."""
        for env in ("development", "staging", "production", "testing"):
            s = Settings(
                ENVIRONMENT=env,
                SECRET_KEY="a" * 32,
                DATABASE_URL="sqlite:///:memory:",
            )
            assert s.ENVIRONMENT == env

    def test_invalid_environment_raises(self):
        """An invalid ENVIRONMENT value should raise ValueError."""
        with pytest.raises(Exception):
            Settings(
                ENVIRONMENT="invalid_env",
                SECRET_KEY="a" * 32,
                DATABASE_URL="sqlite:///:memory:",
            )

    def test_environment_normalized_to_lowercase(self):
        """ENVIRONMENT should be normalized to lowercase."""
        s = Settings(
            ENVIRONMENT="Testing",
            SECRET_KEY="test-key-at-least-32-characters-long!",
            DATABASE_URL="sqlite:///:memory:",
        )
        assert s.ENVIRONMENT == "testing"


# =============================================
# docker-compose.yml Tests
# =============================================


class TestDockerCompose:
    """Validate docker-compose.yml service definitions."""

    @pytest.fixture(autouse=True)
    def load_compose(self):
        """Load docker-compose.yml content."""
        compose_path = PROJECT_ROOT / "docker-compose.yml"
        assert compose_path.exists(), "docker-compose.yml must exist"
        self.content = compose_path.read_text(encoding="utf-8")

    def test_docker_compose_exists(self):
        """docker-compose.yml should exist at project root."""
        assert (PROJECT_ROOT / "docker-compose.yml").exists()

    def test_defines_database_service(self):
        """docker-compose should define a PostgreSQL database service."""
        assert "postgres" in self.content.lower()

    def test_defines_backend_service(self):
        """docker-compose should define a backend service."""
        assert "backend" in self.content

    def test_backend_depends_on_db(self):
        """Backend service should depend on the database service."""
        assert "depends_on" in self.content

    def test_database_uses_volume(self):
        """Database should use a persistent volume."""
        assert "volumes" in self.content
        assert "postgres_data" in self.content

    def test_database_has_healthcheck(self):
        """Database service should have a healthcheck."""
        assert "healthcheck" in self.content
        assert "pg_isready" in self.content

    def test_backend_uses_env_file(self):
        """Backend service should load from .env file."""
        assert "env_file" in self.content

    def test_backend_exposes_port_8000(self):
        """Backend service should expose port 8000."""
        assert "8000" in self.content

    def test_database_port_mapping(self):
        """Database should map a host port to container port 5432."""
        assert "5432" in self.content

    def test_database_url_override_in_compose(self):
        """docker-compose should override DATABASE_URL for container networking."""
        assert "DATABASE_URL" in self.content
