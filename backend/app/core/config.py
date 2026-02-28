"""
Application Configuration Module
================================

Centralized configuration management using Pydantic Settings.

Security Features:
- Environment variable validation
- No hardcoded secrets (production-safe)
- CORS configuration
- Rate limiting settings
- Token security settings

IMPORTANT:
- SECRET_KEY MUST be set via environment variable in production
- Never commit .env files with real secrets
"""

import os
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized application configuration with security-first defaults.
    
    All sensitive values must be provided via environment variables.
    Default values are provided only for local development.
    """

    # ==========================
    # Application Settings
    # ==========================
    APP_NAME: str = Field(
        default="CyberGuard",
        description="Application name"
    )
    APP_VERSION: str = Field(
        default="1.0.0",
        description="Application version"
    )
    DEBUG: bool = Field(
        default=False,
        description="Debug mode - disable in production"
    )
    ENVIRONMENT: str = Field(
        default="development",
        description="Environment: development, staging, production"
    )

    # ==========================
    # Database Configuration
    # ==========================
    DATABASE_URL: str = Field(
        default="postgresql://postgres:postgres@localhost:5433/cyberguard_db",
        description="PostgreSQL connection string"
    )
    DB_POOL_SIZE: int = Field(
        default=5,
        description="Database connection pool size"
    )
    DB_MAX_OVERFLOW: int = Field(
        default=10,
        description="Maximum overflow connections"
    )
    DB_POOL_TIMEOUT: int = Field(
        default=30,
        description="Pool timeout in seconds"
    )
    DB_POOL_RECYCLE: int = Field(
        default=1800,
        description="Recycle connections after N seconds"
    )

    # ==========================
    # JWT Security Configuration
    # ==========================
    SECRET_KEY: str = Field(
        default="",  # Empty default - must be set via environment
        description="Secret key used to sign JWT tokens (REQUIRED in production)"
    )
    ALGORITHM: str = Field(
        default="HS256",
        description="JWT signing algorithm"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=15,
        description="Access token expiration time in minutes"
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7,
        description="Refresh token expiration time in days"
    )
    ISSUER: str = Field(
        default="cyberguard-auth",
        description="Token issuer identifier"
    )
    AUDIENCE: str = Field(
        default="cyberguard-api",
        description="Token audience"
    )

    # ==========================
    # Security Settings
    # ==========================
    MAX_LOGIN_ATTEMPTS: int = Field(
        default=5,
        description="Maximum failed login attempts before lockout"
    )
    LOCKOUT_DURATION_MINUTES: int = Field(
        default=30,
        description="Account lockout duration in minutes (0 = permanent)"
    )
    PASSWORD_MIN_LENGTH: int = Field(
        default=8,
        description="Minimum password length"
    )
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(
        default=True,
        description="Require uppercase letters in password"
    )
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(
        default=True,
        description="Require lowercase letters in password"
    )
    PASSWORD_REQUIRE_DIGIT: bool = Field(
        default=True,
        description="Require digits in password"
    )
    PASSWORD_REQUIRE_SPECIAL: bool = Field(
        default=True,
        description="Require special characters in password"
    )

    # ==========================
    # CORS Configuration
    # ==========================
    CORS_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:8080",
        description="Allowed CORS origins (comma-separated)"
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(
        default=True,
        description="Allow credentials in CORS requests"
    )
    CORS_ALLOW_METHODS: str = Field(
        default="GET,POST,PUT,DELETE,PATCH,OPTIONS",
        description="Allowed HTTP methods (comma-separated)"
    )
    CORS_ALLOW_HEADERS: str = Field(
        default="Authorization,Content-Type,Accept,Origin,X-Requested-With",
        description="Allowed headers (comma-separated)"
    )

    # ==========================
    # Rate Limiting
    # ==========================
    RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        description="Enable rate limiting"
    )
    RATE_LIMIT_REQUESTS: int = Field(
        default=100,
        description="Maximum requests per window"
    )
    RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        description="Rate limit window in seconds"
    )
    LOGIN_RATE_LIMIT: int = Field(
        default=5,
        description="Maximum login attempts per minute per IP"
    )

    # ==========================
    # Logging
    # ==========================
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    )
    LOG_FORMAT: str = Field(
        default="json",
        description="Log format: json or text"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from comma-separated string."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def cors_methods_list(self) -> List[str]:
        """Parse CORS methods from comma-separated string."""
        return [method.strip() for method in self.CORS_ALLOW_METHODS.split(",") if method.strip()]

    @property
    def cors_headers_list(self) -> List[str]:
        """Parse CORS headers from comma-separated string."""
        return [header.strip() for header in self.CORS_ALLOW_HEADERS.split(",") if header.strip()]

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        """Validate that SECRET_KEY is set in production."""
        environment = info.data.get("ENVIRONMENT", "development")
        
        # In production, SECRET_KEY must be set and be sufficiently long
        if environment == "production":
            if not v:
                raise ValueError(
                    "SECRET_KEY environment variable is REQUIRED in production. "
                    "Generate a secure key with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )
            if len(v) < 32:
                raise ValueError(
                    "SECRET_KEY must be at least 32 characters in production. "
                    "Generate a secure key with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )
        
        # For development, generate a warning key if not set
        if not v:
            import secrets
            v = secrets.token_urlsafe(32)
            import warnings
            warnings.warn(
                "SECRET_KEY not set. Using auto-generated key for development. "
                "Set SECRET_KEY environment variable for production.",
                UserWarning
            )
        
        return v

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment value."""
        allowed = {"development", "staging", "production", "testing"}
        if v.lower() not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of: {allowed}")
        return v.lower()

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"  # Ignore extra env vars
    )


# Global settings instance
settings = Settings()
