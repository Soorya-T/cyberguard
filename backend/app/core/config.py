"""
Application Configuration Module
================================

Unified configuration for:

- Pod A: Core app, DB, Auth, Security
- Pod B: Phishing scoring engine, signals, parser, performance

Security-first defaults.
All sensitive values must come from environment variables in production.
"""

from typing import List, Optional
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    # ======================================================================
    # APPLICATION SETTINGS
    # ======================================================================

    APP_NAME: str = Field(default="CyberGuard")
    APP_VERSION: str = Field(default="2.0.0")
    DEBUG: bool = Field(default=False)
    ENVIRONMENT: str = Field(default="development")

    # ======================================================================
    # DATABASE SETTINGS (Pod A)
    # ======================================================================

    DATABASE_URL: str = Field(
        default="postgresql://postgres:postgres@localhost:5433/cyberguard_db"
    )
    DB_POOL_SIZE: int = Field(default=5)
    DB_MAX_OVERFLOW: int = Field(default=10)
    DB_POOL_TIMEOUT: int = Field(default=30)
    DB_POOL_RECYCLE: int = Field(default=1800)

    # ======================================================================
    # JWT SECURITY (Pod A)
    # ======================================================================

    SECRET_KEY: str = Field(default="")
    ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)
    ISSUER: str = Field(default="cyberguard-auth")
    AUDIENCE: str = Field(default="cyberguard-api")

    # ======================================================================
    # SECURITY POLICY (Pod A)
    # ======================================================================

    MAX_LOGIN_ATTEMPTS: int = Field(default=5)
    LOCKOUT_DURATION_MINUTES: int = Field(default=30)

    PASSWORD_MIN_LENGTH: int = Field(default=8)
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_DIGIT: bool = Field(default=True)
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True)

    # ======================================================================
    # CORS (Pod A)
    # ======================================================================

    CORS_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:8080"
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True)
    CORS_ALLOW_METHODS: str = Field(default="GET,POST,PUT,DELETE,PATCH,OPTIONS")
    CORS_ALLOW_HEADERS: str = Field(
        default="Authorization,Content-Type,Accept,Origin,X-Requested-With"
    )

    @property
    def CORS_ORIGINS_LIST(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def CORS_METHODS_LIST(self) -> List[str]:
        return [m.strip() for m in self.CORS_ALLOW_METHODS.split(",") if m.strip()]

    @property
    def CORS_HEADERS_LIST(self) -> List[str]:
        return [h.strip() for h in self.CORS_ALLOW_HEADERS.split(",") if h.strip()]

    # ======================================================================
    # RATE LIMITING (Unified)
    # ======================================================================

    RATE_LIMIT_ENABLED: bool = Field(default=True)
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(default=60)
    RATE_LIMIT_BURST: int = Field(default=10)

    # ======================================================================
    # LOGGING (Unified)
    # ======================================================================

    LOG_LEVEL: str = Field(default="INFO")
    LOG_FORMAT: str = Field(default="json")
    LOG_INCLUDE_TIMESTAMP: bool = Field(default=True)

    # ======================================================================
    # POD B – SCORING THRESHOLDS
    # ======================================================================

    PHISHING_THRESHOLD: int = Field(default=50, ge=0, le=100)
    SUSPICIOUS_THRESHOLD: int = Field(default=20, ge=0, le=100)
    MAX_TOTAL_SCORE: int = Field(default=100, ge=0, le=100)

    # ======================================================================
    # POD B – PARSER SETTINGS
    # ======================================================================

    MAX_EMAIL_SIZE_BYTES: int = Field(default=25 * 1024 * 1024)
    PARSE_TIMEOUT_SECONDS: int = Field(default=30)
    MAX_LINKS_EXTRACT: int = Field(default=1000)
    MAX_ATTACHMENTS_PROCESS: int = Field(default=50)

    # ======================================================================
    # POD B – SIGNAL SETTINGS
    # ======================================================================

    SIGNAL_TIMEOUT_SECONDS: int = Field(default=5)
    ENABLE_PARALLEL_SIGNALS: bool = Field(default=True)

    DOMAIN_SPOOF_SIMILARITY_THRESHOLD: float = Field(default=0.80)
    DOMAIN_SPOOF_SCORE: int = Field(default=30)

    URGENCY_BASE_SCORE: int = Field(default=20)
    URGENCY_PER_KEYWORD_SCORE: int = Field(default=5)
    URGENCY_MAX_SCORE: int = Field(default=40)

    SUSPICIOUS_TLD_BASE_SCORE: int = Field(default=20)
    SUSPICIOUS_TLD_PER_DOMAIN_SCORE: int = Field(default=5)
    SUSPICIOUS_TLD_MAX_SCORE: int = Field(default=35)

    DOUBLE_EXTENSION_SCORE: int = Field(default=25)
    HIGH_RISK_EXTENSION_SCORE: int = Field(default=30)
    MEDIUM_RISK_EXTENSION_SCORE: int = Field(default=15)
    ATTACHMENT_MAX_SCORE: int = Field(default=50)

    REPLY_MISMATCH_SCORE: int = Field(default=25)

    # ======================================================================
    # PERFORMANCE (Pod B)
    # ======================================================================

    ENABLE_CACHING: bool = Field(default=True)
    CACHE_TTL_SECONDS: int = Field(default=3600)
    CACHE_MAX_SIZE: int = Field(default=10000)

    # ======================================================================
    # VALIDATORS
    # ======================================================================

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production", "testing"}
        if v.lower() not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v.lower()

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        environment = info.data.get("ENVIRONMENT", "development")

        if environment == "production":
            if not v or len(v) < 32:
                raise ValueError(
                    "SECRET_KEY must be set and at least 32 characters in production"
                )

        if not v:
            import secrets
            v = secrets.token_urlsafe(32)

        return v

    @model_validator(mode="after")
    def validate_thresholds(self):
        if self.PHISHING_THRESHOLD <= self.SUSPICIOUS_THRESHOLD:
            raise ValueError(
                "PHISHING_THRESHOLD must be greater than SUSPICIOUS_THRESHOLD"
            )
        return self

    # ======================================================================
    # Pydantic Config
    # ======================================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# Single global instance
settings = Settings()