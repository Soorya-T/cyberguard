"""
Unified Application Configuration
==================================

Integrates:
- Pod A: Path management + logging config
- Pod B: Core app, DB, Auth, Security, Scoring engine
- Pod C: Environment-safe configuration structure
"""

import logging
import secrets
from pathlib import Path
from typing import List
from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


# =============================================================================
# SETTINGS
# =============================================================================

class Settings(BaseSettings):

    # =========================================================================
    # APPLICATION
    # =========================================================================

    APP_NAME: str = Field(default="CyberGuard")
    APP_VERSION: str = Field(default="2.0.0")
    DEBUG: bool = Field(default=False)
    ENVIRONMENT: str = Field(default="development")

    # =========================================================================
    # DATABASE
    # =========================================================================

    DATABASE_URL: str = Field(
        default="postgresql://postgres:postgres@localhost:5433/cyberguard_db"
    )
    DB_POOL_SIZE: int = Field(default=5)
    DB_MAX_OVERFLOW: int = Field(default=10)
    DB_POOL_TIMEOUT: int = Field(default=30)
    DB_POOL_RECYCLE: int = Field(default=1800)

    # =========================================================================
    # JWT SECURITY
    # =========================================================================

    SECRET_KEY: str = Field(default="")
    ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)
    ISSUER: str = Field(default="cyberguard-auth")
    AUDIENCE: str = Field(default="cyberguard-api")

    # =========================================================================
    # SECURITY POLICY
    # =========================================================================

    MAX_LOGIN_ATTEMPTS: int = Field(default=5)
    LOCKOUT_DURATION_MINUTES: int = Field(default=30)

    PASSWORD_MIN_LENGTH: int = Field(default=8)
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_DIGIT: bool = Field(default=True)
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True)

    # =========================================================================
    # CORS
    # =========================================================================

    CORS_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:8080"
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True)
    CORS_ALLOW_METHODS: str = Field(default="GET,POST,PUT,DELETE,PATCH,OPTIONS")
    CORS_ALLOW_HEADERS: str = Field(
        default="Authorization,Content-Type,Accept,Origin,X-Requested-With"
    )

    # =========================================================================
    # RATE LIMITING
    # =========================================================================

    RATE_LIMIT_ENABLED: bool = Field(default=True)
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(default=60)
    RATE_LIMIT_BURST: int = Field(default=10)

    # =========================================================================
    # LOGGING
    # =========================================================================

    LOG_LEVEL: str = Field(default="INFO")
    LOG_FORMAT: str = Field(default="json")
    LOG_INCLUDE_TIMESTAMP: bool = Field(default=True)

    # =========================================================================
    # POD B – SCORING ENGINE
    # =========================================================================

    PHISHING_THRESHOLD: int = Field(default=50, ge=0, le=100)
    SUSPICIOUS_THRESHOLD: int = Field(default=20, ge=0, le=100)
    MAX_TOTAL_SCORE: int = Field(default=100, ge=0, le=100)

    URGENCY_KEYWORDS: str = Field(
        default="urgent,immediate,asap,critical,emergency,deadline,24 hours,expire"
    )

    TRUSTED_BRANDS: str = Field(
        default="google,microsoft,amazon,apple,paypal,facebook,linkedin,dropbox,slack,zoom"
    )

    SUSPICIOUS_TLDS: str = Field(
        default="xyz,top,gq,tk,ml,cf,ga,work,click,link,loan"
    )

    HIGH_RISK_EXTENSIONS: str = Field(
        default="exe,scr,pif,bat,cmd,com,vbs,js,jse,wsf,wsh,ps1,jar"
    )
    MEDIUM_RISK_EXTENSIONS: str = Field(
        default="zip,rar,7z,docm,xlsm,pptm,doc,docx,xls,xlsx,ppt,pptx"
    )

    # =========================================================================
    # VALIDATORS
    # =========================================================================

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
            v = secrets.token_urlsafe(32)

        return v

    @model_validator(mode="after")
    def validate_thresholds(self):
        if self.PHISHING_THRESHOLD <= self.SUSPICIOUS_THRESHOLD:
            raise ValueError(
                "PHISHING_THRESHOLD must be greater than SUSPICIOUS_THRESHOLD"
            )
        return self

    # =========================================================================
    # LOWERCASE COMPATIBILITY ACCESSORS
    # =========================================================================

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def urgency_keywords(self) -> List[str]:
        return [k.strip() for k in self.URGENCY_KEYWORDS.split(",") if k.strip()]

    @property
    def trusted_brands(self) -> set[str]:
        return {b.strip().lower() for b in self.TRUSTED_BRANDS.split(",") if b.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# =============================================================================
# PATH CONFIG (Pod A Integration)
# =============================================================================

class PathConfig:

    def __init__(self, settings: Settings):
        self._settings = settings
        self._base_dir = Path(__file__).resolve().parent.parent.parent
        self._reports_dir: Path | None = None

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    @property
    def reports_dir(self) -> Path:
        if self._reports_dir is None:
            path = self._base_dir / "reports"
            path.mkdir(parents=True, exist_ok=True)
            self._reports_dir = path
            logger.info(f"Reports directory: {path}")
        return self._reports_dir

    def get_pdf_path(self, filename: str) -> Path:
        return self.reports_dir / filename


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_path_config() -> PathConfig:
    return PathConfig(get_settings())


settings = get_settings()


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def configure_logging() -> None:
    s = get_settings()
    logging.basicConfig(
        level=getattr(logging, s.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger.info(f"Logging configured at {s.LOG_LEVEL}")