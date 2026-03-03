"""
Application Configuration Module
================================

Unified configuration for:

- Pod A: Core app, DB, Auth, Security
- Pod B: Phishing scoring engine, signals, parser, performance
"""

from typing import List
from functools import lru_cache
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
    # DATABASE SETTINGS
    # ======================================================================

    DATABASE_URL: str = Field(
        default="postgresql://postgres:postgres@localhost:5433/cyberguard_db"
    )
    DB_POOL_SIZE: int = Field(default=5)
    DB_MAX_OVERFLOW: int = Field(default=10)
    DB_POOL_TIMEOUT: int = Field(default=30)
    DB_POOL_RECYCLE: int = Field(default=1800)

    # ======================================================================
    # JWT SECURITY
    # ======================================================================

    SECRET_KEY: str = Field(default="")
    ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)
    ISSUER: str = Field(default="cyberguard-auth")
    AUDIENCE: str = Field(default="cyberguard-api")

    # ======================================================================
    # SECURITY POLICY
    # ======================================================================

    MAX_LOGIN_ATTEMPTS: int = Field(default=5)
    LOCKOUT_DURATION_MINUTES: int = Field(default=30)

    PASSWORD_MIN_LENGTH: int = Field(default=8)
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_DIGIT: bool = Field(default=True)
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True)

    # ======================================================================
    # CORS
    # ======================================================================

    CORS_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:8080"
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True)
    CORS_ALLOW_METHODS: str = Field(default="GET,POST,PUT,DELETE,PATCH,OPTIONS")
    CORS_ALLOW_HEADERS: str = Field(
        default="Authorization,Content-Type,Accept,Origin,X-Requested-With"
    )

    # Uppercase properties (internal)
    @property
    def CORS_ORIGINS_LIST(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def CORS_METHODS_LIST(self) -> List[str]:
        return [m.strip() for m in self.CORS_ALLOW_METHODS.split(",") if m.strip()]

    @property
    def CORS_HEADERS_LIST(self) -> List[str]:
        return [h.strip() for h in self.CORS_ALLOW_HEADERS.split(",") if h.strip()]

    # Lowercase compatibility (required by main.py / FastAPI usage)
    @property
    def cors_origins_list(self) -> List[str]:
        return self.CORS_ORIGINS_LIST

    @property
    def cors_methods_list(self) -> List[str]:
        return self.CORS_METHODS_LIST

    @property
    def cors_headers_list(self) -> List[str]:
        return self.CORS_HEADERS_LIST

    # ======================================================================
    # RATE LIMITING
    # ======================================================================

    RATE_LIMIT_ENABLED: bool = Field(default=True)
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(default=60)
    RATE_LIMIT_BURST: int = Field(default=10)

    # ======================================================================
    # LOGGING
    # ======================================================================

    LOG_LEVEL: str = Field(default="INFO")
    LOG_FORMAT: str = Field(default="json")
    LOG_INCLUDE_TIMESTAMP: bool = Field(default=True)

    # Compatibility for structlog (Pod B logging)
    @property
    def log_level(self) -> str:
        return self.LOG_LEVEL

    @property
    def log_format(self) -> str:
        return self.LOG_FORMAT

    # Compatibility for Pod B settings (lowercase access)
    @property
    def phishing_threshold(self) -> int:
        return self.PHISHING_THRESHOLD

    @property
    def suspicious_threshold(self) -> int:
        return self.SUSPICIOUS_THRESHOLD

    @property
    def max_total_score(self) -> int:
        return self.MAX_TOTAL_SCORE

    @property
    def max_email_size_bytes(self) -> int:
        return self.MAX_EMAIL_SIZE_BYTES

    @property
    def parse_timeout_seconds(self) -> int:
        return self.PARSE_TIMEOUT_SECONDS

    @property
    def max_links_extract(self) -> int:
        return self.MAX_LINKS_EXTRACT

    @property
    def max_attachments_process(self) -> int:
        return self.MAX_ATTACHMENTS_PROCESS

    @property
    def signal_timeout_seconds(self) -> int:
        return self.SIGNAL_TIMEOUT_SECONDS

    @property
    def enable_parallel_signals(self) -> bool:
        return self.ENABLE_PARALLEL_SIGNALS

    @property
    def domain_spoof_similarity_threshold(self) -> float:
        return self.DOMAIN_SPOOF_SIMILARITY_THRESHOLD

    @property
    def domain_spoof_score(self) -> int:
        return self.DOMAIN_SPOOF_SCORE

    @property
    def urgency_base_score(self) -> int:
        return self.URGENCY_BASE_SCORE

    @property
    def urgency_per_keyword_score(self) -> int:
        return self.URGENCY_PER_KEYWORD_SCORE

    @property
    def urgency_max_score(self) -> int:
        return self.URGENCY_MAX_SCORE

    @property
    def suspicious_tld_base_score(self) -> int:
        return self.SUSPICIOUS_TLD_BASE_SCORE

    @property
    def suspicious_tld_per_domain_score(self) -> int:
        return self.SUSPICIOUS_TLD_PER_DOMAIN_SCORE

    @property
    def suspicious_tld_max_score(self) -> int:
        return self.SUSPICIOUS_TLD_MAX_SCORE

    @property
    def double_extension_score(self) -> int:
        return self.DOUBLE_EXTENSION_SCORE

    @property
    def high_risk_extension_score(self) -> int:
        return self.HIGH_RISK_EXTENSION_SCORE

    @property
    def medium_risk_extension_score(self) -> int:
        return self.MEDIUM_RISK_EXTENSION_SCORE

    @property
    def attachment_max_score(self) -> int:
        return self.ATTACHMENT_MAX_SCORE

    @property
    def reply_mismatch_score(self) -> int:
        return self.REPLY_MISMATCH_SCORE

    @property
    def enable_caching(self) -> bool:
        return self.ENABLE_CACHING

    @property
    def cache_ttl_seconds(self) -> int:
        return self.CACHE_TTL_SECONDS

    @property
    def cache_max_size(self) -> int:
        return self.CACHE_MAX_SIZE

    # ======================================================================
    # POD B – ADDITIONAL SETTINGS (missing from config)
    # ======================================================================

    # App version
    APP_VERSION: str = Field(default="2.0.0")

    # Urgency detector
    URGENCY_KEYWORDS: str = Field(
        default="urgent,immediate,asap,critical,emergency,deadline,24 hours,expire"
    )

    # Trusted brands for domain spoofing and reply mismatch
    TRUSTED_BRANDS: str = Field(
        default="google,microsoft,amazon,apple,paypal,facebook,linkedin,dropbox,slack,zoom"
    )

    # Suspicious TLDs
    SUSPICIOUS_TLDS: str = Field(
        default="xyz,top,gq,tk,ml,cf,ga,work,click,link,loan"
    )

    # Attachment risk extensions
    HIGH_RISK_EXTENSIONS: str = Field(
        default="exe,scr,pif,bat,cmd,com,vbs,js,jse,wsf,wsh,ps1,bat,jar"
    )
    MEDIUM_RISK_EXTENSIONS: str = Field(
        default="zip,rar,7z,docm,xlsm,pptm,doc,docx,xls,xlsx,ppt,pptx"
    )

    # Parser settings
    VALIDATE_TENANT_ID: bool = Field(default=True)
    ALLOWED_TENANT_IDS: str = Field(default="")  # Comma-separated list, empty = allow all

    # Lowercase property accessors
    @property
    def app_version(self) -> str:
        return self.APP_VERSION

    @property
    def urgency_keywords(self) -> list[str]:
        return [k.strip() for k in self.URGENCY_KEYWORDS.split(",") if k.strip()]

    @property
    def trusted_brands(self) -> set[str]:
        return {b.strip().lower() for b in self.TRUSTED_BRANDS.split(",") if b.strip()}

    @property
    def suspicious_tlds(self) -> list[str]:
        return [t.strip() for t in self.SUSPICIOUS_TLDS.split(",") if t.strip()]

    @property
    def high_risk_extensions(self) -> list[str]:
        return [e.strip() for e in self.HIGH_RISK_EXTENSIONS.split(",") if e.strip()]

    @property
    def medium_risk_extensions(self) -> list[str]:
        return [e.strip() for e in self.MEDIUM_RISK_EXTENSIONS.split(",") if e.strip()]

    @property
    def validate_tenant_id(self) -> bool:
        return self.VALIDATE_TENANT_ID

    @property
    def allowed_tenant_ids(self) -> list[str]:
        if not self.ALLOWED_TENANT_IDS:
            return []
        return [t.strip() for t in self.ALLOWED_TENANT_IDS.split(",") if t.strip()]

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
    # PERFORMANCE
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


# Cached settings instance (Pod B style)
@lru_cache
def get_settings() -> Settings:
    return Settings()


# Backward compatibility (Pod A style)
settings = get_settings()