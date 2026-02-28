"""
CyberGuard Pod B - Configuration Module

This module provides centralized configuration management using Pydantic Settings.
All configuration values can be overridden via environment variables.

Environment variables are prefixed with CYBERGUARD_ (e.g., CYBERGUARD_PHISHING_THRESHOLD)
"""

from __future__ import annotations

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized configuration for CyberGuard Pod B.
    
    All settings can be overridden via environment variables with the
    CYBERGUARD_ prefix.
    
    Example:
        export CYBERGUARD_PHISHING_THRESHOLD=60
        export CYBERGUARD_LOG_LEVEL=DEBUG
    """
    
    model_config = SettingsConfigDict(
        env_prefix="CYBERGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # ========================================================================
    # APPLICATION SETTINGS
    # ========================================================================
    
    app_name: str = Field(default="CyberGuard Pod B", description="Application name")
    app_version: str = Field(default="2.0.0", description="Application version")
    debug: bool = Field(default=False, description="Enable debug mode")
    environment: str = Field(default="production", description="Deployment environment")
    
    # ========================================================================
    # SCORING THRESHOLDS
    # ========================================================================
    
    phishing_threshold: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Score threshold for PHISHING verdict"
    )
    suspicious_threshold: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Score threshold for SUSPICIOUS verdict"
    )
    max_total_score: int = Field(
        default=100,
        ge=0,
        le=100,
        description="Maximum total score (cap)"
    )
    
    @model_validator(mode='after')
    def validate_thresholds(self) -> 'Settings':
        """Ensure phishing threshold > suspicious threshold."""
        if self.phishing_threshold <= self.suspicious_threshold:
            raise ValueError(
                f"phishing_threshold ({self.phishing_threshold}) must be "
                f"greater than suspicious_threshold ({self.suspicious_threshold})"
            )
        return self
    
    # ========================================================================
    # PARSER SETTINGS
    # ========================================================================
    
    max_email_size_bytes: int = Field(
        default=25 * 1024 * 1024,  # 25 MB
        ge=1024,  # Minimum 1KB
        le=100 * 1024 * 1024,  # Maximum 100MB
        description="Maximum email size in bytes"
    )
    parse_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Timeout for email parsing in seconds"
    )
    max_links_extract: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum number of links to extract"
    )
    max_attachments_process: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of attachments to process"
    )
    
    # ========================================================================
    # SIGNAL SETTINGS
    # ========================================================================
    
    signal_timeout_seconds: int = Field(
        default=5,
        ge=1,
        le=60,
        description="Timeout for individual signal execution"
    )
    enable_parallel_signals: bool = Field(
        default=True,
        description="Enable parallel signal execution"
    )
    
    # Domain Spoof Signal
    domain_spoof_similarity_threshold: float = Field(
        default=0.80,
        ge=0.0,
        le=1.0,
        description="Similarity threshold for domain spoofing detection"
    )
    domain_spoof_score: int = Field(
        default=30,
        ge=0,
        le=100,
        description="Score for domain spoof detection"
    )
    trusted_brands: List[str] = Field(
        default=[
            "paypal.com",
            "amazon.com",
            "microsoft.com",
            "google.com",
            "apple.com",
            "bankofamerica.com",
            "chase.com",
            "wellsfargo.com",
            "citibank.com",
            "facebook.com",
            "twitter.com",
            "linkedin.com",
            "netflix.com",
            "spotify.com",
            "dropbox.com",
        ],
        description="List of trusted brand domains to protect"
    )
    
    # Urgency Detector Signal
    urgency_base_score: int = Field(
        default=20,
        ge=0,
        le=50,
        description="Base score for urgency language detection"
    )
    urgency_per_keyword_score: int = Field(
        default=5,
        ge=0,
        le=20,
        description="Additional score per matched urgency keyword"
    )
    urgency_max_score: int = Field(
        default=40,
        ge=0,
        le=100,
        description="Maximum score for urgency detection"
    )
    urgency_keywords: List[str] = Field(
        default=[
            "urgent",
            "immediately",
            "act now",
            "final warning",
            "verify now",
            "account suspended",
            "limited time",
            "within 24 hours",
            "expire today",
            "respond immediately",
            "action required",
            "security alert",
            "unusual activity",
            "confirm your identity",
            "update your information",
        ],
        description="Keywords indicating urgency language"
    )
    
    # Link Analyzer Signal
    suspicious_tlds: List[str] = Field(
        default=[
            "xyz",
            "top",
            "click",
            "work",
            "biz",
            "info",
            "gq",
            "tk",
            "ml",
            "ga",
            "cf",
            "ovh",
            "pw",
            "cc",
            "ru",
            "cn",
        ],
        description="Suspicious top-level domains"
    )
    suspicious_tld_base_score: int = Field(
        default=20,
        ge=0,
        le=50,
        description="Base score for suspicious TLD detection"
    )
    suspicious_tld_per_domain_score: int = Field(
        default=5,
        ge=0,
        le=20,
        description="Additional score per suspicious domain"
    )
    suspicious_tld_max_score: int = Field(
        default=35,
        ge=0,
        le=100,
        description="Maximum score for suspicious TLD detection"
    )
    
    # Attachment Risk Signal
    high_risk_extensions: List[str] = Field(
        default=[
            "exe", "scr", "js", "bat", "vbs", "ps1", "jar",
            "cmd", "com", "pif", "application", "gadget",
            "msi", "msp", "cpl", "msc", "hta", "wsf", "wsh",
        ],
        description="High-risk file extensions"
    )
    medium_risk_extensions: List[str] = Field(
        default=[
            "zip", "rar", "7z", "iso", "img", "html", "htm",
            "docm", "xlsm", "pptm", "xlam", "ppam", "doc", "xls",
        ],
        description="Medium-risk file extensions"
    )
    double_extension_score: int = Field(
        default=25,
        ge=0,
        le=50,
        description="Score for double extension detection"
    )
    high_risk_extension_score: int = Field(
        default=30,
        ge=0,
        le=50,
        description="Score for high-risk extension detection"
    )
    medium_risk_extension_score: int = Field(
        default=15,
        ge=0,
        le=30,
        description="Score for medium-risk extension detection"
    )
    attachment_max_score: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Maximum score for attachment risk"
    )
    
    # Reply Mismatch Signal
    reply_mismatch_score: int = Field(
        default=25,
        ge=0,
        le=50,
        description="Score for reply-to mismatch detection"
    )
    
    # ========================================================================
    # LOGGING SETTINGS
    # ========================================================================
    
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )
    log_format: str = Field(
        default="json",
        description="Log format (json or text)"
    )
    log_include_timestamp: bool = Field(
        default=True,
        description="Include timestamp in logs"
    )
    
    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v_upper
    
    # ========================================================================
    # RATE LIMITING
    # ========================================================================
    
    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting"
    )
    rate_limit_requests_per_minute: int = Field(
        default=60,
        ge=1,
        le=10000,
        description="Maximum requests per minute per tenant"
    )
    rate_limit_burst: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Burst limit for rate limiting"
    )
    
    # ========================================================================
    # SECURITY SETTINGS
    # ========================================================================
    
    validate_tenant_id: bool = Field(
        default=True,
        description="Validate tenant ID format"
    )
    allowed_tenant_ids: Optional[List[str]] = Field(
        default=None,
        description="List of allowed tenant IDs (None = all allowed)"
    )
    sanitize_html: bool = Field(
        default=True,
        description="Sanitize HTML content to prevent XSS"
    )
    
    # ========================================================================
    # PERFORMANCE SETTINGS
    # ========================================================================
    
    enable_caching: bool = Field(
        default=True,
        description="Enable result caching"
    )
    cache_ttl_seconds: int = Field(
        default=3600,  # 1 hour
        ge=60,
        le=86400,  # Max 24 hours
        description="Cache time-to-live in seconds"
    )
    cache_max_size: int = Field(
        default=10000,
        ge=100,
        le=1000000,
        description="Maximum number of cached results"
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Uses lru_cache to ensure settings are only loaded once.
    
    Returns:
        Settings: The application settings instance.
    """
    return Settings()


# Convenience export
settings = get_settings()