"""
CyberGuard Pod B - Base Data Models

This module defines the core Pydantic models for type-safe data flow
throughout the phishing detection pipeline.

All models use Pydantic v2 for validation and serialization.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    """
    Severity levels for signal detection results.
    
    Attributes:
        LOW: No significant risk detected
        MEDIUM: Potential risk, requires attention
        HIGH: Significant risk detected
        CRITICAL: Critical threat, immediate action required
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    """
    Final verdict for an email scan.
    
    Attributes:
        SAFE: Email passed all checks, no phishing indicators
        SUSPICIOUS: Some indicators present, requires review
        PHISHING: High confidence phishing attempt
        ERROR: Processing error occurred
    """
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    ERROR = "ERROR"


class SignalMetadata(BaseModel):
    """
    Additional metadata for signal results.
    
    Provides context and evidence for the signal detection.
    """
    matched_patterns: List[str] = Field(default_factory=list)
    matched_domains: List[str] = Field(default_factory=list)
    matched_keywords: List[str] = Field(default_factory=list)
    suspicious_links: List[str] = Field(default_factory=list)
    suspicious_attachments: List[str] = Field(default_factory=list)
    raw_evidence: Dict[str, Any] = Field(default_factory=dict)


class SignalResult(BaseModel):
    """
    Standard result structure for all signal modules.
    
    Every signal module must return a SignalResult instance.
    This ensures consistent interface across all detectors.
    
    Attributes:
        signal: Unique identifier for the signal type
        score: Risk score (0-100, normalized)
        severity: Severity level of the detection
        reason: Human-readable explanation
        metadata: Additional context and evidence
        confidence: Confidence level of the detection (0.0-1.0)
        execution_time_ms: Time taken to execute the signal
    """
    signal: str = Field(..., min_length=1, max_length=50)
    score: int = Field(default=0, ge=0, le=100)
    severity: Severity = Field(default=Severity.LOW)
    reason: str = Field(default="No issues detected")
    metadata: SignalMetadata = Field(default_factory=SignalMetadata)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    execution_time_ms: Optional[float] = Field(default=None, ge=0.0)
    
    @field_validator('signal')
    @classmethod
    def validate_signal_name(cls, v: str) -> str:
        """Ensure signal name follows naming convention."""
        if not re.match(r'^[A-Z][A-Z0-9_]*$', v):
            raise ValueError(f"Signal name must be UPPER_SNAKE_CASE: {v}")
        return v


class Attachment(BaseModel):
    """
    Email attachment metadata.
    
    Attributes:
        filename: Original filename of the attachment
        content_type: MIME type of the attachment
        size_bytes: Size of the attachment in bytes
        extension: File extension (extracted from filename)
        hash_sha256: SHA256 hash of the file content (if available)
    """
    filename: str = Field(..., min_length=1, max_length=255)
    content_type: Optional[str] = Field(default=None)
    size_bytes: Optional[int] = Field(default=None, ge=0)
    extension: str = Field(default="")
    hash_sha256: Optional[str] = Field(default=None, min_length=64, max_length=64)
    
    @field_validator('extension', mode='before')
    @classmethod
    def extract_extension(cls, v: str, info) -> str:
        """Extract extension from filename if not provided."""
        filename = info.data.get('filename', '')
        if filename and '.' in filename:
            parts = filename.rsplit('.', 1)
            if len(parts) == 2:
                return parts[1].lower()
        return ""
    
    @field_validator('filename')
    @classmethod
    def sanitize_filename(cls, v: str) -> str:
        """Sanitize filename to prevent path traversal."""
        # Remove any path separators
        v = v.replace('/', '_').replace('\\', '_')
        # Remove null bytes
        v = v.replace('\x00', '')
        return v.strip()


class LinkInfo(BaseModel):
    """
    Extracted link information with security analysis.
    
    Attributes:
        url: The full URL
        domain: Extracted domain
        tld: Top-level domain
        is_https: Whether the link uses HTTPS
        is_suspicious: Whether the link is flagged as suspicious
        redirect_count: Number of redirects (if analyzed)
    """
    url: str = Field(..., min_length=1)
    domain: str = Field(default="")
    tld: str = Field(default="")
    is_https: bool = Field(default=False)
    is_suspicious: bool = Field(default=False)
    redirect_count: Optional[int] = Field(default=None, ge=0)
    
    @field_validator('domain', 'tld', mode='before')
    @classmethod
    def extract_domain_parts(cls, v: str, info) -> str:
        """Domain and TLD are computed from URL."""
        return v  # Will be populated by parser


class ParsedEmail(BaseModel):
    """
    Structured representation of a parsed email.
    
    This is the primary data structure passed to all signal modules.
    It provides type-safe access to all email components.
    
    Attributes:
        email_id: Unique identifier for this email scan
        tenant_id: Identifier for the tenant (multi-tenancy support)
        email_hash: SHA256 hash for deduplication
        sender_email: Sender's email address
        sender_domain: Sender's domain
        sender_display_name: Display name from From header
        reply_to: Reply-To header value
        return_path: Return-Path header value
        subject: Email subject line
        body_text: Plain text body content
        body_html: HTML body content
        links: List of extracted links
        attachments: List of attachments
        received_at: Timestamp when email was received
        ip_origin: Originating IP address from headers
        received_headers: Raw Received headers
        authentication_results: SPF/DKIM/DMARC results
        parse_warnings: Non-fatal parsing issues
    """
    email_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str = Field(..., min_length=1)
    email_hash: str = Field(default="", min_length=64, max_length=64)
    
    sender_email: str = Field(default="")
    sender_domain: str = Field(default="")
    sender_display_name: str = Field(default="")
    reply_to: Optional[str] = Field(default=None)
    return_path: Optional[str] = Field(default=None)
    
    subject: str = Field(default="")
    body_text: str = Field(default="")
    body_html: Optional[str] = Field(default=None)
    
    links: List[LinkInfo] = Field(default_factory=list)
    attachments: List[Attachment] = Field(default_factory=list)
    
    received_at: datetime = Field(default_factory=datetime.utcnow)
    ip_origin: Optional[str] = Field(default=None)
    received_headers: List[str] = Field(default_factory=list)
    
    authentication_results: Dict[str, Any] = Field(default_factory=dict)
    parse_warnings: List[str] = Field(default_factory=list)
    
    @field_validator('sender_email', 'reply_to', 'return_path')
    @classmethod
    def lowercase_email(cls, v: Optional[str]) -> Optional[str]:
        """Normalize email addresses to lowercase."""
        return v.lower() if v else None
    
    @field_validator('sender_domain')
    @classmethod
    def lowercase_domain(cls, v: str) -> str:
        """Normalize domain to lowercase."""
        return v.lower() if v else ""
    
    @property
    def has_attachments(self) -> bool:
        """Check if email has attachments."""
        return len(self.attachments) > 0
    
    @property
    def has_links(self) -> bool:
        """Check if email has links."""
        return len(self.links) > 0
    
    @property
    def link_count(self) -> int:
        """Get number of links."""
        return len(self.links)
    
    @property
    def attachment_count(self) -> int:
        """Get number of attachments."""
        return len(self.attachments)


class ParseError(BaseModel):
    """
    Error information for failed email parsing.
    
    Attributes:
        error_code: Machine-readable error code
        error_message: Human-readable error message
        is_recoverable: Whether the error is recoverable
        raw_error: Original exception details
    """
    error_code: str = Field(..., min_length=1)
    error_message: str = Field(..., min_length=1)
    is_recoverable: bool = Field(default=False)
    raw_error: Optional[str] = Field(default=None)


class ScanResult(BaseModel):
    """
    Complete scan result for an email.
    
    This is the final output of the phishing detection pipeline.
    
    Attributes:
        email_id: Unique identifier for this scan
        tenant_id: Tenant identifier
        email_hash: Hash of the email for deduplication
        verdict: Final verdict (SAFE, SUSPICIOUS, PHISHING, ERROR)
        total_score: Aggregated risk score (0-100)
        confidence: Overall confidence in the verdict
        signals: Individual signal results
        parse_error: Parsing error if any
        scan_duration_ms: Total scan duration
        scanned_at: Timestamp of scan
        version: Scanner version
    """
    email_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    email_hash: str = Field(default="")
    
    verdict: Verdict = Field(default=Verdict.SAFE)
    total_score: int = Field(default=0, ge=0, le=100)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    
    signals: List[SignalResult] = Field(default_factory=list)
    parse_error: Optional[ParseError] = Field(default=None)
    
    scan_duration_ms: Optional[float] = Field(default=None, ge=0.0)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    version: str = Field(default="2.0.0")
    
    @property
    def is_phishing(self) -> bool:
        """Check if verdict is PHISHING."""
        return self.verdict == Verdict.PHISHING
    
    @property
    def is_suspicious(self) -> bool:
        """Check if verdict is SUSPICIOUS."""
        return self.verdict == Verdict.SUSPICIOUS
    
    @property
    def is_safe(self) -> bool:
        """Check if verdict is SAFE."""
        return self.verdict == Verdict.SAFE
    
    @property
    def has_error(self) -> bool:
        """Check if an error occurred."""
        return self.verdict == Verdict.ERROR or self.parse_error is not None
    
    def get_signal_by_name(self, signal_name: str) -> Optional[SignalResult]:
        """Get a specific signal result by name."""
        for signal in self.signals:
            if signal.signal == signal_name:
                return signal
        return None
    
    def get_high_severity_signals(self) -> List[SignalResult]:
        """Get all signals with HIGH or CRITICAL severity."""
        return [
            s for s in self.signals
            if s.severity in (Severity.HIGH, Severity.CRITICAL)
        ]


class EmailScanRequest(BaseModel):
    """
    Request model for email scanning API.
    
    Attributes:
        raw_email: Raw email content (RFC 5322 format)
        tenant_id: Tenant identifier
        options: Scan options
    """
    raw_email: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1, max_length=100)
    options: Dict[str, Any] = Field(default_factory=dict)
    
    @field_validator('tenant_id')
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        """Validate tenant ID format."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("tenant_id must contain only alphanumeric, underscore, or hyphen characters")
        return v


class EmailScanResponse(BaseModel):
    """
    Response model for email scanning API.
    
    Attributes:
        success: Whether the scan was successful
        result: Scan result if successful
        error: Error message if failed
    """
    success: bool = Field(default=True)
    result: Optional[ScanResult] = Field(default=None)
    error: Optional[str] = Field(default=None)