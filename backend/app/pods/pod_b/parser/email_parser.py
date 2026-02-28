"""
CyberGuard Pod B - Email Parser Module

This module pr66ovides secure, production-ready email parsing with:
- Input validation and size limits
- Timeout protection
- Type-safe output using Pydantic models
- Comprehensive error handling
- Structured logging
- Security-focused extraction

The parser converts raw RFC 5322 email content into a structured
ParsedEmail model for downstream signal analysis.
"""

from __future__ import annotations

import hashlib
import re
import signal
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from email import message_from_string
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any, Dict, Generator, List, Optional, Tuple

from bs4 import BeautifulSoup


from app.pods.pod_b.parser.ocsf_normalizer import OCSFNormalizer
from app.core.config import get_settings
from app.core.logging import get_logger, SignalLogger
from app.models.models import (
    Attachment,
    LinkInfo,
    ParsedEmail,
    ParseError,
)


log = get_logger(__name__)


# =============================================================================
# EXCEPTIONS
# =============================================================================


class ParseTimeoutError(Exception):
    """Raised when email parsing exceeds the timeout limit."""
    pass


class EmailTooLargeError(Exception):
    """Raised when email exceeds the maximum size limit."""
    pass


class InvalidEmailFormatError(Exception):
    """Raised when email format is invalid or malformed."""
    pass


class InvalidTenantError(Exception):
    """Raised when tenant ID is invalid."""
    pass


# =============================================================================
# TIMEOUT HANDLING
# =============================================================================


class TimeoutContext:
    """
    Context manager for enforcing timeout on parsing operations.
    
    Uses SIGALRM on Unix systems. For Windows compatibility,
    consider using multiprocessing with timeout.
    """
    
    def __init__(self, seconds: int, error_message: str = "Operation timed out"):
        self.seconds = seconds
        self.error_message = error_message
    
    def __enter__(self) -> "TimeoutContext":
        # Note: signal.alarm() is Unix-only. For production Windows support,
        # use multiprocessing or threading with timeout.
        try:
            signal.signal(signal.SIGALRM, self._timeout_handler)
            signal.alarm(self.seconds)
        except (AttributeError, ValueError):
            # Windows or non-main thread - skip alarm
            log.debug("timeout_alarm_not_available", platform="windows_or_thread")
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            signal.alarm(0)  # Cancel alarm
        except (AttributeError, ValueError):
            pass
    
    def _timeout_handler(self, signum: int, frame: Any) -> None:
        raise ParseTimeoutError(self.error_message)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def generate_email_hash(
    sender: str,
    subject: str,
    date_str: str,
    body_preview: str = ""
) -> str:
    """
    Generate a SHA256 hash for email deduplication.
    
    Args:
        sender: Sender email address
        subject: Email subject line
        date_str: ISO formatted date string
        body_preview: First 100 chars of body for additional uniqueness
    
    Returns:
        SHA256 hash as hex string
    """
    # Normalize inputs
    sender = (sender or "").lower().strip()
    subject = (subject or "").strip()
    date_str = (date_str or "").strip()
    body_preview = (body_preview or "")[:100].strip()
    body_preview = (body_preview or "")[:100]
    body_preview = re.sub(r"\s+", " ", body_preview).strip()
    body_preview = re.sub(r"\s+", " ", body_preview)
    base = f"{sender}|{subject}|{date_str}|{body_preview}"
    return hashlib.sha256(base.encode("utf-8", errors="replace")).hexdigest()


def extract_ip_origin(received_headers: List[str]) -> Optional[str]:
    """
    Extract the originating IP address from Received headers.
    
    Uses a conservative regex to match IPv4 addresses from the
    first hop in the received chain.
    
    Args:
        received_headers: List of Received header values
    
    Returns:
        Originating IP address or None if not found
    """
    # More specific pattern to avoid matching internal IPs
    # Matches IP from "from x.x.x.x" pattern
    ip_pattern = r"from\s+\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?"
    
    for header in received_headers:
        match = re.search(ip_pattern, header, re.IGNORECASE)
        if match:
            ip = match.group(1)
            # Validate IP octets
            try:
                octets = [int(x) for x in ip.split(".")]
                if all(0 <= o <= 255 for o in octets):
                    return ip
            except ValueError:
                continue
    
    return None


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain by removing subdomains.
    
    Args:
        domain: Full domain (e.g., mail.paypal.com)
    
    Returns:
        Root domain (e.g., paypal.com)
    
    Examples:
        >>> normalize_domain("mail.paypal.com")
        'paypal.com'
        >>> normalize_domain("paypal.com")
        'paypal.com'
        >>> normalize_domain("")
        ''
    """
    if not domain:
        return ""
    
    domain = domain.lower().strip()
    parts = domain.split(".")
    
    # Handle co.uk, co.jp, etc.
    if len(parts) >= 2 and parts[-2] in ("co", "com", "org", "net", "gov", "edu"):
        if len(parts) >= 3:
            return ".".join(parts[-3:])
    
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    
    return domain


def extract_tld(domain: str) -> str:
    """
    Extract the top-level domain from a domain.
    
    Args:
        domain: Full domain
    
    Returns:
        TLD (e.g., "com", "xyz")
    """
    if not domain:
        return ""
    
    parts = domain.lower().split(".")
    return parts[-1] if len(parts) > 1 else ""


def sanitize_html(html_content: str) -> str:
    """
    Sanitize HTML content to prevent XSS and extract safe text.
    
    Args:
        html_content: Raw HTML content
    
    Returns:
        Sanitized plain text
    """
    if not html_content:
        return ""
    
    try:
        # Use BeautifulSoup with html.parser for security
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Remove script and style elements
        for element in soup.find_all(["script", "style", "iframe", "object", "embed"]):
            element.decompose()
        
        # Get text with proper spacing
        text = soup.get_text(separator=" ", strip=True)
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()
    except Exception as e:
        log.warning("html_sanitization_failed", error=str(e))
        # Return empty string on failure - safer than returning raw HTML
        return ""


def extract_links_from_html(html_content: str, max_links: int = 1000) -> List[str]:
    """
    Extract links from HTML content.
    
    Args:
        html_content: Raw HTML content
        max_links: Maximum number of links to extract
    
    Returns:
        List of unique URLs
    """
    if not html_content:
        return []
    
    links = []
    
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                links.append(href)
                if len(links) >= max_links:
                    break
    except Exception as e:
        log.warning("link_extraction_failed", error=str(e))
    
    return links


def extract_links_from_text(text: str, max_links: int = 1000) -> List[str]:
    """
    Extract URLs from plain text content.
    
    Args:
        text: Plain text content
        max_links: Maximum number of links to extract
    
    Returns:
        List of URLs
    """
    if not text:
        return []
    
    # URL pattern that matches http/https URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    
    links = re.findall(url_pattern, text)
    
    # Clean up URLs (remove trailing punctuation)
    cleaned = []
    for link in links[:max_links]:
        link = link.rstrip(".,;:!?)")
        cleaned.append(link)
    
    return cleaned


def normalize_links(links: List[str]) -> List[str]:
    """
    Normalize and deduplicate a list of links.
    
    Args:
        links: List of raw URLs
    
    Returns:
        Deduplicated, normalized list of URLs
    """
    if not links:
        return []
    
    cleaned = []
    for link in links:
        link = link.strip().rstrip(".,;:!?)")
        if link:
            cleaned.append(link)
    
    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for link in cleaned:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    
    return unique


def parse_link_info(url: str) -> LinkInfo:
    """
    Parse a URL into a LinkInfo model.
    
    Args:
        url: The URL to parse
    
    Returns:
        LinkInfo model with extracted information
    """
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        
        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]
        
        tld = extract_tld(domain)
        
        return LinkInfo(
            url=url,
            domain=domain,
            tld=tld,
            is_https=parsed.scheme == "https",
            is_suspicious=False,  # Will be set by signal analysis
        )
    except Exception:
        return LinkInfo(url=url)


# =============================================================================
# MAIN PARSER CLASS
# =============================================================================


class EmailParser:
    """
    Production-ready email parser with security hardening.
    
    This class provides a safe, validated interface for parsing
    raw email content into structured ParsedEmail models.
    
    Features:
        - Size limit enforcement
        - Timeout protection
        - Input validation
        - Tenant validation
        - Structured error handling
        - Comprehensive logging
    
    Example:
        >>> parser = EmailParser()
        >>> result = parser.parse(raw_email, tenant_id="tenant-123")
        >>> if result.success:
        ...     print(result.email.sender_email)
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the email parser.
        
        Args:
            settings: Optional settings override. Uses global settings if None.
        """
        self.settings = settings or get_settings()
        self.log = get_logger(__name__)
    
    def parse(
        self,
        raw_email: str,
        tenant_id: str
    ) -> Tuple[Optional[ParsedEmail], Optional[ParseError]]:
        """
        Parse a raw email into a structured ParsedEmail model.
        
        Args:
            raw_email: Raw RFC 5322 email content
            tenant_id: Tenant identifier for multi-tenancy
        
        Returns:
            Tuple of (ParsedEmail or None, ParseError or None)
        
        Raises:
            EmailTooLargeError: If email exceeds size limit
            InvalidTenantError: If tenant ID is invalid
            ParseTimeoutError: If parsing exceeds timeout
        """
        start_time = time.perf_counter()
        email_id = str(uuid.uuid4())
        
        # Pre-validation
        validation_error = self._validate_input(raw_email, tenant_id)
        if validation_error:
            return None, validation_error
        
        try:
            with TimeoutContext(
                self.settings.parse_timeout_seconds,
                f"Email parsing timed out after {self.settings.parse_timeout_seconds}s"
            ):
                parsed_email = self._parse_email_internal(raw_email, tenant_id, email_id)
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            self.log.info(
                "email_parsed_successfully",
                email_id=email_id,
                tenant_id=tenant_id,
                duration_ms=round(duration_ms, 2),
                sender=parsed_email.sender_email,
                has_attachments=parsed_email.has_attachments,
                link_count=parsed_email.link_count
            )
            
            return parsed_email, None
            
        except ParseTimeoutError as e:
            self.log.error(
                "email_parse_timeout",
                email_id=email_id,
                tenant_id=tenant_id,
                error=str(e)
            )
            return None, ParseError(
                error_code="PARSE_TIMEOUT",
                error_message=str(e),
                is_recoverable=False
            )
            
        except Exception as e:
            self.log.error(
                "email_parse_failed",
                email_id=email_id,
                tenant_id=tenant_id,
                error=str(e),
                error_type=type(e).__name__
            )
            return None, ParseError(
                error_code="PARSE_ERROR",
                error_message=f"Failed to parse email: {str(e)}",
                is_recoverable=True,
                raw_error=str(e)
            )
    
    def _validate_input(
        self,
        raw_email: str,
        tenant_id: str
    ) -> Optional[ParseError]:
        """Validate input before parsing."""
        
        # Check email size
        email_size = len(raw_email.encode("utf-8", errors="replace"))
        if email_size > self.settings.max_email_size_bytes:
            return ParseError(
                error_code="EMAIL_TOO_LARGE",
                error_message=(
                    f"Email size ({email_size} bytes) exceeds maximum "
                    f"({self.settings.max_email_size_bytes} bytes)"
                ),
                is_recoverable=False
            )
        
        # Check tenant ID
        if not tenant_id:
            return ParseError(
                error_code="INVALID_TENANT",
                error_message="Tenant ID is required",
                is_recoverable=False
            )
        
        if self.settings.validate_tenant_id:
            if not re.match(r"^[a-zA-Z0-9_-]+$", tenant_id):
                return ParseError(
                    error_code="INVALID_TENANT",
                    error_message="Tenant ID contains invalid characters",
                    is_recoverable=False
                )
            
            if self.settings.allowed_tenant_ids:
                if tenant_id not in self.settings.allowed_tenant_ids:
                    return ParseError(
                        error_code="TENANT_NOT_ALLOWED",
                        error_message=f"Tenant '{tenant_id}' is not allowed",
                        is_recoverable=False
                    )
        
        # Check for empty email
        if not raw_email or not raw_email.strip():
            return ParseError(
                error_code="EMPTY_EMAIL",
                error_message="Email content is empty",
                is_recoverable=False
            )
        
        return None
    
    def _parse_email_internal(
        self,
        raw_email: str,
        tenant_id: str,
        email_id: str
    ) -> ParsedEmail:
        """Internal parsing logic."""
        
        msg = message_from_string(raw_email)
        
        # Extract headers
        sender_email, sender_domain, sender_display_name = self._extract_sender_info(msg)
        reply_to = self._extract_reply_to(msg)
        return_path = msg.get("Return-Path", "")
        if return_path:
            return_path = parseaddr(return_path)[1].lower()
        
        subject = msg.get("Subject", "").strip()
        
        # Extract date
        received_at = self._extract_date(msg)
        
        # Extract body and attachments
        body_text, body_html, attachments = self._extract_body_and_attachments(msg)
        
        # Extract links
        links = self._extract_links(body_html, body_text)
        
        # Extract origin IP
        received_headers = tuple(msg.get_all("Received", []))        
        ip_origin = extract_ip_origin(received_headers)
        
        # Generate hash
        email_hash = generate_email_hash(
            sender_email,
            subject,
            received_at.isoformat(),
            body_text[:100]
        )
        
        return ParsedEmail(
            email_id=email_id,
            tenant_id=tenant_id,
            email_hash=email_hash,
            sender_email=sender_email,
            sender_domain=sender_domain,
            sender_display_name=sender_display_name,
            reply_to=reply_to,
            return_path=return_path if return_path else None,
            subject=subject,
            body_text=body_text,
            body_html=body_html if body_html else None,
            links=links,
            attachments=attachments,
            received_at=received_at,
            ip_origin=ip_origin,
            received_headers=received_headers,
        )
    
    def _extract_sender_info(
        self,
        msg: Message
    ) -> Tuple[str, str, str]:
        """Extract sender email, domain, and display name."""
        sender_raw = msg.get("From", "")
        sender_display_name, sender_email = parseaddr(sender_raw)
        
        sender_email = sender_email.lower().strip()
        sender_display_name = sender_display_name.strip()
        
        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].lower()
        else:
            sender_domain = ""
        
        return sender_email, sender_domain, sender_display_name
    
    def _extract_reply_to(self, msg: Message) -> Optional[str]:
        """Extract Reply-To header."""
        reply_to_raw = msg.get("Reply-To", "")
        if reply_to_raw:
            return parseaddr(reply_to_raw)[1].lower()
        return None
    
    def _extract_date(self, msg: Message) -> datetime:
        date_header = msg.get("Date")

        if not date_header:
            raise InvalidEmailFormatError("Missing Date header")

        try:
            parsed_date = parsedate_to_datetime(date_header)
            return parsed_date.astimezone(timezone.utc)
        except Exception:
            raise InvalidEmailFormatError("Invalid Date header format")
    
    def _extract_body_and_attachments(
        self,
        msg: Message
    ) -> Tuple[str, str, List[Attachment]]:
        """Extract body content and attachments."""
        body_text = ""
        body_html = ""
        attachments = []
        
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "")
            
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                
                decoded = payload.decode(errors="ignore")
                
                if content_type == "text/plain" and "attachment" not in content_disposition.lower():
                    body_text += decoded
                
                elif content_type == "text/html" and "attachment" not in content_disposition.lower():
                    body_html += decoded
                
            except Exception as e:
                self.log.warning(
                    "payload_decode_failed",
                    content_type=content_type,
                    error=str(e)
                )
            
            # Extract attachments
            if "attachment" in content_disposition.lower():
                filename = part.get_filename()
                if filename:
                    attachments.append(Attachment(
                        filename=filename,
                        content_type=content_type,
                    ))
                    
                    if len(attachments) >= self.settings.max_attachments_process:
                        break
        
        # Generate text from HTML if no plain text
        if not body_text and body_html:
            body_text = sanitize_html(body_html)
        
        return body_text.strip(), body_html.strip(), attachments
    
    def _extract_links(
        self,
        body_html: str,
        body_text: str
    ) -> List[LinkInfo]:
        """Extract and parse links from body content."""
        all_links = []
        
        # Extract from HTML
        html_links = extract_links_from_html(
            body_html,
            self.settings.max_links_extract
        )
        all_links.extend(html_links)
        
        # Extract from text
        text_links = extract_links_from_text(
            body_text,
            self.settings.max_links_extract - len(all_links)
        )
        all_links.extend(text_links)
        
        # Normalize and deduplicate
        unique_links = normalize_links(all_links)
        
        # Convert to LinkInfo models
        unique_links = normalize_links(all_links)

        # 🔒 Enforce deterministic ordering
        unique_links = sorted(unique_links)

        return [
            parse_link_info(url)
            for url in unique_links[:self.settings.max_links_extract]
]


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def parse_email(
    raw_input: Any,
    tenant_id: str,
    settings: Optional[Any] = None
) -> Tuple[Optional[ParsedEmail], Optional[ParseError]]:

    parser = EmailParser(settings)

    if isinstance(raw_input, dict):
        normalizer = OCSFNormalizer()
        normalized = normalizer.normalize(raw_input)

        if normalized.get("raw_email"):
            return parser.parse(normalized["raw_email"], tenant_id)

        try:
            event_time = normalized.get("event_time")
            if not event_time:
                raise ValueError("Missing event_time")

            email_hash = generate_email_hash(
                normalized.get("email_sender", ""),
                normalized.get("email_subject", ""),
                event_time.isoformat(),
                ""
            )

            parsed = ParsedEmail(
                email_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                email_hash=email_hash,
                sender_email=normalized.get("email_sender", ""),
                sender_domain=(
                    normalized.get("email_sender", "").split("@")[-1]
                    if "@" in normalized.get("email_sender", "")
                    else ""
                ),
                sender_display_name="",
                reply_to=None,
                return_path=None,
                subject=normalized.get("email_subject", ""),
                body_text="",
                body_html=None,
                links=[],
                attachments=[],
                received_at=event_time,
                ip_origin=normalized.get("src_ip"),
                received_headers=(),
            )

            return parsed, None

        except Exception as e:
            return None, ParseError(
                error_code="OCSF_NORMALIZATION_ERROR",
                error_message=str(e),
                is_recoverable=False
            )

    return parser.parse(raw_input, tenant_id)
    """
    Convenience function to parse an email.
    
    This is a wrapper around EmailParser.parse() for backward compatibility.
    
    Args:
        raw_email: Raw RFC 5322 email content
        tenant_id: Tenant identifier
        settings: Optional settings override
    
    Returns:
        Tuple of (ParsedEmail or None, ParseError or None)
    
    Example:
        >>> email, error = parse_email(raw_email, "tenant-123")
        >>> if error:
        ...     print(f"Error: {error.error_message}")
        >>> else:
        ...     print(f"Sender: {email.sender_email}")
    """
    parser = EmailParser(settings)
    return parser.parse(raw_email, tenant_id)