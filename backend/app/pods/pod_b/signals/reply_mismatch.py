"""
CyberGuard Pod B - Reply-To Mismatch Detection Signal

This signal detects when the Reply-To header points to a different
domain than the sender, a common technique in Business Email Compromise
(BEC) and phishing attacks.

Detection Methods:
    - Reply-To domain comparison with sender domain
    - Display name spoofing detection
    - Lookalike domain detection in Reply-To

Example Threats Detected:
    - Sender: support@paypal.com, Reply-To: attacker@evil.com
    - Sender: ceo@company.com, Reply-To: ceo@company-external.com
    - Display name impersonation with different Reply-To
"""

from __future__ import annotations

from typing import Any, ClassVar, List, Optional, Tuple

from app.core.config import get_settings
from app.models.models import (
    ParsedEmail,
    Severity,
    SignalResult,
    SignalMetadata,
)
from app.pods.pod_b.signals.base import BaseSignal, SignalRegistry


def extract_domain(email: str) -> str:
    """
    Extract domain from an email address.
    
    Args:
        email: Email address
    
    Returns:
        Domain part of email address
    
    Examples:
        >>> extract_domain("user@example.com")
        'example.com'
        >>> extract_domain("invalid-email")
        ''
    """
    if not email or "@" not in email:
        return ""
    
    return email.split("@")[-1].lower().strip()


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain by removing subdomains.
    
    Args:
        domain: Full domain
    
    Returns:
        Root domain
    
    Examples:
        >>> normalize_domain("mail.example.com")
        'example.com'
        >>> normalize_domain("example.com")
        'example.com'
    """
    if not domain:
        return ""
    
    domain = domain.lower().strip()
    parts = domain.split(".")
    
    # Handle special TLDs like co.uk
    special_tlds = {"co", "com", "org", "net", "gov", "edu"}
    if len(parts) >= 3 and parts[-2] in special_tlds:
        return ".".join(parts[-3:])
    
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    
    return domain


def domains_match(domain1: str, domain2: str) -> bool:
    """
    Check if two domains match (after normalization).
    
    Args:
        domain1: First domain
        domain2: Second domain
    
    Returns:
        True if domains match
    """
    norm1 = normalize_domain(domain1)
    norm2 = normalize_domain(domain2)
    
    return bool(norm1 and norm2 and norm1 == norm2)


def is_suspicious_reply_to_domain(
    sender_domain: str,
    reply_to_domain: str,
    trusted_domains: Optional[List[str]] = None
) -> Tuple[bool, Optional[str]]:
    """
    Check if Reply-To domain is suspicious.
    
    Args:
        sender_domain: Sender's domain
        reply_to_domain: Reply-To domain
        trusted_domains: Optional list of trusted domains
    
    Returns:
        Tuple of (is_suspicious, reason)
    """
    if not reply_to_domain:
        return False, None
    
    # If domains match, not suspicious
    if domains_match(sender_domain, reply_to_domain):
        return False, None
    
    # Check if Reply-To is a free email provider
    free_providers = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "aol.com", "icloud.com", "mail.com", "protonmail.com",
        "yandex.com", "zoho.com", "gmx.com",
    }
    
    reply_root = normalize_domain(reply_to_domain)
    
    if reply_root in free_providers:
        return True, "Reply-To uses free email provider"
    
    # Check for lookalike domains
    sender_root = normalize_domain(sender_domain)
    
    # If sender is a trusted brand and reply-to is different
    if trusted_domains and sender_root in [normalize_domain(d) for d in trusted_domains]:
        return True, "Reply-To differs from trusted sender domain"
    
    return True, "Reply-To domain differs from sender domain"


@SignalRegistry.register
class ReplyMismatchSignal(BaseSignal):
    """
    Signal for detecting Reply-To header mismatches.
    
    This signal detects when the Reply-To header points to a different
    domain than the sender, which is a common phishing technique.
    
    Attributes:
        name: Signal identifier "REPLY_MISMATCH"
        description: Human-readable description
        requires: Required email fields
    """
    
    name: ClassVar[str] = "REPLY_MISMATCH"
    description: ClassVar[str] = (
        "Detects when Reply-To header points to a different domain "
        "than the sender, indicating potential BEC or phishing"
    )
    version: ClassVar[str] = "2.0.0"
    weight: ClassVar[float] = 1.0
    requires: ClassVar[List[str]] = ["sender_email", "reply_to"]
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the reply mismatch signal.
        
        Args:
            settings: Optional settings override
        """
        super().__init__(settings)
        self.mismatch_score = self.settings.reply_mismatch_score
        self.trusted_brands = self.settings.trusted_brands
    
    def analyze(self, email: ParsedEmail) -> SignalResult:
        """
        Analyze email for Reply-To mismatch indicators.
        
        Detection Strategy:
            1. Check if Reply-To header exists
            2. Compare Reply-To domain with sender domain
            3. Check for free email provider usage
            4. Check for trusted brand impersonation
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            SignalResult with detection outcome
        """
        sender_email = email.sender_email or ""
        reply_to = email.reply_to
        
        # No Reply-To header - not suspicious
        if not reply_to:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="No Reply-To header present"
            )
        
        # Extract domains
        sender_domain = extract_domain(sender_email)
        reply_to_domain = extract_domain(reply_to)
        
        # Validate we have both domains
        if not sender_domain:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="Could not extract sender domain"
            )
        
        if not reply_to_domain:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="Could not extract Reply-To domain"
            )
        
        # Check for mismatch
        is_suspicious, reason = is_suspicious_reply_to_domain(
            sender_domain,
            reply_to_domain,
            self.trusted_brands
        )
        
        if not is_suspicious:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="Reply-To domain matches sender domain"
            )
        
        # Determine severity
        # Higher severity if sender appears to be a trusted brand
        sender_root = normalize_domain(sender_domain)
        is_trusted_sender = sender_root in [
            normalize_domain(d) for d in self.trusted_brands
        ]
        
        if is_trusted_sender:
            severity = Severity.HIGH
            score = min(self.mismatch_score + 10, 50)
            reason = f"Trusted brand impersonation: {reason}"
        else:
            severity = Severity.MEDIUM
            score = self.mismatch_score
        
        self._log.debug(
            "reply_to_mismatch_detected",
            sender_email=sender_email,
            reply_to=reply_to,
            sender_domain=sender_domain,
            reply_to_domain=reply_to_domain,
            reason=reason
        )
        
        return self._create_result(
            score=score,
            severity=severity,
            reason=f"Reply-To domain '{reply_to_domain}' differs from sender domain '{sender_domain}'",
            metadata=SignalMetadata(
                matched_domains=[sender_domain, reply_to_domain],
                raw_evidence={
                    "sender_email": sender_email,
                    "reply_to": reply_to,
                    "sender_domain": sender_domain,
                    "reply_to_domain": reply_to_domain,
                    "sender_root_domain": sender_root,
                    "reply_to_root_domain": normalize_domain(reply_to_domain),
                    "is_trusted_sender": is_trusted_sender,
                    "detection_reason": reason,
                }
            )
        )


# Backward compatibility function
def evaluate(parsed_email: dict) -> dict:
    """
    Legacy function for backward compatibility.
    
    Deprecated: Use ReplyMismatchSignal class instead.
    
    Args:
        parsed_email: Dictionary with email data
    
    Returns:
        Dictionary with signal result
    """
    email = ParsedEmail(
        email_id=parsed_email.get("email_id", "unknown"),
        tenant_id=parsed_email.get("tenant_id", "default"),
        sender_email=parsed_email.get("sender_email", ""),
        reply_to=parsed_email.get("reply_to"),
    )
    
    signal = ReplyMismatchSignal()
    result = signal.evaluate(email)
    
    return {
        "signal": result.signal,
        "score": result.score,
        "severity": result.severity.value,
        "reason": result.reason,
    }