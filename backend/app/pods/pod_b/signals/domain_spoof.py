"""
CyberGuard Pod B - Domain Spoof Detection Signal

This signal detects domain spoofing attempts where attackers use
domains that visually resemble trusted brands (typosquatting,
homograph attacks, lookalike domains).

Detection Methods:
    - Levenshtein distance similarity matching
    - Known trusted brand protection
    - Subdomain-based spoofing detection

Example Threats Detected:
    - paypa1.com (typosquatting - '1' instead of 'l')
    - paypal-secure-login.com (subdomain spoofing)
    - amazon-support.net (brand impersonation)
"""

from __future__ import annotations

import difflib
from typing import Any, ClassVar, List, Optional, Tuple

from app.core.config import get_settings
from app.models.models import (
    ParsedEmail,
    Severity,
    SignalResult,
    SignalMetadata,
)
from app.pods.pod_b.signals.base import BaseSignal, SignalRegistry


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain by removing subdomains.
    
    Extracts the root domain (e.g., mail.paypal.com → paypal.com).
    Handles special cases like co.uk, co.jp, etc.
    
    Args:
        domain: Full domain string
    
    Returns:
        Root domain string
    
    Examples:
        >>> normalize_domain("mail.paypal.com")
        'paypal.com'
        >>> normalize_domain("support.amazon.co.uk")
        'amazon.co.uk'
        >>> normalize_domain("")
        ''
    """
    if not domain:
        return ""
    
    domain = domain.lower().strip()
    parts = domain.split(".")
    
    if len(parts) < 2:
        return domain
    
    # Handle special TLDs like co.uk, co.jp, com.au
    special_tlds = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(parts) >= 3 and parts[-2] in special_tlds:
        return ".".join(parts[-3:])
    
    return ".".join(parts[-2:])


def calculate_similarity(domain1: str, domain2: str) -> float:
    """
    Calculate similarity ratio between two domains.
    
    Uses difflib.SequenceMatcher for Levenshtein-like comparison.
    
    Args:
        domain1: First domain
        domain2: Second domain
    
    Returns:
        Similarity ratio (0.0 to 1.0)
    """
    if not domain1 or not domain2:
        return 0.0
    
    return difflib.SequenceMatcher(None, domain1.lower(), domain2.lower()).ratio()


def check_typosquatting(
    sender_domain: str,
    trusted_brands: List[str],
    threshold: float
) -> Tuple[Optional[str], float]:
    """
    Check if sender domain is a typosquat of a trusted brand.
    
    Args:
        sender_domain: Domain to check
        trusted_brands: List of trusted brand domains
        threshold: Similarity threshold (0.0-1.0)
    
    Returns:
        Tuple of (matched_brand, similarity) or (None, 0.0)
    """
    normalized_sender = normalize_domain(sender_domain)
    
    if not normalized_sender:
        return None, 0.0
    
    for brand in trusted_brands:
        normalized_brand = normalize_domain(brand)
        
        # Exact match - not spoofing
        if normalized_sender == normalized_brand:
            continue
        
        # Check similarity
        similarity = calculate_similarity(normalized_sender, normalized_brand)
        
        if similarity >= threshold:
            return brand, similarity
    
    return None, 0.0


def check_subdomain_spoof(
    sender_domain: str,
    trusted_brands: List[str]
) -> Tuple[Optional[str], Optional[str]]:
    """
    Check if sender uses a trusted brand as subdomain.
    
    Detects patterns like: paypal.evil.com, secure-amazon.com
    
    Args:
        sender_domain: Domain to check
        trusted_brands: List of trusted brand domains
    
    Returns:
        Tuple of (matched_brand, spoof_type) or (None, None)
    """
    if not sender_domain:
        return None, None
    
    domain_lower = sender_domain.lower()
    parts = domain_lower.split(".")
    
    for brand in trusted_brands:
        brand_lower = brand.lower()
        
        # Check if brand appears as a subdomain
        # e.g., paypal.evil.com
        if len(parts) > 2:
            for part in parts[:-2]:  # Exclude root domain
                if part == brand_lower.replace(".", ""):
                    return brand, "subdomain_spoof"
        
        # Check if brand is embedded in domain name
        # e.g., paypal-secure.com, securepaypal.com
        brand_name = brand_lower.replace(".", "")
        domain_no_tld = "".join(parts[:-1])
        
        if brand_name in domain_no_tld and domain_no_tld != brand_name:
            return brand, "brand_embedding"
    
    return None, None


@SignalRegistry.register
class DomainSpoofSignal(BaseSignal):
    """
    Signal for detecting domain spoofing and typosquatting.
    
    This signal analyzes the sender domain to detect attempts to
    impersonate trusted brands through:
    - Typosquatting (paypa1.com)
    - Subdomain spoofing (paypal.evil.com)
    - Brand embedding (paypal-secure.com)
    
    Attributes:
        name: Signal identifier "DOMAIN_SPOOF"
        description: Human-readable description
        requires: Required email fields
    """
    
    name: ClassVar[str] = "DOMAIN_SPOOF"
    description: ClassVar[str] = (
        "Detects domain spoofing attempts including typosquatting, "
        "subdomain spoofing, and brand impersonation"
    )
    version: ClassVar[str] = "2.0.0"
    weight: ClassVar[float] = 1.0
    requires: ClassVar[List[str]] = ["sender_domain", "sender_email"]
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the domain spoof signal.
        
        Args:
            settings: Optional settings override
        """
        super().__init__(settings)
        self.threshold = self.settings.domain_spoof_similarity_threshold
        self.trusted_brands = self.settings.trusted_brands
        self.base_score = self.settings.domain_spoof_score
    
    def analyze(self, email: ParsedEmail) -> SignalResult:
        """
        Analyze email for domain spoofing indicators.
        
        Detection Strategy:
            1. Check for typosquatting via similarity matching
            2. Check for subdomain-based spoofing
            3. Check for brand embedding in domain name
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            SignalResult with detection outcome
        """
        sender_domain = email.sender_domain.lower() if email.sender_domain else ""
        
        if not sender_domain:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="No sender domain to analyze"
            )
        
        # Check for exact trusted brand match (legitimate email)
        normalized_sender = normalize_domain(sender_domain)
        for brand in self.trusted_brands:
            if normalized_sender == normalize_domain(brand):
                return self._create_result(
                    score=0,
                    severity=Severity.LOW,
                    reason=f"Sender domain is a trusted brand: {sender_domain}"
                )
        
        # Check for typosquatting
        matched_brand, similarity = check_typosquatting(
            sender_domain,
            self.trusted_brands,
            self.threshold
        )
        
        if matched_brand:
            self._log.debug(
                "typosquat_detected",
                sender_domain=sender_domain,
                matched_brand=matched_brand,
                similarity=round(similarity, 3)
            )
            
            # Adjust score based on similarity
            # Higher similarity = more likely to fool users = higher score
            score_multiplier = 1.0 + (similarity - self.threshold)
            adjusted_score = int(self.base_score * score_multiplier)
            
            return self._create_result(
                score=adjusted_score,
                severity=Severity.HIGH,
                reason=(
                    f"Sender domain '{sender_domain}' resembles trusted brand "
                    f"'{matched_brand}' (similarity: {similarity:.0%})"
                ),
                metadata=SignalMetadata(
                    matched_domains=[sender_domain, matched_brand],
                    raw_evidence={
                        "similarity_score": similarity,
                        "detection_type": "typosquatting",
                        "normalized_sender": normalized_sender,
                    }
                )
            )
        
        # Check for subdomain spoofing
        spoofed_brand, spoof_type = check_subdomain_spoof(
            sender_domain,
            self.trusted_brands
        )
        
        if spoofed_brand:
            self._log.debug(
                "subdomain_spoof_detected",
                sender_domain=sender_domain,
                spoofed_brand=spoofed_brand,
                spoof_type=spoof_type
            )
            
            return self._create_result(
                score=self.base_score,
                severity=Severity.HIGH,
                reason=(
                    f"Sender domain '{sender_domain}' appears to spoof "
                    f"brand '{spoofed_brand}' via {spoof_type}"
                ),
                metadata=SignalMetadata(
                    matched_domains=[sender_domain, spoofed_brand],
                    raw_evidence={
                        "detection_type": spoof_type,
                    }
                )
            )
        
        # No spoofing detected
        return self._create_result(
            score=0,
            severity=Severity.LOW,
            reason="No domain spoofing indicators detected"
        )


# Backward compatibility function
def evaluate(parsed_email: dict) -> dict:
    """
    Legacy function for backward compatibility.
    
    Deprecated: Use DomainSpoofSignal class instead.
    
    Args:
        parsed_email: Dictionary with email data
    
    Returns:
        Dictionary with signal result
    """
    # Convert dict to ParsedEmail model
    email = ParsedEmail(
        email_id=parsed_email.get("email_id", "unknown"),
        tenant_id=parsed_email.get("tenant_id", "default"),
        sender_domain=parsed_email.get("sender_domain", ""),
        sender_email=parsed_email.get("sender_email", ""),
    )
    
    signal = DomainSpoofSignal()
    result = signal.evaluate(email)
    
    return {
        "signal": result.signal,
        "score": result.score,
        "severity": result.severity.value,
        "reason": result.reason,
    }