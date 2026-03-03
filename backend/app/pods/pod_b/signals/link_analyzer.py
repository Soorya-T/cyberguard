"""
CyberGuard Pod B - Link Analyzer Signal

This signal analyzes links in emails to detect suspicious patterns
commonly used in phishing campaigns.

Detection Methods:
    - Suspicious TLD detection
    - URL structure analysis
    - Domain reputation checking
    - Redirect chain analysis

Example Threats Detected:
    - Links to suspicious TLDs (.xyz, .top, .click)
    - IP-based URLs
    - URL shortener abuse
    - Credential harvesting URLs
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, List, Optional, Set
from urllib.parse import urlparse, parse_qs

from app.core.config import get_settings
from app.models.models import (
    LinkInfo,
    ParsedEmail,
    Severity,
    SignalResult,
    SignalMetadata,
)
from app.pods.pod_b.signals.base import BaseSignal, SignalRegistry


def extract_tld(domain: str) -> str:
    """
    Extract the top-level domain from a domain string.
    
    Args:
        domain: Full domain (e.g., "example.com")
    
    Returns:
        TLD string (e.g., "com")
    
    Examples:
        >>> extract_tld("example.com")
        'com'
        >>> extract_tld("sub.example.co.uk")
        'uk'
        >>> extract_tld("")
        ''
    """
    if not domain:
        return ""
    
    parts = domain.lower().split(".")
    return parts[-1] if len(parts) > 1 else ""


def is_ip_address(domain: str) -> bool:
    """
    Check if domain is an IP address.
    
    Args:
        domain: Domain string to check
    
    Returns:
        True if domain is an IP address
    """
    # IPv4 pattern
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_pattern, domain):
        return True
    
    # IPv6 pattern (simplified)
    if domain.startswith('[') and domain.endswith(']'):
        return True
    
    return False


def is_url_shortener(domain: str) -> bool:
    """
    Check if domain is a known URL shortener.
    
    Args:
        domain: Domain to check
    
    Returns:
        True if domain is a URL shortener
    """
    shorteners = {
        "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "bl.ink", "short.link",
        "rebrandly.com", "cutt.ly", "rb.gy", "shorturl.at",
    }
    
    domain_lower = domain.lower()
    return domain_lower in shorteners or any(
        domain_lower.endswith(f".{s}") for s in shorteners
    )


def has_suspicious_query_params(url: str) -> List[str]:
    """
    Check for suspicious query parameters.
    
    Args:
        url: URL to analyze
    
    Returns:
        List of suspicious parameters found
    """
    suspicious_params = []
    
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Parameters commonly used in phishing
        suspicious_names = {
            "email", "username", "user", "login", "password", "pass",
            "account", "acct", "redirect", "next", "url", "link",
            "return", "returnurl", "return_url", "dest", "destination",
        }
        
        for param in query_params:
            if param.lower() in suspicious_names:
                suspicious_params.append(param)
    
    except Exception:
        pass
    
    return suspicious_params


@SignalRegistry.register
class LinkAnalyzerSignal(BaseSignal):
    """
    Signal for analyzing links in emails for phishing indicators.
    
    This signal examines all links in an email to detect:
    - Suspicious top-level domains
    - IP-based URLs
    - URL shortener usage
    - Suspicious query parameters
    
    Attributes:
        name: Signal identifier "SUSPICIOUS_TLD"
        description: Human-readable description
        requires: Required email fields
    """
    
    name: ClassVar[str] = "SUSPICIOUS_TLD"
    description: ClassVar[str] = (
        "Analyzes links in emails to detect suspicious TLDs, "
        "IP-based URLs, and other link-based phishing indicators"
    )
    version: ClassVar[str] = "2.0.0"
    weight: ClassVar[float] = 1.0
    requires: ClassVar[List[str]] = ["links", "sender_domain"]
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the link analyzer signal.
        
        Args:
            settings: Optional settings override
        """
        super().__init__(settings)
        self.suspicious_tlds = set(self.settings.suspicious_tlds)
        self.base_score = self.settings.suspicious_tld_base_score
        self.per_domain_score = self.settings.suspicious_tld_per_domain_score
        self.max_score = self.settings.suspicious_tld_max_score
    
    def analyze(self, email: ParsedEmail) -> SignalResult:
        """
        Analyze email links for suspicious indicators.
        
        Detection Strategy:
            1. Check sender domain TLD
            2. Analyze all links for suspicious TLDs
            3. Check for IP-based URLs
            4. Check for URL shorteners
            5. Analyze query parameters
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            SignalResult with detection outcome
        """
        suspicious_domains: List[str] = []
        ip_urls: List[str] = []
        shortener_urls: List[str] = []
        suspicious_params: dict = {}
        
        # Check sender domain
        if email.sender_domain:
            sender_tld = extract_tld(email.sender_domain)
            if sender_tld in self.suspicious_tlds:
                suspicious_domains.append(email.sender_domain)
                self._log.debug(
                    "suspicious_sender_tld",
                    domain=email.sender_domain,
                    tld=sender_tld
                )
        
        # Analyze each link
        for link_info in email.links:
            domain = link_info.domain
            
            # Check for IP-based URLs
            if is_ip_address(domain):
                ip_urls.append(link_info.url)
                self._log.debug(
                    "ip_based_url_detected",
                    url=link_info.url
                )
                continue
            
            # Check for suspicious TLD
            tld = link_info.tld
            if tld in self.suspicious_tlds:
                suspicious_domains.append(domain)
                self._log.debug(
                    "suspicious_tld_detected",
                    domain=domain,
                    tld=tld
                )
            
            # Check for URL shorteners
            if is_url_shortener(domain):
                shortener_urls.append(link_info.url)
                self._log.debug(
                    "url_shortener_detected",
                    url=link_info.url
                )
            
            # Check query parameters
            suspicious = has_suspicious_query_params(link_info.url)
            if suspicious:
                suspicious_params[link_info.url] = suspicious
        
        # Calculate score
        total_indicators = (
            len(set(suspicious_domains)) +
            len(ip_urls) * 2 +  # IP URLs are more suspicious
            len(shortener_urls)
        )
        
        if total_indicators == 0:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="No suspicious link indicators detected"
            )
        
        score = min(
            self.base_score + (total_indicators * self.per_domain_score),
            self.max_score
        )
        
        # Determine severity
        if score >= 25 or len(ip_urls) > 0:
            severity = Severity.HIGH
        elif score >= 15:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        # Build reason message
        reasons = []
        if suspicious_domains:
            reasons.append(f"suspicious TLDs in: {', '.join(list(suspicious_domains)[:3])}")
        if ip_urls:
            reasons.append(f"IP-based URLs: {len(ip_urls)}")
        if shortener_urls:
            reasons.append(f"URL shorteners: {len(shortener_urls)}")
        
        return self._create_result(
            score=score,
            severity=severity,
            reason="; ".join(reasons),
            metadata=SignalMetadata(
                suspicious_links=list(set(suspicious_domains))[:10],
                raw_evidence={
                    "suspicious_domains": list(set(suspicious_domains)),
                    "ip_urls": ip_urls,
                    "shortener_urls": shortener_urls,
                    "suspicious_params": suspicious_params,
                    "total_indicators": total_indicators,
                }
            )
        )


# Backward compatibility function
def evaluate(parsed_email: dict) -> dict:
    """
    Legacy function for backward compatibility.
    
    Deprecated: Use LinkAnalyzerSignal class instead.
    
    Args:
        parsed_email: Dictionary with email data
    
    Returns:
        Dictionary with signal result
    """
    # Convert links to LinkInfo models
    links = []
    for url in parsed_email.get("links", []):
        links.append(LinkInfo(url=url))
    
    email = ParsedEmail(
        email_id=parsed_email.get("email_id", "unknown"),
        tenant_id=parsed_email.get("tenant_id", "default"),
        sender_domain=parsed_email.get("sender_domain", ""),
        links=links,
    )
    
    signal = LinkAnalyzerSignal()
    result = signal.evaluate(email)
    
    return {
        "signal": result.signal,
        "score": result.score,
        "severity": result.severity.value,
        "reason": result.reason,
    }