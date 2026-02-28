"""
Email threat detection service.

Provides phishing signal detection with defensive programming,
proper error handling, and structured output.
"""

import logging
import re
from typing import Any

from pydantic import AnyHttpUrl

from app.schemas.email_schema import AnalysisResult, EmailInput

# Configure logging
logger = logging.getLogger(__name__)


# Severity levels for detected signals
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Known suspicious patterns
SUSPICIOUS_DOMAINS = {
    "fake",
    "phish",
    "malware",
    "scam",
    "suspicious",
    "verify-account",
    "login-secure",
    "account-confirm",
}

URGENCY_WORDS = {
    "urgent",
    "immediately",
    "verify",
    "suspended",
    "click now",
    "act now",
    "limited time",
    "expire",
    "verify now",
    "confirm now",
    "update now",
    "action required",
}

SUSPICIOUS_PHRASES = {
    "click here",
    "click below",
    "verify your account",
    "confirm your identity",
    "update your payment",
    "you have been selected",
    "congratulations",
    "you've won",
    "wire transfer",
    "gift card",
}


def _normalize_email(email: str | None) -> str | None:
    """
    Normalize email address for comparison.

    Args:
        email: Email address to normalize.

    Returns:
        Normalized (lowercase) email or None if input is None/empty.
    """
    if not email:
        return None
    normalized = str(email).strip().lower()
    return normalized if normalized else None


def _extract_domain(email: str | None) -> str | None:
    """
    Extract domain from email address.

    Args:
        email: Email address to extract domain from.

    Returns:
        Domain part of email or None if invalid.
    """
    if not email:
        return None
    try:
        return str(email).split("@")[-1].lower().strip()
    except (IndexError, AttributeError):
        return None


def _is_suspicious_domain(domain: str | None) -> bool:
    """
    Check if domain contains suspicious patterns.

    Args:
        domain: Domain to check.

    Returns:
        True if domain appears suspicious.
    """
    if not domain:
        return False
    domain_lower = domain.lower()
    return any(pattern in domain_lower for pattern in SUSPICIOUS_DOMAINS)


def _is_http_url(url: AnyHttpUrl) -> bool:
    """
    Check if URL uses insecure HTTP.

    Args:
        url: URL to check.

    Returns:
        True if URL uses HTTP (not HTTPS).
    """
    try:
        url_str = str(url)
        return url_str.startswith("http://")
    except Exception:
        return False


def _validate_url(url: AnyHttpUrl) -> dict[str, Any]:
    """
    Validate URL for suspicious characteristics.

    Args:
        url: URL to validate.

    Returns:
        Dictionary with validation results.
    """
    url_str = str(url)
    result = {
        "url": url_str,
        "is_http": _is_http_url(url),
        "has_ip_address": bool(re.match(r"https?://\d{1,3}\.", url_str)),
        "suspicious_tld": any(
            tld in url_str.lower()
            for tld in [".xyz", ".top", ".club", ".work", ".click", ".link"]
        ),
    }
    result["is_suspicious"] = (
        result["is_http"] or result["has_ip_address"] or result["suspicious_tld"]
    )
    return result


def _check_sender_domain(data: EmailInput) -> AnalysisResult | None:
    """
    Check for suspicious sender domain.

    Args:
        data: Email input data.

    Returns:
        AnalysisResult if suspicious, None otherwise.
    """
    sender = getattr(data, "sender", None)
    if not sender:
        return None

    domain = _extract_domain(sender)
    if _is_suspicious_domain(domain):
        logger.info(f"Suspicious sender domain detected: {domain}")
        return AnalysisResult(
            signal="Suspicious Sender Domain",
            severity=SEVERITY_HIGH,
            description=f"The sender domain '{domain}' contains suspicious patterns commonly used in phishing.",
            recommendation="Verify the sender's identity through official channels before responding.",
        )
    return None


def _check_reply_to_mismatch(data: EmailInput) -> AnalysisResult | None:
    """
    Check for reply-to mismatch.

    Args:
        data: Email input data.

    Returns:
        AnalysisResult if mismatch detected, None otherwise.
    """
    sender = getattr(data, "sender", None)
    reply_to = getattr(data, "reply_to", None)

    if not sender or not reply_to:
        return None

    sender_normalized = _normalize_email(sender)
    reply_to_normalized = _normalize_email(reply_to)

    if sender_normalized and reply_to_normalized and sender_normalized != reply_to_normalized:
        sender_domain = _extract_domain(sender)
        reply_domain = _extract_domain(reply_to)

        if sender_domain and reply_domain and sender_domain != reply_domain:
            logger.info(
                f"Reply-to mismatch detected: sender={sender_domain}, reply_to={reply_domain}"
            )
            return AnalysisResult(
                signal="Reply-To Mismatch",
                severity=SEVERITY_CRITICAL,
                description=f"The reply-to address domain '{reply_domain}' differs from sender domain '{sender_domain}'.",
                recommendation="Be extremely cautious. This is a common phishing tactic to redirect responses.",
            )
    return None


def _check_urgent_language(data: EmailInput) -> AnalysisResult | None:
    """
    Check for urgent/threatening language.

    Args:
        data: Email input data.

    Returns:
        AnalysisResult if urgent language detected, None otherwise.
    """
    body = getattr(data, "body", None)
    subject = getattr(data, "subject", None)

    # Combine subject and body for analysis
    content = ""
    if subject:
        content += str(subject) + " "
    if body:
        content += str(body)

    if not content:
        return None

    content_lower = content.lower()

    # Check for urgency words
    found_urgency = [word for word in URGENCY_WORDS if word in content_lower]

    # Check for suspicious phrases
    found_phrases = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in content_lower]

    if found_urgency or found_phrases:
        detected = list(set(found_urgency + found_phrases))
        logger.info(f"Urgent language detected: {detected}")
        return AnalysisResult(
            signal="Urgent Language Detected",
            severity=SEVERITY_MEDIUM,
            description=f"The email contains urgency indicators: {', '.join(detected[:5])}.",
            recommendation="Be cautious of emails pressuring immediate action. Verify through official channels.",
        )
    return None


def _check_suspicious_links(data: EmailInput) -> AnalysisResult | None:
    """
    Check for suspicious links.

    Args:
        data: Email input data.

    Returns:
        AnalysisResult if suspicious links detected, None otherwise.
    """
    links = getattr(data, "links", None)

    if not links:
        return None

    suspicious_links = []
    for link in links:
        try:
            validation = _validate_url(link)
            if validation["is_suspicious"]:
                suspicious_links.append(validation)
        except Exception as e:
            logger.warning(f"Failed to validate URL: {e}")
            continue

    if suspicious_links:
        logger.info(f"Suspicious links detected: {len(suspicious_links)}")
        reasons = []
        for sl in suspicious_links:
            if sl["is_http"]:
                reasons.append("insecure HTTP")
            if sl["has_ip_address"]:
                reasons.append("IP address in URL")
            if sl["suspicious_tld"]:
                reasons.append("suspicious TLD")

        return AnalysisResult(
            signal="Suspicious Link Detected",
            severity=SEVERITY_HIGH,
            description=f"Found {len(suspicious_links)} suspicious link(s). Issues: {', '.join(set(reasons))}.",
            recommendation="Do not click on suspicious links. Verify URLs by hovering or typing the official domain manually.",
        )
    return None


def analyze_email(data: EmailInput) -> dict[str, Any]:
    """
    Analyze email input and detect potential phishing signals.

    This function performs comprehensive phishing detection using
    multiple heuristics and returns structured results.

    Args:
        data: EmailInput model containing email data to analyze.

    Returns:
        Dictionary containing:
            - signals: List of detected signal names
            - results: List of AnalysisResult objects
            - risk_score: Calculated risk score (0-100)

    Raises:
        ValueError: If data is None or invalid.
    """
    if data is None:
        raise ValueError("Email input data cannot be None")

    logger.info("Starting email analysis")

    try:
        results: list[AnalysisResult] = []

        # Run all detection checks
        checks = [
            _check_sender_domain,
            _check_reply_to_mismatch,
            _check_urgent_language,
            _check_suspicious_links,
        ]

        for check in checks:
            try:
                result = check(data)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error in check {check.__name__}: {e}")
                continue

        # Calculate risk score
        risk_score = _calculate_risk_score(results)

        # Extract signal names
        signals = [r.signal for r in results]

        logger.info(f"Analysis complete: {len(signals)} signals detected, risk score: {risk_score}")

        return {
            "signals": signals,
            "results": results,
            "risk_score": risk_score,
        }

    except Exception as e:
        logger.error(f"Unexpected error during email analysis: {e}")
        raise


def _calculate_risk_score(results: list[AnalysisResult]) -> float:
    """
    Calculate overall risk score based on detected signals.

    Args:
        results: List of analysis results.

    Returns:
        Risk score from 0 to 100.
    """
    if not results:
        return 0.0

    severity_weights = {
        SEVERITY_LOW: 10,
        SEVERITY_MEDIUM: 25,
        SEVERITY_HIGH: 50,
        SEVERITY_CRITICAL: 75,
    }

    total_score = sum(severity_weights.get(r.severity, 10) for r in results)

    # Cap at 100 and apply diminishing returns for multiple signals
    capped_score = min(total_score, 100)

    return round(capped_score, 1)


def get_analysis_summary(analysis_result: dict[str, Any]) -> str:
    """
    Generate a human-readable summary of the analysis.

    Args:
        analysis_result: Result dictionary from analyze_email.

    Returns:
        Human-readable summary string.
    """
    signals = analysis_result.get("signals", [])
    risk_score = analysis_result.get("risk_score", 0)

    if not signals:
        return "No phishing signals detected. The email appears to be safe."

    summary = f"Detected {len(signals)} potential threat signal(s) with a risk score of {risk_score}/100. "
    summary += f"Signals: {', '.join(signals)}."

    return summary
