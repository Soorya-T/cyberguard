"""
CyberGuard Pod B - Urgency Language Detection Signal

This signal detects urgency and pressure language commonly used in
phishing emails to manipulate recipients into taking hasty action.

Detection Methods:
    - Keyword matching for urgency phrases
    - Pattern recognition for time pressure
    - Threat language detection

Example Threats Detected:
    - "URGENT: Verify your account now"
    - "Your account will be suspended within 24 hours"
    - "Act immediately to avoid suspension"
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, List, Optional, Set

from app.core.config import get_settings
from app.models.models import (
    ParsedEmail,
    Severity,
    SignalResult,
    SignalMetadata,
)
from app.pods.pod_b.signals.base import BaseSignal, SignalRegistry


# Extended urgency keyword patterns
URGENCY_PATTERNS = {
    # Direct urgency words
    "urgent": r"\burgent\b",
    "immediately": r"\bimmediately\b",
    "asap": r"\basap\b",
    "right away": r"\bright\s+away\b",
    
    # Time pressure
    "act now": r"\bact\s+now\b",
    "verify now": r"\bverify\s+now\b",
    "update now": r"\bupdate\s+now\b",
    "confirm now": r"\bconfirm\s+now\b",
    "limited time": r"\blimited\s+time\b",
    "within 24 hours": r"\bwithin\s+\d+\s+hours?\b",
    "within 48 hours": r"\bwithin\s+\d+\s+hours?\b",
    "expire today": r"\bexpire[s]?\s+today\b",
    "expires soon": r"\bexpire[s]?\s+soon\b",
    "deadline": r"\bdeadline\b",
    "time sensitive": r"\btime\s+sensitive\b",
    
    # Threats and warnings
    "final warning": r"\bfinal\s+warning\b",
    "last warning": r"\blast\s+warning\b",
    "account suspended": r"\baccount\s+suspend(ed)?\b",
    "account locked": r"\baccount\s+lock(ed)?\b",
    "account disabled": r"\baccount\s+disabl(ed)?\b",
    "security alert": r"\bsecurity\s+alert\b",
    "unusual activity": r"\bunusual\s+activity\b",
    "suspicious activity": r"\bsuspicious\s+activity\b",
    "unauthorized access": r"\bunauthorized\s+access\b",
    
    # Action demands
    "respond immediately": r"\brespond\s+immediately\b",
    "action required": r"\baction\s+required\b",
    "attention required": r"\battention\s+required\b",
    "important notice": r"\bimportant\s+notice\b",
    "mandatory": r"\bmandatory\b",
    "required": r"\baction\s+required\b",
    
    # Fear appeals
    "avoid suspension": r"\bavoid\s+suspension\b",
    "prevent closure": r"\bprevent\s+closure\b",
    "don't lose access": r"\bdon'?t\s+lose\s+access\b",
    "verify your identity": r"\bverify\s+your\s+identity\b",
    "confirm your identity": r"\bconfirm\s+your\s+identity\b",
}


def compile_patterns(patterns: dict) -> List[tuple]:
    """
    Compile regex patterns for efficient matching.
    
    Args:
        patterns: Dictionary of name -> pattern string
    
    Returns:
        List of (name, compiled_pattern) tuples
    """
    compiled = []
    for name, pattern in patterns.items():
        try:
            compiled.append((name, re.compile(pattern, re.IGNORECASE)))
        except re.error:
            continue
    return compiled


@SignalRegistry.register
class UrgencyDetectorSignal(BaseSignal):
    """
    Signal for detecting urgency and pressure language in emails.
    
    This signal analyzes email subject and body for language patterns
    that create artificial urgency, a common phishing tactic.
    
    Attributes:
        name: Signal identifier "URGENCY_LANGUAGE"
        description: Human-readable description
        requires: Required email fields
    """
    
    name: ClassVar[str] = "URGENCY_LANGUAGE"
    description: ClassVar[str] = (
        "Detects urgency and pressure language commonly used in phishing "
        "to manipulate recipients into hasty action"
    )
    version: ClassVar[str] = "2.0.0"
    weight: ClassVar[float] = 1.0
    requires: ClassVar[List[str]] = ["subject", "body_text"]
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the urgency detector signal.
        
        Args:
            settings: Optional settings override
        """
        super().__init__(settings)
        self.base_score = self.settings.urgency_base_score
        self.per_keyword_score = self.settings.urgency_per_keyword_score
        self.max_score = self.settings.urgency_max_score
        self.keywords = self.settings.urgency_keywords
        
        # Compile patterns for efficient matching
        self._compiled_patterns = compile_patterns(URGENCY_PATTERNS)
    
    def analyze(self, email: ParsedEmail) -> SignalResult:
        """
        Analyze email for urgency language indicators.
        
        Detection Strategy:
            1. Combine subject and body for analysis
            2. Match against compiled urgency patterns
            3. Calculate score based on number and severity of matches
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            SignalResult with detection outcome
        """
        # Combine subject and body for analysis
        subject = email.subject or ""
        body = email.body_text or ""
        
        combined_text = f"{subject} {body}".lower()
        
        if not combined_text.strip():
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="No content to analyze"
            )
        
        # Find all matching patterns
        matched_keywords: List[str] = []
        matched_patterns: List[str] = []
        
        for pattern_name, compiled_pattern in self._compiled_patterns:
            if compiled_pattern.search(combined_text):
                matched_keywords.append(pattern_name)
                # Find actual matched text
                match = compiled_pattern.search(combined_text)
                if match:
                    matched_patterns.append(match.group())
        
        # Also check configured keywords (for backward compatibility)
        for keyword in self.keywords:
            if keyword.lower() in combined_text:
                if keyword.lower() not in matched_keywords:
                    matched_keywords.append(keyword.lower())
        
        if not matched_keywords:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="No urgency language detected"
            )
        
        # Calculate score
        # Base score + additional for each keyword, capped at max
        score = min(
            self.base_score + (len(matched_keywords) * self.per_keyword_score),
            self.max_score
        )
        
        # Determine severity based on score
        if score >= 30:
            severity = Severity.HIGH
        elif score >= 15:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        # Check for high-risk combinations
        high_risk_combos = self._check_high_risk_combinations(matched_keywords)
        if high_risk_combos:
            score = min(score + 10, self.max_score)
            severity = Severity.HIGH
        
        self._log.debug(
            "urgency_language_detected",
            matched_keywords=matched_keywords,
            score=score
        )
        
        return self._create_result(
            score=score,
            severity=severity,
            reason=f"Urgency phrases detected: {', '.join(matched_keywords[:5])}"
                   + (f" (and {len(matched_keywords) - 5} more)" if len(matched_keywords) > 5 else ""),
            metadata=SignalMetadata(
                matched_keywords=matched_keywords,
                raw_evidence={
                    "matched_patterns": matched_patterns[:10],
                    "high_risk_combinations": high_risk_combos,
                    "keyword_count": len(matched_keywords),
                }
            )
        )
    
    def _check_high_risk_combinations(self, matched: List[str]) -> List[str]:
        """
        Check for high-risk keyword combinations.
        
        Some combinations are particularly indicative of phishing:
        - urgency + threat
        - urgency + action demand
        
        Args:
            matched: List of matched keywords
        
        Returns:
            List of detected high-risk combinations
        """
        combinations = []
        matched_set = set(m.lower() for m in matched)
        
        # Urgency + Threat combination
        urgency_words = {"urgent", "immediately", "act now", "asap"}
        threat_words = {"account suspended", "final warning", "security alert", "unusual activity"}
        
        if matched_set & urgency_words and matched_set & threat_words:
            combinations.append("urgency_with_threat")
        
        # Time pressure + Action demand
        time_pressure = {"within 24 hours", "expire today", "limited time", "deadline"}
        action_demand = {"verify now", "update now", "action required", "confirm now"}
        
        if matched_set & time_pressure and matched_set & action_demand:
            combinations.append("time_pressure_with_action")
        
        return combinations


# Backward compatibility function
def evaluate(parsed_email: dict) -> dict:
    """
    Legacy function for backward compatibility.
    
    Deprecated: Use UrgencyDetectorSignal class instead.
    
    Args:
        parsed_email: Dictionary with email data
    
    Returns:
        Dictionary with signal result
    """
    email = ParsedEmail(
        email_id=parsed_email.get("email_id", "unknown"),
        tenant_id=parsed_email.get("tenant_id", "default"),
        subject=parsed_email.get("subject", ""),
        body_text=parsed_email.get("body_text", parsed_email.get("body", "")),
    )
    
    signal = UrgencyDetectorSignal()
    result = signal.evaluate(email)
    
    return {
        "signal": result.signal,
        "score": result.score,
        "severity": result.severity.value,
        "reason": result.reason,
    }