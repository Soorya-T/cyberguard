"""
CyberGuard Pod B - Attachment Risk Detection Signal

This signal analyzes email attachments for potential security risks
including dangerous file types, double extensions, and suspicious names.

Detection Methods:
    - High-risk extension detection (executable files)
    - Medium-risk extension detection (archives, scripts)
    - Double extension detection (invoice.pdf.exe)
    - Suspicious filename patterns

Example Threats Detected:
    - Executable attachments (.exe, .scr, .js)
    - Double extension spoofing (document.pdf.exe)
    - Macro-enabled documents (.docm, .xlsm)
    - Encrypted archives (potential ransomware delivery)
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional, Set

from app.core.config import get_settings
from app.models.models import (
    Attachment,
    ParsedEmail,
    Severity,
    SignalResult,
    SignalMetadata,
)
from app.pods.pod_b.signals.base import BaseSignal, SignalRegistry


# Risk level classification
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_LOW = "LOW"


def classify_extension(
    extension: str,
    high_risk: Set[str],
    medium_risk: Set[str]
) -> str:
    """
    Classify file extension by risk level.
    
    Args:
        extension: File extension (lowercase, no dot)
        high_risk: Set of high-risk extensions
        medium_risk: Set of medium-risk extensions
    
    Returns:
        Risk level string
    """
    extension = extension.lower().strip(".")
    
    if extension in high_risk:
        return RISK_LEVEL_HIGH
    elif extension in medium_risk:
        return RISK_LEVEL_MEDIUM
    return RISK_LEVEL_LOW


def has_double_extension(filename: str) -> bool:
    """
    Check if filename has a double extension.
    
    Double extensions like "invoice.pdf.exe" are a common technique
    to trick users into opening malicious files.
    
    Args:
        filename: Filename to check
    
    Returns:
        True if double extension detected
    """
    if not filename:
        return False
    
    # Remove leading/trailing dots and split
    clean_name = filename.strip(".")
    parts = clean_name.split(".")
    
    # More than one dot indicates potential double extension
    if len(parts) > 2:
        return True
    
    return False


def get_real_extension(filename: str) -> str:
    """
    Get the real (final) extension from a filename.
    
    Args:
        filename: Filename to analyze
    
    Returns:
        The actual file extension
    """
    if not filename or "." not in filename:
        return ""
    
    return filename.rsplit(".", 1)[-1].lower()


def is_suspicious_filename(filename: str) -> Optional[str]:
    """
    Check for suspicious filename patterns.
    
    Args:
        filename: Filename to check
    
    Returns:
        Reason string if suspicious, None otherwise
    """
    if not filename:
        return None
    
    filename_lower = filename.lower()
    
    # Check for very long filenames (potential buffer overflow attempt)
    if len(filename) > 200:
        return "Filename unusually long"
    
    # Check for multiple consecutive extensions
    if re.search(r'\.\.+', filename):
        return "Multiple consecutive dots in filename"
    
    # Check for null bytes or control characters
    if re.search(r'[\x00-\x1f]', filename):
        return "Control characters in filename"
    
    # Check for common lure patterns
    lure_patterns = [
        (r'invoice.*\.(exe|scr|js|vbs)', "Invoice lure with dangerous extension"),
        (r'receipt.*\.(exe|scr|js|vbs)', "Receipt lure with dangerous extension"),
        (r'document.*\.(exe|scr|js|vbs)', "Document lure with dangerous extension"),
        (r'password.*\.txt', "Password file (common in archive phishing)"),
    ]
    
    for pattern, reason in lure_patterns:
        if re.search(pattern, filename_lower):
            return reason
    
    return None


@SignalRegistry.register
class AttachmentRiskSignal(BaseSignal):
    """
    Signal for detecting risky email attachments.
    
    This signal analyzes attachments for:
    - Dangerous file types (executables, scripts)
    - Double extension spoofing
    - Suspicious filename patterns
    - Archive files (potential malware containers)
    
    Attributes:
        name: Signal identifier "ATTACHMENT_RISK"
        description: Human-readable description
        requires: Required email fields
    """
    
    name: ClassVar[str] = "ATTACHMENT_RISK"
    description: ClassVar[str] = (
        "Analyzes email attachments for dangerous file types, "
        "double extensions, and suspicious filename patterns"
    )
    version: ClassVar[str] = "2.0.0"
    weight: ClassVar[float] = 1.0
    requires: ClassVar[List[str]] = ["attachments"]
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the attachment risk signal.
        
        Args:
            settings: Optional settings override
        """
        super().__init__(settings)
        self.high_risk_extensions = set(self.settings.high_risk_extensions)
        self.medium_risk_extensions = set(self.settings.medium_risk_extensions)
        self.double_extension_score = self.settings.double_extension_score
        self.high_risk_score = self.settings.high_risk_extension_score
        self.medium_risk_score = self.settings.medium_risk_extension_score
        self.max_score = self.settings.attachment_max_score
    
    def analyze(self, email: ParsedEmail) -> SignalResult:
        """
        Analyze email attachments for risk indicators.
        
        Detection Strategy:
            1. Check each attachment for risky extensions
            2. Detect double extension spoofing
            3. Analyze filename patterns
            4. Aggregate risk scores
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            SignalResult with detection outcome
        """
        if not email.attachments:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="No attachments found"
            )
        
        suspicious_files: List[str] = []
        risk_details: Dict[str, List[str]] = {
            "high_risk": [],
            "medium_risk": [],
            "double_extension": [],
            "suspicious_name": [],
        }
        total_score = 0
        max_severity = Severity.LOW
        
        for attachment in email.attachments:
            filename = attachment.filename
            extension = attachment.extension or get_real_extension(filename)
            
            # Check for double extension
            if has_double_extension(filename):
                suspicious_files.append(filename)
                risk_details["double_extension"].append(filename)
                total_score += self.double_extension_score
                max_severity = Severity.HIGH
                
                self._log.debug(
                    "double_extension_detected",
                    filename=filename
                )
                continue
            
            # Check extension risk level
            risk_level = classify_extension(
                extension,
                self.high_risk_extensions,
                self.medium_risk_extensions
            )
            
            if risk_level == RISK_LEVEL_HIGH:
                suspicious_files.append(filename)
                risk_details["high_risk"].append(filename)
                total_score += self.high_risk_score
                max_severity = Severity.HIGH
                
                self._log.debug(
                    "high_risk_extension_detected",
                    filename=filename,
                    extension=extension
                )
            
            elif risk_level == RISK_LEVEL_MEDIUM:
                suspicious_files.append(filename)
                risk_details["medium_risk"].append(filename)
                total_score += self.medium_risk_score
                
                if max_severity != Severity.HIGH:
                    max_severity = Severity.MEDIUM
                
                self._log.debug(
                    "medium_risk_extension_detected",
                    filename=filename,
                    extension=extension
                )
            
            # Check for suspicious filename patterns
            suspicious_reason = is_suspicious_filename(filename)
            if suspicious_reason:
                risk_details["suspicious_name"].append(f"{filename}: {suspicious_reason}")
                total_score += 5  # Small additional score
                
                self._log.debug(
                    "suspicious_filename_detected",
                    filename=filename,
                    reason=suspicious_reason
                )
        
        # Cap the score
        total_score = min(total_score, self.max_score)
        
        if not suspicious_files:
            return self._create_result(
                score=0,
                severity=Severity.LOW,
                reason="No risky attachments detected"
            )
        
        # Build reason message
        reasons = []
        if risk_details["high_risk"]:
            reasons.append(f"High-risk files: {len(risk_details['high_risk'])}")
        if risk_details["double_extension"]:
            reasons.append(f"Double extensions: {len(risk_details['double_extension'])}")
        if risk_details["medium_risk"]:
            reasons.append(f"Medium-risk files: {len(risk_details['medium_risk'])}")
        
        return self._create_result(
            score=total_score,
            severity=max_severity,
            reason=f"Suspicious attachments detected: {', '.join(suspicious_files[:5])}"
                   + (f" (and {len(suspicious_files) - 5} more)" if len(suspicious_files) > 5 else ""),
            metadata=SignalMetadata(
                suspicious_attachments=suspicious_files,
                raw_evidence={
                    "high_risk_files": risk_details["high_risk"],
                    "medium_risk_files": risk_details["medium_risk"],
                    "double_extension_files": risk_details["double_extension"],
                    "suspicious_names": risk_details["suspicious_name"],
                    "total_attachments": len(email.attachments),
                    "suspicious_count": len(suspicious_files),
                }
            )
        )


# Backward compatibility function
def evaluate(parsed_email: dict) -> dict:
    """
    Legacy function for backward compatibility.
    
    Deprecated: Use AttachmentRiskSignal class instead.
    
    Args:
        parsed_email: Dictionary with email data
    
    Returns:
        Dictionary with signal result
    """
    # Convert attachments to Attachment models
    attachments = []
    for att in parsed_email.get("attachments", []):
        attachments.append(Attachment(
            filename=att.get("filename", ""),
            content_type=att.get("type"),
        ))
    
    email = ParsedEmail(
        email_id=parsed_email.get("email_id", "unknown"),
        tenant_id=parsed_email.get("tenant_id", "default"),
        attachments=attachments,
    )
    
    signal = AttachmentRiskSignal()
    result = signal.evaluate(email)
    
    return {
        "signal": result.signal,
        "score": result.score,
        "severity": result.severity.value,
        "reason": result.reason,
    }