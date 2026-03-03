"""
Report data transfer objects (DTOs) for the phishing detection system.

Provides structured models for report data, ensuring type safety
and validation throughout the report generation pipeline.
"""

from datetime import datetime, UTC
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ThreatLevel(str, Enum):
    """Threat level classification for email analysis."""

    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    PHISHING = "Phishing"
    CRITICAL = "Critical"


class SignalType(str, Enum):
    """Types of phishing signals that can be detected."""

    DOMAIN_SPOOF = "DOMAIN_SPOOF"
    REPLY_TO_MISMATCH = "REPLY_TO_MISMATCH"
    SHORT_LINK = "SHORT_LINK"
    URGENCY_LANGUAGE = "URGENCY_LANGUAGE"
    EXECUTABLE_ATTACHMENT = "EXECUTABLE_ATTACHMENT"
    ATTACHMENT_MACRO = "ATTACHMENT_MACRO"
    SPF_FAIL = "SPF_FAIL"
    DKIM_FAIL = "DKIM_FAIL"
    SUSPICIOUS_IP = "SUSPICIOUS_IP"
    CREDENTIAL_FORM_LINK = "CREDENTIAL_FORM_LINK"
    SUSPICIOUS_SENDER_DOMAIN = "Suspicious Sender Domain"
    URGENT_LANGUAGE_DETECTED = "Urgent Language Detected"
    SUSPICIOUS_LINK_DETECTED = "Suspicious Link Detected"


class SignalDetail(BaseModel):
    """
    Detailed information about a detected signal.

    Attributes:
        title: Human-readable title of the signal.
        technical_explanation: Technical explanation of the signal.
        risk_context: Context about the risk this signal poses.
        attacker_behavior: Description of attacker behavior associated with this signal.
        operator_action: Recommended action for security operators.
    """

    title: str = Field(..., description="Human-readable title of the signal")
    technical_explanation: str = Field(
        default="",
        description="Technical explanation of the signal",
    )
    risk_context: str = Field(
        default="",
        description="Context about the risk this signal poses",
    )
    attacker_behavior: str = Field(
        default="",
        description="Description of attacker behavior",
    )
    operator_action: str = Field(
        default="",
        description="Recommended action for security operators",
    )

    model_config = {
        "extra": "forbid",
    }


class AnalysisReport(BaseModel):
    """
    Complete analysis report data transfer object.

    This is the validated data structure passed between services
    and to the PDF generator.

    Attributes:
        executive_summary: High-level summary of the analysis.
        score: Risk score from 0-100.
        verdict: Final threat verdict.
        confidence_score: Confidence level of the analysis (0-1).
        detailed_analysis: List of detailed signal analyses.
        generated_at: Timestamp of report generation.
        email_sender: Sender email address (for report context).
        email_subject: Email subject (for report context).
    """

    executive_summary: str = Field(
        default="",
        description="High-level summary of the analysis",
    )
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Risk score from 0-100",
    )
    verdict: str = Field(
        default="Safe",
        description="Final threat verdict",
    )
    confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence level of the analysis (0-1)",
    )
    detailed_analysis: list[SignalDetail] = Field(
        default_factory=list,
        description="List of detailed signal analyses",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),  # ✅ UPDATED
        description="Timestamp of report generation",
    )
    email_sender: str | None = Field(
        default=None,
        description="Sender email address for report context",
    )
    email_subject: str | None = Field(
        default=None,
        description="Email subject for report context",
    )

    model_config = {
        "extra": "forbid",
    }

    @field_validator("verdict", mode="before")
    @classmethod
    def validate_verdict(cls, v: Any) -> str:
        """Normalize verdict to valid threat level."""
        if isinstance(v, str):
            v_lower = v.lower()
            if v_lower in ("critical", "phishing"):
                return "Phishing"
            elif v_lower == "suspicious":
                return "Suspicious"
            else:
                return "Safe"
        return "Safe"


class PDFGenerationResult(BaseModel):
    """
    Result of PDF generation operation.

    Attributes:
        success: Whether PDF generation was successful.
        file_path: Path to the generated PDF file (if successful).
        file_name: Name of the generated PDF file.
        error_message: Error message if generation failed.
        generated_at: Timestamp of generation.
    """

    success: bool = Field(..., description="Whether PDF generation was successful")
    file_path: str | None = Field(
        default=None,
        description="Path to the generated PDF file",
    )
    file_name: str | None = Field(
        default=None,
        description="Name of the generated PDF file",
    )
    error_message: str | None = Field(
        default=None,
        description="Error message if generation failed",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),  # ✅ UPDATED
        description="Timestamp of generation",
    )

    model_config = {
        "extra": "forbid",
    }

    @classmethod
    def success_result(cls, file_path: str, file_name: str) -> "PDFGenerationResult":
        """Create a successful PDF generation result."""
        return cls(
            success=True,
            file_path=file_path,
            file_name=file_name,
        )

    @classmethod
    def failure_result(cls, error_message: str) -> "PDFGenerationResult":
        """Create a failed PDF generation result."""
        return cls(
            success=False,
            error_message=error_message,
        )


class ReportBuildResult(BaseModel):
    """
    Complete result of report building process.

    Attributes:
        report: The built analysis report.
        pdf_result: Result of PDF generation.
        success: Whether the entire process was successful.
    """

    report: AnalysisReport | None = Field(
        default=None,
        description="The built analysis report",
    )
    pdf_result: PDFGenerationResult | None = Field(
        default=None,
        description="Result of PDF generation",
    )
    success: bool = Field(
        default=True,
        description="Whether the entire process was successful",
    )

    model_config = {
        "extra": "forbid",
    }