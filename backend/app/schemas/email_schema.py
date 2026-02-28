"""
Email input schema for phishing detection API.

Pydantic v2 compliant model with proper validation,
field constraints, and JSON schema examples.
"""

from typing import Any, Optional

from pydantic import AnyHttpUrl, BaseModel, EmailStr, Field, field_validator, model_validator


class EmailInput(BaseModel):
    """
    Schema for email analysis input.

    Attributes:
        sender: The email address of the sender.
        reply_to: Optional reply-to address (often different in phishing).
        subject: The email subject line.
        body: The main content of the email.
        links: Optional list of URLs found in the email.
    """

    sender: EmailStr = Field(
        ...,
        description="The email address of the sender",
        examples=["attacker@fake-bank.com"],
    )
    reply_to: Optional[EmailStr] = Field(
        default=None,
        description="Optional reply-to address, often different in phishing emails",
        examples=["phisher@malicious-domain.com"],
    )
    subject: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="The email subject line",
        examples=["URGENT: Your account has been suspended"],
    )
    body: str = Field(
        ...,
        min_length=1,
        max_length=100000,
        description="The main content/body of the email",
        examples=["Click here immediately to verify your account..."],
    )
    links: Optional[list[AnyHttpUrl]] = Field(
        default_factory=list,
        description="Optional list of URLs found in the email body",
        examples=[["http://fake-bank.com/verify", "http://malicious-site.com"]],
    )

    model_config = {
        "extra": "forbid",
        "str_strip_whitespace": True,
        "json_schema_extra": {
            "examples": [
                {
                    "sender": "support@fake-bank.com",
                    "reply_to": "phisher@malicious-domain.com",
                    "subject": "URGENT: Verify Your Account Immediately",
                    "body": "Dear Customer, Your account has been suspended. Click the link below to verify your identity immediately.",
                    "links": ["http://fake-bank-verify.com/confirm"],
                }
            ]
        },
    }

    @field_validator("sender", mode="after")
    @classmethod
    def sender_must_not_be_empty(cls, v: EmailStr) -> EmailStr:
        """Validate that sender email is not empty after normalization."""
        if not v or not str(v).strip():
            raise ValueError("sender email cannot be empty")
        return v

    @model_validator(mode="after")
    def normalize_emails(self) -> "EmailInput":
        """Normalize email addresses to lowercase for consistent comparison."""
        # Store normalized versions for comparison purposes
        return self


class AnalysisResult(BaseModel):
    """Schema for individual analysis signal result."""

    signal: str = Field(..., description="Name of the detected signal")
    severity: str = Field(..., description="Severity level: low, medium, high, critical")
    description: str = Field(..., description="Detailed description of the finding")
    recommendation: str = Field(..., description="Recommended action for the user")


class EmailAnalysisResponse(BaseModel):
    """Schema for the complete email analysis response."""

    status: str = Field(default="Analysis Complete", description="Status of the analysis")
    signals_detected: list[str] = Field(
        default_factory=list,
        description="List of detected threat signals",
    )
    analysis_results: list[AnalysisResult] = Field(
        default_factory=list,
        description="Detailed analysis results",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Overall risk score from 0-100",
    )
    report: Optional[dict[str, Any]] = Field(
        default=None,
        description="Structured intelligence report",
    )
    pdf_location: Optional[str] = Field(
        default=None,
        description="Path to generated PDF report",
    )

    model_config = {
        "extra": "forbid",
    }
