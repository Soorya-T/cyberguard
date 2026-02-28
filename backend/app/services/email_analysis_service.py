"""
Email analysis orchestration service.

Coordinates detection, report building, and PDF generation.
This service layer keeps business logic out of the routing layer.
"""

import logging
from fastapi import HTTPException

from app.schemas.email_schema import EmailAnalysisResponse, EmailInput
from app.services.detector import analyze_email

logger = logging.getLogger(__name__)


def _determine_verdict(risk_score: float) -> str:
    """
    Determine verdict based on risk score.

    Returns:
        "Safe", "Suspicious", or "Phishing"
    """
    if risk_score >= 70:
        return "Phishing"
    if risk_score >= 40:
        return "Suspicious"
    return "Safe"


def _determine_severity(risk_score: float) -> str:
    """
    Determine SOC severity tier (for queue badges).

    Returns:
        "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    """
    score = float(risk_score or 0)

    # ✅ Enterprise-style tiering (guarantees HIGH can appear)
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "UNKNOWN"


class EmailAnalysisService:
    """
    Service class for orchestrating email analysis workflow.

    This service coordinates:
    - Phishing signal detection
    - Report building
    - PDF generation
    """

    def __init__(self) -> None:
        self._report_builder = None

    def _get_report_builder(self):
        """Lazy load report builder to avoid circular imports."""
        if self._report_builder is None:
            from app.services.report_builder import build_report
            self._report_builder = build_report
        return self._report_builder

    def analyze(self, data: EmailInput) -> EmailAnalysisResponse:
        try:
            logger.info(
                "Processing email analysis for sender: %s",
                getattr(data, "sender", "unknown"),
            )

            # Step 1: Run phishing detection
            detection_result = analyze_email(data)
            signals = detection_result.get("signals", [])
            risk_score = float(detection_result.get("risk_score", 0.0) or 0.0)
            results = detection_result.get("results", [])

            # Step 2: Determine verdict + severity
            verdict = _determine_verdict(risk_score)
            severity = _determine_severity(risk_score)

            # Step 3: Build structured report
            report = None
            pdf_path = None

            try:
                build_report = self._get_report_builder()
                report = build_report(
                    final_score=risk_score,
                    verdict=verdict,
                    signals=signals,
                )

                # ✅ Ensure report always contains verdict + severity
                if report is None:
                    report = {}

                report["verdict"] = verdict
                report["severity"] = severity

                if report.get("pdf_path"):
                    pdf_path = report["pdf_path"]

            except Exception as e:
                logger.warning("Report building failed: %s", e)
                # still return response even if report fails
                report = {"verdict": verdict, "severity": severity}

            # Step 4: Build response
            response = EmailAnalysisResponse(
                status="Analysis Complete",
                signals_detected=signals,
                analysis_results=results,
                risk_score=risk_score,
                report=report,
                pdf_location=pdf_path,
            )

            logger.info(
                "Analysis complete: %d signals detected | score=%s | severity=%s | verdict=%s",
                len(response.signals_detected),
                risk_score,
                severity,
                verdict,
            )
            return response

        except Exception as e:
            logger.error("Unexpected error during email analysis: %s", e, exc_info=True)
            raise HTTPException(
                status_code=500,
                detail="An internal error occurred during analysis. Please try again.",
            )


# Singleton instance for dependency injection
_email_analysis_service: EmailAnalysisService | None = None


def get_email_analysis_service() -> EmailAnalysisService:
    """Get the email analysis service singleton instance."""
    global _email_analysis_service
    if _email_analysis_service is None:
        _email_analysis_service = EmailAnalysisService()
    return _email_analysis_service