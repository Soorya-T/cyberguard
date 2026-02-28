"""
Report builder service for email threat intelligence.

Orchestrates the creation of structured analysis reports,
coordinating between detection results, signal expansion,
summary generation, and confidence calculation.
"""

import logging
from datetime import datetime, UTC  # ✅ UPDATED
from typing import Any

from app.schemas.report_schema import AnalysisReport, PDFGenerationResult, ReportBuildResult, SignalDetail
from app.services.confidence_engine import calculate_confidence
from app.services.pdf_generator import PDFGeneratorError, get_pdf_generator
from app.services.reason_expander import expand_signals
from app.services.summary_engine import generate_summary

logger = logging.getLogger(__name__)


class ReportBuilderError(Exception):
    """Exception raised when report building fails."""

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        super().__init__(message)
        self.original_error = original_error


class ReportBuilder:
    """
    Report builder for creating structured threat intelligence reports.
    """

    def __init__(self) -> None:
        self._pdf_generator = None

    def _get_pdf_generator(self):
        """Lazy load PDF generator to avoid circular imports."""
        if self._pdf_generator is None:
            self._pdf_generator = get_pdf_generator()
        return self._pdf_generator

    def _expand_signals_to_details(self, signals: list[str]) -> list[SignalDetail]:
        expanded = expand_signals(signals)
        details = []

        for signal_data in expanded:
            if isinstance(signal_data, dict):
                details.append(
                    SignalDetail(
                        title=signal_data.get("title", "Unknown Signal"),
                        technical_explanation=signal_data.get("technical_explanation", ""),
                        risk_context=signal_data.get("risk_context", ""),
                        attacker_behavior=signal_data.get("attacker_behavior", ""),
                        operator_action=signal_data.get("operator_action", ""),
                    )
                )
            elif isinstance(signal_data, SignalDetail):
                details.append(signal_data)

        return details

    def build(
        self,
        final_score: float,
        verdict: str,
        signals: list[str],
        generate_pdf: bool = True,
    ) -> ReportBuildResult:

        try:
            logger.info(f"Building report: score={final_score}, verdict={verdict}, signals={len(signals)}")

            # Step 1: Expand signals
            detailed_signals = self._expand_signals_to_details(signals)

            # Step 2: Generate summary
            summary = generate_summary(final_score, verdict, detailed_signals)

            # Step 3: Calculate confidence
            confidence = calculate_confidence(final_score, detailed_signals)

            # Step 4: Create report
            report = AnalysisReport(
                executive_summary=summary,
                score=final_score,
                verdict=verdict,
                confidence_score=confidence,
                detailed_analysis=detailed_signals,
                generated_at=datetime.now(UTC),  # ✅ UPDATED (No more utcnow)
            )

            # Step 5: Generate PDF
            pdf_result: PDFGenerationResult | None = None
            if generate_pdf:
                try:
                    pdf_generator = self._get_pdf_generator()
                    pdf_result = pdf_generator.generate(report)
                except PDFGeneratorError as e:
                    logger.warning(f"PDF generation failed: {e}")
                    pdf_result = PDFGenerationResult.failure_result(str(e))

            logger.info("Report built successfully")

            return ReportBuildResult(
                report=report,
                pdf_result=pdf_result,
                success=True,
            )

        except Exception as e:
            logger.error(f"Error building report: {e}", exc_info=True)
            return ReportBuildResult(
                report=None,
                pdf_result=None,
                success=False,
            )

    def build_from_detection_result(
        self,
        detection_result: dict[str, Any],
        generate_pdf: bool = True,
    ) -> ReportBuildResult:

        score = detection_result.get("risk_score", 0.0)
        signals = detection_result.get("signals", [])

        if score >= 70:
            verdict = "Phishing"
        elif score >= 40:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        return self.build(
            final_score=score,
            verdict=verdict,
            signals=signals,
            generate_pdf=generate_pdf,
        )


# Singleton instance
_report_builder: ReportBuilder | None = None


def get_report_builder() -> ReportBuilder:
    global _report_builder
    if _report_builder is None:
        _report_builder = ReportBuilder()
    return _report_builder


def build_report(
    final_score: float,
    verdict: str,
    signals: list[str],
) -> dict[str, Any]:

    builder = get_report_builder()
    result = builder.build(
        final_score=final_score,
        verdict=verdict,
        signals=signals,
        generate_pdf=True,
    )

    if not result.success or result.report is None:
        logger.error("Report building failed")
        return {
            "executive_summary": "Report generation failed.",
            "score": final_score,
            "verdict": verdict,
            "confidence_score": 0,
            "detailed_analysis": [],
        }

    report_dict = {
        "executive_summary": result.report.executive_summary,
        "score": result.report.score,
        "verdict": result.report.verdict,
        "confidence_score": result.report.confidence_score,
        "detailed_analysis": [
            {
                "title": s.title,
                "technical_explanation": s.technical_explanation,
                "risk_context": s.risk_context,
                "attacker_behavior": s.attacker_behavior,
                "operator_action": s.operator_action,
            }
            for s in result.report.detailed_analysis
        ],
    }

    if result.pdf_result and result.pdf_result.success:
        report_dict["pdf_path"] = result.pdf_result.file_path

    return report_dict