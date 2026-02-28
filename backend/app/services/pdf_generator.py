"""
PDF generation service for email threat intelligence reports.

This module is fully isolated and contains no business logic.
It accepts validated report DTOs and generates PDF documents
using reportlab best practices.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import get_path_config, get_settings
from app.schemas.report_schema import AnalysisReport, PDFGenerationResult, SignalDetail

logger = logging.getLogger(__name__)


class PDFGeneratorError(Exception):
    """Exception raised when PDF generation fails."""

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        super().__init__(message)
        self.original_error = original_error


class PDFGenerator:
    """
    PDF generator for email threat intelligence reports.
    """

    PAGE_SIZES = {
        "A4": A4,
        "LETTER": LETTER,
    }

    def __init__(self) -> None:
        self._settings = get_settings()
        self._path_config = get_path_config()
        self._styles: dict[str, ParagraphStyle] | None = None

    def _get_page_size(self) -> tuple[float, float]:
        page_size_name = self._settings.pdf_page_size.upper()
        return self.PAGE_SIZES.get(page_size_name, A4)

    def _get_styles(self) -> dict[str, ParagraphStyle]:
        if self._styles is None:
            sample_styles = getSampleStyleSheet()
            self._styles = {
                "title": sample_styles["Heading1"],
                "heading2": sample_styles["Heading2"],
                "heading3": sample_styles["Heading3"],
                "normal": sample_styles["Normal"],
            }
        return self._styles

    def _generate_filename(self, timestamp: datetime | None = None) -> str:
        ts = timestamp or datetime.utcnow()
        ts_str = ts.strftime("%Y%m%d_%H%M%S")
        return f"Email_Threat_Report_{ts_str}.pdf"

    def _validate_report(self, report: AnalysisReport) -> None:
        if not report:
            raise PDFGeneratorError("Report data cannot be None")

        if report.score < 0 or report.score > 100:
            raise PDFGeneratorError(f"Invalid score value: {report.score}")

    def _build_title_section(self, styles: dict[str, ParagraphStyle]):
        return [
            Paragraph("Email Threat Intelligence Report", styles["title"]),
            Spacer(1, 0.3 * inch),
        ]

    def _build_metadata_section(self, report: AnalysisReport, styles):
        elements = []

        metadata = [
            ["Generated At:", report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Risk Score:", f"{report.score:.1f}/100"],
            ["Verdict:", report.verdict],
            ["Confidence:", f"{report.confidence_score * 100:.1f}%"],
        ]

        if report.email_sender:
            metadata.append(["Sender:", report.email_sender])

        if report.email_subject:
            metadata.append(
                [
                    "Subject:",
                    report.email_subject[:50] + "..."
                    if len(report.email_subject) > 50
                    else report.email_subject,
                ]
            )

        table = Table(metadata, colWidths=[1.5 * inch, 4 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        elements.append(table)
        elements.append(Spacer(1, 0.4 * inch))
        return elements

    def _build_summary_section(self, report: AnalysisReport, styles):
        elements = [
            Paragraph("<b>Executive Summary</b>", styles["heading2"]),
            Spacer(1, 0.2 * inch),
            Paragraph(
                report.executive_summary or "No executive summary available.",
                styles["normal"],
            ),
            Spacer(1, 0.4 * inch),
        ]
        return elements

    def _build_signal_section(self, signal: SignalDetail, styles, index: int):
        elements = [
            Paragraph(f"<b>{index}. {signal.title}</b>", styles["heading3"]),
            Spacer(1, 0.1 * inch),
        ]

        if signal.technical_explanation:
            elements.append(
                Paragraph(
                    f"<b>Technical Explanation:</b> {signal.technical_explanation}",
                    styles["normal"],
                )
            )

        if signal.risk_context:
            elements.append(
                Paragraph(
                    f"<b>Risk Context:</b> {signal.risk_context}",
                    styles["normal"],
                )
            )

        if signal.attacker_behavior:
            elements.append(
                Paragraph(
                    f"<b>Attacker Behavior:</b> {signal.attacker_behavior}",
                    styles["normal"],
                )
            )

        if signal.operator_action:
            elements.append(
                Paragraph(
                    f"<b>Recommended Action:</b> {signal.operator_action}",
                    styles["normal"],
                )
            )

        elements.append(Spacer(1, 0.2 * inch))
        return elements

    def _build_detailed_analysis_section(self, report, styles):
        elements = [
            Paragraph("<b>Detailed Signal Analysis</b>", styles["heading2"]),
            Spacer(1, 0.2 * inch),
        ]

        if not report.detailed_analysis:
            elements.append(Paragraph("No detailed signals found.", styles["normal"]))
        else:
            for index, signal in enumerate(report.detailed_analysis, start=1):
                elements.extend(self._build_signal_section(signal, styles, index))

        return elements

    def generate(self, report: AnalysisReport) -> PDFGenerationResult:
        try:
            self._validate_report(report)
            styles = self._get_styles()

            filename = self._generate_filename(report.generated_at)
            file_path = self._path_config.get_pdf_path(filename)

            doc = SimpleDocTemplate(
                str(file_path),
                pagesize=self._get_page_size(),
                topMargin=self._settings.pdf_margin_top * inch,
                bottomMargin=self._settings.pdf_margin_bottom * inch,
                leftMargin=self._settings.pdf_margin_left * inch,
                rightMargin=self._settings.pdf_margin_right * inch,
            )

            elements = []
            elements.extend(self._build_title_section(styles))
            elements.extend(self._build_metadata_section(report, styles))
            elements.extend(self._build_summary_section(report, styles))
            elements.extend(self._build_detailed_analysis_section(report, styles))

            doc.build(elements)

            return PDFGenerationResult.success_result(
                file_path=str(file_path),
                file_name=filename,
            )

        except Exception as e:
            logger.error(f"PDF generation failed: {e}", exc_info=True)
            return PDFGenerationResult.failure_result(str(e))

# -----------------------------
# Singleton getter (required by report_builder)
# -----------------------------
_pdf_generator = None

def get_pdf_generator():
    global _pdf_generator
    if _pdf_generator is None:
        _pdf_generator = PDFGenerator()
    return _pdf_generator

# ------------------------------------------------------------------
# CLI SUPPORT - Direct execution from terminal
# ------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("\n🔹 Running PDF Generator in Standalone Mode...\n")

    sample_signals = [
        SignalDetail(
            title="Suspicious Sender Domain",
            technical_explanation="Sender domain mismatch detected.",
            risk_context="May indicate phishing.",
            attacker_behavior="Impersonation technique.",
            operator_action="Do not click unknown links.",
        )
    ]

    sample_report = AnalysisReport(
        executive_summary="This email contains phishing indicators.",
        score=85.0,
        verdict="High Risk",
        confidence_score=0.91,
        detailed_analysis=sample_signals,
        generated_at=datetime.utcnow(),
        email_sender="attacker@fake.com",
        email_subject="Urgent: Verify your account",
    )

    generator = PDFGenerator()
    result = generator.generate(sample_report)

    if result.success:
        print(f"✅ PDF Generated Successfully:\n{result.file_path}\n")
    else:
        print(f"❌ PDF Generation Failed:\n{result.error_message}\n")