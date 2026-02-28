"""
CyberGuard Pod B - Signal Engine Module

This module provides the orchestration layer for all signal detection modules.
It coordinates signal execution, aggregates results, and generates final verdicts.

Features:
    - Error isolation (one failing signal doesn't break the pipeline)
    - Configurable signal execution (enable/disable per deployment)
    - Weighted score aggregation
    - Verdict generation with confidence scoring
    - Structured logging and metrics
"""

from __future__ import annotations

import asyncio
import time
import uuid
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime , timezone
from typing import Any, Dict, List, Optional, Type

from app.core.config import get_settings
from app.core.logging import get_logger, LogContext
from app.models.models import (
    ParsedEmail,
    ParseError,
    ScanResult,
    SignalResult,
    Severity,
    Verdict,
)
from app.pods.pod_b.signals.base import BaseSignal, SignalRegistry

# Force signal imports for registration
import app.pods.pod_b.signals.attachment_risk
import app.pods.pod_b.signals.domain_spoof
import app.pods.pod_b.signals.link_analyzer
import app.pods.pod_b.signals.reply_mismatch
import app.pods.pod_b.signals.urgency_detector

log = get_logger(__name__)


class ScoringEngine:
    """
    Engine for calculating final scores and generating verdicts.
    
    This class handles:
    - Score normalization and capping
    - Verdict threshold evaluation
    - Confidence calculation
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the scoring engine.
        
        Args:
            settings: Optional settings override
        """
        self.settings = settings or get_settings()
        self.phishing_threshold = self.settings.phishing_threshold
        self.suspicious_threshold = self.settings.suspicious_threshold
        self.max_score = self.settings.max_total_score
    
    def calculate_total_score(self, signal_results: List[SignalResult]) -> int:
        """
        Calculate the total aggregated score from all signals.
        
        Args:
            signal_results: List of signal results
        
        Returns:
            Total score (0-100)
        """
        total = sum(result.score for result in signal_results)
        return min(total, self.max_score)
    
    def generate_verdict(self, total_score: int) -> Verdict:
        """
        Generate a verdict based on the total score.
        
        Args:
            total_score: Aggregated risk score
        
        Returns:
            Verdict enum value
        """
        if total_score >= self.phishing_threshold:
            return Verdict.PHISHING
        elif total_score >= self.suspicious_threshold:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.SAFE
    
    def calculate_confidence(
        self,
        signal_results: List[SignalResult],
        total_score: int
    ) -> float:
        """
        Calculate confidence level for the verdict.
        
        Higher confidence when:
        - Multiple signals agree on severity
        - High-severity signals have high confidence
        - Score is decisively above/below thresholds
        
        Args:
            signal_results: List of signal results
            total_score: Aggregated risk score
        
        Returns:
            Confidence level (0.0-1.0)
        """
        if not signal_results:
            return 0.5
        
        # Base confidence on signal agreement
        high_severity_count = sum(
            1 for r in signal_results
            if r.severity in (Severity.HIGH, Severity.CRITICAL)
        )
        low_severity_count = sum(
            1 for r in signal_results
            if r.severity == Severity.LOW
        )
        
        total_signals = len(signal_results)
        
        # Calculate agreement ratio
        if high_severity_count > low_severity_count:
            agreement = high_severity_count / total_signals
        else:
            agreement = low_severity_count / total_signals
        
        # Factor in individual signal confidence
        avg_signal_confidence = sum(
            r.confidence for r in signal_results
        ) / total_signals
        
        # Factor in score decisiveness
        if total_score >= self.phishing_threshold:
            decisiveness = min((total_score - self.phishing_threshold) / 50, 1.0)
        elif total_score < self.suspicious_threshold:
            decisiveness = min((self.suspicious_threshold - total_score) / 20, 1.0)
        else:
            decisiveness = 0.5  # In the suspicious range
        
        # Weighted average
        confidence = (
            0.4 * agreement +
            0.3 * avg_signal_confidence +
            0.3 * decisiveness
        )
        
        return round(min(max(confidence, 0.0), 1.0), 2)


class SignalOrchestrator:
    """
    Orchestrates signal execution and result aggregation.
    
    This class manages:
    - Signal registration and discovery
    - Parallel/sequential signal execution
    - Error isolation and handling
    - Result collection and aggregation
    """
    
    def __init__(
        self,
        settings: Optional[Any] = None,
        signal_classes: Optional[List[Type[BaseSignal]]] = None
    ):
        """
        Initialize the signal orchestrator.
        
        Args:
            settings: Optional settings override
            signal_classes: Optional list of signal classes to use
                           (defaults to all registered signals)
        """
        self.settings = settings or get_settings()
        self.log = get_logger(__name__)
        
        # Initialize signals
        if signal_classes:
            self.signal_classes = signal_classes
        else:
            self.signal_classes = SignalRegistry.get_all_signals()
        
        self.scoring_engine = ScoringEngine(settings)
        
        # Thread pool for parallel execution
        self._executor = ThreadPoolExecutor(max_workers=10)
    
    def get_signal_instances(self) -> List[BaseSignal]:
        """
        Get instances of all configured signals.
        
        Returns:
            List of signal instances
        """
        return [cls(self.settings) for cls in self.signal_classes]
    
    def run_signals(self, email: ParsedEmail) -> List[SignalResult]:
        """

        Run all signals on the parsed email.
        
        Signals are executed with error isolation - a failure in one
        signal does not affect other signals.
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            List of signal results
        """
        results: List[SignalResult] = []
        signals = self.get_signal_instances()
        
        for signal in signals:
            try:
                result = signal.analyze(email)
                results.append(result)
                
                self.log.debug(
                    "signal_completed",
                    signal=signal.name,
                    score=result.score,
                    severity=result.severity.value
                )
                
            except Exception as e:
                self.log.error(
                    "signal_execution_failed",
                    signal=signal.name,
                    error=str(e),
                    error_type=type(e).__name__
                )
                
                # Add error result
                results.append(SignalResult(
                    signal=signal.name,
                    score=0,
                    severity=Severity.LOW,
                    reason=f"Signal execution failed: {str(e)}",
                    confidence=0.0,
                ))
        
        return results
    
    def get_triggered_signals(self, email: ParsedEmail) -> List[str]:
        results = self.run_signals(email)

        return [
         r.signal
         for r in results
         if r.score > 0
    ]

    def run_signals_parallel(self, email: ParsedEmail) -> List[SignalResult]:
        """
        Run all signals in parallel using thread pool.
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            List of signal results
        """
        signals = self.get_signal_instances()
        
        def run_single(signal: BaseSignal) -> SignalResult:
            try:
                return signal.analyze(email)
            except Exception as e:
                self.log.error(
                    "signal_execution_failed",
                    signal=signal.name,
                    error=str(e)
                )
                return SignalResult(
                    signal=signal.name,
                    score=0,
                    severity=Severity.LOW,
                    reason=f"Signal execution failed: {str(e)}",
                    confidence=0.0,
                )
        
        # Execute in parallel
        futures = [
            self._executor.submit(run_single, signal)
            for signal in signals
        ]
        
        results = [future.result() for future in futures]
        return results
    
    def analyze(
        self,
        email: ParsedEmail,
        parallel: Optional[bool] = None
    ) -> ScanResult:
        """
        Perform complete analysis of an email.
        
        Args:
            email: Parsed email to analyze
            parallel: Whether to run signals in parallel
                     (defaults to settings.enable_parallel_signals)
        
        Returns:
            ScanResult with complete analysis
        """
        start_time = time.perf_counter()
        
        if parallel is None:
            parallel = self.settings.enable_parallel_signals
        
        # Run signals
        if parallel:
            signal_results = self.run_signals_parallel(email)
        else:
            signal_results = self.run_signals(email)
        
        # Calculate scores and verdict
        total_score = self.scoring_engine.calculate_total_score(signal_results)
        verdict = self.scoring_engine.generate_verdict(total_score)
        confidence = self.scoring_engine.calculate_confidence(signal_results, total_score)
        
        from app.pods.pod_b.explainability.summary_builder import (
            build_manager_summary,
            recommend_action,
        )

        triggered_signals = [
            r.signal for r in signal_results if r.score > 0
        ]

        manager_summary = build_manager_summary(triggered_signals, total_score)
        action_recommended = recommend_action(total_score)


        # Calculate duration
        duration_ms = (time.perf_counter() - start_time) * 1000
        
        self.log.info(
            "email_analysis_completed",
            email_id=email.email_id,
            tenant_id=email.tenant_id,
            verdict=verdict.value,
            total_score=total_score,
            confidence=confidence,
            duration_ms=round(duration_ms, 2),
            signals_run=len(signal_results)
        )
        
        return ScanResult(
            email_id=email.email_id,
            tenant_id=email.tenant_id,
            email_hash=email.email_hash,
            verdict=verdict,
            total_score=total_score,
            confidence=confidence,

            manager_summary=manager_summary,
            action_recommended=action_recommended,

            signals=signal_results,
            scan_duration_ms=round(duration_ms, 2),
            scanned_at=datetime.now(timezone.utc),
            version=self.settings.app_version,
)


class EmailScanner:
    """
    High-level email scanner combining parsing and signal analysis.
    
    This is the main entry point for email scanning, providing:
    - End-to-end email processing
    - Error handling at all stages
    - Structured logging with context
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the email scanner.
        
        Args:
            settings: Optional settings override
        """
        self.settings = settings or get_settings()
        self.log = get_logger(__name__)
        
        # Import here to avoid circular dependency
        from app.pods.pod_b.parser.email_parser import EmailParser
        
        self.parser = EmailParser(settings)
        self.orchestrator = SignalOrchestrator(settings)
    
    def scan(
        self,
        raw_email: str,
        tenant_id: str
    ) -> ScanResult:
        """
        Scan a raw email for phishing indicators.
        
        This is the main entry point for email scanning.
        
        Args:
            raw_email: Raw RFC 5322 email content
            tenant_id: Tenant identifier
        
        Returns:
            ScanResult with complete analysis
        """
        email_id = None
        
        with LogContext(tenant_id=tenant_id):
            # Parse email
            parsed_email, parse_error = self.parser.parse(raw_email, tenant_id)
            
        if parse_error:
            self.log.warning(
                "email_parse_failed_fallback_mode",
                tenant_id=tenant_id,
                error_code=parse_error.error_code,
                error_message=parse_error.error_message
            )

            # Generate deterministic 64-char SHA256 hash
            email_hash = hashlib.sha256(
                raw_email.encode("utf-8", errors="ignore")
            ).hexdigest()

            fallback_email = ParsedEmail(
                email_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                email_hash=email_hash,

                sender_email="unknown@unknown.local",
                sender_domain="unknown.local",
                sender_display_name="Unknown",

                reply_to=None,
                return_path=None,

                subject="",
                body_text=raw_email[:10000],   # analyze body safely
                body_html=None,

                links=[],
                attachments=[],

                received_at=datetime(1970, 1, 1, tzinfo=timezone.utc),
                ip_origin=None,
                received_headers=(),
            )

            # Continue scanning instead of ERROR
            return self.orchestrator.analyze(fallback_email)
            
        email_id = parsed_email.email_id
            
        with LogContext(email_id=email_id):
        # Run signal analysis
            result = self.orchestrator.analyze(parsed_email)
                
            return result


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def run_signals(parsed_email: dict) -> dict:
    """
    Legacy function for backward compatibility.
    
    Deprecated: Use EmailScanner or SignalOrchestrator instead.
    
    Args:
        parsed_email: Dictionary with email data
    
    Returns:
        Dictionary with scan results
    """
    # Convert dict to ParsedEmail
    email = ParsedEmail(
        email_id=parsed_email.get("email_id", "unknown"),
        tenant_id=parsed_email.get("tenant_id", "default"),
        email_hash=parsed_email.get("email_hash", ""),
        sender_email=parsed_email.get("sender_email", ""),
        sender_domain=parsed_email.get("sender_domain", ""),
        reply_to=parsed_email.get("reply_to"),
        subject=parsed_email.get("subject", ""),
        body_text=parsed_email.get("body_text", parsed_email.get("body", "")),
        links=[],
        attachments=[],
    )
    
    orchestrator = SignalOrchestrator()
    result = orchestrator.analyze(email)
    
    return {
        "total_score": result.total_score,
        "verdict": result.verdict.value,
        "signals": [
            {
                "signal": s.signal,
                "score": s.score,
                "severity": s.severity.value,
                "reason": s.reason,
            }
            for s in result.signals
        ]
    }


def generate_verdict(score: int) -> str:
    """
    Legacy function for backward compatibility.
    
    Deprecated: Use ScoringEngine.generate_verdict instead.
    
    Args:
        score: Total risk score
    
    Returns:
        Verdict string
    """
    engine = ScoringEngine()
    return engine.generate_verdict(score).value

def generate_email_hash(sender, subject, timestamp):
    raw_string = f"{sender}|{subject}|{timestamp}"
    return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()

def from_ocsf(data: dict) -> ParsedEmail:

    email_block = data.get("email", {})

    sender_email = email_block.get("sender")
    sender_domain = None

    if sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@")[-1]

    subject = email_block.get("subject", "")
    timestamp = data.get("time", "")

    raw_string = f"{sender_email}|{subject}|{timestamp}"
    email_hash = hashlib.sha256(
        raw_string.encode("utf-8")
    ).hexdigest()

    return ParsedEmail(
        email_id=data.get("email_id"),
        tenant_id=data.get("tenant_id"),
        email_hash=email_hash,

        sender_email=sender_email,
        sender_domain=sender_domain,
        reply_to=email_block.get("headers", {}).get("reply_to"),

        subject=subject,
        body_text=email_block.get("body", ""),
        body_html=None,

        links=[],
        attachments=email_block.get("attachments", []),

        received_at=datetime.now(timezone.utc),
        ip_origin=data.get("src_endpoint", {}).get("ip"),
        received_headers=(),
    )