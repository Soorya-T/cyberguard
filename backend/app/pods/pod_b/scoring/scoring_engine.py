"""
CyberGuard Pod B - Scoring Engine (TDD-Compliant)

Implements deterministic Base Score calculation
with optional ML Boost layer.
"""

from __future__ import annotations
from typing import Any, List, Optional, Dict

from app.pods.pod_b.ml.feature_builder import FeatureBuilder
from app.pods.pod_b.ml.ml_booster import MLBooster
from app.core.config import get_settings
from app.models.models import (
    SignalResult,
    Severity,
    Verdict,
)


class ScoringEngine:
    """
    Canonical deterministic scoring engine.

    TDD Requirement:
    Base Score must be calculated from hardcoded signal weights.
    """

    SIGNAL_WEIGHTS: Dict[str, int] = {
        "DOMAIN_SPOOF": 45,
        "REPLY_MISMATCH": 25,
        "ATTACHMENT_RISK": 30,
        "URGENCY_LANGUAGE": 15,
        "URGENCY_DETECTED": 15,
        "LINK_OBFUSCATION": 20,
    }

    def __init__(self, settings: Optional[Any] = None):
        self.settings = settings or get_settings()
        self.phishing_threshold = self.settings.phishing_threshold
        self.suspicious_threshold = self.settings.suspicious_threshold
        self.max_score = 100

    # ---------------------------------------------------------
    # 1️⃣ Base Score
    # ---------------------------------------------------------

    def calculate_base_score(self, signal_results: List[SignalResult]) -> int:
        total = 0

        for result in signal_results:
            weight = self.SIGNAL_WEIGHTS.get(result.signal, 0)
            total += weight

        return min(max(total, 0), self.max_score)

    # ---------------------------------------------------------
    # 2️⃣ Verdict Generation
    # ---------------------------------------------------------

    def generate_verdict(self, score: int) -> Verdict:
        if score >= self.phishing_threshold:
            return Verdict.PHISHING
        elif score >= self.suspicious_threshold:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.SAFE

    # ---------------------------------------------------------
    # 3️⃣ Full Risk Computation
    # ---------------------------------------------------------

    def compute_final_risk(self, signal_results: List[SignalResult]) -> dict:
        """
        Full deterministic + ML boosted risk computation.
        """

        # 1️⃣ Deterministic Base Score
        base_score = self.calculate_base_score(signal_results)

        # 2️⃣ Build Feature Vector for ML
        feature_builder = FeatureBuilder()
        feature_vector = feature_builder.build(signal_results)

        # ✅ SAFE DEBUG (remove later if needed)
        print("Feature vector length:", len(feature_vector))

        # 3️⃣ ML Boost Layer
        ml_booster = MLBooster()
        boost, ml_probability = ml_booster.get_boost(feature_vector)

        # 4️⃣ Deterministic Priority Enforcement
        if base_score >= self.phishing_threshold:
            final_score = base_score
        else:
            final_score = min(base_score + boost, self.max_score)

        # 5️⃣ Verdict
        verdict = self.generate_verdict(final_score)

        # 6️⃣ Confidence Calculation (blended)
        confidence = round(
            min(max((final_score / 100 + ml_probability) / 2, 0.0), 1.0),
            2
        )

        return {
            "final_score": final_score,
            "verdict": verdict.value,
            "confidence": confidence
        }


# ---------------------------------------------------------
# Backward Compatibility Wrapper
# ---------------------------------------------------------

def compute_risk(signal_results: List[dict]) -> dict:
    engine = ScoringEngine()

    results = [
        SignalResult(
            signal=s.get("signal", "UNKNOWN"),
            score=0,
            severity=Severity(s.get("severity", "LOW")),
            reason=s.get("reason", ""),
        )
        for s in signal_results
    ]

    return engine.compute_final_risk(results)


def normalize_score(score: float) -> int:
    return int(min(max(score, 0), 100))