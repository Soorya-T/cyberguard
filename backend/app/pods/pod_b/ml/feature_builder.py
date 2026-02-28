"""
Feature Builder for Pod B ML Boost Layer

Converts deterministic SignalResult objects into a
strict 7-feature numeric vector.

⚠ Any change to FEATURE_ORDER requires model retraining.
"""

from typing import List
from app.models.models import SignalResult, Severity


class FeatureBuilder:
    """
    Converts deterministic signals into a numeric feature vector.
    """

    # 🔒 STRICT FEATURE CONTRACT — DO NOT REORDER
    FEATURE_ORDER = [
        "domain_spoof",
        "reply_mismatch",
        "attachment_risk",
        "urgency_detected",
        "link_obfuscation",
        "signal_count",
        "high_severity_count",
    ]

    def build(self, signal_results: List[SignalResult]) -> List[float]:

        features = {
            "domain_spoof": 0,
            "reply_mismatch": 0,
            "attachment_risk": 0,
            "urgency_detected": 0,
            "link_obfuscation": 0,
            "signal_count": len(signal_results),
            "high_severity_count": 0,
        }

        for r in signal_results:

            if r.signal == "DOMAIN_SPOOF":
                features["domain_spoof"] = 1

            if r.signal == "REPLY_MISMATCH":
                features["reply_mismatch"] = 1

            if r.signal == "ATTACHMENT_RISK":
                features["attachment_risk"] = 1

            if r.signal in ("URGENCY_DETECTED", "URGENCY_LANGUAGE"):
                features["urgency_detected"] = 1

            if r.signal == "LINK_OBFUSCATION":
                features["link_obfuscation"] = 1

            if r.severity in (Severity.HIGH, Severity.CRITICAL):
                features["high_severity_count"] += 1

        return [features[name] for name in self.FEATURE_ORDER]
    