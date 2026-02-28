# summary_builder.py

from typing import List
from .translator import translate_signals


def severity_label(score: int) -> str:
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high-risk"
    elif score >= 40:
        return "suspicious"
    return "low-risk"


def recommend_action(score: int) -> str:
    if score >= 90:
        return "QUARANTINE"
    elif score >= 70:
        return "REVIEW"
    return "ALLOW"


def build_manager_summary(triggered_signals: List[str], score: int) -> str:
    translated = translate_signals(triggered_signals)

    threat = f"This email is classified as a {severity_label(score)} phishing attempt."
    evidence = " ".join(translated)

    if score >= 90:
        action = "CyberGuard has automatically quarantined this message to protect your organization."
    elif score >= 70:
        action = "We recommend immediate review before interacting with this message."
    else:
        action = "No automatic action has been taken."

    return f"{threat} {evidence} {action}"