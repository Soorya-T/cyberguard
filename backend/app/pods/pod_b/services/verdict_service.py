from typing import Dict, List
from ..parser.email_parser import parse_email
from app.pods.pod_b.signals.signal_engine import SignalOrchestrator, from_ocsf


# In-memory idempotency protection (temporary until DB layer)
PROCESSED_EVENTS = {}
 
class VerdictService:

    def analyze(self, email_data: Dict) -> Dict:

        event_id = email_data["email_id"]

        # -------- Idempotency --------
        if event_id in PROCESSED_EVENTS:
            return PROCESSED_EVENTS[event_id]

    # -------- Parse OCSF --------
        parsed_email = from_ocsf(email_data)

    # -------- Run Detection --------
        orchestrator = SignalOrchestrator()
        result = orchestrator.analyze(parsed_email)

        risk_score = result.total_score

    # -------- Action Mapping (Verdict Layer Responsibility) --------
        if risk_score >= 80:
            action = "QUARANTINE"
        elif risk_score >= 40:
            action = "REVIEW"
        else:
            action = "ALLOW"

    # -------- Triggered Signals --------
        triggered = [s for s in result.signals if s.score > 0]
        reasons = [s.reason for s in triggered]

    # -------- Manager Summary --------
        manager_summary = self._generate_summary(
            risk_score=risk_score,
            triggered=triggered,
            reasons=reasons,
            action=action
        )

        verdict = {
            "event_id": result.email_id,
            "tenant_id": result.tenant_id,
            "risk_score": risk_score,
            "confidence_level": result.confidence,
            "triggered_signals": [s.signal for s in triggered],
            "manager_summary": manager_summary,
            "incident_graph": None,
            "action_recommended": action
        }

        PROCESSED_EVENTS[event_id] = verdict
        print("ALL SIGNALS:", result.signals)

        for s in result.signals:
            print("Signal:", s.signal, "Score:", s.score)
        return verdict


# ------------------------------------------------------
# Deterministic Explainability Engine (TDD 8.3 Compliant)
# ------------------------------------------------------
    def _generate_summary(self, risk_score, triggered, reasons, action):

        if not triggered:
            return (
                "The email appears to be legitimate. "
                "No phishing indicators were detected during analysis. "
                "No action has been taken."
            )

        threat_sentence = (
            "A potentially malicious email was detected in your environment."
        )

        evidence_sentence = (
            "The system identified the following indicators: "
            + ", ".join(reasons) + "."
        )

        if action == "QUARANTINE":
            action_sentence = (
                "Due to the high risk level, the system recommends quarantining this email immediately."
            )
        elif action == "REVIEW":
            action_sentence = (
                "The email requires manual review by a security analyst."
            )
        else:
            action_sentence = (
                "No containment action is required at this time."
            )

        return f"{threat_sentence} {evidence_sentence} {action_sentence}"