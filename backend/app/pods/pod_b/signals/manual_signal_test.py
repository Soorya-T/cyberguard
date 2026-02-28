import json
from pathlib import Path

from app.pods.pod_b.signals.signal_engine import (
    EmailScanner,
    SignalOrchestrator
)


def run_manual_signal_test():
    # Load JSON input
    file_path = Path(__file__).parent / "test_input.json"

    with open(file_path, "r") as f:
        data = json.load(f)

    scanner = EmailScanner()

    result = scanner.scan(
        raw_email=data["raw_email"],
        tenant_id=data["tenant_id"]
    )
    
    triggered_signals = [
    s.signal
    for s in result.signals
    if s.score > 0
]
    
    # Build structured output
    output = {
    "final_score": result.total_score,
    "verdict": result.verdict.value,
    "confidence": result.confidence,
    "manager_summary": result.manager_summary,
    "action_recommended": result.action_recommended,
    "triggered_signals": triggered_signals,
    "signals": [
        {
            "signal": s.signal,
            "score": s.score,
            "severity": s.severity.value,
            "reason": s.reason,
            "confidence": s.confidence,
        }
        for s in result.signals
    ]
}

    print("\n===== SIGNAL RESULT =====")
    print(result.model_dump_json(indent=2))

if __name__ == "__main__":
    run_manual_signal_test()



    