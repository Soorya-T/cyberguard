from app.pods.pod_b.signals.signal_engine import run_signals
from app.pods.pod_b.scoring.scoring_engine import compute_risk

def test_full_pipeline(phishing_email):
    signal_result = run_signals(phishing_email)

    risk_result = compute_risk(signal_result["signals"])

    assert risk_result["verdict"] == "PHISHING"
    assert risk_result["confidence"] in ["HIGH", "MEDIUM"]