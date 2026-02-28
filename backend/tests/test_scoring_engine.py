from app.pods.pod_b.scoring.scoring_engine import compute_risk


def test_scoring_high_risk():
    signals = [
        {"signal": "DOMAIN_SPOOF", "score": 30},
        {"signal": "REPLY_MISMATCH", "score": 25},
        {"signal": "ATTACHMENT_RISK", "score": 30},
    ]

    result = compute_risk(signals)

    assert result["final_score"] >= 70
    assert result["verdict"] == "PHISHING"