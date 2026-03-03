from cyberguard.backend.app.pods.pod_b.scoring.scoring_engine import compute_risk

mock_signals = [
    {"signal": "DOMAIN_SPOOF", "score": 30},
    {"signal": "REPLY_MISMATCH", "score": 25},
    {"signal": "ATTACHMENT_RISK", "score": 30},
    {"signal": "URGENCY_LANGUAGE", "score": 10},
]

result = compute_risk(mock_signals)
print(result)