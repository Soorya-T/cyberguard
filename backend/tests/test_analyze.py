import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


# ----------------------------
# SUCCESS CASE
# ----------------------------

def test_analyze_email_success():
    response = client.post("/analyze", json={
        "sender": "attacker@fake-bank.com",
        "subject": "URGENT: Verify your account",
        "body": "Click here immediately to verify your bank account.",
        "links": []
    })

    assert response.status_code == 200

    data = response.json()

    assert "status" in data
    assert "risk_score" in data
    assert "signals_detected" in data
    assert "analysis_results" in data

    assert isinstance(data["risk_score"], float)
    assert 0.0 <= data["risk_score"] <= 100.0
    assert isinstance(data["signals_detected"], list)
    assert isinstance(data["analysis_results"], list)


# ----------------------------
# INVALID PAYLOAD (extra field)
# ----------------------------

def test_analyze_invalid_payload():
    response = client.post("/analyze", json={
        "sender": "test@email.com",
        "subject": "Test",
        "body": "Test body",
        "invalid_field": "not allowed"
    })

    assert response.status_code == 422


# ----------------------------
# MISSING REQUIRED FIELD
# ----------------------------

def test_analyze_missing_required_field():
    response = client.post("/analyze", json={
        "sender": "test@email.com",
        "subject": "Missing body"
    })

    assert response.status_code == 422


# ----------------------------
# EMPTY BODY (min_length=1)
# ----------------------------

def test_analyze_empty_body():
    response = client.post("/analyze", json={
        "sender": "test@email.com",
        "subject": "Empty Body Test",
        "body": ""
    })

    assert response.status_code == 422


# ----------------------------
# LARGE EMAIL BODY
# ----------------------------

def test_analyze_large_email():
    large_text = "phishing " * 3000

    response = client.post("/analyze", json={
        "sender": "attacker@evil.com",
        "subject": "Important Security Notice",
        "body": large_text,
        "links": []
    })

    assert response.status_code == 200

    data = response.json()
    assert isinstance(data["risk_score"], float)


# ----------------------------
# WRONG TYPE (sender not email)
# ----------------------------

def test_analyze_wrong_type():
    response = client.post("/analyze", json={
        "sender": "not-an-email",
        "subject": "Test",
        "body": "Test body"
    })

    assert response.status_code == 422


# ----------------------------
# SQL INJECTION CONTENT (should not crash)
# ----------------------------

def test_analyze_sql_injection():
    response = client.post("/analyze", json={
        "sender": "attacker@evil.com",
        "subject": "Security Update",
        "body": "' OR 1=1 -- DROP TABLE users;",
        "links": []
    })

    # Should process normally, not crash
    assert response.status_code == 200


# ----------------------------
# RESPONSE STRUCTURE VALIDATION
# ----------------------------

def test_analyze_response_types():
    response = client.post("/analyze", json={
        "sender": "attacker@fake-bank.com",
        "subject": "Account Suspended",
        "body": "Click here to verify immediately.",
        "links": ["http://fake-bank-verify.com"]
    })

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data["status"], str)
    assert isinstance(data["signals_detected"], list)
    assert isinstance(data["analysis_results"], list)
    assert isinstance(data["risk_score"], float)

    if data["analysis_results"]:
        result = data["analysis_results"][0]
        assert "signal" in result
        assert "severity" in result
        assert "description" in result
        assert "recommendation" in result