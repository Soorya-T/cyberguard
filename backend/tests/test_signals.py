import pytest

from app.pods.pod_b.signals.signal_engine import EmailScanner


# -------------------------------------------------
# FIXTURE: Use real scanner instead of fake model
# -------------------------------------------------
@pytest.fixture
def phishing_result():
    raw_email = """\
From: support@fakebank-secure.com
To: victim@example.com
Subject: URGENT: Verify your account now

Click this link immediately or your account will be suspended.
Visit http://fakebank-login.com
"""

    scanner = EmailScanner()
    result = scanner.scan(raw_email, tenant_id="tenant1")

    return result


# -------------------------------------------------
# TEST 1: Ensure scan runs successfully
# -------------------------------------------------
def test_scan_runs(phishing_result):
    assert phishing_result.total_score >= 0
    assert phishing_result.verdict is not None
    assert phishing_result.confidence >= 0.0


# -------------------------------------------------
# TEST 2: Ensure signals were executed
# -------------------------------------------------
def test_signals_executed(phishing_result):
    assert len(phishing_result.signals) > 0