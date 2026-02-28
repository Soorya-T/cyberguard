import pytest


@pytest.fixture
def safe_email():
    return {
        "sender_email": "support@gmail.com",
        "sender_domain": "gmail.com",
        "reply_to": "",
        "subject": "Meeting reminder",
        "body": "Let's meet tomorrow.",
        "attachments": []
    }


@pytest.fixture
def phishing_email():
    return {
        "email_id": "1",
        "tenant_id": "test",
        "email_hash": "a" * 64,
        "sender_email": "attacker@paypa1.com",
        "sender_domain": "paypa1.com",
        "reply_to": "attacker@evil.com",
        "subject": "Urgent",
        "body": "Click immediately to avoid suspension",
        "attachments": [{"filename": "invoice.pdf.exe"}],
    }