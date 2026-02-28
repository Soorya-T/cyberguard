import pytest
from app.pods.pod_b.parser.email_parser import parse_email


def test_parse_pod_a_json_payload():

    pod_a_event = {
        "time": "2026-02-22T09:00:00+00:00",
        "src_endpoint": {
            "ip": "192.168.1.10"
        },
        "email": {
            "sender": "attacker@evil.com",
            "subject": "Urgent Action Required",
            "attachments": [
                {"filename": "invoice.pdf.exe"}
            ]
        },
        "http": {
            "url": "http://malicious-site.com"
        }
    }

    parsed_email, error = parse_email(pod_a_event, tenant_id="test")

    assert error is None
    assert parsed_email is not None

    assert parsed_email.sender_email == "attacker@evil.com"
    assert parsed_email.subject == "Urgent Action Required"
    assert parsed_email.ip_origin == "192.168.1.10"
    assert len(parsed_email.email_hash) == 64