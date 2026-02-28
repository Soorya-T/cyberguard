from app.pods.pod_b.parser.email_parser import parse_email


def test_parser_extracts_domain():
    raw_email = {
        "sender": "support@paypal.com"
    }

    # Adjust depending on your parser signature
    result = parse_email(raw_email, tenant_id="test")
    assert result["sender_domain"] == "paypal.com"