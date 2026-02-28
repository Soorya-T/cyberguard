TEMPLATES = {
    "DOMAIN_SPOOF": {
        "title": "Domain Spoofing Detected",
        "technical_explanation": "Sender domain mimics a legitimate service.",
        "risk_context": "Users may trust spoofed domains unknowingly.",
        "attacker_behavior": "Impersonation of trusted brands.",
        "operator_action": "Verify sender domain before responding."
    },
    "REPLY_TO_MISMATCH": {
        "title": "Reply-To Mismatch Identified",
        "technical_explanation": "Reply-to address differs from sender.",
        "risk_context": "Responses may go to attacker mailbox.",
        "attacker_behavior": "Phishing redirection tactic.",
        "operator_action": "Do not reply without validation."
    },
    "SHORT_LINK": {
        "title": "Shortened URL Detected",
        "technical_explanation": "URL shortening service used.",
        "risk_context": "Destination may hide malicious site.",
        "attacker_behavior": "Obfuscation of phishing links.",
        "operator_action": "Expand link before clicking."
    },
    "URGENCY_LANGUAGE": {
        "title": "Urgency Language Detected",
        "technical_explanation": "Email uses pressure-based wording.",
        "risk_context": "Forces quick reaction.",
        "attacker_behavior": "Psychological manipulation.",
        "operator_action": "Pause and verify legitimacy."
    },
    "EXECUTABLE_ATTACHMENT": {
        "title": "Executable Attachment Detected",
        "technical_explanation": "Email contains executable file.",
        "risk_context": "May deliver malware payload.",
        "attacker_behavior": "Malware distribution.",
        "operator_action": "Do not open attachment."
    },
    "ATTACHMENT_MACRO": {
        "title": "Macro-Enabled Document Detected",
        "technical_explanation": "Attachment contains macros.",
        "risk_context": "Macros can execute malicious code.",
        "attacker_behavior": "Ransomware delivery tactic.",
        "operator_action": "Disable macros and verify file."
    },
    "SPF_FAIL": {
        "title": "SPF Authentication Failed",
        "technical_explanation": "Sender failed SPF validation.",
        "risk_context": "Email may be spoofed.",
        "attacker_behavior": "Domain spoofing attempt.",
        "operator_action": "Verify sender authenticity."
    },
    "DKIM_FAIL": {
        "title": "DKIM Signature Invalid",
        "technical_explanation": "DKIM validation failed.",
        "risk_context": "Message integrity compromised.",
        "attacker_behavior": "Header manipulation.",
        "operator_action": "Treat as suspicious."
    },
    "SUSPICIOUS_IP": {
        "title": "Suspicious Sending IP",
        "technical_explanation": "IP flagged in threat feeds.",
        "risk_context": "Known malicious infrastructure.",
        "attacker_behavior": "Botnet-based sending.",
        "operator_action": "Block IP and investigate."
    },
    "CREDENTIAL_FORM_LINK": {
        "title": "Credential Harvesting Link",
        "technical_explanation": "Email contains login-like form link.",
        "risk_context": "May steal user credentials.",
        "attacker_behavior": "Account takeover phishing.",
        "operator_action": "Do not enter credentials."
    }
}

severity_order = {
    "EXECUTABLE_ATTACHMENT": 1,
    "ATTACHMENT_MACRO": 2,
    "CREDENTIAL_FORM_LINK": 3,
    "DOMAIN_SPOOF": 4,
    "SPF_FAIL": 5,
    "DKIM_FAIL": 6,
    "REPLY_TO_MISMATCH": 7,
    "SHORT_LINK": 8,
    "SUSPICIOUS_IP": 9,
    "URGENCY_LANGUAGE": 10
}

def expand_signals(signals):
    expanded = []

    for signal in signals:
        # Normalize signal format
        normalized = signal.upper().replace(" ", "_")

        if normalized in TEMPLATES:
            expanded.append(TEMPLATES[normalized])
        else:
            # Fallback template for unknown signals
            expanded.append({
                "title": signal,
                "technical_explanation": "Signal detected but no detailed template found.",
                "risk_context": "This signal may indicate suspicious behavior.",
                "attacker_behavior": "Potential phishing tactic.",
                "operator_action": "Investigate this signal manually."
            })

    return expanded