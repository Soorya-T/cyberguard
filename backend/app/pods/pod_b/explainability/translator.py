# translator.py

from typing import List

TRANSLATION_MAP = {
    "SUSPICIOUS_TLD": "The email contains links to unusual or newly registered web domains often associated with fraudulent websites.",
    "REPLY_MISMATCH": "Replies to this email are redirected to an unrelated external address.",
    "URGENCY_LANGUAGE": "The message pressures the recipient to act immediately, a common tactic used in phishing scams.",
    "DOMAIN_SPOOF": "The sender address appears to impersonate a trusted organization.",
    "ATTACHMENT_RISK": "The email contains potentially dangerous file attachments."
}


def translate_signals(triggered_signals: List[str]) -> List[str]:
    return [
        TRANSLATION_MAP.get(signal, "The email triggered additional security checks.")
        for signal in triggered_signals
    ]