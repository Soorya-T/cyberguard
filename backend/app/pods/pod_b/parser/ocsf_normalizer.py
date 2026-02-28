"""
CyberGuard Pod B - OCSF Normalization Layer

This module converts raw Pod A JSON payloads into
standardized internal structures before email parsing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.logging import get_logger

log = get_logger(__name__)


class OCSFNormalizer:
    """
    Normalizes raw OCSF-aligned JSON into
    universally understood security entities.
    """

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Pod A JSON payload.

        Returns standardized entity map.
        """

        normalized = {
            "event_time": self._normalize_timestamp(raw_event.get("time")),
            "src_ip": self._extract_nested(raw_event, ["src_endpoint", "ip"]),
            "email_sender": self._extract_nested(raw_event, ["email", "sender"]),
            "email_subject": self._extract_nested(raw_event, ["email", "subject"]),
            "body_text": self._extract_nested(raw_event, ["email", "body"]),
            "reply_to": self._extract_nested(raw_event, ["email", "headers", "reply_to"]),
            "http_url": self._extract_nested(raw_event, ["http", "url"]),
            "attachments": self._extract_nested(raw_event, ["email", "attachments"], default=[]),
            "raw_email": raw_event.get("raw_email"),
        }

        return normalized

    def _extract_nested(
        self,
        data: Dict[str, Any],
        path: List[str],
        default: Optional[Any] = None
    ) -> Any:
        """Safely extract nested JSON values."""
        current = data

        for key in path:
            if not isinstance(current, dict):
                return default
            current = current.get(key)

        return current if current is not None else default

    def _normalize_timestamp(self, timestamp: Any) -> datetime:

        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)

        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp).astimezone(timezone.utc)
            except Exception:
                pass

        raise ValueError("Invalid or missing OCSF event_time")