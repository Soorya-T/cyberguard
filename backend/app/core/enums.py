"""
Enumeration Module
==================

Defines enumerations used across the application.
"""

from enum import Enum


class IncidentStatus(str, Enum):
    """Lifecycle statuses for security incidents."""

    RECEIVED = "RECEIVED"
    OPEN = "OPEN"
    PROCESSING = "PROCESSING"
    REVIEW = "REVIEW"
    CLOSED = "CLOSED"
