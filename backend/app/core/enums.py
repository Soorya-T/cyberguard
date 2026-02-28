"""
Enumeration Module
==================

Defines enumerations used across the application.
"""

from enum import Enum


class IncidentStatus(str, Enum):
    """Lifecycle statuses for security incidents."""

    OPEN = "OPEN"
    REVIEW = "REVIEW"
    CLOSED = "CLOSED"
