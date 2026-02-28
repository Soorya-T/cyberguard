"""
Role Enumeration Module
=======================

Defines all valid roles in the system.

Security Purpose:
- Prevents arbitrary role injection
- Prevents frontend role manipulation
- Enforces strict backend validation
"""

from enum import Enum


class Role(str, Enum):
    """
    System-wide allowed roles.
    """

    SUPER_ADMIN = "SUPER_ADMIN"
    ORG_ADMIN = "ORG_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    READ_ONLY = "READ_ONLY"
