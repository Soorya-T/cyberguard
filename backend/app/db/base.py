"""
Database Base Definition
========================

Defines the SQLAlchemy Declarative Base.

All ORM models must inherit from this Base.
"""

from sqlalchemy.orm import declarative_base

# Base class for all database models
Base = declarative_base()

from app.models.user import User
from app.models.organization import Organization
from app.models.incident import Incident