"""
Alembic Environment Configuration
=================================

This file connects Alembic with:

- Application database settings
- SQLAlchemy models metadata

It allows Alembic to:
- Detect model changes
- Generate migrations automatically
"""

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Import app settings and Base metadata
from app.core.config import settings
from app.db.base import Base

# Import models so Alembic can detect them
from app.models.user import User
from app.models.organization import Organization


# Alembic Config object
config = context.config

# Override database URL dynamically from config.py
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Configure logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Tell Alembic where models metadata is
target_metadata = Base.metadata


def run_migrations_offline():
    """
    Run migrations in offline mode.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """
    Run migrations in online mode.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()