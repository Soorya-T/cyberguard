"""convert role to enum

Revision ID: 9d43abf04909
Revises: 202602201230
Create Date: 2026-02-20 22:42:46.017686
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '9d43abf04909'
down_revision: Union[str, None] = '202602201230'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# 🔐 Define enum manually
role_enum = sa.Enum(
    'SUPER_ADMIN',
    'ORG_ADMIN',
    'SECURITY_ANALYST',
    'READ_ONLY',
    name='role_enum'
)


def upgrade() -> None:
    # -----------------------------
    # Create enum type
    # -----------------------------
    role_enum.create(op.get_bind(), checkfirst=True)

    # -----------------------------
    # Drop existing default first
    # -----------------------------
    op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")

    # -----------------------------
    # Convert column to enum
    # -----------------------------
    op.alter_column(
        'users',
        'role',
        existing_type=sa.VARCHAR(),
        type_=role_enum,
        postgresql_using="role::text::role_enum",
        existing_nullable=False
    )

    # -----------------------------
    # Set new enum default
    # -----------------------------
    op.execute(
        "ALTER TABLE users ALTER COLUMN role SET DEFAULT 'READ_ONLY'"
    )   


def downgrade() -> None:
    # Drop enum default
    op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")

    # Convert back to varchar
    op.alter_column(
        'users',
        'role',
        existing_type=role_enum,
        type_=sa.VARCHAR(),
        postgresql_using="role::text",
        existing_nullable=False
    )

    # Restore varchar default
    op.execute(
        "ALTER TABLE users ALTER COLUMN role SET DEFAULT 'READ_ONLY'"
    )

    # Drop enum type
    role_enum.drop(op.get_bind(), checkfirst=True)