"""Add updated_at columns and improve model structure

Revision ID: 202602210000
Revises: 9d43abf04909
Create Date: 2026-02-21 00:00:00.000000

Changes:
- Add updated_at column to users table
- Add updated_at column to organizations table
- Add indexes for better query performance
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '202602210000'
down_revision: Union[str, None] = '9d43abf04909'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply migration changes."""
    
    # ------------------------------
    # Add updated_at to organizations
    # ------------------------------
    op.add_column(
        'organizations',
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False
        )
    )
    
    # ------------------------------
    # Add updated_at to users
    # ------------------------------
    op.add_column(
        'users',
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False
        )
    )
    
    # ------------------------------
    # Add indexes for performance
    # ------------------------------
    
    # Index on role for filtering by role
    op.create_index(
        'ix_users_role',
        'users',
        ['role'],
        unique=False
    )
    
    # Composite index for tenant + role queries
    op.create_index(
        'ix_users_tenant_role',
        'users',
        ['tenant_id', 'role'],
        unique=False
    )
    
    # Index for active users queries
    op.create_index(
        'ix_users_is_active',
        'users',
        ['is_active'],
        unique=False
    )
    
    # Index for locked accounts
    op.create_index(
        'ix_users_is_locked',
        'users',
        ['is_locked'],
        unique=False
    )


def downgrade() -> None:
    """Revert migration changes."""
    
    # Drop indexes
    op.drop_index('ix_users_is_locked', table_name='users')
    op.drop_index('ix_users_is_active', table_name='users')
    op.drop_index('ix_users_tenant_role', table_name='users')
    op.drop_index('ix_users_role', table_name='users')
    
    # Drop columns
    op.drop_column('users', 'updated_at')
    op.drop_column('organizations', 'updated_at')