"""add tenant_id to incidents table for multi-tenancy

Revision ID: 3a2b4c5d6e7f
Revises: 1ff363866437
Create Date: 2026-02-26 12:00:00.000000

Adds multi-tenant support to incidents table:
- Add tenant_id UUID column
- Backfill existing records with default tenant
- Add NOT NULL constraint
- Add index on tenant_id
- Add foreign key constraint to organizations(id)

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Default tenant ID for backfilling existing records
DEFAULT_TENANT_ID = '11111111-1111-1111-1111-111111111111'

# revision identifiers, used by Alembic.
revision: str = '3a2b4c5d6e7f'
down_revision: Union[str, None] = '1ff363866437'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Step 1: Add tenant_id column as nullable first (allows existing rows)
    op.add_column(
        'incidents',
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True)
    )
    
    # Step 2: Backfill existing records with default tenant value
    op.execute(
        f"UPDATE incidents SET tenant_id = '{DEFAULT_TENANT_ID}'::uuid WHERE tenant_id IS NULL"
    )
    
    # Step 3: Alter column to NOT NULL (now that all rows have values)
    op.alter_column(
        'incidents',
        'tenant_id',
        nullable=False
    )
    
    # Step 4: Add foreign key constraint to organizations(id)
    # The organizations table serves as the tenant table in this system
    op.create_foreign_key(
        'fk_incidents_tenant_id_organizations',
        'incidents',
        'organizations',
        ['tenant_id'],
        ['id'],
        ondelete='CASCADE'
    )
    
    # Step 5: Create index on tenant_id for efficient tenant-scoped queries
    op.create_index('ix_incidents_tenant_id', 'incidents', ['tenant_id'], unique=False)


def downgrade() -> None:
    # Remove index first
    op.drop_index('ix_incidents_tenant_id', table_name='incidents')
    # Remove foreign key constraint
    op.drop_constraint('fk_incidents_tenant_id_organizations', 'incidents', type_='foreignkey')
    # Remove NOT NULL constraint
    op.alter_column(
        'incidents',
        'tenant_id',
        nullable=True
    )
    # Remove the column
    op.drop_column('incidents', 'tenant_id')
