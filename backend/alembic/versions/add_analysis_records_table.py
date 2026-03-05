"""Add analysis_records table

Revision ID: add_analysis_records_table
Revises: 202602210000
Create Date: 2026-03-04 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_analysis_records_table'
down_revision = '3a2b4c5d6e7f'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'analysis_records',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('sender', sa.String(), nullable=False),
        sa.Column('subject', sa.String(), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('verdict', sa.String(), nullable=False),
        sa.Column('pdf_location', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('analysis_records')
