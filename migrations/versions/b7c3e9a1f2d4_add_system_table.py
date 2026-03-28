"""add system table for System model

Revision ID: b7c3e9a1f2d4
Revises: a2f6fdc4fa4f
Create Date: 2026-03-28

"""
from alembic import op
import sqlalchemy as sa


revision = 'b7c3e9a1f2d4'
down_revision = 'a2f6fdc4fa4f'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if 'system' in inspector.get_table_names():
        return
    op.create_table(
        'system',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=500), nullable=False),
        sa.Column('token', sa.String(length=500), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', name='uq_system_name'),
        sa.UniqueConstraint('token', name='uq_system_token'),
    )


def downgrade():
    op.drop_table('system')
