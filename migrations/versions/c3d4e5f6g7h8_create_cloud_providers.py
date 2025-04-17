"""create cloud providers table

Revision ID: c3d4e5f6g7h8
Revises: b2c3d4e5f6g7
Create Date: 2023-05-27 14:22:34.567890

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = 'c3d4e5f6g7h8'
down_revision = 'b2c3d4e5f6g7'
branch_labels = None
depends_on = None


def upgrade():
    """Create cloud provider tables."""
    # Cloud providers
    op.create_table(
        'cloud_providers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(64), nullable=False),
        sa.Column('provider_type', sa.String(20), nullable=False),  # aws, azure, gcp
        sa.Column('status', sa.String(20), nullable=False, default='active'),
        sa.Column('credentials', sa.JSON(), nullable=True),  # Encrypted credentials
        sa.Column('regions', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_by_id', sa.Integer(), nullable=False),
        sa.Column('last_verification', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', 'provider_type', name='uq_provider_name_type')
    )
    op.create_index('ix_cloud_providers_provider_type', 'cloud_providers', ['provider_type'])
    op.create_index('ix_cloud_providers_status', 'cloud_providers', ['status'])

    # System configuration
    op.create_table(
        'system_configs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(64), nullable=False, unique=True),
        sa.Column('value', sa.JSON(), nullable=True),
        sa.Column('description', sa.String(255), nullable=True),
        sa.Column('is_encrypted', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_system_configs_key', 'system_configs', ['key'])


def downgrade():
    """Revert the migration."""
    op.drop_table('system_configs')
    op.drop_table('cloud_providers')
