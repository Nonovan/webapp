"""create cloud resources table

Revision ID: a1b2c3d4e5f6
Revises: previous_revision_id
Create Date: 2023-06-15 10:30:45.678901

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = 'a1b2c3d4e5f6'
down_revision = 'previous_revision_id'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'cloud_resources',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('resource_id', sa.String(128), nullable=False),
        sa.Column('provider_id', sa.Integer(), nullable=False),
        sa.Column('resource_type', sa.String(64), nullable=False),
        sa.Column('region', sa.String(64), nullable=False),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('created_by_id', sa.Integer(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['provider_id'], ['cloud_providers.id']),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_cloud_resources_resource_type', 'cloud_resources', ['resource_type'])
    op.create_index('ix_cloud_resources_region', 'cloud_resources', ['region'])
    op.create_index('ix_cloud_resources_status', 'cloud_resources', ['status'])


def downgrade():
    op.drop_index('ix_cloud_resources_status')
    op.drop_index('ix_cloud_resources_region')
    op.drop_index('ix_cloud_resources_resource_type')
    op.drop_table('cloud_resources')
