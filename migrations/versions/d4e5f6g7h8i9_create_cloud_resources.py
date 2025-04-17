"""create cloud resources table

Revision ID: d4e5f6g7h8i9
Revises: c3d4e5f6g7h8
Create Date: 2023-06-15 10:30:45.678901

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = 'd4e5f6g7h8i9'
down_revision = 'c3d4e5f6g7h8'
branch_labels = None
depends_on = None


def upgrade():
    """Create cloud resource related tables."""
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
    
    # Cloud metrics
    op.create_table(
        'cloud_metrics',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('resource_id', sa.Integer(), nullable=False),
        sa.Column('metric_name', sa.String(64), nullable=False),
        sa.Column('metric_value', sa.Float(), nullable=False),
        sa.Column('unit', sa.String(32), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('dimensions', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['resource_id'], ['cloud_resources.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_cloud_metrics_resource_id', 'cloud_metrics', ['resource_id'])
    op.create_index('ix_cloud_metrics_metric_name', 'cloud_metrics', ['metric_name'])
    op.create_index('ix_cloud_metrics_timestamp', 'cloud_metrics', ['timestamp'])

    # Cloud alerts
    op.create_table(
        'cloud_alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('resource_id', sa.Integer(), nullable=True),
        sa.Column('alert_type', sa.String(64), nullable=False),
        sa.Column('title', sa.String(128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, default='active'),
        sa.Column('acknowledged_by', sa.Integer(), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('notification_sent', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['resource_id'], ['cloud_resources.id']),
        sa.ForeignKeyConstraint(['acknowledged_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_cloud_alerts_alert_type', 'cloud_alerts', ['alert_type'])
    op.create_index('ix_cloud_alerts_status', 'cloud_alerts', ['status'])
    op.create_index('ix_cloud_alerts_severity', 'cloud_alerts', ['severity'])


def downgrade():
    """Revert the migration."""
    op.drop_table('cloud_alerts')
    op.drop_table('cloud_metrics')
    op.drop_table('cloud_resources')
