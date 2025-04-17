"""create ics tables

Revision ID: e5f6g7h8i9j0
Revises: d4e5f6g7h8i9
Create Date: 2023-06-30 09:15:22.345678

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = 'e5f6g7h8i9j0'
down_revision = 'd4e5f6g7h8i9'
branch_labels = None
depends_on = None


def upgrade():
    """Create ICS (Industrial Control System) related tables."""
    # ICS Devices
    op.create_table(
        'ics_devices',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('device_type', sa.String(64), nullable=False),
        sa.Column('location', sa.String(128), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('protocol', sa.String(32), nullable=False),
        sa.Column('status', sa.String(32), nullable=False, default='online'),
        sa.Column('last_communication', sa.DateTime(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('settings', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_ics_devices_status', 'ics_devices', ['status'])
    op.create_index('ix_ics_devices_device_type', 'ics_devices', ['device_type'])

    # ICS Readings (sensor data)
    op.create_table(
        'ics_readings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('reading_type', sa.String(64), nullable=False),
        sa.Column('value', sa.Float(), nullable=False),
        sa.Column('unit', sa.String(32), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('is_anomaly', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['ics_devices.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_ics_readings_device_id', 'ics_readings', ['device_id'])
    op.create_index('ix_ics_readings_reading_type', 'ics_readings', ['reading_type'])
    op.create_index('ix_ics_readings_timestamp', 'ics_readings', ['timestamp'])
    op.create_index('ix_ics_readings_is_anomaly', 'ics_readings', ['is_anomaly'])

    # ICS Control Logs (who did what to which device)
    op.create_table(
        'ics_control_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(64), nullable=False),
        sa.Column('value', sa.String(255), nullable=True),
        sa.Column('previous_value', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['ics_devices.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_ics_control_logs_device_id', 'ics_control_logs', ['device_id'])
    op.create_index('ix_ics_control_logs_user_id', 'ics_control_logs', ['user_id'])
    op.create_index('ix_ics_control_logs_action', 'ics_control_logs', ['action'])


def downgrade():
    """Revert the migration."""
    op.drop_table('ics_control_logs')
    op.drop_table('ics_readings')
    op.drop_table('ics_devices')
