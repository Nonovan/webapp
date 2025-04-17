"""create security tables

Revision ID: b2c3d4e5f6g7
Revises: a1b2c3d4e5f6
Create Date: 2023-05-20 11:45:12.345678

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = 'b2c3d4e5f6g7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    """Create security-related tables."""
    # Audit logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('description', sa.String(255), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(255), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_logs_event_type', 'audit_logs', ['event_type'])
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_logs_severity', 'audit_logs', ['severity'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])

    # Security incidents
    op.create_table(
        'security_incidents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(128), nullable=False),
        sa.Column('incident_type', sa.String(50), nullable=False),
        sa.Column('description', sa.String(255), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('source', sa.String(50), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('resolution', sa.Text(), nullable=True),
        sa.Column('assigned_to', sa.Integer(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_security_incidents_incident_type', 'security_incidents', ['incident_type'])
    op.create_index('ix_security_incidents_severity', 'security_incidents', ['severity'])
    op.create_index('ix_security_incidents_status', 'security_incidents', ['status'])

    # User sessions for tracking and security
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('user_agent', sa.String(255), nullable=True),
        sa.Column('login_timestamp', sa.DateTime(), nullable=False),
        sa.Column('last_active', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_sessions_user_id', 'user_sessions', ['user_id'])
    op.create_index('ix_user_sessions_is_active', 'user_sessions', ['is_active'])


def downgrade():
    """Revert the migration."""
    op.drop_table('user_sessions')
    op.drop_table('security_incidents')
    op.drop_table('audit_logs')
