"""add user session table

Revision ID: a8b9c0d1e2f3
Revises: b2c3d4e5f6g7
Create Date: 2023-10-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# Revision identifiers, used by Alembic.
revision = 'a8b9c0d1e2f3'
down_revision = 'b2c3d4e5f6g7'
branch_labels = None
depends_on = None


def upgrade():
    """Create user session table for tracking authenticated sessions."""
    # Create user_session table if it doesn't already exist
    # Note: The user sessions table is already created in b2c3d4e5f6g7_create_security_tables.py
    # This is a conditional creation to prevent errors if the table already exists
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if 'user_session' not in inspector.get_table_names():
        op.create_table(
            'user_session',
            sa.Column('id', sa.String(36), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('session_token', sa.String(length=255), nullable=False, unique=True),
            sa.Column('ip_address', sa.String(45), nullable=False),
            sa.Column('user_agent', sa.String(255), nullable=True),
            sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
            sa.Column('last_active', sa.DateTime, nullable=False, server_default=sa.func.now()),
            sa.Column('expires_at', sa.DateTime, nullable=False),
            sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index('ix_user_session_user_id', 'user_session', ['user_id'])
        op.create_index('ix_user_session_is_active', 'user_session', ['is_active'])


def downgrade():
    """Drop user session table."""
    # Check if table exists before dropping
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if 'user_session' in inspector.get_table_names():
        op.drop_index('ix_user_session_is_active', table_name='user_session')
        op.drop_index('ix_user_session_user_id', table_name='user_session')
        op.drop_table('user_session')
