"""create user activity

Revision ID: g7h8i9j0k1l2
Revises: f6g7h8i9j0k1
Create Date: 2023-07-20 11:25:18.765432

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = 'g7h8i9j0k1l2'
down_revision = 'f6g7h8i9j0k1'
branch_labels = None
depends_on = None


def upgrade():
    """Create user activity tracking and file uploads tables."""
    # User activity tracking
    op.create_table(
        'user_activities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('activity_type', sa.String(64), nullable=False),
        sa.Column('resource_type', sa.String(64), nullable=True),
        sa.Column('resource_id', sa.String(64), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_activities_user_id', 'user_activities', ['user_id'])
    op.create_index('ix_user_activities_activity_type', 'user_activities', ['activity_type'])
    op.create_index('ix_user_activities_created_at', 'user_activities', ['created_at'])

    # File uploads
    op.create_table(
        'file_uploads',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('original_filename', sa.String(255), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('mime_type', sa.String(128), nullable=False),
        sa.Column('file_hash', sa.String(64), nullable=False),
        sa.Column('storage_path', sa.String(512), nullable=False),
        sa.Column('public_url', sa.String(512), nullable=True),
        sa.Column('is_public', sa.Boolean(), nullable=False, default=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(), nullable=True),
        sa.Column('scan_result', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_file_uploads_user_id', 'file_uploads', ['user_id'])
    op.create_index('ix_file_uploads_mime_type', 'file_uploads', ['mime_type'])
    op.create_index('ix_file_uploads_file_hash', 'file_uploads', ['file_hash'])


def downgrade():
    """Revert the migration."""
    op.drop_table('file_uploads')
    op.drop_table('user_activities')
