from alembic import op
import sqlalchemy as sa

"""add user session table

Revision ID: <hash>
Revises: <previous_revision>
Create Date: 2023-10-01 12:00:00.000000

"""

# Revision identifiers, used by Alembic.
revision = '<hash>'
down_revision = '<previous_revision>'
branch_labels = None
depends_on = None


def upgrade():
    # Create user_session table
    op.create_table(
        'user_session',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, nullable=False),
        sa.Column('session_token', sa.String(length=255), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE')
    )


def downgrade():
    # Drop user_session table
    op.drop_table('user_session')