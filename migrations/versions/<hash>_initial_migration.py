from alembic import op
import sqlalchemy as sa

"""Initial migration

Revision ID: <hash>
Revises: 
Create Date: 2023-10-05 12:00:00.000000

"""

# Revision identifiers, used by Alembic.
revision = '<hash>'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Apply the migration."""
    # Example: Create a table
    op.create_table(
        'example_table',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now(), nullable=False),
    )


def downgrade():
    """Revert the migration."""
    # Example: Drop the table
    op.drop_table('example_table')