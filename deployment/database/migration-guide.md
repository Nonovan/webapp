# Database Migration Guide

This document provides guidelines for creating, testing, and deploying database migrations for the Cloud Infrastructure Platform.

## Overview

The application uses Alembic (via Flask-Migrate) for database migrations. This allows us to:

1. Track changes to the database schema
2. Apply changes in a consistent manner across environments
3. Roll back changes if necessary
4. Maintain a history of database schema evolution

## Creating Migrations

### Automatic Migrations

To create an automatic migration based on model changes:

```bash
flask db migrate -m "Description of the changes"

```

This will generate a new migration script in the versions directory.

### Manual Migrations

For complex changes, create a manual migration:

```bash
flask db revision -m "Description of the changes"

```

Then edit the generated file to add your custom upgrade and downgrade operations.

## Best Practices for Writing Migrations

1. **Review Automatic Migrations**: Always review auto-generated migrations before applying them
2. **Test Migrations**: Test migrations thoroughly before applying to production
3. **Idempotency**: Ensure operations are idempotent where possible
4. **Add Comments**: Add detailed comments explaining complex operations
5. **Transaction Safety**: Ensure migrations are transaction-safe
6. **Downgrade Support**: Always implement downgrade methods
7. **Data Migration**: Handle data migrations separately from schema changes when possible

## Common Migration Patterns

### Adding a Column

```python
def upgrade():
    op.add_column('table_name', sa.Column('column_name', sa.String(50), nullable=True))

    # If you need to fill the column with data
    op.execute("UPDATE table_name SET column_name = 'default_value'")

    # Then you can make it non-nullable if needed
    op.alter_column('table_name', 'column_name', nullable=False)

def downgrade():
    op.drop_column('table_name', 'column_name')

```

### Renaming a Column

```python
def upgrade():
    op.alter_column('table_name', 'old_column_name', new_column_name='new_column_name')

def downgrade():
    op.alter_column('table_name', 'new_column_name', new_column_name='old_column_name')

```

### Creating Indexes

```python
def upgrade():
    op.create_index('ix_table_column', 'table_name', ['column_name'], unique=False)

def downgrade():
    op.drop_index('ix_table_column', 'table_name')

```

## Applying Migrations

### Development Environment

```bash
flask db upgrade

```

### Production Environment

Always take a database backup before applying migrations in production:

```bash
# 1. Backup the database
pg_dump -U username -d database_name -f backup_$(date +%Y%m%d_%H%M%S).sql

# 2. Apply migrations
flask db upgrade

```

## Rolling Back Migrations

To roll back the most recent migration:

```bash
flask db downgrade

```

To roll back to a specific migration:

```bash
flask db downgrade <migration_id>

```

## Handling Migration Conflicts

If you encounter migration conflicts (multiple developers creating migrations simultaneously):

1. Keep the migration that was created first (by timestamp)
2. Delete the other conflicting migration file
3. Create a new migration that includes the changes from the deleted migration

## Disaster Recovery

In case of failed migrations:

1. Check the error message and logs
2. Roll back the failed migration: `flask db downgrade`
3. Fix the issue in the migration script
4. Apply the corrected migration: `flask db upgrade`

If the database is in an inconsistent state and downgrading isn't possible:

1. Restore from the backup taken before applying migrations
2. Fix the migration scripts
3. Re-apply the migrations

## Migration Testing Checklist

- [ ]  Verify upgrade path works correctly
- [ ]  Verify downgrade path works correctly
- [ ]  Test with representative data
- [ ]  Ensure indexes are properly created
- [ ]  Check constraints are properly applied
- [ ]  Validate foreign key relationships
- [ ]  Measure migration execution time on a clone of production data

For high-risk migrations, consider implementing a dry-run mode to validate changes before applying them.
