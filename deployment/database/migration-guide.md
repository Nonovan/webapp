# Database Migration Guide

This document provides guidelines for creating, testing, and deploying database migrations for the Cloud Infrastructure Platform.

## Overview

The application uses Alembic (via Flask-Migrate) for database migrations. This allows us to:

1. Track changes to the database schema
2. Apply changes in a consistent manner across environments
3. Roll back changes if necessary
4. Maintain a history of database schema evolution

## Migration Utilities

The Cloud Infrastructure Platform provides dedicated migration utilities in the `deployment.database.migrations` module:

| Function | Description |
|----------|-------------|
| `verify_migrations` | Check if migrations are in sync with models |
| `generate_migration_script` | Create a new migration script |
| `apply_migration` | Apply migrations up to a specified revision |
| `rollback_migration` | Roll back to a specific revision |
| `get_migration_history` | Get the history of applied migrations |
| `stamp_database_revision` | Mark a database as being at a specific revision |
| `merge_migration_heads` | Merge multiple migration heads |
| `check_migration_script` | Verify migration script integrity |
| `get_current_migration_revision` | Get current database revision |
| `create_initial_migration` | Create an initial migration |

## Creating Migrations

### Automatic Migrations

To create an automatic migration based on model changes:

```bash
# Using Flask-Migrate directly
flask db migrate -m "Description of the changes"

# Using the migrations module
from deployment.database import generate_migration_script, read_config

result = generate_migration_script(
    message="Description of the changes",
    env="development",
    autogenerate=True,
    verbose=True
)

if result[0]:
    print(f"Migration file created: {result[1]}")
else:
    print("Failed to create migration")
```

This will generate a new migration script in the versions directory.

### Manual Migrations

For complex changes, create a manual migration:

```bash
# Using Flask-Migrate directly
flask db revision -m "Description of the changes"

# Using the migrations module
from deployment.database import generate_migration_script

result = generate_migration_script(
    message="Description of the changes",
    autogenerate=False,
    verbose=True
)
```

Then edit the generated file to add your custom upgrade and downgrade operations.

### Verifying Migrations

Before applying migrations, verify that they're in sync with your models:

```python
from deployment.database import verify_migrations, read_config

is_sync, details = verify_migrations(env="development", verbose=True)

if not is_sync:
    if details["pending_models"]:
        print("Warning: Model changes detected that need migration files")
    if details["pending_migrations"]:
        print("Warning: Pending migrations need to be applied to database")
```

## Best Practices for Writing Migrations

1. **Review Automatic Migrations**: Always review auto-generated migrations before applying them
2. **Test Migrations**: Test migrations thoroughly before applying to production
3. **Idempotency**: Ensure operations are idempotent where possible
4. **Add Comments**: Add detailed comments explaining complex operations
5. **Transaction Safety**: Ensure migrations are transaction-safe
6. **Downgrade Support**: Always implement downgrade methods
7. **Data Migration**: Handle data migrations separately from schema changes when possible
8. **Security**: Avoid exposing sensitive data in migration scripts
9. **Performance**: Consider performance impact for large tables
10. **Validation**: Check migration script integrity with `check_migration_script()`

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

### Creating a New Table

```python
def upgrade():
    op.create_table(
        'new_table',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index('ix_new_table_name', 'new_table', ['name'], unique=False)

def downgrade():
    op.drop_index('ix_new_table_name', 'new_table')
    op.drop_table('new_table')
```

### Adding a Foreign Key

```python
def upgrade():
    op.add_column('child_table', sa.Column('parent_id', sa.Integer(), nullable=True))

    # Create foreign key constraint
    op.create_foreign_key(
        'fk_child_parent',
        'child_table', 'parent_table',
        ['parent_id'], ['id'],
        ondelete='CASCADE'
    )

def downgrade():
    op.drop_constraint('fk_child_parent', 'child_table', type_='foreignkey')
    op.drop_column('child_table', 'parent_id')
```

### Altering an Enum Type

```python
def upgrade():
    # PostgreSQL-specific way to alter enum types
    op.execute("ALTER TYPE status_enum ADD VALUE IF NOT EXISTS 'new_status'")

def downgrade():
    # Cannot easily remove enum values in PostgreSQL, need a workaround
    # like creating a new type and converting
    pass
```

## Applying Migrations

### Development Environment

```bash
# Using Flask-Migrate directly
flask db upgrade

# Using the migrations module
from deployment.database import apply_migration

success = apply_migration(revision="head", env="development", verbose=True)
if success:
    print("Migrations applied successfully")
else:
    print("Migration failed")
```

### Production Environment

Always take a database backup before applying migrations in production:

```bash
# 1. Backup the database
pg_dump -U username -d database_name -f backup_$(date +%Y%m%d_%H%M%S).sql

# 2. Apply migrations
flask db upgrade

# Alternatively, using the migrations module
from deployment.database import apply_migration

success = apply_migration(
    revision="head",
    env="production",
    verbose=True,
    tag=f"release-{release_version}"  # Optional tag for tracking
)
```

## Rolling Back Migrations

To roll back the most recent migration:

```bash
# Using Flask-Migrate directly
flask db downgrade

# Using the migrations module
from deployment.database import rollback_migration

success = rollback_migration(revision="-1", env="development", verbose=True)
```

To roll back to a specific migration:

```bash
# Using Flask-Migrate directly
flask db downgrade <migration_id>

# Using the migrations module
from deployment.database import rollback_migration

success = rollback_migration(
    revision="e9f14a1d2f38",  # Specific migration identifier
    env="development",
    verbose=True
)
```

## Managing Migration History

### Getting Migration History

```python
from deployment.database import get_migration_history

success, history = get_migration_history(env="development")
if success:
    print(f"Found {len(history)} migration entries")
    for entry in history:
        print(f"{entry['revision']}: {entry['message']} ({entry['date']})")
```

### Manually Set Database Revision

In some cases (like after a database restore), you may need to manually set the current migration revision:

```python
from deployment.database import stamp_database_revision

success = stamp_database_revision(
    revision="e9f14a1d2f38",  # Revision to stamp
    env="development"
)
```

### Get Current Database Revision

```python
from deployment.database import get_current_migration_revision

success, revision = get_current_migration_revision(env="development")
if success:
    print(f"Current database revision: {revision}")
```

## Handling Migration Conflicts

If you encounter migration conflicts (multiple developers creating migrations simultaneously):

1. Keep the migration that was created first (by timestamp)
2. Delete the other conflicting migration file
3. Create a new migration that includes the changes from the deleted migration

### Merging Multiple Heads

When multiple migration heads exist (usually after merging branches):

```python
from deployment.database import merge_migration_heads

success, filename = merge_migration_heads(
    message="Merge branch migrations",
    env="development"
)
```

## Disaster Recovery

In case of failed migrations:

1. Check the error message and logs
2. Roll back the failed migration: `flask db downgrade` or use `rollback_migration()`
3. Fix the issue in the migration script
4. Apply the corrected migration: `flask db upgrade` or use `apply_migration()`

If the database is in an inconsistent state and downgrading isn't possible:

1. Restore from the backup taken before applying migrations
2. Fix the migration scripts
3. Use `stamp_database_revision()` to set the correct revision
4. Re-apply the migrations from that point

## Migration Testing Checklist

- [ ]  Verify upgrade path works correctly
- [ ]  Verify downgrade path works correctly
- [ ]  Test with representative data
- [ ]  Ensure indexes are properly created
- [ ]  Check constraints are properly applied
- [ ]  Validate foreign key relationships
- [ ]  Measure migration execution time on a clone of production data
- [ ]  Verify script integrity with `check_migration_script()`
- [ ]  Test migration conflicts and resolutions
- [ ]  Confirm data integrity after migration

For high-risk migrations, consider implementing a dry-run mode to validate changes before applying them.

## Creating Initial Migration

When setting up a new database or schema, you can create an initial migration:

```python
from deployment.database import create_initial_migration

success, filename = create_initial_migration(
    message="initial_schema",
    env="development",
    verbose=True
)
```

## Environment-Specific Considerations

### Development

- Quick iteration cycle
- Frequent schema changes
- Testing of complex migrations

### Staging

- Testing environment configuration
- Verifying migration performance
- Validating data integrity

### Production

- Schedule during maintenance windows
- Always create backups before migrating
- Test thoroughly in lower environments first
- Consider using transaction batching for large tables
- Monitor database performance during and after migrations

## Security Considerations

When writing migrations:

1. **Database Credentials**: Never hardcode credentials in migration scripts
2. **Sensitive Data**: Avoid logging or exposing sensitive data
3. **SQL Injection**: Parameterize any SQL statements that include user input
4. **Access Control**: Apply the principle of least privilege for migration accounts
5. **Audit**: Track who applied migrations and when

## Related Resources

- [Flask-Migrate Documentation](https://flask-migrate.readthedocs.io/)
- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
