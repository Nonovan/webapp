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
op.add_column('table_name',
              sa.Column('column_name', sa.String(length=50), nullable=True))

```

### Adding a Column with Default Value

```python
# Add with nullable=True first
op.add_column('table_name',
              sa.Column('column_name', sa.Integer(), nullable=True))

# Update existing rows
connection = op.get_bind()
connection.execute(sa.text(
    "UPDATE table_name SET column_name = 0 WHERE column_name IS NULL"
))

# Make column non-nullable
op.alter_column('table_name', 'column_name', nullable=False)

```

### Adding an Index

```python
op.create_index('ix_table_name_column_name', 'table_name', ['column_name'])

```

### Adding a Foreign Key

```python
op.add_column('child_table',
              sa.Column('parent_id', sa.Integer(), nullable=True))
op.create_foreign_key('fk_child_parent', 'child_table', 'parent_table',
                     ['parent_id'], ['id'])

```

## Testing Migrations

1. **Development Testing**:
    
    ```bash
    # Apply pending migrations
    flask db upgrade
    
    # Roll back most recent migration
    flask db downgrade
    
    ```
    
2. **Staging Testing**:
    
    ```bash
    # Deploy to staging and run migrations
    flask deploy azure deploy --env staging
    
    ```
    
3. **Migration Verification**:
    
    ```bash
    # Check current database version
    flask db current
    
    # Show migration history
    flask db history
    
    ```
    

## Deploying Migrations

### Production Deployment

Production migrations should always be deployed as part of a planned deployment:

1. **Backup Database**:
    
    ```bash
    flask db backup --env production
    
    ```
    
2. **Apply Migrations**:
    
    ```bash
    flask db upgrade
    
    ```
    
3. **Verify Success**:
    
    ```bash
    flask db current
    
    ```
    

### Emergency Rollback

In case of migration issues:

1. **Identify Current Version**:
    
    ```bash
    flask db current
    
    ```
    
2. **Roll Back to Previous Version**:
    
    ```bash
    flask db downgrade
    
    ```
    

## Troubleshooting

### Common Migration Issues

1. **Migration Conflicts**: If multiple developers create migrations simultaneously
    - Rebase migrations or merge them manually
    - Re-create the migration if needed
2. **Failed Migrations**:
    - Check migration logs
    - Run with `x` flag to see detailed error information
    - Fix the issue and re-run, or roll back if necessary

## References

- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [Flask-Migrate Documentation](https://flask-migrate.readthedocs.io/)

