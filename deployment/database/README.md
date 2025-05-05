# Database Management for Cloud Infrastructure Platform

This directory contains configuration files, scripts, and documentation for managing the Cloud Infrastructure Platform database.

## Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Environment Configuration](#environment-configuration)
- [Quick Start](#quick-start)
- [Migrations](#migrations)
- [Maintenance and Optimization](#maintenance-and-optimization)
- [Backup and Recovery](#backup-and-recovery)
- [Security Considerations](#security-considerations)
- [Performance Optimization](#performance-optimization)
- [Related Documentation](#related-documentation)

## Overview

The Cloud Infrastructure Platform uses PostgreSQL as its primary database. These files help with database setup, maintenance, migration, and optimization across different environments (development, staging, and production). The management system implements proper security controls, schema versioning, automated backups, and performance monitoring.

## Directory Structure

```plaintext
deployment/database/
├── README.md                # This documentation
├── __init__.py              # Package initialization with exported functions
├── backup_strategy.md       # Documentation on database backup and recovery procedures
├── db_config.ini            # Configuration for database connections in different environments
├── db_constants.py          # Constants for database management
├── init.sql                 # Initial database setup script that creates databases, roles, and permissions
├── init_db.py               # Python script for initializing a new database instance
├── maintenance.md           # Best practices for database maintenance and optimization
├── maintenance.py           # Database maintenance and optimization functions
├── migrations.py            # Database migration utilities
├── migration-guide.md       # Guide for creating and applying database migrations
├── schema.sql               # Reference schema definition for the entire database
└── seed.sql                 # Initial data seeding script
```

## Environment Configuration

The database connection details for each environment are configured in:

1. Environment files (`.env`) in the environments directory
2. `db_config.ini` for initialization and maintenance scripts
3. Flask application configuration files

Configuration parameters include:

- Connection credentials
- Connection pool settings
- SSL configuration
- Timeout values
- Performance parameters

## Quick Start

### Initialize a New Database

```bash
# For development environment
python deployment/database/init_db.py --env development

# For staging environment
python deployment/database/init_db.py --env staging

# For production environment
python deployment/database/init_db.py --env production --schema-only

# With additional options
python deployment/database/init_db.py --env development --drop-existing --create-schemas --verify
```

### Apply Migrations

```bash
# Using Flask-Migrate directly
flask db upgrade

# Using the migrations module
python -c "from deployment.database.migrations import apply_migration; apply_migration('head')"
```

### Create a New Migration

```bash
# Using Flask-Migrate directly
flask db migrate -m "Description of changes"

# Using the migrations module
python -c "from deployment.database.migrations import generate_migration_script; generate_migration_script('Description of changes')"
```

### High-Level Database Initialization

You can also use the high-level `initialize_database` function from the package:

```python
from deployment.database import initialize_database

# Initialize database with customized options
success = initialize_database(
    env="development",
    drop_existing=True,
    create_schemas=True,
    seed=True,
    schema_only=False,
    verbose=True,
    timeout=120,
    verify=True,
    skip_migrations=False,
    use_core_seeder=True
)
```

## Migrations

Database schema changes are managed through migrations using Flask-Migrate (Alembic). The migration system provides:

- Version-controlled schema changes
- Safe application of changes across environments
- Ability to roll back changes if necessary
- Consistent schema evolution history

### Core Migration Utilities

The `migrations.py` module provides these core functions:

- `verify_migrations`: Check if migrations are in sync with models
- `generate_migration_script`: Create a new migration script
- `apply_migration`: Apply migrations up to a specified revision
- `rollback_migration`: Roll back to a specified revision
- `get_migration_history`: Get the history of applied migrations
- `stamp_database_revision`: Mark a database as being at a specific revision
- `merge_migration_heads`: Merge multiple migration heads
- `check_migration_script`: Verify migration script integrity
- `get_current_migration_revision`: Get current database revision
- `create_initial_migration`: Create an initial migration

Key migration practices include:

1. Always review automatically generated migrations
2. Test thoroughly before applying to production
3. Ensure changes are idempotent when possible
4. Include proper downgrade methods for rollbacks
5. Separate schema changes from data migrations when possible

For detailed guidelines, see the migration guide.

## Maintenance and Optimization

The `maintenance.py` module provides tools for ongoing database maintenance:

### Core Maintenance Functions

- `optimize_database`: Perform optimizations based on current database state
- `vacuum_analyze`: Run vacuum and analyze on database tables
- `reindex_database`: Rebuild bloated or corrupt indexes
- `monitor_connection_count`: Monitor database connections
- `check_table_bloat`: Identify tables with significant bloat
- `check_index_usage`: Identify unused or rarely used indexes

### Recommended Maintenance Schedule

#### Daily Tasks

- Backup verification
- Database statistics updates (`ANALYZE`)
- Log review

#### Weekly Tasks

- Database vacuuming (`vacuum_analyze()`)
- Index maintenance
- Review of long-running queries

#### Monthly Tasks

- Full database optimization (`optimize_database()` with full vacuum)
- User access review
- Storage capacity planning

Example usage from Python:

```python
from deployment.database import optimize_database, read_config

# Read database configuration
db_config, _, _ = read_config("deployment/database/db_config.ini", "production")

# Run optimization
result = optimize_database(
    db_config,
    vacuum_mode="standard",
    apply=True,
    verbose=True
)
```

## Backup and Recovery

The platform implements a comprehensive backup strategy with:

### Backup Schedule

| Environment | Full Backup | Incremental Backup | Retention Period |
|-------------|------------|-------------------|-----------------|
| Production  | Daily (3:00 AM) | Hourly | 30 days |
| Staging     | Daily (3:00 AM) | None | 14 days |
| Development | Weekly (Sunday 3:00 AM) | None | 7 days |

### Key Backup Features

- Automated backup procedures using PostgreSQL `pg_dump`
- Multi-location storage with encryption
- Regular verification through automated restore tests
- Comprehensive recovery procedures with defined RTO/RPO
- Quarterly disaster recovery testing

For detailed information, refer to the backup strategy document.

## Security Considerations

- Never commit real database credentials to version control
- Store production credentials in environment variables or a secure vault
- Use least-privilege database users for application connections
- Enable SSL for all database connections in production
- Implement IP-based access restrictions
- Monitor and audit database access
- Apply security patches promptly
- Encrypt sensitive data at rest
- Use proper schema separation for security boundaries
- Implement row-level security where appropriate
- Define read-only roles for reporting access

## Performance Optimization

Performance optimization strategies include:

### Query Performance

- Proper index creation and maintenance
- Query optimization using `EXPLAIN ANALYZE`
- Connection pooling with PgBouncer

### Configuration Optimization

- Memory settings tuned to available system resources
- Write settings optimized for workload
- Query planning parameters tuned for storage type

### Scaling Strategies

- Vertical scaling with resource increases
- Read replicas for read-heavy workloads
- Connection pooling for connection scaling
- Sharding for very large datasets

For detailed recommendations, refer to the maintenance guide.

## Module Exports

The following functions and constants are exported from the package:

### Initialization Functions

- `create_database`: Create a new database with permissions
- `apply_migrations`: Apply database migrations
- `seed_data`: Seed initial data
- `read_config`: Read database configuration
- `verify_database`: Verify database setup
- `check_postgresql_version`: Check PostgreSQL client tools
- `setup_file_logging`: Configure logging for database operations
- `initialize_database`: High-level initialization function
- `get_database_status`: Get database health and status information

### Maintenance Functions

- `optimize_database`: Perform database optimizations
- `vacuum_analyze`: Run vacuum and analyze
- `reindex_database`: Rebuild bloated indexes
- `monitor_connection_count`: Monitor active connections
- `check_table_bloat`: Check for table bloat
- `check_index_usage`: Check index usage statistics

### Migration Utilities

- `verify_migrations`: Check migrations against models
- `generate_migration_script`: Create migration script
- `apply_migration`: Apply migrations
- `rollback_migration`: Roll back migrations
- `get_migration_history`: Get migration history
- `stamp_database_revision`: Set database revision
- `merge_migration_heads`: Merge multiple heads
- `check_migration_script`: Validate migration script
- `get_current_migration_revision`: Get current revision
- `create_initial_migration`: Create initial migration

### Key Constants

- `ENVIRONMENTS`: Supported environment names
- `DEFAULT_ENVIRONMENT`: Default environment name
- `DB_SCHEMAS`: Standard database schemas
- `DEFAULT_EXTENSIONS`: Default PostgreSQL extensions
- `DB_ROLES`: Database role definitions
- `MAINTENANCE_SETTINGS`: Database maintenance thresholds
- `DEFAULT_CONNECTION_PARAMS`: Default connection parameters

## Related Documentation

- [Flask-Migrate Documentation](https://flask-migrate.readthedocs.io/)
- [PostgreSQL Administration Guide](https://www.postgresql.org/docs/current/admin.html)
- [Database Security Best Practices](https://docs.company.com/security/database-security.html)
- [Connection Pooling with PgBouncer](https://www.pgbouncer.org/usage.html)
- Database Migration Guide
- Database Maintenance Guide
