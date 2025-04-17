# Database Management for Cloud Infrastructure Platform

This directory contains configuration files, scripts, and documentation for managing the Cloud Infrastructure Platform database.

## Overview

The Cloud Infrastructure Platform uses PostgreSQL as its primary database. These files help with database setup, maintenance, migration, and optimization across different environments.

## Files

- `init.sql` - Initial database setup script that creates databases, roles, and permissions
- `schema.sql` - Reference schema definition for the entire database
- `init_db.py` - Python script for initializing a new database instance
- `db_config.ini` - Configuration for database connections in different environments
- `backup_strategy.md` - Documentation on database backup and recovery procedures
- `migration-guide.md` - Guide for creating and applying database migrations
- `maintenance.md` - Best practices for database maintenance and optimization

## Quick Start

### Initialize a New Database

```bash
# For development environment
python deployment/database/init_db.py --env development

# For staging environment
python deployment/database/init_db.py --env staging

# For production environment
python deployment/database/init_db.py --env production --schema-only

```

### Apply Migrations

```bash
flask db upgrade

```

### Create a New Migration

```bash
flask db migrate -m "Description of changes"

```

### Database Maintenance Tasks

See the maintenance guide for detailed information on routine maintenance tasks.

## Environment Configuration

The database connection details for each environment are configured in:

1. .env files in the environments directory
2. `db_config.ini` for initialization and maintenance scripts
3. Flask application configuration files

## Security Considerations

- Never commit real database credentials to version control
- Store production credentials in environment variables or a secure vault
- Use least-privilege database users for application connections
- Enable SSL for all database connections in production
- Implement IP-based access restrictions

## Migrations

Database schema changes are managed through migrations using Flask-Migrate (Alembic). See the migration guide for best practices when creating and applying migrations.

## Backup and Recovery

The platform implements a comprehensive backup strategy. See the backup strategy document for details on:

- Automated backup procedures
- Retention policies
- Recovery procedures
- Testing backup integrity

## Performance Optimization

For performance optimization recommendations, refer to the maintenance guide. It includes:

- Index optimization strategies
- Query performance tuning
- PostgreSQL configuration recommendations
- Scaling considerations