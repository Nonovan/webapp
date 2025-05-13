# Database Scripts

This directory contains scripts for managing the Cloud Infrastructure Platform database.

## Contents

- [Overview](#overview)
- [Key Scripts](#key-scripts)
- [Directory Structure](#directory-structure)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Maintenance Schedule](#maintenance-schedule)
- [Usage](#usage)
  - [Database Management](#database-management)
  - [Database Optimization](#database-optimization)
  - [Advanced PostgreSQL Optimization](#advanced-postgresql-optimization)
  - [Database Initialization](#database-initialization)
  - [Index Management](#index-management)
  - [Database Seeding](#database-seeding)
  - [Rollback Operations](#rollback-operations)
- [Python Package API](#python-package-api)
- [Note](#note)

## Overview

The database scripts handle critical database operations including backup/restore, optimization, verification, schema management, and rollback procedures for PostgreSQL databases. These scripts support multiple environments (development, staging, production) and include safeguards to prevent accidental data loss.

## Key Scripts

- **`add_indexes.sh`**: Analyzes query patterns and adds recommended indexes based on usage statistics.
  - **Usage**: Run this script to identify and create missing indexes.
  - **Features**:
    - Identifies slow queries needing indexes
    - Removes unused indexes
    - Generates execution plans
    - Creates detailed recommendation reports
    - Performs safe index application with rollback capability

- **`database-manager.sh`**: Comprehensive utility for database operations.
  - **Usage**: Central command for database administration tasks.
  - **Features**:
    - Backup and restore functionality
    - Replication monitoring
    - Backup verification and rotation
    - Database seeding
    - Secure credential handling
    - Maintenance window awareness

- **`optimize.sh`**: Performs PostgreSQL database optimization.
  - **Usage**: Run this script for database maintenance.
  - **Features**:
    - Table vacuuming to reclaim space
    - Index rebuilding to reduce fragmentation
    - Configuration parameter tuning
    - Storage parameter optimization
    - Performance metrics collection
    - Safe execution with rollback capabilities

- **`pg_optimizer.py`**: Advanced PostgreSQL optimization module with detailed analysis capabilities.
  - **Usage**: Use for in-depth database analysis and performance tuning.
  - **Features**:
    - Cache hit ratio analysis
    - Index usage statistics
    - Table and index bloat detection
    - Slow query identification
    - Comprehensive optimization reports
    - Performance trend analysis

- **`init_db.py`**: Initializes database schema and structure.
  - **Usage**: Set up new database environments.
  - **Features**:
    - Database creation
    - Schema initialization
    - Migration application
    - Initial data setup
    - Environment-specific configuration
    - Role and permission management

- **`seed_data.py`**: Seeds the database with initial and optional development data.
  - **Usage**: Populate database with test or initial data.
  - **Features**:
    - Environment-specific data seeding
    - Test data generation
    - Schema validation
    - Incremental data loading
    - Reference data management

## Directory Structure

```plaintext
scripts/database/
├── __init__.py            # Package initialization and public API
├── add_indexes.sh         # Index management utility
├── database-manager.sh    # Comprehensive database administration tool
├── init_db.py             # Database initialization script
├── optimize.sh            # Database performance optimization
├── pg_optimizer.py        # Advanced PostgreSQL optimization module
├── README.md              # This documentation
└── seed_data.py           # Database seeding utility
```

## Best Practices & Security

- Always create backups before running optimization operations
- Use maintenance windows for resource-intensive operations
- Run optimizations during periods of low database activity
- Verify database integrity after restore operations
- Always use the `--env` parameter to explicitly specify the target environment
- Store database credentials securely in environment files
- Use dedicated database users with appropriate permissions
- Implement proper access controls for backup files (permissions 600)
- Use password files instead of command-line passwords
- Create safety backups before destructive operations
- Test rollback procedures regularly in non-production environments
- Implement proper audit logging for all database operations
- Verify backups regularly with automated checks
- Follow the principle of least privilege for database users
- Enable SSL for all database connections in production

## Common Features

- Environment-aware configurations (development, staging, production)
- Comprehensive logging for audit purposes
- Safe defaults to prevent accidental data loss
- Confirmation prompts for destructive operations
- Timeout handling for long-running operations
- Secure credential management
- Detailed error reporting and handling
- Automated rollback capabilities
- Performance metrics collection
- Integration with monitoring systems
- Safe multi-stage operations with verification steps

## Maintenance Schedule

For optimal database performance, follow this maintenance schedule:

- **Daily**: Run basic `ANALYZE` to update statistics
- **Weekly**: Run standard optimization during low-traffic periods

```bash
./optimize.sh --env production --apply
```

- **Monthly**: Perform full vacuum and reindex

```bash
./optimize.sh --env production --full-vacuum --reindex --apply
```

- **Monthly**: Verify backup integrity

```bash
./database-manager.sh verify-db --env production
```

- **Quarterly**: Verify rollback procedures

```bash
# Test rollback procedure in staging environment
./database-manager.sh backup --env staging
# Make some changes, then test rollback
./database-manager.sh restore --env staging --file latest
```

## Usage

### Database Management

The `database-manager.sh` script provides comprehensive database operations:

```bash
# Create a backup of the production database
./database-manager.sh backup --env production

# Create encrypted backup
./database-manager.sh backup --env production --encrypt

# Restore from backup
./database-manager.sh restore --env staging --file backup_20231101_120000.sql.gz

# List available backups
./database-manager.sh list

# Verify backup integrity
./database-manager.sh verify --file backup_20231101_120000.sql.gz

# Check replication health
./database-manager.sh check-replication --env production --threshold 300

# Get database configuration
./database-manager.sh get-config --env development
```

### Database Optimization

The `optimize.sh` script provides comprehensive database maintenance and optimization:

```bash
# Basic database analysis (dry run)
./optimize.sh --env production

# Run VACUUM ANALYZE to reclaim space and update statistics
./optimize.sh --env production --apply

# More intensive optimization with full vacuum and reindexing
./optimize.sh --env production --full-vacuum --reindex --apply

# Run during maintenance window
./optimize.sh --env production --maintenance-window --start-time 01:00 --end-time 05:00 --apply

# Generate PostgreSQL configuration recommendations
./optimize.sh --env production --optimize-config

# Optimize storage parameters
./optimize.sh --env production --optimize-storage --apply

# Run index optimization together with other operations
./optimize.sh --env production --add-indexes --apply
```

### Advanced PostgreSQL Optimization

The `pg_optimizer.py` module provides advanced database analysis and optimization capabilities:

```bash
# Analyze database without making changes
python pg_optimizer.py --analyze-only --env production

# Run comprehensive optimization with detailed report
python pg_optimizer.py --env production --apply

# Optimize with specific parameters
python pg_optimizer.py --env production --vacuum-mode full --reindex --schema public --apply

# Generate JSON-formatted output
python pg_optimizer.py --analyze-only --env production --json

# Generate performance trend analysis
python pg_optimizer.py --analyze-only --env production --trend-days 30
```

### Database Initialization

The `init_db.py` script handles database creation and initial setup:

```bash
# Initialize development database
python init_db.py --env development

# Create production database with schema only
python init_db.py --env production --schema-only

# Drop existing database and recreate
python init_db.py --env development --drop-existing

# Create database with specific options
python init_db.py --env staging --create-schemas --verify
```

### Index Management

The `add_indexes.sh` script helps identify and create optimal indexes:

```bash
# Analyze index usage without making changes
./add_indexes.sh --analyze --env production

# Apply recommended indexes
./add_indexes.sh --apply --env production

# Analyze with verbose output
./add_indexes.sh --analyze --verbose --env production

# Connect to specific database server
./add_indexes.sh --analyze --host db.example.com --port 5432 --dbname mydb --user dbuser

# Use secure password file instead of command line
./add_indexes.sh --analyze --env production --password-file /path/to/password_file
```

### Database Seeding

The `seed_data.py` script populates the database with initial data:

```bash
# Seed production with minimal data
python seed_data.py --env production

# Seed development with sample data
python seed_data.py --dev --sample-data

# Force seeding even if database is not empty
python seed_data.py --env development --force

# Seed specific data types only
python seed_data.py --env development --data-type reference
```

### Rollback Operations

The scripts provide several ways to roll back changes:

```bash
# Roll back to previous database state using backup
./database-manager.sh restore --env staging --file backup_20231101_120000.sql.gz

# Roll back changes made by index creation
./add_indexes.sh --rollback --env production --file /var/log/cloud-platform/index_recommendations_20231101_120000.sql

# Roll back changes from optimization
./optimize.sh --env production --rollback --timestamp 20231101_120000
```

## Python Package API

The `scripts.database` package exports the following functionality via its `__init__.py` for use in Python code:

### PostgreSQL Optimizer Functions

- `analyze_db_statistics`: Analyzes database statistics and performance metrics
- `perform_optimization`: Performs database optimization operations
- `generate_optimization_report`: Creates detailed optimization reports
- `get_db_config`: Retrieves database configuration settings
- `OptimizationError`: Exception class for optimization errors

### Core Database Operations

- `run_db_manager`: Runs the `database-manager.sh` script with given parameters
- `backup_database`: Creates database backups
- `restore_database`: Restores from database backups
- `verify_database`: Verifies database integrity
- `check_replication`: Checks database replication health
- `optimize_db`: Performs database optimization
- `initialize_database`: Initializes a new database environment

### Database Initialization Functions

- `create_database`: Creates a new database with required permissions
- `read_config`: Reads database configuration from files
- `apply_migrations`: Applies database migrations
- `seed_data`: Seeds the database with initial data

### Main Entry Points

- `seed_data_main`: Main function for the `seed_data.py` script
- `init_db_main`: Main function for the `init_db.py` script

## Note

Always test operations in a staging environment before applying to production, especially for resource-intensive operations like `VACUUM FULL` and reindexing. Create proper backups before any destructive operations and verify rollback procedures regularly to ensure business continuity.
