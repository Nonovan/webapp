# Database Scripts

This directory contains scripts for managing the Cloud Infrastructure Platform database.

## Overview

The database scripts handle critical database operations including backup/restore, optimization, verification, and schema management for PostgreSQL databases. These scripts support multiple environments (development, staging, production) and include safeguards to prevent accidental data loss.

## Key Scripts

- **`add_indexes.sh`**: Analyzes query patterns and adds recommended indexes based on usage statistics.
  - **Usage**: Run this script to identify and create missing indexes.
  - **Features**:
    - Identifies slow queries needing indexes
    - Removes unused indexes
    - Generates execution plans

- **`database-manager.sh`**: Comprehensive utility for database operations.
  - **Usage**: Central command for database administration tasks.
  - **Features**:
    - Backup and restore functionality
    - Replication monitoring
    - Backup verification and rotation
    - Database seeding

- **`optimize.sh`**: Performs PostgreSQL database optimization.
  - **Usage**: Run this script for database maintenance.
  - **Features**:
    - Table vacuuming to reclaim space
    - Index rebuilding to reduce fragmentation
    - Configuration parameter tuning
    - Storage parameter optimization

- **`seed_data.py`**: Seeds the database with initial and optional development data.
  - **Usage**: Populate database with test or initial data.
  - **Features**:
    - Environment-specific data seeding
    - Test data generation
    - Schema validation

## Directory Structure

```bash
scripts/database/
├── add_indexes.sh         # Index management utility
├── database-manager.sh    # Comprehensive database administration tool
├── init_db.py             # Database initialization script
├── optimize.sh            # Database performance optimization
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

## Common Features

- Environment-aware configurations (development, staging, production)
- Comprehensive logging for audit purposes
- Safe defaults to prevent accidental data loss
- Confirmation prompts for destructive operations
- Timeout handling for long-running operations

## Maintenance Schedule

For optimal database performance, follow this maintenance schedule:

- **Daily**: Run basic ANALYZE to update statistics
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

## Usage

### Database Management

The database-manager.sh script provides comprehensive database operations:

```bash
# Create a backup of the production database
./database-manager.sh backup --env production

# Restore from backup
./database-manager.sh restore --env staging --file backup_20231101_120000.sql.gz

# List available backups
./database-manager.sh list

# Verify backup integrity
./database-manager.sh verify --file backup_20231101_120000.sql.gz

# Check replication health
./database-manager.sh check-replication --env production --threshold 300
```

### Database Optimization

The optimize.sh script provides comprehensive database maintenance and optimization:

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
```

### Index Management

The add_indexes.sh script helps identify and create optimal indexes:

```bash
# Analyze index usage without making changes
./add_indexes.sh --analyze --env production

# Apply recommended indexes
./add_indexes.sh --apply --env production

# Analyze with verbose output
./add_indexes.sh --analyze --verbose --env production
```

### Database Seeding

The seed_data.py script populates the database with initial data:

```bash
# Seed production with minimal data
./seed_data.py --env production

# Seed development with sample data
./seed_data.py --dev --sample-data

# Force seeding even if database is not empty
./seed_data.py --env development --force
```

## Note

Always test operations in a staging environment before applying to production, especially for resource-intensive operations like VACUUM FULL and reindexing.
