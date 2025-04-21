# Database Scripts

This directory contains scripts for managing the Cloud Infrastructure Platform database.

## Available Scripts

- `seed_data.py` - Seeds the database with initial and optional development data
- `backup_db.sh` - Creates database backups
- `restore_db.sh` - Restores database from backups
- `database-manager.sh` - Comprehensive utility for database operations (backup, restore, verify, list, rotate, seed)
- `init_db.sh` - Initializes a new database instance with proper structure and permissions
- `optimize.sh` - Performs PostgreSQL database optimization (VACUUM, reindex, configuration optimization)
- `verify-backups.sh` - Verifies database backup integrity by performing test restorations
- `add_indexes.sh` - Analyzes query patterns and adds recommended indexes

## Usage

Most scripts accept an environment parameter:

```bash
./backup_db.sh [environment]  # Default: production
./restore_db.sh [backup_file] [environment]
./database-manager.sh backup --env production

```

### Database Optimization

The [optimize.sh](http://optimize.sh/) script provides comprehensive database maintenance and optimization:

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

### Backup Verification

Verify integrity of database backups:

```bash
# Verify recent backups
./verify-backups.sh --env production

# Verify specific backup file
./verify-backups.sh --file /path/to/backup.sql.gz --env production

```

## Best Practices

- **Regular Maintenance**: Run standard optimization weekly during low-traffic periods:
    
    ```bash
    ./optimize.sh --env production --apply
    
    ```
    
- **Monthly Deep Optimization**: Perform full vacuum and reindex monthly:
    
    ```bash
    ./optimize.sh --env production --full-vacuum --reindex --apply
    
    ```
    
- **Backup Verification**: Verify backup integrity regularly:
    
    ```bash
    ./verify-backups.sh --env production --latest 3
    
    ```
    
- **Database Seeding**: For development environments:
    
    ```bash
    ./seed_data.py --dev --force
    
    ```
    

## Note

Always test these operations in a staging environment before applying to production, especially for resource-intensive operations like VACUUM FULL and reindexing.