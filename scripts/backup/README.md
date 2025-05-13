# Database Backup Scripts

## Overview

This directory contains scripts for managing database backups for the Cloud Infrastructure Platform. These scripts handle the creation, verification, and restoration of database backups across different environments, ensuring data integrity and providing disaster recovery capabilities.

## Key Scripts

- **`backup_db.sh`**: Creates and manages database backups with integrity verification
- **`restore_db.sh`**: Restores database from previous backups with safety checks
- **`verify-backups.sh`**: Validates backup integrity and performs test restorations

## Directory Structure

```plaintext
scripts/backup/
├── backup_db.sh          # Database backup creation script
├── README.md             # This documentation
├── restore_db.sh         # Database restoration script
└── verify-backups.sh     # Backup integrity verification tool
```

## Configuration

Backup scripts rely on environment variables that can be configured in the deployment environment files:

- **BACKUP_DIR**: Directory where backups are stored (default: /var/backups/cloud-platform)
- **LOG_DIR**: Directory for backup logs (default: /var/log/cloud-platform)
- **LOG_RETENTION_HOURS**: Hours to retain backup logs (default: 168)
- **DB_MANAGER**: Path to database manager (default: PROJECT_ROOT/scripts/database/database-manager.sh)
- **DB_BACKUP_NOTIFY**: Email for backup notifications (configurable per environment)
- **DB_RESTORE_NOTIFY**: Email for restore notifications (configurable per environment)

## Best Practices & Security

- Always verify backup integrity after creation using `verify-backups.sh`
- Create safety backups before performing database restorations
- Use encryption for sensitive production backups
- Implement proper retention policies to manage backup storage
- Test restoration procedures regularly in isolated environments
- Use appropriate permissions (600/640) for backup files and logs
- Follow the principle of least privilege for database operations
- Store backup files in multiple secure locations

## Common Features

- Environment-specific configurations (development, staging, production)
- Compression and optional encryption capabilities
- Integrity verification with cryptographic checksums
- Detailed logging for audit and troubleshooting purposes
- Notification system for critical backup and restoration events
- Force mode to override safety checks when necessary
- Backup rotation to implement retention policies

## Usage

### Database Backup

```bash
# Create a backup for production environment
./scripts/backup/backup_db.sh --env production

# Create compressed and encrypted backup
./scripts/backup/backup_db.sh --env production --encrypt

# Back up specific tables only
./scripts/backup/backup_db.sh --env staging --tables users,accounts,settings

# Create schema-only backup (no data)
./scripts/backup/backup_db.sh --env development --schema-only

# Skip verification and rotation
./scripts/backup/backup_db.sh --env production --no-verify --no-rotate
```

### Database Restoration

```bash
# Restore from specific backup file to staging environment
./scripts/backup/restore_db.sh --env staging --file backup_20240415_120000.sql.gz

# Restore latest backup
./scripts/backup/restore_db.sh --env development --file latest

# Restore without owner statements
./scripts/backup/restore_db.sh --file backup_20240415_120000.sql.gz --env development --no-owner

# Restore without safety backup
./scripts/backup/restore_db.sh --file backup_20240415_120000.sql.gz --env staging --no-safety-backup

# Force restore without confirmation
./scripts/backup/restore_db.sh --file backup_20240415_120000.sql.gz --env development --force
```

### Backup Verification

```bash
# Verify backups for production environment
./scripts/backup/verify-backups.sh --environment production

# Verify with test restoration
./scripts/backup/verify-backups.sh --environment staging --restore-test

# Verify all environments
./scripts/backup/verify-backups.sh --all-environments

# Verify backups from last 14 days
./scripts/backup/verify-backups.sh --environment production --verify-days 14

# Verify with detailed integrity checks and notifications
./scripts/backup/verify-backups.sh --environment production --detailed-verify --notify ops@example.com
```

## Module Dependencies

- **Database Scripts**: Required for database operations and management
- **Core Utilities**: Used for configuration loading and environment detection
- **Security Scripts**: Used for cryptographic operations and file integrity verification
- **Notification Scripts**: Used for alerting on backup status and issues
- **Utils Scripts**: Used for logging and error handling

## Related Documentation

- Database Management Documentation
- Backup Strategy and Retention Policies
- Disaster Recovery Plan
- Data Protection Guidelines
- PostgreSQL Administration Guide

## Version History

- **0.0.4 (2024-05-10)**: Enhanced verification with detailed integrity checks and test restoration
- **0.0.3 (2024-03-15)**: Added comprehensive notification system and improved logging
- **0.0.2 (2024-01-20)**: Enhanced restore script with safety features and rollback capabilities
- **0.0.1 (2023-11-05)**: Initial release of database backup scripts
