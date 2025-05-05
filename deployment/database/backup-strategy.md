# Database Backup and Recovery Strategy

This document outlines the backup and recovery strategies for the Cloud Infrastructure Platform databases.

## Backup Schedule

| Environment | Full Backup | Incremental Backup | Retention Period |
|-------------|------------|-------------------|-----------------|
| Production  | Daily (3:00 AM) | Hourly | 30 days |
| Staging     | Daily (3:00 AM) | None | 14 days |
| Development | Weekly (Sunday 3:00 AM) | None | 7 days |
| DR-Recovery | Daily (4:00 AM) | None | 14 days |

## Backup Methods

### Automated Backups

Automated backups are performed using the following tools:

1. **PostgreSQL pg_dump**: Creates logical backups of the database
2. **CLI Tools**: Managed via the Flask CLI command: `flask db backup`
3. **Database Module**: Using the functions in `deployment.database.backup_db` module
4. **Cron Jobs**: Scheduled via the crontab files in `scripts/crontabs/`

### Backup Locations

Backups are stored in the following locations:

1. **Primary Storage**: `/var/backups/cloud-platform/`
2. **Secondary Storage**: Encrypted S3 bucket `cloud-platform-backups-{environment}`
3. **Long-term Archive**: For production, monthly backups are archived to `cloud-platform-archive`
4. **Cross-Region Storage**: Critical production backups are replicated to a secondary region

## Backup Encryption

All backups are encrypted using:

1. **In-transit**: TLS 1.3
2. **At-rest**: AES-256 encryption
3. **Key Management**: AWS KMS for cloud storage, GPG for local storage

## Backup Verification

Backup verification is performed automatically after each backup:

1. **Checksums**: SHA-256 hash verification
2. **Restore Testing**: Weekly automated restore tests to verification environment
3. **Monitoring**: Alerts are triggered if backup jobs fail or verification fails
4. **Metadata Validation**: Schema structure and essential data integrity checks

## Recovery Procedures

### Recovery Time Objectives (RTO)

| Environment | RTO |
|-------------|-----|
| Production  | 1 hour |
| Staging     | 4 hours |
| Development | 8 hours |
| DR-Recovery | 2 hours |

### Recovery Point Objectives (RPO)

| Environment | RPO |
|-------------|-----|
| Production  | 1 hour |
| Staging     | 24 hours |
| Development | 1 week |
| DR-Recovery | 24 hours |

### Recovery Process

1. **Assessment**: Determine the extent and cause of data loss
2. **Backup Selection**: Select the appropriate backup to restore from
3. **Environment Preparation**: Ensure target environment is ready
4. **Restore Operation**: Execute restore using either:
   - CLI approach: `flask db restore <backup_file>`
   - Module approach:

     ```python
     from deployment.database.backup_db import restore_database
     result = restore_database(
         backup_file="/path/to/backup.sql.gz",
         env="production",
         verify=True,
         timeout=3600
     )
     ```

5. **Verification**: Validate data integrity and application functionality
6. **Migration Alignment**: Set correct migration version with:

   ```python
   from deployment.database import stamp_database_revision
   stamp_database_revision(revision="revision_hash", env="production")
   ```

7. **Post-Recovery**: Document incident and update procedures if necessary

## Database-Only Rollback

For situations requiring database-only rollback without code rollback:

```python
# Using the backup_db module
from deployment.database.backup_db import restore_database

success = restore_database(
    backup_file="/path/to/backup.sql.gz",
    env="production",
    dry_run=False,  # Set to True to test without applying changes
    verify=True,    # Verify database integrity after restore
    timeout=3600    # Maximum operation time in seconds
)

# After restore, stamp the correct migration version
from deployment.database import stamp_database_revision
stamp_database_revision(
    revision="target_migration_hash",
    env="production"
)
```

## Integration with System Backup Tools

The database backup system integrates with:

1. **Monitoring Systems**: Prometheus metrics for backup success/failure rates
2. **Notification Systems**: Alerts via email, Slack, and PagerDuty
3. **Centralized Logging**: Detailed logs sent to centralized log aggregation
4. **Infrastructure Automation**: Backup verification tests in CI/CD pipeline

## Disaster Recovery Testing

Disaster recovery testing is performed quarterly, including:

1. **Full Restore**: Complete database restore to isolated environment
2. **Application Validation**: Verify application functionality with restored data
3. **Performance Testing**: Ensure restored database meets performance requirements
4. **Migration Testing**: Verify migration versioning is properly maintained
5. **Integration Testing**: Test system integrations with restored data

## Database Backup Maintenance

Regular maintenance of the backup system includes:

1. **Retention Policy Enforcement**: Automated cleanup of backups beyond retention period
2. **Storage Monitoring**: Alert on backup storage capacity issues
3. **Backup Size Trends**: Monitor backup size growth over time
4. **Backup Performance**: Track backup and restore operation durations
5. **Configuration Updates**: Regular review and update of backup configurations

## Security Considerations

1. **Access Control**: Only authorized personnel have access to backup files
2. **Audit Logging**: All backup and restore operations are logged
3. **Secure Deletion**: Expired backups are securely deleted
4. **Encryption Key Management**: Regular rotation of encryption keys
5. **Data Classification**: Special handling for sensitive data backups

## Backup Command Reference

### Using Built-in Backup Functions

```python
# Import backup functions
from deployment.database.backup_db import (
    create_backup,
    restore_database,
    verify_backup,
    list_backups,
    get_backup_info,
    purge_old_backups
)
from deployment.database import read_config

# Read database configuration
db_config, _, _ = read_config("deployment/database/db_config.ini", "production")

# Create a backup
backup_file = create_backup(
    db_config,
    backup_dir="/var/backups/cloud-platform",
    compress=True,
    include_schema=True,
    include_data=True
)

# List available backups
backups = list_backups("/var/backups/cloud-platform", env="production")
for backup in backups:
    print(f"{backup['filename']} - {backup['size']} - {backup['timestamp']}")

# Verify backup integrity
is_valid = verify_backup(backup_file, check_structure=True)

# Restore from backup (with caution!)
success = restore_database(
    backup_file,
    env="production",
    verify=True,
    timeout=3600
)

# Clean up old backups
purged = purge_old_backups(
    backup_dir="/var/backups/cloud-platform",
    env="production",
    retention_days=30
)
```

## Implementation Details

The backup and restore functionality is implemented in:

1. **CLI Commands**: `cli/commands/db.py` for command-line usage
2. **Backup Module**: `backup_db.py` for programmatic usage
3. **Cron Jobs**: `scripts/crontabs/` for scheduled execution
4. **Utility Scripts**: `database-manager.sh` for administration

## Related Documentation

- Database Maintenance Guide
- Migration Guide
- Disaster Recovery Plan
- Infrastructure Backup Documentation
