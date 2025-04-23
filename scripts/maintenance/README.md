# Maintenance Scripts

This directory contains maintenance scripts for managing routine operational tasks within the Cloud Infrastructure Platform. These scripts handle log management, data cleanup, environment synchronization, and scheduled maintenance operations.

## Overview

The maintenance scripts automate key operational tasks across development, staging, and production environments, ensuring consistent system operation, log management, and data integrity. These scripts help reduce manual operational burden and provide standardized approaches for common maintenance activities.

## Key Scripts

- **`archive_audit_logs.sh`**: Archives audit logs to secure storage with retention policies.
  - **Usage**: Run this script to securely archive application audit logs.
  - **Features**:
    - Database audit log extraction
    - Compressed file archiving
    - Secure file permissions
    - Retention policy enforcement

- **`clean_old_logs.sh`**: Removes old log files based on retention policies.
  - **Usage**: Run this script to clean up outdated log files.
  - **Features**:
    - Age-based log removal
    - Directory traversal with safety checks
    - Configurable retention periods
    - Backup creation before removal

- **`cleanup.sh`**: Performs general system maintenance tasks.
  - **Usage**: Run this script for routine system cleanup.
  - **Features**:
    - Package cache cleaning
    - Old log file removal
    - Temporary file cleanup
    - User cache management
    - Disk space reclamation

- **`env_sync.sh`**: Synchronizes configuration between environments (e.g., production to staging).
  - **Usage**: Run this script to copy and adapt configuration between environments.
  - **Features**:
    - Environment-aware configuration synchronization
    - Backup creation before modification
    - Environment variable adaptation
    - Pattern-based file inclusion/exclusion
    - Secure handling of sensitive files

- **`rotate_logs.sh`**: Rotates and compresses log files.
  - **Usage**: Run this script for log rotation and archiving.
  - **Features**:
    - Age-based log rotation
    - Log compression
    - Archive management
    - Retention policy enforcement

## Directory Structure

```
scripts/maintenance/
├── archive_audit_logs.sh   # Secure archival of audit logs
├── clean_old_logs.sh       # Cleanup of outdated log files
├── cleanup.sh              # General system maintenance
├── env_sync.sh             # Environment configuration synchronization
├── README.md               # This documentation
├── rotate_logs.sh          # Log rotation and compression
└── crontabs/               # Scheduled task configurations
    ├── crontab.example     # Example crontab with documentation
    ├── development.crontab # Development environment scheduled tasks
    ├── install_crontab.sh  # Crontab installation script
    ├── production.crontab  # Production environment scheduled tasks
    ├── README.md           # Crontab documentation
    └── staging.crontab     # Staging environment scheduled tasks
```

## Best Practices & Security

- Run cleanup operations during low-traffic periods
- Always verify targets before running destructive operations
- Use proper error handling and logging for all maintenance tasks
- Create backups before modifying critical configuration files
- Test maintenance scripts in development environments first
- Set appropriate file permissions when working with sensitive data
- Use absolute paths in scripts to prevent working directory issues
- Include timestamps in log output for audit purposes
- Use appropriate timeouts for long-running operations

## Common Features

- Environment-aware operations
- Consistent logging and error handling
- Safe backup creation before modifications
- Configurable retention policies
- Permission management for sensitive files
- Proper cleanup of temporary files
- Detailed log output for auditability

## Usage

### Log Management

```bash
# Archive audit logs
./scripts/maintenance/archive_audit_logs.sh

# Clean logs older than default retention period
./scripts/maintenance/clean_old_logs.sh

# Rotate logs with 30-day retention
./scripts/maintenance/rotate_logs.sh
```

### System Cleanup

```bash
# Perform general system cleanup
./scripts/maintenance/cleanup.sh

# Run cleanup with specific options
./scripts/maintenance/cleanup.sh --disk-space-threshold 85
```

### Environment Configuration

```bash
# Sync configuration from production to staging
./scripts/maintenance/env_sync.sh --source production --target staging

# Sync configuration with specific patterns
./scripts/maintenance/env_sync.sh --source production --target development --include "security*" --exclude "*.bak"

# Dry run to preview changes
./scripts/maintenance/env_sync.sh --source staging --target development --dry-run
```

### Crontab Management

```bash
# Install crontab for the current environment
./scripts/maintenance/crontabs/install_crontab.sh

# Install crontab for a specific environment
ENV=production ./scripts/maintenance/crontabs/install_crontab.sh
```

## Related Documentation

- Maintenance Guide
- Backup Procedures
- System Monitoring
- Disaster Recovery

## Version History

- **1.3.0 (2024-01-15)**: Added environment configuration synchronization
- **1.2.0 (2023-11-10)**: Enhanced log management with improved security
- **1.1.0 (2023-09-20)**: Added crontab management features
- **1.0.0 (2023-08-01)**: Initial release of maintenance scripts
