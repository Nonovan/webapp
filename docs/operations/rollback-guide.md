# Rollback Guide

This document provides detailed procedures for rolling back the Cloud Infrastructure Platform to a previous stable version in case of deployment issues.

## Overview

The rollback process is designed to quickly restore service to a known good state with minimal disruption. It involves reverting both application code and potentially database state.

## When to Roll Back

Consider a rollback when:

- Critical functionality is broken after deployment
- Performance has degraded significantly
- Security vulnerability has been introduced
- Data integrity issues are detected
- User experience is severely impacted

## Rollback Process

### Quick Rollback Command

The simplest way to rollback is using our `rollback.sh` script:

```bash
# Roll back to the previous version
./rollback.sh production

# Roll back to a specific version
./rollback.sh production --version v2.1.0

# Roll back including database changes
./rollback.sh production --database

# Skip confirmation prompts (for automated rollbacks)
./rollback.sh production --force

```

### Manual Rollback Process

If the rollback script is not available or not functioning, follow these manual steps:

1. **Stop Application Services**
    
    ```bash
    systemctl stop cloud-platform.service
    
    ```
    
2. **Revert Code Changes**
    
    ```bash
    cd /opt/cloud-platform
    git fetch --all --tags
    git checkout <previous-tag-or-commit>
    
    ```
    
3. **Reinstall Dependencies**
    
    ```bash
    pip install -r requirements.txt
    
    ```
    
4. **Revert Database (if needed)**
    
    ```bash
    # Find the appropriate backup
    ls -la /var/backups/cloud-platform/database/
    
    # Restore the database
    ./restore_db.sh /var/backups/cloud-platform/database/cloud_platform_production_YYYYMMDD.sql.gz production
    
    ```
    
5. **Restart Services**
    
    ```bash
    systemctl start cloud-platform.service
    systemctl restart nginx
    
    ```
    
6. **Verify Functionality**
    
    ```bash
    ./smoke-test.sh production
    
    ```
    

## Database Rollback Considerations

Database rollbacks require special consideration:

1. **Data Loss Risk**: Rolling back the database may result in data loss for changes made after the backup
2. **Downtime**: Database rollbacks typically require application downtime
3. **Size Considerations**: Large databases may take significant time to restore
4. **Dependencies**: Consider impacts on integrations, caches, and other connected systems

### Database-Only Rollback

To roll back only the database while keeping code at the current version:

```bash
./restore_db.sh /path/to/backup.sql.gz production

```

## Post-Rollback Actions

After completing a rollback:

1. **Document the Issue**
    - Record what happened in the incident log
    - Document the symptoms and impact
    - Note the rollback procedure used
    - Document any data loss or side effects
2. **Notify Stakeholders**
    - Inform users about service disruption
    - Notify the development team
    - Update status pages if applicable
3. **Root Cause Analysis**
    - Investigate why the deployment failed
    - Implement measures to prevent recurrence
4. **Re-Deployment Planning**
    - Fix the issues in a development environment
    - Create a new release addressing the problems
    - Conduct thorough testing before attempting redeployment

## Special Scenarios

### Rolling Back with Schema Changes

When database schema has changed:

1. Restore database from backup
2. Ensure application code is compatible with restored schema
3. Run `flask db stamp` to mark the correct migration version

### Rolling Back Configuration Changes

For configuration-only issues:

1. Revert configuration files from backups in `/etc/cloud-platform/config.backup/`
2. Restart the application to apply changes

### Partial Rollbacks

In some cases, a full rollback might not be necessary:

1. **Feature Flag Rollback**: Disable problematic features via feature flags
2. **Config-Only Rollback**: Revert configuration without changing code
3. **Hotfix Deployment**: Fix the issue with a quick patch rather than rolling back

## Automated Rollback Triggers

Our monitoring system can trigger automatic rollbacks when:

- Health check endpoints return errors for more than 5 minutes
- Error rates exceed 10% for more than 2 minutes
- Response times exceed 5 seconds for more than 5 minutes

## Contact Information

If you need assistance with rollbacks, contact:

- **During Business Hours**: DevOps Team ([devops@example.com](mailto:devops@example.com))
- **After Hours Emergency**: On-Call Engineer ([oncall@example.com](mailto:oncall@example.com), +1-555-123-4567)