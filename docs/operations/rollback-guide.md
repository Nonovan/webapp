# Rollback Guide

This document provides detailed procedures for rolling back the Cloud Infrastructure Platform to a previous stable version in case of deployment issues.

## Contents

- Overview
- When to Roll Back
- Rollback Process
- Database Rollback Considerations
- Post-Rollback Actions
- Special Scenarios
- Automated Rollback Triggers
- Contact Information

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

The simplest way to roll back is using the `rollback.sh` script from the deployment core scripts directory:

```bash
# Roll back to the previous version
cd /opt/cloud-platform
./scripts/deployment/core/rollback.sh production

# Roll back to a specific version
./scripts/deployment/core/rollback.sh production --version v2.1.0

# Roll back including database changes
./scripts/deployment/core/rollback.sh production --database

# Skip confirmation prompts (for automated rollbacks)
./scripts/deployment/core/rollback.sh production --force
```

### Manual Rollback Process

If the rollback script is not available or not functioning, follow these manual steps:

1. **Stop Application Services**

   ```bash
   sudo systemctl stop cloud-platform.service
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
   cd /opt/cloud-platform
   ./scripts/database/restore_db.sh /var/backups/cloud-platform/database/cloud_platform_production_YYYYMMDD.sql.gz production
   ```

5. **Restart Services**

   ```bash
   sudo systemctl start cloud-platform.service
   sudo systemctl restart nginx
   ```

6. **Verify Functionality**

   ```bash
   cd /opt/cloud-platform
   ./scripts/monitoring/smoke-test.sh production
   ```

The key change is adding proper indentation with at least one space after the numbered list items, plus adding a blank line between each list item and its corresponding code block. This ensures the markdown parser correctly maintains the numbering while associating the code blocks with their respective steps.

## Database Rollback Considerations

Database rollbacks require special consideration:

1. **Data Loss Risk**: Rolling back the database may result in data loss for changes made after the backup
2. **Downtime**: Database rollbacks typically require application downtime
3. **Size Considerations**: Large databases may take significant time to restore
4. **Dependencies**: Consider impacts on integrations, caches, and other connected systems

### Database-Only Rollback

To roll back only the database while keeping code at the current version:

```bash
cd /opt/cloud-platform
./scripts/database/restore_db.sh /path/to/backup.sql.gz production
```

### Database Migration Versioning

After a database rollback, ensure the migration version is correctly set:

```bash
cd /opt/cloud-platform
FLASK_APP=app.py FLASK_ENV=production flask db stamp <migration-version>
```

## Post-Rollback Actions

After completing a rollback:

1. **Document the Issue**
   - Record what happened in the incident log
   - Document the symptoms and impact
   - Note the rollback procedure used
   - Document any data loss or side effects
   - Log the rollback in the change management system

2. **Notify Stakeholders**
   - Inform users about service disruption
   - Notify the development team
   - Update status pages if applicable
   - Send formal notifications per communication plan

3. **Root Cause Analysis**
   - Investigate why the deployment failed
   - Implement measures to prevent recurrence
   - Document findings in the incident report
   - Schedule review with the development team

4. **Re-Deployment Planning**
   - Fix the issues in a development environment
   - Create a new release addressing the problems
   - Conduct thorough testing before attempting redeployment
   - Include additional verification steps for the affected components

## Special Scenarios

### Rolling Back with Schema Changes

When database schema has changed:

1. Restore database from backup
2. Ensure application code is compatible with restored schema
3. Run `flask db stamp` to mark the correct migration version:

```bash
cd /opt/cloud-platform
FLASK_APP=app.py FLASK_ENV=production flask db stamp <migration-version>
```

### Rolling Back Configuration Changes

For configuration-only issues:

1. Revert configuration files from backups in `/etc/cloud-platform/config.backup/`
2. Verify configuration file permissions and ownership
3. Restart the application to apply changes:

```bash
sudo systemctl restart cloud-platform.service
```

### Partial Rollbacks

In some cases, a full rollback might not be necessary:

1. **Feature Flag Rollback**: Disable problematic features via feature flags
   - Update the feature flag configuration in the admin panel
   - Or modify the feature flags file directly and restart the application

2. **Config-Only Rollback**: Revert configuration without changing code
   - Restore specific configuration files from backup
   - Apply targeted configuration changes

3. **Hotfix Deployment**: Fix the issue with a quick patch rather than rolling back
   - Deploy a hotfix directly to production
   - Follow emergency change procedures for approval

## Automated Rollback Triggers

Our monitoring system can trigger automatic rollbacks when:

- Health check endpoints return errors for more than 5 minutes
- Error rates exceed 10% for more than 2 minutes
- Response times exceed 5 seconds for more than 5 minutes

### Override Automated Rollbacks

To prevent automated rollbacks during expected maintenance:

```bash
cd /opt/cloud-platform
./scripts/monitoring/maintenance-mode.sh enable --duration 60
```

## Contact Information

If you need assistance with rollbacks, contact:

- **During Business Hours**: DevOps Team ([devops@example.com](mailto:devops@example.com))
- **After Hours Emergency**: On-Call Engineer ([oncall@example.com](mailto:oncall@example.com), +1-555-123-4567)

## Version History

| Version | Date | Description | Author |
|---------|------|-------------|--------|
| 1.0 | 2023-06-15 | Initial rollback guide | DevOps Team |
| 1.1 | 2023-09-20 | Added database considerations | Database Administrator |
| 1.2 | 2024-01-10 | Updated manual rollback steps | Cloud Engineer |
| 1.3 | 2024-03-15 | Added special scenarios section | Platform Engineer |
