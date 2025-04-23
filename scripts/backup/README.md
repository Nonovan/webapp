# Disaster Recovery Scripts

## Overview

This directory contains scripts for managing disaster recovery operations for the Cloud Infrastructure Platform. These scripts handle failover procedures, DNS updates, and infrastructure activation to ensure business continuity during outages or disaster scenarios.

## Key Scripts

- **`dr-activate.sh`**: Activates the disaster recovery infrastructure in the secondary region
- **`dr-failover.sh`**: Handles application failover between primary and secondary regions
- **`update-dns.sh`**: Updates DNS records to point to active infrastructure during failover

## Directory Structure

```bash
scripts/deployment/dr/
├── dr-activate.sh        # DR infrastructure activation script
├── dr-failover.sh        # Application failover management
├── README.md             # This documentation
└── update-dns.sh         # DNS redirection utility
```

## Configuration

DR scripts rely on environment variables that can be configured in the deployment environment files:

- **PRIMARY_REGION**: Primary AWS region (default: us-west-2)
- **SECONDARY_REGION**: Secondary/DR AWS region (default: us-east-1)
- **PRIMARY_REGION_ENDPOINT**: Endpoint for primary region health checks
- **SECONDARY_REGION_ENDPOINT**: Endpoint for secondary region health checks
- **PRIMARY_CLUSTER**: Name of the primary region's auto-scaling group
- **SECONDARY_CLUSTER**: Name of the secondary region's auto-scaling group
- **PRIMARY_DB_HOST**: Primary database host
- **SECONDARY_DB_HOST**: Secondary database host

## Best Practices & Security

- Always verify infrastructure readiness before completing failover
- Use proper cleanup handlers with `trap` to ensure resource cleanup
- Maintain accurate DNS records for both primary and secondary regions
- Never run DR scripts during normal operations without proper planning
- Test DR procedures regularly using `--dry-run` mode
- Coordinate DR activities with all stakeholders using established communication channels

## Common Features

- Detailed logging to both console and log files for audit purposes
- Health checks to verify infrastructure and application availability
- Notification system for critical DR events
- Force mode to override safety checks when necessary
- Automatic DNS updates to redirect traffic

## Usage

### Disaster Recovery Infrastructure Activation

```bash
# Activate DR infrastructure with verification
./scripts/deployment/dr/dr-activate.sh

# Activate DR infrastructure without verification
./scripts/deployment/dr/dr-activate.sh --skip-verification

# Force activation even if verification fails
./scripts/deployment/dr/dr-activate.sh --force
```

### Application Failover

```bash
# Failover to secondary region
./scripts/deployment/dr/dr-failover.sh --activate-region secondary

# Failover back to primary region when recovered
./scripts/deployment/dr/dr-failover.sh --activate-region primary

# Force failover even if checks fail
./scripts/deployment/dr/dr-failover.sh --activate-region secondary --force

# Quiet mode (minimal console output)
./scripts/deployment/dr/dr-failover.sh --activate-region secondary --quiet
```

### DNS Updates

```bash
# Update DNS to point to secondary region
./scripts/deployment/dr/update-dns.sh --point-to secondary

# Update DNS to point back to primary region
./scripts/deployment/dr/update-dns.sh --point-to primary

# Force DNS update even if health checks fail
./scripts/deployment/dr/update-dns.sh --point-to secondary --force
```

## Module Dependencies

- **Database Scripts**: Required for database verification
- **Monitoring Scripts**: Used for health checks and alerts
- **Security Scripts**: Used for file integrity verification
- **Testing Scripts**: Used for smoke tests after failover
- **Utils Scripts**: Used for notifications and logging

## Related Documentation

- Disaster Recovery Plan
- Deployment Overview
- Monitoring Configuration
- DNS Management

## Version History

- **1.3.0 (2024-03-15)**: Added comprehensive verification and notification system
- **1.2.0 (2024-01-20)**: Enhanced logging and database verification
- **1.1.0 (2023-11-10)**: Added support for multi-region deployments
- **1.0.0 (2023-09-01)**: Initial release of DR scripts
