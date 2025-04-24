# Crontab Configuration for Cloud Infrastructure Platform

This directory contains crontab configurations and installation scripts for scheduled maintenance tasks across different environments of the Cloud Infrastructure Platform.

## Overview

The crontabs defined in this directory automate routine maintenance tasks including log rotation, backups, security checks, and system monitoring. Each environment (development, staging, production) has its own crontab configuration with appropriate scheduling frequencies and settings.

## Key Files

- **`development.crontab`**: Development environment scheduled tasks.
  - **Usage**: Used by [`scripts/maintenance/crontabs/install_crontab.sh`](scripts/maintenance/crontabs/install_crontab.sh) for development environments.
  - **Features**:
    - Minimal background tasks
    - Less frequent security checks
    - Basic monitoring

- **`install_crontab.sh`**: Script to install the appropriate crontab based on environment.
  - **Usage**: Run this script to set up scheduled tasks for the current environment.
  - **Features**:
    - Environment auto-detection
    - Variable substitution in crontab files
    - Safe temporary file handling
    - Validation of crontab files

- **`production.crontab`**: Production environment scheduled tasks.
  - **Usage**: Used by [`scripts/maintenance/crontabs/install_crontab.sh`](scripts/maintenance/crontabs/install_crontab.sh) for production deployments.
  - **Features**:
    - Frequent security checks
    - Regular backups
    - Performance monitoring
    - Log rotation

- **`staging.crontab`**: Staging environment scheduled tasks.
  - **Usage**: Used by [`scripts/maintenance/crontabs/install_crontab.sh`](scripts/maintenance/crontabs/install_crontab.sh) for staging deployments.
  - **Features**:
    - Moderate security check frequency
    - Daily backups
    - Periodic monitoring
    - Log management

## Directory Structure

```plaintext
scripts/maintenance/crontabs/
├── crontab.example       # Example crontab with documentation
├── development.crontab   # Development environment scheduled tasks
├── install_crontab.sh    # Crontab installation script
├── production.crontab    # Production environment scheduled tasks
├── README.md             # This documentation
└── staging.crontab       # Staging environment scheduled tasks
```

## Best Practices & Security

- Always verify crontab changes before installation
- Use absolute paths for all commands to avoid path issues
- Redirect both stdout and stderr to log files
- Include date/time parameters in log filenames to prevent overwriting
- Use appropriate user permissions for scheduled tasks
- Avoid placing credentials in crontab files
- Test scheduled tasks manually before scheduling
- Monitor log files to ensure scheduled tasks are running correctly

## Common Features

- Environment-specific task frequencies
- Standard log directory structure
- Proper error handling and logging
- Cleanup processes for temporary files
- Resource-intensive tasks scheduled during off-peak hours
- Security check automation

## Usage

### Installing Crontabs

```bash
# Install crontab for the current environment
./scripts/maintenance/crontabs/install_crontab.sh

# Install crontab for a specific environment
ENV=production ./scripts/maintenance/crontabs/install_crontab.sh

# View the currently installed crontab
crontab -l
```

### Modifying Crontabs

When modifying crontab files:

1. Use comments to document each scheduled task
2. Maintain consistent formatting for readability
3. Group related tasks together
4. Include appropriate logging for each task
5. Test commands manually before adding to crontab

### Environment Variables

Each crontab file defines environment variables used by the scheduled tasks:

```bash
# Common environment variables
CLOUD_PLATFORM_ROOT=/path/to/installation
LOG_DIR=/var/log/cloud-platform
PYTHON_ENV=/path/to/venv/bin/python
FLASK_ENV=production|staging|development
```

## Related Documentation

- Maintenance Guide
- Backup Procedures
- Monitoring Configuration
- Security Policies

## Version History

- **1.2.0 (2023-12-10)**: Added API latency monitoring to all environments
- **1.1.0 (2023-10-15)**: Added file integrity verification checks
- **1.0.0 (2023-09-01)**: Initial crontab configurations
