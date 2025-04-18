# Deployment Scripts

This directory contains scripts for deploying the Cloud Infrastructure Platform across different environments.

## Available Scripts

- `deploy.sh` - Main deployment script for application updates
- `rollback.sh` - Rolls back to a previous version if deployment issues occur
- `pre_deploy_check.sh` - Pre-deployment validation
- `post_deploy_check.sh` - Post-deployment verification
- `collect_static.sh` - Collects and optimizes static assets

## Usage

All scripts accept an environment parameter:

```bash
./deploy.sh [environment]  # Default: production
```