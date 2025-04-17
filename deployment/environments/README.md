# Environment Configuration Files

This directory contains environment-specific configuration files used by the Cloud Infrastructure Platform's deployment processes.

## File Format

Each environment file (`*.env`) follows the standard environment variable format:

KEY=value ANOTHER_KEY=another_value

## Available Environments

- `development.env` - Local development configuration
- `testing.env` - Automated testing environment configuration
- `staging.env` - Pre-production staging environment
- `production.env` - Production environment
- `ci.env` - Continuous Integration environment
- `demo.env` - Demonstration instance configuration

## Security Notice

These files may contain sensitive configuration values for local development.
For actual deployments, sensitive values should be provided through secure environment
variables rather than checked-in files.

In production, security-critical values like database credentials, API keys, etc., should be injected
through environment variables, secrets management systems, or secure parameter stores rather than
stored in these files.

## Usage with Deployment CLI

These environment files are used by the deployment CLI commands:

```bash
# Deploy to a specific environment
flask deploy aws deploy --env production

# Get status from a specific environment
flask deploy gcp status --env staging