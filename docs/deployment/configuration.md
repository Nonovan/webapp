# Configuration Guide

This document provides detailed information about configuring the Cloud Infrastructure Platform for different environments and deployment scenarios.

## Table of Contents

- [Overview](#overview)
- [Configuration Architecture](#configuration-architecture)
- [Environment Configuration](#environment-configuration)
- [Core Configuration Files](#core-configuration-files)
- [Provider-Specific Configuration](#provider-specific-configuration)
- [Security Configuration](#security-configuration)
- [Scaling Configuration](#scaling-configuration)
- [Monitoring Configuration](#monitoring-configuration)
- [Database Configuration](#database-configuration)
- [NGINX Configuration](#nginx-configuration)
- [Advanced Configuration](#advanced-configuration)
- [Troubleshooting](#troubleshooting)

## Overview

The Cloud Infrastructure Platform uses a hierarchical configuration system that separates settings by environment, component, and deployment target. This approach provides flexibility while maintaining consistency across deployments.

## Configuration Architecture

The configuration system follows these principles:

1. **Environment Separation** - Different environments (development, staging, production) have separate configuration files
2. **Layered Configuration** - Core settings are inherited and can be overridden by environment-specific settings
3. **Secrets Management** - Sensitive data is stored separately from regular configuration
4. **Infrastructure as Code** - Infrastructure configurations are expressed as code (Terraform, CloudFormation, etc.)
5. **Template-Based Configuration** - Templates are used to generate environment-specific configurations

## Environment Configuration

### Environment Types

The platform supports the following environments:

| Environment | Purpose | Example File |
|-------------|---------|--------------|
| Development | Local development | `environments/development.env` |
| Testing | Automated testing | `environments/testing.env` |
| Staging | Pre-production validation | `environments/staging.env` |
| Production | Live deployment | `environments/production.env` |

### Environment Variables

Environment-specific configuration is managed through `.env` files in the `deployment/environments/` directory. Key environment variables include:

```bash
# Core application configuration
SECRET_KEY=your-secret-key
ENVIRONMENT=production
DEBUG=False
LOG_LEVEL=INFO

# Database configuration
DATABASE_URL=postgresql://username:password@db-host:5432/dbname
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Redis configuration for caching and queues
REDIS_URL=redis://redis-host:6379/0
CACHE_TYPE=redis

# Security settings
JWT_SECRET_KEY=your-jwt-secret
JWT_ACCESS_TOKEN_EXPIRES=3600
CSRF_ENABLED=True

# Cloud provider settings
CLOUD_PROVIDERS_ENABLED=aws,azure,gcp
AWS_DEFAULT_REGION=us-west-2
AZURE_LOCATION=eastus
GCP_REGION=us-central1

```

### Loading Environment Configuration

The configuration is loaded in this order:

1. Default configuration values from [config.py](http://config.py/)
2. Environment-specific .env file
3. Environment variables from the host system

To generate environment configurations:

```bash
# Create a production environment configuration
flask config generate --env production --output deployment/environments/production.env

# Validate environment configuration
flask config validate --env production

```

## Core Configuration Files

### Application Configuration (`config.py`)

The [config.py](http://config.py/) file defines different configuration classes that are used based on the environment:

```python
class Config:
    """Base configuration."""
    # Base settings here

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True

class StagingConfig(Config):
    """Staging configuration."""
    # Staging-specific settings

class ProductionConfig(Config):
    """Production configuration."""
    # Production-specific settings

```

### Deployment Configuration (`deployment.yml`)

The `deployment/deployment.yml` file defines deployment-specific settings:

```yaml
version: '3'
environments:
  development:
    replicas: 1
    resources:
      cpu: 1
      memory: 1Gi
  staging:
    replicas: 2
    resources:
      cpu: 2
      memory: 2Gi
  production:
    replicas: 3
    resources:
      cpu: 4
      memory: 4Gi
    high_availability: true

```

## Provider-Specific Configuration

### AWS Configuration

AWS-specific configuration files are located in `deployment/infrastructure/aws/`:

- `cloudformation/` - CloudFormation templates
- `terraform/` - Terraform configuration files
- scripts - AWS deployment scripts

Key AWS configuration options:

```yaml
# AWS environment configuration
aws:
  region: us-west-2
  vpc_id: vpc-12345
  subnets:
    - subnet-abcd1
    - subnet-abcd2
    - subnet-abcd3
  instance_type: t3.medium
  auto_scaling:
    min_instances: 2
    max_instances: 10
    target_cpu_utilization: 70

```

### Azure Configuration

Azure-specific configuration is in `deployment/infrastructure/azure/`:

- `arm-templates/` - Azure Resource Manager templates
- `terraform/` - Terraform configuration files
- scripts - Azure deployment scripts

### GCP Configuration

Google Cloud Platform configuration is in `deployment/infrastructure/gcp/`:

- `deployment-manager/` - Deployment Manager templates
- `terraform/` - Terraform configuration files
- scripts - GCP deployment scripts

### Kubernetes Configuration

Kubernetes deployment configuration is in kubernetes:

- `manifests/` - Kubernetes manifests
- `helm-charts/` - Helm charts for application components
- `kustomize/` - Kustomize configurations for different environments

## Security Configuration

Security configurations are managed in security:

### Web Application Firewall Configuration

ModSecurity WAF configuration is defined in waf-rules:

```bash
# Enable the WAF for a production environment
./deployment/security/update-modsecurity-rules.sh --environment production

# Configure WAF protection mode (detection or prevention)
./deployment/security/setup-modsecurity.sh --mode prevention

```

### TLS/SSL Configuration

TLS/SSL settings are defined in ssl.conf.template:

```
# Use strong elliptic curves
ssl_ecdh_curve X25519:secp384r1;

# Diffie-Hellman parameters for DHE ciphersuites
ssl_dhparam {{DHPARAM_PATH}};

# SSL session settings for performance optimization
ssl_session_cache shared:SSL:{{SESSION_CACHE_SIZE}};
ssl_session_timeout {{SESSION_TIMEOUT}};
ssl_session_tickets off; # Disable tickets for better security

# OCSP Stapling
{{#ENABLE_OCSP}}
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate {{TRUSTED_CERT_PATH}};
{{/ENABLE_OCSP}}

```

### Network Security Configuration

Firewall and network security configuration is managed in security:

```bash
# Apply security hardening
./deployment/security/security_setup.sh production

# Run security audit
./deployment/security/security-audit.sh --full

```

## Scaling Configuration

Scaling configuration is defined in various files depending on the deployment platform.

### Auto-Scaling Configuration

For cloud provider auto-scaling:

```yaml
# Auto-scaling configuration (aws-scaling.yml)
auto_scaling:
  web_tier:
    min_instances: 3
    max_instances: 20
    scale_out_threshold: 75
    scale_in_threshold: 25
    cooldown_period: 300
  application_tier:
    min_instances: 2
    max_instances: 15
    scale_out_threshold: 70
    scale_in_threshold: 30
    cooldown_period: 300

```

For Kubernetes-based deployments, Horizontal Pod Autoscaler configurations are in `deployment/kubernetes/autoscaling/`:

```yaml
# HPA configuration (hpa.yaml)
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: cloud-platform-api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: cloud-platform-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70

```

## Monitoring Configuration

Monitoring configurations are in monitoring:

### Prometheus Configuration

Prometheus configuration for metrics collection:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'cloud_platform_app'
    metrics_path: '/api/metrics'
    static_configs:
      - targets: ['localhost:5000']

```

### Alertmanager Configuration

Alert notification settings:

```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'job']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'team-email'

receivers:
  - name: 'team-email'
    email_configs:
      - to: 'alerts@example.com'

  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: '<your-pagerduty-service-key>'

```

## Database Configuration

Database configurations are managed in database:

### Connection Configuration

Database connections are defined in environment files and `db_config.ini`:

```
[development]
host=localhost
port=5432
database=cloud_platform_dev
username=dbuser
password=dbpass
ssl_mode=disable

[production]
host=db.example.com
port=5432
database=cloud_platform_prod
username=dbuser
password=dbpass
ssl_mode=require

```

### Migration Configuration

Database migration settings:

```
# Run database migrations
flask db upgrade

# Create a new migration
flask db migrate -m "Description of changes"

```

## NGINX Configuration

NGINX web server configuration is in nginx:

### Server Block Configuration

Main server configuration in server.conf.template:

```
# Server Configuration Template for Cloud Infrastructure Platform
# Template variables:
# - {{DOMAIN_NAME}}: Primary domain name for the server
# - {{APP_NAME}}: Application name used for directory paths
# - {{ENVIRONMENT}}: Environment (development, staging, production)
# - {{API_UPSTREAM}}: Upstream name for API backend (default: backend_api)

# Define rate limiting zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=api_conn:10m;

```

### API Endpoint Configuration

API routing configuration in api.conf.template:

```
# API Configuration Template for Cloud Infrastructure Platform
# Template variables:
# - {{API_UPSTREAM}}: Name of the API upstream (default: backend_api)
# - {{RATE_LIMIT}}: Rate limit for API requests (requests/second)
# - {{RATE_LIMIT_BURST}}: API rate limit burst parameter
# - {{AUTH_RATE_LIMIT}}: Rate limit for authentication endpoints

# API rate limiting zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate={{RATE_LIMIT}}r/s;
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate={{AUTH_RATE_LIMIT}}r/s;

```

## Advanced Configuration

### Feature Flags

Feature flags can be enabled or disabled in the environment configuration:

```
# Feature flags
FEATURE_MULTI_CLOUD=True
FEATURE_ICS_INTEGRATION=True
FEATURE_ADVANCED_ANALYTICS=True
FEATURE_WEBSOCKETS=True

```

### Custom Scripts

Custom scripts for deployment are in `deployment/scripts/`:

```bash
# Deploy using custom scripts
./scripts/deploy.sh production

# Run post-deployment checks
./scripts/post_deploy_check.sh production

```

## Troubleshooting

### Common Configuration Issues

| Issue | Solution |
| --- | --- |
| Missing environment variables | Check that all required variables are defined in your .env file |
| Database connection errors | Verify database credentials and network connectivity |
| SSL certificate issues | Ensure certificates are valid and configured correctly |
| Permission errors | Check file permissions for configuration files |

### Configuration Validation

Use validation tools to check your configuration:

```bash
# Validate all configuration files
flask config validate --all

# Validate a specific environment
flask config validate --env production

# Test a configuration change before applying
flask config test --env production --changes "DEBUG=False,LOG_LEVEL=INFO"

```

### Configuration Debugging

To enable verbose logging for configuration issues:

```bash
export CONFIG_DEBUG=1
flask config debug --env production

```

This will output detailed information about which configuration files are being loaded and any parsing errors.