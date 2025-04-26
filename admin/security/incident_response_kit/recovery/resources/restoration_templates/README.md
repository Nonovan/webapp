# Service Restoration Templates

This directory contains standardized templates used during the recovery phase of incident response to restore services and applications in a secure and consistent manner. These templates define configuration parameters, dependencies, and validation steps for different types of services after a security incident has been contained.

## Contents

- Overview
- Key Templates
- Directory Structure
- Template Structure
- Usage
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The service restoration templates provide structured configuration parameters and procedures for restoring different types of services after a security incident. These templates ensure that systems are brought back online in a secure manner with proper configuration settings, appropriate security controls, and necessary validation steps. Each template is tailored to a specific service type, containing parameters for secure configuration, dependency mapping, restoration sequencing, and post-restoration validation steps. Using these standardized templates helps ensure consistency, security, and proper documentation throughout the recovery process.

## Key Templates

- **`api_service.json`**: API service restoration template
  - API gateway configuration
  - Authentication integration parameters
  - Endpoint authorization mapping
  - Rate limiting settings
  - Service routing configuration
  - Traffic management rules
  - Versioning configuration

- **`auth_system.json`**: Authentication system restoration template
  - Authentication provider integration
  - Federation settings
  - MFA configuration
  - Password policy enforcement
  - Service account configuration
  - Session management parameters
  - User directory synchronization

- **`database.json`**: Database system restoration template
  - Access control configuration
  - Connection pooling settings
  - Data integrity verification steps
  - Encryption parameters
  - Replication configuration
  - Resource allocation parameters
  - User privilege restrictions

- **`messaging.json`**: Messaging system restoration template
  - Access control configuration
  - Consumer group definitions
  - Integration endpoint settings
  - Message retention policies
  - Queue and topic definitions
  - Throughput parameters
  - Transaction settings

- **`monitoring.json`**: Monitoring system restoration template
  - Alert configuration
  - Dashboard restoration settings
  - Data retention parameters
  - Data source connection details
  - Metric collection settings
  - Notification channel setup
  - Visualization preferences

- **`web_application.json`**: Web application restoration template
  - Application deployment parameters
  - Content security policy
  - Cookie security settings
  - Load balancer configuration
  - SSL/TLS settings
  - User access restoration steps
  - Web server configuration

## Directory Structure

```plaintext
admin/security/incident_response_kit/recovery/resources/restoration_templates/
├── README.md              # This documentation
├── api_service.json       # API service restoration template
├── auth_system.json       # Authentication system restoration template
├── database.json          # Database system restoration template
├── messaging.json         # Messaging system restoration template
├── monitoring.json        # Monitoring system restoration template
└── web_application.json   # Web application restoration template
```

## Template Structure

The service restoration templates follow a standardized JSON format:

```json
{
  "metadata": {
    "template_name": "Web Application Restoration",
    "version": "2.1.0",
    "last_updated": "2024-02-15",
    "applicable_systems": ["Apache", "Nginx", "IIS"],
    "author": "Incident Response Team"
  },
  "dependencies": {
    "required_services": ["database", "authentication", "cache"],
    "optional_services": ["search", "email"],
    "verification_commands": [
      "curl -fsS https://${service_host}/healthcheck",
      "wget -q -O - http://${service_host}:${port}/ping"
    ]
  },
  "configuration": {
    "web_server": {
      "max_connections": 500,
      "keep_alive": true,
      "timeout": 60,
      "compression": true,
      "verification": "grep MaxRequestWorkers ${config_file}",
      "default_value": 250,
      "restart_required": true
    },
    "tls_settings": {
      "min_version": "TLSv1.2",
      "ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
      "certificate_path": "/etc/ssl/certs/${service_name}.crt",
      "private_key_path": "/etc/ssl/private/${service_name}.key",
      "hsts_enabled": true,
      "verification": "openssl s_client -connect ${service_host}:443 -tls1_2",
      "restart_required": true
    }
  },
  "validation": {
    "health_check": {
      "endpoint": "/health",
      "expected_status": 200,
      "timeout_seconds": 5,
      "retries": 3
    },
    "functional_tests": [
      {
        "name": "login_flow",
        "command": "./test_scripts/verify_login.sh ${service_host}",
        "expected_result": "Authentication successful",
        "severity": "critical"
      }
    ]
  }
}
```

## Usage

These templates are used with the service restoration script during incident recovery:

```bash
# Restore web application using the template
../service_restoration.py --incident-id IR-2024-042 \
    --service web-application \
    --template web_application.json \
    --environment production

# Restore database with custom parameters
../service_restoration.py --incident-id IR-2024-042 \
    --service database \
    --template database.json \
    --param "max_connections=200" \
    --param "shared_buffers=4GB"

# Perform dependency validation only
../service_restoration.py --incident-id IR-2024-042 \
    --service api-service \
    --template api_service.json \
    --validate-dependencies-only

# Restore monitoring with specific dashboard configuration
../service_restoration.py --incident-id IR-2024-042 \
    --service monitoring \
    --template monitoring.json \
    --config-file /secure/backup/verified/monitoring_config.yaml
```

For programmatic use:

```python
import json
import subprocess
import os

def restore_service(service_type, incident_id, environment, custom_params=None):
    """Restore a service using the appropriate restoration template.

    Args:
        service_type (str): The type of service to restore
        incident_id (str): The incident ID for tracking
        environment (str): The target environment (dev, staging, prod)
        custom_params (dict): Optional custom parameters for the restoration
    """
    # Find the appropriate template
    template_path = os.path.join(
        "restoration_templates",
        f"{service_type}.json"
    )

    if not os.path.exists(template_path):
        raise ValueError(f"No restoration template found for {service_type}")

    cmd = [
        "../service_restoration.py",
        "--incident-id", incident_id,
        "--service", service_type,
        "--template", template_path,
        "--environment", environment
    ]

    # Add any custom parameters
    if custom_params:
        for key, value in custom_params.items():
            cmd.extend(["--param", f"{key}={value}"])

    # Execute the restoration
    subprocess.run(cmd, check=True)
```

## Customization Guidelines

When customizing restoration templates for specific environments:

1. **Document All Changes**
   - Include the rationale for customization
   - Document who approved the changes
   - Record the date of modification
   - Reference incident lessons learned

2. **Follow Security Best Practices**
   - Update security parameters based on current best practices
   - Use secure default values
   - Follow least privilege principles
   - Include proper validation commands
   - Maintain defense-in-depth approach

3. **Maintain Template Integrity**
   - Keep the standard template structure
   - Preserve validation steps for security controls
   - Retain dependency information
   - Keep proper metadata information
   - Maintain logging configuration

4. **Test Changes**
   - Validate customizations in a test environment
   - Verify all validation steps still work
   - Test rollback procedures
   - Document any unexpected behavior
   - Review performance impacts

## Best Practices & Security

- **Approval Workflow**: Require approval for critical configuration changes
- **Backup Before Restoration**: Always create backups before applying templates
- **Controlled Access**: Restrict access to restoration templates
- **Dependency Management**: Restore services in the correct order based on dependencies
- **Immutable Artifacts**: Use immutable, verified artifacts for restoration
- **Least Privilege**: Start services with minimal privileges and incrementally add permissions
- **Parameter Validation**: Validate all configuration parameters before application
- **Progressive Rollout**: Restore services incrementally rather than all at once
- **Security Verification**: Include security verification steps in all templates
- **Template Versioning**: Maintain version history for all templates
- **Thorough Validation**: Include comprehensive validation steps for restored services
- **Zero Trust**: Verify all components even when trusted sources are used

## Common Features

All restoration templates include these common elements:

- **Configuration Parameters**: Detailed configuration settings with defaults
- **Dependency Mapping**: Clear identification of service dependencies
- **Documentation References**: Links to detailed documentation
- **Health Checks**: Service-specific health verification
- **Metadata Section**: Version and applicability information
- **Restoration Order**: Specified order for component restoration
- **Rollback Procedures**: Steps to revert changes if issues occur
- **Security Controls**: Mandatory security settings
- **Service Verification**: Validation steps for service functionality
- **Template Versioning**: Version tracking for templates
- **User Access Management**: Controlled restoration of user access
- **Validation Commands**: Commands to verify proper restoration

## Related Documentation

- CIS Benchmarks for Secure Configuration
- Incident Response Kit Overview
- Post-Incident Recovery Procedures
- Recovery Documentation Templates
- Security Hardening Profiles Documentation
- Service Configuration Standards
- Service Dependency Mapping
- Service Restoration Script Documentation
- System Verification Procedures
- Verification Scripts Documentation
