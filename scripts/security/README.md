# Security Scripts

This directory contains security-related scripts for the Cloud Infrastructure Platform, providing essential security controls, monitoring, and management capabilities.

## Contents

- [Overview](#overview)
- [Key Scripts](#key-scripts)
- [Directory Structure](#directory-structure)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage](#usage)
- [Integration](#integration)
- [Emergency Response](#emergency-response)
- [Compliance](#compliance)
- [Version History](#version-history)

## Overview

These scripts provide comprehensive security functionality for enforcing security best practices, identifying vulnerabilities, and supporting compliance requirements across development, staging, and production environments. They form the foundation of the platform's security automation framework and integrate with the monitoring, alerting, and documentation systems.

## Key Scripts

- **`access_review.sh`**: Performs periodic reviews of user access rights, roles, and permissions.
  - **Usage**: Run this script to audit user access against defined policies.
  - **Features**:
    - Dormant account identification
    - Privilege escalation detection
    - Role-based access verification
    - Multi-factor authentication compliance
    - Automated remediation capabilities

- **`apply_security_updates.sh`**: Safely applies security updates with rollback capabilities.
  - **Usage**: Run this script to apply security patches with verification steps.
  - **Features**:
    - Environment-specific update application
    - Rollback plan creation
    - System snapshot before updates
    - Automatic service restart
    - Email notifications

- **`check_certificate_expiration.sh`**: Monitors SSL/TLS certificate expiration dates.
  - **Usage**: Run this script to identify certificates nearing expiration.
  - **Features**:
    - Domain validation
    - Configurable warning thresholds
    - Multiple notification channels
    - Certificate metadata extraction
    - Integration with renewal workflows

- **`check_permissions.sh`**: Validates and optionally fixes file/directory permissions and ownership.
  - **Usage**: Run this script to audit and correct file permissions.
  - **Features**:
    - Recursive permission checking
    - Permission fixing capabilities
    - Sensitive file detection
    - Comprehensive reporting
    - Configurable security baselines

- **`firewall_check.sh`**: Verifies firewall rules against security policy.
  - **Usage**: Run this script to validate firewall configurations.
  - **Features**:
    - Policy compliance verification
    - Rule conflict detection
    - Unnecessary rule identification
    - Security gap detection
    - Support for multiple firewall types

- **`generate_security_keys.py`**: Creates cryptographic keys for secure communications.
  - **Usage**: Run this script to generate secure keys for various applications.
  - **Features**:
    - Multiple key type support
    - Secure key generation
    - Custom key parameters
    - Key rotation capabilities
    - Key distribution options

- **`list_users.sh`**: Identifies privileged users and analyzes account security.
  - **Usage**: Run this script to review user account security.
  - **Features**:
    - Privilege enumeration
    - Password policy checking
    - Last login analysis
    - Suspicious access detection
    - Group membership validation

- **`log_analyzer.py`**: Analyzes security logs for suspicious activities.
  - **Usage**: Run this script to identify potential security incidents in logs.
  - **Features**:
    - Pattern-based threat detection
    - Anomaly detection
    - Multiple log format support
    - Correlation analysis
    - Alert generation

- **`security_audit.py`**: Comprehensive security audit tool.
  - **Usage**: Run this script to perform complete security assessments.
  - **Features**:
    - Vulnerability scanning
    - Configuration assessment
    - Security baseline verification
    - Compliance checking
    - Detailed reporting

- **`ssl-setup.sh`**: Configures SSL/TLS certificates for secure communications.
  - **Usage**: Run this script to set up and manage SSL certificates.
  - **Features**:
    - Certificate generation
    - Let's Encrypt integration
    - Certificate deployment
    - Configuration validation
    - Auto-renewal setup

- **`verify_files.py`**: File integrity verification tool to detect unauthorized changes.
  - **Usage**: Run this script to check for unauthorized file modifications.
  - **Features**:
    - Multiple hash algorithm support
    - Baseline creation
    - Change detection
    - Scheduled verification
    - Tamper alerting

## Directory Structure

```plaintext
scripts/security/
├── access_review.sh           # User access rights and permissions review
├── apply_security_updates.sh  # Security update application with rollback capability
├── check_certificate_expiration.sh # SSL/TLS certificate expiration monitoring
├── check_permissions.sh       # File and directory permission verification
├── firewall_check.sh          # Firewall configuration validation
├── generate_security_keys.py  # Cryptographic key generation utility
├── list_users.sh              # User account security analysis
├── log_analyzer.py            # Security log analysis tool
├── README.md                  # This documentation
├── security_audit.py          # Comprehensive security audit tool
├── ssl-setup.sh               # SSL/TLS certificate configuration
├── verify_files.py            # File integrity verification
├── audit/                     # Audit-specific modules and templates
│   ├── baseline/              # Security baseline configurations
│   ├── checkers/              # Individual audit check implementations
│   └── templates/             # Report templates
└── common/                    # Shared security script utilities
    ├── logging.sh             # Standardized logging functionality
    ├── notification.sh        # Alert and notification utilities
    └── validation.sh          # Input validation functions
```

## Best Practices & Security

- All security scripts should be owned by root:root with 750 permissions
- Always run scripts with appropriate privileges (usually root)
- Schedule regular execution via cron for continuous security monitoring
- Always review reports generated by these scripts, especially `security_audit.py`
- Log all script activities to `/var/log/cloud-platform/security/`
- Store sensitive credentials securely in environment variables
- Never hardcode API keys or passwords in these scripts
- Test scripts in development environments before running in production
- Keep all security tools updated to address new threats
- Use the principle of least privilege when granting script execution permissions
- Implement proper error handling to prevent information leakage

## Common Features

- Comprehensive logging with consistent format
- Multiple output formats (text, JSON, HTML, CSV)
- Email notification capabilities
- Integration with monitoring systems
- Environment-specific configurations
- Proper error handling and exit codes
- Clean help and usage documentation
- Verbose and quiet operation modes
- Secure handling of credentials and sensitive data
- Consistent command-line interface patterns
- Support for dry run modes for validation

## Usage

### Access Management

```bash
# Review user access rights against policy
./access_review.sh --scope all --inactive-days 90 --report-format json

# List users with specific privileges
./list_users.sh --group admin --last-login 30 --mfa-status

# Check permissions on sensitive files
./check_permissions.sh --target /etc/cloud-platform --fix --verbose
```

### Security Auditing

```bash
# Run a comprehensive security audit
./security_audit.py --email security@example.com --report-format html

# Check and fix permissions in the security directory
./check_permissions.sh --fix-permissions --verbose

# Verify file integrity
./verify_files.py --target-dir /etc --report-only
```

### Security Updates and Maintenance

```bash
# Apply security updates with notification
./apply_security_updates.sh --environment production --notify

# Check SSL certificate expiration
./check_certificate_expiration.sh --domain example.com --warn-days 30

# Set up SSL certificates with Let's Encrypt
./ssl-setup.sh --domain example.com --email admin@example.com
```

### Security Monitoring

```bash
# Check firewall rules
./firewall_check.sh --compare-policy

# Analyze security logs
./log_analyzer.py --detect-threats --last-hours 24

# Generate security keys
./generate_security_keys.py --type rsa --size 4096 --output /etc/ssl/private/
```

## Integration

These scripts integrate with other platform components:

- **Monitoring**: Reports can be sent to the central monitoring system
- **Alerting**: Critical findings trigger security alerts
- **Documentation**: Results can be used to update security documentation
- **CI/CD**: Some scripts can be integrated into the CI/CD pipeline
- **Compliance**: Findings support regulatory compliance reporting
- **Incident Response**: Scripts provide evidence for security incidents

## Emergency Response

In case of a security incident:

1. Run `security_audit.py --emergency` to perform an immediate full security scan
2. Review `/var/log/cloud-platform/security/incident*.log` for security events
3. Contact the security team at <security@example.com>
4. For critical incidents, call the security hotline: +1-555-123-4567

## Compliance

These scripts help maintain compliance with:

- ISO 27001
- SOC 2 Type II
- GDPR
- NIST Cybersecurity Framework
- PCI DSS (where applicable)
- HIPAA (where applicable)
- CIS Benchmarks
- OWASP Security Standards

## Version History

| Version | Date | Description | Author |
| --- | --- | --- | --- |
| 1.0 | 2023-07-15 | Initial security scripts | Security Team |
| 1.1 | 2023-10-22 | Added WAF validation | DevOps Team |
| 1.2 | 2023-12-15 | Updated compliance requirements | Compliance Manager |
| 2.0 | 2024-03-10 | Major update with enhanced auditing | Security Architect |
| 2.1 | 2024-07-05 | Added access review capabilities | Security Team |
