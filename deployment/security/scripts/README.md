# Security Scripts for Cloud Infrastructure Platform

This directory contains security scripts that automate setup, configuration, monitoring, and maintenance of security controls for the Cloud Infrastructure Platform across various environments.

## Contents

- Overview
- Key Scripts
- Directory Structure
- Usage
- Best Practices & Security
- Common Features
- Related Documentation
- Version History

## Overview

The security scripts implement critical security functions including certificate management, firewall configuration, security hardening, integrity verification, and security auditing. These scripts follow defense-in-depth principles and adhere to industry standards such as CIS benchmarks, NIST guidelines, and OWASP recommendations to ensure robust security across development, staging, and production environments.

## Key Scripts

- **`certificate_renew.sh`**: SSL/TLS certificate renewal automation
  - **Usage**: Renews SSL/TLS certificates for domains using Let's Encrypt
  - **Features**:
    - Automated certificate renewal
    - Certificate backup
    - Certificate validation
    - Expiration monitoring
    - NGINX configuration testing
    - Notification system

- **`check_security_updates.sh`**: Security updates verification script
  - **Usage**: Checks for available security updates across systems
  - **Features**:
    - Critical update identification
    - Multiple package manager support
    - Notification alerts
    - Report generation
    - Update scheduling

- **`iptables_rules.sh`**: Firewall configuration script
  - **Usage**: Configures iptables firewall rules for system protection
  - **Features**:
    - Defense-in-depth firewall rules
    - Environment-aware configuration
    - Internal network protection
    - Rate limiting
    - Service-specific rules
    - Stateful packet inspection

- **`security_audit.sh`**: Security audit and reporting tool
  - **Usage**: Conducts comprehensive security assessments
  - **Features**:
    - File permission analysis
    - Firewall configuration verification
    - HTML report generation
    - Missing update detection
    - Multiple security checks
    - Secure service configuration validation
    - SSL/TLS analysis
    - User account assessment

- **`security_setup.sh`**: Main security setup and hardening script
  - **Usage**: Performs initial security setup and hardening
  - **Features**:
    - AppArmor profile configuration
    - Environment-specific hardening
    - Fail2ban setup
    - File integrity monitoring setup
    - Firewall configuration
    - ModSecurity WAF configuration
    - NGINX security configuration
    - SSH hardening

- **`setup_modsecurity.sh`**: ModSecurity WAF installation and configuration
  - **Usage**: Installs and configures ModSecurity Web Application Firewall
  - **Features**:
    - Core Rule Set installation
    - Custom rule implementation
    - Environment-specific tuning
    - Integration with NGINX
    - Performance optimization
    - Rule testing framework

- **`update_blocklist.sh`**: IP blocklist updates for perimeter defense
  - **Usage**: Updates IP blocklists from threat intelligence sources
  - **Features**:
    - Automated blocklist retrieval
    - Blocklist verification
    - Firewall rule integration
    - Multiple source support
    - Rule deduplication

- **`update_modsecurity_rules.sh`**: WAF rules update script
  - **Usage**: Updates ModSecurity WAF rules including OWASP CRS
  - **Features**:
    - Automatic backup creation
    - Configuration testing
    - Custom rule preservation
    - Error handling with rollback
    - OWASP CRS update support
    - Permission management
    - Safe NGINX reload

- **`verify_permissions.sh`**: Critical file permissions verification
  - **Usage**: Audits and corrects permissions on security-critical files
  - **Features**:
    - Configuration file verification
    - Deviation reporting
    - Key file monitoring
    - Permission remediation
    - Security baseline compliance

## Directory Structure

```plaintext
deployment/security/scripts/
├── README.md                    # This documentation
├── certificate_renew.sh         # SSL/TLS certificate renewal automation
├── check_security_updates.sh    # Security updates verification script
├── iptables_rules.sh            # Firewall configuration script
├── security_audit.sh            # Security audit and reporting tool
├── security_setup.sh            # Main security setup and hardening script
├── setup_modsecurity.sh         # ModSecurity WAF installation and configuration
├── update_blocklist.sh          # IP blocklist updates for perimeter defense
├── update_modsecurity_rules.sh  # WAF rules update script
└── verify_permissions.sh        # Critical file permissions verification
```

## Usage

### Certificate Management

```bash
# Renew certificates
./certificate_renew.sh

# Check certificate expiration without renewal
./certificate_renew.sh --check-only

# Specify custom domain and email
./certificate_renew.sh --domain example.com --email admin@example.com
```

### Security Hardening

```bash
# Set up security for production
./security_setup.sh production

# Set up security for development environment
./security_setup.sh development
```

### Security Auditing

```bash
# Run a comprehensive security audit
./security_audit.sh --email security@example.com

# Run audit excluding specific checks
./security_audit.sh --skip-firewall --skip-users
```

### Firewall and WAF Management

```bash
# Update firewall rules
./iptables_rules.sh

# Install and configure ModSecurity WAF
./setup_modsecurity.sh

# Update ModSecurity WAF rules
./update_modsecurity_rules.sh
```

## Best Practices & Security

- Always run scripts with appropriate privileges (usually root)
- Create backups before making changes to system configuration
- Follow the principle of least privilege for file permissions
- Implement proper error handling and rollback mechanisms
- Keep error and activity logs for auditing purposes
- Maintain secure defaults that require explicit opt-out
- Run scripts in development/staging environments before production
- Store sensitive credentials securely, never hardcode in scripts
- Test changes thoroughly before implementing in production
- Use environment-specific configurations

## Common Features

These security scripts share several common features:

- **Backup Creation**: Automatic backup of configurations before changes
- **Comprehensive Logging**: Detailed output for troubleshooting and auditing
- **Email Notifications**: Alerts for critical events and failures
- **Environment Awareness**: Different behavior based on deployment environment
- **Error Handling**: Proper error detection and graceful failure
- **File Permission Management**: Appropriate permission settings for security
- **Rollback Capabilities**: Restore previous state in case of failure
- **Secure Default Settings**: Conservative security defaults requiring explicit opt-out
- **System Validation**: Pre and post-execution validation checks
- **Verbose Reporting**: Detailed information about operations and findings

## Related Documentation

- Compliance Requirements Documentation
- ModSecurity WAF Configuration Guide
- NGINX Security Hardening Guidelines
- Penetration Testing Procedures
- Security Architecture Overview
- Security Hardening Checklist
- Security Incident Response Procedures
- SSL/TLS Certificate Management Guide
- System Monitoring Documentation

## Version History

- **1.3.0 (2024-03-15)**: Enhanced security audit with detailed HTML reports
- **1.2.0 (2023-12-10)**: Added WAF rule update automation and validation
- **1.1.0 (2023-10-05)**: Enhanced firewall configurations with environment-specific rules
- **1.0.0 (2023-08-01)**: Initial release of security scripts
