# System Security Checkers

This directory contains security check modules for validating system-level security controls in the Cloud Infrastructure Platform. These checkers verify authentication configurations, password policies, and service security settings to identify vulnerabilities and compliance violations.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
- [Related Documentation](#related-documentation)

## Overview

The system security checkers implement specialized validation of core operating system security controls. These modules focus on system-level security configurations such as authentication mechanisms, password policies, and service security settings that form the foundation of the platform's security posture. Each checker provides detailed findings with severity classification, remediation guidance, and compliance mapping.

## Key Components

- **`auth_check.py`**: Validates authentication system configurations.
  - **Usage**: Verifies that authentication mechanisms implement appropriate security controls.
  - **Features**:
    - PAM configuration verification
    - Multi-factor authentication validation
    - Login restrictions enforcement
    - Session timeout configuration
    - Failed login attempt handling
    - Account lockout policy verification
    - Authentication log monitoring
    - LDAP/Active Directory security settings
    - Local authentication security checks
    - Authentication bypass detection

- **`password_policy_check.py`**: Evaluates password policy implementation and strength.
  - **Usage**: Ensures that password policies meet security requirements and best practices.
  - **Features**:
    - Password complexity requirements
    - Password aging configuration
    - Password history enforcement
    - Password storage security
    - Minimum password length verification
    - Password reuse restrictions
    - Default password detection
    - Password hash algorithm validation
    - Password quality requirements
    - Special requirements for privileged accounts

- **`service_check.py`**: Validates security configurations of system services.
  - **Usage**: Checks that system services are securely configured and unnecessary services are disabled.
  - **Features**:
    - Service privilege verification
    - Unnecessary service detection
    - Service isolation validation
    - Service configuration validation
    - Service dependency analysis
    - Systemd unit security checks
    - Network-facing service validation
    - Service hardening verification
    - Service auto-restart configuration
    - Service account privilege limitation

## Directory Structure

```plaintext
scripts/security/audit/checkers/system/
├── README.md                  # This documentation
├── auth_check.py              # Authentication configuration checks
├── password_policy_check.py   # Password policy verification
└── service_check.py           # Service security configuration checks
```

## Configuration

Each system checker can be configured through YAML configurations, environment variables, or direct parameter passing:

### Authentication Check Configuration

```yaml
authentication:
  # PAM configuration
  pam:
    required_modules:
      - pam_tally2.so
      - pam_faillock.so
      - pam_unix.so

  # Account lockout settings
  account_lockout:
    max_attempts: 5
    lockout_duration: 900  # seconds

  # Session settings
  session:
    timeout: 900  # seconds
    remember_limit: 30  # days

  # Multi-factor requirements
  mfa:
    privileged_accounts: true
    remote_access: true
    required_for_services:
      - ssh
      - admin_console
```

### Password Policy Configuration

```yaml
password_policy:
  # Complexity requirements
  complexity:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_special: true

  # Password aging
  aging:
    max_days: 90
    min_days: 1
    warn_days: 7

  # History and reuse prevention
  history:
    remember_count: 5

  # Privileged account requirements
  privileged:
    min_length: 16
    require_mfa: true
```

### Service Check Configuration

```yaml
services:
  # Services that should be enabled
  required:
    - sshd
    - auditd
    - firewalld

  # Services that should be disabled
  prohibited:
    - telnet
    - rsh-server
    - sendmail

  # Service user restrictions
  user_restrictions:
    disable_shell: true
    restrict_home: true

  # Configuration checks
  config_files:
    - path: /etc/ssh/sshd_config
      requirements:
        - PermitRootLogin no
        - PasswordAuthentication no
```

## Best Practices & Security

- Run system checks with sufficient privileges to access protected files
- Tailor checks to environment specifics (development vs production)
- Add custom checks for organization-specific security policies
- Conduct comprehensive validation after system upgrades
- Verify remediation actions with follow-up scans
- Maintain baseline configurations in version control
- Document deviations from security standards with justification
- Test new checks thoroughly before deploying to production
- Add appropriate exclusions for intentional exceptions
- Use dedicated audit accounts with limited privileges for automated checks
- Implement change detection for critical security configurations
- Follow up on all findings classified as high or critical
- Apply centralized reporting for findings across multiple systems
- Leverage historical findings to track security posture over time

## Common Features

- Integration with common check framework for consistent reporting
- Detailed remediation instructions for each finding
- Severity-based classification (critical, high, medium, low, info)
- Performance optimization for running on production systems
- Support for different operating systems and distributions
- Compliance mapping to industry standards (CIS, NIST, etc.)
- Evidence collection for audit trail
- Custom check extension framework
- Exclusion handling for approved exceptions
- Support for command-line and programmatic invocation
- Result caching to improve performance
- Incremental checking for regular execution
- Delta reporting to highlight new findings
- Configuration validation with secure defaults
- Parallel execution capabilities

## Usage Examples

### Authentication Configuration Verification

```python
from scripts.security.audit.checkers.system.auth_check import AuthenticationChecker

# Create checker with default configuration
checker = AuthenticationChecker()

# Run checks against policy
results = checker.check()

# Filter for high severity issues
high_severity = [r for r in results if r.severity.name in ('HIGH', 'CRITICAL')]

# Print findings
for result in high_severity:
    print(f"[{result.severity.name}] {result.title}: {result.description}")
    print(f"  Remediation: {result.remediation}")
    if result.compliance:
        print(f"  Compliance: {', '.join(result.compliance)}")
    print("---")
```

### Password Policy Validation

```python
from scripts.security.audit.checkers.system.password_policy_check import PasswordPolicyChecker

# Create checker with custom configuration
config = {
    "complexity": {
        "min_length": 14,
        "require_special": True
    },
    "aging": {
        "max_days": 60
    }
}

checker = PasswordPolicyChecker(config=config)

# Check if system meets custom policy
results = checker.check()

# Generate compliance report
compliance_report = checker.generate_compliance_report("pci-dss")

# Show all findings
for result in results:
    print(f"[{result.severity.name}] {result.title}")
    print(f"  {result.description}")
    print(f"  Remediation: {result.remediation}")
```

### Service Security Verification

```python
from scripts.security.audit.checkers.system.service_check import ServiceChecker

# Create checker
service_checker = ServiceChecker()

# Verify specific services
results = service_checker.check_services(["sshd", "httpd", "postgresql"])

# Check for unnecessary services
unnecessary = service_checker.find_unnecessary_services()
if unnecessary:
    print("Unnecessary services running:")
    for service in unnecessary:
        print(f"  - {service}")

# Check service configuration files
config_results = service_checker.check_service_configs()

# Generate report
report = service_checker.generate_report(include_all_services=False)
```

### Integration with Security Audit Framework

```python
from scripts.security.audit.checkers.common.check_result import CheckResultSet
from scripts.security.audit.checkers.system.auth_check import AuthenticationChecker
from scripts.security.audit.checkers.system.password_policy_check import PasswordPolicyChecker
from scripts.security.audit.checkers.system.service_check import ServiceChecker

def run_system_security_checks(baseline=None):
    """Run comprehensive system security checks."""
    results = CheckResultSet()

    # Run authentication checks
    auth_checker = AuthenticationChecker()
    results.add_results(auth_checker.check())

    # Run password policy checks
    password_checker = PasswordPolicyChecker()
    results.add_results(password_checker.check())

    # Run service security checks
    service_checker = ServiceChecker()
    results.add_results(service_checker.check())

    # Compare against baseline if provided
    if baseline:
        results.compare_with_baseline(baseline)

    return results
```

## Related Documentation

- Common Checker Framework
- Security Audit Overview
- CIS Authentication Controls
- Password Policy Guidelines
- System Service Security Guide
- Authentication Best Practices
- System Security Baseline
- PAM Configuration Guide
- Service Hardening Documentation
- Account Security Implementation
