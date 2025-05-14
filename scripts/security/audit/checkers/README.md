# Security Audit Checkers

This directory contains modular security check implementations for verifying security controls across the Cloud Infrastructure Platform. These checkers provide specialized validation for specific security domains including file permissions, network security, system configurations, and common utilities.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
- [Development Guide](#development-guide)
- [Related Documentation](#related-documentation)

## Overview

The security audit checkers implement a modular approach to security validation, allowing individual checks to be run independently or combined into comprehensive security assessments. Each check follows a consistent pattern for severity classification, evidence collection, compliance mapping, and remediation guidance to ensure standardized findings across all security domains.

Checkers are organized by security domain (file permissions, network, system) with common functionality shared through the `common` package. This architecture enables consistent security validation while allowing specialized checks for domain-specific requirements.

## Key Components

- **`common/`**: Shared utilities and base components for implementing security checks.
  - **Usage**: Import these modules to implement standardized security checks.
  - **Features**:
    - Security baseline loading and application
    - Standardized result representation
    - Evidence collection utilities
    - Secure command execution
    - Permission validation functions
    - Result formatting (JSON, Markdown, HTML)
    - Resource limit management
    - Error handling patterns

- **`file_permissions/`**: Checkers for file and directory permissions.
  - **Usage**: Use these checkers to validate file system security controls.
  - **Features**:
    - Critical file permission validation
    - File ownership verification
    - World-writable file detection
    - SUID/SGID file detection
    - Recursive directory scanning
    - Permission remediation commands
    - Exception handling for authorized deviations

- **`network/`**: Checkers for network and communication security.
  - **Usage**: Use these checkers to validate network security controls.
  - **Features**:
    - Firewall rule verification
    - Open port detection
    - TLS/SSL configuration validation
    - Network segmentation verification
    - Service exposure analysis
    - Protocol security validation
    - Security header verification

- **`system/`**: Checkers for operating system and service security.
  - **Usage**: Use these checkers to validate system security controls.
  - **Features**:
    - Authentication mechanism validation
    - Password policy verification
    - Service security configuration
    - Account security validation
    - System hardening verification
    - Default configuration validation
    - Unnecessary service detection

## Directory Structure

```plaintext
scripts/security/audit/checkers/
├── README.md                      # This documentation
├── common/                        # Common check utilities
│   ├── README.md                  # Common utilities documentation
│   ├── __init__.py                # Package initialization
│   ├── check_helper.py            # Helper functions for check modules
│   ├── check_result.py            # Standardized check result class
│   └── check_utils.py             # Utility functions for checks
├── file_permissions/              # File permission checks
│   ├── README.md                  # File permission checks documentation
│   ├── __init__.py                # Package initialization
│   ├── critical_file_check.py     # Critical file permissions check
│   ├── ownership_check.py         # File ownership verification
│   └── world_writable_check.py    # World-writable file detection
├── network/                       # Network security checks
│   ├── README.md                  # Network checks documentation
│   ├── __init__.py                # Package initialization
│   ├── firewall_check.py          # Firewall rule verification
│   ├── open_port_check.py         # Open port detection
│   └── tls_check.py               # TLS configuration checks
└── system/                        # System security checks
    ├── README.md                  # System checks documentation
    ├── __init__.py                # Package initialization
    ├── auth_check.py              # Authentication configuration checks
    ├── password_policy_check.py   # Password policy verification
    └── service_check.py           # Service security configuration checks
```

## Configuration

Each security checker supports a consistent configuration approach with environment-specific overrides:

1. **Default Configuration**: Built-in defaults for each checker
2. **Baseline Configuration**: Environment-specific settings (development, staging, production)
3. **Runtime Configuration**: Parameters passed at runtime

Configuration may be provided through:

- Command-line arguments
- Environment variables
- YAML configuration files
- Programmatic API calls

### Common Configuration Options

| Option | Description |
|--------|-------------|
| `baseline` | Baseline name (environment) to validate against |
| `compliance_framework` | Compliance standard to apply (CIS, NIST, PCI-DSS, etc.) |
| `report_format` | Output format (text, json, markdown, html) |
| `severity_threshold` | Minimum severity level to include in results (low, medium, high, critical) |
| `evidence_collection` | Whether to collect evidence for findings (true, false) |
| `remediation` | Whether to generate remediation commands (basic, detailed, none) |
| `output_file` | File path for saving results |

## Best Practices & Security

- Run checks with appropriate privileges to access required resources
- Use the principle of least privilege when configuring automated check execution
- Document intentional exceptions in baseline configurations
- Verify remediation actions after addressing findings
- Collect and retain evidence securely for compliance purposes
- Implement additional security controls when running in regulated environments
- Test new checks thoroughly in development before deploying to production
- Validate security findings before taking remediation actions
- Run checks regularly to detect configuration drift
- Include security check results in change management processes
- Use version-controlled baseline configurations
- Audit all changes to security baselines
- Use secure communications for handling check results
- Apply appropriate access controls to check results

## Common Features

- Standardized severity classification (critical, high, medium, low, info)
- Consistent evidence collection for audit trails
- Detailed remediation instructions
- Performance optimization for minimal system impact
- Comprehensive compliance mapping
- Secure handling of sensitive information
- Custom check extensions
- Incremental check execution
- Parallel checking capabilities
- Central baseline configuration
- Evidence preservation
- Historical comparison
- Check dependencies and prerequisites
- Clear reporting with detailed context
- Cross-platform support where applicable

## Usage Examples

### Running Individual Checkers

```python
from scripts.security.audit.checkers.file_permissions import critical_file_check

# Create checker with default configuration
checker = critical_file_check.CriticalFileChecker()

# Run the check
results = checker.check()

# Print findings
for result in results:
    print(f"[{result.severity.name}] {result.title}")
    print(f"  Description: {result.description}")
    print(f"  Remediation: {result.remediation}")
    if result.compliance:
        print(f"  Compliance: {', '.join(result.compliance)}")
    print("---")
```

### Checking Network Security

```python
from scripts.security.audit.checkers.network import open_port_check

# Create checker with specified allowed ports
checker = open_port_check.OpenPortChecker()
checker.set_allowed_ports([22, 80, 443, 5432])

# Run check
results = checker.check()

# Generate a report
report = checker.generate_report(format='html')

# Save report to file
with open('open_ports_report.html', 'w') as f:
    f.write(report)
```

### Checking System Security

```python
from scripts.security.audit.checkers.system import password_policy_check

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

# Initialize and run check
checker = password_policy_check.PasswordPolicyChecker(config=config)
results = checker.check()

# Filter by severity
high_severity = [r for r in results if r.severity.name in ('HIGH', 'CRITICAL')]

# Create aggregated report with multiple checkers
from scripts.security.audit.checkers.common import CheckResultSet
result_set = CheckResultSet()
result_set.add_results(results)

# Generate compliance report
compliance_report = result_set.generate_report(
    title="Password Policy Compliance",
    format="json"
)
```

### Using Common Utilities

```python
from scripts.security.audit.checkers.common import CheckResult, Severity

# Create a custom check result
result = CheckResult(
    severity=Severity.MEDIUM,
    title="Weak Service Configuration",
    description="Service is running with default configuration",
    remediation="Apply custom configuration according to security baseline",
    evidence={"service": "nginx", "config": "/etc/nginx/nginx.conf"}
)

# Add compliance mapping
result.add_compliance_references(["CIS 3.1.4", "NIST AC-3"])

# Add context
result.add_context("environment", "production")
```

## Development Guide

Follow these steps when creating new security checks:

1. **Select the Appropriate Domain**: Place your check in the most relevant directory (file_permissions, network, system)

2. **Use Common Base Classes**: Inherit from provided base classes in the common package

3. **Follow Standard Patterns**: Implement standard methods:
   - `check()`: Main entry point that returns a list of CheckResult objects
   - `_check_X()`: Internal methods for specific validations
   - `get_evidence()`: Evidence collection for findings
   - `get_remediation()`: Remediation guidance generation

4. **Implement Severity Classification**: Use the standard Severity enumeration:
   - `CRITICAL`: Immediate action required, significant security risk
   - `HIGH`: Important security issue requiring prompt action
   - `MEDIUM`: Security issue that should be addressed
   - `LOW`: Minor security issue that should be fixed when possible
   - `INFO`: Informational finding with minimal security impact

5. **Include Compliance Mappings**: Map findings to relevant compliance standards

6. **Provide Clear Remediation**: Include specific remediation steps for each finding

7. **Handle Errors Gracefully**: Use the error handling patterns from common module

8. **Add Documentation**: Document all assumptions, limitations and requirements

## Related Documentation

- Security Audit Overview
- Common Check Utilities
- File Permission Checks
- Network Security Checks
- System Security Checks
- Security Baseline Configuration
- Security Check Development Guide
- Security Compliance Mapping
- Checker Integration Guide
