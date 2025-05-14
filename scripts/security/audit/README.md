# Security Audit Tools

This directory contains audit-specific modules, templates, and configuration files for security auditing within the Cloud Infrastructure Platform. These tools provide standardized mechanisms for verifying security baselines, implementing compliance checks, and generating comprehensive security reports.

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

The security audit tools implement a modular framework for conducting security assessments against predefined baselines. They support multiple compliance frameworks, generate standardized reports, and provide remediation guidance for identified issues. These tools are designed to operate both in interactive mode for manual assessments and automated mode for continuous security monitoring.

## Key Components

- **`baseline/`**: Security baseline configurations for different environments and compliance standards.
  - **Usage**: Reference implementations of security controls and expected configurations.
  - **Features**:
    - Environment-specific baselines (development, staging, production)
    - Compliance-mapped configurations (PCI DSS, HIPAA, ISO 27001, etc.)
    - Critical system hardening guidelines
    - Versioned baseline history
    - Deviation justification framework

- **`checkers/`**: Individual security check implementations for specific controls.
  - **Usage**: Modular security checks that can be combined for comprehensive audits.
  - **Features**:
    - File permission validation
    - Firewall rule verification
    - User access auditing
    - Service configuration checks
    - SSL/TLS implementation verification
    - Container security validation
    - Network segmentation verification
    - Password policy enforcement
    - Encryption standards compliance

- **`templates/`**: Report templates for different output formats and audiences.
  - **Usage**: Standardized formats for audit result presentation.
  - **Features**:
    - Executive summary templates
    - Technical detail reports
    - Compliance documentation formats
    - Remediation guidance documents
    - Finding prioritization matrices
    - Risk scoring methodology
    - Evidence documentation formats

## Directory Structure

```plaintext
scripts/security/audit/
├── README.md                           # This documentation
├── baseline/                           # Security baseline configurations
│   ├── compliance/                     # Compliance-specific baselines
│   │   ├── cis/                        # CIS benchmark baselines
│   │   │   ├── cis_debian_linux.yaml   # CIS Debian Linux benchmark
│   │   │   ├── cis_nginx.yaml          # CIS NGINX benchmark
│   │   │   └── cis_postgres.yaml       # CIS PostgreSQL benchmark
│   │   ├── hipaa/                      # HIPAA compliance baselines
│   │   ├── iso27001/                   # ISO 27001 compliance baselines
│   │   ├── nist/                       # NIST framework baselines
│   │   └── pci/                        # PCI DSS compliance baselines
│   └── environment/                    # Environment-specific baselines
│       ├── common.yaml                 # Common baseline for all environments
│       ├── development.yaml            # Development environment baseline
│       ├── production.yaml             # Production environment baseline
│       └── staging.yaml                # Staging environment baseline
├── checkers/                           # Individual audit check implementations
│   ├── common/                         # Common check utilities
│   │   ├── check_helper.py             # Helper functions for check modules
│   │   ├── check_result.py             # Standardized check result class
│   │   └── check_utils.py              # Utility functions for checks
│   ├── file_permissions/               # File permission checks
│   │   ├── critical_file_check.py      # Critical file permissions check
│   │   ├── ownership_check.py          # File ownership verification
│   │   └── world_writable_check.py     # World-writable file detection
│   ├── network/                        # Network security checks
│   │   ├── firewall_check.py           # Firewall rule verification
│   │   ├── open_port_check.py          # Open port detection
│   │   └── tls_check.py                # TLS configuration checks
│   └── system/                         # System security checks
│       ├── auth_check.py               # Authentication configuration checks
│       ├── password_policy_check.py    # Password policy verification
│       └── service_check.py            # Service security configuration checks
└── templates/                          # Report templates
    ├── html/                           # HTML report templates
    │   ├── executive_summary.html      # Executive summary template
    │   ├── technical_report.html       # Technical details template
    │   └── css/                        # CSS styles for HTML reports
    ├── json/                           # JSON report templates
    │   └── schema.json                 # JSON schema for reports
    └── text/                           # Text report templates
        ├── executive_summary.txt       # Text executive summary
        └── technical_report.txt        # Text technical report
```

## Configuration

The audit tools can be configured through several methods:

1. **Command-line arguments**: Pass configuration options directly to the audit scripts.
2. **Environment variables**: Set audit-specific variables in the environment.
3. **Configuration files**: Specify custom configuration files for audit runs.

### Key Configuration Options

| Configuration      | Environment Variable     | Default                     | Description                                          |
|--------------------|--------------------------|----------------------------|------------------------------------------------------|
| Baseline Path      | `AUDIT_BASELINE_PATH`    | `baseline/environment/`     | Path to baseline configuration directory             |
| Compliance Profile | `AUDIT_COMPLIANCE`       | `common`                    | Compliance profile to use for checks                 |
| Output Format      | `AUDIT_OUTPUT_FORMAT`    | `text`                      | Output format (text, json, html, csv)                |
| Report Level       | `AUDIT_REPORT_LEVEL`     | `standard`                  | Report detail level (summary, standard, detailed)    |
| Check Modules      | `AUDIT_CHECK_MODULES`    | `all`                       | Comma-separated list of check modules to run         |
| Risk Threshold     | `AUDIT_RISK_THRESHOLD`   | `medium`                    | Minimum risk level to include in reports             |
| Notification       | `AUDIT_NOTIFY`           | `false`                     | Whether to send notifications for findings           |
| Remediate          | `AUDIT_AUTO_REMEDIATE`   | `false`                     | Whether to automatically remediate fixable issues    |
| Evidence Path      | `AUDIT_EVIDENCE_PATH`    | `/var/log/security/evidence` | Path to store audit evidence files                  |

## Best Practices & Security

- Run audit tools with appropriate privileges (usually root)
- Store baseline configurations in version control
- Document deviations from baselines with justification
- Review all changes to baseline configurations
- Use least-privilege accounts for automated audit runs
- Store audit evidence securely with restricted access
- Validate baseline configurations against published standards
- Regularly update baselines to address new threats
- Test new audit checks thoroughly before deployment
- Control access to audit reports containing sensitive findings
- Apply appropriate retention policies to historical audit data
- Never disable checks without proper justification and documentation
- Track findings over time to identify patterns and trends
- Validate remediation effectiveness with follow-up audits

## Common Features

- Modular check framework for easy extension
- Consistent result reporting format
- Severity-based prioritization of findings
- Evidence collection and preservation
- Compliance mapping for findings
- Remediation guidance
- Comparison against historical results
- Delta reporting for changes
- Exemption handling for authorized deviations
- Support for multiple output formats
- Integration with notification systems
- Performance optimization for large-scale audits
- Distributed audit capability
- Parallel check execution
- Resource utilization limits
- Comprehensive audit logging

## Usage Examples

### Basic Security Audit

```bash
# Run a comprehensive security audit using default settings
../security_audit.py --use-baseline=production

# Run specific security checks
../security_audit.py --modules=file_permissions,network,authentication

# Generate HTML report with detailed findings
../security_audit.py --output-format=html --report-level=detailed --output-file=/var/www/security/audit-report.html
```

### Compliance Verification

```bash
# Verify compliance with PCI DSS requirements
../security_audit.py --compliance=pci --report-format=json --output-file=pci-compliance.json

# Verify compliance with HIPAA security standards
../security_audit.py --compliance=hipaa --report-format=html --output-file=hipaa-compliance.html

# Verify compliance with CIS benchmarks
../security_audit.py --compliance=cis --check-group=os --output-format=text
```

### Baseline Management

```bash
# Create a new baseline from current system state
../security_audit.py --create-baseline --baseline-name=custom --baseline-description="Custom baseline for application servers"

# Update existing baseline with approved changes
../security_audit.py --update-baseline=production --changes-approved-by="Security Team" --change-ticket="SEC-1234"

# Compare system against multiple baselines
../security_audit.py --compare-baselines --baselines=production,staging --output-format=html
```

### Automated Integration

```bash
# Integration with CI/CD pipeline
../security_audit.py --ci-mode --fail-on=high --quiet --output-format=json --output-file=/tmp/security-results.json

# Integration with monitoring system
../security_audit.py --monitoring-mode --threshold=medium --statsd-prefix=security.audit
```

## Related Documentation

- Security Scripts Overview
- Security Architecture Overview
- Compliance Framework Documentation
- Audit Requirements Guide
- Baseline Configuration Guide
- Check Development Guide
- CIS Benchmarks Implementation
- Evidence Handling Procedures
- Automated Security Testing
- File Integrity Monitoring
