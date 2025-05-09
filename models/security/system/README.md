# System-Level Security Models

This package contains database models related to system-level security functionalities for the Cloud Infrastructure Platform, providing core infrastructure for security governance, configuration management, compliance verification, and security monitoring.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage Examples](#usage-examples)
- [Implementation Notes](#implementation-notes)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The system-level security models provide foundational security infrastructure that underpins the platform's security posture. These models implement comprehensive auditing, baseline security standards, configuration management, compliance verification, security scan tracking, and file integrity monitoring. The components in this package enable systematic security monitoring, compliance validation, and configuration management across all environments.

## Key Components

- **`AuditLog`**: Comprehensive security event logging system
  - Records all security-relevant events with structured data
  - Supports different severity levels and event categorization
  - Enables compliance tracking and security investigation
  - Provides search, filtering, and analysis capabilities
  - Maintains tamper-resistant logging for auditability
  - Integrates with alerting for critical security events

- **`ComplianceCheck`**: Compliance verification and reporting
  - Maps controls to compliance frameworks (GDPR, HIPAA, PCI-DSS, etc.)
  - Records compliance status with evidence references
  - Supports audit preparation with compliance reports
  - Tracks remediation efforts for non-compliant controls
  - Provides compliance metrics and trend analysis
  - Generates compliance attestation reports
  - Supports file, configuration, and API-based checks

- **`ComplianceControl`**: Compliance control implementation
  - Links controls to specific compliance frameworks
  - Defines implementation requirements and validation methods
  - Supports control categorization and prioritization
  - Maps to technical security baseline controls

- **`ComplianceFramework`**: Compliance standards definition
  - Manages compliance standard information and structure
  - Tracks compliance framework versions and requirements
  - Supports mapping between different compliance frameworks
  - Provides focused views for specific compliance domains

- **`ComplianceValidator`**: Compliance validation engine
  - Validates systems against compliance requirements
  - Generates comprehensive validation reports in multiple formats
  - Supports framework-specific and category-based validation
  - Provides summary metrics and detailed results
  - Integrates with security incident workflows

- **`FileIntegrityBaseline`**: File integrity monitoring baseline management
  - Creates and manages file integrity monitoring baselines
  - Tracks cryptographic hashes of critical system files
  - Detects unauthorized modifications to protected files
  - Supports multiple baseline profiles for different environments
  - Provides change detection with severity classification
  - Performs integrity verification against stored baselines
  - Includes backup and restore capabilities for baselines
  - Exports and imports baseline data in multiple formats

- **`SecurityBaseline`**: Security standard definitions and tracking
  - Defines expected security configurations for different systems
  - Maps baseline controls to compliance requirements
  - Supports baseline validation against actual configurations
  - Tracks deviations with risk assessment capabilities
  - Provides versioned security standards with change history
  - Implements exemption workflows with approval tracking

- **`SecurityScan`**: Security scanning configuration and results
  - Manages security scan schedules and configurations
  - Stores comprehensive scan results with finding details
  - Tracks remediation status for identified vulnerabilities
  - Supports different scan types (vulnerability, compliance, etc.)
  - Provides scan metrics and trend analysis
  - Integrates with external scanning tools
  - Filters findings by severity, status, and target

- **`SystemConfig`**: Security-related configuration management
  - Stores security parameters with version tracking
  - Manages environment-specific security settings
  - Provides configuration validation capabilities
  - Tracks configuration changes with audit logging
  - Implements secure default values for all parameters
  - Manages configuration encryption for sensitive values

## Directory Structure

```plaintext
models/security/system/
├── __init__.py                # Package initialization and exports
├── audit_log.py               # Security event logging system
├── compliance_check.py        # Compliance verification models
├── file_integrity_baseline.py # File integrity monitoring baseline management
├── README.md                  # This documentation
├── security_baseline.py       # Security standards definition
├── security_scan.py           # Security scanning results
└── system_config.py           # Security configuration storage
```

## Usage Examples

### Audit Logging

```python
from models.security.system import AuditLog

# Log a security event
AuditLog.log_event(
    event_type=AuditLog.EVENT_CONFIG_CHANGE,
    resource_type="security_policy",
    resource_id="firewall-policy-123",
    user_id=current_user.id,
    details={
        "action": "update",
        "old_value": {"allow_ssh": True},
        "new_value": {"allow_ssh": False},
        "change_reason": "Implementing security hardening"
    },
    severity=AuditLog.SEVERITY_MEDIUM
)

# Query security events by time range
recent_events = AuditLog.get_events_by_timeframe(
    start_time=datetime.now() - timedelta(hours=24),
    end_time=datetime.now(),
    event_types=[AuditLog.EVENT_LOGIN_FAILED],
    severity_min=AuditLog.SEVERITY_MEDIUM
)

# Get event distribution by type
event_counts = AuditLog.get_event_distribution(days=30)
for event_type, count in event_counts.items():
    print(f"{event_type}: {count} events")

# Export audit logs for compliance reporting
report = AuditLog.export_events_to_report(
    start_time=last_month,
    end_time=today,
    format_type="csv"
)
```

### Security Baseline Management

```python
from models.security.system import SecurityBaseline

# Create a new security baseline
linux_baseline = SecurityBaseline(
    name="Linux Server Hardening",
    version="1.2.0",
    description="Security baseline for Linux servers based on CIS Benchmarks",
    system_type="linux_server",
    created_by_id=current_user.id
)
linux_baseline.save()

# Add baseline items
linux_baseline.add_item(
    control_id="1.1",
    title="Disable unused filesystems",
    description="Disable mounting of unused filesystems",
    implementation="Edit /etc/modprobe.d/CIS.conf and add install cramfs /bin/true",
    verification="Run lsmod | grep cramfs should return no results",
    remediation="Add installation lines to /etc/modprobe.d/CIS.conf",
    impact="Low",
    priority=SecurityBaseline.PRIORITY_MEDIUM
)

# Create baseline assessment
assessment = linux_baseline.create_assessment(
    system_id="web-server-01",
    assessor_id=current_user.id
)

# Record assessment results
assessment.add_result(
    control_id="1.1",
    status=SecurityBaseline.STATUS_PASS,
    evidence="Command output confirmed cramfs is not loaded",
    notes="Verified via SSH and running lsmod | grep cramfs"
)

# Calculate compliance percentage
compliance = assessment.calculate_compliance()
print(f"System is {compliance}% compliant with baseline")
```

### Compliance Verification

```python
from models.security.system import ComplianceCheck, ComplianceStatus, ComplianceValidator

# Create a compliance check
check = ComplianceCheck(
    control_id=1,
    name="Verify Password Policy",
    check_type=ComplianceCheck.CHECK_TYPE_CONFIG,
    description="Verify password policy meets requirements",
    parameters={
        "config_path": "security/password_policy.conf",
        "key": "min_length",
        "expected": "12",
        "check_type": "key_value_min"
    },
    enabled=True
)

# Execute the check
status, details = check.execute(user_id=admin_id)
if status == ComplianceStatus.FAILED.value:
    print(f"Check failed: {details.get('message', '')}")

# Run compliance validation for specific framework
validator = ComplianceValidator(framework="PCI-DSS")
results = validator.validate(user_id=admin_id)

# Generate compliance reports in different formats
text_report = validator.generate_report(format='text')
html_report = validator.generate_report(format='html', output_file='compliance_report.html')
json_report = validator.generate_report(format='json')

# Check the overall compliance status
if json_report['summary']['overall_status'] == ComplianceStatus.PASSED.value:
    print("System is compliant with all requirements!")
else:
    print(f"Failed checks: {json_report['summary']['failed']}")
    print(f"Errors encountered: {json_report['summary']['errors']}")
```

### Security Scan Management

```python
from models.security.system import SecurityScan

# Record a new scan
scan = SecurityScan(
    scan_type=SecurityScan.TYPE_VULNERABILITY,
    target="web-application",
    scanner="OWASP ZAP",
    scanner_version="2.12.0",
    initiated_by_id=current_user.id
)
scan.save()

# Add scan findings
scan.add_finding(
    title="SQL Injection in Search API",
    description="The search API endpoint is vulnerable to SQL injection",
    severity=SecurityScan.SEVERITY_HIGH,
    cvss_score=8.5,
    location="/api/v1/search?q=",
    remediation="Implement input validation and parameterized queries"
)

# Mark finding as false positive
scan.update_finding_status(
    finding_id=123,
    status=SecurityScan.FINDING_STATUS_FALSE_POSITIVE,
    notes="Verified that all queries are parameterized",
    updated_by_id=security_analyst_id
)

# Get open findings by severity
high_severity_findings = SecurityScan.get_open_findings(
    severity_minimum=SecurityScan.SEVERITY_HIGH
)

# Get scan metrics
scan_metrics = SecurityScan.get_scan_metrics(
    past_days=90,
    group_by="week"
)

# Check scan health
health_metrics = SecurityScan.get_scan_health_metrics()
if health_metrics['health_status'] == 'degraded':
    print(f"Warning: {health_metrics['long_running_scans']} scans running for too long")
```

### File Integrity Management

```python
from models.security.system import FileIntegrityBaseline
from datetime import datetime, timezone

# Create a new file integrity baseline
baseline = FileIntegrityBaseline(
    name="Critical System Files",
    baseline_type=FileIntegrityBaseline.TYPE_SYSTEM,
    hash_algorithm=FileIntegrityBaseline.ALGORITHM_SHA256,
    description="Baseline for critical system configuration files",
    created_by=current_user.id
)

# Add file hashes to the baseline
file_hashes = {
    "/etc/passwd": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    "/etc/shadow": "d8e8fca2dc0f896fd7cb4cb0031ba249",
    "/bin/bash": "f9c58f91e2d27e54457fc3908f7db4ad99fc00f3"
}
success, message = baseline.update_baseline(file_hashes, current_user.id)
print(message)

# Activate the baseline for monitoring
baseline.activate(current_user.id)

# Detect changes between current state and baseline
current_hashes = {
    "/etc/passwd": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    "/etc/shadow": "modified_hash_value_here",  # Changed file
    # "/bin/bash" is missing - will be detected
}
changes = baseline.detect_changes(current_hashes)

# Process the detected changes
for change in changes:
    if change['status'] == 'modified':
        print(f"MODIFIED: {change['path']} (Severity: {change['severity']})")
    elif change['status'] == 'missing':
        print(f"MISSING: {change['path']} (Severity: {change['severity']})")
    elif change['status'] == 'new':
        print(f"NEW: {change['path']} (Severity: {change['severity']})")

# Export baseline to file for backup
success, message = baseline.export_to_file("/path/to/backup/baseline.json")
if success:
    print(f"Baseline exported: {message}")
else:
    print(f"Export failed: {message}")
```

### Configuration Management

```python
from models.security.system import SystemConfig

# Store security configuration
SystemConfig.set_config(
    name="password_policy",
    value={
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special_chars": True,
        "max_age_days": 90
    },
    category="authentication",
    environment="production",
    is_sensitive=False
)

# Retrieve configuration
pwd_policy = SystemConfig.get_config("password_policy", environment="production")

# Update configuration with versioning
SystemConfig.update_config(
    name="password_policy",
    value={"min_length": 14, "max_age_days": 60},
    category="authentication",
    environment="production",
    changed_by_id=admin_id,
    reason="Increasing security posture",
    merge=True  # Merge with existing values
)

# Get configuration history
history = SystemConfig.get_config_history("password_policy", limit=5)
for version in history:
    print(f"Changed on {version.changed_at} by {version.changed_by}: {version.change_reason}")
```

## Implementation Notes

- All models inherit from the `BaseModel` and `AuditableMixin` classes for consistent behavior and auditing
- Each model implements comprehensive validation to ensure data integrity
- Models integrate with the platform's RBAC system for access control
- Sensitive information is automatically protected and redacted in logs
- Events from these models are automatically captured in audit logs through event listeners
- Full transaction support ensures atomic operations and proper rollback on errors
- Versioning is implemented for security-critical components for compliance and traceability
- Each model provides pagination support for handling large result sets efficiently
- Bulk operation methods are available for efficiency with large data sets
- Compliance models use enum classes for consistent status and severity values
- File integrity baselines support multiple hash algorithms and monitoring profiles

## Best Practices & Security

- Use appropriate methods provided by these models for security operations
- Implement proper transaction management with commit/rollback patterns
- Set appropriate access controls for administrative operations
- Enable MFA for administrative operations on security models
- Validate all inputs before storing in security models
- Keep security baseline references up to date with current standards
- Schedule regular compliance checks to ensure ongoing compliance
- Rotate sensitive security configurations regularly
- Review audit logs periodically for suspicious activity
- Export and archive audit logs according to retention policies
- Use ComplianceSeverity and ComplianceStatus enums for consistent status values
- Store compliance evidence with proper references and documentation
- Perform regular file integrity checks and verify against baselines
- Keep file integrity baseline backups in secure, separate locations
- Implement alerting for critical file integrity violations
- Use appropriate permission modes for baseline files (0600/0640)
- Only allow authorized users to update file integrity baselines
- Implement approval workflows for baseline changes in production

## Common Features

- Comprehensive audit trails for all changes
- Automatic versioning of security-critical data
- Support for bulk operations with proper transaction management
- Rich query capabilities with filtering and sorting
- Pagination for large result sets
- Proper serialization for API responses
- Input validation with detailed error messages
- Integration with the platform's notification system
- Environment-aware configuration capabilities
- Tamper-resistant logging mechanisms
- Multiple report format generation (text, HTML, JSON)
- Enum-based constants for consistency and type safety
- Baseline management with change detection capabilities
- Export and import functionality for data portability

## Related Documentation

- Security Architecture Overview
- Compliance Framework Documentation
- Audit Requirements Guide
- Security Baseline Management
- Security Scanning Implementation
- Configuration Management Guide
- RBAC Implementation Guide
- Compliance Status Codes Reference
- File Integrity Checking Implementation
- API-Based Compliance Checks
- File Integrity Monitoring Guide
- Security Incident Response Procedures
- Baseline Export Format Specifications
