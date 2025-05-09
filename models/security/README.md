# Security Models

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

This directory contains security-related models for the Cloud Infrastructure Platform. The security models provide core functionality for tracking security incidents, managing vulnerabilities, conducting security scans, maintaining audit logs, validating compliance, managing security baselines, tracking threat intelligence, and storing security-related configurations.

These models support security operations, incident management, vulnerability tracking, compliance verification, and security monitoring across the platform. They integrate with other components of the system to provide comprehensive security capabilities while maintaining detailed audit trails.

## Key Components

- **`AuditLog`**: Comprehensive security event logging
  - Records security-relevant events across the platform
  - Supports different severity levels and event categorization
  - Enables compliance tracking and security investigation
  - Provides structured event storage for analysis and reporting
  - Implements tamper-resistant logging for forensic analysis
  - Offers flexible querying capabilities for security operations

- **`CircuitBreaker`**: Protection against cascading failures
  - Prevents system overload during service disruptions
  - Implements configurable failure thresholds
  - Provides automatic recovery with half-open state pattern
  - Tracks failure statistics and recovery metrics
  - Supports configurable fallback mechanisms
  - Integrates with system health monitoring

- **`LoginAttempt`**: Authentication attempt monitoring
  - Tracks successful and failed login attempts
  - Implements brute force protection through rate limiting
  - Provides account lockout mechanisms with progressive timing
  - Records IP addresses and geolocation data for threat analysis
  - Offers security analytics for authentication patterns
  - Integrates with notification system for unusual activity

- **`SecurityIncident`**: Security incident tracking and management
  - Comprehensive incident lifecycle management (open, investigating, resolved, closed, merged)
  - Status and phase tracking from identification through resolution
  - Assignment, note tracking, and escalation workflows
  - Impact assessment and root cause analysis
  - Related incident tracking and merging capabilities
  - Affected resource management for comprehensive impact assessment
  - Priority scoring based on severity and age
  - SLA tracking with time-based alerts
  - Tag-based categorization for improved organization

- **`Vulnerability`**: Modern vulnerability tracking and management
  - Implements complete vulnerability lifecycle from discovery to resolution
  - Provides comprehensive CVSS scoring and vector string validation
  - Manages vulnerability status transitions with audit logging
  - Tracks affected resources with flexible JSONB storage
  - Calculates risk scores based on multiple factors
  - Implements SLA tracking with deadline enforcement and overdue detection
  - Integrates with security scanning and AuditLog components
  - Supports advanced search and filtering capabilities
  - Provides detailed statistics and metrics tracking

- **`ThreatIntelligence`**: Security threat tracking and analysis
  - Manages indicators of compromise (IoCs) and threat actors
  - Implements automated threat correlation with security events
  - Provides threat feed integration and management
  - Supports flexible indicator types (IP, URL, hash, etc.)
  - Tracks threat intelligence sources and confidence levels
  - Implements automated expiration for time-sensitive indicators
  - Provides STIX/TAXII compatibility for sharing

- **`SystemConfig`**: Security configuration management
  - Centralizes security-related configuration storage
  - Provides environment-aware configuration capabilities
  - Implements version tracking for all configuration changes
  - Enforces validation rules for security parameters
  - Supports encryption for sensitive configuration values
  - Offers comprehensive audit trail for configuration updates

- **`FileIntegrityBaseline`**: File integrity monitoring baseline
  - Creates and manages file integrity monitoring baselines
  - Tracks cryptographic hashes of critical system files
  - Detects unauthorized modifications to protected files
  - Provides change detection with severity classification
  - Supports multiple hash algorithms for different security needs
  - Offers baseline export and import capabilities
  - Implements secure backup and restore functionality

## Directory Structure

```plaintext
models/security/
├── __init__.py               # Package exports and constants
├── circuit_breaker.py        # Service protection components
├── login_attempt.py          # Authentication attempt tracking
├── README.md                 # This documentation
├── security_incident.py      # Security incident management
├── system/                   # System-level security models
│   ├── __init__.py           # System security package exports
│   ├── audit_log.py          # Security event logging
│   ├── compliance_check.py   # Compliance verification models
│   ├── file_integrity_baseline.py # File integrity monitoring
│   ├── README.md             # System security documentation
│   ├── security_baseline.py  # Security standards definition
│   ├── security_scan.py      # Security scanning configuration and results
│   └── system_config.py      # Security configuration storage
├── threat_intelligence.py    # Threat intelligence data management
└── vulnerability.py          # Vulnerability tracking and management
```

## Usage Examples

### Security Incident Management

```python
from models.security import SecurityIncident

# Create a new security incident
incident = SecurityIncident(
    title="Unauthorized Access Attempt",
    incident_type=SecurityIncident.TYPE_UNAUTHORIZED_ACCESS,
    description="Multiple failed login attempts detected from unusual location",
    severity=SecurityIncident.SEVERITY_HIGH,
    details="10 failed login attempts from IP 192.168.1.100 within 2 minutes",
    ip_address="192.168.1.100",
    source=SecurityIncident.SOURCE_SECURITY_SCAN
)
incident.save()  # Automatically logs the creation event

# Assign the incident to a security analyst
incident.assign_to(user_id=5, assigned_by=1)  # Changes status to INVESTIGATING

# Add investigation notes
incident.add_note("Analyzing login patterns and comparing with known attack signatures")

# Escalate if needed
incident.escalate(
    new_severity=SecurityIncident.SEVERITY_CRITICAL,
    reason="Found evidence of successful intrusion",
    user_id=5
)

# Change incident phase
incident.change_phase(
    new_phase=SecurityIncident.PHASE_CONTAINMENT,
    reason="Implementing network isolation",
    user_id=5
)

# Add affected resources
incident.add_affected_resource(
    resource_type="server",
    resource_id="web-server-01",
    details={"services": ["http", "https"]}
)

# Add related incident
incident.add_related_incident(related_incident_id=42)

# Add tags for better categorization
incident.add_tag("web-server")
incident.add_tag("credential-theft")

# Merge with a parent incident if related
incident.merge_into(
    parent_incident_id=50,
    reason="Part of coordinated attack from same threat actor",
    user_id=5
)

# Search for incidents
incidents = SecurityIncident.search(
    query="credential theft",
    status=[SecurityIncident.STATUS_OPEN, SecurityIncident.STATUS_INVESTIGATING],
    severity=[SecurityIncident.SEVERITY_HIGH, SecurityIncident.SEVERITY_CRITICAL],
    days=30
)

# Check for breached SLA incidents
sla_breached = SecurityIncident.get_breached_sla_incidents()
```

### Audit Logging

```python
from models.security.system import AuditLog

# Record a security-relevant event
AuditLog.log_event(
    event_type=AuditLog.EVENT_CONFIG_CHANGE,
    resource_type="firewall_rule",
    resource_id="fw-12345",
    user_id=current_user.id,
    details={
        "action": "update",
        "old_value": {"port": 22, "allowed_ips": ["10.0.0.1/24"]},
        "new_value": {"port": 22, "allowed_ips": ["10.0.0.1/24", "192.168.1.0/24"]}
    },
    severity=AuditLog.SEVERITY_INFO
)

# Query audit history for a specific resource
firewall_logs = AuditLog.get_logs_for_resource(
    resource_type="firewall_rule",
    resource_id="fw-12345",
    limit=50
)

# Get security events by severity
critical_events = AuditLog.query.filter(
    AuditLog.severity >= AuditLog.SEVERITY_CRITICAL,
    AuditLog.created_at >= (datetime.now() - timedelta(days=7))
).order_by(AuditLog.created_at.desc()).all()
```

### Vulnerability Management

```python
from models.security import Vulnerability

# Create a new vulnerability
vuln = Vulnerability(
    title="SQL Injection in Search Function",
    description="The search API endpoint is vulnerable to SQL injection attacks",
    severity=Vulnerability.SEVERITY_HIGH,
    cvss_score=8.5,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    vulnerability_type=Vulnerability.TYPE_CODE,
    affected_resources=[
        {"type": "api", "id": "search-endpoint"}
    ],
    status=Vulnerability.STATUS_OPEN
)
vuln.save()

# Add affected resources
vuln.add_affected_resource({
    "type": "server",
    "id": "web-server-01"
})

# Create remediation plan
vuln.remediation_steps = """
1. Apply input validation to the search parameter
2. Use parameterized queries
3. Update API documentation
4. Add security tests
"""
vuln.remediation_deadline = datetime.now(timezone.utc) + timedelta(days=7)
vuln.assign_to(user_id=5, assigned_by_id=1)
vuln.save()

# Mark as resolved
vuln.resolve(
    resolution_summary="Implemented parameterized queries and input validation",
    user_id=5
)

# Verify the fix
vuln.verify(user_id=security_team_id)

# Search for vulnerabilities
vulnerabilities, total = Vulnerability.get_paginated(
    page=1,
    per_page=20,
    filters={
        'severity': [Vulnerability.SEVERITY_CRITICAL, Vulnerability.SEVERITY_HIGH],
        'status': Vulnerability.STATUS_OPEN,
        'is_overdue': True
    },
    sort_by='risk_score',
    sort_direction='desc'
)

# Get vulnerability statistics
stats = Vulnerability.get_statistics()
print(f"Total vulnerabilities: {stats['total']}")
print(f"Overdue vulnerabilities: {stats['remediation_progress']['overdue']}")
```

### Circuit Breaker Implementation

```python
from models.security import CircuitBreaker, CircuitBreakerState, CircuitOpenError

# Initialize a circuit breaker for a service
circuit = CircuitBreaker(
    name="payment-gateway-api",
    failure_threshold=5,
    recovery_timeout=30,  # seconds
    half_open_max_calls=2
)

# Using the circuit breaker to protect a service call
def call_payment_gateway(payment_data):
    try:
        with circuit:
            # This block is protected by the circuit breaker
            result = payment_gateway_client.process_payment(payment_data)
            circuit.record_success()
            return result
    except CircuitOpenError as e:
        # Circuit is open due to previous failures
        return use_fallback_payment_method(payment_data, e.remaining_timeout)
    except Exception as e:
        # Service call failed
        circuit.record_failure()
        raise

# Checking circuit status
if circuit.state == CircuitBreakerState.OPEN:
    print(f"Circuit {circuit.name} is open. Retry after {circuit.remaining_timeout}s")
elif circuit.state == CircuitBreakerState.HALF_OPEN:
    print(f"Circuit {circuit.name} is half-open, testing limited traffic")
else:
    print(f"Circuit {circuit.name} is closed and fully operational")

# Circuit breaker metrics
metrics = circuit.get_metrics()
print(f"Success rate: {metrics.success_percent}%, Failures: {metrics.failures}")
```

### Security Baseline Management

```python
from models.security.system import SecurityBaseline

# Create a new security baseline
linux_baseline = SecurityBaseline(
    name="Linux Server Hardening Standard",
    version="1.2.0",
    description="Security baseline for Linux servers based on CIS Benchmarks",
    system_type="linux_server",
    created_by_id=security_admin_id
)
linux_baseline.save()

# Add baseline items
linux_baseline.add_control(
    category="filesystem",
    control_id="1.1",
    control_data={
        "title": "Disable unused filesystems",
        "description": "Disable mounting of unused filesystems",
        "implementation": "Edit /etc/modprobe.d/CIS.conf and add `install cramfs /bin/true`",
        "verification": "Run `lsmod | grep cramfs` should return no results",
        "remediation": "Add lines to /etc/modprobe.d/CIS.conf",
        "impact": "Low",
        "priority": "medium"
    }
)

# Publish the baseline when ready
linux_baseline.publish(user_id=security_admin_id)

# Archive old baseline versions
linux_baseline.archive(
    user_id=security_admin_id,
    reason="Superseded by version 1.3.0"
)
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

- All security models inherit from `BaseModel` which provides core CRUD operations
- Security models utilize the `AuditableMixin` for automatic security audit logging
- Most models implement a `to_dict()` method for API serialization
- Date/time fields use timezone-aware datetime objects (UTC)
- Security events are automatically logged using the `AuditLog` model
- Proper indexing is applied to fields commonly used in filtering
- Security models implement status workflows for lifecycle management
- Access to security models is restricted through the RBAC system
- Critical operations include proper transaction management
- Documentation includes security considerations for each model
- Circuit breaker pattern implementation follows industry best practices
- System-level models provide additional infrastructure-specific security capabilities
- Pagination is implemented for all queries that might return large result sets
- Automated security auditing ensures all model changes are tracked

## Best Practices & Security

- Always use the appropriate methods provided by these models for security operations
- Use proper transaction management with commit/rollback patterns
- Enforce strict access control for security model operations
- Log all security-relevant operations using the AuditLog model
- Implement proper data retention policies for security data
- Use constants defined in the models for standardized values
- Validate all inputs carefully before storing in security models
- Follow least privilege principles when granting access to security data
- Implement MFA for administrative operations on security models
- Regularly back up security data with proper access controls
- Apply circuit breakers where external service dependencies exist
- Use rate limiting for publicly exposed endpoints
- Ensure all security-critical operations require approval workflows
- Implement defense in depth with multiple overlapping security controls
- Separate system-level security controls from application-level controls
- Schedule regular security assessments using the baseline models

## Common Features

- Comprehensive audit logging of all security-relevant events
- Role-based access control integration
- Versioning support for security-critical data
- Status tracking with workflow state transitions
- Activity tracking with user attribution
- Structured data storage using JSONB for flexible schemas
- Search and filtering capabilities with proper indexing
- Pagination support for large result sets
- Bulk operations for efficient data manipulation
- Rate limiting and circuit breaking for resilience
- Integration with notification systems for alerts
- Support for environment-specific configurations
- Automatic timestamp tracking (created, updated)
- Tamper-resistant logging mechanisms
- Data retention policy enforcement
- Transaction management with proper rollback

## Related Documentation

- Security Architecture Overview
- Core Security Module
- Incident Response Procedures
- Authentication and Authorization Models
- Compliance Framework Documentation
- Vulnerability Management Policy
- Security Scanning Implementation
- Threat Intelligence Integration Guide
- API Security Documentation
- Security Administration Guide
- Audit Requirements
- Data Retention Policies
- File Integrity Monitoring Guide
- Security Update Policy
