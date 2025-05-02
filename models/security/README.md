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

- **`CircuitBreaker`**: Protection against cascading failures
  - Prevents system overload during service disruptions
  - Implements configurable failure thresholds
  - Provides automatic recovery with half-open state pattern
  - Tracks failure statistics and recovery metrics
  - Supports configurable fallback mechanisms

- **`ComplianceCheck`**: Compliance status tracking and verification
  - Tracks compliance requirements and statuses
  - Maps controls to compliance frameworks
  - Maintains evidence collections for audits
  - Supports gap analysis and remediation

- **`LoginAttempt`**: Authentication attempt monitoring
  - Tracks successful and failed login attempts
  - Implements brute force protection through rate limiting
  - Provides account lockout mechanisms with progressive timing
  - Records IP addresses and geolocation data for threat analysis

- **`SecurityBaseline`**: Security standard definitions
  - Defines expected security configurations for various systems
  - Supports baseline validation and deviation reporting
  - Implements versioned security standards
  - Maps to compliance requirements and security best practices

- **`SecurityIncident`**: Security incident tracking and management
  - Comprehensive incident lifecycle management
  - Status tracking from detection through resolution
  - Assignment and escalation workflows
  - Impact assessment and root cause analysis
  - Integration with notification systems

- **`SecurityScan`**: Security scanning configuration and results
  - Manages security scan schedules and configurations
  - Stores scan results with finding details
  - Tracks remediation status for identified vulnerabilities
  - Integrates with external scanning tools

- **`SystemConfig`**: Security-related configuration management
  - Maintains security parameters and settings
  - Stores security configuration with versioning
  - Supports configuration validation and change tracking
  - Provides environment-specific security settings

- **`ThreatIntelligence`**: Threat intelligence data management
  - Stores indicators of compromise (IOCs) with comprehensive metadata
  - Tracks suspicious IPs, domains, file hashes, and URLs
  - Manages threat feed integrations with automatic updates
  - Provides real-time threat detection capabilities
  - Implements confidence scoring and severity classification
  - Maintains historical tracking of threat indicators

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

## Directory Structure

```plaintext
models/security/
├── __init__.py               # Package exports
├── circuit_breaker.py        # Service protection components
├── login_attempt.py          # Authentication attempt tracking
├── README.md                 # This documentation
├── security_incident.py      # Security incident management
├── system/                   # System-level security models
│   ├── __init__.py           # System security package exports
│   ├── audit_log.py          # System event logging
│   ├── compliance_check.py   # System compliance verification
│   ├── README.md             # System security documentation
│   ├── security_baseline.py  # System security standards
│   ├── security_scan.py      # System security scanning
│   └── system_config.py      # Security configuration storage
├── threat_intelligence.py    # Threat intelligence data
└── vulnerability.py          # Modern vulnerability management
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

# After implementing countermeasures, resolve the incident
incident.resolve(
    resolution="Blocked originating IP address, reset affected user passwords, " +
               "and enabled additional monitoring",
    user_id=5
)

# If new related activity is detected, reopen the incident
incident.reopen(
    reason="Similar attack pattern detected from new IP range",
    user_id=5
)
```

### Audit Logging

```python
from models.security import AuditLog

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
from models.security import CircuitBreaker, RateLimiter, CircuitOpenError

# Create a circuit breaker to protect a database service
db_circuit = CircuitBreaker(
    name="database_service",
    failure_threshold=5,       # Number of failures before opening
    recovery_timeout=60,       # Seconds to wait before trying to recover
    half_open_max_calls=3      # Max calls to allow in half-open state
)

# Use the circuit breaker to protect a function call
try:
    with db_circuit:
        result = database_service.execute_query("SELECT * FROM users")
        return result
except CircuitOpenError:
    # Handle the case when circuit is open
    return cached_data or fallback_response()

# Rate limiting for API endpoints
api_limiter = RateLimiter(
    key="user:12345",
    max_requests=100,
    time_window=60  # 100 requests per minute
)

try:
    with api_limiter:
        # Process API request
        return process_api_request(request_data)
except RateLimitExceededError as e:
    return {"error": "Rate limit exceeded", "retry_after": e.retry_after}
```

### Threat Intelligence Management

```python
from models.security import ThreatIntelligence

# Create a new threat indicator
indicator = ThreatIntelligence.ThreatIndicator(
    indicator_type=ThreatIntelligence.ThreatIndicator.TYPE_IP,
    value="192.168.1.100",
    source="manual",
    description="Suspicious IP address showing brute force patterns",
    severity=ThreatIntelligence.ThreatIndicator.SEVERITY_HIGH,
    confidence=85,
    tags=["brute-force", "ssh-attack"]
)
indicator.save()

# Check if an IP matches any threat indicators
matches = ThreatIntelligence.ThreatIndicator.check_for_matches(
    value="192.168.1.100",
    indicator_type=ThreatIntelligence.ThreatIndicator.TYPE_IP
)

if matches:
    # Create a security event from the match
    ThreatIntelligence.ThreatEvent.create_from_indicator_match(
        indicator=matches[0],
        context={"source_type": "ssh_log", "attempt_count": 35},
        ip_address="192.168.1.100",
        action=ThreatIntelligence.ThreatEvent.ACTION_BLOCKED
    )
```

### Compliance Checks

```python
from models.security import ComplianceCheck

# Create a compliance requirement
pci_req = ComplianceCheck(
    framework="PCI-DSS",
    control_id="6.5.1",
    description="Injection flaws, particularly SQL injection",
    requirement="Address injection flaws, particularly SQL injection",
    status=ComplianceCheck.STATUS_IN_PROGRESS
)
pci_req.save()

# Link to a vulnerability record
pci_req.link_vulnerability(vulnerability_id=123)

# Add verification evidence
pci_req.add_evidence(
    evidence_type=ComplianceCheck.EVIDENCE_SECURITY_TEST,
    description="Penetration test report for SQL injection",
    location="s3://evidence-bucket/pentest-reports/sql-injection-2023.pdf",
    collected_by=current_user.id
)

# Update compliance status
pci_req.update_status(
    new_status=ComplianceCheck.STATUS_COMPLIANT,
    notes="Implemented parameterized queries across all endpoints",
    reviewer_id=auditor_id
)

# Generate compliance report
compliance_report = ComplianceCheck.generate_report(
    framework="PCI-DSS",
    section="6.5",
    as_of_date=datetime.now(timezone.utc)
)
```

### Security Baseline Management

```python
from models.security import SecurityBaseline

# Create a new security baseline
linux_baseline = SecurityBaseline(
    name="Linux Server Hardening Standard",
    version="1.2.0",
    description="Security baseline for Linux servers based on CIS Benchmarks",
    system_type="linux_server",
    created_by=security_admin_id
)
linux_baseline.save()

# Add baseline items
linux_baseline.add_item(
    control_id="1.1",
    title="Disable unused filesystems",
    description="Disable mounting of unused filesystems",
    implementation="Edit /etc/modprobe.d/CIS.conf and add `install cramfs /bin/true`",
    verification="Run `lsmod | grep cramfs` should return no results",
    remediation="Add lines to /etc/modprobe.d/CIS.conf",
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

# Generate baseline compliance report
compliance_percentage = assessment.calculate_compliance()
print(f"System is {compliance_percentage}% compliant with baseline")
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
