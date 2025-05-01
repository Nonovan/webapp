# Security Models

## Overview

This directory contains security-related models for the Cloud Infrastructure Platform. The security models provide core functionality for tracking security incidents, managing vulnerabilities, conducting security scans, maintaining audit logs, validating compliance, managing security baselines, tracking threat intelligence, and storing security-related configurations.

These models support security operations, incident management, vulnerability tracking, compliance verification, and security monitoring across the platform. They integrate with other components of the system to provide comprehensive security capabilities while maintaining detailed audit trails.

## Key Components

- **`AuditLog`**: Comprehensive security event logging
  - Records security-relevant events across the platform
  - Supports different severity levels and event categorization
  - Enables compliance tracking and security investigation
  - Provides structured event storage for analysis and reporting

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
├── audit_log.py              # Security event logging
├── compliance_check.py       # Compliance verification
├── login_attempt.py          # Authentication attempt tracking
├── README.md                 # This documentation
├── security_baseline.py      # Security standards definition
├── security_incident.py      # Security incident management
├── security_scan.py          # Security scanning results
├── system_config.py          # Security configuration storage
├── threat_intelligence.py    # Threat intelligence data
├── vulnerability.py          # Modern vulnerability management
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

# Configure and add a threat feed
feed = ThreatIntelligence.ThreatFeed(
    name="AlienVault OTX",
    url="https://otx.alienvault.com/api/v1/indicators/export",
    feed_type=ThreatIntelligence.ThreatFeed.TYPE_STRUCTURED_JSON,
    description="Open Threat Exchange feed for malicious indicators",
    update_interval=86400,  # Daily updates
    config={
        "api_key": "{{ENV_OTX_API_KEY}}",
        "types": ["domain", "IPv4", "file"]
    }
)
feed.save()

# Bulk import indicators from a threat feed
indicators = [
    {"indicator_type": "ip", "value": "10.0.0.1", "source": "alientvault"},
    {"indicator_type": "domain", "value": "malicious.example.com", "source": "alienvault"}
]
imported, failed, errors = ThreatIntelligence.ThreatIndicator.bulk_import(indicators)
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

### Security Scanning

```python
from models.security import SecurityScan

# Create a new security scan configuration
scan_config = SecurityScan(
    name="Weekly Web Application Scan",
    scan_type=SecurityScan.TYPE_WEB_APPLICATION,
    target="https://app.example.com",
    schedule="0 0 * * 0",  # Weekly on Sunday
    parameters={
        "scan_depth": "full",
        "authentication": True,
        "auth_username": "scanner",
        "excluded_paths": ["/health", "/metrics"]
    },
    creator_id=current_user.id
)
scan_config.save()

# Record scan execution
scan_execution = scan_config.create_execution(
    start_time=datetime.now(timezone.utc),
    executor_id=system_user_id
)

# Record scan completion
scan_execution.complete(
    end_time=datetime.now(timezone.utc) + timedelta(hours=2),
    status=SecurityScan.STATUS_COMPLETED,
    findings_count=12,
    summary="Completed with 12 findings: 2 high, 5 medium, 5 low"
)

# Add findings
scan_execution.add_finding(
    title="Cross-site Scripting in Profile Page",
    description="XSS vulnerability in profile page description field",
    severity=SecurityScan.FINDING_SEVERITY_HIGH,
    details={
        "location": "/user/profile",
        "parameter": "description",
        "proof": "<script>alert(1)</script> is not sanitized"
    }
)

# Get recent scan results
recent_scans = SecurityScan.get_recent_executions(days=30)
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

## Related Documentation

- Security Architecture Overview
- Incident Response Procedures
- Compliance Framework Documentation
- Vulnerability Management Policy
- Security Scanning Implementation
- Threat Intelligence Integration Guide
- API Security Documentation
- Security Administration Guide
- Audit Requirements
- Data Retention Policies
