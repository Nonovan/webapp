# Security API

The Security API module provides endpoints for security incident management, vulnerability tracking, security monitoring, and threat detection in the Cloud Infrastructure Platform.

## Contents

- Overview
- Key Components
- Directory Structure
- API Endpoints
- Configuration
- Security Features
- Usage Examples
- Related Documentation

## Overview

The Security API implements RESTful endpoints following security best practices including input validation, audit logging, authorization checks, and proper error handling. It provides programmatic access to security-related functionality including security incident management, vulnerability tracking, security scan configuration, and threat detection capabilities.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for security operations
  - Security incident management
  - Vulnerability tracking and reporting
  - Security scan configuration and control
  - Threat detection and response
  - Security policy management

- **`incidents.py`**: Security incident management functionality
  - Incident creation and tracking
  - Incident prioritization and categorization
  - Automated incident response workflows
  - Incident correlation engine
  - Reporting and metrics generation

- **`vulnerabilities.py`**: Vulnerability management capabilities
  - Vulnerability tracking
  - Risk scoring and prioritization
  - Remediation tracking
  - Integration with scanners
  - Reporting and metrics

- **`scanning.py`**: Security scanning configuration and control
  - Scan scheduling and management
  - Scan configuration templates
  - Scan result aggregation
  - Integration with scanning engines
  - Compliance reporting

- **`threats.py`**: Threat detection and intelligence
  - Threat detection rules
  - IOC management
  - Threat intelligence integration
  - Suspicious activity detection
  - Alert correlation

- **`__init__.py`**: Module initialization and configuration
  - Blueprint registration
  - Security metrics integration
  - Event handler registration
  - Rate limit configuration

## Directory Structure

```plaintext
api/security/
├── __init__.py         # Module initialization and exports
├── README.md           # This documentation
├── routes.py           # API endpoint implementations
├── incidents.py        # Security incident management
├── vulnerabilities.py  # Vulnerability tracking functionality
├── scanning.py         # Security scanning configuration
├── threats.py          # Threat detection and intelligence
└── schemas.py          # Data validation schemas
```

## API Endpoints

| Endpoint | Method | Description | Access Level |
|----------|--------|-------------|-------------|
| `/api/security/incidents` | GET | List security incidents | Security Analyst, Admin |
| `/api/security/incidents` | POST | Create a security incident | Security Analyst, Admin |
| `/api/security/incidents/{id}` | GET | Get incident details | Security Analyst, Admin |
| `/api/security/incidents/{id}` | PATCH | Update incident status | Security Analyst, Admin |
| `/api/security/incidents/{id}/comments` | POST | Add comment to incident | Security Analyst, Admin |
| `/api/security/vulnerabilities` | GET | List vulnerabilities | Security Analyst, Admin |
| `/api/security/vulnerabilities/{id}` | GET | Get vulnerability details | Security Analyst, Admin |
| `/api/security/scan` | POST | Trigger security scan | Security Admin |
| `/api/security/scan/status` | GET | Get scan status | Security Analyst, Admin |
| `/api/security/threats/ioc` | POST | Create threat indicator | Security Admin |
| `/api/security/threats/ioc/{id}` | DELETE | Remove threat indicator | Security Admin |
| `/api/security/threats/detection` | GET | List threat detections | Security Analyst, Admin |

## Configuration

The security API system uses several configuration settings that can be adjusted in the application config:

```python
# Security API settings
'SECURITY_INCIDENT_AUTO_ASSIGN': True,    # Auto-assign incidents based on type
'SECURITY_SCAN_CONCURRENCY': 3,           # Maximum concurrent security scans
'SECURITY_INCIDENT_RETENTION_DAYS': 365,  # How long to keep incidents in the database
'VULNERABILITY_AUTO_PRIORITIZE': True,    # Auto-prioritize vulnerabilities by CVSS
'THREAT_INTEL_SOURCES': ['internal', 'mitre', 'alienvault'],  # Threat intelligence sources
'SECURITY_API_ADMINS_GROUP': 'security_administrators',  # Group for security admins

# Rate limiting settings
'RATELIMIT_SECURITY_DEFAULT': "60 per minute",
'RATELIMIT_SECURITY_SCAN': "10 per hour",
```

## Security Features

- **Strict Access Controls**: All endpoints require appropriate security role permissions
- **Audit Logging**: Comprehensive logging of all security operations for compliance
- **Input Validation**: Thorough validation of all input parameters
- **Rate Limiting**: Prevents API abuse with endpoint-specific rate limits
- **Correlation Engine**: Links related security incidents and vulnerabilities
- **Workflow Enforcement**: Ensures proper security incident handling procedures
- **Real-time Alerting**: Generates alerts for critical security incidents
- **Secure Error Handling**: Prevents information leakage in error responses
- **Forensic Data Preservation**: Ensures security incident evidence is properly preserved

## Usage Examples

### List Security Incidents

```http
GET /api/security/incidents?severity=high&status=open
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "data": [
    {
      "id": 42,
      "title": "Unusual login pattern detected",
      "description": "Multiple failed login attempts followed by successful login from unusual location",
      "severity": "high",
      "status": "open",
      "created_at": "2023-06-14T23:15:42Z",
      "created_by": "security_monitoring",
      "affected_resources": [
        {
          "type": "user",
          "id": 5,
          "name": "john.doe"
        }
      ]
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 1,
    "total_items": 1
  }
}
```

### Create Security Incident

```http
POST /api/security/incidents
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "title": "Possible file integrity violation",
  "description": "Checksum mismatch detected on system files",
  "severity": "high",
  "affected_resources": [
    {
      "type": "system",
      "id": "file-system",
      "details": {
        "path": "/etc/config",
        "files_affected": 3
      }
    }
  ],
  "evidence": [
    {
      "type": "log",
      "content": "File integrity check failed at 2023-06-15 16:42:15"
    }
  ]
}
```

Response:

```json
{
  "id": 43,
  "title": "Possible file integrity violation",
  "severity": "high",
  "status": "new",
  "created_at": "2023-06-15T17:10:22Z",
  "created_by": {
    "id": 1,
    "username": "admin"
  },
  "triage_by": "2023-06-15T19:10:22Z",
  "tracking_id": "SEC-2023-06-15-043"
}
```

### Trigger Security Scan

```http
POST /api/security/scan
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "scan_type": "vulnerability",
  "targets": ["web-server-01", "api-server-02"],
  "profile": "full",
  "schedule": "immediate",
  "notify_email": "security@example.com"
}
```

Response:

```json
{
  "scan_id": "scan-20230615-001",
  "status": "scheduled",
  "estimated_duration_minutes": 45,
  "targets": ["web-server-01", "api-server-02"],
  "scheduled_start": "2023-06-15T17:15:00Z"
}
```

## Related Documentation

- Security Architecture
- Security Incident Response
- Vulnerability Management
- Security Monitoring Guide
- Security API Reference
