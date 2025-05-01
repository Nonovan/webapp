# Audit API

The Audit API module provides secure endpoints for managing, querying, and analyzing audit logs in the Cloud Infrastructure Platform. This module enables security teams to monitor system activity, investigate security incidents, and demonstrate regulatory compliance.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Related Documentation](#related-documentation)

## Overview

The Audit API implements RESTful endpoints following security best practices including strict access controls, comprehensive logging, and proper error handling. It provides programmatic access to the platform's audit log system, allowing authorized users to query events across the system, generate compliance reports, and monitor security-relevant activities.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for audit log operations
  - Audit log querying with advanced filters
  - Security event analysis and reporting
  - Compliance report generation
  - Audit log export and archival
  - Trend analysis and visualization data

- **`filters.py`**: Audit log filtering and search capabilities
  - Complex query construction
  - Field-specific filtering
  - Time range processing
  - Security-focused search patterns
  - Result pagination

- **`exporters.py`**: Audit log export functionalities
  - CSV/JSON/PDF export formats
  - Compliance-ready report generation
  - Data sanitization for exports
  - Scheduled export configuration

- **`analyzers.py`**: Audit data analysis utilities
  - Event correlation algorithms
  - Anomaly detection
  - User behavior analytics
  - Pattern recognition for security incidents
  - Trend analysis functions

- **`__init__.py`**: Module initialization and configuration
  - Blueprint registration
  - Access control setup
  - Rate limit configuration
  - Authorization checks

- **`schemas.py`**: Data validation schemas
  - Input validation for search parameters
  - Response formatting for consistent output
  - Export format validation
  - Report generation parameters

- **`views/`**: Specialized view helpers
  - Report generation and formatting
  - Dashboard data aggregation
  - Compliance report preparation
  - Security metrics calculation

## Directory Structure

```plaintext
api/audit/
├── __init__.py         # Module initialization and exports
├── README.md           # This documentation
├── routes.py           # API endpoint implementations
├── filters.py          # Audit log filtering capabilities
├── exporters.py        # Export and report generation
├── analyzers.py        # Audit data analysis utilities
├── schemas.py          # Data validation schemas
└── views/              # Specialized view helpers
    ├── __init__.py     # Views package initialization
    ├── reports.py      # Report generation views
    ├── dashboard.py    # Dashboard data aggregation
    └── compliance.py   # Compliance report views
```

## API Endpoints

| Endpoint | Method | Description | Access Level |
|----------|--------|-------------|-------------|
| `/api/audit/logs` | GET | Query and filter audit logs | Auditor, Admin |
| `/api/audit/logs/{id}` | GET | Get detailed audit log entry | Auditor, Admin |
| `/api/audit/export` | POST | Export audit logs in various formats | Auditor, Admin |
| `/api/audit/reports/compliance` | POST | Generate compliance reports | Auditor, Admin |
| `/api/audit/reports/security` | POST | Generate security reports | Security Analyst, Admin |
| `/api/audit/statistics` | GET | Get audit log statistics and trends | Auditor, Admin |
| `/api/audit/search/advanced` | POST | Perform advanced log searches | Security Analyst, Admin |
| `/api/audit/dashboard` | GET | Get dashboard data for audit activity | Auditor, Admin |
| `/api/audit/events/correlate` | POST | Correlate related security events | Security Analyst, Admin |

## Configuration

The audit system uses several configuration settings that can be adjusted in the application config:

```python
# Audit API settings
'AUDIT_LOG_RETENTION_DAYS': 365,         # Default retention period for audit logs
'AUDIT_SEARCH_RESULT_LIMIT': 1000,       # Maximum results per search query
'AUDIT_EXPORT_LIMIT': 50000,             # Maximum records for export operations
'AUDIT_AUTO_ARCHIVE_ENABLED': True,      # Enable automatic archiving of old logs
'AUDIT_CRITICAL_EVENT_CATEGORIES': ['security', 'authentication', 'access_control'],
'AUDIT_DASHBOARD_DATA_TTL': 3600,        # Cache TTL for dashboard data in seconds

# Rate limiting settings
'RATELIMIT_AUDIT_DEFAULT': "60 per minute",
'RATELIMIT_AUDIT_EXPORT': "10 per hour",
'RATELIMIT_AUDIT_REPORTS': "20 per hour",
```

## Security Features

- **Strict Access Controls**: All endpoints require appropriate audit or security role permissions
- **Input Validation**: Thorough validation of all search and filtering parameters
- **Rate Limiting**: Prevents API abuse with endpoint-specific rate limits
- **Query Restrictions**: Enforces appropriate time-range limits on resource-intensive queries
- **Data Sanitization**: Ensures exported data doesn't contain sensitive information
- **Comprehensive Logging**: Records all audit API usage (meta-auditing)
- **Field-Level Security**: Restricts access to sensitive audit fields based on user roles
- **Secure Export Handling**: Ensures secure generation and delivery of exports

## Usage Examples

### Query Audit Logs

```http
GET /api/audit/logs?event_type=login_failed&severity=warning&start_date=2023-06-01T00:00:00Z&end_date=2023-06-30T23:59:59Z&limit=50
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "data": [
    {
      "id": 12345,
      "event_type": "login_failed",
      "timestamp": "2023-06-15T08:24:15Z",
      "description": "Multiple failed login attempts",
      "user_id": 28,
      "username": "david.johnson",
      "ip_address": "198.51.100.73",
      "severity": "warning",
      "details": {
        "attempts": 5,
        "timespan_minutes": 3,
        "action_taken": "temporary_lockout"
      }
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 50,
    "total_pages": 1,
    "total_items": 1
  }
}
```

### Generate a Compliance Report

```http
POST /api/audit/reports/compliance
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "report_type": "pci-dss",
  "start_date": "2023-01-01T00:00:00Z",
  "end_date": "2023-06-30T23:59:59Z",
  "include_sections": ["access_control", "authentication", "file_integrity"],
  "format": "pdf"
}
```

Response:

```json
{
  "report_id": "pci-20230701-a4f82c",
  "status": "processing",
  "estimated_completion": "2023-07-01T10:15:00Z",
  "download_url": "/api/audit/reports/download/pci-20230701-a4f82c",
  "notification": true
}
```

### Get Audit Statistics

```http
GET /api/audit/statistics?period=30d
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "total_events": 24653,
  "by_severity": {
    "critical": 42,
    "error": 156,
    "warning": 1832,
    "info": 22623
  },
  "by_category": {
    "authentication": 5621,
    "access_control": 2349,
    "system": 8407,
    "security": 4982,
    "data": 3294
  },
  "trend": {
    "critical": [0, 2, 5, 1, 3, 8, 0, 4, 2, 3, 1, 0, 0, 1, 4, 2, 1, 0, 0, 0, 1, 2, 0, 1, 0, 0, 0, 1, 0, 0],
    "error": [3, 8, 4, 5, 3, 9, 7, 4, 5, 7, 8, 3, 4, 5, 9, 6, 7, 3, 5, 6, 7, 8, 4, 5, 3, 8, 7, 6, 4, 3],
    "warning": [45, 52, 63, 47, 59, 68, 72, 58, 63, 52, 49, 57, 63, 68, 72, 59, 62, 57, 63, 72, 68, 49, 57, 63, 72, 65, 58, 63, 72, 68]
  },
  "period": "30d"
}
```

## Related Documentation

- Audit System Architecture
- Compliance Reporting Guide
- Security Event Monitoring
- Audit Log Structure
- API Reference
- Audit API Integration Guide
