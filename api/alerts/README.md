# Alerts API

The Alerts API module provides RESTful endpoints for alert creation, management, and notification in the Cloud Infrastructure Platform. This module enables programmatic interaction with the alerting system, allowing for real-time monitoring and response to critical events across cloud resources and ICS systems.

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

The Alerts API implements RESTful endpoints following security best practices including input validation, rate limiting, comprehensive audit logging, and proper error handling. It enables monitoring systems to create alerts when issues are detected, allows operators to acknowledge and resolve alerts, and supports integration with notification systems.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for alert management
  - Alert creation with severity classification
  - Alert status management (acknowledgment, resolution)
  - Filtering and searching capabilities
  - Alert statistics and aggregation
  - Integration with notification systems
  - SLA compliance monitoring and reporting

- **`schemas.py`**: Defines data validation schemas for the alert API
  - Alert creation schema with required fields
  - Alert update schema for status changes
  - Filter parameters schema for search operations
  - Alert statistics request schema
  - SLA compliance check schema

- **`helpers.py`**: Alert-specific helper functions
  - Alert priority calculation
  - Notification formatting
  - Alert correlation algorithms
  - Resource group aggregation
  - Status transition validations
  - SLA compliance checking and history tracking

- **`__init__.py`**: Module initialization with metrics and event handlers
  - Blueprint registration with proper routes
  - Security metrics integration
  - Event handler registration
  - Rate limit configuration
  - SLA compliance metrics

## Directory Structure

```plaintext
api/alerts/
├── __init__.py         # Module initialization and exports
├── README.md           # This documentation
├── routes.py           # API endpoint implementations
├── schemas.py          # Data validation schemas
└── helpers.py          # Alert-specific helper functions
```

## API Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| alerts | GET | List alerts with filtering options | 60/minute |
| alerts | POST | Create a new alert | 120/minute |
| `/api/alerts/{id}` | GET | Get alert details | 60/minute |
| `/api/alerts/{id}` | PATCH | Update alert status | 30/minute |
| `/api/alerts/{id}/acknowledge` | POST | Acknowledge an alert | 30/minute |
| `/api/alerts/{id}/resolve` | POST | Resolve an alert | 30/minute |
| `/api/alerts/statistics` | GET | Get alert statistics | 20/minute |
| `/api/alerts/service/{service_name}` | GET | Get alerts for a service | 60/minute |
| `/api/alerts/{id}/sla` | GET | Check SLA compliance for an alert | 30/minute |
| `/api/alerts/sla/report` | POST | Generate SLA compliance report | 10/minute |

## Configuration

The alerts system uses several configuration settings that can be adjusted in the application config:

```python
# Alert system settings
'ALERT_RETENTION_DAYS': 90,              # How long to keep alerts in the database
'ALERT_AUTO_ACKNOWLEDGE_HOURS': 24,      # Auto-acknowledge after this many hours
'ALERT_NOTIFICATION_CHANNELS': ['email', 'slack', 'webhook'],
'ALERT_SEVERITY_ESCALATION_HOURS': 2,    # Escalate unacknowledged critical alerts
'MAX_ALERTS_PER_SERVICE': 100,           # Throttle excessive alerts from one service

# SLA configuration
'INCIDENT_SLA_HOURS': {                  # Response time SLAs by severity
    'critical': 1,                       # 1 hour for critical alerts
    'high': 4,                           # 4 hours for high severity alerts
    'warning': 24,                       # 24 hours for warnings
    'info': 72                           # 72 hours for informational alerts
},
'RESOLUTION_SLA_MULTIPLIER': 2.0,        # Resolution time = SLA hours * multiplier

# Rate limiting settings
'RATELIMIT_ALERT_LIST': "60 per minute",
'RATELIMIT_ALERT_CREATE': "120 per minute",
'RATELIMIT_ALERT_UPDATE': "30 per minute",
'RATELIMIT_ALERT_SLA': "30 per minute",
'RATELIMIT_ALERT_SLA_REPORT': "10 per minute",
```

## Security Features

- **Input Validation**: Comprehensive validation of all alert fields
- **Rate Limiting**: Prevents alert flooding from compromised systems
- **Audit Logging**: Records all alert operations for security and compliance
- **Authentication Required**: All endpoints require proper authentication
- **Permission-Based Access**: Role-specific access controls
- **Alert Throttling**: Prevents alert storms from overwhelming the system
- **Alert Correlation**: Identifies related alerts to prevent duplication
- **Data Sanitization**: Prevents XSS and injection in alert messages
- **SLA Compliance**: Enforces proper response times based on alert severity

## Usage Examples

### Creating an Alert

```http
POST /api/alerts
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "alert_type": "high_cpu",
  "resource_id": "web-server-01",
  "service_name": "web",
  "severity": "warning",
  "message": "CPU usage exceeded 90%",
  "details": {
    "current_value": 92.5,
    "threshold": 90.0,
    "duration": "5 minutes"
  },
  "environment": "production",
  "region": "us-west-2"
}
```

Response:

```json
{
  "id": 1234,
  "alert_type": "high_cpu",
  "resource_id": "web-server-01",
  "service_name": "web",
  "severity": "warning",
  "message": "CPU usage exceeded 90%",
  "details": {
    "current_value": 92.5,
    "threshold": 90.0,
    "duration": "5 minutes"
  },
  "status": "active",
  "created_at": "2023-06-15T15:01:45Z",
  "environment": "production",
  "region": "us-west-2"
}
```

### Acknowledging an Alert

```http
POST /api/alerts/1234/acknowledge
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "acknowledged_by": "john.doe",
  "comment": "Investigating the issue"
}
```

Response:

```json
{
  "id": 1234,
  "status": "acknowledged",
  "acknowledged_by": "john.doe",
  "acknowledged_at": "2023-06-15T15:10:22Z",
  "message": "Alert acknowledged successfully"
}
```

### Checking SLA Compliance

```http
GET /api/alerts/1234/sla?check_type=both&include_history=true
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "alert_id": 1234,
  "severity": "high",
  "status": "active",
  "created_at": "2023-06-15T14:30:00Z",
  "acknowledged_at": null,
  "resolved_at": null,
  "sla_met": true,
  "compliance": {
    "acknowledgement": {
      "deadline": "2023-06-15T18:30:00Z",
      "time_remaining_seconds": 7200,
      "time_remaining_hours": 2.0,
      "sla_met": true,
      "overdue": false
    },
    "resolution": {
      "deadline": "2023-06-15T22:30:00Z",
      "sla_hours": 8.0,
      "time_remaining_seconds": 21600,
      "time_remaining_hours": 6.0,
      "sla_met": true,
      "overdue": false
    }
  },
  "overall_health": 1.0,
  "history": [
    {
      "timestamp": "2023-06-15T14:45:00Z",
      "status": "active",
      "sla_met": true,
      "check_type": "both",
      "acknowledgement": {
        "sla_met": true,
        "overdue": false,
        "overdue_by_hours": 0
      },
      "resolution": {
        "sla_met": true,
        "overdue": false,
        "overdue_by_hours": 0
      }
    }
  ]
}
```

### Generating SLA Compliance Report

```http
POST /api/alerts/sla/report
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "start_date": "2023-06-10T00:00:00Z",
  "end_date": "2023-06-17T00:00:00Z",
  "environment": "production",
  "severity": "high",
  "include_details": true
}
```

Response:

```json
{
  "period": {
    "start_date": "2023-06-10T00:00:00Z",
    "end_date": "2023-06-17T00:00:00Z",
    "days": 7
  },
  "metrics": {
    "total_alerts": 45,
    "acknowledged_alerts": 42,
    "resolved_alerts": 38,
    "sla_met_count": 41,
    "sla_missed_count": 4,
    "sla_compliance_rate": 0.9111,
    "avg_acknowledgement_time_seconds": 2482.15,
    "avg_resolution_time_seconds": 12684.32
  },
  "filters": {
    "environment": "production",
    "service_name": null,
    "severity": "high"
  },
  "alerts": [
    {
      "alert_id": 1234,
      "severity": "high",
      "service_name": "web",
      "created_at": "2023-06-15T14:30:00Z",
      "status": "resolved",
      "sla_met": true,
      "acknowledgement_time_seconds": 1850,
      "resolution_time_seconds": 9200
    },
    // Additional alerts...
  ]
}
```

### Getting Alert Statistics

```http
GET /api/alerts/statistics?environment=production&period=7d
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "total": 156,
  "by_severity": {
    "critical": 12,
    "warning": 48,
    "info": 96
  },
  "by_status": {
    "active": 24,
    "acknowledged": 18,
    "resolved": 114
  },
  "by_service": {
    "web": 42,
    "database": 35,
    "api": 53,
    "storage": 26
  },
  "period": "7d",
  "environment": "production",
  "sla_compliance_rate": 0.94,
  "sla_compliant_alerts": 147
}
```

## Related Documentation

- Alert Management Guide
- Monitoring Architecture
- Notification System
- Security Monitoring
- API Reference
- SLA Compliance Framework
- Alert Response Procedures
