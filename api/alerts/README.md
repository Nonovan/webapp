# Alerts API

The Alerts API module provides RESTful endpoints for alert creation, management, and notification in the Cloud Infrastructure Platform. This module enables programmatic interaction with the alerting system, allowing for real-time monitoring and response to critical events across cloud resources and ICS systems.

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

The Alerts API implements RESTful endpoints following security best practices including input validation, rate limiting, comprehensive audit logging, and proper error handling. It enables monitoring systems to create alerts when issues are detected, allows operators to acknowledge and resolve alerts, and supports integration with notification systems.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for alert management
  - Alert creation with severity classification
  - Alert status management (acknowledgment, resolution)
  - Filtering and searching capabilities
  - Alert statistics and aggregation
  - Integration with notification systems

- **`schemas.py`**: Defines data validation schemas for the alert API
  - Alert creation schema with required fields
  - Alert update schema for status changes
  - Filter parameters schema for search operations
  - Alert statistics request schema

- **`helpers.py`**: Alert-specific helper functions
  - Alert priority calculation
  - Notification formatting
  - Alert correlation algorithms
  - Resource group aggregation
  - Status transition validations

- **`__init__.py`**: Module initialization with metrics and event handlers
  - Blueprint registration with proper routes
  - Security metrics integration
  - Event handler registration
  - Rate limit configuration

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

## Configuration

The alerts system uses several configuration settings that can be adjusted in the application config:

```python
# Alert system settings
'ALERT_RETENTION_DAYS': 90,              # How long to keep alerts in the database
'ALERT_AUTO_ACKNOWLEDGE_HOURS': 24,      # Auto-acknowledge after this many hours
'ALERT_NOTIFICATION_CHANNELS': ['email', 'slack', 'webhook'],
'ALERT_SEVERITY_ESCALATION_HOURS': 2,    # Escalate unacknowledged critical alerts
'MAX_ALERTS_PER_SERVICE': 100,           # Throttle excessive alerts from one service

# Rate limiting settings
'RATELIMIT_ALERT_LIST': "60 per minute",
'RATELIMIT_ALERT_CREATE': "120 per minute",
'RATELIMIT_ALERT_UPDATE': "30 per minute",
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
  "environment": "production"
}
```

## Related Documentation

- Alert Management Guide
- Monitoring Architecture
- Notification System
- Security Monitoring
- API Reference
