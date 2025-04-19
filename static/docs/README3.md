# API Reference - Cloud Infrastructure Platform

This document provides detailed information about the RESTful API endpoints available in the Cloud Infrastructure Platform. The API follows REST principles with JSON as the primary data interchange format, and all endpoints are secured with JWT authentication.

## Table of Contents
- [Authentication](#authentication)
- [Cloud Resources](#cloud-resources)
- [Metrics](#metrics)
- [Alerts](#alerts)
- [ICS Systems](#ics-systems)
- [Security](#security)
- [User Management](#user-management)
- [Newsletter](#newsletter)

## General Information

### Base URL
All API endpoints are prefixed with `/api`.

### Authentication
Most endpoints require authentication using JWT tokens in the `Authorization` header:

```
GET /api/cloud/resources
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Response Format
All responses are returned in JSON format. Successful responses typically include:

```json
{
  "data": { ... },
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 5,
    "total_items": 98
  }
}
```

Error responses include:

```json
{
  "error": "Description of the error",
  "status_code": 400
}
```

### Rate Limiting
API endpoints are subject to rate limiting:
- Authentication endpoints: 30 requests per minute
- General API endpoints: 60 requests per minute
- Intensive operations: 10 requests per hour

## Authentication

### Login

**POST /api/auth/login**

Authenticates a user and issues a JWT token.

Request:
```json
{
  "username": "your_username",
  "password": "your_password"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "your_username",
    "role": "admin"
  }
}
```

### Register

**POST /api/auth/register**

Creates a new user account.

Request:
```json
{
  "username": "new_user",
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "confirm_password": "SecurePassword123!"
}
```

Response:
```json
{
  "message": "User registered successfully",
  "user_id": 42
}
```

### Extend Session

**POST /api/auth/extend_session**

Extends the current session lifetime.

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2023-07-01T12:00:00Z"
}
```

## Cloud Resources

### List Resources

**GET /api/cloud/resources**

Returns a paginated list of cloud resources.

Query Parameters:
- `page` (int): Page number (default: 1)
- `per_page` (int): Items per page (default: 20)
- `provider_id` (int): Filter by cloud provider
- `resource_type` (string): Filter by resource type
- `region` (string): Filter by region
- `status` (string): Filter by status

Response:
```json
{
  "data": [
    {
      "id": 1,
      "name": "web-server-01",
      "resource_id": "i-0abc12345def67890",
      "provider_id": 1,
      "provider_name": "AWS",
      "resource_type": "vm",
      "region": "us-east-1",
      "status": "running",
      "created_at": "2023-01-15T10:30:00Z",
      "monthly_cost": 45.60
    },
    // More resources...
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 5,
    "total_items": 98
  }
}
```

### Create Resource

**POST /api/cloud/resources**

Creates a new cloud resource.

Request:
```json
{
  "name": "new-database",
  "provider_id": 1,
  "resource_type": "database",
  "region": "us-west-2",
  "config": {
    "instance_type": "db.t3.medium",
    "engine": "postgres",
    "storage_gb": 100
  }
}
```

Response:
```json
{
  "id": 42,
  "name": "new-database",
  "resource_id": "db-abc123def456",
  "provider_id": 1,
  "resource_type": "database",
  "region": "us-west-2",
  "status": "pending",
  "created_at": "2023-06-15T14:22:33Z"
}
```

### Get Resource

**GET /api/cloud/resources/{id}**

Returns detailed information about a specific cloud resource.

Response:
```json
{
  "id": 42,
  "name": "new-database",
  "resource_id": "db-abc123def456",
  "provider_id": 1,
  "provider_name": "AWS",
  "resource_type": "database",
  "region": "us-west-2",
  "status": "running",
  "is_active": true,
  "created_by_id": 5,
  "created_at": "2023-06-15T14:22:33Z",
  "updated_at": "2023-06-15T14:30:45Z",
  "metadata": {
    "vpc_id": "vpc-12345",
    "subnet_id": "subnet-abcdef"
  },
  "config": {
    "instance_type": "db.t3.medium",
    "engine": "postgres",
    "storage_gb": 100
  },
  "tags": {
    "Environment": "Production",
    "Project": "ERP"
  },
  "monthly_cost": 120.50
}
```

### Update Resource

**PATCH /api/cloud/resources/{id}**

Updates a cloud resource.

Request:
```json
{
  "status": "stopped",
  "tags": {
    "Environment": "Development",
    "Project": "ERP"
  }
}
```

Response:
```json
{
  "id": 42,
  "name": "new-database",
  "status": "stopped",
  "updated_at": "2023-06-15T16:45:12Z",
  "tags": {
    "Environment": "Development",
    "Project": "ERP"
  }
}
```

### Delete Resource

**DELETE /api/cloud/resources/{id}**

Deletes a cloud resource.

Response:
- Status code: `204 No Content`

## Metrics

### Get Current Metrics

**GET /api/cloud/metrics**

Returns the latest metrics for a resource.

Query Parameters:
- `resource_id` (int): Resource ID (required)
- `metric_name` (string): Filter by metric name

Response:
```json
{
  "data": [
    {
      "id": 1234,
      "resource_id": 42,
      "metric_name": "cpu_usage",
      "value": 65.5,
      "unit": "percent",
      "timestamp": "2023-06-15T16:50:22Z",
      "dimensions": {
        "instance_id": "i-0abc12345def67890"
      }
    },
    {
      "id": 1235,
      "resource_id": 42,
      "metric_name": "memory_usage",
      "value": 4.2,
      "unit": "GB",
      "timestamp": "2023-06-15T16:50:22Z",
      "dimensions": {
        "instance_id": "i-0abc12345def67890"
      }
    }
  ]
}
```

### Batch Submit Metrics

**POST /api/cloud/metrics/batch**

Submit multiple metrics at once.

Request:
```json
{
  "metrics": [
    {
      "resource_id": 42,
      "provider_id": 1,
      "metric_name": "cpu_usage",
      "value": 65.5,
      "unit": "percent",
      "collection_method": "api"
    },
    {
      "resource_id": 42,
      "provider_id": 1,
      "metric_name": "memory_usage",
      "value": 4.2,
      "unit": "GB",
      "collection_method": "api"
    }
  ]
}
```

Response:
```json
{
  "success": true,
  "count": 2
}
```

### Get Aggregated Metrics

**GET /api/cloud/metrics/aggregated**

Returns aggregated metrics data for a time period.

Query Parameters:
- `resource_id` (int): Resource ID (required)
- `metric_name` (string): Metric name (required)
- `interval` (string): Aggregation interval (e.g., "1 hour", "1 day")
- `start_time` (string): Start time (ISO 8601 format)
- `end_time` (string): End time (ISO 8601 format)

Response:
```json
{
  "data": [
    {
      "timestamp": "2023-06-15T00:00:00Z",
      "avg_value": 45.2,
      "min_value": 12.3,
      "max_value": 78.9,
      "count": 60
    },
    {
      "timestamp": "2023-06-16T00:00:00Z",
      "avg_value": 42.8,
      "min_value": 10.5,
      "max_value": 81.2,
      "count": 60
    }
  ]
}
```

## Alerts

### List Alerts

**GET /api/cloud/alerts**

Returns a paginated list of alerts.

Query Parameters:
- `page` (int): Page number
- `per_page` (int): Items per page
- `resource_id` (int): Filter by resource ID
- `status` (string): Filter by status ("open", "acknowledged", "resolved")
- `severity` (string): Filter by severity ("info", "warning", "critical")

Response:
```json
{
  "data": [
    {
      "id": 123,
      "resource_id": 42,
      "resource_name": "web-server-01",
      "alert_type": "high_cpu",
      "message": "CPU usage exceeded 80%",
      "severity": "warning",
      "status": "open",
      "created_at": "2023-06-15T14:55:22Z",
      "acknowledged_at": null,
      "resolved_at": null
    },
    // More alerts...
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 2,
    "total_items": 37
  }
}
```

### Create Alert

**POST /api/cloud/alerts**

Creates a new alert.

Request:
```json
{
  "resource_id": 42,
  "alert_type": "high_memory",
  "message": "Memory usage exceeded 90%",
  "severity": "critical",
  "details": {
    "current_value": 92.5,
    "threshold": 90.0
  }
}
```

Response:
```json
{
  "id": 124,
  "resource_id": 42,
  "alert_type": "high_memory",
  "message": "Memory usage exceeded 90%",
  "severity": "critical",
  "status": "open",
  "created_at": "2023-06-15T15:01:45Z"
}
```

### Update Alert

**PATCH /api/cloud/alerts/{id}**

Updates an alert's status.

Request:
```json
{
  "status": "acknowledged",
  "comment": "Investigating the issue"
}
```

Response:
```json
{
  "id": 124,
  "status": "acknowledged",
  "acknowledged_at": "2023-06-15T15:10:22Z",
  "acknowledged_by": {
    "id": 5,
    "username": "admin"
  },
  "comment": "Investigating the issue"
}
```

## ICS Systems

### List ICS Devices

**GET /api/ics/devices**

Returns a list of ICS devices.

Response:
```json
{
  "data": [
    {
      "id": 1,
      "name": "Temperature Sensor A1",
      "device_type": "sensor",
      "location": "Building 1, Floor 2",
      "status": "online",
      "last_reading_at": "2023-06-15T16:55:22Z"
    },
    {
      "id": 2,
      "name": "Pressure Controller B3",
      "device_type": "controller",
      "location": "Building 2, Floor 1",
      "status": "online",
      "last_reading_at": "2023-06-15T16:54:45Z"
    },
    // More devices...
  ]
}
```

### Get Device Readings

**GET /api/ics/readings**

Returns readings from ICS devices.

Query Parameters:
- `device_id` (int): Filter by device ID
- `start_time` (string): Start time (ISO 8601 format)
- `end_time` (string): End time (ISO 8601 format)

Response:
```json
{
  "data": [
    {
      "id": 5001,
      "device_id": 1,
      "reading_type": "temperature",
      "value": 22.5,
      "unit": "celsius",
      "timestamp": "2023-06-15T16:45:00Z",
      "quality": "good"
    },
    {
      "id": 5002,
      "device_id": 1,
      "reading_type": "humidity",
      "value": 45.2,
      "unit": "percent",
      "timestamp": "2023-06-15T16:45:00Z",
      "quality": "good"
    },
    // More readings...
  ]
}
```

### Control ICS Device

**POST /api/ics/control**

Sends a control command to an ICS device.

Request:
```json
{
  "device_id": 2,
  "command": "set_value",
  "parameters": {
    "value": 32.5,
    "unit": "psi"
  }
}
```

Response:
```json
{
  "success": true,
  "device_id": 2,
  "command_id": "cmd-12345",
  "status": "accepted",
  "timestamp": "2023-06-15T17:05:12Z"
}
```

## Security

### List Security Incidents

**GET /api/security/incidents**

Returns a list of security incidents.

Query Parameters:
- `page` (int): Page number
- `per_page` (int): Items per page
- `status` (string): Filter by status
- `severity` (string): Filter by severity

Response:
```json
{
  "data": [
    {
      "id": 42,
      "title": "Unusual login pattern detected",
      "description": "Multiple failed login attempts followed by successful login from unusual location",
      "severity": "medium",
      "status": "investigating",
      "created_at": "2023-06-14T23:15:42Z",
      "affected_resources": [
        {
          "type": "user",
          "id": 5,
          "name": "john.doe"
        }
      ]
    },
    // More incidents...
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 1,
    "total_items": 3
  }
}
```

### Create Security Incident

**POST /api/security/incidents**

Creates a new security incident.

Request:
```json
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
    "username": "system"
  }
}
```

## User Management

### List Users

**GET /api/users**

Returns a paginated list of users.

Query Parameters:
- `page` (int): Page number
- `per_page` (int): Items per page
- `role` (string): Filter by role

Response:
```json
{
  "data": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "is_active": true,
      "last_login": "2023-06-15T12:30:45Z"
    },
    {
      "id": 2,
      "username": "operator",
      "email": "operator@example.com",
      "role": "operator",
      "is_active": true,
      "last_login": "2023-06-14T16:22:10Z"
    },
    // More users...
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 1,
    "total_items": 5
  }
}
```

## Newsletter

### Subscribe

**POST /api/newsletter/subscribe**

Subscribes an email address to the newsletter.

Request:
```json
{
  "email": "subscriber@example.com",
  "name": "John Doe",
  "preferences": {
    "product_updates": true,
    "security_alerts": true,
    "marketing": false
  }
}
```

Response:
```json
{
  "success": true,
  "message": "Subscription successful",
  "subscriber_id": 123
}
```

### Unsubscribe

**POST /api/newsletter/unsubscribe**

Unsubscribes an email address from the newsletter.

Request:
```json
{
  "email": "subscriber@example.com",
  "token": "unsubscribe-token-1234567890"
}
```

Response:
```json
{
  "success": true,
  "message": "You have been unsubscribed successfully"
}
```

## Error Codes

| Status Code | Description |
|-------------|-------------|
| 400 | Bad Request - Invalid input parameters |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource does not exist |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation error |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server-side error |

## Webhooks

The API supports webhooks for real-time event notifications, eliminating the need to poll for changes.

### Configuring Webhooks

Configure webhooks at `/api/webhooks` endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/webhooks` | POST | Create a new webhook subscription |
| `/api/webhooks` | GET | List your webhook subscriptions |
| `/api/webhooks/{id}` | GET | Get details of a specific subscription |
| `/api/webhooks/{id}` | DELETE | Delete a subscription |
| `/api/webhooks/{id}/deliveries` | GET | View delivery history |
| `/api/webhooks/test` | POST | Test a webhook delivery |
| `/api/webhooks/events` | GET | List available event types |

### Event Categories

Events are organized into these categories:

1. **Cloud Resources**
   - `resource.created` - Triggered when a new cloud resource is provisioned
   - `resource.updated` - Triggered when a cloud resource is modified
   - `resource.deleted` - Triggered when a cloud resource is deleted

2. **Alerts**
   - `alert.triggered` - Triggered when a new alert is generated
   - `alert.acknowledged` - Triggered when an alert is acknowledged
   - `alert.resolved` - Triggered when an alert is resolved

3. **Security**
   - `security.incident` - Triggered when a security incident is detected
   - `security.scan.completed` - Triggered when a security scan completes

4. **Industrial Control Systems**
   - `ics.reading` - Triggered when a new reading is recorded
   - `ics.state.change` - Triggered when an ICS device changes state

5. **System**
   - `system.backup.completed` - Triggered when a system backup completes
   - `maintenance.scheduled` - Triggered when maintenance is scheduled

### Security Features

- **Payload Signatures**: Each delivery includes an HMAC-SHA256 signature
- **Automatic Retries**: Failed deliveries are retried with exponential backoff
- **Delivery Tracking**: Comprehensive history of all delivery attempts
- **Secret Management**: Webhook secrets are securely handled and never exposed after creation

### Best Practices

1. **Respond Quickly**: Return a 2xx status code as quickly as possible
2. **Process Asynchronously**: Handle webhook processing in the background
3. **Verify Signatures**: Always verify the signature before processing
4. **Handle Duplicates**: Use idempotency keys to handle potential duplicates
5. **Monitor Deliveries**: Use the deliveries endpoint to track failures

## SDK Libraries

Official client libraries are available for easy integration:
- Python: `pip install cloud-platform-client`
- JavaScript: `npm install cloud-platform-js`
- Go: `go get github.com/username/cloud-platform-go`

## Support

For API support and issues, contact the development team at api-support@cloudplatform.com or open an issue on the GitHub repository.