# API Reference - Cloud Infrastructure Platform

## Overview

This documentation provides comprehensive information about the RESTful API endpoints available in the Cloud Infrastructure Platform. The API follows REST principles with JSON as the primary data interchange format, and all endpoints are secured with JWT authentication.

## General Information

### Base URL

All API endpoints are prefixed with api.

### Authentication Requests

Most endpoints require authentication using JWT tokens in the `Authorization` header. To authenticate requests, include your access token in the header as follows:

```plaintext
Authorization: Bearer <your_token_here>
```

### Response Format

All responses are returned in JSON format. Successful responses typically include:

- A `data` object containing the requested information
- A `meta` object with pagination details when applicable

Error responses include:

- An `error` description
- A `status_code` indicating the HTTP error code

### Rate Limiting

API endpoints are subject to rate limiting:

- Authentication endpoints: 30 requests per minute
- General API endpoints: 60 requests per minute
- Intensive operations: 10 requests per hour

When rate limits are exceeded, the API returns a `429 Too Many Requests` status code.

## Core API Endpoints

### Admin

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/audit/logs` | GET | Access security audit logs |
| `/api/admin/audit/events` | GET | Access security events |
| `/api/admin/config` | GET | Get system configuration |
| `/api/admin/config` | PUT | Update system configuration |
| `/api/admin/roles` | GET | List all roles and permissions |
| `/api/admin/system/health` | GET | System health dashboard |
| `/api/admin/users` | GET | List all users with filter options |
| `/api/admin/users` | POST | Create a new user account |
| `/api/admin/users/{id}` | GET | Get detailed user information |
| `/api/admin/users/{id}` | PUT | Update user account details |
| `/api/admin/users/{id}/role` | PATCH | Modify user role assignments |

### Alerts

| Endpoint | Method | Description |
|----------|--------|-------------|
| alerts | GET | List alerts with optional filtering |
| alerts | POST | Create a new alert |
| `/api/alerts/{id}` | PATCH | Update alert status |
| `/api/alerts/{id}/acknowledge` | POST | Acknowledge an alert |
| `/api/alerts/{id}/resolve` | POST | Resolve an alert |

### Audit

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/audit/dashboard` | GET | Get dashboard data for audit activity |
| `/api/audit/events/correlate` | POST | Correlate related security events |
| `/api/audit/export` | POST | Export audit logs in various formats |
| `/api/audit/logs` | GET | Query and filter audit logs |
| `/api/audit/logs/{id}` | GET | Get detailed audit log entry |
| `/api/audit/reports/compliance` | POST | Generate compliance reports |
| `/api/audit/reports/security` | POST | Generate security reports |
| `/api/audit/search/advanced` | POST | Perform advanced log searches |
| `/api/audit/statistics` | GET | Get audit log statistics and trends |

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/extend_session` | POST | Extend current session lifetime |
| `/api/auth/login` | POST | Authenticate user and issue token |
| `/api/auth/logout` | POST | Invalidate current token |
| `/api/auth/mfa/setup` | POST | Set up multi-factor authentication |
| `/api/auth/password/reset` | POST | Request password reset |
| `/api/auth/register` | POST | Create a new user account |
| `/api/auth/session/status` | GET | Check current session status |
| `/api/auth/verify` | POST | Verify token validity |

### Cloud

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cloud/metrics` | GET | Get current metrics |
| `/api/cloud/metrics/aggregated` | GET | Get aggregated metrics for time period |
| `/api/cloud/metrics/batch` | POST | Submit multiple metrics |
| `/api/cloud/metrics/history` | GET | Get historical metrics |
| `/api/cloud/resources` | GET | List all cloud resources |
| `/api/cloud/resources` | POST | Create a new cloud resource |
| `/api/cloud/resources/{id}` | DELETE | Delete a cloud resource |
| `/api/cloud/resources/{id}` | GET | Get specific resource details |
| `/api/cloud/resources/{id}` | PATCH | Update resource properties |

### ICS Systems

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ics/control` | POST | Send control commands to devices |
| `/api/ics/devices` | GET | List all ICS devices |
| `/api/ics/devices` | POST | Register a new ICS device |
| `/api/ics/devices/{id}` | GET | Get specific device details |
| `/api/ics/devices/{id}` | PATCH | Update device configuration |
| `/api/ics/devices/{id}/history` | GET | Get historical data for a device |
| `/api/ics/devices/{id}/readings` | GET | Get readings for specific device |
| `/api/ics/readings` | GET | Get latest readings from devices |
| `/api/ics/readings` | POST | Record new device readings |
| `/api/ics/status` | GET | Get overall ICS system status |

### Metrics

| Endpoint | Method | Description |
|----------|--------|-------------|
| metrics | GET | Get system metrics |
| `/api/metrics/aggregated` | GET | Get aggregated metrics |
| `/api/metrics/batch` | POST | Submit batch metrics |
| `/api/metrics/export` | GET | Export metrics data |
| `/api/metrics/health` | GET | Get system health summary |

### Newsletter

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/newsletter/subscribe` | POST | Subscribe to newsletter |
| `/api/newsletter/unsubscribe` | POST | Unsubscribe from newsletter |

### Security

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/security/incidents` | GET | List security incidents |
| `/api/security/incidents` | POST | Create a new security incident |
| `/api/security/incidents/{id}` | GET | Get incident details |
| `/api/security/incidents/{id}` | PATCH | Update incident status |
| `/api/security/incidents/{id}/comments` | POST | Add comment to incident |
| `/api/security/scan` | POST | Trigger security scan |
| `/api/security/scan/status` | GET | Get scan status |
| `/api/security/threats/detection` | GET | List threat detections |
| `/api/security/threats/ioc` | POST | Create threat indicator |
| `/api/security/threats/ioc/{id}` | DELETE | Remove threat indicator |
| `/api/security/vulnerabilities` | GET | List vulnerabilities |
| `/api/security/vulnerabilities/{id}` | GET | Get vulnerability details |

### Users

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/users` | GET | List all users |
| `/api/users/{id}` | GET | Get user details |
| `/api/users/{id}` | PATCH | Update user information |
| `/api/users/{id}/permissions` | GET | Get user permissions |

### Webhooks

| Endpoint | Method | Description |
|----------|--------|-------------|
| webhooks | GET | List your webhook subscriptions |
| webhooks | POST | Create a new webhook subscription |
| `/api/webhooks/{id}` | DELETE | Delete a subscription |
| `/api/webhooks/{id}` | GET | Get details of a specific subscription |
| `/api/webhooks/{id}/deliveries` | GET | View delivery history |
| `/api/webhooks/events` | GET | List available event types |
| `/api/webhooks/test` | POST | Test a webhook delivery |

### WebSocket

| Endpoint | Protocol | Description |
|----------|----------|-------------|
| `/api/websocket/auth` | HTTP/POST | Generate connection token |
| `/api/websocket/connect` | WebSocket | Main WebSocket connection |
| `/api/websocket/status` | HTTP/GET | Check WebSocket service status |

## Query Parameters

Many endpoints support standard query parameters:

- `filter`: Field-specific filters
- `order`: Sort order (asc/desc)
- `page`: Page number for pagination (default: 1)
- `per_page`: Items per page (default varies by endpoint)
- `sort`: Field to sort by
- `fields`: Specify which fields to include in response

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

## Webhook Event Types

The API supports these event categories:

1. **Alerts**
   - `alert.acknowledged` - When an alert is acknowledged
   - `alert.comment` - When a comment is added to an alert
   - `alert.escalated` - When an alert is escalated
   - `alert.resolved` - When an alert is resolved
   - `alert.triggered` - When a new alert is generated

2. **Cloud Resources**
   - `resource.created` - When a new cloud resource is provisioned
   - `resource.deleted` - When a cloud resource is deleted
   - `resource.error` - When a cloud resource enters an error state
   - `resource.scaled` - When a cloud resource is scaled up or down
   - `resource.started` - When a cloud resource is started
   - `resource.stopped` - When a cloud resource is stopped
   - `resource.updated` - When a cloud resource is modified

3. **ICS Systems**
   - `ics.alarm` - When an ICS device triggers an alarm
   - `ics.calibration` - When a device is calibrated
   - `ics.maintenance_required` - When maintenance is required
   - `ics.reading` - When a new reading is recorded from an ICS device
   - `ics.state.change` - When an ICS device changes state

4. **Security**
   - `security.audit` - When security audit events occur
   - `security.brute_force` - When a brute force attempt is detected
   - `security.file_integrity` - When file integrity validation fails
   - `security.incident` - When a security incident is detected
   - `security.scan.completed` - When a security scan completes
   - `security.vulnerability` - When a vulnerability is discovered

## Message Formats

### WebSocket Messages

All WebSocket messages use a standardized JSON format:

```json
{
  "type": "message_type",
  "data": {
    "key1": "value1",
    "key2": "value2"
  },
  "request_id": "optional_correlation_id"
}
```

### Common Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `auth.refresh` | Client→Server | Refresh authentication token |
| `channel.subscribe` | Client→Server | Subscribe to a channel |
| `channel.unsubscribe` | Client→Server | Unsubscribe from a channel |
| `error` | Server→Client | Error message |
| `notification` | Server→Client | User notification |
| `ping`/`pong` | Both | Connection health check |
| `resource.updated` | Server→Client | Resource state changed |

## SDK Libraries

Official client libraries are available for easy integration:

- Go: Cloud Platform Go (Go package)
- JavaScript: Cloud Platform JS (npm package)
- Python: Cloud Platform Client (Python package)

## Support

For API support and issues, contact the development team or open an issue on the GitHub repository.
