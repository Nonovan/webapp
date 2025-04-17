Collecting workspace information# API Reference - Cloud Infrastructure Platform

## Overview

This documentation provides comprehensive information about the RESTful API endpoints available in the Cloud Infrastructure Platform. The API follows REST principles with JSON as the primary data interchange format, and all endpoints are secured with JWT authentication.

## General Information

### Base URL

All API endpoints are prefixed with api.

### Authentication

Most endpoints require authentication using JWT tokens in the `Authorization` header. To authenticate requests, include your access token in the header as follows:

```
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

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate user and issue token |
| `/api/auth/register` | POST | Create a new user account |
| `/api/auth/extend_session` | POST | Extend current session lifetime |
| `/api/auth/logout` | POST | Invalidate current token |

### Cloud Resources

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cloud/resources` | GET | List all cloud resources |
| `/api/cloud/resources` | POST | Create a new cloud resource |
| `/api/cloud/resources/{id}` | GET | Get specific resource details |
| `/api/cloud/resources/{id}` | PATCH | Update resource properties |
| `/api/cloud/resources/{id}` | DELETE | Delete a cloud resource |

### Cloud Metrics

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cloud/metrics` | GET | Get current metrics |
| `/api/cloud/metrics/history` | GET | Get historical metrics |
| `/api/cloud/metrics/batch` | POST | Submit multiple metrics |
| `/api/cloud/metrics/aggregated` | GET | Get aggregated metrics for time period |

### Alerts

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cloud/alerts` | GET | List alerts with optional filtering |
| `/api/cloud/alerts` | POST | Create a new alert |
| `/api/cloud/alerts/{id}` | PATCH | Update alert status |
| `/api/cloud/alerts/{id}/acknowledge` | POST | Acknowledge an alert |
| `/api/cloud/alerts/{id}/resolve` | POST | Resolve an alert |

### ICS Systems

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ics/devices` | GET | List all ICS devices |
| `/api/ics/readings` | GET | Get latest readings from devices |
| `/api/ics/control` | POST | Send control commands to devices |
| `/api/ics/devices/{id}/history` | GET | Get historical data for a device |

### Security

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/security/incidents` | GET | List security incidents |
| `/api/security/incidents` | POST | Create a new security incident |
| `/api/security/incidents/{id}` | PATCH | Update incident status |
| `/api/security/scan` | POST | Trigger security scan |

### User Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/users` | GET | List all users |
| `/api/users/{id}` | GET | Get user details |
| `/api/users/{id}` | PATCH | Update user information |
| `/api/users/{id}/permissions` | GET | Get user permissions |

### Newsletter

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/newsletter/subscribe` | POST | Subscribe to newsletter |
| `/api/newsletter/unsubscribe` | POST | Unsubscribe from newsletter |

### Webhooks

| Endpoint | Method | Description |
|----------|--------|-------------|
| webhooks | POST | Create a new webhook subscription |
| webhooks | GET | List your webhook subscriptions |
| `/api/webhooks/{id}` | GET | Get details of a specific subscription |
| `/api/webhooks/{id}` | DELETE | Delete a subscription |
| `/api/webhooks/{id}/deliveries` | GET | View delivery history |
| `/api/webhooks/test` | POST | Test a webhook delivery |
| `/api/webhooks/events` | GET | List available event types |

## Query Parameters

Many endpoints support standard query parameters:

- `page`: Page number for pagination (default: 1)
- `per_page`: Items per page (default varies by endpoint)
- `sort`: Field to sort by
- `order`: Sort order (asc/desc)
- `filter`: Field-specific filters

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

1. **Cloud Resources**
   - `resource.created` - When a new cloud resource is provisioned
   - `resource.updated` - When a cloud resource is modified
   - `resource.deleted` - When a cloud resource is deleted
   - `resource.started` - When a cloud resource is started
   - `resource.stopped` - When a cloud resource is stopped
   - `resource.error` - When a cloud resource enters an error state
   - `resource.scaled` - When a cloud resource is scaled up or down

2. **Alerts**
   - `alert.triggered` - When a new alert is generated
   - `alert.acknowledged` - When an alert is acknowledged
   - `alert.resolved` - When an alert is resolved
   - `alert.escalated` - When an alert is escalated
   - `alert.comment` - When a comment is added to an alert

3. **Security**
   - `security.incident` - When a security incident is detected
   - `security.scan.completed` - When a security scan completes
   - `security.vulnerability` - When a vulnerability is discovered
   - `security.brute_force` - When a brute force attempt is detected
   - `security.file_integrity` - When file integrity validation fails
   - `security.audit` - When security audit events occur

4. **ICS Systems**
   - `ics.reading` - When a new reading is recorded from an ICS device
   - `ics.state.change` - When an ICS device changes state
   - `ics.alarm` - When an ICS device triggers an alarm
   - `ics.maintenance_required` - When maintenance is required
   - `ics.calibration` - When a device is calibrated

## SDK Libraries

Official client libraries are available for easy integration:
- Python: Cloud Platform Client (Python package)
- JavaScript: Cloud Platform JS (npm package)
- Go: Cloud Platform Go (Go package)

## Support

For API support and issues, contact the development team or open an issue on the GitHub repository.
