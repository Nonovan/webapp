# Webhook System

The webhook system enables real-time notifications to external systems when events occur within the Cloud Infrastructure Platform.

## Contents

- Overview
- Architecture
- Key Components
- Directory Structure
- API Endpoints
- Database Models
- Delivery Process
- Security Considerations
- Event Types
- Testing
- Best Practices
- Extending the System
- Related Documentation

## Overview

The webhook system provides a mechanism for external applications to receive real-time notifications when events occur within the Cloud Infrastructure Platform. Webhooks allow for loose coupling between systems and enable event-driven architectures across organizational boundaries.

## Architecture

The webhook system consists of these components:

- **Subscription Management**: Creates and manages webhook subscriptions
- **Event Dispatch**: Determines which subscriptions should receive which events
- **Delivery System**: Securely delivers payloads to target URLs with retries
- **History Tracking**: Records all delivery attempts and their outcomes

## Key Components

- **`__init__.py`**: Core webhook definitions and signature generation utilities
  - Event type constants
  - Event category groupings
  - Signature generation and verification
  - Delivery status tracking

- **`models.py`**: Database models for webhook functionality
  - Subscription storage
  - Delivery history tracking
  - Status monitoring

- **`routes.py`**: API endpoints for webhook management
  - Subscription creation, listing, and deletion
  - Delivery history tracking
  - Test functionality

- **`subscription.py`**: Subscription management functionality
  - Subscription creation with validation
  - Secret generation
  - Event filtering

- **`delivery.py`**: Event delivery processing
  - Payload preparation and signing
  - HTTP request handling
  - Retry logic and exponential backoff

- **`testing.py`**: Testing utilities
  - MockWebhookServer for unit testing
  - Delivery verification
  - Response simulation

## Directory Structure

```plaintext
api/webhooks/
├── __init__.py         # Core definitions and utilities
├── delivery.py         # Webhook delivery functionality
├── models.py           # Database models
├── README.md           # This documentation
├── routes.py           # API endpoints
├── services.py         # Business logic services
├── subscription.py     # Subscription management
├── testing.py          # Testing utilities
└── tests/              # Test suite
    ├── conftest.py     # Test fixtures
    ├── README.md       # Testing documentation
    ├── test_delivery.py         # Delivery tests
    ├── test_routes.py           # API endpoint tests
    ├── test_security.py         # Security feature tests
    ├── test_subscription.py     # Subscription management tests
    └── test_testing.py          # Testing utilities tests
```

## API Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| webhooks | GET | List webhook subscriptions | 60/minute |
| webhooks | POST | Create a webhook subscription | 30/minute |
| `/api/webhooks/<id>` | GET | Get a specific subscription | 60/minute |
| `/api/webhooks/<id>` | DELETE | Delete a subscription | 30/minute |
| `/api/webhooks/<id>/deliveries` | GET | Get delivery history | 60/minute |
| `/api/webhooks/test` | POST | Test a webhook delivery | 10/minute |
| `/api/webhooks/events` | GET | List available event types | 30/minute |

## Database Models

### WebhookSubscription

Represents an external endpoint registration to receive webhook events:

- `id`: Unique identifier (UUID)
- `user_id`: User who created the subscription
- `target_url`: URL to send webhook payloads to
- `event_types`: List of event types to notify about
- `description`: Optional description of the subscription
- `headers`: Custom HTTP headers to include with webhook requests
- `secret`: Secret key used to sign webhook payloads
- `max_retries`: Maximum number of retry attempts for failed deliveries
- `is_active`: Whether the subscription is currently active

### WebhookDelivery

Tracks the delivery attempt history and outcomes for webhook events:

- `id`: Unique delivery identifier
- `subscription_id`: ID of the webhook subscription
- `event_type`: Type of event delivered
- `payload`: Event payload data
- `status`: Current delivery status
- `attempts`: Number of delivery attempts made
- `response_code`: HTTP status code from the most recent attempt
- `response_body`: Response body from the most recent attempt
- `duration_ms`: Request duration in milliseconds
- `created_at`: When the delivery was first attempted
- `delivered_at`: When the delivery was successfully completed
- `last_attempt_at`: Timestamp of the most recent delivery attempt

## Delivery Process

1. An event occurs in the system (e.g., resource created, alert triggered)
2. The system identifies all active subscriptions interested in the event type
3. For each subscription, a delivery record is created
4. The payload is signed with the subscription's secret
5. The payload is sent to the target URL with appropriate headers
6. Success/failure is recorded along with response details
7. Failed deliveries are retried with exponential backoff up to max_retries

## Security Considerations

- All webhook payloads are signed using HMAC-SHA256 with a per-subscription secret
- The signature is included in the `X-Webhook-Signature` header
- Webhook secrets are never exposed after initial creation
- Subscriptions are associated with specific users for access control
- All delivery attempts are logged for security auditing
- Rate limiting is applied to all webhook API endpoints
- URL validation prevents callbacks to internal network addresses
- Request timeouts prevent hanging connections
- Payload size limits prevent abuse of the system

## Event Types

The platform supports these event categories:

### 1. Cloud Resources

- `resource.created` - When a new cloud resource is provisioned
- `resource.updated` - When a cloud resource is modified
- `resource.deleted` - When a cloud resource is deleted
- `resource.started` - When a cloud resource is started
- `resource.stopped` - When a cloud resource is stopped
- `resource.error` - When a cloud resource enters an error state
- `resource.scaled` - When a cloud resource is scaled up or down

### 2. Alerts

- `alert.triggered` - When a new alert is generated
- `alert.acknowledged` - When an alert is acknowledged
- `alert.resolved` - When an alert is resolved
- `alert.escalated` - When an alert is escalated
- `alert.comment` - When a comment is added to an alert

### 3. Security

- `security.incident` - When a security incident is detected
- `security.scan.completed` - When a security scan completes
- `security.vulnerability` - When a vulnerability is discovered
- `security.brute_force` - When a brute force attempt is detected
- `security.file_integrity` - When file integrity validation fails
- `security.audit` - When security audit events occur

### 4. ICS Systems

- `ics.reading` - When a new reading is recorded from an ICS device
- `ics.state.change` - When an ICS device changes state
- `ics.alarm` - When an ICS device triggers an alarm
- `ics.maintenance_required` - When maintenance is required
- `ics.calibration` - When a device is calibrated

### 5. System Events

- `system.backup.completed` - When a system backup completes
- `system.maintenance.scheduled` - When system maintenance is scheduled
- `system.upgraded` - When the system is upgraded
- `system.high_load` - When the system experiences high load
- `system.low_disk_space` - When disk space is running low

### 6. User Events

- `user.created` - When a user account is created
- `user.updated` - When a user account is updated
- `user.logged_in` - When a user logs in
- `user.login_failed` - When a login attempt fails
- `user.mfa_enabled` - When multi-factor authentication is enabled

### 7. Cost Events

- `cost.threshold_exceeded` - When a cost threshold is exceeded
- `cost.anomaly` - When a cost anomaly is detected
- `cost.report` - When a cost report is generated

## Testing

The system includes tools for testing webhooks:

- A `MockWebhookServer` class for unit testing
  - Captures webhook deliveries for verification
  - Simulates responses for testing error handling
  - Validates webhook signatures
  - Tracks delivery statistics

- A test endpoint at `/api/webhooks/test` for manual testing
  - Sends test events to a specified subscription
  - Returns delivery status information
  - Accepts custom payloads

- Delivery history viewing for troubleshooting
  - Tracks response codes and bodies
  - Records timing information
  - Maintains retry history

## Best Practices

When using webhooks in your application:

1. **Validate Signatures**: Always verify the signature using your subscription secret
2. **Respond Quickly**: Return a 2xx status code as soon as possible, then process asynchronously
3. **Set Up Health Monitoring**: Monitor webhook delivery success rates for early issue detection
4. **Use Idempotent Handlers**: Design webhook handlers to be safely retryable
5. **Implement Circuit Breakers**: Temporarily disable webhooks that consistently fail
6. **Include Correlation IDs**: Add request IDs in your responses for troubleshooting
7. **Limit Subscription Scope**: Subscribe only to events your application needs
8. **Handle Duplicates**: Design for the possibility of receiving the same event twice

## Extending the System

To add new event types:

1. Add the event type to the `EventType` class in **init**.py
2. Add the event to the appropriate category in `EVENT_CATEGORIES`
3. Trigger the new event type using `deliver_webhook()` from your code

To enhance the webhook system:

1. Implement event buffering for high-volume scenarios
2. Add webhook subscription groups for easier management
3. Implement webhook delivery metrics and dashboards
4. Create subscription templates for common use cases

## Related Documentation

- API Reference
- Integration Guide
- Security Best Practices
- Event Catalog
