# Webhook System

The webhook system enables real-time notifications to external systems when events occur within the Cloud Infrastructure Platform.

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [API Endpoints](#api-endpoints)
- [Database Models](#database-models)
- [Delivery Process](#delivery-process)
- [Circuit Breaker Pattern](#circuit-breaker-pattern)
- [Security Considerations](#security-considerations)
- [Event Types](#event-types)
- [Testing](#testing)
- [Best Practices](#best-practices)
- [Extending the System](#extending-the-system)
- [Related Documentation](#related-documentation)

## Overview

The webhook system provides a mechanism for external applications to receive real-time notifications when events occur within the Cloud Infrastructure Platform. Webhooks allow for loose coupling between systems and enable event-driven architectures across organizational boundaries. The system implements reliable delivery with automatic retries, security through payload signing, and resilience using the circuit breaker pattern.

## Architecture

The webhook system consists of these components:

- **Subscription Management**: Creates and manages webhook subscriptions
- **Event Dispatch**: Determines which subscriptions should receive which events
- **Delivery System**: Securely delivers payloads to target URLs with retries
- **Circuit Breaker**: Prevents repeated calls to failing endpoints
- **History Tracking**: Records all delivery attempts and their outcomes

![Webhook System Architecture](https://link-to-architecture-diagram.png)

## Key Components

- **`__init__.py`**: Core webhook definitions and signature generation utilities
  - Event type constants
  - Event category groupings
  - Signature generation and verification
  - Delivery status tracking
  - Application initialization hooks
  - Circuit breaker initialization

- **`models.py`**: Database models for webhook functionality
  - Subscription storage
  - Delivery history tracking
  - Status monitoring
  - Health metrics calculation
  - Circuit breaker state management

- **`routes.py`**: API endpoints for webhook management
  - Subscription creation, listing, and deletion
  - Delivery history tracking
  - Test functionality
  - Event type listing
  - Circuit breaker status and control

- **`services.py`**: Business logic services
  - Subscription validation
  - Event queueing
  - Webhook triggering
  - Delivery management
  - Circuit breaker operations

- **`subscription.py`**: Subscription management functionality
  - Subscription creation with validation
  - Secret generation
  - Event filtering
  - Subscription health monitoring
  - Circuit breaker configuration

- **`delivery.py`**: Event delivery processing
  - Payload preparation and signing
  - HTTP request handling
  - Retry logic and exponential backoff
  - Circuit breaking for failing endpoints

- **`testing.py`**: Testing utilities
  - MockWebhookServer for unit testing
  - Delivery verification
  - Response simulation
  - Signature validation testing
  - Circuit breaker simulation

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
| `/api/webhooks/<id>` | PUT | Update a subscription | 30/minute |
| `/api/webhooks/<id>` | DELETE | Delete a subscription | 30/minute |
| `/api/webhooks/<id>/deliveries` | GET | Get delivery history | 60/minute |
| `/api/webhooks/test` | POST | Test a webhook delivery | 10/minute |
| `/api/webhooks/events` | GET | List available event types | 30/minute |
| `/api/webhooks/<id>/rotate-secret` | POST | Rotate webhook secret | 5/minute |
| `/api/webhooks/deliveries/<id>/retry` | POST | Retry a failed delivery | 20/minute |
| `/api/webhooks/<id>/circuit` | GET | Get circuit breaker status | 30/minute |
| `/api/webhooks/<id>/circuit` | POST | Manage circuit breaker | 10/minute |

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
- `retry_interval`: Base interval in seconds between retries
- `created_at`: When the subscription was created
- `updated_at`: When the subscription was last updated
- `is_active`: Whether the subscription is currently active

**Circuit breaker fields:**

- `circuit_status`: Current state of the circuit breaker ('closed', 'open', 'half-open')
- `failure_count`: Number of consecutive failures
- `failure_threshold`: Number of failures before the circuit opens
- `last_failure_at`: Timestamp of the most recent failure
- `circuit_tripped_at`: When the circuit breaker was last tripped
- `next_attempt_at`: When to attempt delivery again after circuit opens
- `reset_timeout`: Time in seconds before transitioning from open to half-open
- `success_threshold`: Successful requests needed in half-open state to close circuit
- `half_open_successes`: Counter for successful requests in half-open state

### WebhookDeliveryAttempt

Tracks the delivery attempt history and outcomes for webhook events:

- `id`: Unique delivery identifier
- `subscription_id`: ID of the webhook subscription
- `event_type`: Type of event delivered
- `payload`: Event payload data
- `status`: Current delivery status (pending, delivered, failed, retrying)
- `attempts`: Number of delivery attempts made
- `response_code`: HTTP status code from the most recent attempt
- `response_body`: Response body from the most recent attempt
- `request_id`: Correlation ID for tracking the request
- `error_message`: Error details if delivery failed
- `request_duration`: Request duration in milliseconds
- `created_at`: When the delivery was first attempted
- `completed_at`: When the delivery was successfully completed
- `updated_at`: When the delivery record was last updated
- `last_attempt_at`: Timestamp of the most recent delivery attempt

## Delivery Process

1. An event occurs in the system (e.g., resource created, alert triggered)
2. The system identifies all active subscriptions interested in the event type
3. For each subscription, a delivery record is created
4. The circuit breaker status is checked to determine if delivery should proceed
5. The payload is signed with the subscription's secret
6. The payload is sent to the target URL with appropriate headers
7. Success/failure is recorded along with response details
8. The circuit breaker state is updated based on the delivery outcome
9. Failed deliveries are retried with exponential backoff up to `max_retries`

### Delivery Headers

Every webhook delivery includes these standard headers:

- `Content-Type: application/json`
- `User-Agent: Cloud-Platform-Webhook-Service`
- `X-Webhook-Signature`: HMAC-SHA256 signature of payload
- `X-Event-Type`: Type of event being delivered
- `X-Webhook-ID`: Unique identifier for the webhook delivery
- `X-Request-ID`: Correlation ID for request tracking

## Circuit Breaker Pattern

The webhook system implements the circuit breaker pattern to prevent repeated calls to failing endpoints, improving system reliability and performance.

### Circuit Breaker States

1. **Closed**: Normal operation - webhook deliveries proceed as expected.
2. **Open**: Delivery attempts are suspended after multiple consecutive failures.
3. **Half-Open**: After the reset timeout, a test delivery is allowed to determine if the endpoint has recovered.

### Circuit Breaker Operation

1. **When Closed**:
   - Deliveries proceed normally
   - Failures are counted
   - Once failures reach `failure_threshold`, circuit trips to Open state

2. **When Open**:
   - Webhook deliveries are skipped
   - A reset timeout timer begins
   - After `reset_timeout` seconds, circuit transitions to Half-Open

3. **When Half-Open**:
   - Limited test deliveries are allowed
   - If successful, successful deliveries are counted
   - After `success_threshold` successful deliveries, circuit closes
   - Any failure immediately returns circuit to Open state

### Configuration

Circuit breaker behavior can be configured both globally and per-subscription:

- `WEBHOOK_CIRCUIT_THRESHOLD`: Number of consecutive failures before tripping (default: 5)
- `WEBHOOK_CIRCUIT_RESET`: Seconds to wait before transitioning to half-open (default: 300)
- `WEBHOOK_CIRCUIT_SUCCESS`: Successful requests needed to close circuit (default: 2)
- `WEBHOOK_CIRCUIT_HALFOPEN`: Additional timing control for half-open state (default: 60)

### Background Maintenance

A scheduled background task runs every minute to check for circuit breakers that need to transition from open to half-open state based on their timeouts.

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
- Circuit breakers automatically disable failing subscriptions
- HTTPS is required for all webhook endpoints
- Secrets can be rotated without disrupting service

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
- `alert.suppressed` - When an alert is suppressed
- `alert.correlated` - When an alert is correlated with others
- `alert.metric_threshold` - When a metric threshold is reached
- `alert.notification_sent` - When an alert notification is sent
- `alert.notification_failed` - When sending an alert notification fails

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
  - Simulates circuit breaker scenarios

- A test endpoint at `/api/webhooks/test` for manual testing
  - Sends test events to a specified subscription
  - Returns delivery status information
  - Accepts custom payloads

- Delivery history viewing for troubleshooting
  - Tracks response codes and bodies
  - Records timing information
  - Maintains retry history

### Example Testing Code

```python
# Using the MockWebhookServer in tests
from api.webhooks.testing import MockWebhookServer

def test_webhook_delivery(client, auth):
    # Create test server
    mock_server = MockWebhookServer(secret="test_secret")

    # Set up server to simulate circuit breaker scenario
    # Will fail 6 times then succeed
    mock_server.set_failure_sequence([500, 500, 500, 500, 500, 500, 200])

    # Create subscription pointing to mock server
    subscription = create_subscription(
        target_url=mock_server.url,
        event_types=["resource.created"],
        secret=mock_server.secret,
        failure_threshold=5  # Circuit should trip after 5 failures
    )

    # Trigger webhook
    trigger_event("resource.created", {"id": "res-123", "name": "test-resource"})

    # Verify delivery
    deliveries = mock_server.get_deliveries()
    assert len(deliveries) == 1
    assert deliveries[0]["event_type"] == "resource.created"
    assert deliveries[0]["data"]["id"] == "res-123"

    # Verify circuit breaker tripped
    subscription_record = WebhookSubscription.query.get(subscription.id)
    assert subscription_record.circuit_status == 'open'
```

## Best Practices

When using webhooks in your application:

1. **Validate Signatures**: Always verify the signature using your subscription secret
2. **Respond Quickly**: Return a 2xx status code as soon as possible, then process asynchronously
3. **Set Up Health Monitoring**: Monitor webhook delivery success rates for early issue detection
4. **Use Idempotent Handlers**: Design webhook handlers to be safely retryable
5. **Configure Circuit Breakers**: Adjust circuit breaker thresholds based on your endpoint's reliability
6. **Include Correlation IDs**: Add request IDs in your responses for troubleshooting
7. **Limit Subscription Scope**: Subscribe only to events your application needs
8. **Handle Duplicates**: Design for the possibility of receiving the same event twice
9. **Implement Proper Error Handling**: Log and alert on webhook delivery failures
10. **Rotate Secrets Regularly**: Change webhook secrets periodically for security

### Example Signature Verification (Python)

```python
import hmac
import hashlib

def verify_signature(payload, signature, secret):
    """
    Verify the webhook signature using the shared secret.

    Args:
        payload (str): The raw payload as a string
        signature (str): The X-Webhook-Signature header value
        secret (str): The webhook secret

    Returns:
        bool: True if signature is valid, False otherwise
    """
    computed_signature = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(computed_signature, signature)
```

## Extending the System

To add new event types:

1. Add the event type to the `EventType` class in `__init__.py`
2. Add the event to the appropriate category in `EVENT_CATEGORIES`
3. Trigger the new event type using `trigger_webhook()` from your code

To enhance the webhook system:

1. Implement event buffering for high-volume scenarios
2. Add webhook subscription groups for easier management
3. Implement webhook delivery metrics and dashboards
4. Create subscription templates for common use cases
5. Add filtering capabilities for more precise event selection
6. Implement webhook payload transformations
7. Add support for different payload formats (e.g., XML)
8. Fine-tune circuit breaker parameters by event type

## Related Documentation

- API Reference
- Webhook Integration Guide
- Security Best Practices
- Event Catalog
- Webhook Testing Framework
- Circuit Breaker Pattern
