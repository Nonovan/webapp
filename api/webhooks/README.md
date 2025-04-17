# Webhook System

TThe webhook system enables real-time notifications to external systems when events occur within the Cloud Infrastructure Platform.

## Architecture

The webhook system consists of these components:

- **Subscription Management**: Creates and manages webhook subscriptions
- **Event Dispatch**: Determines which subscriptions should receive which events
- **Delivery System**: Securely delivers payloads to target URLs with retries
- **History Tracking**: Records all delivery attempts and their outcomes

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

## Event Types

The platform supports These event categories:


1. Cloud Resources
- `resource.created` - When a new cloud resource is provisioned
- `resource.updated` - When a cloud resource is modified
- `resource.deleted` - When a cloud resource is deleted
- `resource.started` - When a cloud resource is started
- `resource.stopped` - When a cloud resource is stopped
- `resource.error` - When a cloud resource enters an error state
- `resource.scaled` - When a cloud resource is scaled up or down

2. Alerts
- `alert.triggered` - When a new alert is generated
- `alert.acknowledged` - When an alert is acknowledged
- `alert.resolved` - When an alert is resolved
- `alert.escalated` - When an alert is escalated
- `alert.comment` - When a comment is added to an alert
3. Security
- `security.incident` - When a security incident is detected
- `security.scan.completed` - When a security scan completes
- `security.vulnerability` - When a vulnerability is discovered
- `security.brute_force` - When a brute force attempt is detected
- `security.file_integrity` - When file integrity validation fails
- `security.audit` - When security audit events occur

4. ICS Systems
- `ics.reading` - When a new reading is recorded from an ICS device
- `ics.state.change` - When an ICS device changes state
- `ics.alarm` - When an ICS device triggers an alarm
- `ics.maintenance_required` - When maintenance is required
- `ics.calibration` - When a device is calibrated

## Testing

The system includes tools for testing webhooks:

- A `MockWebhookServer` class for unit testing
- A test endpoint at `/api/webhooks/test` for manual testing
- Delivery history viewing for troubleshooting

## Extending the System

To add new event types:

1. Add the event type to the `EventType` class in `api/webhooks/__init__.py`
2. Add the event to the appropriate category in `EVENT_CATEGORIES`
3. Trigger the new event type using `deliver_webhook()` from your code
