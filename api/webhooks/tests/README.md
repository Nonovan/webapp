# Webhook Testing Framework

This directory contains test suites for the webhook system in the Cloud Infrastructure Platform, ensuring the reliability, security, and correctness of webhook functionality.

## Contents

- Overview
- Key Components
- Directory Structure
- Testing Approach
- Security Testing
- Mock Tools
- Usage Examples
- Common Test Patterns
- Related Documentation

## Overview

The webhook testing framework validates all aspects of the webhook system including subscription management, delivery processing, security controls, and API endpoints. It provides comprehensive test coverage of both the internal webhook processing logic and the external API interfaces.

## Key Components

- **`test_subscription.py`**: Tests for webhook subscription creation and management
  - Validates proper subscription creation with all parameters
  - Tests input validation for subscription parameters
  - Verifies secure generation of subscription secrets
  - Ensures appropriate validation of URLs and event types

- **`test_security.py`**: Tests for webhook security features
  - Validates signature generation and verification
  - Ensures tampered payloads are detected
  - Tests signature validation in the mock webhook server
  - Verifies security headers and authentication requirements

- **`test_delivery.py`**: Tests for webhook delivery functionality
  - Validates delivery to target URLs
  - Tests retry mechanisms for failed deliveries
  - Verifies delivery tracking and status updates
  - Tests delivery payload formatting

- **`test_routes.py`**: Tests for webhook API endpoints
  - Tests all webhook REST endpoints
  - Validates authentication requirements
  - Verifies proper rate limiting
  - Tests response structures and status codes
  - Ensures appropriate error handling

- **`test_testing.py`**: Tests for the webhook testing utilities
  - Validates MockWebhookServer functionality
  - Tests custom response handling
  - Verifies delivery tracking and verification methods
  - Tests signature verification functions

- **`conftest.py`**: Shared test fixtures
  - Provides reusable webhook subscription fixtures
  - Sets up webhook delivery test data
  - Creates test environment configuration

## Directory Structure

```plaintext
api/webhooks/tests/
├── README.md                # This documentation
├── conftest.py              # Shared pytest fixtures
├── test_delivery.py         # Tests for webhook delivery functionality
├── test_routes.py           # Tests for webhook REST API endpoints
├── test_security.py         # Tests for webhook security features
├── test_subscription.py     # Tests for subscription management
└── test_testing.py          # Tests for webhook testing utilities
```

## Testing Approach

The tests follow these key principles:

1. **Isolation**: Each test runs independently with its own isolated test fixtures
2. **Clean State**: All tests restore the database to a clean state after execution
3. **Authorization**: All endpoint tests verify authentication requirements
4. **Mocking**: External HTTP calls are mocked to prevent external dependencies
5. **Edge Cases**: Tests include both happy path and error handling scenarios

## Security Testing

Security testing focuses on these key areas:

- **Signature Verification**: Testing HMAC-SHA256 signature generation and validation
- **Secret Management**: Ensuring webhook secrets are properly generated and stored
- **Authentication**: Verifying all endpoints have proper authentication controls
- **Input Validation**: Testing against invalid URLs and malformed payloads
- **Rate Limiting**: Verifying proper rate limiting on sensitive endpoints

## Mock Tools

The test suite includes a `MockWebhookServer` class that simulates an external webhook receiver for testing deliveries:

- Captures deliveries for verification in tests
- Provides configurable responses for testing error handling
- Includes utilities for verifying signature validation
- Tracks delivery counts and content

## Usage Examples

### Testing Webhook Subscriptions

```python
def test_create_subscription_valid(app, db, test_user):
    """Test creating a valid webhook subscription"""
    with app.app_context():
        subscription = create_subscription(
            target_url="https://example.com/webhook",
            event_types=[EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED],
            description="Test subscription",
            user_id=test_user.id
        )

        assert subscription["id"] is not None
        assert "secret" in subscription
        assert len(subscription["secret"]) > 32
```

### Testing Signature Verification

```python
def test_signature_verification():
    """Test webhook signature verification"""
    payload = json.dumps({"test": "data"})
    secret = "webhook-secret-key"

    # Generate signature
    signature = generate_webhook_signature(payload, secret)

    # Verify correct signature passes
    assert verify_webhook_signature(payload, signature, secret) is True

    # Verify tampered payload fails
    tampered = json.dumps({"test": "tampered"})
    assert verify_webhook_signature(tampered, signature, secret) is False
```

### Testing API Routes

```python
@patch('api.webhooks.routes.deliver_webhook')
def test_test_webhook(mock_deliver, client, db, test_user, webhook_subscription):
    """Test the test webhook endpoint"""
    login_user(client, test_user)

    # Mock delivery function
    mock_deliver.return_value = [{
        "delivery_id": 123,
        "subscription_id": webhook_subscription.id,
        "event_type": "test.event",
        "status": DeliveryStatus.PENDING
    }]

    # Test the endpoint
    response = client.post(
        url_for('api.webhooks.test_webhook'),
        json={"subscription_id": webhook_subscription.id}
    )

    assert response.status_code == 200
    result = json.loads(response.data)
    assert result["success"] is True
```

## Common Test Patterns

1. **Mocking External Services**:

   ```python
   @patch('requests.post')
   def test_webhook_delivery(mock_post):
       mock_post.return_value = MockResponse(200, '{"status":"received"}')
       # Test code here
   ```

2. **Testing Authentication**:

   ```python
   def test_endpoint_requires_auth(client):
       # Test without login
       response = client.get(url_for('api.webhooks.list_webhook_subscriptions'))
       assert response.status_code == 401
   ```

3. **Validating Event Types**:

   ```python
   def test_invalid_event_type():
       with pytest.raises(ValueError):
           create_subscription(event_types=["invalid_event_type"], ...)
   ```

## Related Documentation

- Webhook System Overview
- MockWebhookServer API
- Webhook Models
- API Testing Best Practices
- Security Testing Guide
- Webhook Integration Guide
