# Webhook Testing Framework

This directory contains test suites for the webhook system in the Cloud Infrastructure Platform, ensuring the reliability, security, and correctness of webhook functionality.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Testing Approach](#testing-approach)
- [Security Testing](#security-testing)
- [Mock Tools](#mock-tools)
- [Usage Examples](#usage-examples)
- [Common Test Patterns](#common-test-patterns)
- [Related Documentation](#related-documentation)

## Overview

The webhook testing framework validates all aspects of the webhook system including subscription management, delivery processing, security controls, and API endpoints. It provides comprehensive test coverage of both the internal webhook processing logic and the external API interfaces.

The framework includes specialized tools for testing webhook deliveries, circuit breaker patterns, and security mechanisms. It enables reliable testing through isolation, mocking of external dependencies, and targeted test fixtures.

## Key Components

- **`test_delivery.py`**: Tests for webhook delivery functionality
  - Validates delivery to target URLs
  - Tests retry mechanisms for failed deliveries
  - Verifies delivery tracking and status updates
  - Tests circuit breaker pattern functionality
  - Validates exponential backoff behavior

- **`test_routes.py`**: Tests for webhook API endpoints
  - Tests all webhook REST endpoints
  - Validates authentication requirements
  - Verifies proper rate limiting
  - Tests response structures and status codes
  - Ensures appropriate error handling

- **`test_security.py`**: Tests for webhook security features
  - Validates signature generation and verification
  - Ensures tampered payloads are detected
  - Tests signature validation in the mock webhook server
  - Verifies security headers and authentication requirements
  - Validates CSRF protection

- **`test_subscription.py`**: Tests for webhook subscription creation and management
  - Validates proper subscription creation with all parameters
  - Tests input validation for subscription parameters
  - Verifies secure generation of subscription secrets
  - Ensures appropriate validation of URLs and event types
  - Tests subscription health metrics

- **`test_testing.py`**: Tests for the webhook testing utilities
  - Validates MockWebhookServer functionality
  - Tests custom response handling
  - Verifies delivery tracking and verification methods
  - Tests signature verification functions
  - Validates failure sequence simulation

- **`conftest.py`**: Shared test fixtures
  - Provides reusable webhook subscription fixtures
  - Sets up webhook delivery test data
  - Creates test environment configuration
  - Enables circuit breaker testing scenarios
  - Facilitates authentication testing

- **`__init__.py`**: Initialization utilities
  - Provides setup functions for test environments
  - Contains helper functions for circuit breaker testing
  - Includes utility functions for test assertions
  - Manages test state between test runs
  - Offers timing and condition monitoring utilities

## Directory Structure

```plaintext
api/webhooks/tests/
├── README.md                 # This documentation
├── conftest.py               # Shared pytest fixtures
├── __init__.py               # Test utility functions
├── test_delivery.py          # Tests for webhook delivery functionality
├── test_routes.py            # Tests for webhook REST API endpoints
├── test_security.py          # Tests for webhook security features
├── test_subscription.py      # Tests for subscription management
├── test_testing.py           # Tests for webhook testing utilities
└── webhook_test_constants.py # Shared test constants
```

## Testing Approach

The tests follow these key principles:

1. **Isolation**: Each test runs independently with its own isolated test fixtures
2. **Clean State**: All tests restore the database to a clean state after execution
3. **Authentication**: All endpoint tests verify authentication requirements
4. **Mocking**: External HTTP calls are mocked to prevent external dependencies
5. **Circuit Breaking**: Tests verify the circuit breaker pattern functions correctly
6. **Retries**: Tests validate retry behavior with exponential backoff
7. **Edge Cases**: Tests include both happy path and error handling scenarios

## Security Testing

Security testing focuses on these key areas:

- **Signature Verification**: Testing HMAC-SHA256 signature generation and validation
- **Secret Management**: Ensuring webhook secrets are properly generated and stored
- **Authentication**: Verifying all endpoints have proper authentication controls
- **Input Validation**: Testing against invalid URLs and malformed payloads
- **Rate Limiting**: Verifying proper rate limiting on sensitive endpoints
- **URL Validation**: Testing prevention of callbacks to internal networks
- **CSRF Protection**: Verifying CSRF protections on API endpoints
- **Secret Exposure**: Ensuring secrets aren't exposed in logs or responses

## Mock Tools

The test suite includes a `MockWebhookServer` class that simulates an external webhook receiver for testing deliveries:

- Captures webhooks for verification in tests
- Provides configurable responses for testing error handling
- Simulates intermittent failures for circuit breaker testing
- Includes utilities for verifying signature validation
- Tracks delivery counts and content for assertions
- Supports custom response handlers and delays
- Allows simulation of specific response sequences

## Usage Examples

### Testing Webhook Subscriptions

```python
def test_create_subscription_valid(app, db, test_user):
    """Test creating a valid webhook subscription"""
    with app.app_context():
        subscription = setup_test_subscription(
            app=app,
            db_session=db,
            user_id=test_user.id,
            target_url="https://example.com/webhook",
            event_types=[EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED]
        )

        assert subscription.id is not None
        assert subscription.secret is not None
        assert len(subscription.secret) >= 32
        assert subscription.circuit_status == "closed"
```

### Testing Circuit Breaker Behavior

```python
def test_circuit_breaker_opens_after_failures(app, db, test_user):
    """Test that circuit breaker opens after multiple failures"""
    with app.app_context():
        # Create subscription with mock server that always fails
        subscription, mock_server = setup_circuit_breaker_test_scenario(
            app=app,
            db_session=db,
            user_id=test_user.id,
            state='closed',
            failure_threshold=3
        )

        mock_server.set_response(500, '{"error": "Server error"}')

        # Send webhooks until circuit trips
        for i in range(3):
            deliver_webhook(EventType.RESOURCE_CREATED, {"id": f"res-{i}"},
                           subscription_id=subscription.id)
            time.sleep(0.1)  # Let background task complete

        # Verify circuit is open
        subscription = WebhookSubscription.query.get(subscription.id)
        assert_circuit_state(subscription, 'open')
```

### Testing Signature Verification

```python
def test_signature_verification():
    """Test webhook signature verification"""
    payload = json.dumps({"test": "data"})
    secret = TEST_WEBHOOK_SECRET

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
   def test_webhook_delivery(mock_post, app, db, test_user):
       mock_post.return_value = MagicMock(status_code=200,
                                         text='{"status":"received"}',
                                         headers={})
       # Test code here
   ```

2. **Testing Circuit Breaker States**:

   ```python
   def test_circuit_half_open_state(app, db, test_user):
       subscription, mock_server = setup_circuit_breaker_test_scenario(
           app=app,
           db_session=db,
           user_id=test_user.id,
           state='half-open',
           failure_count=5
       )
       # Test code here
   ```

3. **Waiting for Asynchronous Operations**:

   ```python
   def test_async_webhook_delivery(app, db, test_user):
       # Start delivery
       deliver_webhook(event_type, payload, subscription_id=subscription.id)

       # Wait for delivery to complete
       result = wait_for_condition(
           lambda: WebhookDelivery.query.filter_by(
               subscription_id=subscription.id,
               status=DeliveryStatus.DELIVERED
           ).first() is not None
       )

       assert result is True
   ```

4. **Testing Authentication Requirements**:

   ```python
   def test_endpoint_requires_auth(client):
       # Test without login
       response = client.get(url_for('api.webhooks.list_webhook_subscriptions'))
       assert response.status_code in (401, 403)
   ```

5. **Using Test Context Managers**:

   ```python
   def test_background_tasks(app, db, test_user):
       with wait_for_background_tasks():
           deliver_webhook(event_type, payload, subscription_id=subscription.id)

       # After context exits, background tasks have completed
       delivery = WebhookDelivery.query.filter_by(
           subscription_id=subscription.id
       ).first()

       assert delivery is not None
   ```

## Related Documentation

- Webhook System Overview
- Circuit Breaker Pattern
- Webhook API Reference
- MockWebhookServer API Reference
- Event Types Reference
- Security Best Practices
