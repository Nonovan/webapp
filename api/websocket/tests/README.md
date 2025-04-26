# WebSocket API Testing Framework

This directory contains test suites for the WebSocket API in the Cloud Infrastructure Platform, ensuring reliability, security, and correct functionality of real-time communication features.

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

The WebSocket testing framework validates all aspects of the WebSocket API including connection management, authentication, message handling, channel subscriptions, and API endpoints. It provides comprehensive test coverage of both the internal WebSocket processing logic and the external interfaces, ensuring reliable and secure real-time communication.

## Key Components

- **`test_auth.py`**: Tests for WebSocket authentication and authorization
  - Validates token-based authentication process
  - Tests authentication failure handling
  - Verifies permission checks for channel subscriptions
  - Tests session validation and refreshing
  - Ensures proper security controls for connections

- **`test_channels.py`**: Tests for channel subscription functionality
  - Validates channel subscription and unsubscription flows
  - Tests access control for different channel types
  - Verifies resource-specific channel permissions
  - Tests channel filtering and targeting logic
  - Ensures proper event routing to subscribers

- **`test_events.py`**: Tests for WebSocket event handling
  - Validates event dispatching and routing
  - Tests event type validation and processing
  - Verifies message formatting and structure
  - Tests broadcasting functionality
  - Ensures proper error handling for invalid events

- **`test_integration.py`**: End-to-end integration tests
  - Tests full WebSocket communication flow
  - Verifies interaction with other system components
  - Tests reconnection and error recovery
  - Validates cross-component event propagation
  - Ensures consistency with REST API behavior

- **`test_metrics.py`**: Tests for WebSocket metrics collection
  - Validates connection metrics tracking
  - Tests message throughput measurement
  - Verifies latency measurement accuracy
  - Tests error rate monitoring
  - Ensures proper performance tracking

- **`test_routes.py`**: Tests for WebSocket API endpoints
  - Tests connection establishment
  - Validates proper route handling
  - Tests rate limiting functionality
  - Verifies connection lifecycle hooks
  - Ensures proper error responses

- **`conftest.py`**: Shared pytest fixtures
  - Provides test WebSocket client configurations
  - Sets up mock WebSocket server environment
  - Creates test event data
  - Establishes authenticated test sessions
  - Configures test channel subscriptions

## Directory Structure

```plaintext
api/websocket/tests/
├── README.md              # This documentation
├── conftest.py            # Shared pytest fixtures
├── test_auth.py           # Authentication and authorization tests
├── test_channels.py       # Channel subscription tests
├── test_events.py         # Event handling tests
├── test_integration.py    # End-to-end integration tests
├── test_metrics.py        # Metrics collection tests
└── test_routes.py         # API endpoint tests
```

## Testing Approach

The tests follow these key principles:

1. **Isolation**: Each test runs independently with its own isolated test fixtures
2. **Clean State**: All tests restore the connection state after execution
3. **Authentication**: All connection tests verify authentication requirements
4. **Mocking**: External dependencies are mocked for reliable testing
5. **Edge Cases**: Tests include both happy path and error handling scenarios
6. **Concurrency**: Tests verify behavior under concurrent connections
7. **Performance**: Critical paths include basic performance validation

## Security Testing

Security testing focuses on these key areas:

- **Authentication**: Testing token validation, session management, and authentication workflows
- **Authorization**: Verifying permission checks for channel subscriptions and message routing
- **Input Validation**: Testing against invalid messages and malformed payloads
- **Rate Limiting**: Verifying connection and message rate limiting functionality
- **Session Security**: Ensuring proper session validation and security controls
- **Connection Security**: Validating secure WebSocket protocol usage
- **Access Control**: Testing channel-specific access restrictions

## Mock Tools

The test suite includes a `MockWebSocketClient` class that simulates client connections for testing:

- Supports connection establishment and termination
- Tracks sent and received messages
- Simulates client-side events and responses
- Provides utilities for authentication testing
- Monitors connection state throughout tests

## Usage Examples

### Testing Event Handling

```python
def test_event_dispatching(app, mock_ws_client, test_user):
    """Test that events are properly dispatched to handlers"""
    with app.app_context():
        # Authenticate and connect
        mock_ws_client.authenticate(test_user)
        mock_ws_client.connect()

        # Send a test event
        event = {
            "type": "resource.updated",
            "data": {"resource_id": 123, "status": "active"}
        }
        mock_ws_client.send_event(event)

        # Verify the event was handled
        assert mock_ws_client.has_received_event("resource.updated.ack")

        # Verify event data was processed
        received = mock_ws_client.get_received_events()[-1]
        assert received["data"]["resource_id"] == 123
```

### Testing Channel Subscriptions

```python
def test_channel_subscription(app, mock_ws_client, test_user):
    """Test subscribing to a channel"""
    with app.app_context():
        # Authenticate and connect
        mock_ws_client.authenticate(test_user)
        mock_ws_client.connect()

        # Subscribe to a channel
        mock_ws_client.send_event({
            "type": "channel.subscribe",
            "data": {"channel": "resource:123"}
        })

        # Verify subscription success
        assert mock_ws_client.has_received_event("channel.subscribe.success")

        # Test receiving events on that channel
        send_to_channel("resource:123", {
            "type": "resource.updated",
            "data": {"status": "active"}
        })

        # Verify event was received
        assert mock_ws_client.has_received_event("resource.updated")
```

### Testing Authentication

```python
def test_authentication_required(app, mock_ws_client):
    """Test that authentication is required for connection"""
    # Try to connect without authentication
    connected = mock_ws_client.connect(authenticate=False)

    # Verify connection was rejected
    assert not connected
    assert mock_ws_client.connection_status == "rejected"
    assert "authentication" in mock_ws_client.last_error.lower()

    # Now authenticate and connect
    mock_ws_client.authenticate(test_user)
    connected = mock_ws_client.connect()

    # Verify connection was successful
    assert connected
    assert mock_ws_client.connection_status == "connected"
```

## Common Test Patterns

1. **Testing Connection Authentication**:

   ```python
   def test_token_authentication(app, mock_ws_client, test_user):
       token = generate_ws_token(test_user)
       mock_ws_client.set_auth_token(token)
       connected = mock_ws_client.connect()
       assert connected
   ```

2. **Testing Message Handling**:

   ```python
   def test_message_handling(app, mock_ws_client, test_user):
       mock_ws_client.authenticate(test_user)
       mock_ws_client.connect()
       mock_ws_client.send_message({
           "type": "ping",
           "data": {"timestamp": time.time()}
       })
       assert mock_ws_client.has_received_message("pong")
   ```

3. **Testing Error Responses**:

   ```python
   def test_invalid_message_format(app, mock_ws_client, test_user):
       mock_ws_client.authenticate(test_user)
       mock_ws_client.connect()
       mock_ws_client.send_raw("invalid json data")
       assert mock_ws_client.has_received_error("invalid_format")
   ```

## Related Documentation

- WebSocket API Overview
- MockWebSocketClient API
- WebSocket Models
- WebSocket Integration Guide
- WebSocket Security Guide
- Real-time Communication Architecture
