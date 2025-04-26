# WebSocket API

This module provides real-time communication capabilities for the Cloud Infrastructure Platform through WebSocket connections, enabling bidirectional communication between clients and the server for features like live updates, notifications, and real-time data streaming.

## Contents

- Overview
- Key Components
- Directory Structure
- API Endpoints
- Message Format
- Authentication
- Channel Subscription
- Security Features
- Usage Examples
- Client Implementation
- Related Documentation

## Overview

The WebSocket API implements secure, bidirectional communication channels between clients and the server, supporting features such as real-time updates, notifications, and data streaming. It provides a standardized message format, channel-based subscription model, proper authentication and authorization controls, and comprehensive error handling. The implementation follows security best practices including token-based authentication, permission validation, and input sanitization.

## Key Components

- **`__init__.py`**: Module initialization and connection management
  - Blueprint registration
  - Connection lifecycle management
  - Event handler registration
  - Security middleware configuration
  - WebSocket session tracking

- **`auth.py`**: Authentication and authorization for WebSocket connections
  - Permission checks for subscriptions
  - Session validation and refreshing
  - Token verification for initial connection
  - User identity confirmation

- **`channels.py`**: Channel subscription and management
  - Channel access control
  - Resource-specific channels
  - Subscription management
  - User-specific channels
  - Topic-based filtering

- **`events.py`**: Event handling and message processing
  - Broadcast functionality
  - Event filtering and targeting
  - Event handler registration
  - Event type definitions
  - Message type processors

- **`metrics.py`**: Connection and performance monitoring
  - Connection statistics
  - Error rate tracking
  - Latency measurements
  - Message throughput tracking
  - Performance monitoring

- **`routes.py`**: WebSocket endpoint implementations
  - Channel subscription handling
  - Connection authentication
  - Connection lifecycle hooks
  - Message routing
  - Protocol negotiation

- **`schemas.py`**: Message validation and formatting
  - Error response standardization
  - Message schema validation
  - Request payload validation
  - Response formatting structures
  - Subscription request validation

## Directory Structure

```plaintext
api/websocket/
├── __init__.py         # Module initialization and connection management
├── auth.py             # Authentication for WebSocket connections
├── channels.py         # Channel subscription management
├── events.py           # Event types and handlers
├── metrics.py          # Connection and message metrics
├── README.md           # This documentation
├── routes.py           # WebSocket endpoint implementations
├── schemas.py          # Message validation schemas
└── tests/              # Test suite
    ├── README.md       # Testing documentation
    ├── conftest.py     # Shared pytest fixtures
    ├── test_auth.py    # Authentication and authorization tests
    ├── test_channels.py # Channel subscription tests
    ├── test_events.py  # Event handling tests
    ├── test_integration.py # End-to-end integration tests
    ├── test_metrics.py # Metrics collection tests
    └── test_routes.py  # API endpoint tests
```

## API Endpoints

| Endpoint | Protocol | Description | Authentication | Rate Limit |
|----------|----------|-------------|---------------|------------|
| `/api/websocket/connect` | WebSocket | Main WebSocket connection | Required | 60/minute |
| `/api/websocket/auth` | HTTP/POST | Generate connection token | Required | 30/minute |
| `/api/websocket/status` | HTTP/GET | Check WebSocket service status | Optional | 120/minute |

## Message Format

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
| `ping`/`pong` | Both | Connection health check |
| `channel.subscribe` | Client→Server | Subscribe to a channel |
| `channel.unsubscribe` | Client→Server | Unsubscribe from a channel |
| `auth.refresh` | Client→Server | Refresh authentication token |
| `resource.updated` | Server→Client | Resource state changed |
| `notification` | Server→Client | User notification |
| `error` | Server→Client | Error message |

## Authentication

1. **Initial Authentication**
   - Obtain a WebSocket token via the `/api/websocket/auth` endpoint
   - Include the token in the connection request
   - The server validates the token before establishing the connection

2. **Session Maintenance**
   - Tokens have a limited lifespan
   - Clients can refresh tokens using the `auth.refresh` message
   - Expired tokens result in connection termination

## Channel Subscription

Clients can subscribe to different channels to receive specific events:

```json
{
  "type": "channel.subscribe",
  "data": {
    "channel": "resource:1234"
  },
  "request_id": "sub-1"
}
```

Common channel patterns:

- `user:{user_id}` - User-specific events
- `resource:{resource_id}` - Resource-specific updates
- `alerts:{category}` - Alerts by category
- `system` - System-wide notifications

## Security Features

- **Authentication Enforcement**: All connections require valid authentication
- **Authorization Validation**: Channel subscriptions are checked against user permissions
- **Input Validation**: All messages are validated against defined schemas
- **Rate Limiting**: Prevents connection flooding and abuse
- **Token Expiration**: Connection tokens have limited lifespans
- **Connection Monitoring**: Suspicious connection patterns are detected and reported
- **Secure WebSocket**: Requires WSS (WebSocket Secure) protocol in production

## Usage Examples

### Connection Establishment Examples

```javascript
// Obtain a connection token first via API call to /api/websocket/auth
const token = await getWebSocketToken();

// Connect to the WebSocket endpoint
const socket = new WebSocket('wss://example.com/api/websocket/connect');

// Send authentication immediately after connection
socket.onopen = () => {
  socket.send(JSON.stringify({
    type: 'authentication',
    data: { token: token }
  }));
};

// Handle incoming messages
socket.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received message:', message);
};
```

### Channel Subscription Examples

```javascript
// Subscribe to a resource channel
socket.send(JSON.stringify({
  type: 'channel.subscribe',
  data: {
    channel: 'resource:1234'
  },
  request_id: 'subscription-1'
}));

// Handle subscription confirmation
socket.onmessage = (event) => {
  const message = JSON.parse(event.data);

  if (message.type === 'channel.subscribe.success' &&
      message.request_id === 'subscription-1') {
    console.log('Successfully subscribed to channel');
  }
};
```

### Handling Events Examples

```javascript
socket.onmessage = (event) => {
  const message = JSON.parse(event.data);

  switch (message.type) {
    case 'resource.updated':
      updateResourceUI(message.data);
      break;
    case 'notification':
      showNotification(message.data);
      break;
    case 'error':
      handleError(message.data);
      break;
    case 'pong':
      updateConnectionStatus('healthy');
      break;
  }
};
```

### Maintaining Connection Examples

```javascript
// Send periodic ping messages to keep the connection alive
setInterval(() => {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({
      type: 'ping',
      data: { timestamp: Date.now() }
    }));
  }
}, 30000);

// Handle connection close and implement reconnection
socket.onclose = (event) => {
  console.log('Connection closed:', event.code, event.reason);
  // Implement reconnection logic with exponential backoff
  setTimeout(reconnect, calculateBackoff());
};
```

## Client Implementation

When implementing a client for the WebSocket API:

1. **Handle Authentication Properly**
   - Obtain tokens through secure channels
   - Store tokens securely
   - Implement token refresh before expiration

2. **Implement Robust Error Handling**
   - Handle connection errors gracefully
   - Implement exponential backoff for reconnection
   - Log WebSocket errors appropriately

3. **Process Messages Efficiently**
   - Use a message router pattern for different message types
   - Handle messages asynchronously when appropriate
   - Validate incoming message structure

4. **Optimize Resource Usage**
   - Subscribe only to needed channels
   - Unsubscribe from channels when no longer needed
   - Implement connection pooling for multiple components

5. **Follow Security Best Practices**
   - Validate the server's SSL certificate
   - Never expose connection tokens in client-side logs
   - Sanitize any user input before sending via WebSocket
   - Use the WSS protocol (WebSocket Secure)

## Related Documentation

- API Reference
- Authentication System
- Channel Subscription Guide
- Error Handling
- Event Types Reference
- Real-time Communication Architecture
- Security Best Practices
- WebSocket Client SDKs
