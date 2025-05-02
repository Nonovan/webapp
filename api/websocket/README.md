# WebSocket API

This module provides real-time communication capabilities for the Cloud Infrastructure Platform through WebSocket connections, enabling bidirectional communication between clients and the server for features like live updates, notifications, and real-time data streaming.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [API Endpoints](#api-endpoints)
- [Message Format](#message-format)
- [Authentication](#authentication)
- [Channel Subscription](#channel-subscription)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Client Implementation](#client-implementation)
- [Error Handling](#error-handling)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Related Documentation](#related-documentation)

## Overview

The WebSocket API implements secure, bidirectional communication channels between clients and the server, supporting features such as real-time updates, notifications, and data streaming. It provides a standardized message format, channel-based subscription model, proper authentication and authorization controls, and comprehensive error handling. The implementation follows security best practices including token-based authentication, permission validation, and input sanitization.

## Key Components

- **`__init__.py`**: Module initialization and connection management
  - Blueprint registration
  - Connection lifecycle management
  - Event handler registration
  - Security middleware configuration
  - WebSocket session tracking
  - Application integration hooks

- **`auth.py`**: Authentication and authorization for WebSocket connections
  - Permission checks for subscriptions
  - Session validation and refreshing
  - Token verification for initial connection
  - User identity confirmation
  - Token-based authentication flow
  - Circuit breakers for authentication services

- **`channels.py`**: Channel subscription and management
  - Channel access control
  - Resource-specific channels
  - Subscription management
  - User-specific channels
  - Topic-based filtering
  - Channel pattern validation
  - Channel metadata retrieval

- **`events.py`**: Event handling and message processing
  - Broadcast functionality
  - Event filtering and targeting
  - Event handler registration
  - Event type definitions
  - Message type processors
  - Event permission enforcement
  - Event routing and dispatching

- **`metrics.py`**: Connection and performance monitoring
  - Connection statistics
  - Error rate tracking
  - Latency measurements
  - Message throughput tracking
  - Performance monitoring
  - Resource usage tracking
  - Metrics retention management
  - Real-time metrics emission

- **`routes.py`**: WebSocket endpoint implementations
  - Channel subscription handling
  - Connection authentication
  - Connection lifecycle hooks
  - Message routing
  - Protocol negotiation
  - Event dispatching
  - Error response standardization
  - Rate limiting enforcement
  - Connection cleanup

- **`schemas.py`**: Message validation and formatting
  - Error response standardization
  - Message schema validation
  - Request payload validation
  - Response formatting structures
  - Subscription request validation
  - Data sanitization
  - Input size limits
  - Type checking and conversion

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
   - Include the token in the connection request as a query parameter or in the Authorization header
   - The server validates the token before establishing the connection
   - Tokens are scoped specifically for WebSocket connections with `websocket:connect` scope

2. **Session Maintenance**
   - Tokens have a limited lifespan (typically 60 minutes by default)
   - Clients can refresh tokens using the `auth.refresh` message before expiration
   - Expired tokens result in connection termination
   - The server regularly validates session state during long-lived connections

3. **Token Security**
   - Tokens are JWT-based with appropriate expiration
   - Rate limiting prevents token generation abuse
   - Tokens are bound to specific user identities
   - Failed authentication attempts are logged as security events

## Channel Subscription

Clients can subscribe to different channels to receive specific events:

```json
{
  "type": "channel.subscribe",
  "data": {
    "channel": "resource:1234",
    "filters": {
      "event_types": ["created", "updated", "deleted"],
      "priority": ["high", "medium"]
    }
  },
  "request_id": "sub-1"
}
```

### Channel Patterns

The WebSocket API supports these standard channel patterns:

| Pattern | Description | Required Permission |
|---------|-------------|---------------------|
| `user:{user_id}` | User-specific events | Must be current user or have user admin permission |
| `resource:{resource_type}:{id}` | Resource-specific updates | Resource view permission |
| `resource:{resource_type}` | All events for resource type | Resource type view permission |
| `alerts:{category}` | Alerts by category | Alerts view permission |
| `metrics` | System metrics stream | Metrics view permission |
| `system` | System-wide notifications | System view permission |
| `status:{component}` | Component status updates | Status view permission |

### Subscription Features

- **Permission Validation**: All channel subscriptions are checked against user permissions
- **Filtering**: Clients can specify filters to receive only relevant events
- **Subscription Management**: Clients can unsubscribe from channels they no longer need
- **Scoped Access**: Resource and user channels are restricted based on ownership and permissions

## Security Features

- **Authentication Enforcement**: All connections require valid authentication
- **Authorization Validation**: Channel subscriptions are checked against user permissions
- **Input Validation**: All messages are validated against defined schemas
- **Rate Limiting**: Prevents connection flooding and abuse
- **Token Expiration**: Connection tokens have limited lifespans
- **Connection Monitoring**: Suspicious connection patterns are detected and reported
- **Secure WebSocket**: Requires WSS (WebSocket Secure) protocol in production
- **Message Size Limits**: Prevents denial of service through oversized messages
- **CORS Protection**: Proper origin validation for WebSocket connections
- **Circuit Breakers**: Protection against cascading failures in authentication services
- **Connection Limits**: Maximum connections per user and IP address
- **Payload Validation**: Strict schema validation with input sanitization
- **Comprehensive Logging**: Security-relevant events are logged for audit purposes
- **Connection Timeouts**: Automatic disconnection of idle connections

## Usage Examples

### Connection Establishment Examples

```javascript
// Obtain a connection token first via API call to /api/websocket/auth
const token = await getWebSocketToken();

// Connect to the WebSocket endpoint
const socket = new WebSocket(`wss://example.com/api/websocket/connect?token=${token}`);

// Alternative: Send authentication after connection (if not using query parameter)
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
    channel: 'resource:servers:1234',
    filters: {
      event_types: ['status_changed', 'metric_alert']
    }
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

// Unsubscribe when no longer needed
socket.send(JSON.stringify({
  type: 'channel.unsubscribe',
  data: {
    channel: 'resource:servers:1234'
  },
  request_id: 'unsubscribe-1'
}));
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

  // Implement exponential backoff for reconnection
  const backoff = Math.min(30000, Math.pow(2, reconnectAttempts) * 1000);
  console.log(`Attempting to reconnect in ${backoff}ms...`);

  setTimeout(reconnect, backoff);
};

// Handle connection errors
socket.onerror = (error) => {
  console.error('WebSocket error:', error);
  // Log errors for troubleshooting but don't expose sensitive details
};
```

### Token Refresh Example

```javascript
// Calculate when to refresh the token (e.g., 5 minutes before expiration)
const tokenExpiry = parseJwt(token).exp * 1000; // Convert to milliseconds
const refreshTime = tokenExpiry - Date.now() - (5 * 60 * 1000);

// Set up refresh timer
setTimeout(() => {
  socket.send(JSON.stringify({
    type: 'auth.refresh',
    request_id: 'refresh-1'
  }));
}, refreshTime);

// Handle refresh response
socket.onmessage = (event) => {
  const message = JSON.parse(event.data);

  if (message.type === 'auth.refresh.success' && message.request_id === 'refresh-1') {
    // Store the new token
    const newToken = message.data.token;
    const newExpiry = new Date(message.data.expires_at);

    // Update token and set up next refresh
    updateToken(newToken, newExpiry);
  }
};
```

## Client Implementation

When implementing a client for the WebSocket API:

1. **Handle Authentication Properly**
   - Obtain tokens through secure channels
   - Store tokens securely
   - Implement token refresh before expiration
   - Have a strategy for re-authentication if token refresh fails

2. **Implement Robust Error Handling**
   - Handle connection errors gracefully
   - Implement exponential backoff for reconnection
   - Log WebSocket errors appropriately
   - Handle server-side error messages
   - Implement circuit breakers for failing connections

3. **Process Messages Efficiently**
   - Use a message router pattern for different message types
   - Handle messages asynchronously when appropriate
   - Validate incoming message structure
   - Use a consistent message processing pipeline

4. **Optimize Resource Usage**
   - Subscribe only to needed channels
   - Unsubscribe from channels when no longer needed
   - Implement connection pooling for multiple components
   - Consider batching messages when appropriate
   - Handle reconnection without duplicating subscriptions

5. **Follow Security Best Practices**
   - Validate the server's SSL certificate
   - Never expose connection tokens in client-side logs
   - Sanitize any user input before sending via WebSocket
   - Use the WSS protocol (WebSocket Secure)
   - Implement proper token storage and rotation
   - Close connections when not in use

## Error Handling

The WebSocket API provides standardized error messages:

```json
{
  "type": "error",
  "data": {
    "code": "authorization_error",
    "message": "Insufficient permissions for channel resource:servers:1234",
    "details": {
      "required_permission": "servers:view",
      "channel": "resource:servers:1234"
    }
  },
  "request_id": "subscription-1"
}
```

### Common Error Codes

| Error Code | Description | Typical Action |
|------------|-------------|----------------|
| `authentication_error` | Authentication failed or token expired | Re-authenticate or refresh token |
| `authorization_error` | Insufficient permissions | Check required permissions |
| `channel_error` | Invalid channel format or non-existent channel | Verify channel format |
| `invalid_message` | Invalid message format or content | Check message structure |
| `rate_limit_exceeded` | Too many requests | Implement backoff strategy |
| `subscription_error` | Error in channel subscription | Check channel permissions |
| `validation_error` | Message failed schema validation | Fix message format issues |
| `system_error` | Internal server error | Report to support with correlation ID |

## Metrics and Monitoring

The WebSocket API collects comprehensive metrics to monitor performance and security:

- **Connection Metrics**: Connection count, duration, disconnect reasons
- **Message Metrics**: Message volume, size, and processing time
- **Channel Metrics**: Subscription counts and message distribution
- **Performance Metrics**: Processing latency and resource utilization
- **Error Metrics**: Error rates by type and channel
- **Security Metrics**: Authentication failures and permission denials

These metrics are available through the monitoring system and can be accessed via the metrics endpoint with appropriate permissions.

## Related Documentation

- API Reference - Complete API documentation
- Authentication System - Authentication details
- Channel Subscription Guide - In-depth channel guide
- Error Handling - Error response standards
- Event Types Reference - Available event types
- Real-time Communication Architecture - System design
- Security Best Practices - Security guidelines
- WebSocket Client SDKs - Language-specific clients
