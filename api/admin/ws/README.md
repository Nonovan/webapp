# Administrative WebSocket API

The Administrative WebSocket API provides secure, real-time communication channels for system administrators to receive live updates on system health, security events, audit logs, and to perform interactive administrative tasks in the Cloud Infrastructure Platform.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Message Format](#message-format)
- [Authentication](#authentication)
- [Channel Subscription](#channel-subscription)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Error Handling](#error-handling)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Related Documentation](#related-documentation)

## Overview

The Administrative WebSocket API implements secure WebSocket connections that provide real-time data streaming, event notifications, and interactive command capabilities for administrative users. It follows the same strict authentication and authorization patterns as the REST API while providing enhanced performance for real-time monitoring and operational tasks.

The WebSocket API follows a channel-based subscription model with comprehensive security controls:

- Strict authentication and authorization
- Event-based messaging architecture
- Channel-based subscription model
- Comprehensive audit logging
- Session monitoring and anomaly detection

## Key Components

- **`__init__.py`**: WebSocket connection management
  - Connection establishment and lifecycle management
  - Protocol negotiation and upgrade handling
  - Connection pool management and limits
  - Session binding and verification
  - Heartbeat and ping/pong management
  - Graceful connection termination

- **`routes.py`**: WebSocket route handlers
  - WebSocket endpoint definitions
  - Event dispatching and routing
  - Message distribution
  - Command processing logic
  - System event subscription handling
  - Administrative action handlers
  - Interactive shell functionality

- **`auth.py`**: WebSocket authentication
  - Token validation and verification
  - Connection authentication handlers
  - Permission verification for channels
  - MFA enforcement for privileged operations
  - Session binding and verification
  - Session regeneration handling
  - Connection security monitoring

- **`metrics.py`**: WebSocket performance monitoring
  - Connection statistics tracking
  - Message volume monitoring
  - Performance metrics collection
  - Latency measurement
  - Client usage patterns
  - Error rate tracking
  - Resource utilization monitoring

## Directory Structure

```plaintext
api/admin/ws/
├── __init__.py      # WebSocket connection management
├── README.md        # This documentation
├── routes.py        # WebSocket route handlers
├── auth.py          # Authentication and authorization
├── metrics.py       # Connection and message metrics
└── schemas.py       # Message validation schemas
```

## Message Format

All WebSocket messages follow a standardized JSON format to ensure consistent processing:

```json
{
  "event_type": "system.health",
  "channel": "admin:system",
  "data": {
    "key": "value",
    "nested": {
      "property": "value"
    }
  },
  "meta": {
    "timestamp": "2023-07-15T14:22:31Z",
    "message_id": "msg-a1b2c3d4",
    "correlation_id": "corr-e5f6g7h8"
  }
}
```

Key message properties:

- `event_type`: Type of event being communicated
- `channel`: The channel this message belongs to
- `data`: Event-specific payload
- `meta`: Metadata about the message including timestamps

## Authentication

WebSocket connections require the same level of authentication as the REST API, with additional security measures:

1. **Initial Authentication**:
   - Authentication token provided as a query parameter or in the Authorization header
   - MFA verification for privileged administrative connections
   - IP-based verification against allowed ranges

2. **Connection Binding**:
   - Each WebSocket connection is bound to a specific user session
   - Connections are terminated if the session expires or is invalidated
   - Regular re-authorization checks during long-lived connections

3. **Channel Authorization**:
   - Each subscription request is authorized against user permissions
   - Granular permission checks for each channel subscription
   - Administrative role requirements for sensitive channels

## Channel Subscription

The WebSocket API uses a channel-based subscription model:

```json
{
  "event_type": "subscribe",
  "channel": "admin:audit",
  "data": {
    "filters": {
      "severity": ["warning", "error"],
      "components": ["security", "authentication"]
    },
    "options": {
      "buffer_size": 100,
      "include_historical": false
    }
  }
}
```

Available administrative channels include:

| Channel | Description | Required Role | Purpose |
|---------|-------------|---------------|---------|
| `admin:system` | System health and metrics | Admin | Real-time system health monitoring |
| `admin:audit` | Live audit log streaming | Admin | Real-time audit event monitoring |
| `admin:security` | Security event monitoring | Admin | Real-time security alerts |
| `admin:users` | User activity stream | Admin | Monitor user login/logout and actions |
| `admin:maintenance` | Maintenance operations | SuperAdmin | Coordinate and monitor maintenance |
| `admin:interactive` | Interactive administration | SuperAdmin | Command execution with approval |

## Security Features

The WebSocket API implements comprehensive security measures:

- **Connection Limits**: Maximum concurrent connections per user and IP
- **Message Rate Limiting**: Protection against excessive message rates
- **Payload Validation**: Strict schema validation of all messages
- **Session Monitoring**: Detection of irregular usage patterns
- **Permission Enforcement**: Channel-specific authorization
- **Command Authorization**: Approval workflows for sensitive operations
- **Comprehensive Logging**: Audit trail of all administrative actions
- **Secure WebSocket Configuration**: Secure WebSocket (wss://) protocol enforcement
- **Connection Timeout**: Automatic disconnection of idle connections
- **Security Headers**: Security-focused headers on the initial HTTP connection
- **Protection Against CSRF**: Origin verification for WebSocket connections

## Usage Examples

### Connection Establishment

```javascript
// Client-side connection with authentication
const token = await getAuthToken();
const socket = new WebSocket(`wss://api.example.com/api/admin/ws?token=${token}`);

// Connection event handlers
socket.onopen = (event) => {
  console.log("Connection established");
  // Subscribe to channels after connection
  subscribeToChannels();
};

socket.onclose = (event) => {
  console.log(`Connection closed: ${event.code} - ${event.reason}`);
};

socket.onerror = (error) => {
  console.error(`WebSocket error: ${error}`);
};
```

### Channel Subscription

```javascript
// Subscribe to the system health channel
function subscribeToSystemHealth() {
  socket.send(JSON.stringify({
    event_type: "subscribe",
    channel: "admin:system",
    data: {
      components: ["cpu", "memory", "disk", "network"],
      interval: "1s"
    }
  }));
}

// Subscribe to the audit log channel
function subscribeToAuditLogs() {
  socket.send(JSON.stringify({
    event_type: "subscribe",
    channel: "admin:audit",
    data: {
      filters: {
        severity: ["warning", "error"],
        components: ["security", "authentication"]
      }
    }
  }));
}
```

### Message Handling

```javascript
// Process incoming messages
socket.onmessage = (event) => {
  const message = JSON.parse(event.data);

  switch(message.event_type) {
    case "system.health.update":
      updateSystemHealthDashboard(message.data);
      break;

    case "audit.log.entry":
      addAuditLogEntry(message.data);
      break;

    case "security.incident":
      triggerSecurityAlert(message.data);
      break;

    case "subscription.confirmation":
      console.log(`Successfully subscribed to ${message.channel}`);
      break;

    case "error":
      handleError(message.data);
      break;

    default:
      console.log(`Received message: ${message.event_type}`);
  }
};
```

### Administrative Commands

```javascript
// Execute administrative command with approval workflow
function requestSystemMaintenance(operation, parameters) {
  socket.send(JSON.stringify({
    event_type: "admin.command",
    channel: "admin:maintenance",
    data: {
      operation: operation,
      parameters: parameters,
      justification: "Emergency database maintenance",
      ticket_id: "INC-2023-0701"
    }
  }));
}

// Example: Request a database optimization
requestSystemMaintenance("database.optimize", {
  database: "metrics",
  tables: ["system_metrics", "resource_usage"],
  options: {
    vacuum: true,
    analyze: true
  }
});
```

## Error Handling

The WebSocket API provides standardized error messages:

```json
{
  "event_type": "error",
  "channel": "control",
  "data": {
    "code": "authorization_error",
    "message": "Insufficient permissions for channel admin:interactive",
    "details": {
      "required_role": "SuperAdmin",
      "current_role": "Admin"
    }
  },
  "meta": {
    "timestamp": "2023-07-15T14:25:30Z",
    "request_id": "req-a1b2c3d4e5f6"
  }
}
```

Common error codes include:

| Error Code | Description |
|------------|-------------|
| `authentication_error` | Authentication failed or token expired |
| `authorization_error` | Insufficient permissions for operation |
| `channel_error` | Channel doesn't exist or is unavailable |
| `invalid_message` | Message format or content is invalid |
| `rate_limit_exceeded` | Message rate exceeds allowed limits |
| `subscription_error` | Error in channel subscription |
| `validation_error` | Message validation failed |
| `system_error` | Internal server error |

## Metrics and Monitoring

The WebSocket API collects comprehensive metrics to monitor performance and security:

- **Connection Metrics**: Connection count, duration, disconnect reasons
- **Message Metrics**: Message volume, size, and processing time
- **Channel Metrics**: Subscription counts and message distribution
- **Performance Metrics**: Processing latency and resource utilization
- **Error Metrics**: Error rates by type and channel
- **Security Metrics**: Authentication failures and permission denials

These metrics are available through the monitoring system and in real time on the `admin:metrics` channel.

## Related Documentation

- Administrative API Reference
- WebSocket Security Guide
- Real-time Monitoring Framework
- Administrative Security Controls
- Message Schemas
- WebSocket Client Implementation
- Channel Authorization Model
- WebSocket Performance Tuning
