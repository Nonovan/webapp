# SDK Documentation for Cloud Infrastructure Platform

This directory contains documentation for the official SDK libraries that facilitate integration with the Cloud Infrastructure Platform API across multiple programming languages and environments.

## Contents

- Overview
- Available SDKs
- Directory Structure
- Common Features
- Authentication & Security
- Installation
- Rate Limiting
- Request & Response Formats
- Usage Examples
- Related Documentation

## Overview

The SDK libraries provide language-specific implementations for interacting with the Cloud Infrastructure Platform API. They abstract away the complexity of direct HTTP calls, authentication, error handling, and response parsing while providing a consistent and idiomatic experience in each supported language. These libraries are regularly updated to maintain compatibility with the latest API features and security requirements.

## Available SDKs

The Cloud Infrastructure Platform provides the following officially supported SDK libraries:

- **Go SDK**: For Go applications with proper error handling and concurrency support
- **JavaScript SDK**: For browser and Node.js applications with Promise-based API
- **Python SDK**: For Python applications with both synchronous and asynchronous APIs

## Directory Structure

```plaintext
docs/api/sdks/
├── README.md          # This documentation
├── go.md              # Go SDK documentation
├── javascript.md      # JavaScript SDK documentation
└── python.md          # Python SDK documentation
```

## Common Features

All SDK libraries provide these core features:

- **Authentication Handling**: Automated token management with refresh capability
- **Error Handling**: Standardized error objects with detailed context
- **Pagination Support**: Helper methods for traversing paginated results
- **Rate Limit Handling**: Automatic retry with configurable backoff strategies
- **Request Logging**: Configurable request and response logging
- **Resource Management**: Object-oriented interfaces for API resources
- **Type Safety**: Language-appropriate typing for requests and responses
- **Webhook Validation**: Utilities to validate incoming webhook payloads

## Authentication & Security

The SDKs implement secure authentication practices:

```python
# Python example - authenticating with the SDK
from cloud_platform import Client

# Create a client with API key authentication
client = Client(api_key="YOUR_API_KEY")

# Or authenticate with username/password
client = Client(username="user@example.com", password="secure_password")

# Accessing authenticated resources
user = client.users.get_current()
```

```javascript
// JavaScript example - authenticating with the SDK
import { Client } from 'cloud-platform-js';

// Create a client with API key authentication
const client = new Client({ apiKey: 'YOUR_API_KEY' });

// Or authenticate with username/password
const client = new Client({
  username: 'user@example.com',
  password: 'secure_password'
});

// Accessing authenticated resources
const user = await client.users.getCurrent();
```

```go
// Go example - authenticating with the SDK
import "github.com/organization/cloud-platform-go"

// Create a client with API key authentication
client, err := cloudplatform.NewClient(cloudplatform.WithAPIKey("YOUR_API_KEY"))
if err != nil {
    // Handle error
}

// Or authenticate with username/password
client, err := cloudplatform.NewClient(
    cloudplatform.WithCredentials("user@example.com", "secure_password"),
)

// Accessing authenticated resources
user, err := client.Users.GetCurrent(ctx)
```

## Installation

### Go

```bash
go get github.com/organization/cloud-platform-go
```

### JavaScript

```bash
# Using npm
npm install cloud-platform-js

# Using yarn
yarn add cloud-platform-js
```

### Python

```bash
# Using pip
pip install cloud-platform-client

# Using poetry
poetry add cloud-platform-client
```

## Rate Limiting

The SDKs implement automatic handling of API rate limits:

- **Backoff Strategies**: Exponential and configurable backoff on 429 responses
- **Rate Monitoring**: Tracking of remaining quota from response headers
- **Request Batching**: Methods to optimize multiple related requests
- **Retry Policies**: Configurable retry policies with customizable conditions

Example configuration:

```python
# Python rate limit configuration
from cloud_platform import Client, RetryPolicy

client = Client(
    api_key="YOUR_API_KEY",
    retry_policy=RetryPolicy(
        max_retries=3,
        backoff_factor=1.5,
        retry_status_codes=[429, 500, 502, 503, 504]
    )
)
```

## Request & Response Formats

All SDKs provide consistent patterns for making requests and handling responses:

- **Request Options**: Standardized method to specify query parameters and headers
- **Response Objects**: Strongly-typed response objects with consistent access patterns
- **Error Objects**: Structured error information with HTTP status and API error codes
- **Collection Pagination**: Unified approach to paginating through collections

## Usage Examples

### Working with Cloud Resources

```python
# Python - Managing cloud resources
resources = client.cloud.resources.list(limit=10)
for resource in resources:
    print(f"Resource: {resource.name}, Status: {resource.status}")

# Creating a new resource
new_resource = client.cloud.resources.create(
    name="web-server-01",
    type="vm",
    configuration={
        "cpu": 2,
        "memory": "4GB",
        "disk": "100GB"
    }
)
```

### Handling Alerts

```javascript
// JavaScript - Working with alerts
// List all active alerts
const alerts = await client.alerts.list({ status: 'active' });

// Acknowledge an alert
await client.alerts.acknowledge(alertId, {
  comment: 'Investigating the issue'
});

// Resolve an alert
await client.alerts.resolve(alertId, {
  resolution: 'Applied security patch',
  rootCause: 'Outdated software component'
});
```

### Webhook Integration

```go
// Go - Validating a webhook
import (
    "net/http"
    "github.com/organization/cloud-platform-go/webhook"
)

func webhookHandler(w http.ResponseWriter, r *http.Request) {
    payload, err := webhook.ValidateRequest(r, "webhook_secret")
    if err != nil {
        http.Error(w, "Invalid webhook signature", http.StatusBadRequest)
        return
    }

    // Process validated webhook payload
    switch payload.Event {
    case "alert.created":
        // Handle alert creation
    case "resource.updated":
        // Handle resource update
    }

    w.WriteHeader(http.StatusOK)
}
```

## Related Documentation

- API Overview
- Authentication
- Common API Components
- Error Handling
- Getting Started Guide
- Pagination
- Rate Limiting
- OpenAPI Specification
- Security Best Practices
- Webhook Integration
