# OpenAPI Path Definitions for Cloud Infrastructure Platform

This directory contains OpenAPI (Swagger) path definitions for all API endpoints in the Cloud Infrastructure Platform, organized by functional area.

## Contents

- Overview
- Key Components
- Directory Structure
- Path Structure
- Usage Guidelines
- Best Practices
- Related Documentation

## Overview

The paths directory contains individual YAML files that define the API endpoints for the Cloud Infrastructure Platform. Each file focuses on a specific functional area and defines the paths, operations, parameters, request bodies, and responses for that area's endpoints. These definitions leverage reusable components from the components directory to ensure consistency across the API while maintaining a modular structure that is easy to maintain and extend.

## Key Components

- **`admin.yaml`**: Administrative API endpoints
  - System configuration management
  - User administration operations
  - Role and permission management
  - System health monitoring
  - Audit log access

- **`alerts.yaml`**: Alert management endpoints
  - Alert listing and filtering
  - Alert creation and notification
  - Alert status management
  - Alert acknowledgment and resolution
  - Alert comment operations

- **`auth.yaml`**: Authentication endpoints
  - User authentication and token issuance
  - Multi-factor authentication setup
  - Password reset operations
  - Session management
  - Token verification and refresh

- **`audit.yaml`**: Audit logging endpoints
  - Audit log querying and filtering
  - Compliance report generation
  - Security event analysis
  - Export capabilities
  - Dashboard data aggregation

- **`cloud.yaml`**: Cloud resource endpoints
  - Resource provisioning and management
  - Resource metrics collection
  - Cloud provider operations
  - Resource configuration
  - Resource status monitoring

- **`ics.yaml`**: Industrial control system endpoints
  - Device management and monitoring
  - Sensor reading operations
  - Control operations
  - Historical data retrieval
  - Status monitoring

- **`metrics.yaml`**: Metrics collection endpoints
  - System metrics retrieval
  - Application metrics collection
  - Metrics aggregation
  - Health check operations
  - Export capabilities

- **`newsletter.yaml`**: Newsletter subscription endpoints
  - Subscription management
  - Email preference settings
  - Subscription confirmation
  - Unsubscribe operations

- **`security.yaml`**: Security operation endpoints
  - Security incident management
  - Vulnerability tracking
  - Security scanning operations
  - Threat detection
  - Security policy management

- **`users.yaml`**: User management endpoints
  - User profile operations
  - User permission operations
  - User preference management
  - User session management

- **`webhooks.yaml`**: Webhook management endpoints
  - Webhook subscription creation
  - Event type subscription management
  - Delivery tracking
  - Test operations

## Directory Structure

```plaintext
docs/api/openapi/paths/
├── README.md           # This documentation
├── admin.yaml          # Administrative endpoints
├── alerts.yaml         # Alert management endpoints
├── audit.yaml          # Audit logging endpoints
├── auth.yaml           # Authentication endpoints
├── cloud.yaml          # Cloud resource endpoints
├── ics.yaml            # Industrial control system endpoints
├── metrics.yaml        # Metrics collection endpoints
├── newsletter.yaml     # Newsletter subscription endpoints
├── security.yaml       # Security operation endpoints
├── users.yaml          # User management endpoints
└── webhooks.yaml       # Webhook management endpoints
```

## Path Structure

Each path file follows a consistent structure:

```yaml
# Path definitions for specific functional area
paths:
  /api/{resource}:
    get:
      summary: List resources
      description: Detailed description of the operation
      operationId: listResources
      parameters:
        - $ref: '../components/parameters.yaml#/limit'
        - $ref: '../components/parameters.yaml#/offset'
      responses:
        '200':
          $ref: '../components/responses.yaml#/PaginatedResourceList'
        '400':
          $ref: '../components/responses.yaml#/BadRequest'
      security:
        - bearerAuth: []
      tags:
        - ResourceGroup

    post:
      summary: Create a new resource
      # ... similar structure

  /api/{resource}/{id}:
    get:
      # ... endpoint for single resource
```

## Usage Guidelines

### Integration with Main API Specification

These path files are referenced from the main OpenAPI specification file:

```yaml
# In cloud-platform-api.yaml
paths:
  # Admin paths
  $ref: './paths/admin.yaml#/paths'

  # Alert paths
  $ref: './paths/alerts.yaml#/paths'

  # And so on...
```

### Adding New Endpoints

When adding a new endpoint:

1. Place it in the appropriate path file based on functional area
2. Follow the established naming conventions and structure
3. Reference common components for parameters, responses, and schemas
4. Include comprehensive descriptions and examples
5. Document all possible status codes and error scenarios
6. Follow alphabetical ordering for path segments

## Best Practices

- **Consistent Naming**: Use consistent naming conventions for path segments, parameters, and operation IDs
- **Complete Documentation**: Include detailed descriptions for all operations, parameters, and responses
- **Examples**: Provide meaningful examples for request bodies and responses
- **Error Documentation**: Document all possible error conditions and responses
- **Logical Organization**: Group related endpoints under common path prefixes
- **Parameter Reuse**: Reference common parameters from the components directory
- **Response Reuse**: Use standardized response definitions where possible
- **Security Definitions**: Always include appropriate security requirements
- **Tagging**: Use consistent tags to group related operations

## Related Documentation

- API Overview
- Authentication Documentation
- OpenAPI Components
- Error Handling
- Pagination Implementation
- Rate Limiting
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html)
