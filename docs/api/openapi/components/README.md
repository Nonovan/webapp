# OpenAPI Components for Cloud Infrastructure Platform

This directory contains reusable components for the OpenAPI specifications of the Cloud Infrastructure Platform APIs. These components provide standardized definitions for schemas, parameters, responses, and security schemes that are referenced across multiple API specifications.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage Guidelines
- Best Practices
- Related Documentation

## Overview

The components directory contains shared OpenAPI definitions that ensure consistency across all API specifications. By centralizing these definitions, we maintain a single source of truth for common data structures, parameters, response formats, and security schemes. This approach reduces duplication, simplifies maintenance, and ensures that API consumers have consistent experiences across all endpoints.

## Key Components

- **`parameters.yaml`**: Common API parameters used across multiple endpoints
  - Cursor-based pagination parameters
  - Filter parameters
  - Limit parameters
  - Offset-based pagination parameters
  - Range selection parameters
  - Sorting parameters

- **`requestBodies.yaml`**: Reusable request body definitions
  - Batch operation requests
  - File upload requests
  - Filtering criteria
  - Search parameters
  - Sorting criteria

- **`responses.yaml`**: Standard API response definitions
  - Error responses
  - Paginated collection responses
  - Resource creation responses
  - Status responses
  - Success responses

- **`schemas.yaml`**: Data models and type definitions
  - Alert schemas
  - Cloud resource schemas
  - Common metadata schemas
  - Error schemas
  - ICS device schemas
  - Pagination schemas
  - Security entities schemas
  - User schemas

- **`securitySchemes.yaml`**: Authentication and authorization definitions
  - API key authentication
  - Bearer token (JWT) authentication
  - OAuth 2.0 flows
  - OpenID Connect discovery

## Directory Structure

```plaintext
docs/api/openapi/components/
├── README.md            # This documentation
├── parameters.yaml      # Common API parameters
├── requestBodies.yaml   # Reusable request body definitions
├── responses.yaml       # Standard API responses
├── schemas.yaml         # Data models and schemas
└── securitySchemes.yaml # Authentication scheme definitions
```

## Usage Guidelines

### Referencing Components

In OpenAPI path definitions, reference these components using the `$ref` syntax:

```yaml
# Example path definition using shared components
paths:
  /api/resources:
    get:
      summary: List resources
      parameters:
        - $ref: '../components/parameters.yaml#/limit'
        - $ref: '../components/parameters.yaml#/offset'
      responses:
        '200':
          $ref: '../components/responses.yaml#/PaginatedResourceList'
        '400':
          $ref: '../components/responses.yaml#/BadRequest'
        '401':
          $ref: '../components/responses.yaml#/Unauthorized'
      security:
        - bearerAuth: []
```

### Adding New Components

When adding new components:

1. Place them in the appropriate YAML file based on component type
2. Use descriptive names following existing naming conventions
3. Include comprehensive descriptions for all properties
4. Document any constraints (min/max values, patterns, etc.)
5. Follow alphabetical ordering within each file
6. Include examples where appropriate

## Best Practices

- **Consistency**: Use consistent naming conventions for all components
- **Description**: Include detailed descriptions for all components
- **Documentation**: Add examples for complex schemas
- **Extensibility**: Design components to be extensible for future needs
- **Naming**: Use clear, descriptive names that indicate purpose
- **Reuse**: Look for opportunities to reuse existing components
- **Versioning**: Clearly indicate breaking changes in component evolution

## Related Documentation

- API Overview
- Authentication Documentation
- Error Handling
- [OpenAPI Specification Documentation](https://spec.openapis.org/oas/latest.html)
- Pagination Implementation
- Rate Limiting
