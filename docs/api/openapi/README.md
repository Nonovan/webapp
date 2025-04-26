# OpenAPI Specifications for Cloud Infrastructure Platform

This directory contains OpenAPI (Swagger) specifications for the Cloud Infrastructure Platform APIs, providing machine-readable API documentation that can be used for code generation, API documentation rendering, and testing.

## Contents

- Overview
- Core Components
- Directory Structure
- File Formats
- Schema Organization
- Usage Guidelines
- Validation
- Version Management

## Overview

The OpenAPI specifications define the complete interface for the Cloud Infrastructure Platform's RESTful APIs. These specifications follow the OpenAPI 3.0 standard and provide detailed information about all endpoints, request parameters, response schemas, authentication requirements, and example payloads. They serve as the single source of truth for the API's contract with consumers.

## Core Components

- **`cloud-platform-api.yaml`**: Complete consolidated API specification
  - Authentication schemes
  - Common parameters
  - Error responses
  - Global security requirements
  - Server configurations
  - Version information

- **`components/`**: Reusable OpenAPI components
  - Error schemas
  - Parameter definitions
  - Request bodies
  - Response schemas
  - Schema components
  - Security schemes

- **`paths/`**: API endpoint definitions by module
  - Administrative endpoints
  - Alert management endpoints
  - Audit log endpoints
  - Cloud resource endpoints
  - ICS system endpoints
  - Security operation endpoints
  - User management endpoints
  - Webhook endpoints

## Directory Structure

```plaintext
docs/api/openapi/
├── README.md                   # This documentation
├── cloud-platform-api.yaml     # Complete API specification
├── components/                 # Reusable OpenAPI components
│   ├── parameters.yaml         # Common API parameters
│   ├── requestBodies.yaml      # Common request body schemas
│   ├── responses.yaml          # Standard API responses
│   ├── schemas.yaml            # Data models and schemas
│   └── securitySchemes.yaml    # Authentication scheme definitions
└── paths/                      # API path definitions by module
    ├── admin.yaml              # Administrative endpoints
    ├── alerts.yaml             # Alert management endpoints
    ├── auth.yaml               # Authentication endpoints
    ├── audit.yaml              # Audit log endpoints
    ├── cloud.yaml              # Cloud resource endpoints
    ├── ics.yaml                # ICS system endpoints
    ├── metrics.yaml            # Metrics endpoints
    ├── newsletter.yaml         # Newsletter subscription endpoints
    ├── security.yaml           # Security operation endpoints
    ├── users.yaml              # User management endpoints
    └── webhooks.yaml           # Webhook endpoints
```

## File Formats

The OpenAPI specifications are written in YAML format for readability and maintainability. Key formatting aspects include:

- **Consistent Indentation**: Two-space indentation for all files
- **Comments**: Descriptive comments for complex schemas and operations
- **External References**: `$ref` syntax used for common components
- **Tags**: Logical grouping of operations by domain area
- **Descriptions**: All components include detailed descriptions

## Schema Organization

The schemas follow these organizational principles:

1. **Component Reuse**: Common structures are defined in components/ and referenced
2. **Consistent Naming**: `CamelCase` for schema names, `camelCase` for properties
3. **Domain Modeling**: Schemas reflect domain models with clear relationships
4. **Inheritance**: Uses `allOf` to implement schema inheritance where appropriate
5. **Required Fields**: Clear indication of which fields are required
6. **Validation Rules**: Includes format constraints, patterns, and value ranges

## Usage Guidelines

### Generating Client SDKs

```bash
# Generate Python client
openapi-generator-cli generate -i docs/api/openapi/cloud-platform-api.yaml -g python -o clients/python

# Generate JavaScript client
openapi-generator-cli generate -i docs/api/openapi/cloud-platform-api.yaml -g javascript -o clients/javascript

# Generate Go client
openapi-generator-cli generate -i docs/api/openapi/cloud-platform-api.yaml -g go -o clients/go
```

### Rendering Documentation

```bash
# Generate HTML documentation with ReDoc
npx @redocly/cli build-docs docs/api/openapi/cloud-platform-api.yaml -o api-docs.html

# Generate HTML documentation with Swagger UI
docker run -p 8080:8080 -e SWAGGER_JSON=/api/openapi.yaml -v $(pwd)/docs/api/openapi:/api swaggerapi/swagger-ui
```

### Testing with the Specification

```bash
# Import the specification into Postman
newman run docs/api/openapi/cloud-platform-api.yaml -e environments/dev.json

# Use for contract testing
npm run api-contract-tests
```

## Validation

To ensure the specifications are valid and follow best practices:

```bash
# Validate the OpenAPI specification
npx @stoplight/spectral lint docs/api/openapi/cloud-platform-api.yaml

# Check for breaking changes between versions
npx openapi-diff previous-version.yaml cloud-platform-api.yaml
```

## Version Management

- The OpenAPI specifications follow semantic versioning aligned with the API
- Changes to the API require corresponding specification updates
- Breaking changes are documented in the changelog
- Specifications include API version in the `info.version` field
- Previous versions are archived in version control
