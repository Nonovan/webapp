# Cloud API

The Cloud API module provides RESTful endpoints for monitoring and managing cloud infrastructure resources across multiple providers. This module exposes metrics, alerts, historical data, and resource management capabilities through a consistent interface.

## Contents

- Overview
- Key Components
- Directory Structure
- API Endpoints
- Configuration
- Security Features
- Usage Examples
- Related Documentation

## Overview

The Cloud API implements RESTful endpoints for interacting with cloud resources across multiple providers (AWS, Azure, GCP). It provides a unified interface for resource provisioning, monitoring, management, and alerting through standardized endpoints with consistent security controls and response formatting.

## Key Components

- **`__init__.py`**: Module initialization and blueprint creation
  - Defines the cloud blueprint
  - Imports and registers route modules
  - Sets up shared module configuration

- **`resources.py`**: Cloud resource management endpoints
  - Resource creation, retrieval, update, and deletion
  - Resource status management (start/stop/restart)
  - Resource inventory and filtering
  - Tags and metadata management

- **`metric.py`**: Cloud metrics collection and retrieval
  - Real-time metrics for cloud resources
  - Historical metrics with configurable time ranges
  - Provider-specific metrics collection
  - Metrics aggregation and analysis

- **`alerts.py`**: Alert management for cloud resources
  - Alert configuration and threshold management
  - Alert notification delivery
  - Alert status management (acknowledge, resolve)
  - Alert history and trending

- **`operations.py`**: Cloud infrastructure operations
  - Resource scaling operations
  - Backup and snapshot management
  - Maintenance operations
  - Migration and replication tasks

- **`schemas.py`**: Data validation schemas
  - Input validation for API requests
  - Response formatting for consistency
  - Schema versioning support

- **`services.py`**: Business logic services
  - Provider-agnostic operations
  - Complex multi-step operations
  - Cross-resource coordination

## Directory Structure

```plaintext
api/cloud/
├── __init__.py         # Module initialization and blueprint creation
├── alerts.py           # Alert management for cloud resources
├── metric.py           # Cloud metrics collection and retrieval
├── operations.py       # Cloud infrastructure operations
├── README.md           # This documentation
├── resources.py        # Cloud resource management endpoints
├── schemas.py          # Data validation schemas
└── services.py         # Business logic services
```

## API Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| `/api/cloud/resources` | GET | List cloud resources | 60/minute |
| `/api/cloud/resources` | POST | Create a new cloud resource | 30/minute |
| `/api/cloud/resources/{id}` | GET | Get specific resource details | 60/minute |
| `/api/cloud/resources/{id}` | PATCH | Update resource properties | 30/minute |
| `/api/cloud/resources/{id}` | DELETE | Delete a cloud resource | 30/minute |
| `/api/cloud/resources/{id}/actions/start` | POST | Start a resource | 30/minute |
| `/api/cloud/resources/{id}/actions/stop` | POST | Stop a resource | 30/minute |
| `/api/cloud/metrics` | GET | Get current metrics | 60/minute |
| `/api/cloud/metrics/history` | GET | Get historical metrics | 30/minute |
| `/api/cloud/metrics/provider/{provider}` | GET | Get metrics for specific provider | 60/minute |
| `/api/cloud/alerts` | GET | List resource alerts | 60/minute |
| `/api/cloud/alerts` | POST | Create a new alert | 30/minute |
| `/api/cloud/alerts/{id}` | PATCH | Update alert status | 30/minute |

## Configuration

The cloud API uses several configuration settings that can be adjusted in the application config:

```python
# Cloud provider settings
'CLOUD_PROVIDERS': {
    'aws': {
        'enabled': True,
        'regions': ['us-east-1', 'us-west-2', 'eu-west-1'],
        'default_region': 'us-east-1'
    },
    'azure': {
        'enabled': True,
        'regions': ['eastus', 'westus2', 'westeurope'],
        'default_region': 'eastus'
    },
    'gcp': {
        'enabled': True,
        'regions': ['us-central1', 'us-east1', 'europe-west1'],
        'default_region': 'us-central1'
    }
},

# Resource limits
'MAX_RESOURCES_PER_USER': 50,
'RESOURCE_TYPES': ['vm', 'storage', 'database', 'network', 'container'],

# Metrics configuration
'METRICS_RETENTION_DAYS': 90,
'METRICS_DEFAULT_INTERVAL': 'hour',
'METRICS_COLLECTION_INTERVAL_MINUTES': 5,

# Rate limiting settings
'RATELIMIT_CLOUD_DEFAULT': "60 per minute",
'RATELIMIT_CLOUD_WRITE': "30 per minute"
```

## Security Features

- **Authentication**: All endpoints require JWT authentication
- **Authorization**: Resource-level permission checks
- **Rate Limiting**: Prevents API abuse with endpoint-specific limits
- **Input Validation**: Thorough validation of all input parameters
- **Audit Logging**: Comprehensive logging of all cloud operations
- **Secure Error Handling**: Prevents information leakage in error responses
- **Response Caching**: Optimized performance with cached responses where appropriate
- **Resource Isolation**: Ensures users can only access their own resources
- **Provider Credential Protection**: Secures access to cloud provider credentials

## Usage Examples

### List Cloud Resources

```http
GET /api/cloud/resources?type=vm&status=running
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "data": [
    {
      "id": 1,
      "name": "web-server-01",
      "resource_id": "i-0abc12345def67890",
      "provider_id": 1,
      "provider_name": "AWS",
      "resource_type": "vm",
      "region": "us-east-1",
      "status": "running",
      "created_at": "2023-01-15T10:30:00Z",
      "monthly_cost": 45.60
    },
    {
      "id": 3,
      "name": "app-server-01",
      "resource_id": "i-0123456789abcdef0",
      "provider_id": 1,
      "provider_name": "AWS",
      "resource_type": "vm",
      "region": "us-east-1",
      "status": "running",
      "created_at": "2023-02-10T14:15:00Z",
      "monthly_cost": 65.20
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 1,
    "total_items": 2
  }
}
```

### Create a New VM Resource

```http
POST /api/cloud/resources
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "name": "new-database",
  "provider_id": 1,
  "resource_type": "database",
  "region": "us-west-2",
  "config": {
    "instance_type": "db.t3.medium",
    "engine": "postgres",
    "storage_gb": 100
  },
  "tags": {
    "environment": "production",
    "project": "customer-portal"
  }
}
```

Response:

```json
{
  "id": 42,
  "name": "new-database",
  "resource_id": "db-abc123def456",
  "provider_id": 1,
  "provider_name": "AWS",
  "resource_type": "database",
  "region": "us-west-2",
  "status": "provisioning",
  "created_at": "2023-06-15T14:22:33Z",
  "tags": {
    "environment": "production",
    "project": "customer-portal"
  }
}
```

### Get Current Metrics

```http
GET /api/cloud/metrics?resource_id=42
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "timestamp": "2023-06-15T14:32:25Z",
  "resource_id": 42,
  "metrics": {
    "cpu_usage": 34.2,
    "memory_usage": 68.7,
    "disk_usage": 42.5,
    "connections": 28,
    "iops": 124.5,
    "network_in": 5.2,
    "network_out": 3.4
  }
}
```

## Related Documentation

- Cloud Provider Integration
- Resource Monitoring
- Alert Configuration
- API Reference
- Security Best Practices
- Cloud Resource Models
