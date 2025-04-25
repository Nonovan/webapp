# API Metrics Module

The API Metrics module provides endpoints for collecting, querying, and exporting application and system metrics for the Cloud Infrastructure Platform. This module serves as a central metrics gateway for monitoring dashboards, alerting systems, and performance analysis tools.

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

The API Metrics module implements RESTful endpoints for retrieving various performance and health metrics from the Cloud Infrastructure Platform. It aggregates metrics from multiple sources including system resources, application performance, database operations, security events, and cloud resources to provide comprehensive monitoring capabilities.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for metrics retrieval
  - Current metrics endpoint for real-time status
  - Historical metrics with configurable time ranges
  - Metrics export in various formats (JSON, Prometheus)
  - System health summary endpoint
  - Category-specific metrics endpoints

- **`collectors.py`**: Metric collection from various system components
  - System resource metrics collection
  - Application performance metrics collection
  - Database metrics aggregation
  - Cloud resource metrics gathering
  - Security metrics compilation

- **`exporters.py`**: Metrics export functionality
  - Prometheus format conversion
  - JSON metrics structuring
  - Time-series formatters
  - Integration with monitoring systems

- **`analyzers.py`**: Metric analysis utilities
  - Anomaly detection algorithms
  - Trend analysis functions
  - Threshold evaluation
  - Performance regression detection

- **`aggregators.py`**: Metrics aggregation and calculation
  - Time-based aggregation functions
  - Statistical calculations (percentiles, averages)
  - Cross-component correlation
  - Resource utilization summaries

- **`__init__.py`**: Module initialization and configuration
  - Blueprint registration
  - Metrics caching configuration
  - Rate limiting settings
  - Authorization requirements

## Directory Structure

```plaintext
api/metrics/
├── __init__.py         # Module initialization and exports
├── README.md           # This documentation
├── routes.py           # API endpoint implementations
├── collectors.py       # Metric collection functionality
├── exporters.py        # Export format handlers
├── analyzers.py        # Analysis and anomaly detection
├── aggregators.py      # Metric aggregation functionality
└── schemas.py          # Data validation schemas
```

## API Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| metrics | GET | Get current system and application metrics | 60/minute |
| `/api/metrics/history` | GET | Get historical metrics with time ranges | 30/minute |
| `/api/metrics/export` | GET | Export metrics in various formats | 10/minute |
| `/api/metrics/health` | GET | Get system health summary | 60/minute |
| `/api/metrics/system` | GET | Get system-specific metrics | 30/minute |
| `/api/metrics/application` | GET | Get application performance metrics | 30/minute |
| `/api/metrics/database` | GET | Get database performance metrics | 30/minute |
| `/api/metrics/security` | GET | Get security-related metrics | 30/minute |
| `/api/metrics/cloud` | GET | Get cloud resource metrics | 30/minute |
| `/api/metrics/trends` | GET | Get metrics trend analysis | 20/minute |

## Configuration

The metrics system uses several configuration settings that can be adjusted in the application config:

```python
# Metrics API settings
'METRICS_CACHE_TIMEOUT': 15,          # Cache metrics for 15 seconds
'METRICS_HISTORY_RETENTION_DAYS': 30, # Keep historical metrics for 30 days
'METRICS_EXPORT_FORMATS': ['json', 'prometheus', 'csv'],
'METRICS_MAX_POINTS': 1000,           # Maximum data points to return
'METRICS_DEFAULT_INTERVAL': 'hour',   # Default aggregation interval
'METRICS_SAMPLING_RATES': {           # How often to collect each metric type
    'system': 60,                     # Every minute
    'application': 60,                # Every minute
    'database': 300,                  # Every 5 minutes
    'security': 300,                  # Every 5 minutes
    'cloud': 300                      # Every 5 minutes
},

# Rate limiting settings
'RATELIMIT_METRICS_DEFAULT': "60 per minute",
'RATELIMIT_METRICS_EXPORT': "10 per minute",
'RATELIMIT_METRICS_HISTORY': "30 per minute",
```

## Security Features

- **Authentication Required**: All endpoints require proper authentication
- **Role-Based Access Control**: Different metrics require appropriate roles
- **Rate Limiting**: Prevents excessive API usage
- **Data Sanitization**: Sensitive information is filtered from metrics
- **Caching Strategy**: Implements efficient caching to reduce load
- **Resource Protection**: Limits response size and query complexity
- **Audit Logging**: Records all metrics API access
- **Content Security Headers**: Implements proper security headers on all responses
- **Input Validation**: Validates all query parameters

## Usage Examples

### Get Current Metrics

```http
GET /api/metrics
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "timestamp": "2023-06-15T14:32:25Z",
  "system": {
    "cpu_usage": 34.2,
    "memory_usage": 68.7,
    "disk_usage": 42.5,
    "load_average": [1.25, 1.42, 1.51]
  },
  "application": {
    "request_rate": 42.3,
    "response_time_avg": 128.4,
    "error_rate": 0.12,
    "active_users": 156,
    "cache_hit_rate": 94.2
  },
  "database": {
    "query_time_avg": 3.2,
    "connections": 12,
    "active_queries": 5,
    "slow_queries_1h": 7
  },
  "security": {
    "failed_logins_24h": 23,
    "critical_events_24h": 0,
    "security_scan_status": "completed",
    "security_score": 92
  }
}
```

### Get Historical Metrics

```http
GET /api/metrics/history?metric=cpu_usage&start=2023-06-14T00:00:00Z&end=2023-06-15T00:00:00Z&interval=hour
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "metric": "cpu_usage",
  "interval": "hour",
  "unit": "percent",
  "start_time": "2023-06-14T00:00:00Z",
  "end_time": "2023-06-15T00:00:00Z",
  "data_points": [
    {"timestamp": "2023-06-14T00:00:00Z", "value": 23.4},
    {"timestamp": "2023-06-14T01:00:00Z", "value": 18.2},
    {"timestamp": "2023-06-14T02:00:00Z", "value": 15.7},
    {"timestamp": "2023-06-14T03:00:00Z", "value": 14.1},
    // ... more data points ...
    {"timestamp": "2023-06-14T23:00:00Z", "value": 32.6}
  ],
  "statistics": {
    "min": 12.3,
    "max": 78.9,
    "avg": 34.2,
    "p95": 67.8
  }
}
```

### Get System Health Summary

```http
GET /api/metrics/health
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "timestamp": "2023-06-15T14:35:12Z",
  "status": "healthy",
  "components": {
    "application": {
      "status": "healthy",
      "message": "All services operational"
    },
    "database": {
      "status": "healthy",
      "message": "Connected, optimal performance"
    },
    "storage": {
      "status": "warning",
      "message": "76% capacity used, approaching threshold"
    },
    "cache": {
      "status": "healthy",
      "message": "Operational, hit rate 92%"
    },
    "security": {
      "status": "healthy",
      "message": "No active incidents"
    }
  },
  "alerts": [
    {
      "component": "storage",
      "severity": "warning",
      "message": "Disk usage above 75% threshold"
    }
  ]
}
```

## Related Documentation

- Metrics Reference Guide
- Monitoring Architecture
- Performance Monitoring
- System Health Checks
- API Reference
- Prometheus Integration Guide
