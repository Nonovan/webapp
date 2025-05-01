# API Metrics Module

The API Metrics module provides endpoints for collecting, querying, and exporting application and system metrics for the Cloud Infrastructure Platform. This module serves as a central metrics gateway for monitoring dashboards, alerting systems, and performance analysis tools.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Integration Points](#integration-points)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

## Overview

The API Metrics module implements RESTful endpoints following security best practices including strict authentication, role-based access control, rate limiting, and comprehensive logging. It aggregates metrics from multiple sources including system resources, application performance, database operations, security events, and cloud resources to provide comprehensive monitoring capabilities with support for real-time and historical data views.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for metrics retrieval
  - Current metrics endpoint for real-time status
  - Historical metrics with configurable time ranges
  - Metrics export in various formats (JSON, Prometheus, CSV)
  - System health summary endpoint
  - Category-specific metrics endpoints
  - Trend analysis and forecasting capabilities

- **`collectors.py`**: Metric collection from various system components
  - System resource metrics collection (CPU, memory, disk, network)
  - Application performance metrics collection
  - Database metrics aggregation and query performance
  - Cloud resource metrics gathering across providers
  - Security metrics compilation with compliance focus
  - Container and service metrics collection
  - ICS system telemetry integration

- **`exporters.py`**: Metrics export functionality
  - Prometheus exposition format conversion
  - JSON metrics structuring with schema enforcement
  - Time-series formatters for visualization
  - CSV export with proper escaping
  - Integration with monitoring systems
  - Customizable output filtering
  - Streaming support for large datasets

- **`analyzers.py`**: Metric analysis utilities
  - Anomaly detection algorithms
  - Trend analysis functions
  - Threshold evaluation with smart alerting
  - Performance regression detection
  - Seasonal pattern recognition
  - Forecasting capabilities
  - Correlation between metrics

- **`aggregators.py`**: Metrics aggregation and calculation
  - Time-based aggregation functions
  - Statistical calculations (percentiles, averages, standard deviation)
  - Cross-component correlation
  - Resource utilization summaries
  - Downsampling for historical data
  - Customizable aggregation windows

- **`__init__.py`**: Module initialization and configuration
  - Blueprint registration with proper routes
  - Metrics caching configuration
  - Rate limiting settings with fine-grained control
  - Authorization requirements and permission mapping
  - Security headers and monitoring setup

## Directory Structure

```plaintext
api/metrics/
├── __init__.py         # Module initialization and exports
├── README.md           # This documentation
├── routes.py           # API endpoint implementations
├── collectors.py       # Metric collection functionality
├── exporters.py        # Export format handlers
├── analyzers.py        # Analysis and anomaly detection
└── aggregators.py      # Metric aggregation functionality
```

## API Endpoints

| Endpoint | Method | Description | Access Level | Rate Limit |
|----------|--------|-------------|--------------|------------|
| metrics | GET | Get current system and application metrics | `metrics:view` | 60/minute |
| `/api/metrics/history` | GET | Get historical metrics with time ranges | `metrics:history` | 30/minute |
| `/api/metrics/export` | GET | Export metrics in various formats | `metrics:export` | 10/minute |
| `/api/metrics/health` | GET | Get system health summary | `metrics:health` | 60/minute |
| `/api/metrics/system` | GET | Get system-specific metrics | `metrics:system` | 30/minute |
| `/api/metrics/application` | GET | Get application performance metrics | `metrics:application` | 30/minute |
| `/api/metrics/database` | GET | Get database performance metrics | `metrics:database` | 30/minute |
| `/api/metrics/security` | GET | Get security-related metrics | `metrics:security` | 30/minute |
| `/api/metrics/cloud` | GET | Get cloud resource metrics | `metrics:cloud` | 30/minute |
| `/api/metrics/trends` | GET | Get metrics trend analysis | `metrics:trends` | 20/minute |

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
'METRICS_ANOMALY_DETECTION_ENABLED': True,  # Enable anomaly detection
'METRICS_FORECAST_PERIODS': 12,       # Number of periods for forecasting
'METRICS_HEALTH_CACHE_TIMEOUT': 30,   # Health summary cache duration
'METRICS_RETENTION_POLICY': {         # Data retention settings
    'high_resolution': '7d',          # Keep detailed data for 7 days
    'hourly': '30d',                  # Keep hourly aggregates for 30 days
    'daily': '365d'                   # Keep daily aggregates for 365 days
},

# Rate limiting settings
'RATELIMIT_METRICS_DEFAULT': "60 per minute",
'RATELIMIT_METRICS_EXPORT': "10 per minute",
'RATELIMIT_METRICS_HISTORY': "30 per minute",

# Security settings
'METRICS_SENSITIVE_FIELDS': ['auth_token', 'password', 'secret'],  # Fields to redact
'METRICS_REQUIRE_HTTPS': True,        # Require HTTPS for metrics endpoints
'METRICS_ADMIN_ROLE': 'admin',        # Role for full metrics access
```

## Security Features

- **Authentication Required**: All endpoints require proper authentication using token-based verification
- **Role-Based Access Control**: Different metrics require appropriate roles for access control
- **Rate Limiting**: Prevents excessive API usage with endpoint-specific limits
- **Data Sanitization**: Sensitive information is filtered from metrics before transmission
- **Caching Strategy**: Implements efficient caching to reduce load and prevent DoS
- **Resource Protection**: Limits response size and query complexity to prevent resource exhaustion
- **Audit Logging**: Records all metrics API access for security monitoring
- **Content Security Headers**: Implements proper security headers on all responses
- **Input Validation**: Validates all query parameters with strict schema enforcement
- **HTTPS Enforcement**: Requires secure connections for all metrics operations
- **Circuit Breakers**: Prevents cascading failures during system stress
- **Metrics Segregation**: Multi-tenant environments have isolated metrics
- **Permission Verification**: Uses centralized permission system for consistent controls

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

### Export Metrics in Prometheus Format

```http
GET /api/metrics/export?format=prometheus
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```plaintext
# HELP app_cpu_usage Current CPU utilization percentage
# TYPE app_cpu_usage gauge
app_cpu_usage{instance="app-server-01",environment="production"} 34.2 1623767545000

# HELP app_memory_usage Memory utilization percentage
# TYPE app_memory_usage gauge
app_memory_usage{instance="app-server-01",environment="production"} 68.7 1623767545000

# HELP app_disk_usage Disk utilization percentage
# TYPE app_disk_usage gauge
app_disk_usage{instance="app-server-01",environment="production"} 42.5 1623767545000
```

### Export Metrics in CSV Format

```http
GET /api/metrics/export?format=csv
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```csv
Category,Metric,Value,Unit
Metadata,timestamp,2023-06-15T14:32:25Z,
system,cpu_usage,34.2,%
system,memory_usage,68.7,%
system,disk_usage,42.5,%
application,request_rate,42.3,count
application,response_time_avg,128.4,ms
application,error_rate,0.12,%
database,query_time_avg,3.2,ms
database,connections,12,count
security,failed_logins_24h,23,count
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

### Get Metric Trends with Forecast

```http
GET /api/metrics/trends?metric=memory_usage&period=7d&forecast=true
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "metric": "memory_usage",
  "period": "7d",
  "trends": {
    "direction": "increasing",
    "rate_of_change": 1.2,
    "volatility": "low",
    "peak_time": "14:00",
    "low_time": "03:00",
    "weekly_pattern": "weekday_heavy"
  },
  "forecast": {
    "next_24h": [
      {"timestamp": "2023-06-16T00:00:00Z", "value": 72.1, "confidence": 0.95},
      {"timestamp": "2023-06-16T04:00:00Z", "value": 65.3, "confidence": 0.93},
      {"timestamp": "2023-06-16T08:00:00Z", "value": 70.2, "confidence": 0.91},
      {"timestamp": "2023-06-16T12:00:00Z", "value": 78.4, "confidence": 0.89},
      {"timestamp": "2023-06-16T16:00:00Z", "value": 77.1, "confidence": 0.87},
      {"timestamp": "2023-06-16T20:00:00Z", "value": 74.5, "confidence": 0.85}
    ],
    "prediction": "Expected to reach 80% within 3 days"
  }
}
```

## Implementation Details

### Exporters

The exporters.py module provides the following functionality:

- **Prometheus Export**: Converts metrics to the Prometheus exposition format with proper metadata

  ```python
  export_metrics_prometheus(metrics_data, prefix='app_')
  ```

- **CSV Export**: Converts metrics to CSV format with categories, names, values, and units

  ```python
  export_metrics_csv(metrics_data)
  ```

- **JSON Export**: Formats metrics as structured JSON with optional metadata enrichment

  ```python
  export_metrics_json(metrics_data, include_metadata=True)
  ```

### Aggregators

The `aggregators.py` module provides time series data processing:

- **Time Series Aggregation**: Groups metrics into consistent intervals

  ```python
  aggregate_time_series(data_points, interval='hour', aggregation_method='avg')
  ```

- **Percentile Calculation**: Statistical analysis for performance metrics

  ```python
  calculate_percentiles(data_points, percentiles=[50, 90, 95, 99])
  ```

- **Time Series Resampling**: Handles data gaps and normalization

  ```python
  resample_time_series(data_points, interval='hour', start_time=start, end_time=end)
  ```

### Analyzers

The `analyzers.py` module provides advanced analytics:

- **Anomaly Detection**: Identifies unusual patterns in metrics data

  ```python
  detect_anomalies(metric_name, data_points, sensitivity='medium')
  ```

- **Trend Analysis**: Determines directional patterns in metrics

  ```python
  analyze_trends(metric_name, period='7d')
  ```

- **Statistics Calculation**: Comprehensive statistical measures

  ```python
  calculate_statistics(data_points)
  ```

- **Metric Forecasting**: Predicts future metric values

  ```python
  forecast_metrics(metric_name, trend_data)
  ```

## Integration Points

The Metrics API integrates with several other system components:

1. **Monitoring Systems**: Provides metrics in formats compatible with Prometheus, Grafana, and other monitoring tools

2. **Alerting System**: Feeds metrics to the alerting system for notification generation based on thresholds

3. **Security Module**: Provides security-related metrics and receives information about suspicious activity

4. **Dashboard Services**: Powers operational dashboards with real-time and historical metrics

5. **Cloud Services**: Collects metrics from multiple cloud providers through standardized interfaces

6. **ICS Systems**: Gathers telemetry from industrial control systems when available

7. **Incident Management**: Provides context for security and operational incidents

8. **Audit System**: Exports compliance-related metrics for audit reporting

## Best Practices

When working with the Metrics API:

1. **Efficient Querying**: Limit time ranges and specify only the metrics you need
   - Use appropriate intervals for historical data
   - Filter metrics by category when possible
   - Paginate large result sets

2. **Cache Utilization**: Leverage client-side caching for dashboard displays
   - Set realistic poll frequencies for real-time data
   - Use ETag headers for conditional requests
   - Implement staggered refresh patterns for multiple metrics

3. **Rate Limit Awareness**: Design applications to respect rate limits
   - Implement exponential backoff for retries
   - Combine requests where possible
   - Process metrics in batches rather than individually

4. **Security Considerations**: Follow security best practices
   - Store API tokens securely
   - Request only metrics your application needs
   - Validate and sanitize any metrics before displaying

5. **Error Handling**: Implement robust error handling
   - Handle HTTP 429 (Too Many Requests) gracefully
   - Degrade gracefully when metrics are unavailable
   - Log and report metrics access failures

## Related Documentation

- Metrics Reference Guide
- Monitoring Architecture
- Performance Monitoring
- System Health Checks
- API Reference
- Prometheus Integration Guide
- Alerting Configuration
- Dashboard Development
- File Integrity Monitoring Guide
