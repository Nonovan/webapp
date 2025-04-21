# Core Monitoring Components

This directory contains the core monitoring functionality and reusable components for the Cloud Infrastructure Platform.

## Overview

The core monitoring components provide the foundational functionality for the platform's monitoring system, including health checks, metric collection, and status reporting.

## Key Scripts

- `health-check.sh` - Comprehensive system health verification
- `api_latency.sh` - API performance monitoring and latency measurements
- `connectivity_check.sh` - Network connectivity verification for all services
- `resource_monitor.sh` - System resource utilization monitoring
- `status_reporter.sh` - Aggregates monitoring data into comprehensive reports
- `metric_collector.sh` - Collects and processes system and application metrics

## Features

### Health Checks

The health check system verifies the status of critical components:

- API endpoint availability
- Database connectivity
- Memory and disk usage
- SSL certificate validity
- Service status
- Security updates
- Log analysis for errors

### Performance Monitoring

Core performance monitoring capabilities include:

- API response time measurement
- Resource utilization tracking
- Database query performance
- Network latency and reliability

### Status Reporting

Status reports provide insights into:

- Overall system health
- Component-specific status
- Historical performance trends
- Detected issues and recommendations

## Integration Points

- Integrates with Prometheus for metrics storage
- Works with ELK stack for log aggregation
- Connects with alert system for notification dispatch
- Exports data to Grafana for visualization

## Usage Examples

```bash
# Run comprehensive health check
./health-check.sh production

# Monitor API latency
./api_latency.sh --endpoints /api/v1/status,/api/v1/users --interval 30

# Check connectivity to all services
./connectivity_check.sh --region primary --timeout 5

# Monitor system resources
./resource_monitor.sh --critical-services web,database,cache
```

## Related Documentation

- [Monitoring Architecture](../../../docs/operations/monitoring-guide.md)
- [Health Check Procedures](../../../docs/operations/health-checks.md)
