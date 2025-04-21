# Core Monitoring Components

This directory contains the core monitoring functionality and reusable components for the Cloud Infrastructure Platform.

## Overview

The core monitoring components provide the foundational functionality for the platform's monitoring system, including health checks, metric collection, and status reporting. These components are designed to be robust, secure, and maintainable, with comprehensive error handling and reporting capabilities.

## Key Scripts

- `health-check.sh` - Comprehensive system health verification with component status tracking
- `api_latency.sh` - Enhanced API performance monitoring with circuit breakers and exponential backoff
- `connectivity_check.sh` - Network connectivity verification with detailed diagnostics
- `resource_monitor.sh` - System resource utilization monitoring with threshold alerts
- `status_reporter.sh` - Aggregates monitoring data into comprehensive reports with multiple output formats
- `metric_collector.sh` - Collects and processes system and application metrics with secure execution

## Features

### Health Checks

The health check system verifies the status of critical components:

- API endpoint availability and response validation
- Database connectivity and replication status
- Memory and disk usage with configurable thresholds
- SSL certificate validity and expiration tracking
- Service status with dependency mapping
- Security updates and vulnerability detection
- Log analysis for errors with pattern recognition
- DR-specific component validation

### Performance Monitoring

Core performance monitoring capabilities include:

- API response time measurement with percentile calculations (P95, P99)
- Resource utilization tracking with historical trending
- Database query performance and connection pool analysis
- Network latency and reliability with packet loss detection
- Circuit breaker pattern implementation for fault tolerance
- Exponential backoff for retries to prevent cascading failures
- Connection pooling for improved reliability and performance

### Status Reporting

Status reports provide insights into:

- Overall system health with visual indicators
- Component-specific status with severity classification
- Historical performance trends with configurable time ranges
- Detected issues and actionable recommendations
- Multiple output formats (HTML, JSON, text) for different consumers
- Email notifications with severity-based prioritization
- DR event tracking and monitoring

## Integration Points

- Integrates with Prometheus for metrics storage and alerting
- Works with ELK stack for log aggregation and analysis
- Connects with alert system for notification dispatch
- Exports data to Grafana for visualization
- Support for multiple environments (production, staging, development)
- Region-specific monitoring (primary and secondary/DR)

## Enhanced Security Features

- Input validation and sanitization for all script parameters
- Safe command execution without eval
- Timeout management for external processes
- Proper error handling and secure output formatting
- API authentication token management
- Circuit breaker implementation to prevent cascading failures

## Usage Examples

```bash
# Run comprehensive health check
./health-check.sh production --region primary --format json --notify admin@example.com

# Monitor API latency with advanced options
./api_latency.sh production --endpoints /api/v1/status,/api/v1/users --interval 30 --auth-key $TOKEN

# Check connectivity to all services with circuit breaker support
./connectivity_check.sh --region primary --timeout 5 --circuit-breaker-enabled --verify-ssl

# Monitor system resources with threshold alerting
./resource_monitor.sh --critical-services web,database,cache --cpu-threshold 80 --memory-threshold 85

# Generate comprehensive status report
./status_reporter.sh production --format html --components all --output /var/www/reports/status.html --notify --history 14
```

## Recommended Practices

- Schedule regular health checks using cron or systemd timers
- Integrate status reporting with your incident management system
- Configure notifications for critical components
- Set appropriate thresholds based on system capacity and requirements
- Regularly review historical data to identify trends
- Use DR-mode for validating disaster recovery capabilities

## Related Documentation

- [Monitoring Architecture](../../../docs/operations/monitoring-guide.md)
- [Health Check Procedures](../../../docs/operations/health-checks.md)
- [API Performance Tuning](../../../docs/operations/api-performance.md)
- [DR Testing Procedures](../../../docs/operations/dr-testing.md)
- [Security Monitoring](../../../docs/security/monitoring.md)
