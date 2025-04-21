# Monitoring Test Scripts

This directory contains test scripts for monitoring functionality of the Cloud Infrastructure Platform.

## Overview

These test scripts validate the monitoring systems, verify health checks, and ensure that alerts and notifications work correctly across different environments.

## Key Test Scripts

- `smoke-test.sh` - Quick verification of core monitoring functionality
- `performance-test.sh` - Load testing and performance benchmarking
- `alert-test.sh` - Tests alert generation and notification delivery
- `connectivity-test.sh` - Tests connectivity to monitored services
- `integration-test.sh` - Tests integration with external monitoring systems
- `security-test.sh` - Tests security monitoring features
- `metric-validation.sh` - Validates metric collection accuracy
- `dashboard-test.sh` - Tests dashboard functionality

## Test Categories

### Smoke Tests

Quick tests that verify basic functionality:

- Core health check validation
- Basic metric collection
- Simple connectivity checks
- Alert system availability

### Performance Tests

Tests for system performance under load:

- API response time under load
- Resource utilization monitoring
- Concurrent connection handling
- System recovery after load

### Integration Tests

Tests for integration with external systems:

- Prometheus integration
- Elasticsearch log ingestion
- AlertManager notification delivery
- Grafana dashboard rendering

## Usage Examples

```bash
# Run basic smoke test in production
./smoke-test.sh production

# Run performance test with custom user load
./performance-test.sh production --users 100 --duration 300

# Test alert generation and delivery
./alert-test.sh --trigger cpu --threshold 90 --environment staging

# Test connectivity to all monitored services
./connectivity-test.sh --environment production --region primary
```

## Test Reports

Test scripts generate structured reports in various formats:

- JSON format for programmatic consumption
- HTML format for human readability
- CSV format for data analysis
- Grafana-compatible metrics for visualization

## Best Practices

- Run smoke tests after any monitoring configuration change
- Schedule regular automated test runs
- Test in lower environments before testing in production
- Document test failures and resolutions

## Related Documentation

- [Testing Methodology](../../../docs/operations/testing-methodology.md)
- [Monitoring Architecture](../../../docs/operations/monitoring-guide.md)
- [Troubleshooting Guide](../../../docs/operations/troubleshooting.md)
