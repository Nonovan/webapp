# Monitoring Configuration

This directory contains configuration files for monitoring tools and services used by the Cloud Infrastructure Platform.

## Overview

These configuration files define how monitoring tools should operate, including thresholds, intervals, and connection details for different environments.

## Configuration Files

- `defaults.conf` - Base configuration values used across all environments
- `prometheus.yml` - Configuration for Prometheus metrics collection
- `grafana-dashboards.json` - Grafana dashboard definitions
- `alerts.conf` - Alert thresholds and notification settings
- `logging-rules.json` - Rules for log processing and analysis
- `monitoring-targets.json` - List of services and endpoints to monitor
- `metrics-collection.conf` - Settings for metrics collection frequency
- `healthcheck.conf` - Health check definitions and expected responses

## Environment-Specific Configurations

Each environment (development, staging, production) has specific overrides:

- `development.conf` - Development environment settings
- `staging.conf` - Staging environment settings
- `production.conf` - Production environment settings
- `dr.conf` - Disaster recovery environment settings

## Usage

Configuration files are loaded by monitoring scripts based on the environment:

```bash
# Example: Load production monitoring configuration
./metrics_collector.sh --config config/production.conf

# Example: Run with default configuration
./health_checker.sh --defaults
```

## Configuration Structure

Each configuration file follows a consistent format:

```ini
[Service]
# Service-specific settings
endpoint=https://api.example.com/status
interval=60
timeout=10

[Alerts]
# Alert thresholds
cpu_warning=80
cpu_critical=95
memory_warning=85
```

## Modifying Configurations

When modifying configuration files:

1. Document changes with comments
2. Test in development/staging before production
3. For critical services, ensure alert thresholds are appropriate
4. Maintain backward compatibility when possible

## Related Documentation

- [Monitoring Architecture](../../../docs/operations/monitoring-guide.md)
- [Configuration Management](../../../docs/operations/configuration.md)
