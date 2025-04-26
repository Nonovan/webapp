# Security Monitoring Baseline Configurations

This directory contains security baseline configurations for different environments within the Cloud Infrastructure Platform. These baselines define normal behavior patterns, thresholds for alerts, and expected security metrics that are used by security monitoring tools for anomaly detection and security event analysis.

## Contents

- Overview
- Key Components
- Directory Structure
- Baseline Structure
- Usage
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The security monitoring baselines provide environment-specific definitions of normal behavior patterns across the platform. They establish reference points for anomaly detection, allowing security monitoring tools to identify deviations that may indicate security threats or incidents. Each baseline file contains thresholds and parameters tailored to its environment, reflecting the different security requirements and operational characteristics of development, staging, and production environments.

## Key Components

- **Authentication Baselines**: Normal patterns for authentication activities
  - Failed login thresholds
  - Brute force detection parameters
  - Expected session durations
  - Authentication time deviation limits
  - Location change alert settings

- **API Usage Patterns**: Expected API usage metrics and thresholds
  - API call frequency by endpoint
  - Expected request patterns
  - Rate limiting thresholds
  - Normal error rate ranges
  - Authentication failure thresholds

- **Access Patterns**: Normal user and system access behavior
  - Admin access frequency metrics
  - Data access volume expectations
  - Sensitive resource access patterns
  - Service account activity baselines
  - User access time patterns

- **System Activity Metrics**: Normal system operation parameters
  - CPU utilization ranges
  - Network traffic patterns
  - Database activity thresholds
  - File system activity metrics
  - Memory usage expectations

## Directory Structure

```plaintext
admin/security/monitoring/config/baseline/
├── README.md           # This documentation
├── development.json    # Development environment baseline
├── production.json     # Production environment baseline
└── staging.json        # Staging environment baseline
```

## Baseline Structure

Each baseline file follows a standardized JSON format with environment-specific values:

```json
{
  "metadata": {
    "version": "2.3.0",
    "last_updated": "2024-03-15",
    "environment": "production",
    "description": "Security baseline for production environment"
  },
  "authentication": {
    "failed_login_threshold": 5,
    "brute_force_time_window": 300,
    "session_duration_avg": 28800,
    "auth_time_deviation_threshold": 7200,
    "location_change_alert": true
  },
  "system_activity": {
    "cpu_baseline": {
      "web_servers": {"normal_range": [10, 50], "alert_threshold": 85},
      "database_servers": {"normal_range": [20, 60], "alert_threshold": 90},
      "api_servers": {"normal_range": [15, 55], "alert_threshold": 85}
    },
    "network_baseline": {
      "outbound_connections_per_hour": {"normal_range": [100, 5000], "alert_threshold": 10000},
      "data_transfer_mb_per_hour": {"normal_range": [500, 10000], "alert_threshold": 25000},
      "connection_error_rate": {"normal_range": [0.0, 0.05], "alert_threshold": 0.15}
    }
  },
  "access_patterns": {
    "admin_access_frequency": {"per_day": 5, "alert_threshold": 15},
    "sensitive_data_access": {"per_day": 25, "alert_threshold": 100},
    "api_calls_per_minute": {"normal_range": [10, 1000], "alert_threshold": 5000}
  },
  "api_usage": {
    "authentication_endpoint": {"requests_per_minute": {"normal_range": [5, 300], "alert_threshold": 800}},
    "resource_creation_endpoints": {"requests_per_minute": {"normal_range": [1, 50], "alert_threshold": 200}},
    "data_retrieval_endpoints": {"requests_per_minute": {"normal_range": [10, 1000], "alert_threshold": 3000}}
  }
}
```

## Usage

Security monitoring tools use these baseline configurations to detect anomalies and potential security threats:

```python
import json
import os
import logging
from typing import Dict, Any

def load_security_baseline(environment: str) -> Dict[str, Any]:
    """
    Load the security baseline for the specified environment.

    Args:
        environment: The environment name (development, staging, production)

    Returns:
        The baseline configuration as a dictionary
    """
    logger = logging.getLogger(__name__)

    try:
        # Determine the baseline file path
        baseline_dir = os.path.dirname(os.path.abspath(__file__))
        baseline_file = os.path.join(baseline_dir, f"{environment}.json")

        # Check if file exists
        if not os.path.exists(baseline_file):
            logger.error(f"Baseline file not found for environment: {environment}")
            # Fall back to default baseline
            baseline_file = os.path.join(baseline_dir, "production.json")
            logger.info(f"Falling back to production baseline")

        # Load baseline configuration
        with open(baseline_file, "r") as f:
            baseline = json.load(f)

        logger.info(f"Loaded security baseline for {environment}, version {baseline.get('metadata', {}).get('version', 'unknown')}")
        return baseline

    except Exception as e:
        logger.error(f"Error loading security baseline: {str(e)}")
        raise
```

Example usage in the anomaly detector:

```bash
# Run anomaly detection with a specific baseline
./anomaly_detector.sh --environment production \
    --baseline-path config/baseline/production.json \
    --detection-sensitivity high
```

## Customization Guidelines

When customizing baseline configurations for specific environments:

1. **Start with a Copy**
   - Begin with a copy of the closest existing baseline
   - Maintain the same structure and key names
   - Update the metadata section completely
   - Document the reason for customization

2. **Tune Environment-Specific Values**
   - Adjust thresholds based on environment characteristics
   - Set wider thresholds for development environments
   - Use stricter thresholds for production
   - Consider time-of-day patterns if applicable
   - Account for expected traffic patterns

3. **Test Before Deployment**
   - Validate baseline against historical data
   - Run in observation mode before enforcing
   - Monitor false positive rates after changes
   - Gradually tighten thresholds as confidence increases
   - Document baseline performance metrics

4. **Regular Review**
   - Schedule periodic baseline reviews
   - Update baselines after significant system changes
   - Adjust for seasonal or cyclical traffic patterns
   - Review after false positives or missed detections
   - Document all threshold adjustments with rationale

## Best Practices & Security

- **Access Control**: Restrict baseline file modification to security personnel
- **Change Management**: Follow proper change management for baseline updates
- **Environment Separation**: Maintain separate baselines for each environment
- **False Positive Management**: Balance security with operational impact
- **Gradual Adjustment**: Make incremental changes to thresholds
- **Historical Data**: Base thresholds on historical behavior analysis
- **Monitoring Tuning**: Regularly review and tune baseline thresholds
- **Performance Impact**: Consider performance impact of detection thresholds
- **Version Control**: Track all baseline changes in version control
- **Validation**: Validate baseline files before deployment

## Common Features

All baseline configurations share these common elements:

- **Environment Designation**: Explicit environment identification
- **Metadata Section**: Version tracking and update information
- **Standard Structure**: Consistent structure across environments
- **Threshold Definitions**: Clear definition of normal ranges and alert thresholds
- **Tiered Alerting**: Multiple threshold levels for graduated response
- **Time Windows**: Appropriate time windows for pattern detection
- **Versioned Updates**: Version tracking for change management
- **Validation Schema**: JSON schema for configuration validation
- **System Classifications**: Component-specific threshold groups
- **Documentation**: Comments and descriptions of threshold purposes

## Related Documentation

- Anomaly Detection Configuration
- Security Monitoring Overview
- Security Monitoring Tools
- Security Event Correlation Guide
- Threat Detection Strategy
- Security Baseline Development Guide
- False Positive Tuning Guide
- Incident Response Procedures
- Security Monitoring Best Practices
- Environment-Specific Security Requirements
