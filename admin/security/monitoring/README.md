# Security Monitoring Tools

This directory contains specialized security monitoring tools for administrative use. These tools provide enhanced visibility into security events, support incident investigation, and enable proactive threat detection beyond what's available in the standard monitoring system. They are designed for security operations personnel and incident responders.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Report Generation](#report-generation)
- [Common Workflows](#common-workflows)
- [Related Documentation](#related-documentation)

## Overview

The monitoring directory contains specialized security monitoring tools for administrative use. These tools provide enhanced visibility into security events, support incident investigation, and enable proactive threat detection beyond what's available in the standard monitoring system. They are designed for security operations personnel and incident responders.

The tools implement a comprehensive security monitoring framework focused on:

- Detection of unauthorized changes to critical files
- Identification of suspicious administrative activities
- Correlation of security events to identify attack patterns
- Visualization and reporting of security metrics
- Integration with external threat intelligence sources
- Analysis of behavioral patterns for anomaly detection

## Key Components

- **`anomaly_detector.sh`**: Behavioral anomaly detection system
  - Machine learning-based anomaly detection
  - Network traffic anomaly detection
  - Resource usage pattern monitoring
  - System call pattern analysis
  - User behavior analytics
  - HTML, JSON, and text report generation

- **`integrity_monitor.sh`**: Enhanced file integrity monitoring system
  - Administrative configuration integrity verification
  - Critical file monitoring beyond standard system checks
  - Cryptographic verification of system binaries
  - Detection of unauthorized file modifications
  - Rootkit and backdoor detection capabilities
  - Structured report generation for findings

- **`privilege_audit.py`**: Administrative privilege monitoring
  - Administrative action verification
  - Permission escalation detection
  - Privileged account usage tracking
  - Role-based access control validation
  - Unexpected privilege changes
  - Integration with alerting system

- **`security_dashboard.py`**: Administrative security dashboard generator
  - Anomaly detection visualization
  - Incident tracking and management
  - Real-time security posture visualization
  - Risk scoring and trending
  - Security alert summaries
  - Threat intelligence integration

- **`security_event_correlator.py`**: Security event correlation engine
  - Attack chain reconstruction
  - Cross-source event correlation
  - Detection rule management
  - Pattern-based threat detection
  - Security alert generation
  - SIEM integration capabilities

- **`threat_intelligence.py`**: Threat intelligence integration tool
  - Indicator of compromise management
  - Malicious IP/domain tracking
  - Threat data aggregation
  - Threat feed integration
  - Threat scoring and prioritization
  - TAXII/STIX support for structured threat information

## Directory Structure

```plaintext
admin/security/monitoring/
├── README.md                     # This documentation
├── __init__.py                   # Package initialization and exports
├── anomaly_detector.sh           # Behavioral anomaly detection system
├── config/                       # Configuration files
│   ├── README.md                 # Configuration documentation
│   ├── baseline/                 # Security baselines for different environments
│   │   ├── README.md             # Baseline documentation
│   │   ├── development.json      # Development environment baseline
│   │   ├── production.json       # Production environment baseline
│   │   └── staging.json          # Staging environment baseline
│   ├── detection_rules/          # Detection rule definitions
│   │   ├── README.md             # Detection rules documentation
│   │   ├── command_injection.yml # Command injection detection rules
│   │   ├── data_exfiltration.yml # Data theft detection patterns
│   │   ├── lateral_movement.yml  # Lateral movement detection rules
│   │   ├── persistence.yml       # Persistence technique detection rules
│   │   ├── privilege_esc.yml     # Privilege escalation detection rules
│   │   └── suspicious_auth.yml   # Suspicious authentication patterns
│   └── threat_feeds.json         # Threat intelligence feed configuration
├── integrity_monitor.sh          # Enhanced file integrity monitoring system
├── monitoring_constants.py       # Shared constants and configuration
├── privilege_audit.py            # Administrative privilege monitoring
├── security_dashboard.py         # Administrative security dashboard generator
├── security_event_correlator.py  # Security event correlation engine
├── templates/                    # Report and visualization templates
│   ├── README.md                 # Templates documentation
│   ├── anomaly_report.html       # Anomaly detection report template
│   ├── dashboard.html            # Security dashboard template
│   └── incident_summary.html     # Incident summary template
├── threat_intelligence.py        # Threat intelligence integration tool
└── utils/                        # Monitoring utilities
    ├── README.md                 # Utilities documentation
    ├── __init__.py               # Package initialization
    ├── alert_formatter.py        # Security alert formatting functions
    ├── event_normalizer.py       # Event normalization functions
    ├── indicator_matcher.py      # IOC matching functions
    └── log_parser.py             # Security log parsing utilities
```

## Configuration

The security monitoring tools use configuration files in the config directory to determine what to monitor and how to respond:

### Threat Intelligence Configuration

The `threat_feeds.json` file defines external threat intelligence sources:

```json
{
  "feeds": [
    {
      "name": "malicious_ips",
      "url": "https://threatfeed.example.com/api/v1/ips",
      "type": "ip",
      "update_interval": 3600,
      "enabled": true,
      "auth_required": true,
      "auth_header": "X-API-Key",
      "auth_env_var": "THREAT_API_KEY",
      "expiration": 86400
    }
  ]
}
```

### Baselines

Each environment has specific baseline files that define normal behavior patterns:

```json
// production.json (example)
{
  "authentication": {
    "failed_login_threshold": 5,
    "brute_force_time_window": 300,
    "session_duration_avg": 28800
  },
  "system_activity": {
    "cpu_baseline": {
      "web_servers": {"normal_range": [10, 50], "alert_threshold": 85}
    },
    "network_baseline": {
      "outbound_connections_per_hour": {"normal_range": [100, 5000]}
    }
  }
}
```

### Detection Rules

YAML-formatted detection rules for different attack patterns:

```yaml
# Example from privilege_esc.yml
rules:
  - id: PRIV-ESC-001
    name: "Unexpected Privilege Elevation"
    description: "Detects when a user gains elevated privileges through unexpected means"
    severity: high
    condition:
      event_type: "permission_change"
      new_permissions:
        - "admin:*"
        - "system:write"
      not:
        approver_role: "security_admin"
    tags:
      - "MITRE_T1078"
      - "privilege_escalation"
      - "compliance_violation"
    actions:
      - alert: "security_team"
      - log: "security_audit"
      - notify: "security_admin"
```

## Security Features

- **Access Controls**: Only authorized security personnel can access these tools
- **Authentication**: Multi-factor authentication for tool access
- **Audit Logging**: All actions are logged for security accountability
- **Encryption**: Sensitive data is encrypted at rest and in transit
- **Input Validation**: All user inputs and external data are validated
- **Integrity Protection**: Self-verification mechanisms prevent tampering
- **Need-to-Know Basis**: Information is compartmentalized based on roles
- **Rate Limiting**: Protects against API abuse and resource exhaustion
- **Secure Credential Handling**: API keys and credentials are securely managed
- **Secure Output Handling**: Sensitive information is properly protected in reports

## Usage Examples

### File Integrity Verification

```bash
# Perform comprehensive integrity check
./integrity_monitor.sh --scan-all --verify-signatures

# Check only critical configuration files
./integrity_monitor.sh --scope config-files --alert-on-change

# Generate JSON report of integrity status
./integrity_monitor.sh --output-format json --report-file /tmp/integrity_report.json
```

### Security Dashboard Generation

```bash
# Generate a comprehensive security dashboard
./security_dashboard.py --environment production --output /var/www/security/dashboard.html

# Generate a focused dashboard for a specific incident
./security_dashboard.py --incident-id INC-2023-42 --detail-level high

# Generate dashboard as JSON data
./security_dashboard.py --format json --output /tmp/security_data.json
```

### Security Event Correlation

```bash
# Run correlation against recent security events
./security_event_correlator.py --timeframe 24h --sensitivity high

# Use custom detection rules
./security_event_correlator.py --rules-dir /path/to/custom_rules --output correlated_events.json

# Generate HTML report of correlated events
./security_event_correlator.py --format html --output-file /tmp/correlation_report.html
```

### Threat Intelligence Integration

```bash
# Update threat intelligence from all configured feeds
./threat_intelligence.py --update-all

# Check specific indicators against threat intelligence
./threat_intelligence.py --check-ip 203.0.113.100 --check-domain suspicious-domain.example.com

# Generate threat intelligence report
./threat_intelligence.py --report --output /tmp/threat_report.html --days 7
```

### Anomaly Detection

```bash
# Run full anomaly detection scan
./anomaly_detector.sh --scope all --sensitivity high

# Focus on user behavior anomalies
./anomaly_detector.sh --scope user --timeframe 48h

# Generate HTML report of detected anomalies
./anomaly_detector.sh --output-format html --report-file /tmp/anomalies.html
```

### Usage from Python

```python
from admin.security.monitoring import (
    init_file_integrity_monitoring,
    init_threat_intelligence,
    init_security_dashboard,
    init_event_correlation,
    init_privilege_audit,
    init_all_tools
)

# Initialize individual components
integrity_status = init_file_integrity_monitoring()
threat_intel_status = init_threat_intelligence()

# Or initialize all available tools at once
results = init_all_tools(app)
```

## Report Generation

Security monitoring tools can generate reports in multiple formats:

- **HTML**: Interactive dashboards and reports with visualizations
- **JSON**: Structured data for programmatic processing and integration
- **Text**: Plain text reports for command-line review and logging
- **CSV**: Tabular data for spreadsheet analysis and record keeping

Report customization is available through the templates directory, where you can modify the HTML templates used for report generation to meet specific requirements.

## Common Workflows

### Incident Investigation

1. Start with the security dashboard for a high-level overview
2. Run event correlation to identify attack patterns
3. Use anomaly detection to find unusual behaviors
4. Verify file integrity to check for unauthorized changes
5. Query threat intelligence for indicators

### Daily Security Monitoring

1. Generate the security dashboard each morning
2. Review anomaly detection reports
3. Check integrity verification status
4. Update threat intelligence feeds
5. Investigate any correlated events

### Security Baseline Management

1. Run anomaly detection in learning mode
2. Adjust baseline thresholds based on findings
3. Update detection rules based on new threats
4. Verify changes with dry-run mode
5. Apply changes to production environment

## Related Documentation

- Security Architecture Overview
- Threat Intelligence Framework
- Event Correlation Guide
- Incident Response Procedures
- Security Monitoring Strategy
- File Integrity Monitoring Guide
