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
  - Security metrics tracking
  - Threat intelligence integration
  - Environment-aware display options
  - Multiple output formats (HTML, JSON)

- **`security_event_correlator.py`**: Security event correlation engine
  - Advanced persistent threat detection
  - Attack pattern recognition
  - Baseline deviation alerting
  - Cross-system event analysis
  - Sequential attack detection
  - Rule-based correlation capabilities
  - HTML report generation for findings

- **`threat_intelligence.py`**: Threat intelligence integration tool
  - Automated blocklist updates
  - IOC (Indicators of Compromise) matching
  - IP reputation analysis and alerting
  - Known malicious pattern detection
  - Threat feed integration and management
  - Detailed HTML reporting on threat matches
  - Batch indicator processing

## Directory Structure

```plaintext
admin/security/monitoring/
├── README.md                     # This documentation
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
├── privilege_audit.py            # Administrative privilege monitoring
├── security_dashboard.py         # Administrative security dashboard generator
├── security_event_correlator.py  # Security event correlation engine
├── templates/                    # Report and visualization templates
│   ├── README.md                 # Templates documentation
│   ├── anomaly_report.html       # Anomaly detection report template
│   ├── dashboard.html            # Security dashboard template
│   └── incident_summary.html     # Incident summary template
├── threat_intelligence.py        # Threat intelligence integration tool
└── utils/                        # Utility functions
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

```json
// threat_feeds.json
{
  "feeds": [
    {
      "name": "EmergingThreats",
      "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
      "type": "ip_list",
      "update_interval": 86400,
      "enabled": true
    },
    {
      "name": "AlienVaultOTX",
      "api_key": "${OTX_API_KEY}",
      "url": "https://otx.alienvault.com/api/v1/indicators/export",
      "type": "structured",
      "update_interval": 43200,
      "enabled": true
    }
  ],
  "local_cache_dir": "/var/cache/cloud-platform/threat_intel",
  "retention_days": 90,
  "match_threshold": 0.75
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
# Analyze events from the past 24 hours
./security_event_correlator.py --hours 24 --correlation-window 300

# Analyze events related to a specific user
./security_event_correlator.py --user-id 42 --detection-mode aggressive

# Generate HTML report of correlated events
./security_event_correlator.py --hours 48 --output-format html
```

### Threat Intelligence Integration

```bash
# Update threat intelligence from all feeds
./threat_intelligence.py --update-all

# Check specific indicators against threat intelligence
./threat_intelligence.py --check-ioc "185.159.128.243" --type ip

# Process multiple indicators from a file
./threat_intelligence.py --report --indicators-file /tmp/suspicious_ips.txt
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

## Report Generation

All tools can generate reports in various formats. The main output formats include:

### HTML Reports

HTML reports feature rich visualizations with:

- Severity color-coding (critical, high, medium, low)
- Interactive elements for exploring details
- Print-friendly formatting
- Responsive design for different screen sizes
- Consistent styling across all monitoring tools

### JSON Reports

JSON format provides structured data for:

- Integration with other security tools
- Custom dashboard construction
- Automated analysis and response
- Historical data analysis
- Audit record maintenance

### Text Reports

Plain text reports offer:

- Console-friendly output
- Email compatibility
- Quick review of findings
- Low bandwidth requirements
- Simplified archiving

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

- Anomaly Detection Configuration
- Event Correlation Guide
- Incident Response Procedures
- Security Architecture
- Security Monitoring Strategy
- Threat Intelligence Framework
