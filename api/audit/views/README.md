# Audit API View Helpers

This directory contains specialized view helper modules used by the Audit API to generate different types of reports, dashboards, and compliance documentation. These view helpers transform raw audit data into structured formats suitable for presentation and analysis.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage
- Configuration
- Security Features
- Common Features
- Related Documentation

## Overview

The view helpers in the Audit API provide specialized functionality for generating reports, aggregating dashboard data, and preparing compliance documentation from audit logs. They implement data transformation, aggregation, and formatting logic needed to present audit information in useful ways for different audiences. These modules follow security best practices including input validation, output sanitization, and proper handling of sensitive information.

## Key Components

- **`compliance.py`**: Compliance report generation
  - Compliance framework mapping
  - Control validation reporting
  - Evidence document generation
  - Regulatory report formatting
  - Standard-specific filtering

- **`dashboard.py`**: Dashboard data aggregation
  - Audit trend analysis
  - Data visualization preparation
  - Key metrics calculation
  - Security posture indicators
  - Time series generation

- **`reports.py`**: Report generation views
  - Anomaly highlighting
  - Data export formatting
  - Filtering by security criteria
  - PDF report generation
  - Tabular data formatting

## Directory Structure

```plaintext
api/audit/views/
├── __init__.py      # Package initialization
├── compliance.py    # Compliance report generation
├── dashboard.py     # Dashboard data aggregation
├── README.md        # This documentation
└── reports.py       # Report generation views
```

## Usage

The view helpers are used internally by the Audit API endpoints to format and present audit data:

```python
from api.audit.views.reports import generate_security_report
from api.audit.views.dashboard import generate_trend_data
from api.audit.views.compliance import generate_compliance_report

# Generate a security report
report_data = generate_security_report(
    start_date="2023-07-01T00:00:00Z",
    end_date="2023-07-31T23:59:59Z",
    severity=["critical", "high"],
    format="pdf"
)

# Generate trend data for dashboard
trend_data = generate_trend_data(
    period="30d",
    metrics=["login_failures", "permission_changes"],
    interval="day"
)

# Generate a compliance report
compliance_report = generate_compliance_report(
    framework="pci-dss",
    controls=["access_control", "authentication", "audit_logging"],
    evidence_period="quarter",
    format="pdf"
)
```

## Configuration

The view helpers use the following configuration settings from the main application config:

```python
# Report generation settings
'REPORT_TEMPLATES_PATH': 'api/audit/templates/reports',
'MAX_REPORT_PAGES': 500,
'REPORT_BRANDING_ENABLED': True,
'DEFAULT_REPORT_FORMAT': 'pdf',

# Dashboard settings
'DASHBOARD_CACHE_TTL': 900,  # Time to live for cached dashboard data
'DASHBOARD_DEFAULT_TIMESPAN': '7d',
'DASHBOARD_METRICS': ['auth_events', 'security_events', 'system_events'],

# Compliance settings
'COMPLIANCE_FRAMEWORKS': {
    'pci-dss': {
        'title': 'PCI DSS Compliance Report',
        'controls': ['requirement_1', 'requirement_2', '...'],
        'evidence_required': True
    },
    'hipaa': {
        'title': 'HIPAA Compliance Report',
        'controls': ['access_controls', 'audit_controls', '...'],
        'evidence_required': True
    }
}
```

## Security Features

- **Access Control**: All view helpers enforce proper access control checks
- **Data Sanitization**: All output is sanitized to prevent XSS and injection attacks
- **Field-Level Security**: Enforces redaction of sensitive fields based on user role
- **Input Validation**: All parameters are validated before processing
- **PII Handling**: Special handling for personally identifiable information
- **Rate Limiting**: Resource-intensive operations have specific rate limits
- **Secure Defaults**: Conservative defaults for report generation and exports
- **Sensitive Data Filtering**: Automatic filtering of sensitive information in reports

## Common Features

All view helpers share these common features:

- **Access Controls**: Role-based access for all operations
- **Caching**: Efficient caching of frequently accessed data
- **Comprehensive Logging**: Detailed logging of all operations
- **Error Handling**: Graceful handling of processing failures
- **Exception Tracking**: Proper exception capture and reporting
- **Internationalization**: Support for localized report formats
- **Pagination**: Support for handling large datasets
- **Performance Optimization**: Efficient processing of large audit datasets
- **Structured Output**: Consistent, well-defined output formats
- **Template Support**: Modular template system for consistent presentation

## Related Documentation

- Audit API Documentation
- Audit Data Model
- Compliance Framework Mappings
- Dashboard Documentation
- Export Format Specification
- Report Generation Guide
- Security Event Classification
- Template Customization Guide
