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
  - Compliance framework mapping (PCI-DSS, HIPAA, GDPR, ISO27001, SOC2, FedRAMP)
  - Control validation reporting with evidence collection
  - Compliance status tracking and verification
  - Regulatory report formatting with framework-specific templates
  - Standard-specific filtering for relevant audit events

- **`dashboard.py`**: Dashboard data aggregation
  - Audit trend analysis with configurable time periods
  - Interactive data visualization preparation
  - Security metrics calculation and threshold monitoring
  - Security posture indicators with historical comparison
  - Time series generation with customizable granularity

- **`reports.py`**: Report generation views
  - Security incident and audit summary reporting
  - Multiple export formats (JSON, CSV, PDF, HTML)
  - Comprehensive user activity reporting
  - Advanced data filtering and segmentation
  - Structured data formatting for compliance needs

## Directory Structure

```plaintext
api/audit/views/
├── __init__.py      # Package initialization and exports
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
    report_type="authentication",  # Focus on authentication events
    start_date="2023-07-01T00:00:00Z",
    end_date="2023-07-31T23:59:59Z",
    severity=["critical", "high"],
    format_type="pdf"
)

# Generate trend data for dashboard
trend_data = generate_trend_data(
    period="30d",
    interval="day"  # Granularity: hour, day, week, month
)

# Generate a compliance report
compliance_report = generate_compliance_report(
    report_type="pci-dss",
    start_date="2023-01-01T00:00:00Z",
    end_date="2023-03-31T23:59:59Z",
    format_type="pdf",
    sections=["req_1", "req_2", "req_10"]  # Specific PCI-DSS requirements
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
'AUDIT_DASHBOARD_CATEGORY_LIMIT': 10,  # Maximum categories in distribution charts
'AUDIT_DASHBOARD_DATA_TTL': 900,  # Cache TTL for dashboard data in seconds

# Dashboard settings
'DASHBOARD_CACHE_TTL': 900,  # Time to live for cached dashboard data
'DASHBOARD_DEFAULT_TIMESPAN': '7d',
'DASHBOARD_METRICS': ['auth_events', 'security_events', 'system_events'],

# Compliance settings
'COMPLIANCE_STATUS_CACHE_TTL': 900,  # Cache TTL for compliance status data
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

- **Access Control**: All view helpers enforce proper access control checks through role-based permissions
- **Data Sanitization**: All output is sanitized to prevent XSS and injection attacks
- **Field-Level Security**: Enforces redaction of sensitive fields based on user role
- **Input Validation**: All parameters are validated before processing to prevent injection attacks
- **PII Handling**: Special handling for personally identifiable information with automatic redaction
- **Rate Limiting**: Resource-intensive operations have specific rate limits
- **Secure Defaults**: Conservative defaults for report generation and exports
- **Sensitive Data Filtering**: Automatic filtering of sensitive information in reports
- **Critical Event Handling**: Special processing for security-critical events identified by `core.security.cs_audit.get_critical_event_categories()`

## Common Features

All view helpers share these common features:

- **Access Controls**: Role-based access for all operations
- **Caching**: Efficient caching of frequently accessed data with proper TTL management
- **Comprehensive Logging**: Detailed logging of all operations for debugging and audit
- **Error Handling**: Graceful handling of processing failures with fallback functionality
- **Exception Tracking**: Proper exception capture and reporting
- **Internationalization**: Support for localized report formats and timestamps
- **Pagination**: Support for handling large datasets with efficient database querying
- **Performance Optimization**: Efficient processing of large audit datasets
- **Structured Output**: Consistent, well-defined output formats for reliable API consumption
- **Template Support**: Modular template system for consistent presentation

## Integration Points

The view helpers integrate with several core platform components:

- **Database Layer**: Uses SQLAlchemy for efficient data retrieval and aggregation
- **Redis Cache**: Implements caching for expensive operations and dashboard data
- **Security Module**: Leverages `core.security.cs_audit` for security event categorization
- **Time Utilities**: Uses `core.security.cs_utils` for time period formatting and parsing
- **Compliance Framework**: Integrates with compliance validation services
- **Export Services**: Supports multiple export formats with proper formatting

## Related Documentation

- Audit API Documentation
- Audit Data Model
- Compliance Framework Mappings
- Dashboard Documentation
- Export Format Specification
- Report Generation Guide
- Security Event Classification
- Template Customization Guide
