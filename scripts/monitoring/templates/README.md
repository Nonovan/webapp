# Monitoring Templates

This directory contains template files for reports, dashboards, and notifications for the Cloud Infrastructure Platform monitoring system.

## Overview

These templates provide standardized formats for various monitoring outputs, ensuring consistency in reporting, notifications, and visualizations across different environments and services.

## Template Categories

### Report Templates

- `health_report.html` - HTML template for system health reports
- `performance_report.html` - Template for performance analysis reports
- `security_report.html` - Template for security assessment reports
- `compliance_report.html` - Template for compliance status reports
- `incident_report.html` - Template for incident documentation

### Dashboard Templates

- `system_dashboard.json` - Grafana dashboard for system metrics
- `application_dashboard.json` - Dashboard for application performance
- `security_dashboard.json` - Security monitoring dashboard
- `database_dashboard.json` - Database performance dashboard
- `network_dashboard.json` - Network monitoring dashboard

### Notification Templates

- `alert_email.html` - Email template for alert notifications
- `incident_notification.html` - Template for incident notifications
- `status_update.html` - Template for status update messages
- `weekly_summary.html` - Template for weekly monitoring summaries
- `sms_alert.txt` - Plain text template for SMS alerts

## Usage

Templates are referenced by monitoring scripts and can be customized for specific environments:

```bash
# Generate health report using template
./health_reporter.sh --template templates/health_report.html

# Send alert using email template
./alert_manager.sh --notify --template templates/alert_email.html

# Import dashboard template to Grafana
./dashboard_manager.sh --import templates/system_dashboard.json
```

## Template Variables

Templates use a consistent set of variables that are populated at runtime:

- `{{timestamp}}` - Date and time of report generation
- `{{environment}}` - Environment name (dev, staging, production)
- `{{status}}` - Overall status (healthy, warning, critical)
- `{{metrics.*}}` - Various metric values
- `{{alerts[]}}` - Array of active alerts
- `{{components[]}}` - Array of system components and their status

## Customization Guidelines

When customizing templates:

1. Maintain all required variables
2. Preserve the overall structure for consistency
3. Test templates in all target environments
4. Document any environment-specific customizations
5. Follow the style guide for visual consistency

## Related Files

- [Monitoring Configuration](../config/)
- [Notification System](../alerts/)
- [Report Generation Scripts](../core/)
