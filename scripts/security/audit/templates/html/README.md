# HTML Report Templates for Security Audits

This directory contains HTML templates used to generate standardized security audit reports for the Cloud Infrastructure Platform. These templates provide structured, visually accessible representations of security findings with consistent formatting, severity classification, and remediation guidance.

## Contents

- [Overview](#overview)
- [Key Templates](#key-templates)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
- [Related Documentation](#related-documentation)

## Overview

The HTML report templates transform audit findings into professional, actionable reports targeted at different audiences. These templates use responsive design principles, maintain security classifications, and provide clear prioritization of issues. They are designed to be rendered in browsers, embedded in emails, or converted to PDF documents while maintaining visual consistency.

## Key Templates

- **`executive_summary.html`**: High-level overview template for leadership and management.
  - **Usage**: Generate concise summaries focusing on risk posture and critical issues.
  - **Features**:
    - Key metrics visualization
    - Risk trend analysis
    - Critical findings summary
    - Compliance status indicators
    - Strategic recommendations
    - Business impact assessment
    - Responsibility assignment
    - Timeline visualization

- **`technical_report.html`**: Comprehensive technical report for security teams.
  - **Usage**: Generate detailed reports with full technical information on all findings.
  - **Features**:
    - Detailed vulnerability descriptions
    - Technical evidence documentation
    - Reproduction steps for findings
    - Detailed remediation instructions
    - Security control mapping
    - Configuration validation results
    - Reference to security standards
    - Component-specific guidance

- **`css/`**: Stylesheet directory for HTML reports.
  - **Usage**: Provides consistent visual styling for all report types.
  - **Features**:
    - Responsive design elements
    - Print-friendly formatting
    - Severity color coding
    - Consistent typography
    - Accessible design elements
    - Dark mode support
    - Custom theme capabilities
    - Chart and table styling

## Directory Structure

```plaintext
scripts/security/audit/templates/html/
├── README.md                 # This documentation
├── executive_summary.html    # Executive summary template
├── technical_report.html     # Technical details template
└── css/                      # CSS styles for HTML reports
    ├── report.css            # Common styling for all reports
    ├── summary.css           # Executive summary specific styling
    ├── technical.css         # Technical report specific styling
    └── print.css             # Print-friendly stylesheet
```

## Configuration

The HTML templates support various configuration options that can be set through the audit tool interface:

### Template Variables

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `report_title` | Title of the report | "Security Audit Report - Q2 2024" |
| `organization` | Organization name | "Cloud Infrastructure Platform" |
| `report_date` | Date of report generation | "2024-07-15" |
| `scope` | Audit scope description | "Production environment" |
| `classification` | Report security classification | "Confidential" |
| `prepared_by` | Report author | "Security Team" |
| `approved_by` | Report approver | "CISO" |
| `logo_path` | Path to organization logo | "/static/images/logo.png" |
| `risk_threshold` | Minimum risk level to include | "medium" |
| `include_evidence` | Whether to include evidence | true |

### CSS Customization

You can customize the visual appearance of reports by modifying the CSS files or by providing custom CSS at runtime:

```bash
../security_audit.py --output-format=html --custom-css=/path/to/custom.css
```

## Best Practices & Security

- **Classification Marking**: Always include appropriate security classification in reports
- **Data Sanitization**: Ensure sensitive information is properly redacted before sharing
- **Report Encryption**: Consider encrypting reports that contain sensitive findings
- **Access Control**: Restrict access to reports containing security vulnerabilities
- **Version Control**: Maintain report templates in version control
- **Mobile Compatibility**: Test reports on both desktop and mobile browsers
- **Print Formatting**: Ensure reports are properly formatted for printing
- **Image Handling**: Use proper data URI schemes for embedding images securely
- **JavaScript Limitation**: Minimize JavaScript usage for security reasons
- **Clean Headers**: Implement appropriate security headers when serving reports
- **Report Integrity**: Include report integrity hashes where appropriate
- **Accessibility**: Ensure reports meet accessibility standards
- **Consistent Branding**: Maintain consistent branding across all report types
- **Remediation Clarity**: Present remediation steps clearly and actionably
- **Severity Visibility**: Make severity classifications immediately visible

## Common Features

- **Responsive Design**: Reports adapt to different screen sizes
- **Severity Classification**: Visual indicators of finding severity
- **Interactive Elements**: Collapsible sections for better navigation
- **Evidence Integration**: Structured presentation of supporting evidence
- **Compliance Mapping**: Mapping of findings to compliance frameworks
- **Print Optimization**: Special styling for printed reports
- **Table of Contents**: Automatic generation of navigation elements
- **Risk Scoring**: Consistent visualization of risk scores
- **Finding Categorization**: Logical grouping of related findings
- **Data Visualization**: Charts and graphs for metrics presentation
- **Report Metadata**: Consistent header with audit metadata
- **CSV/PDF Export**: Options to export data in different formats
- **Filtering Capabilities**: Dynamic filtering of findings by severity
- **Time Tracking**: Documentation of assessment timeline
- **Change Tracking**: Visual indicators of changes since previous audits

## Usage Examples

### Template Integration

```python
from scripts.security.audit.checkers.common.check_result import CheckResultSet
from scripts.security.audit.reporting.html_generator import HTMLReportGenerator

# Create generator with results
results = CheckResultSet()
generator = HTMLReportGenerator(
    results=results,
    template='technical_report.html',
    report_title="Security Assessment - Production Environment",
    organization="Cloud Infrastructure Platform",
    classification="Confidential"
)

# Generate the report
html_report = generator.generate()

# Save to file
with open('security-report.html', 'w') as f:
    f.write(html_report)
```

### Custom Template Extension

```python
from scripts.security.audit.reporting.html_generator import HTMLReportGenerator

# Create generator with custom template
generator = HTMLReportGenerator(
    template_path='/custom/templates/custom_report.html',
    results=audit_results
)

# Add custom variables
generator.set_variable('compliance_framework', 'PCI-DSS')
generator.set_variable('custom_logo', '/path/to/logo.png')

# Generate and save report
html_report = generator.generate()
with open('custom-security-report.html', 'w') as f:
    f.write(html_report)
```

### Template Preprocessing

```python
from scripts.security.audit.reporting.template_preprocessor import TemplatePreprocessor

# Initialize preprocessor with custom filters
preprocessor = TemplatePreprocessor()

# Add custom filter
def severity_badge(severity):
    colors = {
        'critical': 'darkred',
        'high': 'red',
        'medium': 'orange',
        'low': 'green',
        'info': 'blue'
    }
    return f'<span class="badge" style="background-color:{colors[severity.lower()]}">{severity}</span>'

preprocessor.add_filter('severity_badge', severity_badge)

# Process template with custom filters
html = preprocessor.process('technical_report.html', results=findings)
```

## Related Documentation

- Security Audit Framework
- Common Check Utilities
- Security Report Design Guidelines
- Audit Finding Classification
- Compliance Report Templates
- HTML Content Security
- Security Assessment Methodology
- Template Development Guide
- Evidence Documentation Standards
- Report Distribution Guidelines
