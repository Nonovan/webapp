# Report Templates

This directory contains standardized templates for generating reports in the Cloud Infrastructure Platform. These templates ensure consistent formatting, structure, and branding across various report types used for compliance, security assessments, and system auditing.

## Contents

- Overview
- Key Templates
- Directory Structure
- Usage
- Template Variables
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The report templates provide structured formats for creating professional, consistent reports that document various system activities, assessment results, and compliance statuses. These templates ensure that all reports follow organizational standards, include proper branding, and present information in a clear, actionable format. They support multiple output formats including HTML, PDF, and Microsoft Word, with appropriate styling for each format.

## Key Templates

- **`assessment_report.html`**: Security assessment report template
  - Executive summary section
  - Findings categorization
  - Risk rating system
  - Remediation recommendations
  - Technical details presentation
  - Evidence documentation

- **`audit_report.html`**: System audit report template
  - Audit scope definition
  - Compliance mapping section
  - Control verification results
  - Non-compliance documentation
  - Corrective action tracking
  - Attestation information

- **`compliance_report.html`**: Compliance status report template
  - Regulatory framework mapping
  - Control implementation status
  - Gap analysis presentation
  - Evidence documentation
  - Remediation planning
  - Attestation information

- **`executive_summary.html`**: Executive briefing template
  - High-level overview format
  - Key metrics visualization
  - Risk assessment summary
  - Strategic recommendations
  - Business impact analysis
  - Timeline for remediation

- **`incident_report.html`**: Security incident report template
  - Incident classification
  - Timeline visualization
  - Impact assessment
  - Response documentation
  - Root cause analysis
  - Preventive measures

- **`metrics_report.html`**: Security metrics report template
  - Key performance indicators
  - Trend analysis visualization
  - Benchmark comparison
  - Goal achievement tracking
  - Risk tracking metrics
  - Security posture visualization

## Directory Structure

```plaintext
admin/templates/reports/
├── README.md                # This documentation
├── assessment_report.html   # Security assessment report template
├── audit_report.html        # System audit report template
├── compliance_report.html   # Compliance status report template
├── components/              # Reusable report components
│   ├── README.md            # Components documentation
│   ├── chart_templates.html # Data visualization components
│   ├── finding_card.html    # Finding presentation component
│   ├── header_footer.html   # Standard header and footer
│   ├── risk_rating.html     # Risk rating visualization
│   ├── css/                 # Component-specific styling
│   │   ├── charts.css       # Chart styling
│   │   ├── findings.css     # Finding card styling
│   │   ├── layout.css       # Header and footer styling
│   │   └── risk.css         # Risk rating styling
│   └── js/                  # Component JavaScript functionality
│       ├── chart_behavior.js # Chart interactivity
│       ├── finding_behavior.js # Finding card behaviors
│       ├── print_helpers.js # Print-specific functionality
│       └── risk_calculator.js # Risk calculation utilities
├── executive_summary.html   # Executive briefing template
├── incident_report.html     # Security incident report template
├── metrics_report.html      # Security metrics report template
└── styles/                  # Style definitions for different formats
    ├── pdf.css              # PDF output styling
    ├── report.css           # HTML report styling
    └── word.css             # Word document styling
```

## Usage

The templates are designed to be used with the reporting engine:

```python
from jinja2 import Environment, FileSystemLoader
import os
from weasyprint import HTML
import json

def generate_assessment_report(assessment_data, output_format='pdf', output_path=None):
    """Generate a security assessment report from assessment data.

    Args:
        assessment_data (dict): Assessment results and metadata
        output_format (str): Output format ('pdf', 'html', or 'docx')
        output_path (str): Where to save the report

    Returns:
        str: Path to the generated report
    """
    # Set up the template environment
    template_dir = os.path.join(os.path.dirname(__file__), 'admin/templates/reports')
    env = Environment(loader=FileSystemLoader(template_dir))

    # Load the template
    template = env.get_template('assessment_report.html')

    # Apply security filtering to data
    filtered_data = sanitize_sensitive_data(assessment_data)

    # Render the template with the data
    html_content = template.render(
        title=filtered_data['title'],
        date=filtered_data['date'],
        target=filtered_data['target'],
        classification=filtered_data['classification'],
        executive_summary=filtered_data['executive_summary'],
        findings=filtered_data['findings'],
        assessor=filtered_data['assessor'],
        methodology=filtered_data['methodology'],
        recommendations=filtered_data['recommendations'],
        appendices=filtered_data.get('appendices', [])
    )

    # Generate the report in the requested format
    if output_format == 'html':
        with open(output_path, 'w') as f:
            f.write(html_content)
        return output_path
    elif output_format == 'pdf':
        pdf = HTML(string=html_content).write_pdf()
        with open(output_path, 'wb') as f:
            f.write(pdf)
        return output_path
    elif output_format == 'docx':
        # Implementation for Word format
        # ...
        pass
```

## Template Variables

The templates use standardized variables that are populated by the report generation functions:

### Common Variables

- `{{author}}` - Report author name
- `{{classification}}` - Document classification level
- `{{date}}` - Report generation date
- `{{document_id}}` - Unique document identifier
- `{{report_status}}` - Report status (Draft, Final, etc.)
- `{{target}}` - Assessment or audit target
- `{{title}}` - Report title
- `{{version}}` - Report version

### Assessment Report Variables

- `{{assessment_date}}` - When the assessment was conducted
- `{{assessment_scope}}` - Scope of the assessment
- `{{assessor}}` - Assessment team or individual
- `{{executive_summary}}` - Executive summary text
- `{{findings}}` - List of security findings
- `{{methodology}}` - Assessment methodology used
- `{{recommendations}}` - Recommended actions

### Audit Report Variables

- `{{audit_period}}` - Time period covered by the audit
- `{{audit_scope}}` - Scope of the audit
- `{{auditor}}` - Audit team or individual
- `{{compliance_framework}}` - Compliance framework reference
- `{{control_results}}` - Control verification results
- `{{evidence_references}}` - References to evidence collected
- `{{non_compliance}}` - Non-compliant items identified

### Compliance Report Variables

- `{{compliance_status}}` - Overall compliance status
- `{{control_framework}}` - Referenced control framework
- `{{control_implementations}}` - Status of control implementations
- `{{gap_analysis}}` - Identified compliance gaps
- `{{remediation_plans}}` - Plans for addressing gaps
- `{{requirements}}` - Applicable regulatory requirements
- `{{validation_method}}` - How compliance was validated

## Customization Guidelines

When customizing report templates:

1. **Maintain Required Elements**
   - Keep the standard header and footer
   - Preserve document classification markings
   - Maintain version history section
   - Keep standard disclaimer text
   - Retain document metadata fields

2. **Follow Formatting Standards**
   - Use defined styles for consistency
   - Apply proper heading hierarchy
   - Use standard table formatting
   - Follow chart and graph guidelines
   - Apply consistent font usage

3. **Address Content Requirements**
   - Ensure all required sections are present
   - Follow section ordering conventions
   - Include appropriate level of detail
   - Provide proper attribution for data
   - Include methodologies used

4. **Test Thoroughly**
   - Verify rendering in all output formats
   - Check pagination in PDF output
   - Test with representative data sets
   - Verify accessibility features
   - Check all dynamic elements

## Best Practices & Security

- **Audience Awareness**: Create reports with the intended audience in mind
- **Classification**: Properly mark reports with appropriate classification
- **Data Minimization**: Include only necessary information
- **Document Controls**: Implement proper document controls and tracking
- **Evidence Handling**: Follow proper handling procedures for evidence
- **Fact-Based Reporting**: Base reports on facts rather than speculation
- **Information Security**: Handle reports according to their classification level
- **Metrics Validation**: Validate all metrics before including in reports
- **Redaction**: Properly redact sensitive information when necessary
- **Secure Distribution**: Follow secure distribution procedures for reports
- **Storage**: Store reports in accordance with retention policies
- **Verification**: Verify all information before inclusion in reports

## Common Features

All report templates include these common elements:

- **Classification Headers**: Security classification markings
- **Cover Page**: Standard title page with required metadata
- **Document Controls**: Version tracking and document management information
- **Executive Summary**: Concise overview of key findings
- **Footer Information**: Classification, page numbers, and document identifiers
- **Header Elements**: Report title, date, and classification
- **Methodology Section**: Description of methods used
- **Page Numbering**: Consistent page numbering format
- **Recommendations**: Clear, actionable recommendations
- **Revision History**: Tracking of document changes
- **Table of Contents**: Auto-generated contents listing
- **Visual Elements**: Charts, graphs, and tables with consistent styling

## Related Documentation

- Assessment Methodology
- Audit Procedures
- Compliance Requirements
- Document Classification Guidelines
- Evidence Handling Guidelines
- Report Components Documentation
- Report Distribution Guidelines
- Reporting Engine Documentation
- Report Review Process
- Risk Rating Methodology
- Template Development Guide
