# Assessment Templates

This directory contains standardized templates used by the security assessment supporting scripts for report generation, finding documentation, and remediation planning. These templates ensure consistent reporting formats, proper documentation of security findings, and standardized approach to remediation activities across all security assessments.

## Contents

- Overview
- Key Templates
- Template Variables
- Directory Structure
- Usage
- Template Customization
- Best Practices
- Related Documentation

## Overview

The assessment templates provide structured formats for various outputs generated by the security assessment tools. They support multiple report types including executive summaries, technical reports, finding details, and remediation plans. These templates ensure that security findings are documented consistently, with appropriate detail levels for different audiences, and maintain standardized metadata fields for tracking and integration with other security systems.

## Key Templates

- **`executive_summary.md`**: Template for high-level assessment overviews
  - Designed for management and stakeholders
  - Summarizes critical findings and risk levels
  - Provides context and business impact
  - Includes risk metrics and trend analysis
  - Outlines key recommendations

- **`technical_report.md`**: Comprehensive technical assessment report
  - Detailed technical findings for security teams
  - Full methodology documentation
  - Comprehensive finding details
  - Evidence references and validation steps
  - Technical remediation guidance

- **`finding_detail.md`**: Individual security finding documentation
  - Structured format for individual vulnerabilities
  - CVSS scoring and risk classification
  - Detailed reproduction steps
  - Evidence references and screenshots
  - Technical remediation guidance

- **`remediation_plan.md`**: Action plan for addressing findings
  - Prioritized remediation steps
  - Owner assignment structure
  - Timeline guidance
  - Verification criteria
  - Resource requirements estimation

## Template Variables

Templates use standardized variables that are populated by the report generation tools:

### Common Variables

- `{{assessment_id}}` - Unique assessment identifier
- `{{assessment_date}}` - Date of assessment
- `{{assessor}}` - Name of assessment team/individual
- `{{target}}` - Assessment target system or application
- `{{classification}}` - Document classification level
- `{{timestamp}}` - Report generation timestamp

### Executive Summary Variables

- `{{critical_findings_count}}` - Number of critical findings
- `{{high_findings_count}}` - Number of high severity findings
- `{{total_findings_count}}` - Total number of findings
- `{{risk_summary}}` - Overall risk assessment
- `{{key_recommendations}}` - Primary recommendations

### Technical Details Variables

- `{{methodology}}` - Assessment methodology description
- `{{scope}}` - Assessment scope details
- `{{tools}}` - Tools used during assessment
- `{{limitations}}` - Assessment limitations
- `{{findings_list}}` - Detailed list of findings

### Finding-Specific Variables

- `{{finding_id}}` - Unique finding identifier
- `{{finding_title}}` - Finding title
- `{{severity}}` - Severity classification
- `{{cvss_score}}` - CVSS score (if applicable)
- `{{cvss_vector}}` - CVSS vector string
- `{{description}}` - Finding description
- `{{impact}}` - Business impact description
- `{{reproduction_steps}}` - Steps to reproduce
- `{{evidence}}` - References to evidence
- `{{remediation}}` - Remediation guidance

## Directory Structure

```plaintext
admin/security/assessment_tools/supporting_scripts/templates/
├── README.md               # This documentation
├── executive_summary.md    # Executive summary template
├── technical_report.md     # Detailed technical report template
├── finding_detail.md       # Individual finding documentation template
├── remediation_plan.md     # Remediation planning template
├── sections/               # Reusable template sections
│   ├── header.md           # Standard report header
│   ├── methodology.md      # Assessment methodology section
│   ├── risk_rating.md      # Risk rating explanation
│   └── disclaimer.md       # Legal disclaimer text
└── styles/                 # Style definitions for different output formats
    ├── pdf.css             # PDF output styling
    ├── html.css            # HTML output styling
    └── docx.json           # Word document styling
```

## Usage

Templates are used by the `report_generator.py` script to create assessment reports:

```python
from report_generator import ReportGenerator

# Create report generator with assessment data
generator = ReportGenerator(
    assessment_id="SEC-2024-07-15",
    target="customer-portal",
    assessor="Security Assessment Team",
    template_dir="templates"
)

# Generate executive summary
generator.generate_report(
    template="executive_summary.md",
    output="executive_summary.pdf",
    format="pdf"
)

# Generate technical report with all findings
generator.generate_report(
    template="technical_report.md",
    output="technical_report.pdf",
    format="pdf",
    include_all_findings=True
)

# Generate focused report with only high and critical findings
generator.generate_report(
    template="technical_report.md",
    output="critical_findings.pdf",
    format="pdf",
    severity_filter=["critical", "high"]
)
```

## Template Customization

When customizing templates:

1. **Maintain Required Variables**: Ensure all required variables are preserved
2. **Follow Formatting Guidelines**:
   - Use Markdown formatting for consistent rendering across formats
   - Use section headers consistently (# for main headers, ## for sections)
   - Use tables for structured data
3. **Version Control**: Track template changes in version control
4. **Testing**: Test modified templates with the report generator before use
5. **Documentation**: Document any custom variables or sections

## Best Practices

- **Consistency**: Maintain consistent formatting across templates
- **Modularity**: Use the sections directory for reusable content
- **Version Control**: Track template changes in version control
- **Plain Language**: Use clear, concise language in templates
- **Accessibility**: Ensure templates are accessible when converted to different formats
- **Validation**: Regularly validate templates with the report generator
- **Security**: Review templates to ensure they don't include sensitive data by default
- **Branding**: Maintain consistent branding elements across all templates

## Related Documentation

- Security Assessment Methodology
- Report Generator Documentation
- Finding Classification Guide
- CVSS Scoring Reference
- Evidence Handling Guide
