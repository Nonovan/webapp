# Supporting Scripts for Security Assessment

This directory contains supporting scripts and utilities used across the security assessment tools in the Cloud Infrastructure Platform. These scripts provide standardized functionality that enhances the core assessment capabilities, including report generation, finding management, evidence handling, and assessment coordination.

## Contents

- Overview
- Key Components
- Directory Structure
- Configuration
- Security Features
- Usage Examples
- Best Practices
- Related Documentation

## Overview

The supporting scripts enhance the core assessment tools by providing shared functionality for report generation, finding classification, evidence collection, remediation tracking, and assessment coordination. They ensure consistent approaches to handling assessment data, generating standardized outputs, and coordinating remediation activities across the organization.

## Key Components

- **`assessment_utils.py`**: Shared utilities for assessment tools
  - Configuration management
  - Assessment state handling
  - Resource discovery
  - Input validation
  - Format conversion
  - Assessment metadata management

- **`report_generator.py`**: Creates standardized security assessment reports
  - Template-based report generation
  - Multiple format support (PDF, HTML, Markdown, CSV)
  - Executive summary creation
  - Technical finding details
  - Risk scoring visualization
  - Compliance mapping

- **`finding_classifier.py`**: Classifies and prioritizes security findings
  - CVSS scoring implementation
  - Risk level assignment
  - Finding categorization
  - Business impact assessment
  - Compliance impact mapping
  - Remediation priority calculation

- **`remediation_tracker.py`**: Tracks remediation status for identified issues
  - Finding lifecycle management
  - SLA tracking and alerting
  - Remediation status reporting
  - Assignment and ownership tracking
  - Verification process management
  - Integration with ticketing systems

- **`evidence_collector.py`**: Securely collects and stores assessment evidence
  - Secure evidence acquisition
  - Proper chain of custody
  - Metadata tagging
  - Evidence validation
  - Secure storage management
  - Evidence retrieval interface

- **`assessment_coordinator.py`**: Coordinates multi-component assessments
  - Assessment scheduling
  - Component orchestration
  - Progress monitoring
  - Resource allocation
  - Result aggregation
  - Multi-tool assessment coordination

## Directory Structure

```plaintext
admin/security/assessment_tools/supporting_scripts/
├── assessment_utils.py           # Shared assessment utilities
├── report_generator.py           # Report generation engine
├── finding_classifier.py         # Finding classification and prioritization
├── remediation_tracker.py        # Remediation status tracking
├── evidence_collector.py         # Evidence collection and management
├── assessment_coordinator.py     # Assessment coordination functionality
├── README.md                     # This documentation
└── templates/                    # Report and output templates
    ├── executive_summary.md      # Executive summary template
    ├── technical_report.md       # Technical report template
    ├── finding_detail.md         # Individual finding template
    └── remediation_plan.md       # Remediation plan template
```

## Configuration

Supporting scripts use shared configuration from the parent directory:

```python
import os
from pathlib import Path
import json
import logging

def get_config_path():
    """Get path to configuration files."""
    current_dir = Path(__file__).parent
    config_path = current_dir.parent / "config_files"

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration directory not found: {config_path}")

    return config_path

def load_report_templates():
    """Load report templates for the report generator."""
    template_dir = Path(__file__).parent / "templates"

    templates = {}
    for template_file in template_dir.glob("*.md"):
        template_name = template_file.stem
        with open(template_file, 'r') as f:
            templates[template_name] = f.read()

    return templates

def setup_logging(module_name):
    """Set up secure logging for assessment scripts."""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=os.environ.get('LOG_LEVEL', 'INFO'),
        format=log_format,
        handlers=[
            logging.FileHandler(f"/var/log/security/assessment/{module_name}.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(module_name)
```

## Security Features

- **Secure Evidence Handling**: All evidence is collected with proper chain of custody
- **Data Protection**: Sensitive findings are encrypted at rest and in transit
- **Access Control**: Scripts implement role-based access control for reports and findings
- **Input Validation**: All inputs are validated before processing
- **Audit Logging**: All script operations are logged for accountability
- **Secure Defaults**: Scripts use secure default settings
- **Error Handling**: Secure error handling prevents information leakage
- **Authentication**: Operations require proper authentication
- **Integrity Verification**: Evidence and findings include integrity verification
- **Data Sanitization**: Reports are sanitized to remove sensitive information

## Usage Examples

### Report Generation

```python
from report_generator import ReportGenerator
from datetime import datetime

# Create report generator with assessment data
generator = ReportGenerator(
    assessment_id="sec-assess-20240712-01",
    target="web-application",
    assessor="security-team",
    timestamp=datetime.now()
)

# Add findings
generator.add_finding({
    "id": "CVE-2024-12345",
    "title": "Cross-Site Scripting Vulnerability",
    "description": "Input validation issue allows XSS attacks",
    "severity": "high",
    "cvss_score": 7.6,
    "affected_components": ["login-form", "search-function"],
    "remediation": "Implement proper input sanitization"
})

# Generate reports in different formats
generator.generate_report(format="pdf", output_path="security-report.pdf")
generator.generate_executive_summary(output_path="executive-summary.md")
```

### Finding Classification

```python
from finding_classifier import FindingClassifier

classifier = FindingClassifier()

# Classify finding based on details
classification = classifier.classify_finding({
    "type": "sql_injection",
    "authentication_required": False,
    "affected_data": "customer_records",
    "exploitability": "easy",
    "affected_systems": ["payment_processing"]
})

print(f"Risk Level: {classification['risk_level']}")
print(f"CVSS Score: {classification['cvss_score']}")
print(f"Priority: {classification['priority']}")
print(f"Compliance Impact: {classification['compliance_impact']}")
```

### Remediation Tracking

```python
from remediation_tracker import RemediationTracker

tracker = RemediationTracker(
    assessment_id="sec-assess-20240712-01",
    integration={"jira": {"url": "https://jira.example.com", "project": "SEC"}}
)

# Create remediation task
task_id = tracker.create_task(
    finding_id="CVE-2024-12345",
    title="Fix XSS in login form",
    description="Implement input sanitization to prevent XSS",
    severity="high",
    owner="development-team",
    due_date="2024-07-30"
)

# Update remediation status
tracker.update_status(task_id, status="in_progress", notes="Fix implemented in PR #123")

# Generate remediation status report
report = tracker.generate_status_report(format="html")
```

## Best Practices

- **Standardized Reporting**: Always use the report templates for consistent outputs
- **Evidence Management**: Maintain proper chain of custody for all collected evidence
- **Secure Storage**: Store assessment artifacts in properly secured locations
- **Integration**: Integrate with ticketing systems for efficient remediation tracking
- **Audit Trail**: Maintain detailed logs of all assessment activities
- **Classification**: Properly classify findings to prioritize remediation efforts
- **Verification**: Always verify remediation before closing findings
- **Documentation**: Document all assessment procedures and decisions
- **Access Control**: Restrict access to assessment results based on need-to-know
- **Data Sanitization**: Remove sensitive information before sharing reports

## Related Documentation

- Security Assessment Methodology
- Assessment Tools User Guide
- Finding Classification Guide
- Remediation Process
- Evidence Handling Guide
- Report Templates Guide
