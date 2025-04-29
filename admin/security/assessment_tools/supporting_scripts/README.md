# Supporting Scripts for Security Assessment

This directory contains supporting scripts and utilities used across the security assessment tools in the Cloud Infrastructure Platform. These scripts provide standardized functionality that enhances the core assessment capabilities, including report generation, finding management, evidence handling, and assessment coordination.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

## Overview

The supporting scripts enhance the core assessment tools by providing shared functionality for report generation, finding classification, evidence collection, remediation tracking, and assessment coordination. They ensure consistent approaches to handling assessment data, generating standardized outputs, and coordinating remediation activities across the organization.

## Key Components

- **`assessment_utils.py`**: Shared utilities for assessment tools
  - Configuration management
  - Assessment state handling
  - Resource discovery and enumeration
  - Input validation and sanitization
  - Format conversion and standardization
  - Assessment metadata management
  - Common security functions
  - Error handling utilities

- **`report_generator.py`**: Creates standardized security assessment reports
  - Template-based report generation
  - Multiple format support (PDF, HTML, Markdown, CSV)
  - Executive summary creation
  - Technical finding details
  - Risk scoring visualization
  - Compliance control mapping
  - Evidence integration
  - Custom branding options
  - Report encryption and access control

- **`finding_classifier.py`**: Classifies and prioritizes security findings
  - CVSS scoring implementation
  - Risk level assignment
  - Finding categorization
  - Business impact assessment
  - Compliance impact mapping
  - Remediation priority calculation
  - Custom classification rules
  - Risk scoring algorithms
  - Trend analysis capabilities

- **`remediation_tracker.py`**: Tracks remediation status for identified issues
  - Finding lifecycle management
  - SLA tracking and alerting
  - Remediation status reporting
  - Assignment and ownership tracking
  - Verification process management
  - Integration with ticketing systems
  - Escalation management
  - Progress metrics and analytics
  - Historical trend analysis

- **`evidence_collector.py`**: Securely collects and stores assessment evidence
  - Secure evidence acquisition
  - Proper chain of custody
  - Metadata tagging
  - Evidence validation
  - Secure storage management
  - Evidence retrieval interface
  - Cryptographic verification
  - Tamper detection
  - Retention policy enforcement

- **`assessment_coordinator.py`**: Coordinates multi-component assessments
  - Assessment scheduling
  - Component orchestration
  - Progress monitoring
  - Resource allocation
  - Result aggregation
  - Multi-tool assessment coordination
  - Dependency management
  - Parallel execution optimization
  - Assessment notifications

## Directory Structure

```plaintext
admin/security/assessment_tools/supporting_scripts/
├── README.md                     # This documentation
├── assessment_coordinator.py     # Assessment coordination functionality
├── assessment_utils.py           # Shared assessment utilities
├── evidence_collector.py         # Evidence collection and management
├── finding_classifier.py         # Finding classification and prioritization
├── remediation_tracker.py        # Remediation status tracking
├── report_generator.py           # Report generation engine
└── templates/                    # Report and output templates
    ├── executive_summary.md      # Executive summary template
    ├── finding_detail.md         # Individual finding template
    ├── remediation_plan.md       # Remediation plan template
    ├── sections/                 # Reusable template sections
    │   ├── disclaimer.md         # Legal disclaimer text
    │   ├── header.md             # Standard report header
    │   ├── methodology.md        # Assessment methodology section
    │   └── risk_rating.md        # Risk rating explanation
    ├── styles/                   # Style definitions for output formats
    │   ├── docx.json             # Word document styling
    │   ├── html.css              # HTML output styling
    │   └── pdf.css               # PDF output styling
    └── technical_report.md       # Technical report template
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

def load_assessment_profile(profile_name, compliance_addon=None):
    """Load assessment profile with optional compliance addon."""
    config_path = get_config_path()
    profiles_dir = config_path / "assessment_profiles"

    # Load base profile
    profile_path = profiles_dir / f"{profile_name}.json"
    with open(profile_path, "r") as f:
        profile = json.load(f)

    # Load compliance addon if specified
    if compliance_addon:
        compliance_path = profiles_dir / "compliance" / f"{compliance_addon}.json"
        with open(compliance_path, "r") as f:
            compliance_profile = json.load(f)

        # Merge profiles with compliance requirements taking precedence
        profile = deep_merge(profile, compliance_profile)

    return profile
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
- **Non-Repudiation**: Cryptographic signatures for assessment outputs
- **Principle of Least Privilege**: Access to functions and data is restricted
- **Secure Coding Practices**: Follows OWASP secure coding guidelines
- **Defense in Depth**: Multiple layers of security controls
- **Secure Communication**: All remote communications are encrypted

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

# Generate compliance-mapped report
generator.generate_compliance_report(
    compliance_standard="pci-dss",
    controls_mapping={"CVE-2024-12345": ["6.5.7"]},
    output_path="pci-compliance-report.pdf"
)
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

# Classify multiple findings from assessment output
with open('vulnerability_scan_results.json', 'r') as f:
    findings = json.load(f)

classified_findings = classifier.classify_findings_batch(
    findings,
    environment="production",
    business_context={"critical_systems": ["payment_processing", "user_database"]}
)

# Export classification results
with open('classified_findings.json', 'w') as f:
    json.dump(classified_findings, f, indent=2)
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

# Track SLA compliance
overdue_items = tracker.get_overdue_items()
if overdue_items:
    tracker.send_alerts(overdue_items)

# Verify remediation for a task
verification_result = tracker.verify_remediation(
    task_id,
    evidence={"commit_id": "abc123", "test_results": "passed"},
    verifier="security-team-member"
)

if verification_result["status"] == "verified":
    tracker.close_task(task_id, resolution="fixed")
```

### Evidence Collection

```python
from evidence_collector import EvidenceCollector

collector = EvidenceCollector(
    assessment_id="sec-assess-20240712-01",
    storage_path="/secure/evidence/"
)

# Collect configuration evidence
config_evidence_id = collector.collect_configuration(
    target_system="web-server-01",
    config_type="web_server",
    method="api"
)

# Collect network evidence
network_evidence_id = collector.collect_network_traffic(
    target_system="web-server-01",
    duration=120,
    filter_expression="port 443"
)

# Store screenshot evidence
screenshot_evidence_id = collector.store_file_evidence(
    file_path="/tmp/vulnerability-screenshot.png",
    evidence_type="screenshot",
    description="XSS vulnerability demonstration",
    metadata={"finding_id": "CVE-2024-12345"}
)

# Add chain of custody entry
collector.add_custody_entry(
    evidence_id=screenshot_evidence_id,
    action="analysis",
    performed_by="security-analyst",
    notes="Initial analysis completed"
)

# Retrieve evidence for reporting
evidence_items = collector.get_evidence_for_finding("CVE-2024-12345")
evidence_package = collector.create_evidence_package(evidence_items)
```

### Assessment Coordination

```python
from assessment_coordinator import AssessmentCoordinator

coordinator = AssessmentCoordinator(
    assessment_id="sec-assess-20240712-01",
    assessment_profile="production",
    compliance_standard="pci-dss"
)

# Define assessment components
coordinator.add_component("vulnerability_scan", target="payment-system")
coordinator.add_component("configuration_analysis", target="payment-system")
coordinator.add_component("access_control_audit", target="payment-system")

# Set component dependencies
coordinator.add_dependency("access_control_audit", "vulnerability_scan")

# Configure notifications
coordinator.set_notification_config({
    "on_start": ["security-team@example.com"],
    "on_complete": ["security-team@example.com", "compliance@example.com"],
    "on_error": ["security-ops@example.com"]
})

# Execute assessment
assessment_results = coordinator.execute()

# Monitor progress
while not coordinator.is_complete():
    status = coordinator.get_status()
    print(f"Progress: {status['percent_complete']}%")
    time.sleep(30)

# Generate consolidated report
consolidated_report = coordinator.generate_consolidated_report()
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
- **Regular Updates**: Keep classification rules and templates current with evolving standards
- **Contextual Risk**: Consider business context when classifying findings
- **Metrics Tracking**: Monitor remediation effectiveness over time
- **Cross-Validation**: Use multiple tools to validate critical findings
- **Continuous Improvement**: Regularly review and enhance assessment processes

## Related Documentation

- Security Assessment Methodology
- Assessment Tools User Guide
- Finding Classification Guide
- Remediation Process
- Evidence Handling Guide
- Report Templates Guide
- Compliance Framework Documentation
- Security Control Verification
- Assessment API Documentation
- Integration Points Guide
