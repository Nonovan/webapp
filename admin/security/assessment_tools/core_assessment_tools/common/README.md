# Common Assessment Components

This directory contains shared utilities and common components used across the security assessment tools in the Cloud Infrastructure Platform. These components provide reusable functionality for security assessments, ensuring consistent behavior, proper security controls, and standardized outputs.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Component Interactions](#component-interactions)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

## Overview

The common components provide a foundation for all security assessment tools, implementing core functionality for assessment execution, result processing, evidence collection, and secure logging. These shared utilities ensure that all assessment tools follow consistent patterns, maintain proper security controls, and generate standardized outputs that can be easily aggregated and analyzed.

## Key Components

- **`assessment_base.py`**: Base classes for assessment tools
  - Common interfaces for all assessment tools
  - Shared assessment state definitions
  - Standardized initialization and cleanup
  - Assessment exception handling
  - Standard result models

- **`assessment_engine.py`**: Core assessment functionality
  - Standardized assessment execution framework
  - Assessment state management
  - Progress tracking and reporting
  - Plugin architecture for assessment modules
  - Consistent error handling and recovery
  - Resource management and cleanup

- **`result_formatter.py`**: Assessment result formatting
  - Structured output generation (JSON, CSV, XML, HTML, Markdown)
  - Finding severity classification
  - CVSS score calculation
  - Compliance mapping support
  - Report template rendering
  - Evidence linking and attachment

- **`output_formatters.py`**: Standalone formatting utilities
  - Individual format conversion functions
  - Multiple output formats (JSON, CSV, XML, HTML, Markdown)
  - Clean separation of formatting logic
  - Content transformation utilities
  - Reusable rendering components

- **`evidence_collector.py`**: Assessment evidence collection
  - Secure evidence gathering and storage
  - Screenshot capture functionality
  - File and configuration extraction
  - Response data collection
  - Evidence chain of custody tracking
  - Evidence metadata management

- **`assessment_logging.py`**: Secure logging functionality
  - Assessment activity audit logging
  - Structured log formats
  - Sensitive data filtering
  - Log integrity protection
  - Log aggregation support
  - Performance impact minimization

- **`connection_manager.py`**: Secure connection handling
  - Authentication and session management
  - Secure credential handling
  - Connection pooling and reuse
  - Protocol-specific connections
  - Timeout and retry handling

- **`data_types.py`**: Common data structures
  - Standardized result and finding models
  - Evidence data structures
  - Target definition models
  - Assessment configuration types
  - Severity and risk classification

- **`error_handlers.py`**: Error handling utilities
  - Standardized exception handling
  - Error categorization and classification
  - Safe recovery patterns
  - Error reporting utilities
  - Exponential backoff implementation

- **`permission_utils.py`**: Permission verification utilities
  - Access control checks
  - Authorization validation
  - Permission model implementation
  - Role-based access checks
  - Capability verification

- **`result_cache.py`**: Result caching implementation
  - Assessment result storage
  - Cache invalidation logic
  - Performance optimization
  - Memory and disk caching
  - Thread-safe access

- **`validation.py`**: Input validation utilities
  - Parameter validation
  - Schema verification
  - Type checking
  - Range and boundary validation
  - Input sanitization

- **`__init__.py`**: Package initialization
  - Module exports
  - Version information
  - Dependency checks
  - Configuration validation
  - Format constants and definitions

## Directory Structure

```plaintext
admin/security/assessment_tools/core_assessment_tools/common/
├── __init__.py               # Package initialization
├── assessment_base.py        # Base assessment classes
├── assessment_engine.py      # Core assessment functionality
├── assessment_logging.py     # Secure logging functionality
├── connection_manager.py     # Secure connection handling
├── data_types.py             # Common data structures
├── error_handlers.py         # Error handling utilities
├── evidence_collector.py     # Assessment evidence collection
├── output_formatters.py      # Output formatting utilities
├── permission_utils.py       # Permission verification utilities
├── README.md                 # This documentation
├── result_cache.py           # Result caching implementation
├── result_formatter.py       # Assessment result formatting
└── validation.py             # Input validation utilities
```

## Component Interactions

The common components work together in a cohesive architecture, with well-defined responsibilities and interfaces:

```plaintext
┌─────────────────────────────┐
│     Assessment Engine       │
│  (orchestrates assessment)  │
└───────────────┬─────────────┘
                │
        ┌───────┴────────┐
        │                │
┌───────▼──────┐   ┌─────▼────────┐     ┌───────────────┐
│ Assessment   │   │ Evidence      │────▶│ Result Cache  │
│ Base Classes │   │ Collector     │     │               │
└──────────────┘   └──────┬────────┘     └───────┬───────┘
                          │                      │
                   ┌──────▼────────┐     ┌──────▼────────┐
                   │ Connection    │     │ Result        │
                   │ Manager       │     │ Formatter     │
                   └──────┬────────┘     └──────┬────────┘
                          │                      │
┌──────────────┐   ┌──────▼────────┐     ┌──────▼────────┐
│ Permission   │◀──┤ Validation    │     │ Output        │
│ Utils        │   │ Utils         │     │ Formatters    │
└──────────────┘   └───────────────┘     └───────────────┘
        ▲                  ▲
        │                  │
┌───────┴──────┐   ┌──────┴────────┐
│ Error        │   │ Assessment    │
│ Handlers     │   │ Logging       │
└──────────────┘   └───────────────┘
```

Key interactions include:

- **Assessment Engine** coordinates all assessment operations and manages the lifecycle
- **Evidence Collector** gathers and stores assessment evidence with secure chain of custody
- **Connection Manager** handles secure connections to assessment targets
- **Result Formatter** processes assessment findings into standardized formats
- **Validation** ensures all inputs and configurations meet security requirements
- **Permission Utils** enforces proper access controls for all operations
- **Error Handlers** provide consistent, secure error management patterns

## Configuration

The common components use configuration from the parent assessment tools directory:

```python
# Example of configuration loading in common components
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

def get_config_path() -> Path:
    """Get the path to configuration files."""
    # Start with current directory and navigate to config files
    current_dir = Path(__file__).parent
    config_path = current_dir.parent.parent / "config_files"

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration directory not found: {config_path}")

    return config_path

def load_common_config() -> Dict[str, Any]:
    """Load common configuration used by all assessment components."""
    config_path = get_config_path() / "common_config.json"

    if not config_path.exists():
        raise FileNotFoundError(f"Common configuration file not found: {config_path}")

    with open(config_path, 'r') as f:
        return json.load(f)

def get_evidence_storage_path() -> Path:
    """Get the path for storing assessment evidence."""
    config = load_common_config()
    base_path = Path(config.get('evidence_storage_path', '/tmp/assessment_evidence'))

    # Create directory if it doesn't exist
    os.makedirs(base_path, exist_ok=True)

    return base_path
```

## Security Features

- **Authentication**: Components verify caller authentication before executing sensitive operations
- **Least Privilege**: Functions operate with minimal required permissions
- **Input Validation**: All inputs are validated before processing
- **Output Sanitization**: Sensitive data is filtered from outputs and logs
- **Evidence Protection**: Assessment evidence is securely stored with integrity verification
- **Audit Logging**: All component operations are logged for accountability
- **Secure Defaults**: Conservative defaults requiring explicit opt-in for invasive operations
- **Rate Limiting**: Built-in protection against resource exhaustion
- **Error Handling**: Secure error handling preventing information leakage
- **Secure Cleanup**: Guaranteed resource cleanup even during exceptions
- **Log Integrity**: Tamper-evident logging with secure chain of custody
- **Circuit Breakers**: Protection against cascading failures during assessment
- **Data Encryption**: Sensitive assessment data is encrypted at rest
- **Non-repudiation**: Signed evidence collection with verifiable timestamps

## Usage Examples

### Assessment Engine

```python
from common.assessment_engine import AssessmentEngine, AssessmentTarget
from common.assessment_logging import setup_assessment_logging

# Setup assessment logging
logger = setup_assessment_logging("vulnerability_scan")

# Create assessment target
target = AssessmentTarget(
    target_id="web-server-01",
    target_type="server",
    ip_address="10.0.0.15",
    hostname="web-server-01.example.com"
)

# Create and run assessment
assessment = AssessmentEngine(
    name="Vulnerability Scan",
    target=target,
    profile_name="production",
    output_format="detailed",
    non_invasive=True
)

try:
    assessment.initialize()
    assessment.run()
    results = assessment.get_results()
    assessment.cleanup()
except Exception as e:
    logger.error("Assessment failed: %s", str(e))
    assessment.cleanup()
```

### Evidence Collection

```python
from common.evidence_collector import EvidenceCollector
from datetime import datetime

# Create evidence collector for an assessment
collector = EvidenceCollector(
    assessment_id="vuln-scan-20240712-01",
    target_id="db-server-03",
    assessor="security-team"
)

# Collect various types of evidence
collector.collect_file("/etc/nginx/nginx.conf")
collector.collect_command_output("netstat -tuln")
collector.collect_screenshot("login_page")
collector.add_text_evidence("Found unencrypted password in config file",
                           severity="critical")

# Finalize and get evidence report
evidence_report = collector.finalize()
evidence_path = collector.get_evidence_path()
```

### Result Formatting

```python
from common.result_formatter import ResultFormatter
from common.data_types import AssessmentResult

# Format assessment results
formatter = ResultFormatter()
formatted_results = formatter.format(
    results=assessment_results,
    format_type="json",
    include_evidence=True,
    filter_severity=["critical", "high"],
    compliance_map=["pci-dss", "nist"],
)

# Write results to file
formatter.write_to_file(
    formatted_results,
    "/var/reports/assessment-2024-07-15.json"
)

# Generate executive summary
summary = formatter.generate_summary(assessment_results)
```

### Output Formatters

```python
from common.output_formatters import format_json_output, format_html_output, write_to_file

# Format data as JSON
findings_data = [
    {"id": "VULN-001", "title": "SQL Injection", "severity": "critical"},
    {"id": "VULN-002", "title": "XSS Vulnerability", "severity": "high"}
]

# Format as JSON
json_output = format_json_output(findings_data, indent=2)

# Format as HTML
html_output = format_html_output(
    {"findings": findings_data},
    title="Security Assessment Findings",
    include_css=True
)

# Write to file
write_to_file(html_output, "/var/reports/findings.html")
```

### Format Conversion

```python
from common.result_formatter import ResultFormatter

# Create formatter instance
formatter = ResultFormatter()

# Convert between formats
with open('assessment-results.json', 'r') as f:
    json_content = f.read()

# Convert JSON to other formats
html_content = formatter.convert_format(json_content, "json", "html")
markdown_content = formatter.convert_format(json_content, "json", "markdown")
csv_content = formatter.convert_format(json_content, "json", "csv")

# Write converted content to files
with open('assessment-results.html', 'w') as f:
    f.write(html_content)
```

### Secure Connections

```python
from common.connection_manager import ConnectionManager, ConnectionTarget

# Create connection manager with secure defaults
manager = ConnectionManager(
    verify_ssl=True,
    timeout=30,
    retries=3,
    cert_path="/path/to/client.cert"
)

# Create connection target
target = ConnectionTarget(
    hostname="database.example.com",
    port=5432,
    protocol="postgresql",
    auth_method="certificate"
)

# Establish secure connection
with manager.connect(target) as conn:
    results = conn.execute("SELECT version();")
    manager.log_connection_event(target, "Database version check", success=True)
```

## Best Practices

- **Component Re-use**: Use these shared components rather than duplicating functionality
- **Error Handling**: Always use try/except blocks when calling component methods
- **Resource Cleanup**: Call cleanup methods even when exceptions occur
- **Configuration Validation**: Validate configuration before beginning assessment
- **Evidence Collection**: Collect evidence methodically with proper documentation
- **Sensitive Data**: Never log credentials or sensitive configuration details
- **Access Control**: Verify user permissions before running assessments
- **Rate Limiting**: Implement appropriate delays for scanning operations
- **Integration**: Follow the established patterns when integrating with other tools
- **Defense in Depth**: Apply multiple security controls for critical operations
- **Timeout Management**: Always implement appropriate timeouts for external operations
- **Centralized Authentication**: Use the connection manager for all target system access
- **Content Validation**: Validate all content from assessment targets before processing

## Related Documentation

- Security Assessment Methodology
- Assessment Tools User Guide
- Security Baseline Management
- Vulnerability Management Process
- Compliance Framework Documentation
- Evidence Handling Guide
- Reporting Format Standards
- Output Format Specification
- Secure Coding Guidelines
- Assessment Plugin Development
- Assessment Workflow Automation
- Assessment Tool Integration API
- CVSS Scoring Implementation
