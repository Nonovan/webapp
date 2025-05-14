# Common Checker Utilities

This directory contains shared utilities and base components for security check implementations in the Cloud Infrastructure Platform. These common components provide the foundation for implementing modular, reliable, and consistent security checks across various domains.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage Examples](#usage-examples)
- [Check Development](#check-development)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The common checker utilities provide a standardized framework for implementing security checks that can be used independently or combined into comprehensive security audits. They handle result formatting, evidence collection, compliance mapping, and remediation guidance in a consistent manner across all security checks, ensuring reliable and actionable security findings.

## Key Components

- **`check_helper.py`**: Helper functions for implementing security checks.
  - **Usage**: Import this module to access common helper functions for security checks.
  - **Features**:
    - Standard file system operations
    - Security configuration parsing
    - Result formatting utilities
    - Resource limitation controls
    - Exception handling patterns
    - Default security thresholds
    - Common security patterns
    - Command execution wrappers

- **`check_result.py`**: Standardized result class for security checks.
  - **Usage**: Import this class to represent security check results consistently.
  - **Features**:
    - Severity classification
    - Finding categorization
    - Evidence attachment
    - Compliance mapping
    - Remediation guidance
    - JSON serialization
    - Markdown formatting
    - HTML report integration
    - Result aggregation
    - Result comparison

- **`check_utils.py`**: General utility functions for security checks.
  - **Usage**: Import this module for reusable security check utility functions.
  - **Features**:
    - Security baseline loading
    - Value comparison utilities
    - Pattern matching functions
    - Secure command execution
    - Permission calculation
    - Secure logging patterns
    - Evidence management
    - String sanitization
    - Compliance helpers
    - Configuration validation

## Directory Structure

```plaintext
scripts/security/audit/checkers/common/
├── README.md                 # This documentation
├── __init__.py               # Package initialization
├── check_helper.py           # Helper functions for check modules
├── check_result.py           # Standardized check result class
└── check_utils.py            # Utility functions for checks
```

## Usage Examples

### Basic Check Implementation

```python
from scripts.security.audit.checkers.common.check_result import CheckResult, Severity
from scripts.security.audit.checkers.common.check_utils import get_file_permissions

def check_secure_directories():
    """Check permissions on security-sensitive directories."""
    results = []

    sensitive_dirs = [
        ("/etc/ssl/private", 0o700),
        ("/var/log/cloud-platform", 0o750)
    ]

    for dir_path, expected_mode in sensitive_dirs:
        actual_mode = get_file_permissions(dir_path)

        if actual_mode > expected_mode:
            results.append(
                CheckResult(
                    severity=Severity.HIGH,
                    title="Insecure Directory Permissions",
                    description=f"Directory {dir_path} has permissions {oct(actual_mode)[2:]} (expected {oct(expected_mode)[2:]})",
                    remediation=f"Fix permissions with: chmod {oct(expected_mode)[2:]} {dir_path}",
                    evidence={"path": dir_path, "actual_mode": oct(actual_mode), "expected_mode": oct(expected_mode)},
                    compliance=["CIS 6.1.2", "NIST AC-3", "PCI-DSS 7.1.1"]
                )
            )

    return results
```

### Working with Check Results

```python
from scripts.security.audit.checkers.common.check_result import CheckResult, Severity

# Create a check result
result = CheckResult(
    severity=Severity.MEDIUM,
    title="Weak Password Policy",
    description="Password policy does not enforce complexity requirements",
    remediation="Update /etc/security/pwquality.conf to enforce stronger passwords",
    evidence={"file": "/etc/security/pwquality.conf", "issues": ["minlen=8", "missing dcredit"]}
)

# Add compliance references
result.add_compliance_references(["CIS 5.3.1", "NIST IA-5"])

# Add additional context
result.add_context("account_types", "system")

# Convert to different formats
json_output = result.to_json()
markdown_output = result.to_markdown()
html_output = result.to_html()
```

### Creating Aggregate Results

```python
from scripts.security.audit.checkers.common.check_result import CheckResultSet

# Create a result set from multiple checks
result_set = CheckResultSet()

# Run multiple checks and add their results
result_set.add_results(check_file_permissions())
result_set.add_results(check_network_security())
result_set.add_results(check_authentication())

# Filter results by severity
high_risk_findings = result_set.filter_by_severity(Severity.HIGH)

# Filter by compliance standard
pci_findings = result_set.filter_by_compliance("PCI-DSS")

# Generate a report
report = result_set.generate_report("security-audit-results")
```

## Check Development

When developing new security checks, follow these guidelines to ensure consistency and integration with the existing framework:

1. **Inherit from Base Classes**: Use the base classes provided in this directory as the foundation for all checks.

2. **Use Standard Severity Levels**: Apply the standard `Severity` enumeration for all findings:
   - `CRITICAL`: Immediate action required, significant risk
   - `HIGH`: Serious vulnerability requiring prompt action
   - `MEDIUM`: Important issue that should be addressed
   - `LOW`: Minor issue that should be fixed when possible
   - `INFO`: Informational finding with minimal security impact

3. **Provide Clear Remediation**: All check results should include specific remediation guidance.

4. **Include Compliance Mappings**: Map findings to relevant compliance standards where applicable.

5. **Collect Evidence**: Gather and attach relevant evidence to support findings.

6. **Handle Errors Gracefully**: Implement proper error handling to ensure checks fail safely.

7. **Test Thoroughly**: Validate checks in various environments before deployment.

8. **Document Assumptions**: Document any assumptions or limitations in check implementation.

## Best Practices & Security

- Design checks to be idempotent and safe to run multiple times
- Include appropriate timeouts to prevent hanging operations
- Always validate inputs before use, especially file paths
- Use secure alternatives to shell commands where possible
- Follow the principle of least privilege for all operations
- Handle sensitive findings with appropriate protections
- Ensure evidence collection excludes sensitive data
- Use atomic file operations when reading configuration files
- Implement performance optimizations for checks on large systems
- Apply appropriate resource limits to prevent denial of service
- Consider the security implications of remediation recommendations
- Test checks against both compliant and non-compliant systems
- Document the security implications of each check

## Common Features

- Standardized result structure across all checks
- Consistent severity classification
- Multiple output formats (JSON, Markdown, HTML)
- Evidence collection and preservation
- Compliance standard mapping
- Clear remediation guidance
- Context-aware security recommendations
- Secure execution patterns
- Resource utilization management
- Error handling and recovery
- Performance optimization
- Finding categorization
- Baseline comparison capabilities
- Result data validation
- Cross-platform compatibility

## Related Documentation

- Check Development Guide
- Severity Classification Standards
- Compliance Mapping Reference
- Evidence Collection Guidelines
- Baseline Configuration Guide
- Security Audit Overview
- Check Module Writing Guide
