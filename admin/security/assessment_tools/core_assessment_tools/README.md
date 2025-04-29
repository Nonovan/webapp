# Core Assessment Tools

This directory contains the primary security assessment tools for the Cloud Infrastructure Platform. These tools provide comprehensive security evaluation capabilities including vulnerability scanning, configuration analysis, network testing, and access control validation.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Installation and Setup](#installation-and-setup)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [Integration Points](#integration-points)
- [Troubleshooting](#troubleshooting)
- [Related Documentation](#related-documentation)

## Overview

Core assessment tools provide security teams with the necessary capabilities to evaluate the security posture of systems, applications, and infrastructure components. These tools follow industry best practices for security assessment methodology and are designed to be integrated into both scheduled security evaluations and incident response procedures.

The tools work together to provide comprehensive security coverage:

- **Vulnerability Management**: Identify, categorize, and prioritize security vulnerabilities
- **Configuration Validation**: Verify system configurations against security baselines
- **Network Security**: Evaluate network security controls and protections
- **Access Control**: Validate permission models and identify authorization issues
- **Application Security**: Analyze code and dependencies for security vulnerabilities
- **Authentication Security**: Test password policies and credential management

## Key Components

- **`vulnerability_scanner.py`**: Automated vulnerability identification
  - CVE detection across system components
  - Configuration weakness identification
  - Misconfigurations and security policy violations
  - Remediation prioritization based on risk
  - Plugin-based architecture for custom checks
  - Integration with vulnerability intelligence feeds
  - False positive reduction algorithms
  - Non-disruptive scanning capabilities

- **`configuration_analyzer.py`**: System configuration assessment
  - Security baseline comparison engine
  - Hardening validation against CIS benchmarks
  - Configuration drift detection
  - Policy compliance checking
  - Detailed remediation guidance
  - Historical configuration tracking
  - Customizable configuration checks
  - Multi-system consistency validation

- **`network_security_tester.py`**: Network security evaluation
  - Firewall rule validation
  - Network segmentation verification
  - Secure communication enforcement
  - Unauthorized access path detection
  - Protocol security verification
  - Network topology analysis
  - Connectivity mapping
  - Traffic pattern analysis

- **`access_control_auditor.py`**: Access control validation
  - Permission model validation
  - Least privilege enforcement checking
  - Role separation analysis
  - Privilege escalation path detection
  - Cross-service permission evaluation
  - Access control visualization
  - Unauthorized access attempt simulation
  - Dynamic permission testing

- **`code_security_analyzer.py`**: Application security assessment
  - Static code analysis with security focus
  - Secure coding practice validation
  - Security vulnerability pattern detection
  - Dependency scanning for known vulnerabilities
  - Language-specific security rule engines
  - Custom rule development framework
  - SAST/SCA integration capabilities
  - Secure code pattern recommendation

- **`password_strength_tester.py`**: Authentication security validation
  - Password policy enforcement validation
  - Credential strength assessment
  - Brute force resistance testing
  - Password storage security verification
  - Authentication system integration
  - Multi-factor authentication validation
  - Account lockout verification
  - Password reset flow security testing

## Directory Structure

```plaintext
admin/security/assessment_tools/core_assessment_tools/
├── README.md                     # This documentation
├── access_control_auditor.py     # Access control validation tool
├── code_security_analyzer.py     # Application security assessment tool
├── common/                       # Shared components
│   ├── __init__.py               # Package initialization
│   ├── assessment_base.py        # Base assessment classes
│   ├── assessment_engine.py      # Core assessment functionality
│   ├── assessment_logging.py     # Secure logging functionality
│   ├── connection_manager.py     # Secure connection handling
│   ├── data_types.py             # Common data structures
│   ├── error_handlers.py         # Error handling utilities
│   ├── evidence_collector.py     # Assessment evidence collection
│   ├── output_formatters.py      # Output formatting utilities
│   ├── permission_utils.py       # Permission verification utilities
│   ├── result_cache.py           # Result caching implementation
│   ├── result_formatter.py       # Assessment result formatting
│   └── validation.py             # Input validation utilities
├── configuration_analyzer.py     # Configuration assessment tool
├── network_security_tester.py    # Network security evaluation tool
├── password_strength_tester.py   # Authentication security validation tool
└── vulnerability_scanner.py      # Vulnerability identification tool
```

## Installation and Setup

### Prerequisites

- Python 3.8 or higher
- Required Python packages (installed via requirements.txt in parent directory)
- Appropriate access permissions for target systems

### Initial Setup

1. Ensure all dependencies are installed:

   ```bash
   pip install -r ../requirements.txt
   ```

2. Verify tool availability:

   ```bash
   python3 vulnerability_scanner.py --version
   ```

3. Configure authentication credentials:

   ```bash
   # Set environment variables for tool authentication
   export ASSESSMENT_TOOLS_API_KEY="your_api_key"
   export ASSESSMENT_TOOLS_CERT_PATH="/path/to/client/certificate"
   ```

4. Test connection to authentication service:

   ```bash
   python3 -c "from common.connection_manager import test_connection; test_connection()"
   ```

## Configuration

Assessment tools use configuration files from the parent directory. Key configuration points:

```python
# Example configuration usage
from pathlib import Path
import json
import logging
from common.assessment_logging import setup_logging

# Set up secure logging
logger = setup_logging("configuration_loader")

def load_assessment_profile(profile_name):
    """Load assessment profile configuration."""
    try:
        profile_path = Path('../config_files/assessment_profiles') / f"{profile_name}.json"

        if not profile_path.exists():
            logger.error(f"Assessment profile {profile_name} not found at {profile_path}")
            raise FileNotFoundError(f"Assessment profile {profile_name} not found")

        with open(profile_path, 'r') as f:
            profile_data = json.load(f)
            logger.info(f"Successfully loaded assessment profile: {profile_name}")
            return profile_data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in profile {profile_name}: {str(e)}")
        raise ValueError(f"Invalid assessment profile format: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to load profile {profile_name}: {str(e)}")
        raise

def load_security_baseline(system_type):
    """Load security baseline for comparison."""
    try:
        baseline_path = Path('../config_files/security_baselines') / f"{system_type}_baseline.json"

        if not baseline_path.exists():
            logger.error(f"Security baseline for {system_type} not found at {baseline_path}")
            raise FileNotFoundError(f"Security baseline for {system_type} not found")

        with open(baseline_path, 'r') as f:
            baseline_data = json.load(f)
            logger.info(f"Successfully loaded security baseline: {system_type}")
            return baseline_data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in baseline {system_type}: {str(e)}")
        raise ValueError(f"Invalid security baseline format: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to load baseline {system_type}: {str(e)}")
        raise
```

### Configuration Override Options

All tools support the following configuration override options:

| Option | Description | Example |
|--------|-------------|---------|
| `--config-file` | Use a custom config file | `--config-file /path/to/custom-config.json` |
| `--profile` | Use a specific assessment profile | `--profile production` |
| `--compliance` | Add compliance requirements | `--compliance pci-dss` |
| `--log-level` | Set logging verbosity | `--log-level debug` |
| `--non-invasive` | Use only non-invasive tests | `--non-invasive` |
| `--output-format` | Set output format | `--output-format json` |
| `--output-file` | Set output file | `--output-file results.json` |

## Security Features

- **Authentication Required**: Tools require appropriate authentication before execution
- **Least Privilege Operation**: Each tool operates with minimal required permissions
- **Secure Evidence Handling**: Assessment data is securely stored with encryption (AES-256)
- **Non-Invasive Testing**: Default mode uses non-disruptive testing methods
- **Audit Logging**: All assessment activities are comprehensively logged with tamper-evident trails
- **Network Isolation**: Option to operate in isolated network environments
- **Safe Defaults**: Conservative testing by default with explicit opt-in for invasive operations
- **Data Sanitization**: Results are sanitized to remove sensitive information
- **Role-Based Access Controls**: Different assessment capabilities based on user role
- **Input Validation**: All input parameters are validated to prevent injection attacks
- **Certificate Validation**: Strict certificate validation for all TLS connections
- **Rate Limiting**: Built-in rate limiting to prevent service disruption
- **Connection Timeouts**: Appropriate timeouts to prevent resource exhaustion
- **Secure Error Handling**: Error messages designed not to leak sensitive information

## Usage Examples

### Vulnerability Scanning

```bash
# Run a vulnerability scan against a specific target
./vulnerability_scanner.py --target web-server-01 --profile production

# Run a comprehensive scan with detailed findings
./vulnerability_scanner.py --target database-cluster \
  --profile comprehensive --output-format detailed

# Run a scan focused on a specific vulnerability class
./vulnerability_scanner.py --target api-servers \
  --profile api-security --vuln-class injection

# Exclude specific vulnerability checks
./vulnerability_scanner.py --target payment-systems \
  --profile production --exclude-checks sql-injection,xss

# Scan multiple targets defined in a file
./vulnerability_scanner.py --target-file targets.txt \
  --profile production --output-format json --output-file scan-results.json

# Perform a low-impact scan during business hours
./vulnerability_scanner.py --target production-services \
  --non-invasive --business-hours --output-format json
```

### Configuration Analysis

```bash
# Compare system configuration against baseline
./configuration_analyzer.py --target application-server-01 \
  --baseline web_server_baseline

# Check for compliance with specific standard
./configuration_analyzer.py --target database-01 \
  --compliance pci-dss

# Find configuration drift across environment
./configuration_analyzer.py --target-group production-web \
  --detect-drift

# Analyze against multiple security baselines
./configuration_analyzer.py --target api-gateway \
  --baseline api_gateway_baseline,security_gateway_baseline \
  --output-format detailed

# Validate only critical security controls
./configuration_analyzer.py --target payment-processing \
  --critical-only --compliance pci-dss

# Generate remediation guidance for failed checks
./configuration_analyzer.py --target auth-service \
  --baseline identity_service_baseline --remediation-guidance \
  --output-format html --output-file remediation.html
```

### Network Security Testing

```bash
# Validate firewall rules
./network_security_tester.py --target dmz-segment \
  --test-type firewall --profile production

# Test network segmentation
./network_security_tester.py --target production-network \
  --test-type segmentation --detailed-mapping

# Verify secure communication requirements
./network_security_tester.py --target-group payment-services \
  --test-type encryption --protocols tls,ssh,ipsec

# Check for unexpected open ports
./network_security_tester.py --target web-servers \
  --test-type port-scan --expected-services "80,443,22"

# Test DNS security configurations
./network_security_tester.py --target dns-servers \
  --test-type dns-security --include-dnssec
```

### Access Control Validation

```bash
# Validate access control implementation
./access_control_auditor.py --application customer-portal \
  --validate-all

# Look for privilege escalation paths
./access_control_auditor.py --role standard-user \
  --find-escalation-paths --output-format detailed

# Verify proper role separation
./access_control_auditor.py --application financial-system \
  --validate-separation-of-duties --compliance soc2

# Test for overprivileged accounts
./access_control_auditor.py --scope all-services \
  --find-excessive-permissions --risk-threshold high

# Validate cross-service permissions
./access_control_auditor.py --role api-service-account \
  --cross-service-analysis --output-format json
```

### Code Security Analysis

```bash
# Analyze Python application code
./code_security_analyzer.py --target ./src \
  --language python --ruleset owasp-top-10

# Scan JavaScript code with custom rules
./code_security_analyzer.py --target ./web-frontend \
  --language javascript --custom-rules ../config_files/custom_rules/javascript_rules.json

# Analyze code with dependency scanning
./code_security_analyzer.py --target ./payment-service \
  --scan-dependencies --output-format html --output-file code-scan-results.html

# Fail CI pipeline on severe findings
./code_security_analyzer.py --target ./authentication-service \
  --fail-level high --output-format sarif --output-file code-findings.sarif

# Analyze code with specific focus areas
./code_security_analyzer.py --target ./banking-api \
  --focus-areas "input-validation,authentication,encryption" --detailed-output
```

### Password Security Testing

```bash
# Test password policy compliance
./password_strength_tester.py --target auth-service \
  --policy-test --compliance pci-dss

# Check for default or weak credentials
./password_strength_tester.py --target admin-interfaces \
  --check-defaults --wordlist ../config_files/wordlists/common-passwords.txt

# Test password storage security
./password_strength_tester.py --target user-database \
  --storage-security --check-encryption --check-hashing

# Verify account lockout policies
./password_strength_tester.py --target login-service \
  --check-lockout --attempts 5 --lockout-period 15

# Audit multi-factor authentication implementation
./password_strength_tester.py --target sso-service \
  --check-mfa --required-level high
```

## Integration Points

The core assessment tools integrate with other components of the security framework:

### Orchestration

```python
# Python API for programmatic tool invocation
from admin.security.assessment_tools.api import SecurityAssessmentAPI

api = SecurityAssessmentAPI()
results = api.run_vulnerability_scan(target="web-server-01", profile="production")
```

### CI/CD Pipeline Integration

```yaml
# Example GitHub Actions workflow
security_scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v2
    - name: Run security scan
      run: |
        ./admin/security/assessment_tools/core_assessment_tools/code_security_analyzer.py \
          --target ./src \
          --language python \
          --fail-level high \
          --output-format sarif \
          --output-file code-scan.sarif
    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: code-scan.sarif
```

### Supporting Scripts Integration

All assessment tools produce output compatible with the supporting scripts:

```bash
# Generate a vulnerability assessment, then create a report
./vulnerability_scanner.py --target payment-system \
  --profile production --output-format json --output-file vuln-scan.json

../supporting_scripts/report_generator.py \
  --input vuln-scan.json \
  --format pdf \
  --template comprehensive \
  --output vulnerability-report.pdf
```

## Troubleshooting

Common issues and solutions:

| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| Authentication error | Expired credentials | Refresh API key or certificate |
| Connection timeout | Network issue or firewall | Check connectivity and firewall rules |
| Permission denied | Insufficient privileges | Request elevated permissions or use service account |
| Missing dependencies | Incomplete installation | Run `pip install -r ../requirements.txt` |
| Configuration not found | Incorrect path | Verify config file paths and existence |

For detailed logging:

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
./vulnerability_scanner.py --target test-server --profile production
```

## Related Documentation

- Security Assessment Methodology
- Assessment Tools User Guide
- Security Baseline Management
- Vulnerability Management Process
- Compliance Framework Documentation
- Development Guide
- API Reference
- Supporting Scripts Documentation
- Configuration Files Documentation
- Common Components Reference
