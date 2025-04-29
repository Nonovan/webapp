# Security Assessment Tools - Usage Guide

This document provides detailed instructions for using the security assessment tools to evaluate and validate the security posture of the Cloud Infrastructure Platform.

## Contents

- [Getting Started](#getting-started)
- [Core Assessment Tools](#core-assessment-tools)
- [Supporting Scripts](#supporting-scripts)
- [Configuration Options](#configuration-options)
- [Common Workflows](#common-workflows)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)
- [Appendices](#appendices)

## Getting Started

### Prerequisites

Before using the security assessment tools, ensure you have:

1. **Access Permissions**: Appropriate access to the systems you intend to assess
2. **Authentication Credentials**: Valid authentication credentials for the platform
3. **Environment Setup**: Python 3.8+ with required dependencies installed
4. **Configuration Files**: Applicable assessment profiles and security baselines

### Installation

1. Clone the repository to your local environment:

   ```bash
   git clone https://github.com/organization/cloud-infrastructure-platform.git
   ```

2. Install required dependencies:

   ```bash
   pip install -r admin/security/assessment_tools/requirements.txt
   ```

3. Verify installation:

   ```bash
   cd admin/security/assessment_tools
   ./core_assessment_tools/vulnerability_scanner.py --version
   ```

### Basic Operation Flow

1. **Select the appropriate assessment tool** for your security evaluation needs
2. **Choose an assessment profile** that matches your environment (development, production)
3. **Specify the target system(s)** to evaluate
4. **Run the assessment** with appropriate parameters
5. **Review findings** and generate reports
6. **Track remediation** of identified issues

## Core Assessment Tools

### Vulnerability Scanner

The vulnerability scanner identifies security vulnerabilities in target systems.

#### Vulnerability Scanner Usage

```bash
./core_assessment_tools/vulnerability_scanner.py --target HOSTNAME --profile PROFILE_NAME
```

#### Vulnerability Scanner Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--target` | Target system to scan | None (Required) | `--target web-server-01` |
| `--profile` | Assessment profile to use | `default` | `--profile production` |
| `--output-format` | Output format | `standard` | `--output-format json` |
| `--output-file` | Output file path | stdout | `--output-file scan-results.json` |
| `--vuln-class` | Vulnerability class filter | All | `--vuln-class injection` |
| `--severity` | Minimum severity | `low` | `--severity high` |
| `--scan-timeout` | Scan timeout in seconds | 3600 | `--scan-timeout 7200` |
| `--non-invasive` | Non-invasive testing only | `false` | `--non-invasive` |

#### Vulnerability Scanner Examples

```bash
# Basic vulnerability scan
./core_assessment_tools/vulnerability_scanner.py --target app-server-01 --profile production

# Scan multiple targets and generate JSON report
./core_assessment_tools/vulnerability_scanner.py --target-list targets.txt \
  --profile production --output-format json --output-file vulnerability-report.json

# Focus on high severity issues only
./core_assessment_tools/vulnerability_scanner.py --target db-server-01 \
  --severity high --profile database-servers
```

### Configuration Analyzer

Analyzes system configurations against security baselines and compliance requirements.

#### Configuration Analyzer Usage

```bash
./core_assessment_tools/configuration_analyzer.py --target HOSTNAME --baseline BASELINE_NAME
```

#### Configuration Analyzer Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--target` | Target system to analyze | None (Required) | `--target app-server-01` |
| `--baseline` | Security baseline name | None (Required) | `--baseline linux_server_baseline` |
| `--compliance` | Compliance profile | None | `--compliance pci-dss` |
| `--output-format` | Output format | `standard` | `--output-format detailed` |
| `--output-file` | Output file path | stdout | `--output-file config-analysis.pdf` |
| `--detect-drift` | Enable drift detection | `false` | `--detect-drift` |
| `--remediation` | Include remediation guidance | `true` | `--remediation` |
| `--evidence-collection` | Collect evidence | `false` | `--evidence-collection` |

#### Configuration Analyzer Examples

```bash
# Analyze against Linux server baseline
./core_assessment_tools/configuration_analyzer.py --target app-server-01 \
  --baseline linux_server_baseline

# Check for PCI DSS compliance
./core_assessment_tools/configuration_analyzer.py --target payment-server \
  --baseline web_server_baseline --compliance pci-dss

# Analyze multiple servers for configuration drift
./core_assessment_tools/configuration_analyzer.py --target-group database-servers \
  --baseline database_baseline --detect-drift
```

### Network Security Tester

Tests network security controls and identifies weaknesses in network protections.

#### Network Security Tester Usage

```bash
./core_assessment_tools/network_security_tester.py --target HOSTNAME --profile PROFILE_NAME
```

#### Network Security Tester Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--target` | Target system or network | None (Required) | `--target 10.0.0.0/24` |
| `--profile` | Assessment profile to use | `default` | `--profile dmz` |
| `--test-type` | Type of test to perform | `all` | `--test-type firewall` |
| `--output-format` | Output format | `standard` | `--output-format json` |
| `--bandwidth-limit` | Bandwidth limit (KB/s) | 1000 | `--bandwidth-limit 500` |
| `--parallel` | Max parallel operations | 5 | `--parallel 10` |
| `--exclude` | Exclude targets | None | `--exclude 10.0.0.5,10.0.0.6` |

#### Network Security Tester Examples

```bash
# Test firewall rules
./core_assessment_tools/network_security_tester.py --target 10.0.1.0/24 \
  --test-type firewall --profile production

# Check network segmentation
./core_assessment_tools/network_security_tester.py --target vpc-prod \
  --test-type segmentation --output-format detailed

# Test secure communication enforcement
./core_assessment_tools/network_security_tester.py --target api-gateway \
  --test-type encryption --output-file encryption-report.pdf
```

### Access Control Auditor

Validates access control implementations across the platform.

#### Access Control Auditor Usage

```bash
./core_assessment_tools/access_control_auditor.py --target SYSTEM_NAME
```

#### Access Control Auditor Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--target` | Target system to audit | None (Required) | `--target customer-portal` |
| `--user-role` | User role to test | `user` | `--user-role admin` |
| `--validate-all` | Test all permissions | `false` | `--validate-all` |
| `--find-escalation` | Look for privilege escalation | `false` | `--find-escalation` |
| `--validate-separation` | Check duty separation | `false` | `--validate-separation` |
| `--output-format` | Output format | `standard` | `--output-format json` |

#### Access Control Auditor Examples

```bash
# Validate basic access controls
./core_assessment_tools/access_control_auditor.py --target customer-portal

# Look for privilege escalation paths
./core_assessment_tools/access_control_auditor.py --target payment-system \
  --find-escalation --user-role standard-user

# Verify separation of duties
./core_assessment_tools/access_control_auditor.py --target financial-system \
  --validate-separation --output-format detailed
```

### Code Security Analyzer

Performs static analysis on application code to identify security vulnerabilities.

#### Code Security Analyzer Usage

```bash
./core_assessment_tools/code_security_analyzer.py --target CODE_PATH
```

#### Code Security Analyzer Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--target` | Target code repository or path | None (Required) | `--target /path/to/code` |
| `--language` | Programming language focus | `all` | `--language python` |
| `--ruleset` | Security rules to apply | `standard` | `--ruleset owasp-top-10` |
| `--ignore-paths` | Paths to ignore | None | `--ignore-paths tests/,vendor/` |
| `--output-format` | Output format | `standard` | `--output-format sarif` |
| `--scan-dependencies` | Include dependency scan | `true` | `--scan-dependencies` |
| `--fail-level` | Level to fail the scan | `high` | `--fail-level medium` |

#### Code Security Analyzer Examples

```bash
# Scan a Python application
./core_assessment_tools/code_security_analyzer.py --target ./src --language python

# Scan with OWASP Top 10 ruleset
./core_assessment_tools/code_security_analyzer.py --target ./app \
  --ruleset owasp-top-10 --output-format html --output-file code-security.html

# Scan with dependency checking
./core_assessment_tools/code_security_analyzer.py --target ./payment-service \
  --scan-dependencies --fail-level high
```

### Password Strength Tester

Tests password policies and identifies weak credentials.

#### Password Strength Tester Usage

```bash
./core_assessment_tools/password_strength_tester.py --target SYSTEM_NAME
```

#### Password Strength Tester Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--target` | Target authentication system | None (Required) | `--target auth-service` |
| `--policy-only` | Test only the policy | `false` | `--policy-only` |
| `--with-default-creds` | Check for default credentials | `true` | `--with-default-creds` |
| `--dictionary` | Path to dictionary file | Built-in | `--dictionary ./wordlists/common.txt` |
| `--output-format` | Output format | `standard` | `--output-format csv` |
| `--check-storage` | Check password storage | `true` | `--check-storage` |

#### Password Strength Tester Examples

```bash
# Test password policy
./core_assessment_tools/password_strength_tester.py --target user-auth-service \
  --policy-only

# Check for weak/default credentials
./core_assessment_tools/password_strength_tester.py --target admin-portal \
  --with-default-creds --dictionary ./wordlists/top-10000.txt

# Verify password storage security
./core_assessment_tools/password_strength_tester.py --target customer-database \
  --check-storage --output-format detailed
```

## Supporting Scripts

### Report Generator

Creates standardized security assessment reports from assessment results.

#### Report Generator Usage

```bash
./supporting_scripts/report_generator.py --assessment-id ID --format FORMAT
```

#### Report Generator Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--assessment-id` | Assessment identifier | None (Required) | `--assessment-id sec-2024-42` |
| `--format` | Report format | `pdf` | `--format html` |
| `--template` | Report template | `standard` | `--template executive` |
| `--output` | Output file path | Auto-generated | `--output ./reports/exec-summary.pdf` |
| `--include-evidence` | Include evidence | `false` | `--include-evidence` |
| `--compliance-map` | Map to compliance controls | None | `--compliance-map pci-dss` |

#### Report Generator Examples

```bash
# Generate a standard assessment report
./supporting_scripts/report_generator.py --assessment-id sec-2024-071 \
  --format pdf --output security-assessment.pdf

# Create an executive summary
./supporting_scripts/report_generator.py --assessment-id sec-2024-071 \
  --format html --template executive-summary --output executive-summary.html

# Generate compliance-mapped report
./supporting_scripts/report_generator.py --assessment-id sec-2024-071 \
  --format pdf --template compliance --compliance-map pci-dss --output pci-compliance.pdf
```

### Finding Classifier

Classifies and prioritizes security findings based on risk and impact.

#### Finding Classifier Usage

```bash
./supporting_scripts/finding_classifier.py --input INPUT_FILE
```

#### Finding Classifier Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--input` | Input findings file | None (Required) | `--input raw-findings.json` |
| `--output` | Output file path | stdout | `--output classified-findings.json` |
| `--context` | Business context file | None | `--context business-systems.json` |
| `--taxonomy` | Vulnerability taxonomy | `cvss` | `--taxonomy owasp` |
| `--risk-matrix` | Risk matrix definition | `standard` | `--risk-matrix custom-matrix.json` |

#### Finding Classifier Examples

```bash
# Classify findings with CVSS scoring
./supporting_scripts/finding_classifier.py --input scan-results.json \
  --output classified-findings.json

# Classify with business context
./supporting_scripts/finding_classifier.py --input scan-results.json \
  --context business-systems.json --output risk-prioritized.json

# Use custom risk matrix
./supporting_scripts/finding_classifier.py --input scan-results.json \
  --risk-matrix custom-risk-matrix.json --output classified.json
```

### Remediation Tracker

Tracks the remediation status of identified security issues.

#### Remediation Tracker Usage

```bash
./supporting_scripts/remediation_tracker.py COMMAND
```

#### Remediation Tracker Commands

| Command | Description | Example |
|---------|-------------|---------|
| `create` | Create remediation task | `create --finding-id CVE-2024-1234` |
| `update` | Update remediation status | `update --task-id RT-123 --status in_progress` |
| `list` | List remediation tasks | `list --status open` |
| `report` | Generate status report | `report --output remediation-status.html` |
| `verify` | Verify remediation | `verify --task-id RT-123` |

#### Remediation Tracker Examples

```bash
# Create a remediation task
./supporting_scripts/remediation_tracker.py create --finding-id CVE-2024-1234 \
  --title "Fix XSS in login form" --owner "webapp-team" --due-date "2024-08-15"

# Update task status
./supporting_scripts/remediation_tracker.py update --task-id RT-123 \
  --status in_progress --notes "Fix implemented in PR #456"

# Generate remediation status report
./supporting_scripts/remediation_tracker.py report --format html \
  --output remediation-status.html
```

### Evidence Collector

Securely collects and stores assessment evidence for findings.

#### Evidence Collector Usage

```bash
./supporting_scripts/evidence_collector.py COMMAND
```

#### Evidence Collector Commands

| Command | Description | Example |
|---------|-------------|---------|
| `collect` | Collect evidence | `collect --target app-server-01` |
| `verify` | Verify evidence integrity | `verify --evidence-id E12345` |
| `export` | Export evidence | `export --evidence-id E12345 --format zip` |
| `list` | List collected evidence | `list --assessment-id sec-2024-071` |

#### Evidence Collector Examples

```bash
# Collect evidence from a server
./supporting_scripts/evidence_collector.py collect --target app-server-01 \
  --evidence-type screenshots,logs --assessment-id sec-2024-071

# Verify evidence integrity
./supporting_scripts/evidence_collector.py verify --evidence-id E12345

# Export evidence for reporting
./supporting_scripts/evidence_collector.py export --evidence-id E12345 \
  --format zip --output ./evidence/finding-123-evidence.zip
```

## Configuration Options

### Assessment Profiles

Assessment profiles define the scope, depth, and parameters of security assessments:

```bash
# List available assessment profiles
ls -la config_files/assessment_profiles/

# View profile details
cat config_files/assessment_profiles/production.json | jq
```

#### Creating Custom Profiles

1. Copy an existing profile as a starting point:

   ```bash
   cp config_files/assessment_profiles/production.json \
     config_files/assessment_profiles/custom-profile.json
   ```

2. Modify the profile with appropriate settings for your environment:

   ```bash
   # Edit using your preferred editor
   vim config_files/assessment_profiles/custom-profile.json
   ```

3. Validate the profile:

   ```bash
   ./supporting_scripts/assessment_utils.py validate-profile \
     --profile config_files/assessment_profiles/custom-profile.json
   ```

### Security Baselines

Security baselines define the expected secure configurations for different system types:

```bash
# List available security baselines
ls -la config_files/security_baselines/

# View baseline details
cat config_files/security_baselines/linux_server_baseline.json | jq
```

#### Customizing Security Baselines

1. Copy an existing baseline:

   ```bash
   cp config_files/security_baselines/linux_server_baseline.json \
     config_files/security_baselines/custom_server_baseline.json
   ```

2. Edit the baseline to match your security requirements:

   ```bash
   # Edit using your preferred editor
   vim config_files/security_baselines/custom_server_baseline.json
   ```

3. Validate the baseline:

   ```bash
   ./supporting_scripts/assessment_utils.py validate-baseline \
     --baseline config_files/security_baselines/custom_server_baseline.json
   ```

## Common Workflows

### Security Compliance Assessment

This workflow assesses a system against a specific compliance standard:

1. Identify the target system and compliance framework:

   ```bash
   # Example: Assess a payment system against PCI DSS
   SYSTEM="payment-server-01"
   STANDARD="pci-dss"
   ```

2. Run configuration analysis:

   ```bash
   ./core_assessment_tools/configuration_analyzer.py --target $SYSTEM \
     --compliance $STANDARD --output-format json --output-file config-findings.json
   ```

3. Run vulnerability scan:

   ```bash
   ./core_assessment_tools/vulnerability_scanner.py --target $SYSTEM \
     --profile production --output-format json --output-file vuln-findings.json
   ```

4. Run access control audit:

   ```bash
   ./core_assessment_tools/access_control_auditor.py --target $SYSTEM \
     --validate-all --output-format json --output-file access-findings.json
   ```

5. Classify findings by risk:

   ```bash
   ./supporting_scripts/finding_classifier.py --input config-findings.json,vuln-findings.json,access-findings.json \
     --output classified-findings.json --context business-context.json
   ```

6. Generate compliance report:

   ```bash
   ASSESSMENT_ID=$(date +%Y%m%d)-$STANDARD-$SYSTEM
   ./supporting_scripts/report_generator.py --assessment-id $ASSESSMENT_ID \
     --input classified-findings.json --format pdf --template compliance \
     --compliance-map $STANDARD --output $STANDARD-compliance-report.pdf
   ```

### Security Baseline Verification

This workflow verifies that systems comply with your organization's security baselines:

1. Define the target group and baseline:

   ```bash
   # Example: Verify web servers against web server baseline
   TARGET_GROUP="web-servers"
   BASELINE="web_server_baseline"
   ```

2. Generate target list:

   ```bash
   ./supporting_scripts/assessment_utils.py get-targets --group $TARGET_GROUP > targets.txt
   ```

3. Run configuration analysis:

   ```bash
   ./core_assessment_tools/configuration_analyzer.py --target-list targets.txt \
     --baseline $BASELINE --output-format json --output-file baseline-verification.json
   ```

4. Generate report:

   ```bash
   ./supporting_scripts/report_generator.py --assessment-id baseline-$(date +%Y%m%d) \
     --input baseline-verification.json --format html --template baseline-verification \
     --output baseline-verification-report.html
   ```

## Best Practices

### Risk-Based Assessment

1. **Identify Critical Assets**: Focus assessment efforts on your most critical systems first
2. **Apply Risk Context**: Use business context to prioritize findings and remediation
3. **Consider Threat Landscape**: Adapt assessment profiles to current threat intelligence
4. **Balance Controls**: Different systems require different security controls based on risk

### Secure Assessment Operations

1. **Authorization**: Always obtain proper authorization before scanning systems
2. **Change Management**: Follow change management processes for any invasive tests
3. **Network Impact**: Use bandwidth limiting and rate controls to minimize operational impact
4. **Credentials**: Never hardcode credentials in assessment commands or scripts
5. **Evidence Handling**: Follow the chain of custody for all security evidence
6. **Sensitive Data**: Sanitize reports to remove sensitive details before distribution

### Effective Remediation

1. **Prioritize Strategically**: Fix high-risk issues affecting critical systems first
2. **Verify Fixes**: Always verify remediation effectiveness after implementation
3. **Document Exceptions**: Properly document any accepted risks with business justification
4. **Track Trends**: Monitor security posture improvements over time with metrics

## Troubleshooting

### Common Issues

| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| Connection timeout | Network issues or firewall blocking | Check network connectivity and firewall rules |
| Authentication failure | Invalid or expired credentials | Verify credentials or renew authentication token |
| Permission denied | Insufficient access rights | Ensure proper permissions are granted |
| Missing dependencies | Required libraries not installed | Install missing dependencies with `pip install` |
| Resource constraints | Target system resource limitations | Use rate limiting and lower concurrency settings |

### Logging and Diagnostics

Enable verbose logging for troubleshooting:

```bash
# Enable debug logging for vulnerability scanner
./core_assessment_tools/vulnerability_scanner.py --target web-server-01 --debug-level 2

# Capture diagnostic information
./supporting_scripts/assessment_utils.py diagnostic --output diagnostic-report.zip
```

### Getting Help

If you encounter persistent issues:

1. Check the documentation in the docs directory
2. Review the common issues in this guide
3. Search the issue tracker for similar problems
4. Contact the security operations team for assistance

## Advanced Usage

### API Integration

The assessment tools provide API endpoints for integration with other systems:

```python
# Python example of API usage
from admin.security.assessment_tools.api import SecurityAssessmentAPI

# Initialize API client
api = SecurityAssessmentAPI(api_key="YOUR_API_KEY")

# Run vulnerability scan
scan_results = api.run_vulnerability_scan(
    target="web-server-01",
    profile="production"
)

# Process results
for finding in scan_results.findings:
    print(f"Finding: {finding.title} - Severity: {finding.severity}")
```

### Automation Integration

Integrate the assessment tools into CI/CD pipelines:

```bash
# Example: Add security scanning to CI pipeline
./core_assessment_tools/code_security_analyzer.py --target ./src \
  --ruleset owasp-top-10 --fail-level high --output-format junit \
  --output-file test-results/security-scan.xml
```

### Custom Rule Development

Create custom security rules for your environment:

1. Create a new rule file:

   ```bash
   cp config_files/custom_rules/example_rule.json config_files/custom_rules/my_custom_rule.json
   ```

2. Define the rule logic:

   ```json
   {
     "rule_id": "CUSTOM-001",
     "name": "Custom Security Control",
     "description": "Verifies a specific security requirement",
     "severity": "high",
     "check_type": "configuration",
     "parameters": { ... },
     "remediation": "Implement the required control by..."
   }
   ```

3. Register the rule with the scanner:

   ```bash
   ./supporting_scripts/assessment_utils.py register-rule \
     --rule-file config_files/custom_rules/my_custom_rule.json
   ```

## Appendices

### Severity Classifications

Security findings are classified according to the following severity levels:

| Severity | CVSS Range | Description | Remediation Timeline |
|----------|------------|-------------|---------------------|
| Critical | 9.0 - 10.0 | Poses an immediate threat, exploitable with significant impact | 7 days |
| High | 7.0 - 8.9 | Significant risk, relatively easy to exploit | 30 days |
| Medium | 4.0 - 6.9 | Moderate risk, requires specific conditions | 90 days |
| Low | 0.1 - 3.9 | Limited impact or difficult to exploit | 180 days |
| Info | 0.0 | Informational finding, no direct risk | Not required |

### File Formats

| Format | Extension | Description | Best For |
|--------|-----------|-------------|----------|
| JSON | .json | Structured data format | Machine processing, API integration |
| CSV | .csv | Comma-separated values | Spreadsheet import, data analysis |
| PDF | .pdf | Portable Document Format | Formal reports, presentation |
| HTML | .html | Web format with styling | Interactive viewing, distribution |
| Markdown | .md | Text-based markup | Documentation, version control |
| SARIF | .sarif | Static Analysis Results Format | IDE integration, tool interoperability |
| JUnit | .xml | XML test results format | CI/CD pipeline integration |

### Compliance Framework Coverage

| Framework | Tool Support | Configuration |
|-----------|-------------|--------------|
| PCI DSS | Full | `--compliance pci-dss` |
| HIPAA | Full | `--compliance hipaa` |
| ISO 27001 | Full | `--compliance iso27001` |
| NIST CSF | Full | `--compliance nist-csf` |
| NIST 800-53 | Full | `--compliance nist-800-53` |
| SOC 2 | Partial | `--compliance soc2` |
| GDPR | Partial | `--compliance gdpr` |
| CIS Benchmarks | Full | Uses security baselines |
| OWASP ASVS | Full | `--ruleset owasp-asvs` |
| DISA STIGs | Partial | Uses security baselines |

---

This document is maintained by the Security Assessment Team and should be reviewed quarterly.

**Last Updated**: 2024-07-20
**Version**: 1.0.0
