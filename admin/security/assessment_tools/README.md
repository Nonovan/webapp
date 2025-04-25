# Security Assessment Tools

## Core Assessment Tools

- **`vulnerability_scanner.py`** - Automated vulnerability scanning tool for internal systems
- **`configuration_analyzer.py`** - Analyzes system configurations against security baselines
- **`network_security_tester.py`** - Tests network security controls and identifies weaknesses
- **`access_control_auditor.py`** - Validates access control implementations across the platform
- **`code_security_analyzer.py`** - Static analysis tool for reviewing application code security
- **`password_strength_tester.py`** - Tests password policies and identifies weak credentials

## Supporting Scripts

- **`assessment_utils.py`** - Shared utilities for assessment tools
- **`report_generator.py`** - Creates standardized security assessment reports
- **`finding_classifier.py`** - Classifies and prioritizes security findings
- **`remediation_tracker.py`** - Tracks remediation status for identified issues
- **`evidence_collector.py`** - Securely collects and stores assessment evidence

## Configuration Files

- **`assessment_profiles/`** - Directory containing assessment profiles for different environments
  - **`default.json`** - Default assessment profile
  - **`production.json`** - Production-specific assessment profile
  - **`development.json`** - Development environment assessment profile
  - **`compliance/`** - Compliance-specific assessment profiles
    - **`pci-dss.json`** - PCI DSS assessment profile
    - **`hipaa.json`** - HIPAA assessment profile
    - **`iso27001.json`** - ISO 27001 assessment profile
    - **`nist-csf.json`** - NIST Cybersecurity Framework assessment profile

- **`security_baselines/`** - Security baseline configurations for comparison
  - **`linux_server_baseline.json`** - Linux server security baseline
  - **`web_server_baseline.json`** - Web server security baseline
  - **`database_baseline.json`** - Database security baseline
  - **`cloud_service_baseline.json`** - Cloud service security baseline

## Assessment Templates

- **`templates/`** - Templates for assessment reporting and documentation
  - **`report_template.md`** - Markdown template for assessment reports
  - **`executive_summary.md`** - Template for executive summaries
  - **`findings_template.md`** - Template for documenting individual findings
  - **`remediation_plan.md`** - Template for remediation planning

## Documentation

- **`README.md`** - Overview and usage documentation (already present)
- **`USAGE.md`** - Detailed usage instructions for all tools
- **`CONTRIBUTING.md`** - Guidelines for contributing to the assessment tools
- **`SECURITY_STANDARDS.md`** - Security standards referenced by the assessment tools
