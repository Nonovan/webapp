# System Verification Scripts

This directory contains scripts and utilities for validating system integrity and security controls during the recovery phase of incident response. These scripts verify that systems have been properly restored, security measures are correctly implemented, and functionality is working as expected after an incident.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage
- Configuration
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The verification scripts provide automated and consistent validation of system integrity, configuration, and security controls during the recovery phase of incident response. These scripts ensure that restored systems meet security requirements, critical functionality is working properly, and no security vulnerabilities or indicators of compromise remain. By automating the verification process, these scripts help ensure thorough and consistent testing while reducing human error and speeding up the recovery process.

## Key Components

- **`app_functionality.py`**: Validates application functionality
  - API endpoint testing
  - Critical path verification
  - Integration point testing
  - Service dependency validation
  - User workflow verification
  - Session management validation
  - Error handling verification

- **`data_integrity.py`**: Checks data integrity
  - Database consistency verification
  - Checksum validation
  - File integrity verification
  - Schema structure validation
  - Configuration file validation
  - Data constraint verification
  - Reference integrity checking

- **`generate_checklist.py`**: Creates verification procedure documents
  - System-specific checklist generation
  - Control validation requirements
  - Compliance mapping
  - Evidence collection guidelines
  - Signoff requirements
  - Responsibility assignment
  - Verification timeline generation

- **`logging_verify.py`**: Checks logging system configuration
  - Log file presence verification
  - Log permission validation
  - Logging format verification
  - Logging level confirmation
  - Log forwarding validation
  - Log rotation settings
  - Audit logging verification

- **`network_verify.sh`**: Validates network security and connectivity
  - Firewall rule verification
  - Network segmentation testing
  - Security group validation
  - Traffic flow verification
  - DNS resolution checks
  - Latency measurement
  - Service port accessibility

- **`run_verification.sh`**: Executes all verification scripts
  - Orchestration of verification steps
  - Result aggregation
  - Reporting generation
  - Error handling
  - Dependency sequencing
  - Parallel execution options
  - Comprehensive verification

- **`security_controls.py`**: Validates security control implementation
  - Access control validation
  - Authentication mechanism verification
  - Encryption configuration checks
  - Security header validation
  - Certificate verification
  - Permission enforcement checks
  - Security baseline comparison

## Directory Structure

```plaintext
admin/security/incident_response_kit/recovery/resources/verification_scripts/
├── README.md                # This documentation
├── app_functionality.py     # Application functionality verification
├── data_integrity.py        # Data integrity verification
├── generate_checklist.py    # Verification checklist generator
├── logging_verify.py        # Logging system verification
├── network_verify.sh        # Network security and connectivity tests
├── run_verification.sh      # Verification execution coordinator
└── security_controls.py     # Security control validation
```

## Usage

The verification scripts can be used individually for targeted verification or collectively for comprehensive system validation:

```bash
# Generate a verification checklist for a specific system type
./generate_checklist.py --system-type web-server \
    --output /secure/evidence/IR-2024-042/web_verification_checklist.md

# Verify network configuration and connectivity
./network_verify.sh --target web-app-01 \
    --baseline /secure/baselines/network_baseline.json \
    --output /secure/evidence/IR-2024-042/network_verification.log

# Verify data integrity across database systems
python3 data_integrity.py --database orders_db \
    --checks schema,constraints,rows \
    --report /secure/evidence/IR-2024-042/data_integrity_report.json

# Run security control verification
python3 security_controls.py --target auth-system \
    --controls authentication,authorization,encryption \
    --baseline /secure/baselines/auth_security_baseline.json \
    --report /secure/evidence/IR-2024-042/security_controls_verification.pdf

# Execute full verification suite with detailed reporting
./run_verification.sh --system web-app-01 \
    --checklist /secure/evidence/IR-2024-042/verification_checklist.md \
    --report /secure/evidence/IR-2024-042/verification_results.json \
    --notify ir-team@example.com
```

For programmatic use:

```python
import subprocess
import json
import os
from pathlib import Path

def run_system_verification(system_name, incident_id, verification_types=None):
    """Run system verification checks on a restored system.

    Args:
        system_name (str): The system to verify
        incident_id (str): The incident ID for documentation
        verification_types (list): Optional list of verification types to run
                                   (default: all verification types)

    Returns:
        dict: Verification results and status
    """
    verification_dir = Path(__file__).parent
    output_dir = Path(f"/secure/evidence/{incident_id}")
    output_dir.mkdir(exist_ok=True, parents=True)

    verification_types = verification_types or ["network", "data", "security", "app"]
    results = {}

    for vtype in verification_types:
        if vtype == "network":
            cmd = [
                verification_dir / "network_verify.sh",
                "--target", system_name,
                "--baseline", f"/secure/baselines/network_{system_name}.json",
                "--output", str(output_dir / f"network_verification_{system_name}.log")
            ]
        elif vtype == "security":
            cmd = [
                "python3", verification_dir / "security_controls.py",
                "--target", system_name,
                "--baseline", f"/secure/baselines/security_{system_name}.json",
                "--report", str(output_dir / f"security_verification_{system_name}.json")
            ]
        # Add other verification types...

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            results[vtype] = {
                "status": "success",
                "output_file": cmd[-1],
                "details": result.stdout
            }
        except subprocess.CalledProcessError as e:
            results[vtype] = {
                "status": "failed",
                "error": e.stderr,
                "exit_code": e.returncode
            }

    # Save overall results
    results_file = output_dir / f"verification_results_{system_name}.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

    return results
```

## Configuration

The verification scripts use configuration files to define verification parameters:

```json
{
  "verification": {
    "network": {
      "required_services": ["web", "api", "database"],
      "allowed_ports": [443, 8443, 5432],
      "response_time_threshold_ms": 500,
      "dns_servers": ["10.0.0.2", "10.0.0.3"],
      "verification_endpoints": {
        "api": "/health",
        "web": "/status"
      }
    },
    "security_controls": {
      "required_headers": {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff"
      },
      "certificate": {
        "min_key_size": 2048,
        "min_validity_days": 30,
        "trusted_issuers": ["Let's Encrypt Authority X3", "DigiCert SHA2"]
      }
    }
  }
}
```

## Best Practices & Security

- **Automation**: Automate verification where possible for consistency and thoroughness
- **Defense in Depth**: Verify multiple layers of security controls
- **Documentation**: Generate clear documentation of verification results
- **Evidence Preservation**: Preserve verification results as part of incident evidence
- **Independence**: Use separate verification tools than those used for recovery
- **Least Privilege**: Run verification scripts with minimal required privileges
- **Parallel Verification**: Verify controls independently where possible
- **Prioritization**: Verify critical security controls first
- **Secure Baseline Comparison**: Compare against secure, known-good baselines
- **Versioning**: Maintain verification script versions in sync with system versions

## Common Features

All verification scripts share these common features:

- **Baseline Comparison**: Comparison against known-good configurations
- **Comprehensive Logging**: Detailed logging of all verification activities
- **Configuration Options**: Configurable verification parameters
- **Executable Documentation**: Scripts serve as executable documentation
- **Exit Codes**: Standardized exit codes for automation integration
- **Failure Handling**: Proper handling and reporting of verification failures
- **Machine-Readable Output**: JSON or XML output for programmatic processing
- **Report Generation**: Structured output reports in multiple formats
- **Security Focus**: Priority on security control validation
- **Verification Evidence**: Generation of verification evidence for auditing

## Related Documentation

- Incident Response Kit Overview
- Recovery Tools Documentation
- Security Hardening Profiles
- Service Restoration Templates
- System Verification Procedures
- Verification Framework Guide
- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- Security Control Verification Guide
- Recovery Process Documentation
