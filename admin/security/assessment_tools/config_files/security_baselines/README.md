# Security Baselines

This directory contains security baseline configurations used by the security assessment tools to evaluate systems and services against established security standards. These baselines define the expected secure state for different system types in the Cloud Infrastructure Platform.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage
- Baseline Structure
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The security baselines provide standardized configuration requirements that systems must meet to be considered secure. These baselines implement industry best practices from sources like CIS Benchmarks, NIST guidelines, and cloud provider security recommendations. They serve as the foundation for security assessment tools to evaluate system configurations, validate security controls, and identify deviations from secure standards. Each baseline is tailored to a specific type of system or service while maintaining consistent security principles across the platform.

## Key Components

- **`cloud_service_baseline.json`**: Security baseline for cloud services
  - Access control requirements
  - API security configurations
  - Authentication standards
  - Cloud-specific security controls
  - Encryption requirements
  - Logging and monitoring settings
  - Network security controls
  - Resource protection measures

- **`database_baseline.json`**: Security baseline for database systems
  - Access control configurations
  - Audit logging requirements
  - Authentication settings
  - Backup configurations
  - Encryption standards
  - Network isolation requirements
  - Patch management guidelines
  - Privilege management controls

- **`linux_server_baseline.json`**: Security baseline for Linux servers
  - Account management requirements
  - File system security settings
  - Logging configurations
  - Network security controls
  - Package management settings
  - Process isolation requirements
  - Service hardening configurations
  - System access controls

- **`web_server_baseline.json`**: Security baseline for web servers
  - Authentication configurations
  - Content security policy settings
  - Cookie security requirements
  - Header security standards
  - HTTPS configuration requirements
  - Request filtering settings
  - Server hardening parameters
  - TLS configuration standards

## Directory Structure

```plaintext
admin/security/assessment_tools/config_files/security_baselines/
├── README.md                   # This documentation
├── cloud_service_baseline.json # Cloud service security baseline
├── database_baseline.json      # Database security baseline
├── linux_server_baseline.json  # Linux server security baseline
└── web_server_baseline.json    # Web server security baseline
```

## Usage

The security baselines are used with the security assessment tools to evaluate system configurations:

```bash
# Check a Linux server against the baseline
./configuration_analyzer.py --baseline security_baselines/linux_server_baseline.json --target app-server-01

# Evaluate a web server using the web server baseline
./configuration_analyzer.py --baseline security_baselines/web_server_baseline.json --target web-server-01

# Assess a database server with both general and database-specific controls
./configuration_analyzer.py --baseline security_baselines/linux_server_baseline.json \
  --additional-baseline security_baselines/database_baseline.json --target db-server-01

# Check cloud service configuration against security baseline
./configuration_analyzer.py --baseline security_baselines/cloud_service_baseline.json \
  --target aws-production --service-type aws
```

For programmatic use in Python:

```python
import json
from pathlib import Path

def load_security_baseline(system_type):
    """Load a security baseline configuration.

    Args:
        system_type (str): The type of system baseline to load
                          ('linux_server', 'web_server', 'database', 'cloud_service')

    Returns:
        dict: The security baseline configuration
    """
    baseline_dir = Path(__file__).parent
    baseline_file = f"{system_type}_baseline.json"
    baseline_path = baseline_dir / baseline_file

    if not baseline_path.exists():
        raise FileNotFoundError(f"Security baseline not found: {baseline_file}")

    with open(baseline_path, 'r') as f:
        return json.load(f)
```

## Baseline Structure

Security baselines follow a standardized JSON format:

```json
{
  "metadata": {
    "title": "Linux Server Security Baseline",
    "version": "2.3.0",
    "last_updated": "2024-07-01",
    "source_standards": ["CIS Benchmark v2.0.0", "NIST SP 800-53 Rev. 5"],
    "applicable_systems": ["Linux servers", "Application servers"],
    "owner": "Security Operations"
  },
  "controls": {
    "account_management": {
      "password_policy": {
        "min_length": 12,
        "complexity": true,
        "max_age_days": 90,
        "reuse_prevention": 24,
        "remediation": "Set password policy in /etc/security/pwquality.conf and /etc/login.defs",
        "validation": "grep -E '^password\\s+requisite\\s+pam_pwquality.so' /etc/pam.d/password-auth",
        "severity": "high",
        "rationale": "Strong password policies prevent brute force attacks and credential compromise"
      },
      "root_access": {
        "direct_login_disabled": true,
        "remediation": "Edit /etc/ssh/sshd_config, set PermitRootLogin to no",
        "validation": "grep ^PermitRootLogin /etc/ssh/sshd_config | grep no",
        "severity": "critical",
        "rationale": "Direct root login creates audit gaps and increases privilege escalation risks"
      }
    },
    "filesystem_security": {
      "tmp_partition": {
        "mounted_noexec": true,
        "remediation": "Add noexec option to /tmp mount in /etc/fstab",
        "validation": "mount | grep /tmp | grep noexec",
        "severity": "medium",
        "rationale": "Prevents execution of malicious scripts from temporary directories"
      }
    },
    "network_security": {
      "ssh_configuration": {
        "protocol_version": 2,
        "permitted_algorithms": ["aes256-ctr", "aes192-ctr", "aes128-ctr"],
        "remediation": "Edit /etc/ssh/sshd_config with secure configuration",
        "validation": "sshd -T | grep ciphers",
        "severity": "high",
        "rationale": "Prevents use of insecure SSH algorithms vulnerable to cryptographic attacks"
      }
    }
  }
}
```

## Customization Guidelines

When customizing security baselines:

1. **Start With Reference Standards**
   - Use recognized security standards as the foundation
   - Reference source standards in metadata
   - Maintain traceability to source requirements
   - Document deviations from standard benchmarks

2. **Consider Environment Context**
   - Adjust requirements for specific operational needs
   - Document any exceptions with rationale
   - Define scope of applicability clearly
   - Balance security with operational requirements

3. **Maintain Validation Methods**
   - Include verification commands for each control
   - Provide both manual and automated validation methods
   - Test validation commands before implementation
   - Document expected output for validation

4. **Provide Clear Remediation**
   - Include specific remediation steps
   - Reference configuration files and parameters
   - Include example commands where appropriate
   - Document potential operational impacts of remediation

## Best Practices & Security

- **Control Categorization**: Group controls by security domain or function
- **Environment Consideration**: Adapt baselines to specific environments without compromising security
- **Exception Management**: Document any exceptions to baseline requirements with appropriate approvals
- **Policy Alignment**: Ensure baselines align with organizational security policies
- **Rationale Documentation**: Include security rationale for each control requirement
- **Regular Updates**: Review and update baselines quarterly or when standards change
- **Risk-Based Approach**: Focus more stringent controls on higher-risk systems
- **Standard References**: Maintain references to source security standards
- **Technical Validation**: Include technical validation methods for automated verification
- **Version Control**: Track baseline versions and changes in source control

## Common Features

All security baselines share these common elements:

- **Control Categories**: Logical grouping of related security controls
- **Control Descriptions**: Clear descriptions of security requirements
- **Metadata**: Version, update date, and ownership information
- **Rationales**: Explanations for why controls are required
- **Remediation Steps**: Instructions for addressing non-compliant settings
- **Severity Ratings**: Indication of control importance (critical, high, medium, low)
- **Source Standards**: References to industry standards and best practices
- **System Applicability**: Clear definition of applicable systems
- **Technical Details**: Specific configuration parameters and settings
- **Validation Methods**: Commands or procedures to verify compliance

## Related Documentation

- Assessment Methodology Guide
- CIS Benchmarks Reference
- Configuration Analysis Tool Guide
- Compliance Framework Documentation
- Exception Management Process
- NIST Security Guidelines
- Parent Assessment Configuration Documentation
- Risk Assessment Framework
- Security Hardening Standards
- Vulnerability Management Policy
