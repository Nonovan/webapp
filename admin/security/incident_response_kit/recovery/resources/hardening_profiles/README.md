# Security Hardening Profiles

This directory contains security hardening profiles used during the recovery phase of incident response in the Cloud Infrastructure Platform. These profiles define security configurations and controls that should be applied to systems after a security incident to prevent similar incidents in the future.

## Contents

- Overview
- Key Components
- Directory Structure
- Profile Structure
- Usage
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The security hardening profiles provide standardized security configurations for different types of systems and services. These profiles are applied during the recovery phase of incident response to implement additional security controls based on lessons learned from the incident. Each profile contains configuration settings, security controls, and implementation guidance tailored to specific system types, ensuring a consistent and comprehensive approach to security hardening. The profiles incorporate industry best practices, compliance requirements, and intelligence from past incidents.

## Key Components

- **`application.json`**: Security hardening profile for custom applications
  - Access control hardening
  - Authentication enhancements
  - Configuration management
  - Dependency security settings
  - Input validation requirements
  - Logging and monitoring configurations
  - Output encoding enforcement
  - Session management security

- **`cloud_infrastructure.json`**: Security hardening profile for cloud resources
  - Access management controls
  - Audit logging configuration
  - Encryption requirements
  - Identity management settings
  - Network security configurations
  - Resource tagging standards
  - Service-specific security settings
  - Storage security controls

- **`container.json`**: Security hardening profile for containerized environments
  - Base image security requirements
  - Container isolation settings
  - Image scanning configuration
  - Network policy requirements
  - Orchestrator security settings
  - Privilege restrictions
  - Resource limitation parameters
  - Secrets management guidelines

- **`database.json`**: Security hardening profile for database systems
  - Access control restrictions
  - Audit configuration
  - Authentication security
  - Data encryption settings
  - Network access limitations
  - Patch management requirements
  - Privilege management controls
  - Query control settings

- **`network.json`**: Security hardening profile for network infrastructure
  - Access control lists
  - Firewall configuration
  - Intrusion detection settings
  - Network segmentation requirements
  - Protocol security settings
  - Routing security controls
  - Traffic filtering rules
  - VPN configuration requirements

- **`web_server.json`**: Security hardening profile for web servers
  - Content security policies
  - Directory access restrictions
  - File permission requirements
  - HTTP security headers
  - Module restrictions
  - Request rate limiting
  - Service configuration hardening
  - TLS configuration settings

## Directory Structure

```plaintext
admin/security/incident_response_kit/recovery/resources/hardening_profiles/
├── README.md                  # This documentation
├── application.json           # Application hardening profile
├── cloud_infrastructure.json  # Cloud infrastructure hardening profile
├── container.json             # Container environment hardening profile
├── database.json              # Database system hardening profile
├── network.json               # Network infrastructure hardening profile
└── web_server.json            # Web server hardening profile
```

## Profile Structure

The security hardening profiles follow a standardized JSON format:

```json
{
  "metadata": {
    "name": "Web Server Security Hardening Profile",
    "version": "2.3.0",
    "last_updated": "2023-09-15",
    "compliance": ["NIST SP 800-53", "CIS Benchmark"],
    "applicable_systems": ["Apache", "Nginx", "IIS"],
    "author": "Security Operations"
  },
  "controls": {
    "tls_configuration": {
      "enforce_tls": true,
      "min_tls_version": "1.2",
      "preferred_cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
      "disabled_protocols": ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"],
      "cert_key_size_min": 2048,
      "require_hsts": true,
      "hsts_max_age": 31536000,
      "hsts_include_subdomains": true,
      "verification_commands": [
        "openssl s_client -connect ${host}:${port} -tls1_2",
        "curl -sI https://${host} | grep Strict-Transport-Security"
      ],
      "remediation": "Configure TLS settings in web server configuration",
      "severity": "critical"
    },
    "security_headers": {
      "x_content_type_options": "nosniff",
      "x_frame_options": "DENY",
      "content_security_policy": "default-src 'self'",
      "x_xss_protection": "1; mode=block",
      "referrer_policy": "strict-origin-when-cross-origin",
      "permissions_policy": "geolocation=(), microphone=()",
      "verification_commands": [
        "curl -sI https://${host} | grep -E 'X-Content-Type-Options|X-Frame-Options'"
      ],
      "remediation": "Configure security headers in web server configuration",
      "severity": "high"
    }
  }
}
```

## Usage

These profiles are used with the security hardening script during incident recovery:

```bash
# Apply web server hardening profile
../security_hardening.sh --target web-01 \
    --profile web_server.json \
    --log /secure/evidence/IR-2024-042/web_hardening.log

# Apply database hardening with exceptions
../security_hardening.sh --target db-cluster \
    --profile database.json \
    --skip-rules "encryption,audit_logging" \
    --reason "Temporary exception approved by CISO"

# Apply targeted hardening to authentication components
../security_hardening.sh --target auth-service \
    --profile application.json \
    --components "authentication,session_management" \
    --backup-configs

# Apply hardening with custom parameters
../security_hardening.sh --target api-gateway \
    --profile network.json \
    --param "min_tls_version=1.3" \
    --param "max_auth_failures=3"
```

For programmatic use:

```python
import json
import os
import subprocess

def apply_hardening_profile(target_system, profile_name, skip_rules=None, parameters=None):
    """Apply a security hardening profile to a system.

    Args:
        target_system (str): The target system identifier
        profile_name (str): The name of the hardening profile to apply
        skip_rules (list): Optional list of rules to skip
        parameters (dict): Optional parameters to customize the profile
    """
    profile_path = os.path.join(
        "hardening_profiles",
        f"{profile_name}.json"
    )

    if not os.path.exists(profile_path):
        raise ValueError(f"Hardening profile not found: {profile_path}")

    cmd = ["../security_hardening.sh", "--target", target_system, "--profile", profile_path]

    if skip_rules:
        cmd.extend(["--skip-rules", ",".join(skip_rules)])

    if parameters:
        for key, value in parameters.items():
            cmd.extend(["--param", f"{key}={value}"])

    subprocess.run(cmd, check=True)
```

## Customization Guidelines

When customizing hardening profiles:

1. **Start with Baseline Profiles**
   - Use existing profiles as starting points
   - Document any deviations from baseline
   - Maintain structure and format consistency
   - Preserve verification commands

2. **Tailor to Environment**
   - Adjust settings based on system specificities
   - Consider application compatibility
   - Account for operational requirements
   - Document environment-specific adaptations

3. **Balance Security and Usability**
   - Apply defense-in-depth principles
   - Implement least privilege access
   - Consider operational impact
   - Test hardening changes in staging first

4. **Document Changes**
   - Update version information
   - Document rationale for changes
   - Reference security standards
   - Note any exceptions with justification
   - Record approvals for exceptions

## Best Practices & Security

- **Automation Support**: Design profiles to support automated implementation
- **Defense in Depth**: Implement multiple layers of security controls
- **Exception Documentation**: Document any exceptions with proper justification and approval
- **Feedback Integration**: Incorporate lessons learned from previous incidents
- **Incremental Hardening**: Apply critical security controls first, then enhance incrementally
- **Least Privilege**: Follow principle of least privilege for all access controls
- **Regression Testing**: Test applications after hardening to ensure functionality
- **Rollback Capability**: Include rollback procedures for each hardening measure
- **Secure Defaults**: Set secure defaults requiring explicit opt-out
- **Standard Alignment**: Align with industry standards (NIST, CIS, OWASP)
- **Validation Steps**: Include verification commands to validate implementation
- **Version Control**: Maintain all profiles in version control

## Common Features

All hardening profiles include these common elements:

- **Compliance Mapping**: References to relevant compliance requirements
- **Control Categories**: Logical grouping of related controls
- **Control Descriptions**: Clear descriptions of security requirements
- **Implementation Guidance**: Instructions for implementing controls
- **Metadata**: Version, update date, and applicable systems
- **Remediation Steps**: Instructions for implementing controls
- **Required vs. Recommended**: Clear distinction between mandatory and optional controls
- **Severity Ratings**: Indication of control importance (critical, high, medium, low)
- **Technical Details**: Specific configuration parameters
- **Verification Commands**: Commands to verify control implementation

## Related Documentation

- CIS Benchmarks
- Incident Recovery Procedures
- NIST SP 800-53 Security Controls
- OWASP Secure Configuration Guide
- Recovery Tools Documentation
- Security Control Testing Guide
- Security Hardening Guidelines
- Service Restoration Templates
- System Verification Procedures
- Verification Scripts Documentation
