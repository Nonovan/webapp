# Security Assessment Configuration Files

This directory contains configuration files for security assessment tools used by the Cloud Infrastructure Platform. These files define assessment profiles, security baselines, and compliance requirements for the various environments and systems being evaluated.

## Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Assessment Profiles](#assessment-profiles)
- [Security Baselines](#security-baselines)
- [Usage](#usage)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

The configuration files in this directory drive the security assessment tools by defining what to assess, how to assess it, and what standards to enforce. They provide consistent, repeatable security evaluations across different environments while maintaining appropriate context-specific requirements for each deployment scenario.

## Directory Structure

```plaintext
admin/security/assessment_tools/config_files/
├── README.md                          # This documentation
├── assessment_profiles/               # Assessment configuration profiles
│   ├── README.md                      # Assessment profiles documentation
│   ├── default.json                   # Default assessment profile
│   ├── development.json               # Development environment profile
│   ├── production.json                # Production environment profile
│   └── compliance/                    # Compliance-specific profiles
│       ├── README.md                  # Compliance profiles documentation
│       ├── ccpa.json                  # California Consumer Privacy Act profile
│       ├── cmmc.json                  # Cybersecurity Maturity Model Certification profile
│       ├── fedramp.json               # FedRAMP Moderate compliance profile
│       ├── gdpr.json                  # GDPR compliance profile
│       ├── hipaa.json                 # HIPAA Security Rule compliance profile
│       ├── iso27001.json              # ISO 27001:2013 compliance profile
│       ├── nist-csf.json              # NIST Cybersecurity Framework profile
│       └── pci-dss.json               # PCI DSS v3.2.1 compliance profile
└── security_baselines/                # Security baseline definitions
    ├── README.md                      # Security baselines documentation
    ├── application_security_baseline.json # Application security baseline
    ├── cloud_service_baseline.json    # Cloud service security baseline
    ├── container_baseline.json        # Container environment security baseline
    ├── database_baseline.json         # Database security baseline
    ├── identity_management_baseline.json # Identity management security baseline
    ├── linux_server_baseline.json     # Linux server security baseline
    ├── network_appliance_baseline.json # Network device security baseline
    ├── web_server_baseline.json       # Web server security baseline
    └── schema/                        # JSON schema definitions
        └── baseline_schema.json       # Schema for validating baseline files
```

## Assessment Profiles

Assessment profiles define the scope, depth, and configuration of security assessments for different environments:

- **`default.json`**: Base assessment profile with sensible defaults that other profiles inherit from
- **`development.json`**: Tailored for development environments with focus on early detection of security issues, secure coding practices, and CI/CD integration
- **`production.json`**: Strict assessment profile for production environments with comprehensive checks, enhanced monitoring, and detailed validation requirements

Compliance-specific profiles include additional checks required by specific standards:

- **`ccpa.json`**: Privacy controls specific to California Consumer Privacy Act requirements
- **`cmmc.json`**: Defense industrial base security controls for Cybersecurity Maturity Model Certification
- **`fedramp.json`**: Federal security controls mapped to NIST SP 800-53 for FedRAMP authorization
- **`gdpr.json`**: European privacy and data protection controls for GDPR compliance
- **`hipaa.json`**: Healthcare security and privacy controls for HIPAA compliance
- **`iso27001.json`**: Checks mapped to ISO 27001 Annex A control objectives
- **`nist-csf.json`**: Evaluation based on NIST Cybersecurity Framework functions (Identify, Protect, Detect, Respond, Recover)
- **`pci-dss.json`**: Payment card industry security controls for PCI DSS compliance

## Security Baselines

Security baselines define the expected secure configuration for different system types:

- **`application_security_baseline.json`**: Security baseline for web applications and APIs
- **`cloud_service_baseline.json`**: Security baseline for cloud services (AWS, Azure, GCP)
- **`container_baseline.json`**: Security baseline for container environments and orchestration
- **`database_baseline.json`**: Security baseline for database systems
- **`identity_management_baseline.json`**: Security baseline for identity and access management systems
- **`linux_server_baseline.json`**: Security baseline for Linux servers based on CIS benchmarks
- **`network_appliance_baseline.json`**: Security baseline for network devices (firewalls, routers, switches)
- **`web_server_baseline.json`**: Security baseline for web servers (NGINX, Apache)

## Usage

Assessment tools use these configuration files as follows:

```bash
# Run assessment with a specific profile
./vulnerability_scanner.py --profile assessment_profiles/production.json

# Compare system against baseline
./configuration_analyzer.py --baseline security_baselines/web_server_baseline.json --target webserver01

# Run compliance-specific assessment
./access_control_auditor.py --compliance assessment_profiles/compliance/pci-dss.json

# Generate a custom assessment using multiple configs
./network_security_tester.py --profile assessment_profiles/production.json --compliance assessment_profiles/compliance/iso27001.json

# Layer development profile with specific compliance requirements
./configuration_analyzer.py --base-profile development.json --compliance-profile compliance/fedramp.json --target application-server
```

## Best Practices & Security

- **Version Control**: All configuration changes should be version-controlled
- **Review Changes**: Peer review all security baseline modifications
- **Secure Storage**: Store configuration files with appropriate permissions (600 or 640)
- **Validate Before Use**: Validate configuration files before using them for assessments
- **Regular Updates**: Update baselines and profiles quarterly or when security standards change
- **Documentation**: Document the rationale for security requirements in the configuration
- **Consistency**: Maintain consistency between environments while addressing specific risks
- **Traceability**: Ensure compliance requirements are traceable to their source standards
- **Schema Validation**: Use schema definitions to validate configuration file structure
- **Risk-Based Approach**: Focus controls on areas with highest risk and business impact

## Related Documentation

- Security Assessment Methodology
- Configuration Analyzer Documentation
- Compliance Framework Documentation
- CIS Benchmark Implementation Guide
- Security Baseline Management
- Assessment Profile Customization
