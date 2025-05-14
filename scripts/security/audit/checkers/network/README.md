# Network Security Checkers

This directory contains security check implementations for validating network security controls in the Cloud Infrastructure Platform. These checkers examine firewall configurations, open ports, TLS implementations, and other network security aspects to identify vulnerabilities and compliance issues.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Configuration](#configuration)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
- [Related Documentation](#related-documentation)

## Overview

The network security checkers provide specialized security validation for network infrastructure components, including firewalls, open ports, and secure communications. These components support both standalone usage and integration into the broader security audit framework. Each checker implements controls that align with security standards such as CIS, NIST, and PCI DSS to ensure comprehensive network security validation.

## Key Components

- **`firewall_check.py`**: Validates firewall rule configurations against security policies.
  - **Usage**: Import this module to verify firewall configurations comply with security requirements.
  - **Features**:
    - Policy-based rule validation
    - Rule consistency checking
    - Default policy verification
    - Identification of overly permissive rules
    - Detection of security gaps
    - Multiple firewall type support (iptables, firewalld, ufw, nftables)
    - Zone-based security validation
    - Service accessibility analysis
    - Network segmentation validation
    - Custom policy enforcement

- **`open_port_check.py`**: Detects and analyzes open network ports against allowed service lists.
  - **Usage**: Import this module to identify potentially risky open network ports.
  - **Features**:
    - Port discovery and enumeration
    - Risk-based port classification
    - Well-known service mapping
    - Insecure service detection
    - Service-to-process correlation
    - Unnecessary port identification
    - Multiple detection methods (ss, netstat)
    - Configurable port allowlists
    - Risk scoring of findings
    - Integration with system services

- **`tls_check.py`**: Validates TLS/SSL configurations for security and compliance.
  - **Usage**: Import this module to verify secure communication implementations.
  - **Features**:
    - Protocol version verification
    - Cipher suite security validation
    - Certificate validation
    - Key strength analysis
    - Certificate expiration checking
    - Trust chain verification
    - SNI implementation validation
    - TLS extension security
    - Protocol vulnerability detection
    - Security header validation
    - OCSP stapling verification

## Directory Structure

```plaintext
scripts/security/audit/checkers/network/
├── README.md           # This documentation
├── firewall_check.py   # Firewall rule verification
├── open_port_check.py  # Open port detection
└── tls_check.py        # TLS configuration checks
```

## Configuration

Each checker supports configuration through multiple mechanisms to provide flexible integration:

### Firewall Check Configuration

```yaml
firewall:
  # Supported firewall types
  supported_types: ["iptables", "firewalld", "ufw", "nftables"]

  # Default policy requirements
  default_policy:
    input: "DROP"
    forward: "DROP"
    output: "ACCEPT"

  # High-risk services that should be restricted
  restricted_services:
    - {port: 22, name: "SSH", allowed_sources: ["10.0.0.0/8", "172.16.0.0/12"]}
    - {port: 3389, name: "RDP", allowed_sources: ["10.0.0.0/8"]}

  # Services that should never be exposed
  blocked_services:
    - {port: 23, name: "Telnet"}
    - {port: 21, name: "FTP"}
    - {port: 111, name: "RPC"}
    - {port: 135, name: "RPC/DCOM"}

  # Minimum requirement checks
  required_checks:
    stateful_inspection: true
    syn_flood_protection: true
    icmp_controls: true
    fragment_protection: true
```

### Open Port Check Configuration

```yaml
ports:
  # Standard allowed ports
  allowed:
    - {port: 22, name: "SSH", reason: "Administrative access"}
    - {port: 80, name: "HTTP", reason: "Web service"}
    - {port: 443, name: "HTTPS", reason: "Secure web service"}
    - {port: 5432, name: "PostgreSQL", reason: "Database service"}

  # High-risk ports that require special justification
  high_risk:
    - {port: 23, name: "Telnet", risk: "Unencrypted traffic"}
    - {port: 21, name: "FTP", risk: "Unencrypted traffic"}
    - {port: 25, name: "SMTP", risk: "Mail relay abuse potential"}
    - {port: 139, name: "NetBIOS", risk: "Windows file sharing vulnerabilities"}
    - {port: 445, name: "SMB", risk: "Windows file sharing vulnerabilities"}
    - {port: 3389, name: "RDP", risk: "Remote desktop vulnerabilities"}

  # Detection settings
  detection:
    preferred_tool: "ss"  # ss or netstat
    timeout: 10  # Seconds
    exclude_ephemeral: true
```

### TLS Check Configuration

```yaml
tls:
  # Minimum requirements
  minimum_version: "TLS1.2"

  # Forbidden protocols
  disallowed_protocols:
    - "SSLv2"
    - "SSLv3"
    - "TLS1.0"
    - "TLS1.1"

  # Certificate requirements
  certificates:
    min_key_size: 2048
    max_validity: 398  # Days
    preferred_signature_algorithms:
      - "sha256WithRSAEncryption"
      - "ecdsa-with-SHA256"

  # Required security headers
  security_headers:
    - "Strict-Transport-Security"
    - "Content-Security-Policy"
    - "X-Content-Type-Options"
```

## Best Practices & Security

- Run security checks with appropriate privileges to access network configurations
- Keep security policies updated as new vulnerabilities are discovered
- Create environment-specific baseline configurations
- Implement defense-in-depth strategies by combining multiple network security controls
- Document exceptions to security policies with clear justification
- Regularly review firewall rules for obsolete or overly permissive configurations
- Implement least privilege principles for network access
- Schedule periodic network security audits to detect drift from approved configurations
- Store network security findings in a secure location with restricted access
- Consider both internal and external network security boundaries in assessments
- Maintain backup network security configurations before making changes
- Use network segmentation to isolate sensitive systems
- Implement standardized naming conventions for firewall rules
- Validate both ingress and egress filtering rules
- Test changes thoroughly in development environments before implementing in production

## Common Features

- Comprehensive network security findings with severity classification
- Mapping of findings to security compliance frameworks (CIS, NIST, PCI DSS)
- Standardized result reporting using common result classes
- Evidence collection for audit verification
- Detailed remediation guidance with specific commands
- Multiple detection methods with graceful fallbacks
- Cross-platform support (Linux, macOS)
- Integration with notification systems for critical findings
- Performance optimization for quick assessments
- Configurable reporting thresholds
- Historical result comparison
- Incremental assessment capabilities
- Exception handling for authorized deviations
- Component availability checking before operations
- Context-aware security evaluations

## Usage Examples

### Firewall Configuration Validation

```python
from scripts.security.audit.checkers.network.firewall_check import FirewallChecker

# Create checker with default configuration
checker = FirewallChecker()

# Run checks with different methods
results = checker.check_firewall()

# Get firewall type
fw_type = checker.get_firewall_type()
print(f"Detected firewall type: {fw_type}")

# Compare against policy
policy_results = checker.compare_with_policy("/path/to/policy.yaml")

# Analyze security gaps
gaps = checker.analyze_security_gaps()

# Print findings
for result in results:
    print(f"[{result.severity.name}] {result.title}: {result.description}")
    print(f"Remediation: {result.remediation}")
    if result.compliance:
        print(f"Compliance: {', '.join(result.compliance)}")
```

### Open Port Detection

```python
from scripts.security.audit.checkers.network.open_port_check import OpenPortChecker

# Create checker
port_checker = OpenPortChecker()

# Configure allowed ports
allowed_ports = [22, 80, 443, 5432]
port_checker.set_allowed_ports(allowed_ports)

# Run check
results = port_checker.check()

# Get list of open ports
open_ports = port_checker.get_open_ports()
print(f"Open ports: {', '.join(map(str, open_ports))}")

# Check if specific port is open
if port_checker.is_port_open(22):
    print("SSH port is open")

# Get high-risk ports
high_risk_ports = port_checker.get_high_risk_ports()
for port in high_risk_ports:
    print(f"High risk port open: {port}")
```

### TLS Security Validation

```python
from scripts.security.audit.checkers.network.tls_check import TLSChecker

# Create checker
tls_checker = TLSChecker()

# Check specific domain
results = tls_checker.check_endpoint("example.com", 443)

# Check certificate
cert_results = tls_checker.check_certificate("example.com", 443)

# Check TLS version
tls_version_results = tls_checker.check_protocol_versions("example.com", 443)

# Check cipher suite security
cipher_results = tls_checker.check_cipher_suites("example.com", 443)

# Check security headers
header_results = tls_checker.check_security_headers("https://example.com")

# Generate comprehensive report
report = tls_checker.generate_report("example.com", 443, include_details=True)
```

### Integration with Security Audit

```python
from scripts.security.audit.checkers.common.check_result import CheckResultSet
from scripts.security.audit.checkers.network.firewall_check import FirewallChecker
from scripts.security.audit.checkers.network.open_port_check import OpenPortChecker
from scripts.security.audit.checkers.network.tls_check import TLSChecker

def run_network_security_audit(endpoints=None):
    """Run a comprehensive network security audit."""
    results = CheckResultSet()

    # Check firewall configuration
    firewall_checker = FirewallChecker()
    results.add_results(firewall_checker.check_firewall())

    # Check for open ports
    port_checker = OpenPortChecker()
    results.add_results(port_checker.check())

    # Check TLS configuration for endpoints
    if endpoints:
        tls_checker = TLSChecker()
        for endpoint in endpoints:
            host, port = endpoint.split(':')
            results.add_results(tls_checker.check_endpoint(host, int(port)))

    return results
```

## Related Documentation

- Network Security Baseline
- Common Check Utilities
- Firewall Policy Guide
- CIS Network Security Controls
- Port Security Guidelines
- TLS Security Configuration Guide
- Security Audit Framework Overview
- NIST 800-41 Firewall Guidelines
- Network Segmentation Best Practices
- Security Check Development Guide
