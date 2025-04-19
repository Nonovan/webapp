```markdown
# Security Components - Cloud Infrastructure Platform

This directory contains security-related configurations, hardening scripts, and documentation used to secure the Cloud Infrastructure Platform in various environments.

## Overview

The Cloud Infrastructure Platform security implementation follows a defense-in-depth approach with multiple layers of security controls to protect infrastructure, applications, data, and network communications. Our implementation follows industry best practices including NIST Cybersecurity Framework, CIS benchmarks, and OWASP recommendations.

## Directory Contents

### Configuration Files

- **`nginx-hardening.conf`**: NGINX web server security hardening configuration
- **`ssh-hardening.conf`**: SSH server security hardening configuration
- **`apparmor-profile-nginx`**: AppArmor security profile for NGINX
- **`network-policies.yaml`**: Kubernetes network security policies
- **`aide.conf`**: File integrity monitoring configuration
- **`fail2ban.local`**: Fail2ban configuration for brute force protection
- **`iptables-rules.sh`**: Firewall configuration script
- **`security-update-cron`**: Scheduled security tasks for automated updates

### WAF Configuration

- **`waf-rules/`**: Directory containing Web Application Firewall rules organized by category:
  - `sensitive-data.conf`: Rules to protect against data leakage
  - `generic-attacks.conf`: Rules for common web attack patterns
  - `ip-reputation.conf`: Rules for IP-based threat intelligence
  - `ics-protection.conf`: Rules specific to Industrial Control Systems
- **`malicious-user-agents.txt`**: List of known malicious user agents to block
- **`update-modsecurity-rules.sh`**: Script to update and deploy ModSecurity WAF rules

### Fail2ban Filters

- **`cloud-platform-api-auth.conf`**: Filter for API authentication failures
- **`cloud-platform-admin-auth.conf`**: Filter for admin interface authentication failures

### Security Scripts

- **`security_setup.sh`**: Main security setup and hardening script
- **`security-audit.sh`**: Security audit and reporting tool
- **`certificate-renew.sh`**: SSL/TLS certificate renewal automation
- **`check_security_updates.sh`**: Checks for available security updates
- **`update-blocklist.sh`**: Updates IP blocklists for perimeter defense
- **`verify_permissions.sh`**: Verifies critical file permissions

## Key Security Features

1. **Web Application Security**
   - Content Security Policy (CSP) with nonce-based script execution
   - CSRF protection for all forms and API endpoints
   - Input validation and output encoding
   - Security headers (HSTS, X-Frame-Options, etc.)
   - ModSecurity WAF with custom rule sets

2. **Infrastructure Security**
   - File integrity monitoring with AIDE
   - Defense-in-depth network protection with iptables
   - Security auditing with automated checks
   - Vulnerability management with continuous scanning

3. **Authentication & Session Security**
   - Multi-factor authentication support
   - Secure session management
   - Rate limiting and brute force protection
   - Strong password policies

4. **Industrial Control System (ICS) Security**
   - Protocol-specific protections for Modbus, DNP3, and OPC-UA
   - Command validation for control operations
   - Network segmentation for ICS components

## Setup and Usage

### Basic Security Hardening

```bash
# Apply firewall rules
sudo bash ./iptables-rules.sh

# Set up SSH hardening
sudo cp ./ssh-hardening.conf /etc/ssh/sshd_config.d/
sudo systemctl restart sshd

# Configure NGINX security
sudo cp ./nginx-hardening.conf /etc/nginx/conf.d/
sudo systemctl reload nginx

# Install and configure AIDE for file integrity monitoring
sudo cp ./aide.conf /etc/aide/
sudo aide --init
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

```

### Web Application Firewall Setup

```bash
# Install and update ModSecurity rules
sudo bash ./update-modsecurity-rules.sh

# Apply ModSecurity configuration
sudo systemctl restart nginx

```

### Automated Security Checks

```bash
# Run a comprehensive security audit
sudo bash ./security-audit.sh --email security@example.com

# Set up automated security updates
sudo cp ./security-update-cron /etc/cron.d/cloud-platform-security

```

### SSL/TLS Certificate Management

```bash
# Renew SSL certificates
sudo bash ./certificate-renew.sh

# Configure automated renewal
sudo crontab -e
# Add: 0 1 * * 1,4 /opt/cloud-platform/deployment/security/certificate-renew.sh >> /var/log/cloud-platform/cert-renewal.log 2>&1

```

## Maintenance and Updates

1. **Regular Updates**:
    - Update WAF rules monthly: [update-modsecurity-rules.sh](http://update-modsecurity-rules.sh/)
    - Update system security packages: Handled by security-update-cron
2. **Security Auditing**:
    - Run quarterly security audits: [security-audit.sh](http://security-audit.sh/) --full`
    - Review and address findings in audit reports
3. **Certificate Management**:
    - Monitor certificate expiration: `./certificate-renew.sh --check-only`
    - Renew certificates before expiration: `./certificate-renew.sh`

## Compliance

The security implementation helps maintain compliance with:

- ISO 27001
- SOC 2 Type II
- GDPR
- NIST Cybersecurity Framework
- PCI DSS (where applicable)
- HIPAA (where applicable)
- FedRAMP (in progress)

## Troubleshooting

### Common Issues

1. **WAF Blocking Legitimate Traffic**:
    - Check ModSecurity logs: `/var/log/nginx/modsec_audit.log`
    - Adjust rules in `/etc/nginx/modsecurity.d/`
2. **Failed Security Audits**:
    - Review the audit report at `/var/www/reports/security-audit-*.html`
    - Follow remediation steps in the report
3. **Certificate Renewal Failures**:
    - Check renewal logs: `/var/log/cloud-platform/cert-renewal.log`
    - Verify domain accessibility and DNS configuration

## References

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ModSecurity Core Rule Set](https://coreruleset.org/)

## Contributing

When contributing to these security components:

1. Always test changes in development environment before production
2. Document any modifications in the appropriate configuration files
3. Update this README if adding new security components
4. Follow security best practices and principle of least privilege

For questions or assistance, contact the security team at [security@example.com](mailto:security@example.com)