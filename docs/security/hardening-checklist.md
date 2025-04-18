# Server Hardening Checklist

This document provides a comprehensive checklist for hardening servers running the Cloud Infrastructure Platform.

## Initial Setup and Configuration

- [x] Maintain updated inventory of all production servers
- [x] Configure centralized log collection
- [x] Enable automatic security updates
- [x] Implement time synchronization (NTP)
- [x] Configure resource limits
- [x] Setup file integrity monitoring (AIDE)

## User Management

- [x] Configure strong password policies
- [x] Implement account lockout policies
- [x] Disable unused default accounts
- [x] Remove unnecessary user accounts
- [x] Configure password aging policies
- [x] Disable direct root login
- [x] Implement sudo with minimal privileges
- [x] Use SSH keys instead of passwords where possible

## File System Security

- [x] Set appropriate file permissions
- [x] Set proper ownership of files and directories
- [x] Restrict mount options (noexec, nosuid, nodev)
- [x] Separate partitions for /var, /tmp, /home
- [x] Implement disk quotas
- [x] Configure proper umask settings
- [x] Restrict access to system binaries and libraries

## Network Security

- [x] Configure host-based firewall (iptables)
- [x] Close unused ports
- [x] Disable unnecessary network services
- [x] Enable TCP wrappers where applicable
- [x] Configure proper host definitions
- [x] Implement connection rate limiting
- [x] Restrict ICMP traffic
- [x] Implement network segmentation

## SSH Hardening

- [x] Use SSH Protocol 2 only
- [x] Configure strong key exchange and ciphers
- [x] Disable empty passwords
- [x] Implement login timeout intervals
- [x] Set maximum authentication attempts
- [x] Restrict SSH access by IP address
- [x] Disable X11 forwarding
- [x] Disable SSH tunneling
- [x] Enable strict mode
- [x] Configure proper SSH logging

## Web Server (NGINX) Security

- [x] Disable server signature and version display
- [x] Configure proper TLS/SSL settings
- [x] Implement HTTPS-only communication
- [x] Configure proper HTTP security headers
- [x] Implement Content Security Policy
- [x] Enable ModSecurity WAF
- [x] Configure request rate limiting
- [x] Implement proper connection timeout settings
- [x] Remove default files and directories
- [x] Restrict access to sensitive directories

## Database Security

- [x] Use minimal privilege database users
- [x] Remove default database users
- [x] Configure proper authentication mechanisms
- [x] Implement database connection encryption
- [x] Restrict database network access
- [x] Configure proper database auditing
- [x] Implement query rate limiting
- [x] Remove sample databases and data
- [x] Configure automatic database backups

## Logging and Monitoring

- [x] Enable appropriate system logging
- [x] Configure proper log rotation
- [x] Implement centralized log collection
- [x] Configure log analysis and alerting
- [x] Monitor authentication failures
- [x] Log all privileged operations
- [x] Monitor file integrity
- [x] Implement log timestamps and synchronization

## Malware and Intrusion Prevention

- [x] Install and configure antivirus software
- [x] Implement host-based intrusion detection
- [x] Configure file integrity monitoring
- [x] Implement Fail2ban for brute force protection
- [x] Configure ModSecurity rules
- [x] Enable SELinux/AppArmor mandatory access controls
- [x] Implement USB device restrictions
- [x] Configure process whitelisting where applicable

## Application Security

- [x] Remove unnecessary packages and libraries
- [x] Keep applications updated with security patches
- [x] Configure proper application permissions
- [x] Implement application sandboxing where possible
- [x] Use security wrappers for vulnerable applications
- [x] Disable unnecessary application features
- [x] Configure application-level encryption
- [x] Implement proper error handling and logging

## Physical Security Considerations

- [x] Secure physical access to servers
- [x] Configure boot loader passwords
- [x] Disable booting from external media
- [x] Enable disk encryption for sensitive data
- [x] Configure BIOS/UEFI passwords
- [x] Implement chassis locks where applicable
- [x] Configure proper system shutdown procedures
- [x] Document physical security requirements

## Regular Maintenance Tasks

- [x] Review system logs regularly
- [x] Scan for vulnerabilities weekly
- [x] Update security patches promptly
- [x] Review user accounts quarterly
- [x] Test backups and recovery regularly
- [x] Perform file integrity verification
- [x] Review firewall rules quarterly
- [x] Test intrusion detection system effectiveness
- [x] Conduct security awareness training

## Verification

- [x] Run automated configuration compliance checks
- [x] Perform penetration testing
- [x] Validate security controls effectiveness
- [x] Document and remediate findings
- [x] Update security documentation
