# Server Hardening Checklist

This document provides a comprehensive checklist for hardening servers running the Cloud Infrastructure Platform.

## Initial Setup and Configuration

- [x] Maintain updated inventory of all production servers
- [x] Configure centralized log collection
- [x] Enable automatic security updates
- [x] Implement time synchronization (NTP)
- [x] Configure resource limits
- [x] Setup file integrity monitoring (AIDE)
- [x] Disable unnecessary services and daemons
- [x] Implement kernel hardening parameters

## User Management

- [x] Configure strong password policies
- [x] Implement account lockout policies
- [x] Disable unused default accounts
- [x] Remove unnecessary user accounts
- [x] Configure password aging policies
- [x] Disable direct root login
- [x] Implement sudo with minimal privileges
- [x] Use SSH keys instead of passwords where possible
- [x] Implement multi-factor authentication for privileged access
- [x] Regularly audit user accounts and permissions

## File System Security

- [x] Set appropriate file permissions
- [x] Set proper ownership of files and directories
- [x] Restrict mount options (noexec, nosuid, nodev)
- [x] Separate partitions for /var, /tmp, /home
- [x] Implement disk quotas
- [x] Configure proper umask settings
- [x] Restrict access to system binaries and libraries
- [x] Enable filesystem encryption for sensitive data
- [x] Implement secure file deletion methods
- [x] Configure proper /tmp directory protection

## Network Security

- [x] Configure host-based firewall (iptables/nftables)
- [x] Close unused ports
- [x] Disable unnecessary network services
- [x] Enable TCP wrappers where applicable
- [x] Configure proper host definitions
- [x] Implement connection rate limiting
- [x] Restrict ICMP traffic
- [x] Implement network segmentation
- [x] Enable IPv6 security controls
- [x] Implement DNS security measures

## SSH Hardening

- [x] Use SSH Protocol 2 only
- [x] Configure strong key exchange algorithms and ciphers
- [x] Disable empty passwords
- [x] Implement login grace timeout
- [x] Restrict SSH access by IP address/range
- [x] Implement client alive interval
- [x] Change SSH default port (where appropriate)
- [x] Disable X11 forwarding
- [x] Disable port forwarding
- [x] Implement strict mode checking

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

## System Access Controls

- [x] Implement session timeout for idle sessions
- [x] Configure proper umask
- [x] Install and configure PAM modules
- [x] Implement access control lists (ACLs)
- [x] Configure proper terminal security
- [x] Implement time-based restrictions
- [x] Enforce access controls for cron jobs
- [x] Configure proper resource limits (ulimit)

## Logging and Monitoring

- [x] Configure comprehensive system logging
- [x] Implement secure log rotation
- [x] Enable auditd for system call auditing
- [x] Configure remote log storage
- [x] Implement log analysis tools
- [x] Set appropriate log retention policies
- [x] Configure alerts for critical security events
- [x] Implement log integrity verification

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

## Container and Virtualization Security

- [x] Implement container isolation
- [x] Use minimal base images
- [x] Scan container images for vulnerabilities
- [x] Implement proper network segmentation for containers
- [x] Use read-only file systems where possible
- [x] Implement resource limits for containers
- [x] Use secure container orchestration configurations
- [x] Regularly update hypervisor software

## Verification

- [x] Run automated configuration compliance checks
- [x] Perform penetration testing
- [x] Validate security controls effectiveness
- [x] Document and remediate findings
- [x] Update security documentation
- [x] Conduct security control validation
- [x] Use industry standard benchmarks (CIS, NIST)
- [x] Implement continuous security validation

## Cloud-Specific Controls

- [x] Implement cloud provider security groups
- [x] Use private networks and VPCs
- [x] Enable cloud provider logging and monitoring
- [x] Implement IAM with least privilege
- [x] Configure cloud provider firewalls
- [x] Enable API access logging
- [x] Restrict management access by IP
- [x] Configure S3/object storage security controls

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST SP 800-123](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf)
- [DISA STIGs](https://public.cyber.mil/stigs/)
- [Cloud Infrastructure Platform Internal Security Standards](/docs/security/standards/)
