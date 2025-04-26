# Fail2Ban Filters for Cloud Infrastructure Platform

This directory contains custom Fail2ban filter configurations for detecting and preventing brute force and unauthorized access attempts against the Cloud Infrastructure Platform.

## Contents

- Overview
- Filter Types
- File Structure
- Configuration Format
- Usage
- Custom Rule Development
- Testing Guidelines
- Related Configuration

## Overview

The Fail2ban filters provide pattern recognition rules to identify authentication failures, brute force attempts, and other suspicious activities in log files. When these patterns are detected, Fail2ban can automatically implement temporary IP bans to protect the system from continued attack attempts. These filters are specifically designed to work with Cloud Infrastructure Platform log formats and authentication mechanisms.

## Filter Types

- **`cloud-platform-admin-auth.conf`**: Detects failed authentication attempts to administrative interfaces
  - Administrative console login failures
  - Management API authentication failures
  - Privileged operation access attempts
  - Session hijacking attempts
  - Unusual admin authentication patterns

- **`cloud-platform-api-auth.conf`**: Detects failed API authentication attempts
  - API key authentication failures
  - API rate limit violations
  - JWT signature verification failures
  - OAuth token validation failures
  - Unusual API access patterns

- **`cloud-platform-ics.conf`**: Detects unauthorized ICS (Industrial Control System) access attempts
  - Control system authentication failures
  - Control system probing activities
  - ICS protocol violations
  - Restricted operation attempts
  - Unauthorized command attempts

- **`cloud-platform-login.conf`**: Detects failed user login attempts
  - Account lockout triggers
  - Multi-factor authentication bypasses
  - Password reset abuse
  - Standard user authentication failures
  - Suspicious login patterns

## File Structure

```plaintext
deployment/security/filters/fail2ban-filters/
├── README.md                      # This documentation
├── cloud-platform-admin-auth.conf # Admin interface authentication filter
├── cloud-platform-api-auth.conf   # API authentication filter
├── cloud-platform-ics.conf        # ICS protection filter
└── cloud-platform-login.conf      # Application login filter
```

## Configuration Format

The filter files follow the standard Fail2ban filter format:

```ini
[Definition]
# Filter name and description
# Example: Detect failed authentication to Cloud Platform admin console

# Variables for log path options
_daemon = cloud-platform
_prefix = auth

# Optional custom date pattern if needed
__date_re = \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}

# The actual filter regex patterns - multiple failregex entries allowed
failregex = ^%(__date_re)s \[ERROR\] \[%(_daemon)s\.%(_prefix)s\] Failed login attempt for admin user <F-USER>.+</F-USER> from <HOST>
            ^%(__date_re)s \[WARNING\] \[%(_daemon)s\.%(_prefix)s\] Authentication failure for admin console from <HOST> \(user: <F-USER>.+</F-USER>\)

# Patterns to ignore (whitelist)
ignoreregex = ^%(__date_re)s \[INFO\] \[%(_daemon)s\.%(_prefix)s\] Password reset initiated
```

## Usage

### Configuration with Fail2ban

To use these filters with Fail2ban, they need to be referenced in the jail.local configuration:

```ini
[cloud-platform-admin-auth]
enabled = true
filter = cloud-platform-admin-auth
logpath = /var/log/cloud-platform/admin-auth.log
maxretry = 3
findtime = 300
bantime = 3600
action = iptables-multiport[name=cloud-admin, port="80,443,8443"]
         mail-whois[name=Cloud-Admin-Auth, dest=security@example.com]
```

### Integrating with System Logs

For syslog-based logs:

```ini
[cloud-platform-api-auth]
enabled = true
filter = cloud-platform-api-auth
logpath = /var/log/syslog
          /var/log/cloud-platform/api.log
maxretry = 5
findtime = 300
bantime = 1800
```

## Custom Rule Development

When creating or modifying filter rules:

1. **Study Log Patterns**:
   - Identify consistent patterns and unique identifiers
   - Note any variations in log formats across environments
   - Review authentic authentication failure logs

2. **Develop Regular Expressions**:
   - Start with a simple pattern that matches known failures
   - Test with increasing complexity
   - Use capture groups to extract usernames with `<F-USER>...</F-USER>`
   - Use Fail2ban's special tags like `<HOST>` to identify IP addresses

3. **Validate and Optimize**:
   - Balance specificity with readability and performance
   - Ensure minimal false positives
   - Use `fail2ban-regex` to test your patterns against log samples

## Testing Guidelines

Test your filters using the fail2ban-regex utility:

```bash
# Test a filter against a log file
fail2ban-regex /var/log/cloud-platform/admin-auth.log /etc/fail2ban/filter.d/cloud-platform-admin-auth.conf

# Test with verbose output for detailed matching information
fail2ban-regex /var/log/cloud-platform/api.log /etc/fail2ban/filter.d/cloud-platform-api-auth.conf --verbose
```

Verify that:

- The `<HOST>` tag correctly captures the IP address
- No legitimate authentication activities are matched
- The regex performance is reasonable for high-volume logs
- Your filter matches all expected authentication failure patterns

## Related Configuration

- **fail2ban.local**: Main Fail2ban configuration file
- **iptables-rules.sh**: Firewall configuration script
- **security-update-cron**: Scheduled security tasks
