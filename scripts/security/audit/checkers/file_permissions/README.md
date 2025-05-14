# File Permissions Checkers

This directory contains checkers for auditing and validating file and directory permissions within the Cloud Infrastructure Platform. These checkers ensure that files have appropriate permissions, ownership, and access controls in accordance with security best practices and compliance requirements.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Check Configuration](#check-configuration)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
- [Related Documentation](#related-documentation)

## Overview

The file permission checkers analyze file and directory permissions, ownership, and special permissions (SUID, SGID, sticky bit) to identify security vulnerabilities and compliance violations. These checkers enforce the principle of least privilege by validating that files only have the permissions necessary for their intended function. Each checker can be used independently or combined with other checkers for comprehensive security assessments.

## Key Components

- **`critical_file_check.py`**: Validates permissions on security-critical system files.
  - **Usage**: Verifies that critical system files have secure permissions and ownership.
  - **Features**:
    - Predefined list of critical files (e.g., /etc/passwd, /etc/shadow)
    - File existence verification
    - Permission validation against secure baselines
    - Ownership verification (root:root or specific user/group)
    - Environment-specific permission enforcement
    - Compliance mapping to security standards

- **`ownership_check.py`**: Validates file and directory ownership.
  - **Usage**: Ensures files and directories have appropriate owner and group assignments.
  - **Features**:
    - Configurable ownership requirements by path
    - Recursive directory traversal
    - Pattern-based file matching
    - Path exclusion functionality
    - Owner and group validation
    - Service-specific ownership requirements

- **`world_writable_check.py`**: Detects world-writable files and directories.
  - **Usage**: Identifies files and directories with insecure world-writable permissions.
  - **Features**:
    - Detection of world-writable regular files
    - Detection of world-writable directories
    - Sticky bit validation on world-writable directories
    - Exception handling for authorized world-writable paths
    - Risk scoring based on location and file type
    - Filesystem context awareness

## Directory Structure

```plaintext
scripts/security/audit/checkers/file_permissions/
├── README.md                 # This documentation
├── __init__.py               # Package initialization
├── critical_file_check.py    # Critical file permissions check
├── ownership_check.py        # File ownership verification
└── world_writable_check.py   # World-writable file detection
```

## Check Configuration

Each permission checker can be configured through command-line arguments, environment variables, or YAML configuration files:

### Critical File Check Configuration

```yaml
critical_files:
  # Format: file_path: {owner: "owner", group: "group", mode: 0xxx, required: true/false}
  "/etc/passwd": {owner: "root", group: "root", mode: 0644, required: true}
  "/etc/shadow": {owner: "root", group: "shadow", mode: 0640, required: true}
  "/etc/ssh/sshd_config": {owner: "root", group: "root", mode: 0600, required: true}
  "/etc/cloud-platform/config/credentials.json": {owner: "app", group: "app", mode: 0600, required: true}

exceptions:
  # Paths that should be skipped
  - "/var/run/container-*"
  - "*/node_modules/*"
```

### Ownership Check Configuration

```yaml
file_ownership:
  # Format: path_pattern: {owner: "owner", group: "group", recursive: true/false}
  "/etc/cloud-platform/config/*": {owner: "app", group: "app", recursive: false}
  "/var/www/html": {owner: "www-data", group: "www-data", recursive: true}
  "/opt/application/data": {owner: "app", group: "app", recursive: true}

exceptions:
  - "/opt/application/data/cache"
```

### World-Writable Check Configuration

```yaml
world_writable:
  allowed_directories:
    # Directories that may legitimately be world-writable
    - "/tmp"
    - "/var/tmp"
    - "/var/spool/public"

  excluded_paths:
    # Paths to exclude from checking
    - "/dev"
    - "/proc"
    - "/sys"
```

## Best Practices & Security

- Run permission checks with sufficient privileges to access all files
- Apply file permission baselines based on environment type
- Follow the principle of least privilege for all file permissions
- Store baseline configurations in version control
- Review all exceptions to file permission policies
- Use POSIX ACLs for complex permission requirements
- Remove world-writable permissions from all system files
- Ensure critical files are owned by appropriate users
- Apply sticky bit to world-writable directories
- Apply recursive permission checks cautiously in large directories
- Schedule regular permission audits as part of maintenance
- Document all special permissions or exceptions

## Common Features

- Detailed permission findings with severity levels
- Mapping to compliance frameworks (CIS, NIST, PCI DSS)
- Remediation commands for fixing issues
- Support for both Linux and macOS permission models
- Recursive directory traversal with path exclusions
- Efficient permission checking with minimal system impact
- Git-aware checks that ignore version control directories
- Special permission detection (SUID, SGID, sticky bit)
- Environment-specific baseline application
- Pattern-based path matching and exclusion
- Ownership validation for users and groups
- Comprehensive logging of findings
- Automated remediation suggestions

## Usage Examples

### Running Critical File Checks

```python
from scripts.security.audit.checkers.file_permissions.critical_file_check import CriticalFileChecker

# Create checker with default configuration
checker = CriticalFileChecker()

# Run checks against specific baseline
results = checker.check(baseline="production")

# Print findings
for result in results:
    print(f"[{result.severity}] {result.title}: {result.description}")
    print(f"  Remediation: {result.remediation}")
```

### Running from Command Line

```bash
# Run critical file check
python -m scripts.security.audit.checkers.file_permissions.critical_file_check --baseline production

# Check file ownership
python -m scripts.security.audit.checkers.file_permissions.ownership_check --directory /etc/cloud-platform

# Find world-writable files
python -m scripts.security.audit.checkers.file_permissions.world_writable_check --exclude-standard --report-format json
```

### Integration with Security Audit

```python
from scripts.security.audit.checkers.file_permissions import critical_file_check, ownership_check, world_writable_check

def run_file_permission_audit(directory, config):
    """Run comprehensive file permission checks."""
    all_results = []

    # Check critical files
    critical_checker = critical_file_check.CriticalFileChecker(config.get('critical_files', {}))
    all_results.extend(critical_checker.check())

    # Check ownership
    ownership_checker = ownership_check.OwnershipChecker(config.get('ownership', {}))
    all_results.extend(ownership_checker.check(directory))

    # Check for world-writable files
    ww_checker = world_writable_check.WorldWritableChecker(config.get('world_writable', {}))
    all_results.extend(ww_checker.check(directory))

    return all_results
```

## Related Documentation

- Security Audit Framework
- Common Check Utilities
- CIS Benchmark Controls for File Permissions
- Permission Security Model
- System Security Baseline
- File Permission Remediation Guide
- Permission Check Development Guide
- File System Security
