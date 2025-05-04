"""
Command group initialization module for the myproject CLI.

This module serves as the entry point for all CLI command groups in the application.
It imports and exposes the individual command groups that provide specific functionality
for different aspects of the application, such as database management, user administration,
system monitoring, and application maintenance.

The command groups are designed to be modular and focused on specific domains of
functionality, allowing for clear organization of commands and separation of concerns.
This structure facilitates both discovery of available commands and extension with
new commands as the application evolves.

Available command groups:
- db_cli: Database management commands
  - init: Initialize the database with schema and optional seed data
  - backup: Create database backups (full or schema-only)
  - restore: Restore database from a backup file
  - verify: Verify database integrity and constraints
  - optimize: Run database optimization operations (ANALYZE, VACUUM, REINDEX)
  - list-backups: List available database backup files
  - stats: Show database statistics
  - connections: View and manage database connections

- monitor_cli: System monitoring and metrics commands
  - status: Show system monitoring status
  - logs: View application logs with filtering options
  - metrics: Export system and application metrics

- system_cli: System administration and configuration commands
  - status: Show system resource utilization and status
  - health: Run health checks on system components
  - config: Verify and display configuration settings
  - check-integrity: Verify file integrity against baseline
  - services: Check status of dependent services
  - diagnostics: Generate system diagnostic information

- user_cli: User administration commands
  - create: Create a new user account
  - list: List users with optional filtering
  - info: View detailed information about a specific user
  - reset-password: Reset a user's password
  - change-role: Change a user's role
  - deactivate: Deactivate a user account
  - activate: Activate a user account
  - delete: Delete a user account
  - mfa: Manage multi-factor authentication requirements
  - bulk-import: Import users in bulk from CSV or JSON
  - export: Export user data to a file
  - lock/unlock: Manage account locking

- security_cli: Security management commands
  - check-baseline: Verify the current security baseline status
  - update-baseline: Update the security baseline
  - events: View security events and alerts
  - analyze: Analyze system security posture

- maintenance_cli: System maintenance commands
  - cache-clear: Clear application caches
  - logs-rotate: Rotate application logs
  - cleanup: Clean up old files
"""

# Import CLI command groups
from .db import db_cli
from .monitor import monitor_cli
from .system import system_cli
from .user import user_cli
from .security import security_cli
from .maintenance import maintenance_cli

# Import necessary security functions from the core module
from core.security import (
    # Audit logging functions
    audit_log,
    get_security_events,

    # File integrity functions
    check_file_integrity,
    check_critical_file_integrity,
    create_file_hash_baseline,
    update_file_integrity_baseline,
    verify_baseline_update,

    # Security monitoring functions
    get_security_anomalies,
    get_threat_summary,
    detect_suspicious_activity
)

# Export all command groups and required functions to make them available when importing this package
__all__ = [
    # Command groups
    'db_cli',
    'monitor_cli',
    'system_cli',
    'user_cli',
    'security_cli',
    'maintenance_cli',

    # Audit logging functions
    'audit_log',
    'get_security_events',

    # File integrity functions
    'check_file_integrity',
    'check_critical_file_integrity',
    'create_file_hash_baseline',
    'update_file_integrity_baseline',
    'verify_baseline_update',

    # Security monitoring functions
    'get_security_anomalies',
    'get_threat_summary',
    'detect_suspicious_activity'
]

# Version information
__version__ = '0.1.1'
