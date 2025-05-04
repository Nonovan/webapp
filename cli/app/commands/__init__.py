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
"""

# Import CLI command groups
from .db import db_cli
from .monitor import monitor_cli
from .system import system_cli
from .user import user_cli

# Import audit logging functionality from core security
from core.security import audit_log, log_security_event

# Export all command groups to make them available when importing this package
__all__ = [
    # Command groups
    'db_cli',
    'monitor_cli',
    'system_cli',
    'user_cli',

    # Security and audit logging
    'audit_log',
    'log_security_event'
]

# Version information
__version__ = '0.1.1'  # Version updated to reflect additions
