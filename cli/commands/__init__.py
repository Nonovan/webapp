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
- db_cli: Database management commands (migration, backup, restore)
- monitor_cli: System monitoring and metrics collection commands
- system_cli: System administration and configuration commands
- user_cli: User management and administration commands
"""

from .db import db_cli
from .monitor import monitor_cli
from .system import system_cli
from .user import user_cli

# Export all command groups to make them available when importing this package
__all__ = ['db_cli', 'monitor_cli', 'system_cli', 'user_cli']
