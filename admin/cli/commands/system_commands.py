"""
System-related command handlers for the administrative CLI.
"""

from typing import Dict, List, Any, Optional
import sys
from admin.cli.base_command import BaseCommand
from admin.utils.admin_auth import require_permission

__all__ = [
    "HelpCommand",
    "ListCategoriesCommand",
    "VersionCommand",
    "CheckPermissionsCommand"
]

class HelpCommand(BaseCommand):
    """Get help information for commands."""
    name = "help"
    description = "Get help information for commands"
    permissions = ["admin:read"]
    category = "system"

    @classmethod
    @require_permission("admin:read")
    def execute(cls, command: Optional[str] = None, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Get help information for commands.

        If a command name is specified, returns detailed help for that command.
        Otherwise, lists all available commands, optionally filtered by category.

        Args:
            command: Optional command name for detailed help
            category: Optional category filter

        Returns:
            Help information dictionary
        """
        from admin.cli.admin_commands import get_command_help, list_commands

        if command:
            return get_command_help(command)
        else:
            return {"commands": list_commands(category)}


class ListCategoriesCommand(BaseCommand):
    """List all available command categories."""
    name = "list-categories"
    description = "List all available command categories"
    permissions = ["admin:read"]
    category = "system"

    @classmethod
    @require_permission("admin:read")
    def execute(cls) -> Dict[str, Any]:
        """
        List all available command categories.

        Returns:
            Dictionary with list of categories
        """
        from admin.cli.admin_commands import COMMAND_REGISTRY

        categories = set()
        for cmd_info in COMMAND_REGISTRY.values():
            categories.add(cmd_info["category"])

        return {"categories": sorted(list(categories))}


class VersionCommand(BaseCommand):
    """Get admin CLI version information."""
    name = "version"
    description = "Get admin CLI version information"
    permissions = ["admin:read"]
    category = "system"

    @classmethod
    @require_permission("admin:read")
    def execute(cls) -> Dict[str, Any]:
        """
        Get admin CLI version information.

        Returns:
            Version information dictionary
        """
        from admin.cli.admin_commands import VERSION

        return {
            "version": VERSION,
            "python_version": sys.version,
            "platform": sys.platform
        }


class CheckPermissionsCommand(BaseCommand):
    """Check if current user has specified permissions."""
    name = "check-permissions"
    description = "Check if current user has specified permissions"
    permissions = ["admin:user:read"]
    category = "security"

    @classmethod
    @require_permission("admin:user:read")
    def execute(cls, permissions: List[str]) -> Dict[str, Any]:
        """
        Check if current user has specified permissions.

        Args:
            permissions: List of permission strings to check

        Returns:
            Permission check results
        """
        from admin.utils.admin_auth import check_permission

        results = {}
        for permission in permissions:
            results[permission] = check_permission(None, permission)

        return {
            "permissions": results,
            "has_all": all(results.values())
        }


# Register all commands when this module is imported
HelpCommand.register()
ListCategoriesCommand.register()
VersionCommand.register()
CheckPermissionsCommand.register()
