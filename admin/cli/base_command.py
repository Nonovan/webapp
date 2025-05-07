"""
Base class for command handlers in the administrative CLI.

This module provides a standardized base class that all command handlers
should inherit from to ensure consistent behavior, proper permission
validation, and audit logging.
"""

import logging
from typing import Dict, List, Any, Optional

from admin.utils.audit_utils import log_admin_action

logger = logging.getLogger(__name__)

__all__ = [

]

class BaseCommand:
    """Base class for all admin command handlers."""

    # Default attributes that can be overridden by subclasses
    name = None
    description = None
    permissions = []
    requires_mfa = False
    category = "general"

    @classmethod
    def register(cls):
        """Register this command with the command registry."""
        from admin.cli.admin_commands import register_command

        if cls.name is None:
            raise ValueError(f"Command class {cls.__name__} must define a name")

        register_command(
            name=cls.name,
            handler=cls.execute,
            description=cls.description or cls.__doc__ or "",
            permissions=cls.permissions,
            requires_mfa=cls.requires_mfa,
            category=cls.category
        )
        logger.debug(f"Registered command '{cls.name}' in category '{cls.category}'")

    @classmethod
    def execute(cls, **kwargs) -> Dict[str, Any]:
        """
        Execute the command with the provided arguments.

        This method should be implemented by subclasses.

        Args:
            **kwargs: Command arguments

        Returns:
            Command result as a dictionary
        """
        raise NotImplementedError("Subclasses must implement execute()")

    @staticmethod
    def log_action(action: str, details: Dict[str, Any], user_id: Optional[str] = None,
                  status: str = "success") -> None:
        """
        Log an administrative action.

        Args:
            action: Action name
            details: Action details
            user_id: User ID performing the action
            status: Action status
        """
        try:
            log_admin_action(action=action, user_id=user_id, details=details, status=status)
        except Exception as e:
            logger.error(f"Failed to log admin action: {e}")
