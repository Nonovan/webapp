#!/usr/bin/env python3
"""
Command testing utilities for the Cloud Infrastructure Platform admin CLI.

This module provides utilities for testing commands without executing them,
as well as mocking dependencies and validating command behavior.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple

# Add project root to path to allow imports from core packages
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from admin.cli.admin_commands import (
    register_command, execute_command, enable_test_mode, disable_test_mode,
    get_test_results, clear_test_results, COMMAND_REGISTRY, COMMAND_DEPENDENCIES,
    EXIT_TEST_MODE
)

logger = logging.getLogger(__name__)

__all__ = [
    "CommandTester",
    "mock_command",
    "verify_command_called",
    "verify_command_args",
    "verify_command_permissions"
]


class CommandTester:
    """
    Utility class for testing command execution.

    This class manages the test environment for commands, including
    setting up test mode, recording command executions, and verifying
    command behavior.
    """

    def __init__(self, auto_enable: bool = True):
        """
        Initialize a new command tester.

        Args:
            auto_enable: Whether to automatically enable test mode
        """
        self.previous_mode = False
        self.mocked_commands = set()

        if auto_enable:
            self.enable_test_mode()

    def enable_test_mode(self) -> None:
        """Enable test mode for command execution."""
        enable_test_mode()
        clear_test_results()

    def disable_test_mode(self) -> None:
        """Disable test mode for command execution."""
        disable_test_mode()

    def reset(self) -> None:
        """Reset test state and clear recorded results."""
        clear_test_results()

    def mock_command(self, name: str, result: Dict[str, Any] = None) -> None:
        """
        Mock a command to return a specific result without executing.

        Args:
            name: Name of the command to mock
            result: Result the command should return (default: empty dict)
        """
        # Create a mock handler that just returns the specified result
        def mock_handler(**kwargs):
            return result or {}

        # Register or override the command
        register_command(
            name=name,
            handler=mock_handler,
            description=f"Mocked command: {name}",
            category="test"
        )

        # Track this as a mocked command
        self.mocked_commands.add(name)
        logger.debug(f"Registered mock command: {name}")

    def verify_command_called(self, name: str, times: int = None) -> bool:
        """
        Verify that a command was called the expected number of times.

        Args:
            name: Name of the command to verify
            times: Expected number of calls (None for any number > 0)

        Returns:
            True if the command was called as expected, False otherwise
        """
        results = get_test_results()
        actual_calls = len(results.get(name, []))

        if times is None:
            return actual_calls > 0
        else:
            return actual_calls == times

    def verify_command_args(self, name: str, expected_args: Dict[str, Any],
                           call_index: int = 0) -> bool:
        """
        Verify that a command was called with the expected arguments.

        Args:
            name: Name of the command to verify
            expected_args: Expected arguments dictionary
            call_index: Which call to check (0-based index)

        Returns:
            True if the arguments match, False otherwise
        """
        results = get_test_results()
        calls = results.get(name, [])

        if not calls or call_index >= len(calls):
            return False

        actual_args = calls[call_index]["args"]

        # Check that all expected args are present with matching values
        for key, value in expected_args.items():
            if key not in actual_args or actual_args[key] != value:
                return False

        return True

    def get_command_calls(self, name: str) -> List[Dict[str, Any]]:
        """
        Get all recorded calls for a command.

        Args:
            name: Name of the command

        Returns:
            List of call records including arguments and context
        """
        results = get_test_results()
        return results.get(name, [])

    def execute(self, command: str, args: Dict[str, Any] = None,
               auth_token: str = None, mfa_token: str = None) -> Tuple[int, Dict[str, Any]]:
        """
        Execute a command in test mode.

        Args:
            command: Name of the command to execute
            args: Command arguments (default: empty dict)
            auth_token: Optional authentication token
            mfa_token: Optional MFA token

        Returns:
            Tuple of (exit_code, result)
        """
        return execute_command(
            command_name=command,
            args=args or {},
            auth_token=auth_token,
            mfa_token=mfa_token
        )

    def __enter__(self):
        """Context manager entry - enables test mode."""
        self.previous_mode = get_test_results() != {}  # Approximate check for test mode
        self.enable_test_mode()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - restores previous mode."""
        if not self.previous_mode:
            self.disable_test_mode()


# Module-level convenience functions
def mock_command(name: str, result: Dict[str, Any] = None) -> None:
    """
    Mock a command to return a specific result.

    Args:
        name: Name of the command to mock
        result: Result to return (default: empty dict)
    """
    tester = CommandTester(auto_enable=False)
    tester.mock_command(name, result)


def verify_command_called(name: str, times: int = None) -> bool:
    """
    Verify that a command was called the expected number of times.

    Args:
        name: Name of the command to verify
        times: Expected number of calls (None for any number > 0)

    Returns:
        True if the command was called as expected, False otherwise
    """
    tester = CommandTester(auto_enable=False)
    return tester.verify_command_called(name, times)


def verify_command_args(name: str, expected_args: Dict[str, Any],
                       call_index: int = 0) -> bool:
    """
    Verify that a command was called with the expected arguments.

    Args:
        name: Name of the command to verify
        expected_args: Expected arguments dictionary
        call_index: Which call to check (0-based index)

    Returns:
        True if the arguments match, False otherwise
    """
    tester = CommandTester(auto_enable=False)
    return tester.verify_command_args(name, expected_args, call_index)


def verify_command_permissions(name: str) -> Set[str]:
    """
    Get the permissions required by a command.

    Args:
        name: Name of the command

    Returns:
        Set of permission strings required by the command
    """
    command = COMMAND_REGISTRY.get(name)
    if not command:
        return set()

    return set(command["permissions"])
