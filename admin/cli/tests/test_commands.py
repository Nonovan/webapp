#!/usr/bin/env python3
"""
Test suite for admin commands framework.

This module demonstrates how to use the command testing facilities
to test command behavior without actually executing commands.
"""

import unittest
import json
import sys
from pathlib import Path
from typing import Dict, Any

# Add project root to path to allow imports from core packages
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from admin.cli.admin_commands import register_command, validate_dependencies, ValidationError
from admin.cli.command_tester import CommandTester, verify_command_called, verify_command_args


class CommandTestCase(unittest.TestCase):
    """Test case for admin commands."""

    def setUp(self):
        """Set up test case."""
        self.tester = CommandTester()

        # Register test commands
        register_command(
            name="test-echo",
            handler=self._echo_command,
            description="Echo command for testing",
            permissions=["admin:test"],
            category="test"
        )

        register_command(
            name="test-add",
            handler=self._add_command,
            description="Addition command for testing",
            permissions=["admin:test"],
            category="test"
        )

        # Register commands with dependencies
        register_command(
            name="parent-command",
            handler=self._parent_command,
            description="Parent command for testing dependencies",
            permissions=["admin:test"],
            category="test",
            dependencies=["child-command"]
        )

        register_command(
            name="child-command",
            handler=self._child_command,
            description="Child command for testing dependencies",
            permissions=["admin:test"],
            category="test"
        )

    def tearDown(self):
        """Clean up after test."""
        self.tester.disable_test_mode()
        self.tester = None

    def _echo_command(self, message: str = "Hello", **kwargs) -> Dict[str, Any]:
        """Test echo command implementation."""
        return {"message": message}

    def _add_command(self, a: int, b: int, **kwargs) -> Dict[str, Any]:
        """Test addition command implementation."""
        return {"result": a + b}

    def _parent_command(self, **kwargs) -> Dict[str, Any]:
        """Test parent command implementation."""
        return {"status": "parent-executed"}

    def _child_command(self, **kwargs) -> Dict[str, Any]:
        """Test child command implementation."""
        return {"status": "child-executed"}

    def test_command_execution(self):
        """Test basic command execution in test mode."""
        # Execute command
        exit_code, result = self.tester.execute("test-echo", {"message": "Test"})

        # Verify test mode exit code
        self.assertEqual(exit_code, 100)
        self.assertTrue(result["test_mode"])

        # Verify command was called
        self.assertTrue(verify_command_called("test-echo"))

        # Verify arguments
        self.assertTrue(verify_command_args("test-echo", {"message": "Test"}))

    def test_multiple_commands(self):
        """Test executing multiple commands."""
        # Execute first command
        self.tester.execute("test-echo", {"message": "First"})

        # Execute second command
        self.tester.execute("test-add", {"a": 5, "b": 7})

        # Verify both commands were called
        self.assertTrue(verify_command_called("test-echo"))
        self.assertTrue(verify_command_called("test-add"))

        # Verify arguments for second command
        self.assertTrue(verify_command_args("test-add", {"a": 5, "b": 7}))

        # Get all calls to echo command
        calls = self.tester.get_command_calls("test-echo")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"]["message"], "First")

    def test_dependency_validation(self):
        """Test command dependency validation."""
        # This should work because child-command exists
        validate_dependencies("parent-command")

        # Create a command with missing dependency
        register_command(
            name="broken-command",
            handler=lambda: None,
            description="Command with broken dependency",
            dependencies=["non-existent-command"]
        )

        # This should raise a ValidationError
        with self.assertRaises(ValidationError):
            validate_dependencies("broken-command")

    def test_command_mocking(self):
        """Test mocking commands."""
        # Mock a command
        self.tester.mock_command("mocked-command", {"status": "success", "data": [1, 2, 3]})

        # Execute the mocked command
        exit_code, result = self.tester.execute("mocked-command", {"param": "value"})

        # Verify it was called
        self.assertTrue(verify_command_called("mocked-command"))

        # Verify arguments
        self.assertTrue(verify_command_args("mocked-command", {"param": "value"}))


if __name__ == "__main__":
    unittest.main()
