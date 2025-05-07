#!/usr/bin/env python3
"""
Command registry and execution framework for the Cloud Infrastructure Platform admin CLI.

This module provides a centralized framework for managing, discovering, and executing
administrative commands. It implements common functionality such as authentication,
permission verification, input validation, output formatting, and audit logging.

The command registry enables a consistent interface for all administrative operations
while ensuring appropriate security controls and audit trails for administrative
actions across development, staging, and production environments.
"""

import argparse
import datetime
import importlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Tuple, Union, Set

# Add project root to path to allow imports from core packages
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from admin.utils.admin_auth import (
    get_admin_session, check_permission,
    require_permission, verify_mfa_token
)
from admin.utils.audit_utils import log_admin_action
from admin.utils.secure_credentials import secure_credential
from core.security import require_mfa
from core.security.cs_audit import log_security_event as audit_log
from core.security.cs_authentication import authenticate_user, is_ip_in_whitelist
from core.security.cs_authorization import verify_permission

# Core utilities
from core.utils.logging_utils import logger as core_logger
from admin.utils.formatters import format_output, mask_sensitive_data

# Create a module-level logger
logger = logging.getLogger(__name__)

# Constants
VERSION = "1.0.0"
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_AUTHENTICATION_ERROR = 5
EXIT_DEPENDENCY_ERROR = 6
EXIT_OPERATION_CANCELLED = 7
EXIT_TEST_MODE = 100  # Special exit code for test mode

# Command registry
COMMAND_REGISTRY = {}
# Track command dependencies
COMMAND_DEPENDENCIES = {}
# Test mode settings
TEST_MODE = False
TEST_RESULTS = {}

__all__ = [
    "register_command",
    "execute_command",
    "add_command_dependency",
    "validate_dependencies",
    "enable_test_mode",
    "disable_test_mode",
    "get_test_results",
    "clear_test_results",

    "CommandError",
    "ValidationError",
    "PermissionError",
    "AuthenticationError",
    "DependencyError",

    "list_commands",
    "get_command_help",
    "format_output",
    "mask_sensitive_data",
    "authenticate",
]


class CommandError(Exception):
    """Base exception for command execution errors."""
    pass


class ValidationError(CommandError):
    """Raised when command validation fails."""
    pass


class PermissionError(CommandError):
    """Raised when permission verification fails."""
    pass


class AuthenticationError(CommandError):
    """Raised when authentication fails."""
    pass


class DependencyError(CommandError):
    """Raised when a command dependency cannot be satisfied."""
    pass


def enable_test_mode() -> None:
    """
    Enable test mode for commands.

    In test mode, commands are registered but not actually executed.
    Instead, their arguments and context are recorded for inspection.
    """
    global TEST_MODE
    TEST_MODE = True
    clear_test_results()
    logger.info("Test mode enabled for admin commands")


def disable_test_mode() -> None:
    """
    Disable test mode for commands.
    """
    global TEST_MODE
    TEST_MODE = False
    logger.info("Test mode disabled for admin commands")


def get_test_results() -> Dict[str, List[Dict[str, Any]]]:
    """
    Get the recorded command execution attempts from test mode.

    Returns:
        Dictionary of command names to lists of execution attempts,
        each containing the arguments and context of the execution.
    """
    return TEST_RESULTS


def clear_test_results() -> None:
    """
    Clear all recorded test results.
    """
    global TEST_RESULTS
    TEST_RESULTS = {}
    logger.debug("Test results cleared")


def register_command(
    name: str,
    handler: Callable,
    description: str,
    permissions: List[str] = None,
    requires_mfa: bool = False,
    category: str = "general",
    dependencies: List[str] = None
) -> None:
    """
    Register a command in the global command registry.

    Args:
        name: Command name (used for invocation)
        handler: Function that implements the command
        description: Brief description of the command
        permissions: List of permissions required to execute the command
        requires_mfa: Whether MFA verification is required for this command
        category: Command category for organization in help/docs
        dependencies: List of command names this command depends on
    """
    if name in COMMAND_REGISTRY:
        logger.warning("Command '%s' is already registered, overwriting", name)

    COMMAND_REGISTRY[name] = {
        "handler": handler,
        "description": description,
        "permissions": permissions or [],
        "requires_mfa": requires_mfa,
        "category": category
    }

    # Register dependencies if provided
    if dependencies:
        COMMAND_DEPENDENCIES[name] = set(dependencies)

    logger.debug("Registered command '%s' in category '%s'", name, category)


def add_command_dependency(from_command: str, to_command: str) -> None:
    """
    Add a dependency between commands.

    Args:
        from_command: The command that depends on another
        to_command: The command that is depended upon

    Raises:
        ValidationError: If a circular dependency would be created
    """
    # Check if this would create a circular dependency
    if _has_circular_dependency(to_command, from_command):
        raise ValidationError(
            f"Cannot add dependency from '{from_command}' to '{to_command}': "
            f"would create circular dependency"
        )

    if from_command not in COMMAND_DEPENDENCIES:
        COMMAND_DEPENDENCIES[from_command] = set()

    COMMAND_DEPENDENCIES[from_command].add(to_command)
    logger.debug("Added dependency from '%s' to '%s'", from_command, to_command)


def _has_circular_dependency(from_cmd: str, to_cmd: str, visited: Set[str] = None) -> bool:
    """
    Check if adding a dependency would create a circular reference.

    Args:
        from_cmd: Command being checked
        to_cmd: Target command that would depend on from_cmd
        visited: Set of already visited commands (for recursion)

    Returns:
        True if a circular dependency would be created, False otherwise
    """
    if visited is None:
        visited = set()

    # If we've found the target command in the dependency chain, we have a cycle
    if from_cmd == to_cmd:
        return True

    # Avoid revisiting nodes
    if from_cmd in visited:
        return False

    # Add current command to visited set
    visited.add(from_cmd)

    # Check dependencies of the current command
    dependencies = COMMAND_DEPENDENCIES.get(from_cmd, set())
    for dependency in dependencies:
        if _has_circular_dependency(dependency, to_cmd, visited):
            return True

    return False


def validate_dependencies(command_name: str) -> bool:
    """
    Validate that all dependencies for a command are available.

    Args:
        command_name: Name of the command to check

    Returns:
        True if all dependencies are satisfied, False otherwise

    Raises:
        ValidationError: If a dependency is not registered
    """
    dependencies = COMMAND_DEPENDENCIES.get(command_name, set())

    for dependency in dependencies:
        if dependency not in COMMAND_REGISTRY:
            raise ValidationError(
                f"Command '{command_name}' depends on '{dependency}', "
                f"which is not registered"
            )

    return True


def execute_command(
    command_name: str,
    args: Dict[str, Any],
    auth_token: str = None,
    mfa_token: str = None,
    session_id: str = None
) -> Tuple[int, Dict[str, Any]]:
    """
    Execute a registered command with authentication and permission checks.

    Args:
        command_name: Name of the command to execute
        args: Command arguments
        auth_token: Authentication token (JWT)
        mfa_token: Multi-factor authentication token
        session_id: Session identifier

    Returns:
        Tuple with exit code and result dictionary

    Raises:
        CommandError: If command execution fails
        ValidationError: If command arguments are invalid
        PermissionError: If permission verification fails
        AuthenticationError: If authentication fails
        DependencyError: If command dependencies are not satisfied
    """
    start_time = time.time()

    # Handle test mode
    if TEST_MODE:
        # Record this execution attempt
        if command_name not in TEST_RESULTS:
            TEST_RESULTS[command_name] = []

        execution_record = {
            "args": args.copy(),
            "auth_token": auth_token is not None,
            "mfa_token": mfa_token is not None,
            "session_id": session_id,
            "timestamp": datetime.datetime.now().isoformat(),
        }
        TEST_RESULTS[command_name].append(execution_record)

        # In test mode, just return success with a test indicator
        return EXIT_TEST_MODE, {
            "test_mode": True,
            "command": command_name,
            "args": args,
            "message": "Command execution simulated in test mode"
        }

    command = COMMAND_REGISTRY.get(command_name)

    if not command:
        logger.error("Unknown command: %s", command_name)
        return EXIT_ERROR, {"error": f"Unknown command: {command_name}"}

    try:
        # Validate command dependencies
        try:
            validate_dependencies(command_name)
        except ValidationError as e:
            logger.error("Dependency validation failed: %s", e)
            return EXIT_DEPENDENCY_ERROR, {"error": str(e)}

        # Authenticate if token provided
        user_info = None
        if auth_token:
            user_info = get_admin_session(auth_token)
            if not user_info:
                raise AuthenticationError("Invalid or expired authentication token")

            # Log the authentication
            logger.info("User %s authenticated for command %s",
                      user_info.get("username", "unknown"), command_name)

        # Check permissions if required
        if command["permissions"] and not user_info:
            raise PermissionError("Authentication required for this command")

        if command["permissions"] and user_info:
            for permission in command["permissions"]:
                if not check_permission(auth_token, permission):
                    logger.warning("Permission denied: %s required for %s",
                                 permission, command_name)
                    raise PermissionError(f"Permission denied: {permission} required")

        # Check MFA if required
        if command["requires_mfa"]:
            if not mfa_token:
                raise AuthenticationError("MFA token required for this command")

            if not verify_mfa_token(user_info.get("username"), mfa_token):
                logger.warning("Invalid MFA token provided by %s",
                             user_info.get("username", "unknown"))
                raise AuthenticationError("Invalid MFA token")

        # Execute the command
        logger.info("Executing command '%s' with args: %s",
                  command_name, mask_sensitive_data(args))

        result = command["handler"](**args)

        # Log the successful execution
        execution_time = time.time() - start_time
        logger.info("Command '%s' executed successfully (%.2fs)",
                  command_name, execution_time)

        # Audit log for sensitive operations
        if user_info and (command["requires_mfa"] or command["permissions"]):
            try:
                log_admin_action(
                    action=f"command.{command_name}",
                    user_id=user_info.get("user_id"),
                    details={
                        "command": command_name,
                        "args": mask_sensitive_data(args),
                        "execution_time": execution_time
                    },
                    status="success"
                )
            except Exception as e:
                logger.error("Failed to log admin action: %s", e)

        return EXIT_SUCCESS, result

    except ValidationError as e:
        logger.error("Validation error: %s", e)
        return EXIT_VALIDATION_ERROR, {"error": str(e)}

    except PermissionError as e:
        logger.error("Permission error: %s", e)
        return EXIT_PERMISSION_ERROR, {"error": str(e)}

    except AuthenticationError as e:
        logger.error("Authentication error: %s", e)
        return EXIT_AUTHENTICATION_ERROR, {"error": str(e)}

    except DependencyError as e:
        logger.error("Dependency error: %s", e)
        return EXIT_DEPENDENCY_ERROR, {"error": str(e)}

    except CommandError as e:
        logger.error("Command error: %s", e)
        return EXIT_ERROR, {"error": str(e)}

    except Exception as e:
        logger.exception("Unhandled exception in command execution")
        return EXIT_ERROR, {"error": f"Internal error: {str(e)}"}


def list_commands(category: str = None) -> List[Dict[str, Any]]:
    """
    List available commands, optionally filtered by category.

    Args:
        category: Optional category filter

    Returns:
        List of command information dictionaries
    """
    commands = []

    for name, info in COMMAND_REGISTRY.items():
        if category and info["category"] != category:
            continue

        # Include dependency information for each command
        dependencies = list(COMMAND_DEPENDENCIES.get(name, set()))

        commands.append({
            "name": name,
            "description": info["description"],
            "category": info["category"],
            "requires_permissions": bool(info["permissions"]),
            "requires_mfa": info["requires_mfa"],
            "dependencies": dependencies
        })

    # Sort by category then name
    commands.sort(key=lambda c: (c["category"], c["name"]))
    return commands


def get_command_help(command_name: str) -> Dict[str, Any]:
    """
    Get detailed help information for a specific command.

    Args:
        command_name: Name of the command

    Returns:
        Command help information as a dictionary
    """
    command = COMMAND_REGISTRY.get(command_name)
    if not command:
        return {"error": f"Unknown command: {command_name}"}

    handler = command["handler"]

    # Get parameter information from function annotations and docstring
    import inspect
    signature = inspect.signature(handler)
    doc = inspect.getdoc(handler) or ""

    # Parse parameters
    parameters = []
    for name, param in signature.parameters.items():
        parameters.append({
            "name": name,
            "required": param.default == inspect.Parameter.empty,
            "default": None if param.default == inspect.Parameter.empty else param.default,
            "type": str(param.annotation) if param.annotation != inspect.Parameter.empty else "any"
        })

    # Parse docstring for examples
    examples = []
    in_examples = False
    for line in doc.split("\n"):
        if line.strip().lower().startswith("example"):
            in_examples = True
            continue
        if in_examples and line.strip():
            examples.append(line.strip())

    # Include dependency information
    dependencies = list(COMMAND_DEPENDENCIES.get(command_name, set()))

    return {
        "name": command_name,
        "description": command["description"],
        "documentation": doc,
        "category": command["category"],
        "parameters": parameters,
        "examples": examples,
        "permissions": command["permissions"],
        "requires_mfa": command["requires_mfa"],
        "dependencies": dependencies
    }


def authenticate(username: str, password: str) -> Dict[str, Any]:
    """
    Authenticate user and generate session token.

    Args:
        username: User's username
        password: User's password

    Returns:
        Authentication response with token or error
    """
    try:
        auth_result = authenticate_user(username, password)

        if not auth_result:
            logger.warning("Authentication failed for user: %s", username)
            return {"success": False, "error": "Invalid credentials"}

        # Check if user has any admin permissions
        user_id = auth_result.get("user_id")
        admin_permissions = verify_permission(user_id, "admin:*")

        if not admin_permissions:
            logger.warning("User %s authenticated but has no admin permissions", username)
            return {
                "success": False,
                "error": "User does not have administrative permissions"
            }

        # Generate session token
        token = auth_result.get("token")

        # Log successful authentication
        logger.info("Admin authentication successful for user: %s", username)
        audit_log(
            "admin_authentication",
            "successful",
            details={"username": username, "admin_access": True}
        )

        return {
            "success": True,
            "token": token,
            "user": {
                "username": username,
                "user_id": user_id,
                "permissions": admin_permissions,
                "requires_mfa": auth_result.get("requires_mfa", False)
            }
        }

    except Exception as e:
        logger.exception("Authentication error")
        return {"success": False, "error": str(e)}


def setup_cli_parser() -> argparse.ArgumentParser:
    """
    Set up command line argument parser.

    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Cloud Infrastructure Platform Admin CLI",
        epilog="For detailed help on a specific command, use: %(prog)s --command COMMAND_NAME --help"
    )

    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--username", help="Username for authentication")
    auth_group.add_argument("--password", help="Password for authentication")
    auth_group.add_argument("--token", help="Authentication token (alternative to username/password)")
    auth_group.add_argument("--mfa-token", help="MFA token for commands requiring additional verification")

    # Command specification
    parser.add_argument("--command", help="Command to execute")
    parser.add_argument("--args", help="Command arguments in JSON format")
    parser.add_argument("--auth", action="store_true", help="Authenticate and print token")
    parser.add_argument("--check-dependencies", action="store_true", help="Check command dependencies only")

    # Testing options
    test_group = parser.add_argument_group("Testing")
    test_group.add_argument("--test-mode", action="store_true", help="Enable test mode (no actual execution)")
    test_group.add_argument("--dump-test-results", help="Dump test results to specified file")

    # Output options
    parser.add_argument("--format", choices=["text", "json", "csv", "table"], default="text",
                      help="Output format (default: text)")
    parser.add_argument("--output", help="Output file (default: stdout)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--silent", action="store_true", help="Suppress all non-error output")

    # Built-in commands
    parser.add_argument("--list-commands", action="store_true", help="List available commands")
    parser.add_argument("--list-categories", action="store_true", help="List command categories")
    parser.add_argument("--version", action="store_true", help="Show version information")
    parser.add_argument("--help-command", help="Show help for a specific command")

    return parser


def load_command_modules():
    """
    Dynamically load all command modules to register commands.
    """
    commands_dir = Path(__file__).parent / "commands"
    if not commands_dir.exists():
        logger.warning(f"Commands directory not found: {commands_dir}")
        return

    for file_path in commands_dir.glob("*.py"):
        if file_path.name.startswith("_"):
            continue

        module_name = f"admin.cli.commands.{file_path.stem}"
        try:
            importlib.import_module(module_name)
            logger.debug(f"Loaded command module: {module_name}")
        except ImportError as e:
            logger.error(f"Failed to import command module {module_name}: {e}")


def main() -> int:
    """
    Main CLI entry point.

    Returns:
        Exit code
    """
    # Load command modules which will register their commands
    load_command_modules()

    # Set up parser and parse arguments
    parser = setup_cli_parser()
    args = parser.parse_args()

    # Configure logging level based on verbosity
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    elif args.silent:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)

    # Handle test mode
    if args.test_mode:
        enable_test_mode()
        logger.info("Running in test mode - commands will not actually execute")

    try:
        # Handle authentication
        auth_token = None
        if args.auth or (args.username and args.password):
            if not args.username or not args.password:
                print("Error: Both username and password are required for authentication")
                return EXIT_AUTHENTICATION_ERROR

            auth_result = authenticate(args.username, args.password)

            if not auth_result["success"]:
                print(f"Authentication failed: {auth_result.get('error', 'Unknown error')}")
                return EXIT_AUTHENTICATION_ERROR

            auth_token = auth_result["token"]

            # If just authenticating, print token and exit
            if args.auth:
                output = auth_result
                if args.format == "json":
                    print(json.dumps(output, indent=2))
                else:
                    print(f"Authentication successful")
                    print(f"Token: {auth_token}")
                    print(f"User: {auth_result['user']['username']}")
                    print(f"MFA required: {auth_result['user']['requires_mfa']}")
                return EXIT_SUCCESS
        elif args.token:
            auth_token = args.token

        # Check dependencies if requested
        if args.check_dependencies and args.command:
            try:
                validate_dependencies(args.command)
                print(f"All dependencies for command '{args.command}' are satisfied")
                return EXIT_SUCCESS
            except ValidationError as e:
                print(f"Dependency check failed: {e}")
                return EXIT_DEPENDENCY_ERROR

        # Handle built-in command shortcuts
        if args.list_commands:
            exit_code, result = execute_command(
                "help", {}, auth_token, args.mfa_token
            )
        elif args.list_categories:
            exit_code, result = execute_command(
                "list-categories", {}, auth_token, args.mfa_token
            )
        elif args.version:
            exit_code, result = execute_command(
                "version", {}, auth_token, args.mfa_token
            )
        elif args.help_command:
            exit_code, result = execute_command(
                "help", {"command": args.help_command}, auth_token, args.mfa_token
            )
        # Handle command execution
        elif args.command:
            command_args = {}
            if args.args:
                try:
                    command_args = json.loads(args.args)
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON arguments: {e}")
                    return EXIT_VALIDATION_ERROR

            exit_code, result = execute_command(
                args.command, command_args, auth_token, args.mfa_token
            )
        else:
            # No command specified, show help
            parser.print_help()
            return EXIT_SUCCESS

        # Format and output result
        output_str = format_output(result, args.format)

        if args.output:
            with open(args.output, "w") as f:
                f.write(output_str)
                if not args.silent:
                    print(f"Output written to {args.output}")
        else:
            print(output_str)

        # Handle test mode results
        if args.test_mode and args.dump_test_results:
            test_results = get_test_results()
            with open(args.dump_test_results, 'w') as f:
                json.dump(test_results, f, indent=2)
                if not args.silent:
                    print(f"Test results written to {args.dump_test_results}")

        return exit_code

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return EXIT_OPERATION_CANCELLED

    except Exception as e:
        logger.exception("Unhandled exception in main")
        print(f"Error: {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
