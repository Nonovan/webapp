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
from typing import Dict, List, Any, Optional, Callable, Tuple, Union

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
EXIT_OPERATION_CANCELLED = 7

# Command registry
COMMAND_REGISTRY = {}


__all__ = [
    "register_command",
    "execute_command",

    "CommandError",
    "ValidationError",
    "PermissionError",
    "AuthenticationError",

    "list_commands",
    "get_command_help",
    "format_output",
    "mask_sensitive_data",
    "authenticate",
    "help_command",
    "list_categories_command",
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


def register_command(
    name: str,
    handler: Callable,
    description: str,
    permissions: List[str] = None,
    requires_mfa: bool = False,
    category: str = "general"
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

    logger.debug("Registered command '%s' in category '%s'", name, category)


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
    """
    start_time = time.time()
    command = COMMAND_REGISTRY.get(command_name)

    if not command:
        logger.error("Unknown command: %s", command_name)
        return EXIT_ERROR, {"error": f"Unknown command: {command_name}"}

    try:
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

    except CommandError as e:
        logger.error("Command error: %s", e)
        return EXIT_ERROR, {"error": str(e)}

    except Exception as e:
        logger.exception("Unhandled exception in command execution")
        return EXIT_ERROR, {"error": f"Internal error: {str(e)}"}


def format_output(data: Any, output_format: str = "text") -> str:
    """
    Format command output in the requested format.

    Args:
        data: Output data to format
        output_format: Format to use (text, json, csv, table)

    Returns:
        Formatted output string
    """
    if output_format == "json":
        return json.dumps(data, indent=2, default=str)

    elif output_format == "csv":
        if not isinstance(data, list) or not data:
            return "No data or invalid format for CSV output"

        import csv
        import io

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

        return output.getvalue()

    elif output_format == "table":
        if not isinstance(data, list) or not data:
            return "No data or invalid format for table output"

        # Simple ASCII table implementation
        columns = list(data[0].keys())
        col_widths = {col: len(col) for col in columns}

        # Find maximum width for each column
        for row in data:
            for col in columns:
                width = len(str(row.get(col, "")))
                col_widths[col] = max(col_widths[col], width)

        # Generate header
        header = " | ".join(col.ljust(col_widths[col]) for col in columns)
        separator = "-+-".join("-" * col_widths[col] for col in columns)

        # Generate rows
        rows = []
        for row in data:
            formatted_row = " | ".join(
                str(row.get(col, "")).ljust(col_widths[col]) for col in columns
            )
            rows.append(formatted_row)

        return "\n".join([header, separator] + rows)

    else:  # Default text format
        if isinstance(data, dict):
            return "\n".join(f"{k}: {v}" for k, v in data.items())
        elif isinstance(data, list):
            return "\n".join(str(item) for item in data)
        else:
            return str(data)


def mask_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mask sensitive data in command arguments for logging.

    Args:
        data: Command arguments dictionary

    Returns:
        Dictionary with sensitive values masked
    """
    if not isinstance(data, dict):
        return data

    sensitive_fields = [
        "password", "secret", "token", "key", "auth", "credential",
        "api_key", "private", "access_key", "secret_key"
    ]

    masked_data = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_fields):
            masked_data[key] = "******" if value else value
        elif isinstance(value, dict):
            masked_data[key] = mask_sensitive_data(value)
        elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
            masked_data[key] = [mask_sensitive_data(item) for item in value]
        else:
            masked_data[key] = value

    return masked_data


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

        commands.append({
            "name": name,
            "description": info["description"],
            "category": info["category"],
            "requires_permissions": bool(info["permissions"]),
            "requires_mfa": info["requires_mfa"]
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

    return {
        "name": command_name,
        "description": command["description"],
        "documentation": doc,
        "category": command["category"],
        "parameters": parameters,
        "examples": examples,
        "permissions": command["permissions"],
        "requires_mfa": command["requires_mfa"]
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


# Built-in commands
@require_permission("admin:read")
def help_command(command: str = None, category: str = None) -> Dict[str, Any]:
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
    if command:
        return get_command_help(command)
    else:
        return {"commands": list_commands(category)}


@require_permission("admin:read")
def list_categories_command() -> Dict[str, Any]:
    """
    List all available command categories.

    Returns:
        Dictionary with list of categories
    """
    categories = set()
    for cmd_info in COMMAND_REGISTRY.values():
        categories.add(cmd_info["category"])

    return {"categories": sorted(list(categories))}


@require_permission("admin:read")
def version_command() -> Dict[str, Any]:
    """
    Get admin CLI version information.

    Returns:
        Version information dictionary
    """
    return {
        "version": VERSION,
        "python_version": sys.version,
        "platform": sys.platform
    }


@require_permission("admin:user:read")
def check_permissions_command(permissions: List[str]) -> Dict[str, Any]:
    """
    Check if current user has specified permissions.

    Args:
        permissions: List of permission strings to check

    Returns:
        Permission check results
    """
    results = {}
    for permission in permissions:
        results[permission] = check_permission(None, permission)

    return {
        "permissions": results,
        "has_all": all(results.values())
    }


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
