#!/usr/bin/env python3
"""
System Configuration Administration for Cloud Infrastructure Platform.

This module provides a command-line interface for administrators to view,
modify, and manage system configuration settings stored in the database.
It allows managing configurations across different environments, importing
and exporting settings, and validating configuration changes against schemas.

The system configuration tool includes protections for sensitive settings,
validation of configuration values against defined rules, and comprehensive
auditing of all configuration changes.
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set

# Add project root to path to allow imports from core packages
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from admin.utils.admin_auth import (
    get_admin_session, check_permission, verify_mfa_token
)
from admin.utils.config_validation import (
    validate_config, load_schema, ValidationResult
)
from admin.utils.audit_utils import log_admin_action
from core.security import require_permission
from models.security import SystemConfig
from extensions import db

# Core utilities
from core.utils.logging_utils import logger as core_logger

# Create a module-level logger
logger = logging.getLogger(__name__)

# Exit status codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PERMISSION_ERROR = 2
EXIT_VALIDATION_ERROR = 3
EXIT_NOT_FOUND = 4

# Constants
VERSION = "1.0.0"
DEFAULT_OUTPUT_FORMAT = "text"
ALLOWED_CATEGORIES = {
    "security", "system", "notification", "feature_flag",
    "appearance", "performance", "maintenance", "integration"
}
DEFAULT_SCHEMA_DIR = Path("/etc/cloud-platform/schemas")
SENSITIVE_KEYS = {"password", "key", "secret", "token", "credential"}


__all__ = [
    "get_config_value",
    "set_config_value",
    "delete_config_value",
    "list_configs",
    "export_configs",
    "import_configs",
    "validate_configs",
    "initialize_defaults",
    "format_output",
    "parse_key_value",
    "get_system_settings",
    "setup_arg_parser",
    "execute_cli",

    "ConfigurationError",
    "ValidationError",
    "PermissionError",
]


class ConfigurationError(Exception):
    """Base exception for configuration-related errors."""
    pass


class ValidationError(ConfigurationError):
    """Raised when configuration validation fails."""
    pass


class PermissionError(ConfigurationError):
    """Raised when a permission check fails."""
    pass


def get_config_value(key: str, default: Optional[str] = None, mask: bool = True) -> Optional[str]:
    """
    Get a configuration value from the database.

    Args:
        key: Configuration key to retrieve
        default: Default value if key doesn't exist
        mask: Whether to mask sensitive values

    Returns:
        Configuration value or None if not found
    """
    config = SystemConfig.query.filter_by(key=key).first()

    if config:
        value = config.value

        # Mask sensitive values if requested
        if mask and is_sensitive_key(key):
            return "********"
        return value

    return default


def is_sensitive_key(key: str) -> bool:
    """
    Check if a configuration key contains sensitive data.

    Args:
        key: Configuration key to check

    Returns:
        True if key is sensitive, False otherwise
    """
    return any(sensitive in key.lower() for sensitive in SENSITIVE_KEYS)


def set_config_value(
    key: str, value: str, category: Optional[str] = None,
    description: Optional[str] = None, validation_rules: Optional[Dict] = None,
    auth_token: Optional[str] = None, reason: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Set a configuration value in the database.

    Args:
        key: Configuration key to set
        value: Value to set
        category: Configuration category
        description: Configuration description
        validation_rules: Validation rules for the configuration
        auth_token: Authentication token
        reason: Reason for the change

    Returns:
        Tuple of (success, message)
    """
    try:
        # Check if config exists
        config = SystemConfig.query.filter_by(key=key).first()
        old_value = None

        if config:
            # Store old value for audit log
            old_value = config.value

            # Update existing config
            config.value = value
            if category:
                config.category = category
            if description:
                config.description = description
            if validation_rules:
                config.validation_rules = validation_rules

            config.updated_at = datetime.datetime.now(datetime.timezone.utc)
            message = f"Updated configuration: {key}"
        else:
            # Create new config
            if not category:
                category = "system"  # Default category

            config = SystemConfig(
                key=key,
                value=value,
                category=category,
                description=description or f"Configuration setting: {key}",
                validation_rules=validation_rules,
                created_at=datetime.datetime.now(datetime.timezone.utc)
            )
            db.session.add(config)
            message = f"Created configuration: {key}"

        # Validate the configuration value against rules if they exist
        if config.validation_rules:
            validation_error = config.validate_value(value)
            if validation_error:
                return False, f"Validation error: {validation_error}"

        # Commit the transaction
        db.session.commit()

        # Log the configuration change
        log_admin_action(
            action="system_config.change",
            details={
                "key": key,
                "new_value": "********" if is_sensitive_key(key) else value,
                "old_value": "********" if is_sensitive_key(key) else old_value,
                "category": category,
                "reason": reason
            }
        )

        return True, message

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to set configuration {key}: {e}")
        return False, f"Error setting configuration: {str(e)}"


def delete_config_value(
    key: str, auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Delete a configuration value from the database.

    Args:
        key: Configuration key to delete
        auth_token: Authentication token
        reason: Reason for deletion

    Returns:
        Tuple of (success, message)
    """
    try:
        config = SystemConfig.query.filter_by(key=key).first()

        if not config:
            return False, f"Configuration not found: {key}"

        # Check if this is a system-critical configuration that shouldn't be deleted
        if config.category == "security" and not reason:
            return False, "Cannot delete security configuration without providing a reason"

        # Delete the configuration
        db.session.delete(config)
        db.session.commit()

        # Log the deletion
        log_admin_action(
            action="system_config.delete",
            details={
                "key": key,
                "category": config.category,
                "reason": reason
            }
        )

        return True, f"Deleted configuration: {key}"

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete configuration {key}: {e}")
        return False, f"Error deleting configuration: {str(e)}"


def list_configs(
    category: Optional[str] = None,
    search: Optional[str] = None,
    mask_sensitive: bool = True
) -> List[Dict[str, Any]]:
    """
    List configuration values with optional filtering.

    Args:
        category: Optional category to filter by
        search: Optional search term to filter by
        mask_sensitive: Whether to mask sensitive values

    Returns:
        List of configuration dictionaries
    """
    query = SystemConfig.query

    if category:
        query = query.filter_by(category=category)

    if search:
        query = query.filter(SystemConfig.key.ilike(f"%{search}%") |
                            SystemConfig.description.ilike(f"%{search}%"))

    configs = query.all()
    result = []

    for config in configs:
        value = config.value

        # Mask sensitive values if requested
        if mask_sensitive and is_sensitive_key(config.key):
            value = "********"

        result.append({
            "key": config.key,
            "value": value,
            "category": config.category,
            "description": config.description,
            "updated_at": config.updated_at.isoformat() if config.updated_at else None,
            "created_at": config.created_at.isoformat() if config.created_at else None
        })

    return result


def export_configs(
    output_file: str,
    category: Optional[str] = None,
    search: Optional[str] = None,
    include_sensitive: bool = False,
    format: str = "json"
) -> Tuple[bool, str, int]:
    """
    Export configuration values to a file.

    Args:
        output_file: File to export to
        category: Optional category to filter by
        search: Optional search term to filter by
        include_sensitive: Whether to include sensitive values
        format: Output format (json or yaml)

    Returns:
        Tuple of (success, message, count)
    """
    try:
        # Get configurations
        configs = list_configs(category, search, not include_sensitive)

        # Create the output directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

        if format == "json":
            with open(output_file, 'w') as f:
                json.dump({
                    "version": VERSION,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "environment": os.environ.get("ENVIRONMENT", "development"),
                    "config_count": len(configs),
                    "configs": configs
                }, f, indent=2)

        elif format == "yaml":
            try:
                with open(output_file, 'w') as f:
                    yaml.dump({
                        "version": VERSION,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "environment": os.environ.get("ENVIRONMENT", "development"),
                        "config_count": len(configs),
                        "configs": configs
                    }, f, default_flow_style=False)
            except ImportError:
                return False, "YAML support requires PyYAML package", 0
        else:
            return False, f"Unsupported export format: {format}", 0

        # Log the export
        log_admin_action(
            action="system_config.export",
            details={
                "output_file": output_file,
                "format": format,
                "config_count": len(configs),
                "category": category,
                "search": search,
                "include_sensitive": include_sensitive
            }
        )

        return True, f"Exported {len(configs)} configurations to {output_file}", len(configs)

    except Exception as e:
        logger.error(f"Failed to export configurations: {e}")
        return False, f"Error exporting configurations: {str(e)}", 0


def import_configs(
    input_file: str,
    environment: Optional[str] = None,
    dry_run: bool = False,
    merge: bool = True,
    auth_token: Optional[str] = None,
    reason: Optional[str] = None
) -> Tuple[bool, str, Dict[str, int]]:
    """
    Import configuration values from a file.

    Args:
        input_file: File to import from
        environment: Target environment for the import
        dry_run: Whether to perform a dry run without making changes
        merge: Whether to merge with existing configurations
        auth_token: Authentication token
        reason: Reason for import

    Returns:
        Tuple of (success, message, stats)
    """
    try:
        if not os.path.exists(input_file):
            return False, f"Input file not found: {input_file}", {}

        # Read the input file
        with open(input_file, 'r') as f:
            if input_file.endswith(".json"):
                data = json.load(f)
            elif input_file.endswith(".yaml") or input_file.endswith(".yml"):
                try:
                    data = yaml.safe_load(f)
                except ImportError:
                    return False, "YAML support requires PyYAML package", {}
            else:
                return False, f"Unsupported import format: {input_file}", {}

        # Validate the file structure
        if not isinstance(data, dict) or "configs" not in data:
            return False, "Invalid import file format", {}

        # Check environment if specified
        if environment and data.get("environment") != environment:
            logger.warning(f"Import file environment ({data.get('environment')}) "
                          f"does not match target environment ({environment})")

        configs = data["configs"]
        stats = {
            "total": len(configs),
            "created": 0,
            "updated": 0,
            "failed": 0,
            "skipped": 0
        }

        if dry_run:
            logger.info(f"Dry run: Would import {len(configs)} configurations")
            return True, f"Dry run: Would import {len(configs)} configurations", stats

        # Import each configuration
        for config_data in configs:
            key = config_data.get("key")
            value = config_data.get("value")
            category = config_data.get("category", "system")
            description = config_data.get("description")

            if not key or value is None:
                logger.warning(f"Skipping invalid configuration: {config_data}")
                stats["skipped"] += 1
                continue

            # Check if configuration exists
            existing = SystemConfig.query.filter_by(key=key).first()

            if existing and not merge:
                logger.info(f"Skipping existing configuration: {key}")
                stats["skipped"] += 1
                continue

            # Set the configuration value
            success, message = set_config_value(
                key=key,
                value=value,
                category=category,
                description=description,
                auth_token=auth_token,
                reason=reason
            )

            if success:
                if existing:
                    stats["updated"] += 1
                else:
                    stats["created"] += 1
            else:
                logger.warning(f"Failed to import configuration {key}: {message}")
                stats["failed"] += 1

        # Log the import
        log_admin_action(
            action="system_config.import",
            details={
                "input_file": input_file,
                "environment": environment,
                "dry_run": dry_run,
                "merge": merge,
                "stats": stats,
                "reason": reason
            }
        )

        message = (f"Import completed: {stats['created']} created, {stats['updated']} updated, "
                  f"{stats['failed']} failed, {stats['skipped']} skipped")
        return True, message, stats

    except Exception as e:
        logger.error(f"Failed to import configurations: {e}")
        return False, f"Error importing configurations: {str(e)}", {}


def validate_configs(schema_dir: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Validate all configurations against schemas.

    Args:
        schema_dir: Directory containing validation schemas

    Returns:
        Tuple of (success, results)
    """
    try:
        schema_dir_path = Path(schema_dir) if schema_dir else DEFAULT_SCHEMA_DIR

        if not schema_dir_path.exists():
            return False, {
                "error": f"Schema directory not found: {schema_dir_path}",
                "valid": False
            }

        # Get all configurations by category
        categories = {}
        for config in SystemConfig.query.all():
            if config.category not in categories:
                categories[config.category] = {}

            categories[config.category][config.key] = config.value

        results = {
            "valid": True,
            "categories": {},
            "errors": []
        }

        # Validate each category against its schema
        for category, config_values in categories.items():
            schema_file = schema_dir_path / f"{category}.json"

            if not schema_file.exists():
                logger.warning(f"No schema found for category: {category}")
                results["categories"][category] = {
                    "valid": True,
                    "error": "No schema available"
                }
                continue

            # Load the schema
            schema = load_schema(str(schema_file))

            # Validate against schema
            validation_result = validate_config(config_values, schema)

            results["categories"][category] = {
                "valid": validation_result.is_valid,
                "errors": validation_result.errors
            }

            # Update overall validity
            if not validation_result.is_valid:
                results["valid"] = False
                results["errors"].extend([
                    f"{category}.{error.path}: {error.message}"
                    for error in validation_result.errors
                ])

        return results["valid"], results

    except Exception as e:
        logger.error(f"Failed to validate configurations: {e}")
        return False, {
            "error": f"Error validating configurations: {str(e)}",
            "valid": False
        }


def initialize_defaults() -> Tuple[bool, str, int]:
    """
    Initialize default system configurations.

    Returns:
        Tuple of (success, message, count)
    """
    try:
        # Call the model's initialize_defaults method
        SystemConfig.initialize_defaults()

        # Count the configurations
        count = SystemConfig.query.count()

        # Log the initialization
        log_admin_action(
            action="system_config.initialize_defaults",
            details={
                "config_count": count
            }
        )

        return True, f"Initialized {count} default configurations", count

    except Exception as e:
        logger.error(f"Failed to initialize default configurations: {e}")
        return False, f"Error initializing default configurations: {str(e)}", 0


def format_output(data: Any, output_format: str = DEFAULT_OUTPUT_FORMAT) -> str:
    """
    Format data for output based on the specified format.

    Args:
        data: Data to format
        output_format: Output format (text, json, yaml, table)

    Returns:
        Formatted output string
    """
    if output_format == "json":
        return json.dumps(data, indent=2, default=str)

    elif output_format == "yaml":
        try:
            return yaml.dump(data, default_flow_style=False)
        except ImportError:
            return "YAML output requires PyYAML package"

    elif output_format == "table":
        if isinstance(data, list) and data and isinstance(data[0], dict):
            # Create a simple ASCII table
            result = []

            # Get column headers from first dict
            headers = list(data[0].keys())

            # Calculate column widths
            widths = {header: len(header) for header in headers}
            for item in data:
                for header in headers:
                    if header in item:
                        widths[header] = max(widths[header], len(str(item[header] or "")))

            # Create header row
            header_row = " | ".join(h.ljust(widths[h]) for h in headers)
            separator = "-+-".join("-" * widths[h] for h in headers)

            result.append(header_row)
            result.append(separator)

            # Create data rows
            for item in data:
                row = " | ".join(
                    str(item.get(h, "")).ljust(widths[h]) for h in headers
                )
                result.append(row)

            return "\n".join(result)

        elif isinstance(data, dict):
            # Format dictionary as key-value pairs
            result = []
            for k, v in data.items():
                if isinstance(v, dict):
                    result.append(f"{k}:")
                    for sub_k, sub_v in v.items():
                        result.append(f"  {sub_k}: {sub_v}")
                else:
                    result.append(f"{k}: {v}")
            return "\n".join(result)
        else:
            return str(data)

    else:  # Default to text format
        if isinstance(data, dict):
            return "\n".join(f"{k}: {v}" for k, v in data.items())
        elif isinstance(data, list):
            return "\n".join(str(item) for item in data)
        else:
            return str(data)


def parse_key_value(arg: str) -> Tuple[str, str]:
    """
    Parse a key=value argument into a tuple.

    Args:
        arg: Key=value string

    Returns:
        Tuple of (key, value)

    Raises:
        ValueError: If the argument is not in key=value format
    """
    if "=" not in arg:
        raise ValueError(f"Invalid format: {arg} (should be key=value)")

    key, value = arg.split("=", 1)
    return key.strip(), value.strip()


def get_system_settings() -> Dict[str, Any]:
    """
    Get system environment settings.

    Returns:
        Dictionary of system settings
    """
    import platform
    import socket

    return {
        "hostname": socket.gethostname(),
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "timestamp": datetime.datetime.now().isoformat()
    }


def setup_arg_parser() -> argparse.ArgumentParser:
    """
    Set up command-line argument parser.

    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="System Configuration Management for Cloud Infrastructure Platform",
        epilog="For detailed help, see the documentation."
    )

    # Authentication
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--token", help="Authentication token")
    auth_group.add_argument("--mfa-token", help="MFA token for privileged operations")

    # Command actions (mutually exclusive)
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--show", action="store_true",
                            help="Show current configuration")
    action_group.add_argument("--get", metavar="KEY",
                            help="Get a specific configuration value")
    action_group.add_argument("--set", metavar="KEY=VALUE", action="append",
                            help="Set configuration value(s)")
    action_group.add_argument("--delete", metavar="KEY",
                            help="Delete a configuration value")
    action_group.add_argument("--export", action="store_true",
                            help="Export configurations to a file")
    action_group.add_argument("--import", dest="import_file", metavar="FILE",
                            help="Import configurations from a file")
    action_group.add_argument("--validate", action="store_true",
                            help="Validate configurations against schemas")
    action_group.add_argument("--init-defaults", action="store_true",
                            help="Initialize default configurations")
    action_group.add_argument("--version", action="store_true",
                            help="Show version information")

    # Filtering options
    filter_group = parser.add_argument_group("Filtering Options")
    filter_group.add_argument("--category",
                            help=f"Filter by category: {', '.join(sorted(ALLOWED_CATEGORIES))}")
    filter_group.add_argument("--search", help="Search term for configuration keys/descriptions")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--format", choices=["text", "json", "yaml", "table"],
                            default="text", help="Output format (default: text)")
    output_group.add_argument("--output", metavar="FILE",
                            help="Output file (default: stdout)")
    output_group.add_argument("--no-mask", action="store_true",
                            help="Do not mask sensitive values")

    # Import/Export options
    imp_exp_group = parser.add_argument_group("Import/Export Options")
    imp_exp_group.add_argument("--environment",
                             help="Target environment for import/export")
    imp_exp_group.add_argument("--dry-run", action="store_true",
                             help="Validate import without making changes")
    imp_exp_group.add_argument("--no-merge", action="store_true",
                             help="Don't update existing configurations on import")
    imp_exp_group.add_argument("--schema-dir",
                             help="Directory containing validation schemas")

    # Set options
    set_group = parser.add_argument_group("Set Options")
    set_group.add_argument("--description",
                         help="Description for new configuration")

    # Additional options
    parser.add_argument("--reason", help="Reason for the change (for audit logs)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    return parser


def execute_cli(args: argparse.Namespace) -> int:
    """
    Execute CLI commands based on parsed arguments.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code
    """
    # Check for authentication if needed for certain operations
    auth_token = args.token
    mfa_token = args.mfa_token

    operations_requiring_auth = ["set", "delete", "import_file", "init_defaults"]
    operation_name = None

    for op in operations_requiring_auth:
        if hasattr(args, op) and getattr(args, op):
            operation_name = op
            break

    # Check auth for operations that require it
    if operation_name and not auth_token:
        print("Error: Authentication required for this operation.")
        print("Please provide an authentication token with --token.")
        return EXIT_PERMISSION_ERROR

    try:
        # Version command
        if args.version:
            print(f"System Configuration Manager v{VERSION}")
            print(f"Running on {get_system_settings()['platform']}")
            return EXIT_SUCCESS

        # Show all configurations
        elif args.show:
            configs = list_configs(
                category=args.category,
                search=args.search,
                mask_sensitive=not args.no_mask
            )

            # Sort by category and key
            configs.sort(key=lambda x: (x["category"], x["key"]))

            # Output the configurations
            output = format_output(configs, args.format)

            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
                print(f"Configuration written to {args.output}")
            else:
                print(output)

            return EXIT_SUCCESS

        # Get a specific configuration
        elif args.get:
            value = get_config_value(args.get, mask=not args.no_mask)

            if value is None:
                print(f"Configuration not found: {args.get}")
                return EXIT_NOT_FOUND

            # Output the value
            if args.format == "json":
                output = json.dumps({"key": args.get, "value": value}, indent=2)
            elif args.format == "yaml":
                output = yaml.dump({"key": args.get, "value": value}, default_flow_style=False)
            else:
                output = value

            if args.output:
                with open(args.output, "w") as f:
                    f.write(str(output))
                print(f"Configuration written to {args.output}")
            else:
                print(output)

            return EXIT_SUCCESS

        # Set configuration values
        elif args.set:
            # Parse all key=value pairs
            for pair in args.set:
                try:
                    key, value = parse_key_value(pair)
                except ValueError as e:
                    print(f"Error: {e}")
                    return EXIT_VALIDATION_ERROR

                # Set the configuration
                success, message = set_config_value(
                    key=key,
                    value=value,
                    category=args.category,
                    description=args.description,
                    auth_token=auth_token,
                    reason=args.reason
                )

                if success:
                    print(f"Success: {message}")
                else:
                    print(f"Error: {message}")
                    return EXIT_ERROR

            return EXIT_SUCCESS

        # Delete a configuration
        elif args.delete:
            success, message = delete_config_value(
                key=args.delete,
                auth_token=auth_token,
                reason=args.reason
            )

            if success:
                print(f"Success: {message}")
                return EXIT_SUCCESS
            else:
                print(f"Error: {message}")
                return EXIT_ERROR

        # Export configurations
        elif args.export:
            if not args.output:
                print("Error: --output is required for export")
                return EXIT_VALIDATION_ERROR

            success, message, count = export_configs(
                output_file=args.output,
                category=args.category,
                search=args.search,
                include_sensitive=args.no_mask,
                format=args.format if args.format in ["json", "yaml"] else "json"
            )

            if success:
                print(f"Success: {message}")
                return EXIT_SUCCESS
            else:
                print(f"Error: {message}")
                return EXIT_ERROR

        # Import configurations
        elif args.import_file:
            success, message, stats = import_configs(
                input_file=args.import_file,
                environment=args.environment,
                dry_run=args.dry_run,
                merge=not args.no_merge,
                auth_token=auth_token,
                reason=args.reason
            )

            if success:
                print(f"Success: {message}")

                if args.verbose and not args.dry_run:
                    print(f"Stats: {stats['created']} created, {stats['updated']} updated, "
                         f"{stats['failed']} failed, {stats['skipped']} skipped")

                return EXIT_SUCCESS
            else:
                print(f"Error: {message}")
                return EXIT_ERROR

        # Validate configurations
        elif args.validate:
            success, results = validate_configs(schema_dir=args.schema_dir)

            # Format the output
            output = format_output(results, args.format)

            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
                print(f"Validation results written to {args.output}")
            else:
                print(output)

            return EXIT_SUCCESS if success else EXIT_VALIDATION_ERROR

        # Initialize default configurations
        elif args.init_defaults:
            success, message, count = initialize_defaults()

            if success:
                print(f"Success: {message}")
                return EXIT_SUCCESS
            else:
                print(f"Error: {message}")
                return EXIT_ERROR

    except PermissionError as e:
        print(f"Permission error: {e}")
        return EXIT_PERMISSION_ERROR

    except ValidationError as e:
        print(f"Validation error: {e}")
        return EXIT_VALIDATION_ERROR

    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        return EXIT_ERROR

    except Exception as e:
        print(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code
    """
    # Parse command-line arguments
    parser = setup_arg_parser()
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level,
                      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Execute CLI
    return execute_cli(args)


if __name__ == "__main__":
    sys.exit(main())
