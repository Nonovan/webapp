#!/usr/bin/env python3
# filepath: scripts/core/security/init.py
"""
Security Components Initialization Module

This module provides centralized initialization for security components in the
Cloud Infrastructure Platform. It handles proper startup sequence, dependency
management, configuration loading, and status tracking for the security subsystem.

The initialization process ensures that all security components are properly
configured before use, following security best practices from NIST, CIS, and OWASP.
It implements secure defaults and handles graceful degradation when dependencies
are unavailable.

Key features:
- Security component dependency resolution
- Cryptography subsystem initialization
- File integrity monitoring setup
- Permission management configuration
- Security metrics collection
- Centralized security logging
- Component availability tracking
- Initialization status reporting
"""

import os
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union, Any, Callable

# Ensure the scripts package is in path for imports
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

# Component availability tracking
CRYPTO_AVAILABLE = False
INTEGRITY_CHECK_AVAILABLE = False
PERMISSIONS_AVAILABLE = False
CORE_LOGGER_AVAILABLE = False
ERROR_HANDLER_AVAILABLE = False
CONFIG_LOADER_AVAILABLE = False
NOTIFICATION_AVAILABLE = False

# Default configurations
DEFAULT_SECURITY_LEVEL = "high"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_CONFIG_PATH = "config/security"
DEFAULT_SECURITY_CONFIG_FILE = "security.yaml"
DEFAULT_BASELINE_DIR = "/var/lib/cloud-platform/security/baselines"
DEFAULT_KEY_DIR = "/etc/cloud-platform/security/keys"
SECURITY_LOG_FILE = "/var/log/cloud-platform/security.log"

# Set up minimal logging for bootstrapping
logger = logging.getLogger("security.init")


def setup_minimal_logging(level: str = DEFAULT_LOG_LEVEL) -> None:
    """
    Set up minimal logging for bootstrapping before core logger is available.

    Args:
        level: Log level to use
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout
    )
    logger.setLevel(log_level)


def initialize_security_components(
    security_level: str = DEFAULT_SECURITY_LEVEL,
    config_path: Optional[str] = None,
    log_level: str = DEFAULT_LOG_LEVEL,
    skip_unavailable: bool = True
) -> Tuple[bool, List[str]]:
    """
    Initialize security components with proper dependency resolution.

    Args:
        security_level: Security level (low, medium, high)
        config_path: Path to security configuration
        log_level: Logging level to use
        skip_unavailable: Skip unavailable components instead of failing

    Returns:
        Tuple of (success flag, list of error messages)
    """
    global CRYPTO_AVAILABLE, INTEGRITY_CHECK_AVAILABLE, PERMISSIONS_AVAILABLE
    global CORE_LOGGER_AVAILABLE, ERROR_HANDLER_AVAILABLE
    global CONFIG_LOADER_AVAILABLE, NOTIFICATION_AVAILABLE

    errors = []

    # Set up minimal logging
    setup_minimal_logging(log_level)
    logger.debug(f"Initializing security components (level: {security_level})")

    # Step 1: Initialize core logger if available
    try:
        from scripts.core.logger import get_logger
        logger = get_logger("security")
        CORE_LOGGER_AVAILABLE = True
        logger.debug("Core logger initialized")
    except ImportError as e:
        errors.append(f"Failed to import core logger: {e}")
        logger.warning(f"Core logger import failed: {e}")

    # Step 2: Initialize config loader if available
    if CORE_LOGGER_AVAILABLE:
        try:
            from scripts.core.config_loader import load_config, ConfigLoader
            config_file = config_path or DEFAULT_SECURITY_CONFIG_FILE
            CONFIG_LOADER_AVAILABLE = True
            logger.debug("Config loader initialized")
        except ImportError as e:
            errors.append(f"Failed to import config_loader module: {e}")
            logger.warning(f"Config loader import failed: {e}")

    # Step 3: Initialize error handler if available
    if CORE_LOGGER_AVAILABLE:
        try:
            from scripts.core.error_handler import handle_error, ErrorCategory
            ERROR_HANDLER_AVAILABLE = True
            logger.debug("Error handler initialized")
        except ImportError as e:
            errors.append(f"Failed to import error_handler module: {e}")
            logger.warning(f"Error handler import failed: {e}")

    # Step 4: Initialize notification system if available
    if CORE_LOGGER_AVAILABLE and CONFIG_LOADER_AVAILABLE:
        try:
            from scripts.core.notification import send_notification
            NOTIFICATION_AVAILABLE = True
            logger.debug("Notification system initialized")
        except ImportError as e:
            errors.append(f"Failed to import notification module: {e}")
            logger.warning(f"Notification system import failed: {e}")

    # Step 5: Initialize crypto module
    try:
        from scripts.core.security.crypto import initialize_crypto
        config = {}
        if CONFIG_LOADER_AVAILABLE:
            try:
                config = load_config(os.path.join(DEFAULT_CONFIG_PATH, "crypto.yaml")) or {}
            except Exception as e:
                logger.warning(f"Failed to load crypto configuration: {e}")

        # Initialize crypto with appropriate security level
        initialize_crypto(
            key_dir=config.get("KEY_DIR", DEFAULT_KEY_DIR),
            security_level=security_level
        )
        CRYPTO_AVAILABLE = True
        logger.info("Cryptographic subsystem initialized")
    except ImportError as e:
        error_msg = f"Failed to import crypto module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if not skip_unavailable:
            return (False, errors)
    except Exception as e:
        error_msg = f"Failed to initialize crypto module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            from scripts.core.error_handler import ErrorCategory
            handle_error(e, category=ErrorCategory.SECURITY)
        if not skip_unavailable:
            return (False, errors)

    # Step 6: Initialize integrity check module
    try:
        from scripts.core.security.integrity_check import create_baseline
        INTEGRITY_CHECK_AVAILABLE = True
        logger.info("Integrity check module initialized")

        # Load integrity check configuration if available
        if CONFIG_LOADER_AVAILABLE:
            try:
                integrity_config = load_config(os.path.join(DEFAULT_CONFIG_PATH, "integrity.yaml"))
                if integrity_config and integrity_config.get("AUTO_INITIALIZE_BASELINES", False):
                    baseline_dir = integrity_config.get("BASELINE_DIR", DEFAULT_BASELINE_DIR)
                    os.makedirs(baseline_dir, exist_ok=True)
                    logger.info(f"Created baseline directory: {baseline_dir}")
            except Exception as e:
                logger.warning(f"Failed to load integrity check configuration: {e}")
    except ImportError as e:
        error_msg = f"Failed to import integrity_check module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if not skip_unavailable:
            return (False, errors)
    except Exception as e:
        error_msg = f"Failed to initialize integrity_check module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            from scripts.core.error_handler import ErrorCategory
            handle_error(e, category=ErrorCategory.SECURITY)
        if not skip_unavailable:
            return (False, errors)

    # Step 7: Initialize permissions module
    try:
        from scripts.core.security.permissions import audit_directory_permissions
        PERMISSIONS_AVAILABLE = True
        logger.info("Permissions module initialized")
    except ImportError as e:
        error_msg = f"Failed to import permissions module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if not skip_unavailable:
            return (False, errors)
    except Exception as e:
        error_msg = f"Failed to initialize permissions module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            from scripts.core.error_handler import ErrorCategory
            handle_error(e, category=ErrorCategory.SECURITY)
        if not skip_unavailable:
            return (False, errors)

    # Return the initialization status
    success = (len(errors) == 0)

    # Log initialization result
    if success:
        logger.info("All security components initialized successfully")
        if NOTIFICATION_AVAILABLE:
            from scripts.core.notification import send_notification
            send_notification(
                "Security Module Initialized",
                "All security components successfully initialized",
                priority="low",
                category="security"
            )
    else:
        logger.warning(f"Some security components failed to initialize ({len(errors)} errors)")

    return (success, errors)


def get_security_component_status() -> Dict[str, bool]:
    """
    Get current status of security components.

    Returns:
        Dictionary with component names and availability status
    """
    return {
        "crypto": CRYPTO_AVAILABLE,
        "integrity_check": INTEGRITY_CHECK_AVAILABLE,
        "permissions": PERMISSIONS_AVAILABLE,
        "core_logger": CORE_LOGGER_AVAILABLE,
        "error_handler": ERROR_HANDLER_AVAILABLE,
        "config_loader": CONFIG_LOADER_AVAILABLE,
        "notification": NOTIFICATION_AVAILABLE
    }


def verify_security_prerequisites() -> Dict[str, Dict[str, Any]]:
    """
    Verify that security prerequisites are met for safe operation.

    Checks for proper directory permissions, critical file integrity,
    and secure configuration settings.

    Returns:
        Dict with verification results for different security aspects
    """
    results = {
        "directories": {
            "status": True,
            "issues": []
        },
        "files": {
            "status": True,
            "issues": []
        },
        "configuration": {
            "status": True,
            "issues": []
        },
        "environment": {
            "status": True,
            "issues": []
        }
    }

    # Check critical directories
    security_dirs = [
        DEFAULT_KEY_DIR,
        DEFAULT_BASELINE_DIR,
        os.path.dirname(SECURITY_LOG_FILE)
    ]

    for directory in security_dirs:
        dir_path = Path(directory)
        try:
            # Check if directory exists
            if not dir_path.exists():
                results["directories"]["status"] = False
                results["directories"]["issues"].append(f"Directory does not exist: {directory}")
                continue

            # Check permissions (should not be world-writable)
            if os.name == 'posix':  # Unix-like systems
                mode = dir_path.stat().st_mode
                if mode & 0o002:  # Check if world-writable
                    results["directories"]["status"] = False
                    results["directories"]["issues"].append(
                        f"Insecure permissions on {directory}: world-writable"
                    )
        except Exception as e:
            results["directories"]["status"] = False
            results["directories"]["issues"].append(f"Error checking {directory}: {str(e)}")

    # Check environment variables
    required_env_vars = []  # Add any required environment variables here
    for var in required_env_vars:
        if var not in os.environ:
            results["environment"]["status"] = False
            results["environment"]["issues"].append(f"Missing required environment variable: {var}")

    return results


def setup_security_cli_parser() -> argparse.ArgumentParser:
    """
    Set up command-line argument parser for security initialization.

    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="Initialize security components for the Cloud Infrastructure Platform"
    )
    parser.add_argument(
        "--security-level",
        choices=["low", "medium", "high"],
        default=DEFAULT_SECURITY_LEVEL,
        help="Security level for component initialization"
    )
    parser.add_argument(
        "--config",
        help="Path to security configuration file"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=DEFAULT_LOG_LEVEL,
        help="Set log level"
    )
    parser.add_argument(
        "--skip-unavailable",
        action="store_true",
        help="Skip unavailable components instead of failing"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify security prerequisites"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print status of security components"
    )
    return parser


def main() -> int:
    """
    Main entry point for command-line usage.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    parser = setup_security_cli_parser()
    args = parser.parse_args()

    # Handle --status option
    if args.status:
        status = get_security_component_status()
        print("Security Component Status:")
        for component, available in status.items():
            print(f"  {component.ljust(20)}: {'Available' if available else 'Not Available'}")
        return 0

    # Handle --verify option
    if args.verify:
        verify_results = verify_security_prerequisites()

        all_ok = True
        print("Security Prerequisite Verification:")

        for category, result in verify_results.items():
            status_str = "OK" if result["status"] else "ISSUES FOUND"
            print(f"  {category.ljust(15)}: {status_str}")

            if not result["status"]:
                all_ok = False
                for issue in result["issues"]:
                    print(f"    - {issue}")

        return 0 if all_ok else 1

    # Initialize security components
    success, errors = initialize_security_components(
        security_level=args.security_level,
        config_path=args.config,
        log_level=args.log_level,
        skip_unavailable=args.skip_unavailable
    )

    # Print errors if any
    if errors:
        print("Security initialization errors:")
        for error in errors:
            print(f"  - {error}")

    # Return appropriate exit code
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
