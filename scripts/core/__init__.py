#!/usr/bin/env python3
# filepath: scripts/core/init.py
"""
Core Initialization Module for Cloud Infrastructure Platform

This module provides centralized initialization for all core script components,
ensuring consistent configuration, logging, and environment setup across
the entire platform. It bootstraps the core functionality needed by all
scripts and handles dependency resolution.

Key features:
- Unified environment setup
- Centralized logging configuration
- Configuration loading and validation
- Security initialization
- Core component dependency management
- Health check verification
"""

import os
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Union

# Make the scripts package available for imports
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

# Component availability tracking
LOGGER_AVAILABLE = False
CONFIG_LOADER_AVAILABLE = False
ENVIRONMENT_AVAILABLE = False
ERROR_HANDLER_AVAILABLE = False
NOTIFICATION_AVAILABLE = False
SECURITY_MODULE_AVAILABLE = False
SYSTEM_MODULE_AVAILABLE = False

# Default configurations
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_CONFIG_FILE = "config/default.yaml"
DEFAULT_ENV = "development"
CONFIG_PATH_ENV_VAR = "CONFIG_PATH"

# Initialize minimal logger for bootstrapping
logger = logging.getLogger(__name__)


def setup_minimal_logging(level: str = DEFAULT_LOG_LEVEL) -> None:
    """
    Set up minimal logging before proper logger is initialized.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    logging.basicConfig(
        format='[%(asctime)s] %(levelname)s in %(name)s: %(message)s',
        level=numeric_level
    )


def initialize_components() -> Tuple[bool, List[str]]:
    """
    Initialize all core components with appropriate dependency resolution.

    Returns:
        Tuple of (success, error_list)
    """
    global LOGGER_AVAILABLE, CONFIG_LOADER_AVAILABLE, ENVIRONMENT_AVAILABLE
    global ERROR_HANDLER_AVAILABLE, NOTIFICATION_AVAILABLE
    global SECURITY_MODULE_AVAILABLE, SYSTEM_MODULE_AVAILABLE

    errors = []

    # Step 1: Initialize logger (no dependencies)
    try:
        from scripts.core.logger import Logger, setup_logging
        setup_logging(level=os.environ.get('LOG_LEVEL', DEFAULT_LOG_LEVEL))
        logger = logging.getLogger(__name__)
        logger.debug("Logger module initialized")
        LOGGER_AVAILABLE = True
    except ImportError as e:
        errors.append(f"Failed to import logger module: {e}")
        logger.warning(f"Logger module import failed: {e}")

    # Step 2: Initialize environment (depends on logger)
    if LOGGER_AVAILABLE:
        try:
            from scripts.core.environment import Environment, load_env
            env_file = os.environ.get("ENV_FILE")
            env_name = os.environ.get("ENVIRONMENT", DEFAULT_ENV)
            env = load_env(env_file=env_file, environment=env_name)
            logger.debug(f"Environment module initialized: {env.get_current_environment()}")
            ENVIRONMENT_AVAILABLE = True
        except ImportError as e:
            errors.append(f"Failed to import environment module: {e}")
            logger.warning(f"Environment module import failed: {e}")

    # Step 3: Initialize config loader (depends on logger)
    if LOGGER_AVAILABLE:
        try:
            from scripts.core.config_loader import ConfigLoader, load_config
            config_file = os.environ.get(CONFIG_PATH_ENV_VAR, DEFAULT_CONFIG_FILE)
            env_name = os.environ.get("ENVIRONMENT", DEFAULT_ENV) if not ENVIRONMENT_AVAILABLE else None
            CONFIG_LOADER_AVAILABLE = True
            logger.debug("Config loader module initialized")
        except ImportError as e:
            errors.append(f"Failed to import config_loader module: {e}")
            logger.warning(f"Config loader module import failed: {e}")

    # Step 4: Initialize notification system (depends on logger, config)
    if LOGGER_AVAILABLE and CONFIG_LOADER_AVAILABLE:
        try:
            from scripts.core.notification import NotificationManager
            notification_manager = NotificationManager()
            NOTIFICATION_AVAILABLE = True
            logger.debug("Notification module initialized")
        except ImportError as e:
            errors.append(f"Failed to import notification module: {e}")
            logger.warning(f"Notification module import failed: {e}")

    # Step 5: Initialize error handler (depends on logger, notification)
    if LOGGER_AVAILABLE:
        try:
            from scripts.core.error_handler import ErrorHandler
            ERROR_HANDLER_AVAILABLE = True
            logger.debug("Error handler module initialized")
        except ImportError as e:
            errors.append(f"Failed to import error_handler module: {e}")
            logger.warning(f"Error handler module import failed: {e}")

    # Step 6: Initialize security module (depends on logger, error_handler)
    if LOGGER_AVAILABLE and ERROR_HANDLER_AVAILABLE:
        try:
            # Try to import core security modules
            from scripts.core.security import crypto, integrity_check, permissions
            SECURITY_MODULE_AVAILABLE = True
            logger.debug("Security module initialized")
        except ImportError as e:
            errors.append(f"Failed to import security modules: {e}")
            logger.warning(f"Security module import failed: {e}")

    # Step 7: Initialize system module (depends on logger, error_handler, config)
    if LOGGER_AVAILABLE and ERROR_HANDLER_AVAILABLE:
        try:
            # Try to import system modules
            from scripts.core.system import cloud_provider, resource_monitor, system_info
            SYSTEM_MODULE_AVAILABLE = True
            logger.debug("System module initialized")
        except ImportError as e:
            errors.append(f"Failed to import system modules: {e}")
            logger.warning(f"System module import failed: {e}")

    # Return the initialization status
    success = (len(errors) == 0)

    if success:
        logger.info("All core components initialized successfully")
    else:
        logger.warning(f"Some core components failed to initialize ({len(errors)} errors)")

    return (success, errors)


def get_component_status() -> Dict[str, bool]:
    """
    Get initialization status of all core components.

    Returns:
        Dictionary mapping component names to availability status
    """
    return {
        "logger": LOGGER_AVAILABLE,
        "config_loader": CONFIG_LOADER_AVAILABLE,
        "environment": ENVIRONMENT_AVAILABLE,
        "error_handler": ERROR_HANDLER_AVAILABLE,
        "notification": NOTIFICATION_AVAILABLE,
        "security": SECURITY_MODULE_AVAILABLE,
        "system": SYSTEM_MODULE_AVAILABLE
    }


def load_configuration(config_file: Optional[str] = None,
                      environment: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Load configuration with the specified parameters.

    Args:
        config_file: Path to configuration file
        environment: Environment name

    Returns:
        Configuration dictionary or None if loading fails
    """
    if not CONFIG_LOADER_AVAILABLE:
        logger.error("Config loader module not available, cannot load configuration")
        return None

    try:
        from scripts.core.config_loader import load_config

        # Use environment from environment module if available and not explicitly specified
        if environment is None and ENVIRONMENT_AVAILABLE:
            from scripts.core.environment import get_current_environment
            environment = get_current_environment()

        # Default config file if not specified
        if config_file is None:
            config_file = os.environ.get(CONFIG_PATH_ENV_VAR, DEFAULT_CONFIG_FILE)

        # Load configuration
        config = load_config(config_file, environment)
        logger.info(f"Configuration loaded from {config_file} for environment {environment or 'default'}")

        return config.get_all()
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return None


def setup_script_environment(config_file: Optional[str] = None,
                           environment: Optional[str] = None,
                           log_level: Optional[str] = None,
                           log_file: Optional[str] = None) -> bool:
    """
    Set up a consistent environment for scripts.

    Args:
        config_file: Path to configuration file
        environment: Environment name
        log_level: Logging level
        log_file: Path to log file

    Returns:
        True if setup was successful, False otherwise
    """
    # Set up minimal logging for bootstrapping
    setup_minimal_logging(log_level or DEFAULT_LOG_LEVEL)

    # Initialize components
    success, errors = initialize_components()

    if not success:
        logger.warning("Some components failed to initialize. Limited functionality available.")
        for error in errors:
            logger.debug(f"Initialization error: {error}")

    # Set up proper logging if logger is available
    if LOGGER_AVAILABLE and log_level:
        from scripts.core.logger import setup_logging
        setup_logging(level=log_level, log_file=log_file)

    # Load environment if not already done
    if ENVIRONMENT_AVAILABLE and environment:
        from scripts.core.environment import load_env
        load_env(environment=environment)

    # Load configuration
    if CONFIG_LOADER_AVAILABLE and config_file:
        config = load_configuration(config_file, environment)
        if not config:
            logger.warning("Failed to load configuration")

    # Return overall success status
    return success


def setup_cli_parser() -> argparse.ArgumentParser:
    """
    Set up a standard command-line argument parser for scripts.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="Core script initialization",
        epilog="Initializes core components for the Cloud Infrastructure Platform scripts"
    )

    parser.add_argument(
        "-c", "--config",
        dest="config_file",
        default=os.environ.get(CONFIG_PATH_ENV_VAR, DEFAULT_CONFIG_FILE),
        help=f"Path to configuration file (default: {DEFAULT_CONFIG_FILE})"
    )

    parser.add_argument(
        "-e", "--environment",
        dest="environment",
        default=os.environ.get("ENVIRONMENT", DEFAULT_ENV),
        help=f"Environment (development, staging, production) (default: {DEFAULT_ENV})"
    )

    parser.add_argument(
        "-l", "--log-level",
        dest="log_level",
        default=os.environ.get("LOG_LEVEL", DEFAULT_LOG_LEVEL),
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help=f"Logging level (default: {DEFAULT_LOG_LEVEL})"
    )

    parser.add_argument(
        "-f", "--log-file",
        dest="log_file",
        default=os.environ.get("LOG_FILE"),
        help="Path to log file (default: console only)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (sets log level to DEBUG)"
    )

    return parser


def main() -> int:
    """
    Main function when module is run directly.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    parser = setup_cli_parser()
    args = parser.parse_args()

    # Handle verbose flag (overrides log level)
    if args.verbose:
        args.log_level = "DEBUG"

    # Initialize environment
    success = setup_script_environment(
        config_file=args.config_file,
        environment=args.environment,
        log_level=args.log_level,
        log_file=args.log_file
    )

    # Print component status
    status = get_component_status()
    print("\nCore Component Status:")
    print("-" * 30)
    for component, available in status.items():
        status_str = "Available" if available else "Not Available"
        print(f"{component:<15}: {status_str}")
    print("-" * 30)

    if success:
        print("\nInitialization successful. Core components are ready to use.")
    else:
        print("\nInitialization completed with some errors. Limited functionality available.")

    return 0 if success else 1


# Make key functions available for import
__all__ = [
    'initialize_components',
    'get_component_status',
    'load_configuration',
    'setup_script_environment',
    'setup_cli_parser',
    'setup_minimal_logging'
]


# Run main function if called directly
if __name__ == "__main__":
    sys.exit(main())
