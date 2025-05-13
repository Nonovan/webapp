#!/usr/bin/env python3
# filepath: scripts/core/init.py
"""
Core Initialization Module for Cloud Infrastructure Platform Scripts

This module provides centralized initialization for script components with proper
dependency resolution and component availability tracking. It bootstraps core
functionality needed by all scripts in a consistent and secure manner.

Key features:
- Unified component initialization with proper dependency order
- Environment-aware configuration loading
- Graceful degradation when components are unavailable
- Integration with core.environment for environment management
- Script-specific environment configuration
- Component availability tracking for conditional functionality
- Standardized logging setup across all scripts
- Security-focused initialization for security-critical components
"""

import os
import sys
import logging
import argparse
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Union, Set

# Make the project package available for imports
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
ENV_MANAGER_AVAILABLE = False

# Default configurations
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_CONFIG_PATH = "config"
DEFAULT_ENV = "development"
CONFIG_PATH_ENV_VAR = "CONFIG_PATH"
DEFAULT_SECURITY_LEVEL = "standard"

# Initialize minimal logger for bootstrapping
logging.basicConfig(
    format="[%(asctime)s] %(levelname)s in %(name)s: %(message)s",
    level=logging.INFO,
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


def setup_minimal_logging(level: str = DEFAULT_LOG_LEVEL) -> None:
    """
    Set up minimal logging for bootstrapping before full logger is available.

    Args:
        level: Log level to use (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] %(levelname)s in %(name)s: %(message)s",
        stream=sys.stdout
    )
    logger.setLevel(log_level)
    logger.debug("Minimal logging configured for initialization")


def initialize_components() -> Tuple[bool, List[str]]:
    """
    Initialize all core components with appropriate dependency resolution.

    Returns:
        Tuple of (success, error_list)
    """
    global LOGGER_AVAILABLE, CONFIG_LOADER_AVAILABLE, ENVIRONMENT_AVAILABLE
    global ERROR_HANDLER_AVAILABLE, NOTIFICATION_AVAILABLE, ENV_MANAGER_AVAILABLE
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

    # Step 2: Initialize environment from core module (depends on logger)
    if LOGGER_AVAILABLE:
        try:
            # First try to use the main core.environment module
            from core.environment import Environment, load_env, get_current_environment
            env_file = os.environ.get("ENV_FILE")
            env_name = os.environ.get("ENVIRONMENT", DEFAULT_ENV)

            # Load environment variables
            env = load_env(env_file=env_file, environment=env_name)

            logger.debug(f"Environment module initialized: {get_current_environment()}")
            ENVIRONMENT_AVAILABLE = True
        except ImportError as e:
            errors.append(f"Failed to import core environment module: {e}")
            logger.warning(f"Core environment module import failed: {e}")

    # Step 3: Initialize env_manager (depends on logger, falls back if core.environment unavailable)
    if LOGGER_AVAILABLE:
        try:
            from scripts.core.env_manager import initialize_environment, get_current_environment
            env_file = os.environ.get("ENV_FILE")
            env_name = os.environ.get("ENVIRONMENT", DEFAULT_ENV)

            # Initialize the environment manager
            initialize_environment(env_file=env_file, environment=env_name)

            ENV_MANAGER_AVAILABLE = True
            logger.debug(f"Environment manager initialized: {get_current_environment()}")
        except ImportError as e:
            errors.append(f"Failed to import env_manager module: {e}")
            logger.warning(f"Environment manager import failed: {e}")

            # If neither is available, this is a critical failure
            if not ENVIRONMENT_AVAILABLE:
                logger.error("No environment management available (both core.environment and env_manager failed)")

    # Step 4: Initialize config loader (depends on logger, environment)
    if LOGGER_AVAILABLE:
        try:
            from scripts.core.config_loader import ConfigLoader, load_config

            # Get configuration path from environment if available
            config_path = None
            if ENVIRONMENT_AVAILABLE or ENV_MANAGER_AVAILABLE:
                if ENV_MANAGER_AVAILABLE:
                    from scripts.core.env_manager import get_env_value
                    config_path = get_env_value(CONFIG_PATH_ENV_VAR)
                else:
                    from core.environment import get_env
                    config_path = get_env(CONFIG_PATH_ENV_VAR)

            CONFIG_LOADER_AVAILABLE = True
            logger.debug("Config loader module initialized")
        except ImportError as e:
            errors.append(f"Failed to import config_loader module: {e}")
            logger.warning(f"Config loader module import failed: {e}")

    # Step 5: Initialize notification system (depends on logger, config)
    if LOGGER_AVAILABLE and CONFIG_LOADER_AVAILABLE:
        try:
            from scripts.core.notification import NotificationManager
            notification_manager = NotificationManager()
            NOTIFICATION_AVAILABLE = True
            logger.debug("Notification module initialized")
        except ImportError as e:
            errors.append(f"Failed to import notification module: {e}")
            logger.warning(f"Notification module import failed: {e}")

    # Step 6: Initialize error handler (depends on logger, notification)
    if LOGGER_AVAILABLE:
        try:
            from scripts.core.error_handler import ErrorHandler
            ERROR_HANDLER_AVAILABLE = True
            logger.debug("Error handler module initialized")
        except ImportError as e:
            errors.append(f"Failed to import error_handler module: {e}")
            logger.warning(f"Error handler module import failed: {e}")

    # Step 7: Initialize security module (depends on logger, error_handler)
    if LOGGER_AVAILABLE and ERROR_HANDLER_AVAILABLE:
        try:
            # Try to import core security modules
            from scripts.core.security import initialize_security_components

            # Get security level from environment
            security_level = DEFAULT_SECURITY_LEVEL
            if ENV_MANAGER_AVAILABLE:
                from scripts.core.env_manager import get_env_value
                security_level = get_env_value("SECURITY_LEVEL", DEFAULT_SECURITY_LEVEL)
            elif ENVIRONMENT_AVAILABLE:
                from core.environment import get_env
                security_level = get_env("SECURITY_LEVEL", DEFAULT_SECURITY_LEVEL)

            # Initialize security components with secure defaults
            success, security_errors = initialize_security_components(
                security_level=security_level,
                skip_unavailable=True
            )

            if not success:
                for error in security_errors:
                    errors.append(f"Security initialization error: {error}")
                    logger.warning(f"Security initialization error: {error}")

            SECURITY_MODULE_AVAILABLE = True
            logger.debug("Security module initialized")
        except ImportError as e:
            errors.append(f"Failed to import security modules: {e}")
            logger.warning(f"Security module import failed: {e}")

    # Step 8: Initialize system module (depends on logger, error_handler, config)
    if LOGGER_AVAILABLE and ERROR_HANDLER_AVAILABLE:
        try:
            # Try to import system modules
            from scripts.core.system import initialize_system_components

            # Initialize system components with appropriate defaults
            success, system_errors = initialize_system_components(
                skip_unavailable=True
            )

            if not success:
                for error in system_errors:
                    errors.append(f"System initialization error: {error}")
                    logger.warning(f"System initialization error: {error}")

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
    Get status of all core components.

    Returns:
        Dictionary mapping component names to their availability status
    """
    return {
        "logger": LOGGER_AVAILABLE,
        "environment": ENVIRONMENT_AVAILABLE or ENV_MANAGER_AVAILABLE,
        "config_loader": CONFIG_LOADER_AVAILABLE,
        "notification": NOTIFICATION_AVAILABLE,
        "error_handler": ERROR_HANDLER_AVAILABLE,
        "security": SECURITY_MODULE_AVAILABLE,
        "system": SYSTEM_MODULE_AVAILABLE,
        "env_manager": ENV_MANAGER_AVAILABLE
    }


def load_configuration(config_file: Optional[str] = None,
                      environment: Optional[str] = None) -> Optional[Any]:
    """
    Load configuration from file with environment-specific settings.

    Args:
        config_file: Path to configuration file
        environment: Environment name

    Returns:
        Configuration object or None if failed
    """
    if not CONFIG_LOADER_AVAILABLE:
        logger.warning("Config loader not available, cannot load configuration")
        return None

    try:
        from scripts.core.config_loader import load_config

        # Determine environment if not specified
        if not environment:
            if ENV_MANAGER_AVAILABLE:
                from scripts.core.env_manager import get_current_environment
                environment = get_current_environment()
            elif ENVIRONMENT_AVAILABLE:
                from core.environment import get_current_environment
                environment = get_current_environment()
            else:
                # Default to development if environment not available
                environment = DEFAULT_ENV

        # Load configuration
        config = load_config(config_file, environment=environment)

        if config:
            logger.debug(f"Configuration loaded: {config_file}")
            return config
        else:
            logger.warning(f"Failed to load configuration: {config_file}")
            return None

    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        if ERROR_HANDLER_AVAILABLE:
            from scripts.core.error_handler import handle_error
            handle_error(e, f"Failed to load configuration {config_file}")
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

    # Load environment if specified
    if ENV_MANAGER_AVAILABLE and environment:
        from scripts.core.env_manager import initialize_environment
        initialize_environment(environment=environment)
    elif ENVIRONMENT_AVAILABLE and environment:
        from core.environment import load_env
        load_env(environment=environment)

    # Load configuration if specified
    if CONFIG_LOADER_AVAILABLE and config_file:
        config = load_configuration(config_file, environment)
        if not config:
            logger.warning("Failed to load configuration")

    # Return overall success status
    return success


def setup_cli_parser() -> argparse.ArgumentParser:
    """
    Set up command-line argument parser for the module.

    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Core Script Initialization",
        epilog="Use this tool to initialize and check status of core components"
    )

    parser.add_argument(
        "-e", "--environment",
        dest="environment",
        help="Environment name (development, staging, production)"
    )
    parser.add_argument(
        "-l", "--log-level",
        dest="log_level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=DEFAULT_LOG_LEVEL,
        help="Log level"
    )
    parser.add_argument(
        "--log-file",
        dest="log_file",
        help="Path to log file"
    )
    parser.add_argument(
        "-c", "--config",
        dest="config_file",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show component status"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    return parser


def main() -> int:
    """
    Main function when module is run directly.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    parser = setup_cli_parser()
    args = parser.parse_args()

    # Set up logging based on arguments
    if args.verbose:
        setup_minimal_logging("DEBUG")
    else:
        setup_minimal_logging(args.log_level)

    # Check status if requested
    if args.status:
        # Initialize components first
        initialize_components()

        # Get and show status
        status = get_component_status()
        print("\nComponent Status:")
        for component, available in status.items():
            state = "✓ Available" if available else "✗ Not available"
            print(f"  {component.ljust(15)}: {state}")

        # Determine exit code based on core component availability
        critical_components = ["logger", "environment", "config_loader"]
        all_critical_available = all(status.get(c, False) for c in critical_components)
        return 0 if all_critical_available else 1

    # Initialize components with provided settings
    logger.info("Initializing core components")
    success = setup_script_environment(
        config_file=args.config_file,
        environment=args.environment,
        log_level=args.log_level,
        log_file=args.log_file
    )

    # Return appropriate exit code
    return 0 if success else 1


# Initialize the module when imported
if __name__ != "__main__":
    setup_minimal_logging()


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
