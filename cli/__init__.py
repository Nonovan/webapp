"""
CLI Initialization Module for Cloud Infrastructure Platform.

This module provides initialization functionality for the command-line interface,
including environment setup, configuration loading, and security checks.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from flask.cli import FlaskGroup
from flask import Flask, current_app

from .cli_constants import (
    # Environment constants
    ENVIRONMENT_DEVELOPMENT,
    DEFAULT_ENVIRONMENT,
    ALLOWED_ENVIRONMENTS,

    # Exit codes
    EXIT_SUCCESS,
    EXIT_ERROR,
    EXIT_CONFIGURATION_ERROR,
    EXIT_DEPENDENCY_ERROR,

    # Path constants
    PROJECT_ROOT,
    DEFAULT_CONFIG_DIR,
    DEFAULT_LOG_DIR,

    # File settings
    FILE_SECURITY_SETTINGS,
    FILE_INTEGRITY_SETTINGS,
    CONFIG_FILE_PERMISSIONS,

    # Default configuration
    DEFAULT_CLI_CONFIG
)
from .common.utils import (
    configure_logging,
    load_config,
    save_config,
    handle_error,
    confirm_action
)
from .common.security import (
    verify_cli_environment,
    calculate_file_hash,
    validate_file_permissions
)

# Initialize logger
logger = logging.getLogger(__name__)

def init_cli_environment(env: Optional[str] = None,
                         config_dir: Optional[str] = None,
                         verify_integrity: bool = True) -> Tuple[bool, Dict[str, Any]]:
    """
    Initialize the CLI environment with proper configuration and security checks.

    This function sets up the CLI environment, loads or creates configuration,
    ensures necessary directories exist, and performs security checks.

    Args:
        env: Target environment (development, testing, staging, production)
        config_dir: Custom configuration directory path
        verify_integrity: Whether to verify file integrity during initialization

    Returns:
        Tuple containing (success_bool, config_dict)
    """
    try:
        # Set up environment
        env = env or os.environ.get('ENVIRONMENT') or DEFAULT_ENVIRONMENT
        if env not in ALLOWED_ENVIRONMENTS:
            logger.warning(f"Unsupported environment: {env}, falling back to {DEFAULT_ENVIRONMENT}")
            env = DEFAULT_ENVIRONMENT

        # Set up configuration directory
        config_dir = config_dir or DEFAULT_CONFIG_DIR
        os.makedirs(config_dir, exist_ok=True)

        # Set up logging directory
        log_dir = DEFAULT_LOG_DIR
        os.makedirs(log_dir, exist_ok=True)
        configure_logging(log_dir)

        # Load or create configuration
        config = load_config(env)
        if not config:
            logger.info(f"Creating default configuration for {env} environment")
            config = DEFAULT_CLI_CONFIG.copy()
            save_config(config, env=env)

        # Verify CLI environment security
        if verify_integrity:
            security_result = verify_cli_environment(
                verify_permissions=FILE_INTEGRITY_SETTINGS['VERIFY_PERMISSIONS'],
                allowed_paths=FILE_SECURITY_SETTINGS['SAFE_PATHS']
            )

            if not security_result:
                logger.warning("CLI environment security check failed")
                if not confirm_action("Continue despite security warnings?", default=False):
                    logger.error("Aborting due to security concerns")
                    return False, {}

        # Set proper permissions on config files if on Unix-like system
        if sys.platform != 'win32' and os.path.exists(config_dir):
            try:
                config_file = os.path.join(config_dir, f"{env}.json")
                if os.path.exists(config_file):
                    os.chmod(config_file, CONFIG_FILE_PERMISSIONS)
            except (IOError, OSError) as e:
                logger.warning(f"Could not set permissions on config file: {e}")

        return True, config

    except Exception as e:
        logger.error(f"Error initializing CLI environment: {e}")
        return False, {}

def create_cli_app(script_info):
    """
    Create a Flask application for CLI commands.

    Args:
        script_info: Information passed by Flask script runner

    Returns:
        Flask application instance
    """
    # Import here to avoid circular imports
    from core.factory import create_app

    # Get environment from script info or default
    env = getattr(script_info, 'env', os.environ.get('FLASK_ENV', DEFAULT_ENVIRONMENT))

    # Initialize CLI environment
    success, config = init_cli_environment(env=env)
    if not success:
        logger.warning("CLI environment initialization had issues, some features may be limited")

    # Create Flask app with proper environment
    app = create_app(env)

    # Register CLI commands
    from . import register_cli_commands
    register_cli_commands(app)

    return app

def get_cli_version() -> str:
    """Get the current CLI version."""
    from . import __version__
    return __version__

def get_available_commands() -> Dict[str, bool]:
    """
    Get a dictionary of available CLI command groups and their availability status.

    Returns:
        Dictionary mapping command group names to boolean availability
    """
    from .cli_constants import (
        COMMAND_GROUP_USER,
        COMMAND_GROUP_DB,
        COMMAND_GROUP_SYSTEM,
        COMMAND_GROUP_SECURITY,
        COMMAND_GROUP_MAINTENANCE,
        COMMAND_GROUP_INIT,
        COMMAND_GROUP_DEPLOY,
        COMMAND_GROUP_AWS,
        COMMAND_GROUP_AZURE,
        COMMAND_GROUP_GCP,
        COMMAND_GROUP_K8S,
        COMMAND_GROUP_DOCKER
    )

    # Try to import each command group to check availability
    commands = {}

    try:
        from .app import user_cli
        commands[COMMAND_GROUP_USER] = True
    except ImportError:
        commands[COMMAND_GROUP_USER] = False

    try:
        from .app import db_cli
        commands[COMMAND_GROUP_DB] = True
    except ImportError:
        commands[COMMAND_GROUP_DB] = False

    try:
        from .app import system_cli
        commands[COMMAND_GROUP_SYSTEM] = True
    except ImportError:
        commands[COMMAND_GROUP_SYSTEM] = False

    try:
        from .app import security_cli
        commands[COMMAND_GROUP_SECURITY] = True
    except ImportError:
        commands[COMMAND_GROUP_SECURITY] = False

    try:
        from .app import maintenance_cli
        commands[COMMAND_GROUP_MAINTENANCE] = True
    except ImportError:
        commands[COMMAND_GROUP_MAINTENANCE] = False

    try:
        from .app import init_cli
        commands[COMMAND_GROUP_INIT] = True
    except ImportError:
        commands[COMMAND_GROUP_INIT] = False

    try:
        from .deploy import deploy_cli
        commands[COMMAND_GROUP_DEPLOY] = True
    except ImportError:
        commands[COMMAND_GROUP_DEPLOY] = False

    try:
        from .deploy import aws_cli
        commands[COMMAND_GROUP_AWS] = True
    except ImportError:
        commands[COMMAND_GROUP_AWS] = False

    try:
        from .deploy import azure_cli
        commands[COMMAND_GROUP_AZURE] = True
    except ImportError:
        commands[COMMAND_GROUP_AZURE] = False

    try:
        from .deploy import gcp_cli
        commands[COMMAND_GROUP_GCP] = True
    except ImportError:
        commands[COMMAND_GROUP_GCP] = False

    try:
        from .deploy import k8s_cli
        commands[COMMAND_GROUP_K8S] = True
    except ImportError:
        commands[COMMAND_GROUP_K8S] = False

    try:
        from .deploy import docker_cli
        commands[COMMAND_GROUP_DOCKER] = True
    except ImportError:
        commands[COMMAND_GROUP_DOCKER] = False

    return commands

# Create FlaskGroup CLI
cli = FlaskGroup(create_app=create_cli_app)

__all__ = [
    'init_cli_environment',
    'create_cli_app',
    'get_cli_version',
    'get_available_commands',
    'cli'
]
