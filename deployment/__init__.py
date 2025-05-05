"""
Deployment package for the Cloud Infrastructure Platform.

This package provides tools and utilities for deploying the Cloud Infrastructure
Platform across various environments, including database management, server
configuration, and containerization.

The package organizes deployment code by purpose, with specialized modules for
database management, configuration, security, and infrastructure provisioning.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union

# Set up package-level logging
logger = logging.getLogger(__name__)

# Export constants for deployment environments
ENVIRONMENT_DEVELOPMENT = "development"
ENVIRONMENT_TESTING = "testing"
ENVIRONMENT_STAGING = "staging"
ENVIRONMENT_PRODUCTION = "production"
ENVIRONMENT_DR_RECOVERY = "dr-recovery"
ENVIRONMENT_CI = "ci"
ALLOWED_ENVIRONMENTS = [
    ENVIRONMENT_DEVELOPMENT,
    ENVIRONMENT_TESTING,
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_DR_RECOVERY,
    ENVIRONMENT_CI
]
SECURE_ENVIRONMENTS = [ENVIRONMENT_STAGING, ENVIRONMENT_PRODUCTION, ENVIRONMENT_DR_RECOVERY]

# Try to import database management components
try:
    from .database import (
        # Initialization functions
        create_database,
        apply_migrations,
        seed_data,
        read_config,
        verify_database,
        check_postgresql_version,
        setup_file_logging,
        initialize_database,
        get_database_status,

        # Maintenance functions
        optimize_database,
        vacuum_analyze,
        reindex_database,
        monitor_connection_count,
        check_table_bloat,
        check_index_usage,

        # Migration utilities
        verify_migrations,
        generate_migration_script,
        apply_migration,
        rollback_migration,
        get_migration_history,
        stamp_database_revision,
        merge_migration_heads,
        check_migration_script,
        get_current_migration_revision,
        create_initial_migration,

        # Constants
        ENVIRONMENTS as DB_ENVIRONMENTS,
        DEFAULT_ENVIRONMENT as DB_DEFAULT_ENVIRONMENT,
        DB_SCHEMAS,
        DEFAULT_EXTENSIONS,
        DB_ROLES,
        MAINTENANCE_SETTINGS,
        DEFAULT_CONNECTION_PARAMS
    )
    DATABASE_MODULE_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Could not import database module: {e}")
    DATABASE_MODULE_AVAILABLE = False

# Try to import CI package components if available
try:
    from .ci import (
        verify_dependency_integrity,
        generate_dependency_report
    )
    CI_MODULE_AVAILABLE = True
except ImportError:
    CI_MODULE_AVAILABLE = False

# Try to import docker components if available
try:
    from .docker import (
        build_image,
        push_image,
        run_container,
        stop_container
    )
    DOCKER_MODULE_AVAILABLE = True
except ImportError:
    DOCKER_MODULE_AVAILABLE = False

# Try to import security settings if available
try:
    from .security import (
        setup_security_baseline,
        validate_security_configuration,
        apply_security_patches,
        generate_security_report
    )
    SECURITY_MODULE_AVAILABLE = True
except ImportError:
    SECURITY_MODULE_AVAILABLE = False

# Try to import nginx utilities if available
try:
    from .nginx import (
        generate_nginx_config,
        validate_nginx_config,
        reload_nginx_config
    )
    NGINX_MODULE_AVAILABLE = True
except ImportError:
    NGINX_MODULE_AVAILABLE = False

# Define utility functions for deployment

def detect_environment() -> str:
    """
    Detect the current environment from environment variables.

    Returns:
        str: The detected environment name or the default (development)
    """
    env = os.environ.get("ENVIRONMENT", "").lower()
    if env in ALLOWED_ENVIRONMENTS:
        return env
    return ENVIRONMENT_DEVELOPMENT

def get_resource_path(resource_name: str, env: Optional[str] = None) -> Path:
    """
    Get the path to a deployment resource.

    Args:
        resource_name: Name of the resource file
        env: Optional environment name to get environment-specific resources

    Returns:
        Path: Path to the requested resource
    """
    if env is None:
        env = detect_environment()

    base_path = Path(__file__).parent

    # Check if environment-specific resource exists
    env_path = base_path / "config" / env / resource_name
    if env_path.exists():
        return env_path

    # Fall back to general resource
    return base_path / "config" / resource_name

def run_deployment_task(task_name: str, env: Optional[str] = None, **kwargs) -> bool:
    """
    Run a specific deployment task.

    Args:
        task_name: Name of the deployment task to run
        env: Target environment for the task
        **kwargs: Additional parameters for the task

    Returns:
        bool: True if the task was successful, False otherwise
    """
    if env is None:
        env = detect_environment()

    logger.info(f"Running deployment task '{task_name}' for environment '{env}'")

    # Map task names to actual functions
    task_map = {
        "initialize_database": initialize_database if DATABASE_MODULE_AVAILABLE else None,
        "optimize_database": optimize_database if DATABASE_MODULE_AVAILABLE else None,
        "verify_dependencies": verify_dependency_integrity if CI_MODULE_AVAILABLE else None,
        "security_baseline": setup_security_baseline if SECURITY_MODULE_AVAILABLE else None,
        "nginx_config": generate_nginx_config if NGINX_MODULE_AVAILABLE else None
    }

    if task_name not in task_map:
        logger.error(f"Unknown deployment task: {task_name}")
        return False

    if task_map[task_name] is None:
        logger.error(f"Task '{task_name}' is not available (module not imported)")
        return False

    try:
        result = task_map[task_name](env=env, **kwargs)
        return result if isinstance(result, bool) else True
    except Exception as e:
        logger.error(f"Error running deployment task '{task_name}': {e}")
        return False

# Package metadata
__version__ = "0.2.0"
__author__ = "Cloud Infrastructure Platform Team"

# Define public exports
__all__ = [
    # Core deployment environment constants
    "ENVIRONMENT_DEVELOPMENT",
    "ENVIRONMENT_TESTING",
    "ENVIRONMENT_STAGING",
    "ENVIRONMENT_PRODUCTION",
    "ENVIRONMENT_DR_RECOVERY",
    "ENVIRONMENT_CI",
    "ALLOWED_ENVIRONMENTS",
    "SECURE_ENVIRONMENTS",

    # Deployment utility functions
    "detect_environment",
    "get_resource_path",
    "run_deployment_task",

    # Database functions (if available)
    *([
        # Initialization functions
        "create_database",
        "apply_migrations",
        "seed_data",
        "read_config",
        "verify_database",
        "check_postgresql_version",
        "setup_file_logging",
        "initialize_database",
        "get_database_status",

        # Maintenance functions
        "optimize_database",
        "vacuum_analyze",
        "reindex_database",
        "monitor_connection_count",
        "check_table_bloat",
        "check_index_usage",

        # Migration utilities
        "verify_migrations",
        "generate_migration_script",
        "apply_migration",
        "rollback_migration",
        "get_migration_history",
        "stamp_database_revision",
        "merge_migration_heads",
        "check_migration_script",
        "get_current_migration_revision",
        "create_initial_migration",

        # Database constants
        "DB_ENVIRONMENTS",
        "DB_DEFAULT_ENVIRONMENT",
        "DB_SCHEMAS",
        "DEFAULT_EXTENSIONS",
        "DB_ROLES",
        "MAINTENANCE_SETTINGS",
        "DEFAULT_CONNECTION_PARAMS"
    ] if DATABASE_MODULE_AVAILABLE else []),

    # CI functions (if available)
    *([
        "verify_dependency_integrity",
        "generate_dependency_report"
    ] if CI_MODULE_AVAILABLE else []),

    # Docker functions (if available)
    *([
        "build_image",
        "push_image",
        "run_container",
        "stop_container"
    ] if DOCKER_MODULE_AVAILABLE else []),

    # Security functions (if available)
    *([
        "setup_security_baseline",
        "validate_security_configuration",
        "apply_security_patches",
        "generate_security_report"
    ] if SECURITY_MODULE_AVAILABLE else []),

    # NGINX functions (if available)
    *([
        "generate_nginx_config",
        "validate_nginx_config",
        "reload_nginx_config"
    ] if NGINX_MODULE_AVAILABLE else []),

    # Module availability flags
    "DATABASE_MODULE_AVAILABLE",
    "CI_MODULE_AVAILABLE",
    "DOCKER_MODULE_AVAILABLE",
    "SECURITY_MODULE_AVAILABLE",
    "NGINX_MODULE_AVAILABLE",

    # Version information
    "__version__",
    "__author__"
]
