#!/usr/bin/env python3
# filepath: scripts/database/__init__.py
"""
Database Management Package for Cloud Infrastructure Platform.

This package provides utilities for database operations, optimization, and maintenance
across different environments (development, staging, production).

Core functionality includes:
- Database initialization and schema creation
- Performance optimization and statistics analysis
- Data seeding for development and testing
- Index management and query optimization
"""

import os
import sys
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union

# Setup module logger
logger = logging.getLogger(__name__)

# Define package constants
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_CONFIG_PATH = "deployment/database/db_config.ini"
DEFAULT_ENVIRONMENT = "development"

# Try to import PostgreSQL optimizer functionality
try:
    from .pg_optimizer import (
        analyze_db_statistics,
        perform_optimization,
        generate_optimization_report,
        get_db_config,
        OptimizationError
    )
    PG_OPTIMIZER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Could not import pg_optimizer module: {e}")
    PG_OPTIMIZER_AVAILABLE = False

# Try to import seed_data functionality
try:
    from .seed_data import main as seed_data_main
    SEED_DATA_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Could not import seed_data module: {e}")
    SEED_DATA_AVAILABLE = False

# Try to import init_db functionality
try:
    from .init_db import (
        create_database,
        read_config,
        apply_migrations,
        seed_data,
        main as init_db_main
    )
    INIT_DB_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Could not import init_db module: {e}")
    INIT_DB_AVAILABLE = False


def run_db_manager(command: str, env: str = None, **kwargs) -> Tuple[bool, str]:
    """
    Run the database-manager.sh script with the given parameters.

    Args:
        command: Command to execute (backup, restore, verify, etc.)
        env: Target environment (production, staging, development)
        **kwargs: Additional arguments to pass to the script

    Returns:
        Tuple of (success, output)
    """
    cmd = [str(SCRIPT_DIR / "database-manager.sh"), command]

    if env:
        cmd.extend(["--env", env])

    # Add other parameters
    for key, value in kwargs.items():
        if value is True:
            cmd.append(f"--{key}")
        elif value not in (None, False):
            cmd.append(f"--{key}={value}")

    logger.debug(f"Executing command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        return result.returncode == 0, result.stdout
    except Exception as e:
        logger.error(f"Error executing database-manager.sh: {str(e)}")
        return False, f"Error executing database-manager.sh: {str(e)}"


def backup_database(env: str, compress: bool = True, schema_only: bool = False) -> Tuple[bool, str]:
    """
    Create a database backup for the specified environment.

    Args:
        env: Target environment (production, staging, development)
        compress: Whether to compress the backup
        schema_only: Whether to back up only schema without data

    Returns:
        Tuple of (success, output)
    """
    return run_db_manager("backup", env=env, compress=compress, schema_only=schema_only)


def restore_database(env: str, backup_file: str, force: bool = False) -> Tuple[bool, str]:
    """
    Restore database from backup file.

    Args:
        env: Target environment (production, staging, development)
        backup_file: Path to backup file
        force: Whether to force restore without confirmation

    Returns:
        Tuple of (success, output)
    """
    return run_db_manager("restore", env=env, file=backup_file, force=force)


def verify_database(env: str, quick_check: bool = False) -> Tuple[bool, str]:
    """
    Verify database integrity.

    Args:
        env: Target environment (production, staging, development)
        quick_check: Whether to perform only basic verification

    Returns:
        Tuple of (success, output)
    """
    return run_db_manager("verify-db", env=env, quick=quick_check)


def check_replication(env: str, lag_threshold: int = 300) -> Tuple[bool, str]:
    """
    Check database replication health.

    Args:
        env: Target environment (production, staging, development)
        lag_threshold: Maximum allowed replication lag in seconds

    Returns:
        Tuple of (success, output)
    """
    return run_db_manager("check-replication", env=env, threshold=lag_threshold)


def optimize_db(env: str, vacuum_mode: str = "standard", reindex: bool = False,
               apply: bool = False, analyze_only: bool = False) -> Dict[str, Any]:
    """
    Perform database optimization using pg_optimizer.py.

    Args:
        env: Target environment (production, staging, development)
        vacuum_mode: Type of vacuum to perform ('standard', 'full', 'analyze')
        reindex: Whether to rebuild indexes
        apply: Whether to apply changes or run in dry-run mode
        analyze_only: Whether to only analyze without optimization recommendations

    Returns:
        Dictionary with optimization results
    """
    if not PG_OPTIMIZER_AVAILABLE:
        logger.error("pg_optimizer module not available")
        return {
            "success": False,
            "error": "pg_optimizer module not available"
        }

    try:
        db_config = get_db_config(env)

        if analyze_only:
            return analyze_db_statistics(db_config=db_config)

        return perform_optimization(
            db_config=db_config,
            vacuum_mode=vacuum_mode,
            reindex=reindex,
            dry_run=not apply
        )
    except OptimizationError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def initialize_database(env: str, seed: bool = False, drop_existing: bool = False,
                      schema_only: bool = False, verbose: bool = False,
                      skip_migrations: bool = False) -> bool:
    """
    Initialize database for the specified environment.

    Args:
        env: Target environment (production, staging, development)
        seed: Whether to seed initial data
        drop_existing: Whether to drop existing database
        schema_only: Whether to create only schema without data
        verbose: Whether to enable verbose output
        skip_migrations: Whether to skip running migrations

    Returns:
        True if database was initialized successfully
    """
    if not INIT_DB_AVAILABLE:
        logger.error("init_db module not available")
        return False

    try:
        # Read database configuration
        config_path = os.path.join(PROJECT_ROOT, DEFAULT_CONFIG_PATH)
        db_config, app_user, app_password = read_config(config_path, env)

        # Create database
        success = create_database(
            db_config,
            app_user,
            app_password,
            drop_existing=drop_existing,
            skip_extensions=False
        )
        if not success:
            return False

        # Apply migrations
        if not skip_migrations:
            if not apply_migrations(env, skip=skip_migrations):
                return False
        else:
            logger.info("Skipping database migrations")

        # Seed data if requested
        if seed and not schema_only:
            if not seed_data(env, schema_only=schema_only):
                return False

        logger.info(f"Database initialization for {env} completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False


# Define package version and metadata
__version__ = "0.1.1"
__author__ = "Cloud Infrastructure Platform Team"

# Define public API
__all__ = [
    # PostgreSQL optimizer functions (if available)
    *([
        "analyze_db_statistics",
        "perform_optimization",
        "generate_optimization_report",
        "get_db_config",
        "OptimizationError"
    ] if PG_OPTIMIZER_AVAILABLE else []),

    # Database manager shell script wrapper
    "run_db_manager",

    # Convenience functions for common operations
    "backup_database",
    "restore_database",
    "verify_database",
    "check_replication",
    "optimize_db",
    "initialize_database",

    # Database initialization functions (if available)
    *([
        "create_database",
        "read_config",
        "apply_migrations",
        "seed_data"
    ] if INIT_DB_AVAILABLE else []),

    # Main entry points
    *([
        "seed_data_main"
    ] if SEED_DATA_AVAILABLE else []),
    *([
        "init_db_main"
    ] if INIT_DB_AVAILABLE else []),

    # Version information
    "__version__",
    "__author__"
]
