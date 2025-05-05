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
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union

# Setup module logger
logger = logging.getLogger(__name__)

# Define package constants
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent

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

# Define a function to run database-manager.sh since it's a shell script
def run_db_manager(command: str, env: str = None, **kwargs) -> Tuple[bool, str]:
    """
    Run database-manager.sh with given command and parameters.

    Args:
        command: Command to execute (backup, restore, verify, list, etc.)
        env: Target environment (production, staging, development, etc.)
        **kwargs: Additional parameters for the command

    Returns:
        Tuple of (success, output)
    """
    import subprocess

    script_path = os.path.join(SCRIPT_DIR, "database-manager.sh")
    if not os.path.exists(script_path):
        return False, f"database-manager.sh not found at {script_path}"

    cmd = [script_path, command]
    if env:
        cmd.extend(["--env", env])

    # Add any additional parameters
    for key, value in kwargs.items():
        if len(key) == 1:
            cmd.append(f"-{key}")
        else:
            cmd.append(f"--{key.replace('_', '-')}")

        if value is not True:  # Don't add value for boolean flags
            cmd.append(str(value))

    try:
        result = subprocess.run(cmd,
                               capture_output=True,
                               text=True,
                               check=False)
        return result.returncode == 0, result.stdout
    except Exception as e:
        return False, f"Error executing database-manager.sh: {str(e)}"

# Define convenience functions for common database operations
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
    Verify database integrity for the specified environment.

    Args:
        env: Target environment (production, staging, development)
        quick_check: Whether to perform only connectivity check

    Returns:
        Tuple of (success, output)
    """
    return run_db_manager("verify-db", env=env, quick_check=quick_check)

def check_replication(env: str, lag_threshold: int = 300) -> Tuple[bool, str]:
    """
    Check database replication status.

    Args:
        env: Target environment (production, staging, development)
        lag_threshold: Maximum acceptable replication lag in seconds

    Returns:
        Tuple of (success, output)
    """
    return run_db_manager("check-replication", env=env, threshold=lag_threshold)

def optimize_db(env: str, vacuum_mode: str = "standard", reindex: bool = False,
               apply: bool = False, analyze_only: bool = False) -> Dict[str, Any]:
    """
    Optimize database by running vacuum, analyze, and/or reindex operations.

    Args:
        env: Target environment (production, staging, development)
        vacuum_mode: Type of vacuum to perform (standard, full, analyze)
        reindex: Whether to reindex bloated indexes
        apply: Whether to apply changes (false for dry run)
        analyze_only: Whether to only analyze without performing optimizations

    Returns:
        Dictionary containing optimization results
    """
    if not PG_OPTIMIZER_AVAILABLE:
        logger.error("pg_optimizer module not available")
        return {"success": False, "error": "pg_optimizer module not available"}

    try:
        # Get database configuration for the environment
        db_config = get_db_config(env)

        # Run analysis if analyze_only is True
        if analyze_only:
            return analyze_db_statistics(db_config=db_config)

        # Otherwise perform optimization
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

def initialize_database(env: str, seed: bool = False, drop_existing: bool = False) -> bool:
    """
    Initialize database for the specified environment.

    Args:
        env: Target environment (production, staging, development)
        seed: Whether to seed initial data
        drop_existing: Whether to drop existing database

    Returns:
        True if database was initialized successfully
    """
    if not INIT_DB_AVAILABLE:
        logger.error("init_db module not available")
        return False

    try:
        # Read database configuration
        db_config, app_user, app_password = read_config("../deployment/database/db_config.ini", env)

        # Create database
        if not create_database(db_config, app_user, app_password, drop_existing):
            return False

        # Apply migrations
        if not apply_migrations():
            return False

        # Seed data if requested
        if seed and not seed_data():
            return False

        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False

# Define package version and metadata
__version__ = "0.2.0"
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
