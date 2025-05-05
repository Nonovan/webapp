"""
Database Management Package for Cloud Infrastructure Platform.

This package provides utilities for database setup, initialization, migration,
backup, and maintenance operations across different environments (development,
staging, production, dr-recovery).
"""

import os
import logging
from typing import Dict, Any, List, Optional, Tuple
import datetime

# Setup package logging
logger = logging.getLogger(__name__)

# Try to import database initialization functions from init_db
try:
    from .init_db import (
        create_database,
        apply_migrations,
        seed_data,
        read_config,
        verify_database,
        check_postgresql_version,
        setup_file_logging,
        parse_args as init_db_parse_args,
        main as init_db_main
    )
except ImportError as e:
    logger.debug(f"Could not import init_db module: {e}")

# Try to import maintenance functions if available
try:
    from .maintenance import (
        optimize_database,
        vacuum_analyze,
        reindex_database,
        monitor_connection_count,
        check_table_bloat,
        check_index_usage
    )
except ImportError as e:
    logger.debug(f"Could not import maintenance module: {e}")

# Try to import migration utilities
try:
    from .migrations import (
        verify_migrations,
        generate_migration_script,
        apply_migration,
        rollback_migration,
        get_migration_history,
        stamp_database_revision,
        merge_migration_heads,
        check_migration_script,
        get_current_migration_revision,
        create_initial_migration
    )
except ImportError as e:
    logger.debug(f"Could not import migrations module: {e}")

# Try to import constants from db_constants
try:
    from .db_constants import (
        ENVIRONMENTS,
        DEFAULT_ENVIRONMENT,
        DEFAULT_CONFIG_PATH,
        DEFAULT_DB_NAMES,
        DB_ROLES,
        DB_SCHEMAS,
        DEFAULT_EXTENSIONS,
        DEFAULT_CONNECTION_PARAMS,
        MAINTENANCE_SETTINGS,
        BACKUP_SETTINGS,
        DB_METRICS,
        MONITORING_QUERIES,
        INIT_PARAMS,
        SCRIPT_INIT_DB,
        SCRIPT_CREATE_DB,
        SCRIPT_BACKUP_DB,
        SCRIPT_RESTORE_DB,
        SCRIPT_ADD_INDEXES,
        SCRIPT_OPTIMIZE,
        LOG_FORMAT,
        LOG_DATE_FORMAT,
        EXIT_CODE_SUCCESS,
        EXIT_CODE_ERROR,
        EXIT_CODE_WARNING,
        EXIT_CODE_PERMISSION_ERROR,
        EXIT_CODE_RESOURCE_ERROR,
        EXIT_CODE_VALIDATION_ERROR,
        EXIT_CODE_CONFIGURATION_ERROR,
        EXIT_CODE_OPERATION_CANCELLED
    )
except ImportError as e:
    logger.debug(f"Could not import db_constants module: {e}")
    # Define minimal constants for backward compatibility
    ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]
    DEFAULT_ENVIRONMENT = "development"
    DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "db_config.ini")
    DEFAULT_DB_NAMES = {
        "development": "cloud_platform_development",
        "staging": "cloud_platform_staging",
        "production": "cloud_platform_production",
        "dr-recovery": "cloud_platform_dr"
    }
    DB_ROLES = {
        "app": "cloud_platform_app",         # Application user with write access
        "readonly": "cloud_platform_readonly", # Read-only access for reporting
        "admin": "cloud_platform_admin"       # Administrative access for maintenance
    }
    DB_SCHEMAS = ["public", "cloud", "ics", "security", "audit"]
    DEFAULT_EXTENSIONS = ["pgcrypto", "uuid-ossp", "pg_stat_statements"]
    DEFAULT_CONNECTION_PARAMS = {
        "application_name": "cloud_platform",
        "connect_timeout": 10,
        "client_encoding": "utf8",
        "options": "-c statement_timeout=30000"  # 30 second query timeout
    }
    MAINTENANCE_SETTINGS = {
        "vacuum_threshold": 20,              # Vacuum when >20% of tuples are dead
        "analyze_threshold": 10,             # Analyze when >10% of tuples have changed
        "index_bloat_threshold": 30,         # Reindex when bloat >30%
        "max_connection_percent": 80,        # Alert when connections >80% of max
        "max_transaction_age": 30 * 60,      # Alert for transactions running >30 minutes
        "max_idle_transaction_age": 5 * 60   # Alert for idle transactions >5 minutes
    }
    DB_METRICS = [
        "active_connections",
        "transaction_rate",
        "cache_hit_ratio",
        "index_usage",
        "table_size",
        "slow_queries",
        "deadlocks"
    ]
    BACKUP_SETTINGS = {}
    MONITORING_QUERIES = {}
    INIT_PARAMS = {}
    LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
    LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    EXIT_CODE_SUCCESS = 0
    EXIT_CODE_ERROR = 1
    EXIT_CODE_WARNING = 2
    EXIT_CODE_PERMISSION_ERROR = 3
    EXIT_CODE_RESOURCE_ERROR = 4
    EXIT_CODE_VALIDATION_ERROR = 5
    EXIT_CODE_CONFIGURATION_ERROR = 6
    EXIT_CODE_OPERATION_CANCELLED = 7
    SCRIPT_INIT_DB = "init_db.py"
    SCRIPT_CREATE_DB = "create_db.py"
    SCRIPT_BACKUP_DB = "backup_db.py"
    SCRIPT_RESTORE_DB = "restore_db.py"
    SCRIPT_ADD_INDEXES = "add_indexes.sh"
    SCRIPT_OPTIMIZE = "optimize.sh"

def initialize_database(
    env: str = DEFAULT_ENVIRONMENT,
    drop_existing: bool = False,
    create_schemas: bool = True,
    seed: bool = False,
    schema_only: bool = False,
    verbose: bool = False,
    timeout: int = 60,
    verify: bool = True,
    skip_migrations: bool = False,
    use_core_seeder: bool = False,
    dry_run: bool = False
) -> bool:
    """
    High-level function to initialize a database for the specified environment.

    This is a convenience function that combines multiple steps of database setup.

    Args:
        env: Target environment (development, staging, production, dr-recovery)
        drop_existing: Whether to drop the database if it exists
        create_schemas: Whether to create standard schemas
        seed: Whether to seed initial data
        schema_only: If True, only create schema without seeding data
        verbose: Whether to output detailed progress information
        timeout: Operation timeout in seconds
        verify: Whether to verify database integrity after creation
        skip_migrations: Whether to skip running database migrations
        use_core_seeder: Whether to use core.seeder module instead of seed_data.py script
        dry_run: If True, don't make actual changes

    Returns:
        True if database was initialized successfully, False otherwise
    """
    try:
        # Read configuration for the environment
        config_path = DEFAULT_CONFIG_PATH
        db_config, app_user, app_password = read_config(config_path, env)

        # Create the database with schemas and extensions
        success = create_database(
            db_config,
            app_user,
            app_password,
            drop_existing=drop_existing,
            create_schemas=create_schemas,
            dry_run=dry_run,
            timeout=timeout
        )

        if not success:
            logger.error(f"Failed to create database for {env}")
            return False

        # Verify database setup if requested and not in dry run mode
        if verify and not dry_run:
            if not verify_database(db_config, app_user):
                logger.error("Database verification failed")
                return False

        # Apply migrations if not skipped
        if not skip_migrations and not schema_only:
            if not apply_migrations(env, dry_run, timeout):
                logger.error("Failed to apply database migrations")
                return False

        # Seed data if requested
        if seed and not schema_only:
            if not seed_data(env, dry_run, use_core_seeder, timeout):
                logger.error("Failed to seed database")
                return False

        logger.info(f"Database initialization for {env} completed successfully")
        return True

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

def get_database_status(db_config: Dict[str, str]) -> Dict[str, Any]:
    """
    Get current database status information.

    Retrieves information about the database including version, size,
    connection count, and recent activity.

    Args:
        db_config: Database connection parameters

    Returns:
        Dictionary containing database status information
    """
    status = {
        "timestamp": None,
        "version": None,
        "size": None,
        "connections": None,
        "vacuum_status": None,
        "errors": []
    }

    try:
        if 'monitor_connection_count' in globals():
            conn_status = monitor_connection_count(db_config, verbose=False)
            if conn_status and conn_status.get('success'):
                status["connections"] = conn_status.get("connection_count", 0)
                status["connection_percent"] = conn_status.get("connection_percent", 0)

        status["timestamp"] = datetime.datetime.now().isoformat()
        return status

    except NameError:
        # monitor_connection_count not available
        status["errors"].append("Monitoring functions not available")
        return status

    except Exception as e:
        status["errors"].append(f"Error getting database status: {str(e)}")
        return status

# Export public API
__version__ = "0.1.2"
__author__ = "Cloud Infrastructure Platform Team"

__all__ = [
    # Initialization functions
    "create_database",
    "apply_migrations",
    "seed_data",
    "read_config",
    "verify_database",
    "check_postgresql_version",
    "setup_file_logging",
    "init_db_parse_args",
    "init_db_main",
    "initialize_database",
    "get_database_status",

    # Maintenance functions (may not be available in all installations)
    "optimize_database",
    "vacuum_analyze",
    "reindex_database",
    "monitor_connection_count",
    "check_table_bloat",
    "check_index_usage",

    # Migration utilities (may not be available in all installations)
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

    # Constants
    "ENVIRONMENTS",
    "DEFAULT_ENVIRONMENT",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_DB_NAMES",
    "DB_ROLES",
    "DB_SCHEMAS",
    "DEFAULT_EXTENSIONS",
    "DEFAULT_CONNECTION_PARAMS",
    "MAINTENANCE_SETTINGS",
    "BACKUP_SETTINGS",
    "DB_METRICS",
    "MONITORING_QUERIES",
    "INIT_PARAMS",
    "LOG_FORMAT",
    "LOG_DATE_FORMAT",

    # Exit codes
    "EXIT_CODE_SUCCESS",
    "EXIT_CODE_ERROR",
    "EXIT_CODE_WARNING",
    "EXIT_CODE_PERMISSION_ERROR",
    "EXIT_CODE_RESOURCE_ERROR",
    "EXIT_CODE_VALIDATION_ERROR",
    "EXIT_CODE_CONFIGURATION_ERROR",
    "EXIT_CODE_OPERATION_CANCELLED",

    # Script names
    "SCRIPT_INIT_DB",
    "SCRIPT_CREATE_DB",
    "SCRIPT_BACKUP_DB",
    "SCRIPT_RESTORE_DB",
    "SCRIPT_ADD_INDEXES",
    "SCRIPT_OPTIMIZE",

    # Version information
    "__version__",
    "__author__"
]
