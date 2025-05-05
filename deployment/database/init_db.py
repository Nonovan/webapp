#!/usr/bin/env python3
"""
Database initialization script for Cloud Infrastructure Platform

This script initializes a new database with the required schema and initial data.
It can be used for setting up new environments or resetting development databases.
"""

import os
import sys
import argparse
import subprocess
import logging
import platform
import time
from datetime import datetime
from pathlib import Path
from configparser import ConfigParser
from typing import Dict, Tuple, Optional, List, Any, Union
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from psycopg2 import errors as psycopg2_errors

# Try to import database constants
try:
    from .db_constants import (
        ENVIRONMENTS, DEFAULT_ENVIRONMENT, DEFAULT_CONFIG_PATH,
        DB_SCHEMAS, DEFAULT_EXTENSIONS, DEFAULT_CONNECTION_PARAMS,
        DB_ROLES, MAINTENANCE_SETTINGS, BACKUP_SETTINGS,
        EXIT_CODE_SUCCESS, EXIT_CODE_ERROR
    )
except ImportError:
    # Define minimal constants if db_constants.py is not available
    ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]
    DEFAULT_ENVIRONMENT = "development"
    DEFAULT_CONFIG_PATH = "deployment/database/db_config.ini"
    DB_SCHEMAS = ["public", "cloud", "ics", "security", "audit"]
    DEFAULT_EXTENSIONS = ["pgcrypto", "uuid-ossp", "pg_stat_statements"]
    EXIT_CODE_SUCCESS = 0
    EXIT_CODE_ERROR = 1
    # Define empty placeholders for other constants
    DEFAULT_CONNECTION_PARAMS = {}
    DB_ROLES = {}
    MAINTENANCE_SETTINGS = {}
    BACKUP_SETTINGS = {}

# Configure logging
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    format=LOG_FORMAT,
    level=logging.INFO,
    datefmt=LOG_DATE_FORMAT
)
logger = logging.getLogger("database-init")


def setup_file_logging(log_file: Optional[str] = None, verbose: bool = False) -> None:
    """
    Set up file logging in addition to console logging.

    Args:
        log_file: Path to log file, uses default if None
        verbose: Whether to enable debug logging
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose output enabled")

    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
            logger.addHandler(file_handler)
            logger.debug(f"File logging enabled at {log_file}")
        except Exception as e:
            logger.warning(f"Could not set up file logging: {e}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Initialize database for Cloud Infrastructure Platform")
    parser.add_argument("--env", default=DEFAULT_ENVIRONMENT, choices=ENVIRONMENTS,
                        help=f"Target environment (default: {DEFAULT_ENVIRONMENT})")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help=f"Path to database config file (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--schema-only", action="store_true",
                        help="Only create schema, skip sample data")
    parser.add_argument("--drop-existing", action="store_true",
                        help="Drop existing database before creating")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--skip-migrations", action="store_true",
                        help="Skip running database migrations")
    parser.add_argument("--create-schemas", action="store_true", default=True,
                        help="Create standard schemas (default: True)")
    parser.add_argument("--skip-extensions", action="store_true",
                        help="Skip installing PostgreSQL extensions")
    parser.add_argument("--log-file",
                        help="Path to log file (default: None, console only)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without making changes")
    parser.add_argument("--use-core-seeder", action="store_true",
                        help="Use core.seeder module instead of seed_data.py script")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Operation timeout in seconds (default: 60)")
    parser.add_argument("--verify", action="store_true", default=True,
                        help="Verify database integrity after operations (default: True)")
    return parser.parse_args()


def read_config(config_path: str, env: str) -> Tuple[Dict[str, str], str, str]:
    """
    Read database configuration from file.

    Args:
        config_path: Path to configuration file
        env: Target environment

    Returns:
        Tuple containing database config dict, app username, and app password

    Raises:
        FileNotFoundError: If config file doesn't exist
        KeyError: If required config keys are missing
    """
    config_path = Path(config_path)
    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        raise FileNotFoundError(f"Config file not found: {config_path}")

    config = ConfigParser()
    config.read(config_path)

    try:
        # Check if section exists
        if env not in config.sections():
            available_envs = ", ".join(config.sections())
            logger.error(f"Environment '{env}' not found in config. Available environments: {available_envs}")
            raise KeyError(f"Environment '{env}' not found in config")

        db_config = {
            "host": config.get(env, "host"),
            "port": config.get(env, "port"),
            "user": config.get(env, "admin_user"),
            "password": config.get(env, "admin_password"),
            "dbname": config.get(env, "dbname")
        }

        # Add connection parameters from constants if available
        if DEFAULT_CONNECTION_PARAMS:
            for key, value in DEFAULT_CONNECTION_PARAMS.items():
                if key not in db_config:
                    db_config[key] = value

        app_user = config.get(env, "app_user")
        app_password = config.get(env, "app_password")

        # Validate connection parameters
        for param in ["host", "port", "user", "password", "dbname"]:
            if not db_config.get(param):
                raise KeyError(f"Required parameter '{param}' is missing or empty")

        if not app_user or not app_password:
            raise KeyError("Application user credentials are missing or empty")

        return db_config, app_user, app_password

    except (KeyError, ValueError) as e:
        logger.error(f"Error reading config: {e}")
        raise KeyError(f"Missing required configuration: {e}")


def check_postgresql_version() -> Tuple[bool, str]:
    """
    Check if PostgreSQL client tools are installed and get version.

    Returns:
        Tuple containing (success, version_string)
    """
    try:
        result = subprocess.run(
            ["psql", "--version"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            logger.debug(f"PostgreSQL client version: {version}")
            return True, version
        else:
            logger.warning("PostgreSQL client tools not found or not working properly")
            return False, ""
    except Exception as e:
        logger.warning(f"Error checking PostgreSQL version: {e}")
        return False, ""


def create_database(
    db_config: Dict[str, str],
    app_user: str,
    app_password: str,
    drop_existing: bool = False,
    create_schemas: bool = True,
    skip_extensions: bool = False,
    dry_run: bool = False,
    timeout: int = 60
) -> bool:
    """
    Create a new database with appropriate permissions.

    Args:
        db_config: Database connection parameters
        app_user: Application user to create and grant permissions to
        app_password: Password for application user
        drop_existing: Whether to drop existing database if it exists
        create_schemas: Whether to create standard schemas
        skip_extensions: Whether to skip installing PostgreSQL extensions
        dry_run: If True, don't make actual changes
        timeout: Operation timeout in seconds

    Returns:
        True if database was created successfully

    Raises:
        Exception: If database creation fails
    """
    if dry_run:
        logger.info("[DRY RUN] Would create database with the following parameters:")
        logger.info(f"  Database: {db_config['dbname']}")
        logger.info(f"  Host: {db_config['host']}")
        logger.info(f"  Port: {db_config['port']}")
        logger.info(f"  Admin user: {db_config['user']}")
        logger.info(f"  App user: {app_user}")
        logger.info(f"  Drop existing: {drop_existing}")
        logger.info(f"  Create schemas: {create_schemas}")
        logger.info(f"  Skip extensions: {skip_extensions}")
        return True

    # Connect to default postgres database to create new database
    conn_params = db_config.copy()
    conn_params["dbname"] = "postgres"
    conn = cursor = None

    start_time = time.time()

    try:
        # Connect to postgres database
        logger.info(f"Connecting to database at {conn_params['host']}:{conn_params['port']}...")
        conn = psycopg2.connect(**conn_params)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        dbname = db_config["dbname"]

        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
        exists = cursor.fetchone()

        # Drop database if requested and exists
        if exists:
            if drop_existing:
                logger.info(f"Dropping existing database '{dbname}'...")

                # Close all connections to the database first
                try:
                    cursor.execute(f"""
                        SELECT pg_terminate_backend(pg_stat_activity.pid)
                        FROM pg_stat_activity
                        WHERE pg_stat_activity.datname = %s
                        AND pid <> pg_backend_pid()
                    """, (dbname,))

                    cursor.execute("DROP DATABASE IF EXISTS %s", (dbname,))
                    logger.info(f"Database '{dbname}' dropped")
                except psycopg2_errors.ObjectInUse as e:
                    logger.error(f"Could not drop database: {e}")
                    logger.error("Database is in use by other connections.")
                    return False
            else:
                logger.warning(f"Database '{dbname}' already exists. Use --drop-existing to recreate it.")
                return False

        # Create database
        logger.info(f"Creating database '{dbname}'...")
        cursor.execute(f"CREATE DATABASE {dbname}")

        # Create app user if not exists
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (app_user,))
        user_exists = cursor.fetchone()
        if not user_exists:
            logger.info(f"Creating application user '{app_user}'...")
            cursor.execute(f"CREATE USER {app_user} WITH PASSWORD %s", (app_password,))
        else:
            logger.info(f"Application user '{app_user}' already exists, updating password...")
            cursor.execute(f"ALTER USER {app_user} WITH PASSWORD %s", (app_password,))

        # Grant privileges to app user
        logger.info(f"Granting privileges to '{app_user}'...")
        cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {dbname} TO {app_user}")

    except Exception as e:
        logger.error(f"Error setting up database: {e}")
        if conn:
            conn.close()
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # Now connect to the newly created database
    conn_params = db_config.copy()
    conn = cursor = None

    try:
        # Check timeout
        if time.time() - start_time > timeout:
            logger.error(f"Operation timed out after {timeout} seconds")
            return False

        # Connect to the newly created database
        conn = psycopg2.connect(**conn_params)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        # Install PostgreSQL extensions if not skipped
        if not skip_extensions:
            logger.info("Enabling PostgreSQL extensions...")
            for extension in DEFAULT_EXTENSIONS:
                logger.info(f"Creating extension: {extension}")
                try:
                    cursor.execute(f"CREATE EXTENSION IF NOT EXISTS \"{extension}\"")
                except Exception as e:
                    logger.warning(f"Could not create extension {extension}: {e}")

        # Create schemas if requested
        if create_schemas:
            logger.info("Creating standard schemas...")
            for schema in DB_SCHEMAS:
                if schema != "public":  # public schema already exists
                    logger.info(f"Creating schema: {schema}")
                    cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")

                    # Grant usage on schema to app user
                    cursor.execute(f"GRANT USAGE ON SCHEMA {schema} TO {app_user}")

                    # Grant privileges on future objects
                    cursor.execute(f"""
                        ALTER DEFAULT PRIVILEGES FOR ROLE {db_config['user']} IN SCHEMA {schema}
                        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app_user}
                    """)

                    cursor.execute(f"""
                        ALTER DEFAULT PRIVILEGES FOR ROLE {db_config['user']} IN SCHEMA {schema}
                        GRANT USAGE, SELECT ON SEQUENCES TO {app_user}
                    """)

                    # Add read-only role grants if available in DB_ROLES
                    if DB_ROLES and "readonly" in DB_ROLES:
                        readonly_role = DB_ROLES["readonly"]
                        logger.info(f"Granting read-only privileges to {readonly_role} role")

                        # Check if readonly role exists, create it if not
                        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (readonly_role,))
                        if not cursor.fetchone():
                            cursor.execute(f"CREATE ROLE {readonly_role}")

                        # Grant read-only privileges
                        cursor.execute(f"GRANT USAGE ON SCHEMA {schema} TO {readonly_role}")
                        cursor.execute(f"""
                            ALTER DEFAULT PRIVILEGES FOR ROLE {db_config['user']} IN SCHEMA {schema}
                            GRANT SELECT ON TABLES TO {readonly_role}
                        """)

            # Set search path
            cursor.execute(f"ALTER DATABASE {dbname} SET search_path TO {', '.join(DB_SCHEMAS)}")

        # Create database comment
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = os.environ.get("USER", "unknown")
        hostname = platform.node()
        cursor.execute(f"""
            COMMENT ON DATABASE {dbname} IS
            'Cloud Infrastructure Platform database. Created on {timestamp} by {username}@{hostname}.'
        """)

        logger.info(f"Database '{dbname}' initialized successfully")
        return True

    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def verify_database(db_config: Dict[str, str], app_user: str) -> bool:
    """
    Verify the database was created properly and is accessible.

    Args:
        db_config: Database connection parameters
        app_user: Application user to test connection with

    Returns:
        True if verification passed, False otherwise
    """
    logger.info("Verifying database setup...")

    # Test connection with admin user
    try:
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()

        # Check that we can query the database
        cursor.execute("SELECT version()")
        version = cursor.fetchone()[0]
        logger.info(f"Successfully connected to database using admin user. PostgreSQL version: {version}")

        # Check schemas exist
        cursor.execute("""
            SELECT schema_name FROM information_schema.schemata
            WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        """)
        schemas = [row[0] for row in cursor.fetchall()]
        logger.info(f"Available schemas: {', '.join(schemas)}")

        # Check extensions
        cursor.execute("SELECT extname FROM pg_extension")
        extensions = [row[0] for row in cursor.fetchall()]
        logger.info(f"Installed extensions: {', '.join(extensions)}")

        cursor.close()
        conn.close()
    except Exception as e:
        logger.error(f"Admin connection verification failed: {e}")
        return False

    # Attempt connection with application user if provided
    if app_user:
        try:
            # Modify connection params for app user
            app_conn_params = db_config.copy()
            app_conn_params["user"] = app_user

            conn = psycopg2.connect(**app_conn_params)
            cursor = conn.cursor()

            # Try a simple query
            cursor.execute("SELECT current_user, current_database()")
            user, database = cursor.fetchone()
            logger.info(f"Successfully connected as application user '{user}' to database '{database}'")

            cursor.close()
            conn.close()
        except Exception as e:
            logger.error(f"Application user connection verification failed: {e}")
            return False

    logger.info("Database verification completed successfully")
    return True


def apply_migrations(
    env: str = DEFAULT_ENVIRONMENT,
    dry_run: bool = False,
    timeout: int = 60
) -> bool:
    """
    Apply database migrations using Flask-Migrate.

    Args:
        env: Target environment
        dry_run: If True, don't actually apply migrations
        timeout: Operation timeout in seconds

    Returns:
        True if migrations were applied successfully
    """
    if dry_run:
        logger.info("[DRY RUN] Would apply database migrations")
        return True

    logger.info("Applying database migrations...")
    try:
        start_time = time.time()
        env_vars = os.environ.copy()
        env_vars["FLASK_ENV"] = env

        result = subprocess.run(
            ["flask", "db", "upgrade"],
            check=True,
            capture_output=True,
            text=True,
            env=env_vars,
            timeout=timeout
        )

        if result.stdout:
            logger.info(f"Migration output: {result.stdout}")
        if result.stderr and result.stderr.strip():
            logger.warning(f"Migration stderr: {result.stderr}")

        logger.info("Migrations applied successfully")
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"Migration timed out after {timeout} seconds")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"Error applying migrations: {e}")
        if e.stdout:
            logger.error(f"Migration stdout: {e.stdout}")
        if e.stderr:
            logger.error(f"Migration stderr: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during migration: {e}")
        return False


def seed_data(
    env: str = DEFAULT_ENVIRONMENT,
    dry_run: bool = False,
    use_core_seeder: bool = False,
    timeout: int = 60
) -> bool:
    """
    Seed initial data.

    Args:
        env: Target environment
        dry_run: If True, don't actually seed data
        use_core_seeder: If True, use core.seeder module instead of seed_data.py script
        timeout: Operation timeout in seconds

    Returns:
        True if data was seeded successfully
    """
    if dry_run:
        logger.info("[DRY RUN] Would seed database with initial data")
        return True

    logger.info("Seeding initial data...")
    try:
        start_time = time.time()

        # Create environment variables dict
        env_vars = os.environ.copy()
        env_vars["FLASK_ENV"] = env

        if use_core_seeder:
            # Use Flask shell to call core.seeder functions
            seed_command = """
from flask import current_app
from core.seeder import seed_database, seed_development_data
with current_app.app_context():
    success = seed_database(verbose=True)
    print('SEED_RESULT=' + ('success' if success else 'failure'))
"""
            logger.info("Using core.seeder module to seed database")
            result = subprocess.run(
                ["flask", "shell"],
                input=seed_command,
                capture_output=True,
                text=True,
                env=env_vars,
                timeout=timeout,
                check=False
            )

            success = 'SEED_RESULT=success' in result.stdout
        else:
            # Use seed_data.py script
            script_path = "scripts/database/seed_data.py"
            if not Path(script_path).exists():
                logger.warning(f"Seed script not found at {script_path}, falling back to core.seeder")
                return seed_data(env, dry_run, use_core_seeder=True, timeout=timeout)

            logger.info(f"Using {script_path} to seed database")
            result = subprocess.run(
                ["python", script_path, f"--env={env}"],
                check=False,
                capture_output=True,
                text=True,
                env=env_vars,
                timeout=timeout
            )
            success = result.returncode == 0

        if result.stdout:
            logger.info(f"Seeding output: {result.stdout}")
        if result.stderr and result.stderr.strip():
            logger.warning(f"Seeding stderr: {result.stderr}")

        if success:
            logger.info("Data seeded successfully")
            return True
        else:
            logger.error("Seeding failed")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Seeding timed out after {timeout} seconds")
        return False
    except Exception as e:
        logger.error(f"Error seeding data: {e}")
        return False


def main() -> int:
    """
    Main function.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    args = parse_args()

    # Setup logging with file if specified
    setup_file_logging(args.log_file, args.verbose)

    logger.info(f"Initializing {args.env} database...")

    # Track metrics if possible
    try:
        from core.metrics import increment_counter
        increment_counter('database.init.attempt', {'environment': args.env})
    except ImportError:
        pass

    # Check PostgreSQL client tools
    pg_available, pg_version = check_postgresql_version()
    if pg_available:
        logger.info(f"Using PostgreSQL client: {pg_version}")
    else:
        logger.warning("PostgreSQL client tools not detected. Make sure pg_dump/psql are available.")

    try:
        # Read database configuration
        db_config, app_user, app_password = read_config(args.config, args.env)

        # Create database
        success = create_database(
            db_config,
            app_user,
            app_password,
            args.drop_existing,
            args.create_schemas,
            args.skip_extensions,
            args.dry_run,
            args.timeout
        )

        if not success:
            logger.error("Database creation failed or skipped")
            return EXIT_CODE_ERROR

        # Verify database setup if requested and not in dry run mode
        if args.verify and not args.dry_run:
            if not verify_database(db_config, app_user):
                logger.error("Database verification failed")
                return EXIT_CODE_ERROR

        # Apply migrations if not skipped
        if not args.skip_migrations:
            if not apply_migrations(args.env, args.dry_run, args.timeout):
                logger.error("Failed to apply database migrations")
                return EXIT_CODE_ERROR
        else:
            logger.info("Skipping database migrations")

        # Seed initial data if not schema-only
        if not args.schema_only:
            if not seed_data(args.env, args.dry_run, args.use_core_seeder, args.timeout):
                logger.error("Failed to seed database")
                return EXIT_CODE_ERROR
        else:
            logger.info("Skipping data seeding (schema-only mode)")

        logger.info(f"Database initialization for {args.env} completed successfully")

        # Track metrics if possible
        try:
            from core.metrics import increment_counter
            increment_counter('database.init.success', {'environment': args.env})
        except ImportError:
            pass

        return EXIT_CODE_SUCCESS
    except Exception as e:
        logger.error(f"Unexpected error during database initialization: {e}",
                    exc_info=True if args.verbose else False)

        # Track metrics if possible
        try:
            from core.metrics import increment_counter
            increment_counter('database.init.failure', {'environment': args.env})
        except ImportError:
            pass

        return EXIT_CODE_ERROR


if __name__ == "__main__":
    sys.exit(main())
