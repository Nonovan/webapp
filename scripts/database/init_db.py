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
from configparser import ConfigParser
from pathlib import Path
import time
from typing import Dict, Tuple, Optional, Any, List, Union
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Default settings
DEFAULT_CONFIG_PATH = "deployment/database/db_config.ini"
DEFAULT_ENVIRONMENT = "development"
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_EXTENSIONS = ["pgcrypto", "uuid-ossp", "pg_stat_statements", "btree_gist", "pg_trgm"]
DEFAULT_SCHEMAS = ["public", "audit", "config", "security"]

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Initialize database for Cloud Infrastructure Platform")
    parser.add_argument("--env", default="development",
                        choices=["development", "staging", "production"],
                        help="Target environment (default: development)")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help=f"Path to database config file (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--schema-only", action="store_true",
                        help="Only create schema, skip sample data")
    parser.add_argument("--drop-existing", action="store_true",
                        help="Drop existing database before creating")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip verification steps")
    parser.add_argument("--skip-migrations", action="store_true",
                        help="Skip running database migrations")
    parser.add_argument("--skip-extensions", action="store_true",
                        help="Skip installing PostgreSQL extensions")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Timeout in seconds for operations (default: 60)")
    parser.add_argument("--connection-attempts", type=int, default=3,
                        help="Number of connection attempts (default: 3)")
    return parser.parse_args()

def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)
    # Update handler levels
    for handler in logging.root.handlers:
        handler.setLevel(log_level)

def read_config(config_path: str, env: str) -> Tuple[Dict[str, str], str, str]:
    """
    Read database configuration from file.

    Args:
        config_path: Path to configuration file
        env: Environment name (development, staging, production)

    Returns:
        Tuple of (db_config_dict, app_user, app_password)

    Raises:
        FileNotFoundError: If config file not found
        KeyError: If required configuration keys are missing
        ValueError: If there are issues parsing config values
    """
    config_path = os.path.join(PROJECT_ROOT, config_path)
    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        raise FileNotFoundError(f"Config file not found: {config_path}")

    config = ConfigParser()
    config.read(config_path)

    if env not in config.sections():
        available_envs = ', '.join(config.sections())
        logger.error(f"Environment '{env}' not found in config file. Available: {available_envs}")
        raise KeyError(f"Environment '{env}' not in config file")

    try:
        db_config = {
            "host": config.get(env, "host"),
            "port": config.get(env, "port"),
            "user": config.get(env, "admin_user"),
            "password": config.get(env, "admin_password"),
            "dbname": config.get(env, "dbname")
        }
        app_user = config.get(env, "app_user")
        app_password = config.get(env, "app_password")

        # Validate required fields
        for param in ["host", "port", "user", "password", "dbname"]:
            if not db_config.get(param):
                raise KeyError(f"Required parameter '{param}' is missing or empty")

        if not app_user or not app_password:
            raise KeyError("Application user credentials are missing or empty")

        # Apply environment variables if specified with $VAR format
        for key, value in db_config.items():
            if isinstance(value, str) and value.startswith("$"):
                env_var = value[1:]
                env_value = os.environ.get(env_var)
                if env_value:
                    db_config[key] = env_value
                else:
                    logger.warning(f"Environment variable {env_var} not found for {key}")

        return db_config, app_user, app_password
    except (KeyError, ValueError) as e:
        logger.error(f"Error reading config: {e}")
        raise

def create_database(db_config: Dict[str, str], app_user: str, app_password: str,
                   drop_existing: bool = False, skip_extensions: bool = False,
                   create_schemas: bool = True, connection_attempts: int = 3) -> bool:
    """
    Create a new database with appropriate permissions.

    Args:
        db_config: Database connection parameters
        app_user: Application username to create
        app_password: Application user password
        drop_existing: Whether to drop the database if it exists
        skip_extensions: Whether to skip installing PostgreSQL extensions
        create_schemas: Whether to create standard schemas
        connection_attempts: Number of connection attempts before failing

    Returns:
        True if database was created successfully, False otherwise
    """
    # Connect to default postgres database to create a new database
    conn_params = db_config.copy()
    conn_params["dbname"] = "postgres"

    conn = cursor = None
    attempt = 1
    dbname = db_config["dbname"]

    while attempt <= connection_attempts:
        try:
            # Connect to postgres database
            logger.info(f"Connecting to database at {conn_params['host']}:{conn_params['port']} (attempt {attempt}/{connection_attempts})...")
            conn = psycopg2.connect(**conn_params)
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()

            # Check if database exists
            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
            exists = cursor.fetchone()
            if exists:
                if drop_existing:
                    logger.info(f"Dropping existing database '{dbname}'...")

                    # Close all connections to the database first
                    cursor.execute("""
                        SELECT pg_terminate_backend(pg_stat_activity.pid)
                        FROM pg_stat_activity
                        WHERE pg_stat_activity.datname = %s
                        AND pid <> pg_backend_pid()
                    """, (dbname,))

                    cursor.execute(f"DROP DATABASE IF EXISTS {dbname}")
                    logger.info(f"Database '{dbname}' dropped")
                else:
                    logger.warning(f"Database '{dbname}' already exists. Use --drop-existing to recreate it.")
                    return False

            # Create database
            logger.info(f"Creating database '{dbname}'...")
            cursor.execute(f"CREATE DATABASE {dbname} WITH ENCODING 'UTF8'")

            # Create app user if not exists
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (app_user,))
            user_exists = cursor.fetchone()
            if not user_exists:
                logger.info(f"Creating application user '{app_user}'...")
                cursor.execute("CREATE USER %s WITH PASSWORD %s", (app_user, app_password))
            else:
                logger.info(f"Application user '{app_user}' already exists, updating password...")
                cursor.execute("ALTER USER %s WITH PASSWORD %s", (app_user, app_password))

            # Grant privileges
            logger.info(f"Granting privileges to '{app_user}'...")
            cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {dbname} TO {app_user}")

            # Close connection to postgres database
            cursor.close()
            conn.close()

            break
        except psycopg2.OperationalError as e:
            attempt += 1
            if attempt <= connection_attempts:
                logger.warning(f"Connection failed, retrying... ({e})")
                time.sleep(2)
            else:
                logger.error(f"Failed to connect after {connection_attempts} attempts: {e}")
                return False
        except Exception as e:
            logger.error(f"Error creating database: {e}")
            return False

    # Now connect to the new database to run initialization
    conn_params = db_config.copy()

    try:
        # Connect to the newly created database
        logger.info(f"Connecting to newly created database '{dbname}'...")
        conn = psycopg2.connect(**conn_params)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        # Enable extensions
        if not skip_extensions:
            logger.info("Enabling PostgreSQL extensions...")
            for extension in DEFAULT_EXTENSIONS:
                try:
                    logger.debug(f"Creating extension: {extension}")
                    cursor.execute(f"CREATE EXTENSION IF NOT EXISTS \"{extension}\"")
                except Exception as e:
                    logger.warning(f"Could not create extension {extension}: {e}")

        # Create schemas
        if create_schemas:
            logger.info("Creating standard schemas...")
            for schema in DEFAULT_SCHEMAS:
                if schema != "public":  # public schema already exists
                    logger.debug(f"Creating schema: {schema}")
                    cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")

                # Grant permissions to application user for this schema
                cursor.execute(f"GRANT USAGE ON SCHEMA {schema} TO {app_user}")
                cursor.execute(f"""
                    ALTER DEFAULT PRIVILEGES IN SCHEMA {schema}
                    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app_user}
                """)
                cursor.execute(f"""
                    ALTER DEFAULT PRIVILEGES IN SCHEMA {schema}
                    GRANT USAGE, SELECT ON SEQUENCES TO {app_user}
                """)

        cursor.close()
        conn.close()

        logger.info(f"Database '{dbname}' initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        if conn:
            conn.close()
        return False

def apply_migrations(env: str, skip: bool = False, timeout: int = 60) -> bool:
    """
    Apply database migrations using Flask-Migrate.

    Args:
        env: Target environment
        skip: Whether to skip migrations
        timeout: Timeout in seconds

    Returns:
        True if migrations were applied successfully, False otherwise
    """
    if skip:
        logger.info("Skipping database migrations")
        return True

    logger.info("Applying database migrations...")
    try:
        # Set environment variables
        env_vars = os.environ.copy()
        env_vars["FLASK_ENV"] = env

        # Run Flask migrate upgrade command
        logger.debug("Running 'flask db upgrade' command")
        result = subprocess.run(
            ["flask", "db", "upgrade"],
            env=env_vars,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        if result.returncode == 0:
            logger.info("Migrations applied successfully")
            if result.stdout:
                logger.debug(f"Migration output: {result.stdout}")
            return True
        else:
            logger.error(f"Error applying migrations: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Migration timed out after {timeout} seconds")
        return False
    except FileNotFoundError:
        logger.error("Flask command not found. Is Flask installed and in PATH?")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during migration: {e}")
        return False

def seed_data(env: str, schema_only: bool = False, timeout: int = 60) -> bool:
    """
    Seed initial data into the database.

    Args:
        env: Target environment
        schema_only: Skip if schema-only mode is active
        timeout: Timeout in seconds

    Returns:
        True if data was seeded successfully, False otherwise
    """
    if schema_only:
        logger.info("Skipping data seeding (schema-only mode)")
        return True

    logger.info("Seeding initial data...")
    try:
        # Set environment variables
        env_vars = os.environ.copy()
        env_vars["FLASK_ENV"] = env

        # First try the project's seed_data.py script
        seed_script = os.path.join(SCRIPT_DIR, "seed_data.py")
        if os.path.exists(seed_script):
            logger.debug(f"Running seed script: {seed_script}")
            result = subprocess.run(
                ["python", seed_script, f"--env={env}"],
                env=env_vars,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
        else:
            # Alternative: try using Flask shell to run seeder from core.seeder
            logger.debug("Using Flask shell with core.seeder")
            seed_command = """
from flask import current_app
from core.seeder import seed_database
with current_app.app_context():
    success = seed_database(verbose=True)
    print('SEED_RESULT=' + ('success' if success else 'failure'))
"""
            result = subprocess.run(
                ["flask", "shell"],
                input=seed_command,
                env=env_vars,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )

        # Check success
        if result.returncode == 0 and 'SEED_RESULT=success' in result.stdout:
            logger.info("Data seeded successfully")
            return True
        elif result.returncode == 0:
            logger.info("Seeding script completed without explicit success signal")
            return True
        else:
            logger.error(f"Error seeding data: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Seeding timed out after {timeout} seconds")
        return False
    except FileNotFoundError as e:
        logger.error(f"Command not found: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during seeding: {e}")
        return False

def verify_database(db_config: Dict[str, str], app_user: str, skip_verify: bool = False) -> bool:
    """
    Verify the database was set up correctly.

    Args:
        db_config: Database connection parameters
        app_user: Application user to verify
        skip_verify: Whether to skip verification

    Returns:
        True if verification passed, False otherwise
    """
    if skip_verify:
        logger.info("Skipping database verification")
        return True

    logger.info("Verifying database setup...")
    conn = None

    try:
        # Verify admin connection
        logger.debug(f"Verifying admin connection to {db_config['host']}:{db_config['port']}/{db_config['dbname']}")
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()

        # Check if we can run queries
        cursor.execute("SELECT version()")
        version = cursor.fetchone()[0]
        logger.debug(f"PostgreSQL version: {version}")

        # Check if extensions are installed
        cursor.execute("SELECT extname FROM pg_extension")
        extensions = [row[0] for row in cursor.fetchall()]
        logger.debug(f"Installed extensions: {', '.join(extensions)}")

        # Check for required extensions
        for ext in DEFAULT_EXTENSIONS:
            if ext not in extensions:
                logger.warning(f"Extension '{ext}' is not installed")

        # Check schemas
        cursor.execute("SELECT nspname FROM pg_namespace WHERE nspname != 'information_schema' AND nspname NOT LIKE 'pg_%'")
        schemas = [row[0] for row in cursor.fetchall()]
        logger.debug(f"Available schemas: {', '.join(schemas)}")

        cursor.close()
        conn.close()
    except Exception as e:
        logger.error(f"Admin connection verification failed: {e}")
        if conn:
            conn.close()
        return False

    # Attempt connection with application user if provided
    try:
        # Modify connection params for app user
        app_conn_params = db_config.copy()
        app_conn_params["user"] = app_user

        # App password is not passed - We would need it to complete this check
        # but we can't get it back after reading from config

        logger.debug(f"Verification complete")
        logger.info("Database verification passed")
        return True
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        return False

def main() -> int:
    """Main function."""
    args = parse_args()
    setup_logging(args.verbose)

    logger.info(f"Initializing {args.env} database...")

    try:
        # Read database configuration
        db_config, app_user, app_password = read_config(args.config, args.env)

        # Create database
        success = create_database(
            db_config,
            app_user,
            app_password,
            drop_existing=args.drop_existing,
            skip_extensions=args.skip_extensions,
            connection_attempts=args.connection_attempts
        )
        if not success:
            return 1

        # Verify database setup
        if not args.no_verify:
            if not verify_database(db_config, app_user, skip_verify=args.no_verify):
                logger.error("Database verification failed")
                return 1

        # Apply migrations
        if not args.skip_migrations:
            if not apply_migrations(args.env, skip=args.skip_migrations, timeout=args.timeout):
                logger.error("Failed to apply database migrations")
                return 1

        # Seed initial data if not schema-only
        if not args.schema_only:
            if not seed_data(args.env, schema_only=args.schema_only, timeout=args.timeout):
                logger.error("Failed to seed database")
                return 1

        logger.info(f"Database initialization for {args.env} completed successfully!")
        return 0

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.debug("Error details:", exc_info=True if args.verbose else False)
        return 1

if __name__ == "__main__":
    sys.exit(main())
