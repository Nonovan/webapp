"""
Database migration utilities for Cloud Infrastructure Platform.

This module provides functions for managing database migrations, including
verification, generation, application, and rollback of migrations. It works
with Flask-Migrate (Alembic) to ensure proper schema versioning and evolution
across different environments.
"""

import os
import sys
import logging
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union

# Set up logging
logger = logging.getLogger(__name__)

# Try to import constants from db_constants
try:
    from .db_constants import (
        ENVIRONMENTS, DEFAULT_ENVIRONMENT, DEFAULT_CONFIG_PATH,
        EXIT_CODE_SUCCESS, EXIT_CODE_ERROR
    )
except ImportError:
    # Define minimal constants if db_constants.py is not available
    ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]
    DEFAULT_ENVIRONMENT = "development"
    DEFAULT_CONFIG_PATH = "deployment/database/db_config.ini"
    EXIT_CODE_SUCCESS = 0
    EXIT_CODE_ERROR = 1


def verify_migrations(
    env: str = DEFAULT_ENVIRONMENT,
    verbose: bool = False,
    timeout: int = 60
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify that migrations are in sync with models.

    Checks if there are any model changes that need migration files.
    This helps detect when models have been modified without generating
    corresponding migration files.

    Args:
        env: Target environment
        verbose: Whether to enable verbose output
        timeout: Command timeout in seconds

    Returns:
        Tuple of (is_sync, details) where:
        - is_sync: True if migrations are in sync with models, False otherwise
        - details: Dictionary with verification details
    """
    logger.info(f"Verifying migrations for {env} environment")
    start_time = time.time()

    env_vars = os.environ.copy()
    env_vars["FLASK_ENV"] = env

    result = {
        "is_sync": True,
        "pending_models": [],
        "pending_migrations": [],
        "head_revision": None,
        "current_revision": None,
        "error": None
    }

    try:
        # Check current and head revisions
        cmd_output = subprocess.run(
            ["flask", "db", "current", "--verbose"],
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        # Parse current revision from output
        for line in cmd_output.stdout.splitlines():
            if "current revision" in line.lower():
                parts = line.split()
                if parts and len(parts) >= 3:
                    result["current_revision"] = parts[-1].strip()
                break

        # Get head revision
        cmd_output = subprocess.run(
            ["flask", "db", "heads"],
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        if cmd_output.stdout.strip():
            result["head_revision"] = cmd_output.stdout.strip()

        # Check if there are pending migrations to apply
        cmd_output = subprocess.run(
            ["flask", "db", "check"],
            capture_output=True,
            text=True,
            check=False,  # Don't raise on non-zero exit
            env=env_vars,
            timeout=timeout
        )

        # Parse output to check if migrations need to be applied
        if "Your database is up to date" not in cmd_output.stdout:
            result["is_sync"] = False
            result["pending_migrations"] = True

        # Check if model changes need migration files
        # Create a temporary migration script to detect changes
        with tempfile.NamedTemporaryFile(suffix='.py') as tmp:
            cmd_output = subprocess.run(
                ["flask", "db", "migrate", "-m", "temp_check", "--output-file", tmp.name],
                capture_output=True,
                text=True,
                check=False,
                env=env_vars,
                timeout=timeout
            )

            # If changes were detected, there would be migration commands in the file
            content = tmp.read().decode('utf-8')
            if "op.create_table" in content or "op.add_column" in content or "op.drop_" in content:
                result["is_sync"] = False
                result["pending_models"] = True

        if verbose:
            if result["is_sync"]:
                logger.info("Models and migrations are in sync")
            else:
                if result["pending_models"]:
                    logger.warning("Model changes detected that need migration files")
                if result["pending_migrations"]:
                    logger.warning("Pending migrations need to be applied to database")

        return result["is_sync"], result

    except subprocess.TimeoutExpired:
        error_msg = f"Migration verification timed out after {timeout} seconds"
        logger.error(error_msg)
        result["error"] = error_msg
        result["is_sync"] = False
        return False, result

    except subprocess.CalledProcessError as e:
        error_msg = f"Error checking migrations: {str(e)}"
        if e.stderr:
            error_msg += f"\n{e.stderr}"
        logger.error(error_msg)
        result["error"] = error_msg
        result["is_sync"] = False
        return False, result

    except Exception as e:
        error_msg = f"Unexpected error during migration verification: {str(e)}"
        logger.error(error_msg)
        result["error"] = error_msg
        result["is_sync"] = False
        return False, result


def generate_migration_script(
    message: str,
    env: str = DEFAULT_ENVIRONMENT,
    autogenerate: bool = True,
    sql: bool = False,
    head: str = "head",
    verbose: bool = False,
    timeout: int = 60
) -> Tuple[bool, Optional[str]]:
    """
    Generate a new database migration script.

    Creates a new migration script based on model changes (if autogenerate=True)
    or creates an empty migration script (if autogenerate=False).

    Args:
        message: Description message for the migration
        env: Target environment
        autogenerate: Whether to autogenerate migration based on model changes
        sql: Whether to generate SQL statements instead of a Python script
        head: Migration head reference
        verbose: Whether to enable verbose output
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, filename) where:
        - success: True if migration script was generated, False otherwise
        - filename: Path to the generated migration file (or None if failed)
    """
    logger.info(f"Generating migration script: {message}")
    start_time = time.time()

    env_vars = os.environ.copy()
    env_vars["FLASK_ENV"] = env

    # Prepare command
    cmd = ["flask", "db", "migrate" if autogenerate else "revision"]

    # Add message
    if message:
        cmd.extend(["-m", message])

    # Add other options
    if sql:
        cmd.append("--sql")

    if head and head != "head":
        cmd.extend(["--head", head])

    if verbose:
        cmd.append("--verbose")

    try:
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        # Extract filename from output
        filename = None
        for line in output.stdout.splitlines():
            if "Generating" in line and ".py" in line:
                # Extract path from line like "Generating /path/to/migrations/versions/abcdef123456_message.py"
                parts = line.split(" ")
                for part in parts:
                    if part.endswith(".py"):
                        filename = part
                        break

        if not filename and not sql:
            logger.warning("Migration script generated but couldn't extract filename from output")

        if verbose:
            logger.info(output.stdout)

        if filename:
            logger.info(f"Migration script generated: {filename}")
            return True, filename
        else:
            logger.info("Migration script generated successfully")
            return True, None

    except subprocess.TimeoutExpired:
        logger.error(f"Migration generation timed out after {timeout} seconds")
        return False, None

    except subprocess.CalledProcessError as e:
        logger.error(f"Error generating migration: {e}")
        if e.stdout:
            logger.info(f"Output: {e.stdout}")
        if e.stderr:
            logger.error(f"Error: {e.stderr}")
        return False, None

    except Exception as e:
        logger.error(f"Unexpected error generating migration: {e}")
        return False, None


def apply_migration(
    revision: str = "head",
    env: str = DEFAULT_ENVIRONMENT,
    sql: bool = False,
    tag: Optional[str] = None,
    verbose: bool = False,
    dry_run: bool = False,
    timeout: int = 180
) -> bool:
    """
    Apply database migrations up to the specified revision.

    Args:
        revision: Target revision to upgrade to (default: "head" for latest)
        env: Target environment
        sql: Whether to output SQL instead of executing migration
        tag: Optional tag to apply to the database version
        verbose: Whether to enable verbose output
        dry_run: If True, don't actually apply migrations
        timeout: Command timeout in seconds

    Returns:
        True if migrations were applied successfully, False otherwise
    """
    if dry_run:
        logger.info(f"[DRY RUN] Would apply migrations up to revision: {revision}")
        return True

    logger.info(f"Applying migrations up to revision: {revision}")
    start_time = time.time()

    env_vars = os.environ.copy()
    env_vars["FLASK_ENV"] = env

    # Prepare command
    cmd = ["flask", "db", "upgrade", revision]

    # Add other options
    if sql:
        cmd.append("--sql")

    if tag:
        cmd.extend(["--tag", tag])

    if verbose:
        cmd.append("--verbose")

    try:
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        if verbose and output.stdout:
            logger.info(output.stdout)

        logger.info(f"Migrations applied successfully (revision: {revision})")
        return True

    except subprocess.TimeoutExpired:
        logger.error(f"Migration application timed out after {timeout} seconds")
        return False

    except subprocess.CalledProcessError as e:
        logger.error(f"Error applying migrations: {e}")
        if e.stdout:
            logger.info(f"Output: {e.stdout}")
        if e.stderr:
            logger.error(f"Error: {e.stderr}")
        return False

    except Exception as e:
        logger.error(f"Unexpected error applying migrations: {e}")
        return False


def rollback_migration(
    revision: str,
    env: str = DEFAULT_ENVIRONMENT,
    sql: bool = False,
    tag: Optional[str] = None,
    verbose: bool = False,
    dry_run: bool = False,
    timeout: int = 180
) -> bool:
    """
    Roll back database migrations to the specified revision.

    Args:
        revision: Target revision to downgrade to (e.g., "-1" for one migration back)
        env: Target environment
        sql: Whether to output SQL instead of executing rollback
        tag: Optional tag to apply to the database version
        verbose: Whether to enable verbose output
        dry_run: If True, don't actually roll back migrations
        timeout: Command timeout in seconds

    Returns:
        True if migrations were rolled back successfully, False otherwise
    """
    if dry_run:
        logger.info(f"[DRY RUN] Would roll back migrations to revision: {revision}")
        return True

    logger.info(f"Rolling back migrations to revision: {revision}")
    start_time = time.time()

    env_vars = os.environ.copy()
    env_vars["FLASK_ENV"] = env

    # Prepare command
    cmd = ["flask", "db", "downgrade", revision]

    # Add other options
    if sql:
        cmd.append("--sql")

    if tag:
        cmd.extend(["--tag", tag])

    if verbose:
        cmd.append("--verbose")

    try:
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        if verbose and output.stdout:
            logger.info(output.stdout)

        logger.info(f"Migrations rolled back successfully (revision: {revision})")
        return True

    except subprocess.TimeoutExpired:
        logger.error(f"Migration rollback timed out after {timeout} seconds")
        return False

    except subprocess.CalledProcessError as e:
        logger.error(f"Error rolling back migrations: {e}")
        if e.stdout:
            logger.info(f"Output: {e.stdout}")
        if e.stderr:
            logger.error(f"Error: {e.stderr}")
        return False

    except Exception as e:
        logger.error(f"Unexpected error rolling back migrations: {e}")
        return False


def get_migration_history(
    env: str = DEFAULT_ENVIRONMENT,
    verbose: bool = False,
    timeout: int = 60
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Get the history of applied migrations.

    Args:
        env: Target environment
        verbose: Whether to enable verbose output
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, history) where:
        - success: True if history was retrieved successfully, False otherwise
        - history: List of dictionaries with migration information
    """
    logger.info(f"Retrieving migration history for {env} environment")

    env_vars = os.environ.copy()
    env_vars["FLASK_ENV"] = env

    try:
        output = subprocess.run(
            ["flask", "db", "history", "--verbose"],
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        history = []
        current_entry = None

        # Parse output to extract migration history
        for line in output.stdout.splitlines():
            line = line.strip()

            if line.startswith("Rev: "):
                # Start a new entry
                if current_entry:
                    history.append(current_entry)

                revision = line.replace("Rev: ", "").strip()
                current_entry = {"revision": revision}

            elif line.startswith("Parent: "):
                if current_entry:
                    current_entry["parent"] = line.replace("Parent: ", "").strip()

            elif line.startswith("Path: "):
                if current_entry:
                    current_entry["path"] = line.replace("Path: ", "").strip()

            elif line.startswith("Date: "):
                if current_entry:
                    date_str = line.replace("Date: ", "").strip()
                    current_entry["date"] = date_str

            elif line.startswith("Message: "):
                if current_entry:
                    current_entry["message"] = line.replace("Message: ", "").strip()

        # Add the last entry
        if current_entry:
            history.append(current_entry)

        if verbose:
            logger.info(f"Retrieved {len(history)} migration entries")

        return True, history

    except subprocess.TimeoutExpired:
        logger.error(f"Migration history retrieval timed out after {timeout} seconds")
        return False, []

    except subprocess.CalledProcessError as e:
        logger.error(f"Error retrieving migration history: {e}")
        if e.stderr:
            logger.error(f"Error: {e.stderr}")
        return False, []

    except Exception as e:
        logger.error(f"Unexpected error retrieving migration history: {e}")
        return False, []


def stamp_database_revision(
    revision: str,
    env: str = DEFAULT_ENVIRONMENT,
    sql: bool = False,
    verbose: bool = False,
    dry_run: bool = False,
    timeout: int = 60
) -> bool:
    """
    Set the database revision without running migrations.

    This is useful for marking a database as being at a specific revision
    without actually running migrations, typically used after manual changes
    or when resolving migration issues.

    Args:
        revision: Target revision to stamp the database with
        env: Target environment
        sql: Whether to output SQL instead of executing the command
        verbose: Whether to enable verbose output
        dry_run: If True, don't actually stamp the database
        timeout: Command timeout in seconds

    Returns:
        True if database was stamped successfully, False otherwise
    """
    if dry_run:
        logger.info(f"[DRY RUN] Would stamp database at revision: {revision}")
        return True

    logger.info(f"Stamping database at revision: {revision}")

    env_vars = os.environ.copy()
    env_vars["FLASK_ENV"] = env

    # Prepare command
    cmd = ["flask", "db", "stamp", revision]

    # Add other options
    if sql:
        cmd.append("--sql")

    if verbose:
        cmd.append("--verbose")

    try:
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        if verbose and output.stdout:
            logger.info(output.stdout)

        logger.info(f"Database stamped successfully at revision: {revision}")
        return True

    except subprocess.TimeoutExpired:
        logger.error(f"Database stamping timed out after {timeout} seconds")
        return False

    except subprocess.CalledProcessError as e:
        logger.error(f"Error stamping database: {e}")
        if e.stdout:
            logger.info(f"Output: {e.stdout}")
        if e.stderr:
            logger.error(f"Error: {e.stderr}")
        return False

    except Exception as e:
        logger.error(f"Unexpected error stamping database: {e}")
        return False


def merge_migration_heads(
    message: str,
    env: str = DEFAULT_ENVIRONMENT,
    verbose: bool = False,
    timeout: int = 60
) -> Tuple[bool, Optional[str]]:
    """
    Merge multiple migration heads into a single revision.

    This is used when there are multiple heads in the migration tree,
    typically after branches were merged in version control.

    Args:
        message: Description message for the merge migration
        env: Target environment
        verbose: Whether to enable verbose output
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, filename) where:
        - success: True if heads were merged successfully, False otherwise
        - filename: Path to the generated merge migration file (or None if failed)
    """
    logger.info(f"Merging migration heads with message: {message}")

    env_vars = os.environ.copy()
    env_vars["FLASK_ENV"] = env

    # Prepare command
    cmd = ["flask", "db", "merge"]

    # Add message
    if message:
        cmd.extend(["-m", message])

    if verbose:
        cmd.append("--verbose")

    try:
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        # Extract filename from output
        filename = None
        for line in output.stdout.splitlines():
            if "Generating" in line and ".py" in line:
                # Extract path from line like "Generating /path/to/migrations/versions/abcdef123456_message.py"
                parts = line.split(" ")
                for part in parts:
                    if part.endswith(".py"):
                        filename = part
                        break

        if not filename:
            logger.warning("Merge migration created but couldn't extract filename from output")

        if verbose:
            logger.info(output.stdout)

        if filename:
            logger.info(f"Merge migration generated: {filename}")
            return True, filename
        else:
            logger.info("Merge migration generated successfully")
            return True, None

    except subprocess.TimeoutExpired:
        logger.error(f"Migration merge timed out after {timeout} seconds")
        return False, None

    except subprocess.CalledProcessError as e:
        logger.error(f"Error merging migration heads: {e}")
        if e.stdout:
            logger.info(f"Output: {e.stdout}")
        if e.stderr:
            logger.error(f"Error: {e.stderr}")
        return False, None

    except Exception as e:
        logger.error(f"Unexpected error merging migration heads: {e}")
        return False, None


def check_migration_script(
    filepath: str,
    verbose: bool = False
) -> bool:
    """
    Check if a migration script has both upgrade and downgrade operations.

    This validates that a migration script is properly implemented with
    both upgrade and downgrade operations.

    Args:
        filepath: Path to the migration script file
        verbose: Whether to enable verbose output

    Returns:
        True if the migration script has both upgrade and downgrade operations,
        False otherwise
    """
    filepath = Path(filepath)

    if not filepath.exists():
        logger.error(f"Migration file not found: {filepath}")
        return False

    try:
        with open(filepath, 'r') as f:
            content = f.read()

        # Check for upgrade and downgrade operations
        has_upgrade = "def upgrade(" in content or "def upgrade():" in content
        has_downgrade = "def downgrade(" in content or "def downgrade():" in content

        if has_upgrade and has_downgrade:
            if verbose:
                logger.info(f"Migration script {filepath} has both upgrade and downgrade operations")
            return True
        else:
            missing = []
            if not has_upgrade:
                missing.append("upgrade")
            if not has_downgrade:
                missing.append("downgrade")

            logger.warning(f"Migration script {filepath} is missing {', '.join(missing)} operation(s)")
            return False

    except Exception as e:
        logger.error(f"Error checking migration script {filepath}: {e}")
        return False


# Additional utility functions

def get_current_migration_revision(
    env: str = DEFAULT_ENVIRONMENT,
    verbose: bool = False,
    timeout: int = 30
) -> Tuple[bool, Optional[str]]:
    """
    Get the current migration revision of the database.

    Args:
        env: Target environment
        verbose: Whether to enable verbose output
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, revision) where:
        - success: True if revision was retrieved successfully, False otherwise
        - revision: The current revision string or None if not available
    """
    logger.info(f"Getting current migration revision for {env} environment")

    env_vars = os.environ.copy()
    env_vars["FLASK_ENV"] = env

    try:
        output = subprocess.run(
            ["flask", "db", "current"],
            capture_output=True,
            text=True,
            check=True,
            env=env_vars,
            timeout=timeout
        )

        revision = output.stdout.strip()

        if not revision:
            logger.warning("No current revision found (database may be at base state)")
            return True, None

        if verbose:
            logger.info(f"Current revision: {revision}")

        return True, revision

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds")
        return False, None

    except subprocess.CalledProcessError as e:
        logger.error(f"Error getting current revision: {e}")
        if e.stderr:
            logger.error(f"Error: {e.stderr}")
        return False, None

    except Exception as e:
        logger.error(f"Unexpected error getting current revision: {e}")
        return False, None


def create_initial_migration(
    message: str = "initial_schema",
    env: str = DEFAULT_ENVIRONMENT,
    verbose: bool = False,
    timeout: int = 60
) -> Tuple[bool, Optional[str]]:
    """
    Create an initial migration for a new database.

    This creates a migration script that establishes the initial schema.

    Args:
        message: Description message for the initial migration
        env: Target environment
        verbose: Whether to enable verbose output
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, filename) where:
        - success: True if migration was created successfully, False otherwise
        - filename: Path to the generated migration file (or None if failed)
    """
    return generate_migration_script(
        message=message,
        env=env,
        autogenerate=True,
        verbose=verbose,
        timeout=timeout
    )


# Module exports - these should match what's imported in __init__.py
__all__ = [
    "verify_migrations",
    "generate_migration_script",
    "apply_migration",
    "rollback_migration",
    "get_migration_history",
    "stamp_database_revision",
    "merge_migration_heads",
    "check_migration_script",
    "get_current_migration_revision",
    "create_initial_migration"
]
