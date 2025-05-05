"""
Database maintenance utilities for Cloud Infrastructure Platform.

This module provides functions for maintaining optimal database performance
through regular maintenance operations such as vacuum, analyze, reindexing,
connection management, and monitoring. It supports the various environments
(development, staging, production, dr-recovery) with appropriate settings.
"""

import os
import sys
import logging
import time
import datetime
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional, Union
import psycopg2
from psycopg2.extras import DictCursor

# Try to import database constants
try:
    from .db_constants import (
        ENVIRONMENTS, DEFAULT_ENVIRONMENT, DEFAULT_CONFIG_PATH,
        DEFAULT_CONNECTION_PARAMS, MAINTENANCE_SETTINGS, DB_METRICS,
        EXIT_CODE_SUCCESS, EXIT_CODE_ERROR
    )
    from .init_db import read_config
except ImportError:
    # Fallback to minimal constants if db_constants.py is not available
    ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]
    DEFAULT_ENVIRONMENT = "development"
    DEFAULT_CONFIG_PATH = "deployment/database/db_config.ini"
    EXIT_CODE_SUCCESS = 0
    EXIT_CODE_ERROR = 1
    MAINTENANCE_SETTINGS = {
        "vacuum_threshold": 20,              # Vacuum when >20% of tuples are dead
        "analyze_threshold": 10,             # Analyze when >10% of tuples have changed
        "index_bloat_threshold": 30,         # Reindex when bloat >30%
        "max_connection_percent": 80,        # Alert when connections >80% of max
        "max_transaction_age": 30 * 60,      # Alert for transactions running >30 minutes
        "max_idle_transaction_age": 5 * 60   # Alert for idle transactions >5 minutes
    }
    DEFAULT_CONNECTION_PARAMS = {}
    DB_METRICS = [
        "active_connections",
        "transaction_rate",
        "cache_hit_ratio",
        "index_usage",
        "table_size",
        "slow_queries",
        "deadlocks"
    ]

    # Define minimal read_config function if not imported
    def read_config(config_path: str, env: str) -> Tuple[Dict[str, str], str, str]:
        """Minimal implementation of read_config."""
        raise NotImplementedError("db_constants.py not found and read_config not available")

# Configure logging
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("database-maintenance")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Database maintenance operations for Cloud Infrastructure Platform")
    parser.add_argument("--env", choices=ENVIRONMENTS, default=DEFAULT_ENVIRONMENT,
                        help=f"Target environment (default: {DEFAULT_ENVIRONMENT})")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help=f"Path to database config file (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--action", choices=["optimize", "vacuum", "analyze", "reindex", "monitor", "check-bloat"],
                        default="optimize", help="Maintenance action to perform (default: optimize)")
    parser.add_argument("--table", help="Specific table to maintain (default: all tables)")
    parser.add_argument("--schema", help="Specific schema to maintain (default: all schemas)")
    parser.add_argument("--vacuum-mode", choices=["full", "analyze", "standard"], default="standard",
                        help="Type of vacuum to perform (default: standard)")
    parser.add_argument("--threshold", type=float,
                        help="Override the default threshold for the selected operation")
    parser.add_argument("--apply", action="store_true", help="Actually perform the maintenance, not just report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--log-file", help="Path to log file (default: None, console only)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Operation timeout in seconds (default: 3600)")
    return parser.parse_args()


def setup_file_logging(log_file: Optional[str] = None, verbose: bool = False) -> None:
    """
    Set up file logging in addition to console logging.

    Args:
        log_file: Path to log file, uses default if None
        verbose: Whether to enable debug logging
    """
    if verbose:
        logger.setLevel(logging.DEBUG)

    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                "%Y-%m-%d %H:%M:%S"
            ))
            logger.addHandler(file_handler)
            logger.debug(f"File logging enabled at {log_file}")
        except Exception as e:
            logger.warning(f"Could not set up file logging: {e}")


def connect_to_database(
    db_config: Dict[str, str],
    maintenance_mode: bool = False
) -> Tuple[Optional[Any], Optional[Any]]:
    """
    Connect to database with appropriate settings for maintenance operations.

    Args:
        db_config: Database connection parameters
        maintenance_mode: Set maintenance work memory if True

    Returns:
        Tuple of (connection, cursor) or (None, None) if connection fails
    """
    try:
        # Add application name for monitoring purposes
        conn_params = db_config.copy()
        if "application_name" not in conn_params:
            conn_params["application_name"] = "cloud_platform_maintenance"

        conn = psycopg2.connect(**conn_params)

        # Set autocommit for maintenance operations
        conn.set_session(autocommit=True)

        # Create cursor that returns dictionaries
        cursor = conn.cursor(cursor_factory=DictCursor)

        # Set maintenance work memory if in maintenance mode
        if maintenance_mode:
            # Calculate appropriate maintenance work memory - 10% of system memory up to 1GB
            try:
                cursor.execute("SHOW maintenance_work_mem")
                current_mem = cursor.fetchone()[0]
                logger.debug(f"Current maintenance_work_mem: {current_mem}")

                # For actual maintenance, try to set higher value for better performance
                # This is per session only, won't affect other connections
                cursor.execute("SET maintenance_work_mem = '256MB'")
            except Exception as e:
                logger.warning(f"Could not optimize maintenance_work_mem: {e}")

        return conn, cursor
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return None, None


def optimize_database(
    db_config: Dict[str, str],
    vacuum_mode: str = "standard",
    schema: Optional[str] = None,
    table: Optional[str] = None,
    apply: bool = False,
    verbose: bool = False,
    vacuum_threshold: float = MAINTENANCE_SETTINGS["vacuum_threshold"],
    analyze_threshold: float = MAINTENANCE_SETTINGS["analyze_threshold"],
    bloat_threshold: float = MAINTENANCE_SETTINGS["index_bloat_threshold"]
) -> Dict[str, Any]:
    """
    Perform optimizations on the database based on current state.

    This function inspects table statistics and performs necessary maintenance
    operations (vacuum, analyze, reindex) based on thresholds.

    Args:
        db_config: Database connection parameters
        vacuum_mode: Type of vacuum to perform ('standard', 'full', or 'analyze')
        schema: Specific schema to optimize (None for all schemas)
        table: Specific table to optimize (None for all tables)
        apply: Actually perform optimization instead of just reporting
        verbose: Whether to show detailed information
        vacuum_threshold: Dead tuple percentage threshold for vacuum
        analyze_threshold: Modified tuple percentage threshold for analyze
        bloat_threshold: Bloat percentage threshold for reindexing

    Returns:
        Dictionary with optimization results
    """
    result = {
        "started_at": datetime.datetime.now().isoformat(),
        "operations": {
            "vacuum": [],
            "analyze": [],
            "reindex": []
        },
        "tables_checked": 0,
        "tables_needing_vacuum": 0,
        "tables_needing_analyze": 0,
        "indexes_needing_reindex": 0,
        "operations_performed": 0,
        "success": False,
        "errors": []
    }

    logger.info(f"Starting database optimization in {('reporting' if not apply else 'apply')} mode")

    # Connect to database in maintenance mode
    conn, cursor = connect_to_database(db_config, maintenance_mode=apply)
    if not conn or not cursor:
        result["errors"].append("Failed to connect to database")
        return result

    try:
        # Check for tables needing vacuum or analyze
        schema_filter = f"AND n.nspname = '{schema}'" if schema else ""
        table_filter = f"AND c.relname = '{table}'" if table else ""

        query = """
        SELECT
            n.nspname AS schema,
            c.relname AS table_name,
            c.reltuples AS estimated_rows,
            CASE WHEN c.reltuples > 0
                THEN ROUND(100.0 * s.n_dead_tup / c.reltuples, 1)
                ELSE 0
            END AS dead_tuple_percent,
            CASE WHEN c.reltuples > 0
                THEN ROUND(100.0 * s.n_mod_since_analyze / c.reltuples, 1)
                ELSE 0
            END AS modified_tuple_percent,
            pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
            s.last_vacuum,
            s.last_analyze
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        LEFT JOIN pg_stat_all_tables s ON c.oid = s.relid
        WHERE c.relkind = 'r'  -- Only regular tables
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {0}
          {1}
        ORDER BY dead_tuple_percent DESC, modified_tuple_percent DESC
        """.format(schema_filter, table_filter)

        cursor.execute(query)
        tables = cursor.fetchall()

        result["tables_checked"] = len(tables)

        if verbose:
            logger.info(f"Checking {len(tables)} tables for optimization needs")

        # Process each table
        for tbl in tables:
            table_id = f"{tbl['schema']}.{tbl['table_name']}"
            need_vacuum = tbl["dead_tuple_percent"] >= vacuum_threshold
            need_analyze = tbl["modified_tuple_percent"] >= analyze_threshold

            # Check if this table needs vacuum
            if need_vacuum:
                result["tables_needing_vacuum"] += 1
                operation = {
                    "schema": tbl["schema"],
                    "table": tbl["table_name"],
                    "dead_tuple_percent": tbl["dead_tuple_percent"],
                    "size": tbl["table_size"],
                    "performed": False
                }

                if apply:
                    logger.info(f"Vacuuming table {table_id} ({tbl['dead_tuple_percent']}% dead tuples)")
                    try:
                        if vacuum_mode == "full":
                            cursor.execute(f"VACUUM FULL {table_id}")
                        elif vacuum_mode == "analyze":
                            cursor.execute(f"VACUUM ANALYZE {table_id}")
                        else:  # standard
                            cursor.execute(f"VACUUM {table_id}")

                        operation["performed"] = True
                        result["operations_performed"] += 1
                    except Exception as e:
                        error_msg = f"Error vacuuming {table_id}: {str(e)}"
                        logger.error(error_msg)
                        operation["error"] = error_msg
                        result["errors"].append(error_msg)
                else:
                    logger.info(f"Table {table_id} needs vacuum ({tbl['dead_tuple_percent']}% dead tuples)")

                result["operations"]["vacuum"].append(operation)

            # Check if this table needs analyze (and wasn't already analyzed during vacuum)
            if need_analyze and (not need_vacuum or vacuum_mode != "analyze"):
                result["tables_needing_analyze"] += 1
                operation = {
                    "schema": tbl["schema"],
                    "table": tbl["table_name"],
                    "modified_tuple_percent": tbl["modified_tuple_percent"],
                    "performed": False
                }

                if apply:
                    logger.info(f"Analyzing table {table_id} ({tbl['modified_tuple_percent']}% modified tuples)")
                    try:
                        cursor.execute(f"ANALYZE {table_id}")
                        operation["performed"] = True
                        result["operations_performed"] += 1
                    except Exception as e:
                        error_msg = f"Error analyzing {table_id}: {str(e)}"
                        logger.error(error_msg)
                        operation["error"] = error_msg
                        result["errors"].append(error_msg)
                else:
                    logger.info(f"Table {table_id} needs analyze ({tbl['modified_tuple_percent']}% modified tuples)")

                result["operations"]["analyze"].append(operation)

        # Check for bloated indexes if no specific table is provided
        if not table:
            # Query to find bloated indexes
            index_query = """
            SELECT
                schemaname,
                tablename,
                indexname,
                pg_size_pretty(pg_relation_size(indexrelid::regclass)) AS index_size,
                CASE WHEN idx_scan = 0 THEN 'Unused'
                     WHEN (100 * idx_scan / GREATEST(seq_scan + idx_scan, 1))::real < 5 THEN 'Rarely Used'
                     ELSE 'OK'
                END AS usage_status,
                round((100 * pg_relation_size(indexrelid)::numeric /
                       GREATEST(pg_relation_size(indrelid), 1))::numeric, 1) AS size_ratio
            FROM pg_stat_all_indexes
            JOIN pg_index ON pg_index.indexrelid = pg_stat_all_indexes.indexrelid
            WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
              AND pg_relation_size(indexrelid) > 8192  -- Ignore tiny indexes
              AND size_ratio > %s
              {0}
            ORDER BY size_ratio DESC, pg_relation_size(indexrelid) DESC
            """.format(schema_filter)

            cursor.execute(index_query, (bloat_threshold,))
            bloated_indexes = cursor.fetchall()

            result["indexes_needing_reindex"] = len(bloated_indexes)

            if bloated_indexes:
                if verbose:
                    logger.info(f"Found {len(bloated_indexes)} potentially bloated indexes")

                # Process each bloated index
                for idx in bloated_indexes:
                    index_id = f"{idx['schemaname']}.{idx['indexname']}"
                    operation = {
                        "schema": idx["schemaname"],
                        "table": idx["tablename"],
                        "index": idx["indexname"],
                        "size": idx["index_size"],
                        "size_ratio": idx["size_ratio"],
                        "usage_status": idx["usage_status"],
                        "performed": False
                    }

                    if apply:
                        logger.info(f"Reindexing {index_id} (bloat ratio {idx['size_ratio']}%)")
                        try:
                            # Use CONCURRENTLY for minimal disruption if possible
                            cursor.execute(f"REINDEX INDEX CONCURRENTLY {index_id}")
                            operation["performed"] = True
                            result["operations_performed"] += 1
                        except Exception as e:
                            error_msg = f"Error reindexing {index_id}: {str(e)}"
                            logger.error(error_msg)
                            operation["error"] = error_msg
                            result["errors"].append(error_msg)
                    else:
                        logger.info(f"Index {index_id} needs reindexing (bloat ratio {idx['size_ratio']}%)")

                    result["operations"]["reindex"].append(operation)

        # Summarize operations
        total_needs = (result["tables_needing_vacuum"] +
                       result["tables_needing_analyze"] +
                       result["indexes_needing_reindex"])

        if apply:
            logger.info(f"Optimization completed: {result['operations_performed']} operations performed")
            if result["errors"]:
                logger.warning(f"{len(result['errors'])} errors occurred during optimization")
        else:
            logger.info(f"Optimization needed for {total_needs} objects:")
            logger.info(f"  - {result['tables_needing_vacuum']} tables need vacuum")
            logger.info(f"  - {result['tables_needing_analyze']} tables need analyze")
            logger.info(f"  - {result['indexes_needing_reindex']} indexes need reindexing")
            logger.info("Use --apply to perform these operations")

        result["success"] = True
        result["completed_at"] = datetime.datetime.now().isoformat()

    except Exception as e:
        error_msg = f"Error during database optimization: {str(e)}"
        logger.error(error_msg)
        result["errors"].append(error_msg)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return result


def vacuum_analyze(
    db_config: Dict[str, str],
    vacuum_mode: str = "standard",
    schema: Optional[str] = None,
    table: Optional[str] = None,
    apply: bool = False,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Perform vacuum and analyze on database tables.

    Args:
        db_config: Database connection parameters
        vacuum_mode: Type of vacuum to perform ('standard', 'full', or 'analyze')
        schema: Specific schema to vacuum (None for all schemas)
        table: Specific table to vacuum (None for all tables)
        apply: Actually perform vacuum instead of just reporting
        verbose: Whether to show detailed information

    Returns:
        Dictionary with vacuum results
    """
    result = {
        "started_at": datetime.datetime.now().isoformat(),
        "vacuum_mode": vacuum_mode,
        "tables_processed": 0,
        "tables_skipped": 0,
        "success": False,
        "errors": []
    }

    logger.info(f"Starting {vacuum_mode} vacuum in {('reporting' if not apply else 'apply')} mode")

    # Connect to database in maintenance mode
    conn, cursor = connect_to_database(db_config, maintenance_mode=apply)
    if not conn or not cursor:
        result["errors"].append("Failed to connect to database")
        return result

    try:
        # Get list of tables to vacuum
        schema_filter = f"AND n.nspname = '{schema}'" if schema else ""
        table_filter = f"AND c.relname = '{table}'" if table else ""

        query = """
        SELECT
            n.nspname AS schema,
            c.relname AS table_name,
            pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE c.relkind = 'r'  -- Only regular tables
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {0}
          {1}
        ORDER BY pg_total_relation_size(c.oid) DESC
        """.format(schema_filter, table_filter)

        cursor.execute(query)
        tables = cursor.fetchall()

        if not tables:
            if schema and table:
                result["errors"].append(f"Table {schema}.{table} not found")
            elif schema:
                result["errors"].append(f"No tables found in schema {schema}")
            else:
                result["errors"].append("No tables found")
            return result

        if verbose:
            logger.info(f"Found {len(tables)} tables to process")

        # Perform vacuum on all tables or specific table
        for tbl in tables:
            table_id = f"{tbl['schema']}.{tbl['table_name']}"

            if apply:
                try:
                    logger.info(f"Vacuuming {table_id} ({tbl['total_size']})")

                    start_time = time.time()

                    if vacuum_mode == "full":
                        cursor.execute(f"VACUUM FULL {table_id}")
                    elif vacuum_mode == "analyze":
                        cursor.execute(f"VACUUM ANALYZE {table_id}")
                    else:  # standard
                        cursor.execute(f"VACUUM {table_id}")

                    elapsed = time.time() - start_time
                    logger.info(f"Vacuum of {table_id} completed in {elapsed:.1f} seconds")

                    result["tables_processed"] += 1
                except Exception as e:
                    error_msg = f"Error vacuuming {table_id}: {str(e)}"
                    logger.error(error_msg)
                    result["errors"].append(error_msg)
                    result["tables_skipped"] += 1
            else:
                logger.info(f"Would vacuum {table_id} ({tbl['total_size']})")
                result["tables_processed"] += 1

        result["success"] = True
        result["completed_at"] = datetime.datetime.now().isoformat()

        if apply:
            logger.info(f"Vacuum completed: {result['tables_processed']} tables processed, "
                      f"{result['tables_skipped']} tables skipped")
        else:
            logger.info(f"Vacuum would process {result['tables_processed']} tables")
            logger.info("Use --apply to perform this operation")

    except Exception as e:
        error_msg = f"Error during vacuum operation: {str(e)}"
        logger.error(error_msg)
        result["errors"].append(error_msg)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return result


def reindex_database(
    db_config: Dict[str, str],
    schema: Optional[str] = None,
    table: Optional[str] = None,
    concurrent: bool = True,
    apply: bool = False,
    verbose: bool = False,
    bloat_threshold: float = MAINTENANCE_SETTINGS["index_bloat_threshold"]
) -> Dict[str, Any]:
    """
    Reindex bloated or corrupt indexes in the database.

    Args:
        db_config: Database connection parameters
        schema: Specific schema to reindex (None for all schemas)
        table: Specific table to reindex (None for all tables)
        concurrent: Use CONCURRENTLY option for minimal disruption
        apply: Actually perform reindexing instead of just reporting
        verbose: Whether to show detailed information
        bloat_threshold: Bloat percentage threshold for reindexing

    Returns:
        Dictionary with reindexing results
    """
    result = {
        "started_at": datetime.datetime.now().isoformat(),
        "indexes_checked": 0,
        "indexes_needing_reindex": 0,
        "indexes_reindexed": 0,
        "success": False,
        "errors": []
    }

    logger.info(f"Starting database reindexing in {('reporting' if not apply else 'apply')} mode")

    # Connect to database
    conn, cursor = connect_to_database(db_config, maintenance_mode=apply)
    if not conn or not cursor:
        result["errors"].append("Failed to connect to database")
        return result

    try:
        # Define filters
        schema_filter = f"AND schemaname = '{schema}'" if schema else ""
        table_filter = f"AND tablename = '{table}'" if table else ""

        # Query to find bloated indexes
        bloat_query = """
        SELECT
            schemaname,
            tablename,
            indexname,
            pg_size_pretty(pg_relation_size(indexrelid::regclass)) AS index_size,
            ROUND((100 * pg_relation_size(indexrelid)::numeric /
                  GREATEST(pg_relation_size(indrelid), 1))::numeric, 1) AS size_ratio,
            idx_scan,
            idx_tup_read,
            idx_tup_fetch
        FROM pg_stat_all_indexes
        JOIN pg_index ON pg_index.indexrelid = pg_stat_all_indexes.indexrelid
        WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
          AND pg_relation_size(indexrelid) > 8192  -- Ignore tiny indexes
          AND size_ratio > %s
          {0}
          {1}
        ORDER BY size_ratio DESC, pg_relation_size(indexrelid) DESC
        """.format(schema_filter, table_filter)

        cursor.execute(bloat_query, (bloat_threshold,))
        indexes = cursor.fetchall()

        result["indexes_checked"] = len(indexes)
        result["indexes_needing_reindex"] = len(indexes)

        if verbose:
            if indexes:
                logger.info(f"Found {len(indexes)} bloated indexes to reindex")
            else:
                logger.info("No bloated indexes found")

        # Process each index
        for idx in indexes:
            index_id = f"{idx['schemaname']}.{idx['indexname']}"

            if apply:
                try:
                    logger.info(f"Reindexing {index_id} (size: {idx['index_size']}, "
                              f"bloat: {idx['size_ratio']}%)")

                    start_time = time.time()

                    # Use CONCURRENTLY for minimal disruption if requested
                    concurrent_str = "CONCURRENTLY" if concurrent else ""
                    cursor.execute(f"REINDEX INDEX {concurrent_str} {index_id}")

                    elapsed = time.time() - start_time
                    logger.info(f"Reindex of {index_id} completed in {elapsed:.1f} seconds")

                    result["indexes_reindexed"] += 1
                except Exception as e:
                    error_msg = f"Error reindexing {index_id}: {str(e)}"
                    logger.error(error_msg)
                    result["errors"].append(error_msg)

                    # If concurrent reindex fails, try without CONCURRENTLY
                    if concurrent and "CONCURRENTLY" in str(e):
                        try:
                            logger.info(f"Retrying reindex of {index_id} without CONCURRENTLY")
                            cursor.execute(f"REINDEX INDEX {index_id}")
                            logger.info(f"Reindex of {index_id} completed without CONCURRENTLY")
                            result["indexes_reindexed"] += 1
                        except Exception as e2:
                            error_msg = f"Error in non-concurrent reindex of {index_id}: {str(e2)}"
                            logger.error(error_msg)
                            result["errors"].append(error_msg)
            else:
                logger.info(f"Would reindex {index_id} (size: {idx['index_size']}, "
                          f"bloat: {idx['size_ratio']}%)")

        result["success"] = True
        result["completed_at"] = datetime.datetime.now().isoformat()

        if apply:
            logger.info(f"Reindexing completed: {result['indexes_reindexed']} of "
                      f"{result['indexes_needing_reindex']} indexes reindexed")
            if result["errors"]:
                logger.warning(f"{len(result['errors'])} errors occurred during reindexing")
        else:
            logger.info(f"Reindexing would process {result['indexes_needing_reindex']} indexes")
            logger.info("Use --apply to perform this operation")

    except Exception as e:
        error_msg = f"Error during reindexing operation: {str(e)}"
        logger.error(error_msg)
        result["errors"].append(error_msg)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return result


def monitor_connection_count(
    db_config: Dict[str, str],
    verbose: bool = False,
    max_connection_percent: float = MAINTENANCE_SETTINGS["max_connection_percent"],
    max_transaction_age: int = MAINTENANCE_SETTINGS["max_transaction_age"],
    max_idle_transaction_age: int = MAINTENANCE_SETTINGS["max_idle_transaction_age"]
) -> Dict[str, Any]:
    """
    Monitor database connections and active transactions.

    This function reports on current database connections, identifies long-running
    transactions, and provides statistics on connection usage.

    Args:
        db_config: Database connection parameters
        verbose: Whether to show detailed connection information
        max_connection_percent: Alert threshold for connection usage (percentage)
        max_transaction_age: Alert threshold for transaction age (seconds)
        max_idle_transaction_age: Alert threshold for idle transaction age (seconds)

    Returns:
        Dictionary with connection monitoring results
    """
    result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "connection_stats": {},
        "connection_count": 0,
        "max_connections": 0,
        "connection_percent": 0,
        "active_transactions": [],
        "idle_transactions": [],
        "application_connections": {},
        "alerts": [],
        "success": False
    }

    logger.info("Starting database connection monitoring")

    # Connect to database
    conn, cursor = connect_to_database(db_config)
    if not conn or not cursor:
        result["alerts"].append("Failed to connect to database")
        return result

    try:
        # Get max connections setting
        cursor.execute("SHOW max_connections")
        result["max_connections"] = int(cursor.fetchone()[0])

        # Get current connections stats
        cursor.execute("""
        SELECT state, count(*)
        FROM pg_stat_activity
        GROUP BY state
        """)

        states = cursor.fetchall()
        total_connections = 0

        for state in states:
            if state[0] is None:
                result["connection_stats"]["no_state"] = state[1]
            else:
                result["connection_stats"][state[0]] = state[1]
            total_connections += state[1]

        result["connection_count"] = total_connections
        result["connection_percent"] = round((total_connections / result["max_connections"]) * 100, 1)

        # Check if connection count is approaching the limit
        if result["connection_percent"] >= max_connection_percent:
            alert_msg = (f"High connection usage: {result['connection_percent']}% "
                       f"({total_connections}/{result['max_connections']})")
            logger.warning(alert_msg)
            result["alerts"].append(alert_msg)

        # Get active transactions
        cursor.execute("""
        SELECT
            pid,
            usename,
            application_name,
            client_addr::text,
            state,
            EXTRACT(EPOCH FROM now() - query_start) as query_age_seconds,
            EXTRACT(EPOCH FROM now() - state_change) as state_age_seconds,
            LEFT(query, 100) as query_preview
        FROM pg_stat_activity
        WHERE state = 'active'
          AND pid <> pg_backend_pid()  -- Exclude this connection
          AND query_start < now() - interval '5 second'  -- Only include queries running > 5 sec
        ORDER BY query_start ASC
        """)

        active_transactions = cursor.fetchall()
        for txn in active_transactions:
            # Convert row to dict for JSON serialization
            txn_dict = {
                "pid": txn["pid"],
                "user": txn["usename"],
                "application": txn["application_name"],
                "client_addr": txn["client_addr"],
                "state": txn["state"],
                "query_age_seconds": txn["query_age_seconds"],
                "state_age_seconds": txn["state_age_seconds"],
                "query_preview": txn["query_preview"]
            }
            result["active_transactions"].append(txn_dict)

            # Alert on long-running transactions
            if txn["query_age_seconds"] > max_transaction_age:
                alert_msg = (f"Long-running transaction: {txn['query_age_seconds']:.0f} seconds, "
                           f"PID {txn['pid']}, app: {txn['application_name']}")
                logger.warning(alert_msg)
                result["alerts"].append(alert_msg)

        # Get idle transactions (potentially holding locks)
        cursor.execute("""
        SELECT
            pid,
            usename,
            application_name,
            client_addr::text,
            state,
            EXTRACT(EPOCH FROM now() - query_start) as query_age_seconds,
            EXTRACT(EPOCH FROM now() - state_change) as state_age_seconds
        FROM pg_stat_activity
        WHERE state = 'idle in transaction'
          AND state_change < now() - interval '30 second'  -- Only include idle transactions > 30 sec
        ORDER BY state_change ASC
        """)

        idle_transactions = cursor.fetchall()
        for txn in idle_transactions:
            # Convert row to dict for JSON serialization
            txn_dict = {
                "pid": txn["pid"],
                "user": txn["usename"],
                "application": txn["application_name"],
                "client_addr": txn["client_addr"],
                "state": txn["state"],
                "query_age_seconds": txn["query_age_seconds"],
                "state_age_seconds": txn["state_age_seconds"]
            }
            result["idle_transactions"].append(txn_dict)

            # Alert on long-idle transactions
            if txn["state_age_seconds"] > max_idle_transaction_age:
                alert_msg = (f"Idle transaction: {txn['state_age_seconds']:.0f} seconds, "
                           f"PID {txn['pid']}, app: {txn['application_name']}")
                logger.warning(alert_msg)
                result["alerts"].append(alert_msg)

        # Get connections by application name
        cursor.execute("""
        SELECT application_name, count(*)
        FROM pg_stat_activity
        GROUP BY application_name
        """)

        app_connections = cursor.fetchall()
        for app in app_connections:
            result["application_connections"][app[0] or "unknown"] = app[1]

        # Log connection summary
        logger.info(f"Connection usage: {result['connection_percent']}% "
                  f"({total_connections}/{result['max_connections']})")
        logger.info(f"Active queries: {len(active_transactions)}")
        logger.info(f"Idle transactions: {len(idle_transactions)}")

        if verbose:
            logger.info("Connection state breakdown:")
            for state, count in result["connection_stats"].items():
                logger.info(f"  - {state}: {count}")

            logger.info("Connections by application:")
            for app, count in result["application_connections"].items():
                logger.info(f"  - {app}: {count}")

        result["success"] = True

    except Exception as e:
        error_msg = f"Error monitoring database connections: {str(e)}"
        logger.error(error_msg)
        result["alerts"].append(error_msg)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return result


def check_table_bloat(
    db_config: Dict[str, str],
    schema: Optional[str] = None,
    bloat_threshold: float = 20.0,
    min_table_size_mb: float = 1.0,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Check for table bloat in the database.

    Table bloat occurs when tables have a lot of dead tuples or wasted space.
    This function identifies tables that could benefit from a VACUUM FULL.

    Args:
        db_config: Database connection parameters
        schema: Specific schema to check (None for all schemas)
        bloat_threshold: Percentage of bloat to report (default: 20%)
        min_table_size_mb: Minimum table size in MB to consider (default: 1MB)
        verbose: Whether to show detailed information

    Returns:
        Dictionary with bloat check results
    """
    result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "tables_checked": 0,
        "bloated_tables": [],
        "success": False
    }

    logger.info(f"Checking for table bloat (threshold: {bloat_threshold}%, min size: {min_table_size_mb}MB)")

    # Connect to database
    conn, cursor = connect_to_database(db_config)
    if not conn or not cursor:
        result["error"] = "Failed to connect to database"
        return result

    try:
        # Schema filter
        schema_filter = f"AND n.nspname = '{schema}'" if schema else ""

        # Complex query to estimate table bloat
        # This is an estimation based on statistics and may not be 100% accurate
        bloat_query = """
        WITH constants AS (
            SELECT current_setting('block_size')::numeric AS bs,
                   23 AS hdr_size,
                   8 AS ma_size
        ), bloat_info AS (
            SELECT
                ma.nspname AS schema_name,
                ma.relname AS table_name,
                ma.reltuples::bigint AS n_live_tup,
                ma.relpages::bigint AS pages,
                bs,
                (datawidth + (hdr_size + ma_size) * (1 - null_frac) * 2)::numeric AS datahdr,
                (ma.bs - ((hdr_size + ma_size) * (1 - null_frac) * 2))::numeric AS datalen,
                (CASE WHEN ma.bs > 0
                THEN CEIL((ma.datahdr)::numeric / ma.bs)
                ELSE NULL
                END)::smallint AS datahdr_pages,
                (CASE
                    WHEN ma.datawidth IS NOT NULL AND ma.bs > 0
                      THEN CEIL((ma.datalen * ma.reltuples) / (ma.bs - ma.hdr_size))::bigint
                    ELSE 0
                END) AS estimated_pages
            FROM (
                SELECT
                    ns.nspname,
                    tbl.relname,
                    tbl.reltuples,
                    tbl.relpages,
                    constants.bs,
                    constants.hdr_size,
                    constants.ma_size,
                    SUM((1 - stats.null_frac) * stats.avg_width)::int AS datawidth,
                    MAX(1 - stats.null_frac) AS null_frac
                FROM pg_class tbl
                JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
                JOIN constants ON 1=1
                LEFT JOIN pg_stats stats ON stats.schemaname = ns.nspname
                    AND stats.tablename = tbl.relname
                WHERE tbl.relkind = 'r'
                    AND tbl.relpages > 0
                    AND ns.nspname NOT IN ('pg_catalog', 'information_schema')
                    {0}
                GROUP BY 1, 2, 3, 4, 5, 6, 7
            ) ma
        )
        SELECT
            schema_name,
            table_name,
            n_live_tup,
            CAST(pages AS numeric) AS pages,
            CAST(estimated_pages AS numeric) AS estimated_pages,
            CAST(pages - estimated_pages AS numeric) AS extra_pages,
            ROUND(100 * (pages - estimated_pages) / GREATEST(1, pages))::numeric AS bloat_percent,
            pg_size_pretty(pages::bigint * bs) AS table_size,
            pg_size_pretty((pages - estimated_pages)::bigint * bs) AS bloat_size
        FROM bloat_info
        JOIN constants ON 1=1
        WHERE pages > 0
            AND pages > estimated_pages
            AND (pages - estimated_pages) * bs / (1024*1024) > %s  -- Min bloat size in MB
            AND ROUND(100 * (pages - estimated_pages) / GREATEST(1, pages))::numeric > %s  -- Bloat percent threshold
        ORDER BY bloat_percent DESC, bloat_size DESC
        """.format(schema_filter)

        cursor.execute(bloat_query, (min_table_size_mb, bloat_threshold))
        bloated_tables = cursor.fetchall()

        # Process results
        for tbl in bloated_tables:
            table_info = {
                "schema": tbl["schema_name"],
                "table": tbl["table_name"],
                "rows": tbl["n_live_tup"],
                "bloat_percent": float(tbl["bloat_percent"]),
                "table_size": tbl["table_size"],
                "bloat_size": tbl["bloat_size"]
            }
            result["bloated_tables"].append(table_info)

            if verbose:
                logger.info(f"Bloated table: {tbl['schema_name']}.{tbl['table_name']} "
                          f"({tbl['bloat_percent']}% bloat, {tbl['bloat_size']})")

        result["tables_checked"] = cursor.rowcount

        if result["bloated_tables"]:
            logger.info(f"Found {len(result['bloated_tables'])} tables with significant bloat")
            logger.info("Consider running VACUUM FULL on these tables during a maintenance window")
        else:
            logger.info(f"No tables with significant bloat (>{bloat_threshold}%) found")

        result["success"] = True

    except Exception as e:
        error_msg = f"Error checking table bloat: {str(e)}"
        logger.error(error_msg)
        result["error"] = error_msg
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return result


def check_index_usage(
    db_config: Dict[str, str],
    schema: Optional[str] = None,
    table: Optional[str] = None,
    min_index_size_kb: float = 128.0,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Check for unused or rarely used indexes.

    This function identifies indexes that are not being used or are rarely used,
    which could be candidates for removal to improve write performance.

    Args:
        db_config: Database connection parameters
        schema: Specific schema to check (None for all schemas)
        table: Specific table to check (None for all tables)
        min_index_size_kb: Minimum index size in KB to consider (default: 128KB)
        verbose: Whether to show detailed information

    Returns:
        Dictionary with index usage check results
    """
    result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "indexes_checked": 0,
        "unused_indexes": [],
        "rarely_used_indexes": [],
        "indexes_with_duplicates": [],
        "success": False
    }

    logger.info("Checking for unused and rarely used indexes")

    # Connect to database
    conn, cursor = connect_to_database(db_config)
    if not conn or not cursor:
        result["error"] = "Failed to connect to database"
        return result

    try:
        # Schema and table filters
        schema_filter = f"AND schemaname = '{schema}'" if schema else ""
        table_filter = f"AND tablename = '{table}'" if table else ""

        # Query for unused indexes (excluding primary keys and unique constraints)
        unused_query = """
        SELECT
            schemaname,
            tablename,
            indexrelname AS index_name,
            pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,
            pg_relation_size(indexrelid) AS index_bytes,
            idx_scan
        FROM pg_stat_all_indexes
        JOIN pg_index ON pg_index.indexrelid = pg_stat_all_indexes.indexrelid
        WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
            AND idx_scan = 0
            AND indisunique = FALSE  -- Skip unique indexes
            AND pg_relation_size(indexrelid) > %s * 1024  -- Skip small indexes
            {0}
            {1}
        ORDER BY pg_relation_size(indexrelid) DESC
        """.format(schema_filter, table_filter)

        cursor.execute(unused_query, (min_index_size_kb,))
        unused_indexes = cursor.fetchall()

        # Process unused indexes
        for idx in unused_indexes:
            index_info = {
                "schema": idx["schemaname"],
                "table": idx["tablename"],
                "index_name": idx["index_name"],
                "index_size": idx["index_size"],
                "scans": idx["idx_scan"]
            }
            result["unused_indexes"].append(index_info)

            if verbose:
                logger.info(f"Unused index: {idx['schemaname']}.{idx['index_name']} "
                          f"on {idx['tablename']} (size: {idx['index_size']})")

        # Query for rarely used indexes
        rarely_used_query = """
        SELECT
            schemaname,
            tablename,
            indexrelname AS index_name,
            pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,
            pg_relation_size(indexrelid) AS index_bytes,
            idx_scan,
            seq_scan,
            idx_tup_read,
            seq_tup_read,
            CASE WHEN seq_scan > 0
                THEN ROUND(100.0 * idx_scan / (idx_scan + seq_scan), 1)
                ELSE 0
            END AS index_scan_percent
        FROM pg_stat_all_indexes
        JOIN pg_stat_all_tables USING (schemaname, relname)
        JOIN pg_index ON pg_index.indexrelid = pg_stat_all_indexes.indexrelid
        WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
            AND idx_scan > 0  -- Used at least once
            AND idx_scan < 50  -- But not used much
            AND seq_scan > 10  -- Table is scanned often
            AND indisunique = FALSE  -- Skip unique indexes
            AND pg_relation_size(indexrelid) > %s * 1024  -- Skip small indexes
            {0}
            {1}
            AND CASE WHEN seq_scan > 0
                THEN ROUND(100.0 * idx_scan / (idx_scan + seq_scan), 1) < 5.0  -- Used in less than 5% of operations
                ELSE FALSE
                END
        ORDER BY idx_scan ASC
        """.format(schema_filter, table_filter)

        cursor.execute(rarely_used_query, (min_index_size_kb,))
        rarely_used = cursor.fetchall()

        # Process rarely used indexes
        for idx in rarely_used:
            index_info = {
                "schema": idx["schemaname"],
                "table": idx["tablename"],
                "index_name": idx["index_name"],
                "index_size": idx["index_size"],
                "scans": idx["idx_scan"],
                "seq_scans": idx["seq_scan"],
                "index_scan_percent": idx["index_scan_percent"]
            }
            result["rarely_used_indexes"].append(index_info)

            if verbose:
                logger.info(f"Rarely used index: {idx['schemaname']}.{idx['index_name']} "
                          f"on {idx['tablename']} (used in {idx['index_scan_percent']}% of operations)")

        # Check for potentially redundant indexes
        # This is a simplification - some indexes might look similar but serve different purposes
        duplicate_query = """
        SELECT
            ns.nspname AS schema_name,
            t.relname AS table_name,
            array_agg(i.relname::text) AS index_names,
            array_agg(am.amname::text) AS index_types,
            array_agg(pg_size_pretty(pg_relation_size(i.oid))) AS index_sizes,
            (array_agg(indkey))[1] AS index_columns
        FROM pg_index ind
        JOIN pg_class i ON i.oid = ind.indexrelid
        JOIN pg_class t ON t.oid = ind.indrelid
        JOIN pg_namespace ns ON ns.oid = t.relnamespace
        JOIN pg_am am ON am.oid = i.relam
        WHERE ns.nspname NOT IN ('pg_catalog', 'information_schema')
            {0}
            {1}
            AND pg_relation_size(i.oid) > %s * 1024  -- Skip small indexes
        GROUP BY schema_name, table_name, indkey
        HAVING COUNT(*) > 1
        ORDER BY schema_name, table_name
        """.format(schema_filter, table_filter)

        cursor.execute(duplicate_query, (min_index_size_kb,))
        potential_duplicates = cursor.fetchall()

        # Process potential duplicates
        for dup in potential_duplicates:
            duplicate_info = {
                "schema": dup["schema_name"],
                "table": dup["table_name"],
                "index_names": dup["index_names"],
                "index_types": dup["index_types"],
                "index_sizes": dup["index_sizes"]
            }
            result["indexes_with_duplicates"].append(duplicate_info)

            if verbose:
                logger.info(f"Potential duplicate indexes on {dup['schema_name']}.{dup['table_name']}: "
                          f"{', '.join(dup['index_names'])}")

        result["indexes_checked"] = cursor.rowcount

        # Log summary
        logger.info(f"Index usage check results:")
        logger.info(f"  - Unused indexes: {len(result['unused_indexes'])}")
        logger.info(f"  - Rarely used indexes: {len(result['rarely_used_indexes'])}")
        logger.info(f"  - Potentially duplicate indexes: {len(result['indexes_with_duplicates'])}")

        if len(result["unused_indexes"]) > 0:
            logger.info("Consider dropping unused indexes to improve write performance")

        result["success"] = True

    except Exception as e:
        error_msg = f"Error checking index usage: {str(e)}"
        logger.error(error_msg)
        result["error"] = error_msg
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return result


def main() -> int:
    """Main execution function."""
    args = parse_args()

    # Setup logging based on arguments
    setup_file_logging(args.log_file, args.verbose)

    # Read database configuration
    try:
        db_config, app_user, app_password = read_config(args.config, args.env)

        # For monitoring we just need read-only access, use app_user with read privileges
        # Only some operations need admin privileges
        if args.action == "monitor" or args.action == "check-bloat":
            db_config["user"] = app_user
            db_config["password"] = app_password
    except Exception as e:
        logger.error(f"Error reading configuration: {e}")
        return EXIT_CODE_ERROR

    result = {}

    # Execute the requested action
    try:
        if args.action == "optimize":
            result = optimize_database(
                db_config,
                args.vacuum_mode,
                args.schema,
                args.table,
                args.apply,
                args.verbose,
                args.threshold or MAINTENANCE_SETTINGS["vacuum_threshold"],
                args.threshold or MAINTENANCE_SETTINGS["analyze_threshold"],
                args.threshold or MAINTENANCE_SETTINGS["index_bloat_threshold"]
            )
        elif args.action == "vacuum":
            result = vacuum_analyze(
                db_config,
                args.vacuum_mode,
                args.schema,
                args.table,
                args.apply,
                args.verbose
            )
        elif args.action == "analyze":
            # We can use vacuum_analyze with analyze mode
            result = vacuum_analyze(
                db_config,
                "analyze",
                args.schema,
                args.table,
                args.apply,
                args.verbose
            )
        elif args.action == "reindex":
            result = reindex_database(
                db_config,
                args.schema,
                args.table,
                True,  # Use CONCURRENTLY by default
                args.apply,
                args.verbose,
                args.threshold or MAINTENANCE_SETTINGS["index_bloat_threshold"]
            )
        elif args.action == "monitor":
            result = monitor_connection_count(
                db_config,
                args.verbose,
                MAINTENANCE_SETTINGS["max_connection_percent"],
                MAINTENANCE_SETTINGS["max_transaction_age"],
                MAINTENANCE_SETTINGS["max_idle_transaction_age"]
            )
        elif args.action == "check-bloat":
            result = check_table_bloat(
                db_config,
                args.schema,
                args.threshold or MAINTENANCE_SETTINGS["index_bloat_threshold"],
                1.0,  # 1MB minimum size
                args.verbose
            )
        else:
            logger.error(f"Unknown action: {args.action}")
            return EXIT_CODE_ERROR

        # Handle result
        if not result.get("success", False):
            logger.error("Operation failed")
            for error in result.get("errors", []):
                logger.error(f"  {error}")
            return EXIT_CODE_ERROR

        return EXIT_CODE_SUCCESS

    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        return EXIT_CODE_ERROR
    except Exception as e:
        logger.error(f"Error during {args.action}: {e}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        return EXIT_CODE_ERROR


if __name__ == "__main__":
    sys.exit(main())
