#!/usr/bin/env python3
# filepath: scripts/database/pg_optimizer.py
"""
PostgreSQL Database Optimizer

This module provides comprehensive optimization capabilities for PostgreSQL databases
including index optimization, table statistics updating, bloat detection and removal,
and automated maintenance operations based on database statistics.

It implements best practices for PostgreSQL performance optimization and can operate
in both analysis and execution modes across different environments.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, Set

# Ensure project root is in path
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from deployment.database.maintenance import (
        optimize_database, read_config, connect_to_database,
        MAINTENANCE_SETTINGS
    )
    from core.security.cs_audit import log_security_event
    from core.utils import get_environment_info, sanitize_sql
    CORE_MODULES_AVAILABLE = True
except ImportError:
    CORE_MODULES_AVAILABLE = False

# Configure logging
LOG_DIR = os.environ.get('LOG_DIR', '/var/log/cloud-platform')
os.makedirs(LOG_DIR, exist_ok=True)
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(LOG_DIR, f"pg-optimizer-{TIMESTAMP}.log")

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("pg_optimizer")

# Default thresholds (will be overridden by config values when available)
DEFAULT_THRESHOLDS = {
    "vacuum_threshold": 20.0,        # Dead tuples percentage to trigger VACUUM
    "analyze_threshold": 20.0,       # Modified tuples percentage to trigger ANALYZE
    "index_bloat_threshold": 30.0,   # Index bloat percentage to trigger REINDEX
    "table_bloat_threshold": 40.0,   # Table bloat percentage to suggest VACUUM FULL
    "unused_index_threshold": 10000, # Table size threshold to consider dropping unused indexes
    "index_scan_ratio": 0.01,        # Minimum scan/write ratio for index to be considered useful
    "cache_hit_threshold": 0.95      # Minimum cache hit ratio before recommending more memory
}

# Operation types for audit logging
OPERATION_VACUUM = "vacuum"
OPERATION_ANALYZE = "analyze"
OPERATION_REINDEX = "reindex"
OPERATION_ADD_INDEX = "add_index"
OPERATION_DROP_INDEX = "drop_index"
OPERATION_CONFIG = "config_change"


class OptimizationError(Exception):
    """Exception raised for errors during optimization operations."""
    pass


def load_maintenance_settings() -> Dict[str, float]:
    """
    Load maintenance settings from deployment configuration or use defaults.

    Returns:
        Dict of maintenance settings with threshold values
    """
    settings = DEFAULT_THRESHOLDS.copy()

    if CORE_MODULES_AVAILABLE:
        for key in settings:
            if key in MAINTENANCE_SETTINGS:
                settings[key] = MAINTENANCE_SETTINGS[key]

    return settings


def get_db_config(environment: str) -> Dict[str, str]:
    """
    Get database configuration for the specified environment.

    Args:
        environment: The environment to get configuration for (dev, staging, production)

    Returns:
        Dictionary with database connection parameters

    Raises:
        OptimizationError: If configuration cannot be loaded
    """
    try:
        if CORE_MODULES_AVAILABLE:
            db_config, _, _ = read_config(
                os.path.join(PROJECT_ROOT, "deployment/database/db_config.ini"),
                environment
            )
            return db_config
        else:
            # Fallback for when core modules aren't available
            return {
                "host": os.environ.get(f"DB_HOST_{environment.upper()}", "localhost"),
                "port": os.environ.get(f"DB_PORT_{environment.upper()}", "5432"),
                "database": os.environ.get(f"DB_NAME_{environment.upper()}", "postgres"),
                "user": os.environ.get(f"DB_USER_{environment.upper()}", "postgres"),
                "password": os.environ.get(f"DB_PASSWORD_{environment.upper()}", "")
            }
    except Exception as e:
        logger.error(f"Failed to load database configuration: {e}")
        raise OptimizationError(f"Failed to load database configuration: {str(e)}")


def analyze_db_statistics(
    db_config: Dict[str, str],
    schema: Optional[str] = None,
    table: Optional[str] = None,
    settings: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    Analyze database statistics for potential optimization opportunities.

    Args:
        db_config: Database connection parameters
        schema: Specific schema to analyze (None for all schemas)
        table: Specific table to analyze (None for all tables)
        settings: Maintenance threshold settings

    Returns:
        Dictionary with analysis results and recommendations
    """
    settings = settings or load_maintenance_settings()

    try:
        if CORE_MODULES_AVAILABLE:
            # Use the core module's optimize_database function in analysis mode
            result = optimize_database(
                db_config=db_config,
                schema=schema,
                table=table,
                apply=False,
                verbose=True,
                vacuum_threshold=settings["vacuum_threshold"],
                analyze_threshold=settings["analyze_threshold"],
                bloat_threshold=settings["index_bloat_threshold"]
            )

            # Add more detailed statistics
            conn, cursor = connect_to_database(db_config)

            if conn and cursor:
                try:
                    # Add cache hit ratio statistics
                    result.update(analyze_cache_hit_ratio(cursor))

                    # Add index usage statistics
                    result.update(analyze_index_usage(cursor, settings))

                    # Add table bloat analysis
                    result.update(analyze_table_bloat(cursor, settings, schema))

                    # Add query statistics
                    result.update(analyze_slow_queries(cursor))

                finally:
                    cursor.close()
                    conn.close()

            return result
        else:
            # Simplified analysis when core modules aren't available
            logger.warning("Core modules not available, performing simplified analysis")
            conn, cursor = None, None
            try:
                import psycopg2
                conn = psycopg2.connect(
                    host=db_config.get("host", "localhost"),
                    port=db_config.get("port", "5432"),
                    database=db_config.get("database", "postgres"),
                    user=db_config.get("user", "postgres"),
                    password=db_config.get("password", "")
                )
                cursor = conn.cursor()

                result = {
                    "tables_checked": 0,
                    "tables_needing_vacuum": 0,
                    "tables_needing_analyze": 0,
                    "indexes_needing_reindex": 0,
                    "operations": {
                        "vacuum": [],
                        "analyze": [],
                        "reindex": []
                    },
                    "success": True,
                    "errors": []
                }

                # Add cache hit ratio statistics
                result.update(analyze_cache_hit_ratio(cursor))

                # Add index usage statistics
                result.update(analyze_index_usage(cursor, settings))

                # Add table bloat analysis
                result.update(analyze_table_bloat(cursor, settings, schema))

                # Add query statistics
                result.update(analyze_slow_queries(cursor))

                return result
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()
    except Exception as e:
        logger.error(f"Error analyzing database statistics: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "tables_checked": 0,
            "tables_needing_vacuum": 0,
            "tables_needing_analyze": 0,
            "indexes_needing_reindex": 0,
            "operations": {"vacuum": [], "analyze": [], "reindex": []}
        }


def analyze_cache_hit_ratio(cursor) -> Dict[str, Any]:
    """
    Analyze cache hit ratios to determine if memory settings need adjustment.

    Args:
        cursor: Database cursor

    Returns:
        Dictionary with cache analysis results
    """
    result = {
        "cache_hit_analysis": {
            "buffer_cache_hit_ratio": 0.0,
            "index_cache_hit_ratio": 0.0,
            "needs_memory_increase": False,
            "recommendation": ""
        }
    }

    try:
        # Check buffer cache hit ratio
        cursor.execute("""
        SELECT
            sum(heap_blks_read) as heap_read,
            sum(heap_blks_hit) as heap_hit,
            sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read) + 0.001) as ratio
        FROM
            pg_statio_user_tables;
        """)
        buffer_stats = cursor.fetchone()

        # Check index cache hit ratio
        cursor.execute("""
        SELECT
            sum(idx_blks_read) as idx_read,
            sum(idx_blks_hit) as idx_hit,
            sum(idx_blks_hit) / (sum(idx_blks_hit) + sum(idx_blks_read) + 0.001) as ratio
        FROM
            pg_statio_user_indexes;
        """)
        index_stats = cursor.fetchone()

        # Calculate hit ratios
        buffer_hit_ratio = float(buffer_stats[2])
        index_hit_ratio = float(index_stats[2])

        result["cache_hit_analysis"]["buffer_cache_hit_ratio"] = buffer_hit_ratio
        result["cache_hit_analysis"]["index_cache_hit_ratio"] = index_hit_ratio

        # Check if memory increase might help
        settings = load_maintenance_settings()
        cache_hit_threshold = settings.get("cache_hit_threshold", 0.95)

        if buffer_hit_ratio < cache_hit_threshold or index_hit_ratio < cache_hit_threshold:
            result["cache_hit_analysis"]["needs_memory_increase"] = True

            # Generate recommendations
            recommendations = []
            if buffer_hit_ratio < cache_hit_threshold:
                recommendations.append(f"Consider increasing shared_buffers (current buffer hit ratio: {buffer_hit_ratio:.2%})")
            if index_hit_ratio < cache_hit_threshold:
                recommendations.append(f"Consider increasing work_mem (current index hit ratio: {index_hit_ratio:.2%})")

            result["cache_hit_analysis"]["recommendation"] = ". ".join(recommendations)

    except Exception as e:
        logger.warning(f"Error analyzing cache hit ratios: {str(e)}")
        result["cache_hit_analysis"]["error"] = str(e)

    return result


def analyze_index_usage(cursor, settings: Dict[str, float]) -> Dict[str, Any]:
    """
    Analyze index usage statistics to find unused or rarely used indexes.

    Args:
        cursor: Database cursor
        settings: Optimization threshold settings

    Returns:
        Dictionary with index usage analysis
    """
    result = {
        "index_usage_analysis": {
            "total_indexes": 0,
            "unused_indexes": [],
            "rarely_used_indexes": []
        }
    }

    try:
        cursor.execute("""
        SELECT
            schemaname,
            relname as table_name,
            indexrelname as index_name,
            pg_relation_size(quote_ident(schemaname) || '.' || quote_ident(relname)) as table_size,
            pg_relation_size(quote_ident(schemaname) || '.' || quote_ident(indexrelname)) as index_size,
            idx_scan as index_scans,
            idx_tup_read as tuples_read,
            idx_tup_fetch as tuples_fetched,
            seq_scan as sequential_scans,
            seq_tup_read as seq_tuples_read
        FROM
            pg_stat_all_indexes
        WHERE
            schemaname NOT IN ('pg_catalog', 'pg_toast', 'information_schema')
        ORDER BY
            pg_relation_size(quote_ident(schemaname) || '.' || quote_ident(indexrelname)) DESC;
        """)
        indexes = cursor.fetchall()

        result["index_usage_analysis"]["total_indexes"] = len(indexes)

        for idx in indexes:
            (schema, table_name, index_name, table_size, index_size,
             index_scans, tuples_read, tuples_fetched, seq_scans, seq_tuples_read) = idx

            # Skip small tables
            if table_size < settings["unused_index_threshold"]:
                continue

            if index_scans == 0:
                result["index_usage_analysis"]["unused_indexes"].append({
                    "schema": schema,
                    "table": table_name,
                    "index": index_name,
                    "table_size": table_size,
                    "index_size": index_size,
                    "recommendation": f"DROP INDEX {schema}.{index_name}"
                })
            elif seq_scans > 0 and index_scans / seq_scans < settings["index_scan_ratio"]:
                result["index_usage_analysis"]["rarely_used_indexes"].append({
                    "schema": schema,
                    "table": table_name,
                    "index": index_name,
                    "table_size": table_size,
                    "index_size": index_size,
                    "index_scans": index_scans,
                    "seq_scans": seq_scans,
                    "scan_ratio": index_scans / seq_scans,
                    "recommendation": f"Consider dropping {schema}.{index_name} (low usage)"
                })

    except Exception as e:
        logger.warning(f"Error analyzing index usage: {str(e)}")
        result["index_usage_analysis"]["error"] = str(e)

    return result


def analyze_table_bloat(
    cursor,
    settings: Dict[str, float],
    schema: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyze table bloat to identify tables that need VACUUM FULL.

    Args:
        cursor: Database cursor
        settings: Optimization threshold settings
        schema: Specific schema to analyze (None for all schemas)

    Returns:
        Dictionary with table bloat analysis
    """
    result = {
        "table_bloat_analysis": {
            "total_tables": 0,
            "bloated_tables": []
        }
    }

    try:
        # Schema filter
        schema_clause = ""
        if schema:
            schema_clause = f"AND nspname = '{schema}'"

        # Using the pgstattuple extension if available, otherwise estimate
        cursor.execute(f"""
        SELECT EXISTS (
            SELECT 1 FROM pg_extension WHERE extname = 'pgstattuple'
        )
        """)
        has_pgstattuple = cursor.fetchone()[0]

        if has_pgstattuple:
            # More accurate approach with pgstattuple
            cursor.execute(f"""
            SELECT
                nspname AS schema_name,
                relname AS table_name,
                pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
                pg_relation_size(c.oid) AS size_bytes,
                pgstattuple.free_percent AS bloat_percent
            FROM
                pg_class c
                JOIN pg_namespace n ON c.relnamespace = n.oid
                CROSS JOIN LATERAL pgstattuple(c.oid::regclass) AS pgstattuple
            WHERE
                c.relkind = 'r'
                AND nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                {schema_clause}
                AND pgstattuple.free_percent >= {settings["table_bloat_threshold"]}
            ORDER BY
                pgstattuple.free_percent DESC;
            """)
        else:
            # Estimation approach for when pgstattuple isn't available
            cursor.execute(f"""
            WITH constants AS (
                SELECT current_setting('block_size')::numeric AS bs
            ),
            table_stats AS (
                SELECT
                    nspname AS schema_name,
                    relname AS table_name,
                    bs*relpages AS total_bytes,
                    bs*relpages - pg_relation_size(c.oid) AS bloat_bytes,
                    CASE WHEN relpages > 0
                        THEN 100 * (bs*relpages - pg_relation_size(c.oid)) / (bs*relpages)
                        ELSE 0
                    END AS bloat_percent,
                    pg_relation_size(c.oid) AS actual_bytes,
                    pg_size_pretty(pg_relation_size(c.oid)) AS pretty_size
                FROM
                    pg_class c
                    JOIN pg_namespace n ON c.relnamespace = n.oid
                    CROSS JOIN constants
                WHERE
                    c.relkind = 'r'
                    AND nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                    {schema_clause}
            )
            SELECT
                schema_name,
                table_name,
                pretty_size AS table_size,
                actual_bytes AS size_bytes,
                bloat_percent
            FROM
                table_stats
            WHERE
                bloat_percent >= {settings["table_bloat_threshold"]}
            ORDER BY
                bloat_percent DESC;
            """)

        bloated_tables = cursor.fetchall()
        result["table_bloat_analysis"]["total_tables"] = len(bloated_tables)

        for tbl in bloated_tables:
            schema_name, table_name, table_size, size_bytes, bloat_percent = tbl
            result["table_bloat_analysis"]["bloated_tables"].append({
                "schema": schema_name,
                "table": table_name,
                "size": table_size,
                "size_bytes": size_bytes,
                "bloat_percent": bloat_percent,
                "recommendation": f"VACUUM FULL {schema_name}.{table_name}"
            })

    except Exception as e:
        logger.warning(f"Error analyzing table bloat: {str(e)}")
        result["table_bloat_analysis"]["error"] = str(e)

    return result


def analyze_slow_queries(cursor) -> Dict[str, Any]:
    """
    Analyze slow queries using pg_stat_statements if available.

    Args:
        cursor: Database cursor

    Returns:
        Dictionary with slow query analysis
    """
    result = {
        "slow_queries": {
            "available": False,
            "queries": [],
            "error": None
        }
    }

    try:
        # Check if pg_stat_statements is installed
        cursor.execute("""
        SELECT EXISTS (
            SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
        )
        """)
        has_pg_stat_statements = cursor.fetchone()[0]

        result["slow_queries"]["available"] = has_pg_stat_statements

        if has_pg_stat_statements:
            # Get top slow queries
            cursor.execute("""
            SELECT
                substring(query from 1 for 500) as query_text,
                calls,
                mean_exec_time as avg_time,
                rows as avg_rows,
                shared_blks_hit * 100.0 / nullif(shared_blks_hit + shared_blks_read, 0) as hit_percent
            FROM
                pg_stat_statements
            ORDER BY
                avg_time DESC
            LIMIT 10;
            """)
            slow_queries = cursor.fetchall()

            for q in slow_queries:
                query_text, calls, avg_time, avg_rows, hit_percent = q

                # Add sanitized query to results
                if CORE_MODULES_AVAILABLE:
                    # Use project's sanitization function if available
                    query_text = sanitize_sql(query_text)
                else:
                    # Simple sanitization to remove sensitive data
                    query_text = query_text.replace("'", "''")

                result["slow_queries"]["queries"].append({
                    "query": query_text,
                    "calls": calls,
                    "avg_time_ms": avg_time,
                    "avg_rows": avg_rows,
                    "cache_hit_percent": hit_percent if hit_percent is not None else 0
                })

    except Exception as e:
        logger.warning(f"Error analyzing slow queries: {str(e)}")
        result["slow_queries"]["error"] = str(e)

    return result


def perform_optimization(
    db_config: Dict[str, str],
    schema: Optional[str] = None,
    table: Optional[str] = None,
    vacuum_mode: str = "standard",
    reindex: bool = False,
    drop_unused_indexes: bool = False,
    settings: Optional[Dict[str, float]] = None,
    dry_run: bool = True
) -> Dict[str, Any]:
    """
    Perform database optimization based on analysis.

    Args:
        db_config: Database connection parameters
        schema: Specific schema to optimize (None for all schemas)
        table: Specific table to optimize (None for all tables)
        vacuum_mode: Type of vacuum to perform ('standard', 'full', 'analyze')
        reindex: Whether to perform reindexing
        drop_unused_indexes: Whether to drop unused indexes
        settings: Maintenance threshold settings
        dry_run: Whether to run in dry-run mode without making changes

    Returns:
        Dictionary with optimization results
    """
    settings = settings or load_maintenance_settings()

    # Analysis first
    logger.info("Performing database analysis before optimization")
    analysis = analyze_db_statistics(db_config, schema, table, settings)

    if not analysis["success"]:
        logger.error(f"Analysis failed: {analysis.get('error', 'Unknown error')}")
        return analysis

    if dry_run:
        logger.info("DRY RUN mode - no changes will be made")
        logger.info(f"Would perform the following operations:")
        logger.info(f"- VACUUM on {analysis['tables_needing_vacuum']} tables")
        logger.info(f"- ANALYZE on {analysis['tables_needing_analyze']} tables")

        if reindex:
            logger.info(f"- REINDEX on {analysis['indexes_needing_reindex']} indexes")

        if drop_unused_indexes and "index_usage_analysis" in analysis:
            logger.info(f"- Drop {len(analysis['index_usage_analysis']['unused_indexes'])} unused indexes")

        # Add table bloat recommendations
        if "table_bloat_analysis" in analysis and analysis["table_bloat_analysis"]["bloated_tables"]:
            logger.info(f"- VACUUM FULL would be recommended for {len(analysis['table_bloat_analysis']['bloated_tables'])} tables")

        # Return analysis with dry run indicator
        analysis["dry_run"] = True
        return analysis

    # Actually perform optimization
    try:
        if CORE_MODULES_AVAILABLE:
            # Use the core module's optimize_database function
            result = optimize_database(
                db_config=db_config,
                vacuum_mode=vacuum_mode,
                schema=schema,
                table=table,
                apply=True,
                verbose=True,
                vacuum_threshold=settings["vacuum_threshold"],
                analyze_threshold=settings["analyze_threshold"],
                bloat_threshold=settings["index_bloat_threshold"]
            )
        else:
            # Simplified execution when core modules aren't available
            logger.warning("Core modules not available, performing manual optimization")
            conn, cursor = None, None

            try:
                # Connect with psycopg2 directly
                import psycopg2
                conn = psycopg2.connect(
                    host=db_config.get("host", "localhost"),
                    port=db_config.get("port", "5432"),
                    database=db_config.get("database", "postgres"),
                    user=db_config.get("user", "postgres"),
                    password=db_config.get("password", "")
                )
                conn.set_session(autocommit=True)
                cursor = conn.cursor()

                # Initialize result
                result = {
                    "operations_performed": 0,
                    "tables_optimized": [],
                    "indexes_optimized": [],
                    "success": True,
                    "errors": []
                }

                # Perform vacuum on tables needing it
                for op in analysis["operations"]["vacuum"]:
                    table_id = f"{op['schema']}.{op['table']}"

                    try:
                        logger.info(f"Vacuuming table {table_id}")
                        if vacuum_mode == "full":
                            cursor.execute(f"VACUUM FULL {table_id}")
                        elif vacuum_mode == "analyze":
                            cursor.execute(f"VACUUM ANALYZE {table_id}")
                        else:
                            cursor.execute(f"VACUUM {table_id}")

                        result["operations_performed"] += 1
                        result["tables_optimized"].append({
                            "schema": op["schema"],
                            "table": op["table"],
                            "operation": "vacuum"
                        })
                    except Exception as e:
                        error_msg = f"Error vacuuming {table_id}: {str(e)}"
                        logger.error(error_msg)
                        result["errors"].append(error_msg)

                # Perform analyze on tables needing it if not done during vacuum
                if vacuum_mode != "analyze":
                    for op in analysis["operations"]["analyze"]:
                        table_id = f"{op['schema']}.{op['table']}"

                        try:
                            logger.info(f"Analyzing table {table_id}")
                            cursor.execute(f"ANALYZE {table_id}")

                            result["operations_performed"] += 1
                            result["tables_optimized"].append({
                                "schema": op["schema"],
                                "table": op["table"],
                                "operation": "analyze"
                            })
                        except Exception as e:
                            error_msg = f"Error analyzing {table_id}: {str(e)}"
                            logger.error(error_msg)
                            result["errors"].append(error_msg)

                # Perform reindexing if requested
                if reindex:
                    for op in analysis["operations"]["reindex"]:
                        index_id = f"{op['schema']}.{op['index']}"

                        try:
                            logger.info(f"Reindexing {index_id}")
                            cursor.execute(f"REINDEX INDEX CONCURRENTLY {index_id}")

                            result["operations_performed"] += 1
                            result["indexes_optimized"].append({
                                "schema": op["schema"],
                                "index": op["index"],
                                "operation": "reindex"
                            })
                        except Exception as e:
                            error_msg = f"Error reindexing {index_id}: {str(e)}"
                            logger.error(error_msg)
                            result["errors"].append(error_msg)

                # Drop unused indexes if requested
                if drop_unused_indexes and "index_usage_analysis" in analysis:
                    for idx in analysis["index_usage_analysis"]["unused_indexes"]:
                        index_id = f"{idx['schema']}.{idx['index']}"

                        try:
                            logger.info(f"Dropping unused index {index_id}")
                            cursor.execute(f"DROP INDEX CONCURRENTLY {index_id}")

                            result["operations_performed"] += 1
                            result["indexes_optimized"].append({
                                "schema": idx["schema"],
                                "index": idx["index"],
                                "operation": "drop_index"
                            })
                        except Exception as e:
                            error_msg = f"Error dropping index {index_id}: {str(e)}"
                            logger.error(error_msg)
                            result["errors"].append(error_msg)

            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()

        # Merge the analysis into the result
        if isinstance(result, dict) and "cache_hit_analysis" not in result:
            for key in ["cache_hit_analysis", "index_usage_analysis", "table_bloat_analysis",
                        "slow_queries"]:
                if key in analysis:
                    result[key] = analysis[key]

        # Log significant operations to audit log
        if CORE_MODULES_AVAILABLE and result["operations_performed"] > 0:
            try:
                # Get environment info for audit context
                env_info = get_environment_info()

                log_security_event(
                    event_type="database_optimization",
                    description=f"Performed {result['operations_performed']} database optimization operations",
                    severity="info",
                    environment=env_info.get("environment", "unknown"),
                    details={
                        "vacuum": len([op for op in result.get("tables_optimized", []) if op.get("operation") == "vacuum"]),
                        "analyze": len([op for op in result.get("tables_optimized", []) if op.get("operation") == "analyze"]),
                        "reindex": len([op for op in result.get("indexes_optimized", []) if op.get("operation") == "reindex"]),
                        "drop_index": len([op for op in result.get("indexes_optimized", []) if op.get("operation") == "drop_index"])
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to log to audit log: {str(e)}")

        return result

    except Exception as e:
        logger.error(f"Error during optimization: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "operations_performed": 0
        }


def generate_optimization_report(analysis_result: Dict[str, Any], output_file: Optional[str] = None) -> None:
    """
    Generate a human-readable optimization report from analysis results.

    Args:
        analysis_result: Analysis results dictionary
        output_file: Optional file path to write report
    """
    def hr():
        return "-" * 80

    report_lines = []
    report_lines.append("DATABASE OPTIMIZATION REPORT")
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(hr())

    # Summary section
    report_lines.append("SUMMARY:")
    report_lines.append(f"- Tables Analyzed: {analysis_result.get('tables_checked', 0)}")
    report_lines.append(f"- Tables Needing VACUUM: {analysis_result.get('tables_needing_vacuum', 0)}")
    report_lines.append(f"- Tables Needing ANALYZE: {analysis_result.get('tables_needing_analyze', 0)}")
    report_lines.append(f"- Indexes Needing REINDEX: {analysis_result.get('indexes_needing_reindex', 0)}")

    if "operations_performed" in analysis_result:
        report_lines.append(f"- Operations Performed: {analysis_result.get('operations_performed', 0)}")
    if analysis_result.get("errors"):
        report_lines.append(f"- Errors Encountered: {len(analysis_result.get('errors', []))}")
    report_lines.append(hr())

    # Cache hit analysis
    if "cache_hit_analysis" in analysis_result:
        report_lines.append("CACHE HIT ANALYSIS:")
        cache = analysis_result["cache_hit_analysis"]
        report_lines.append(f"- Buffer Cache Hit Ratio: {cache['buffer_cache_hit_ratio']:.2%}")
        report_lines.append(f"- Index Cache Hit Ratio: {cache['index_cache_hit_ratio']:.2%}")
        if cache.get("recommendation"):
            report_lines.append(f"- Recommendation: {cache['recommendation']}")
        report_lines.append(hr())

    # Table bloat analysis
    if "table_bloat_analysis" in analysis_result and analysis_result["table_bloat_analysis"].get("bloated_tables"):
        report_lines.append("TABLE BLOAT ANALYSIS:")
        bloated_tables = analysis_result["table_bloat_analysis"]["bloated_tables"]
        report_lines.append(f"- Found {len(bloated_tables)} tables with significant bloat")

        if bloated_tables:
            report_lines.append("\n  Top bloated tables:")
            for i, tbl in enumerate(bloated_tables[:5], 1):
                report_lines.append(f"  {i}. {tbl['schema']}.{tbl['table']} - {tbl['bloat_percent']:.1f}% bloat ({tbl['size']})")

            if len(bloated_tables) > 5:
                report_lines.append(f"  ... and {len(bloated_tables) - 5} more")
        report_lines.append(hr())

    # Index usage analysis
    if "index_usage_analysis" in analysis_result:
        report_lines.append("INDEX USAGE ANALYSIS:")
        index_analysis = analysis_result["index_usage_analysis"]
        unused_indexes = index_analysis.get("unused_indexes", [])
        rarely_used = index_analysis.get("rarely_used_indexes", [])

        report_lines.append(f"- Total Indexes: {index_analysis.get('total_indexes', 0)}")
        report_lines.append(f"- Unused Indexes: {len(unused_indexes)}")
        report_lines.append(f"- Rarely Used Indexes: {len(rarely_used)}")

        if unused_indexes:
            report_lines.append("\n  Unused indexes:")
            for i, idx in enumerate(unused_indexes[:5], 1):
                report_lines.append(f"  {i}. {idx['schema']}.{idx['index']} on {idx['table']} ({idx['index_size']} bytes)")

            if len(unused_indexes) > 5:
                report_lines.append(f"  ... and {len(unused_indexes) - 5} more")
        report_lines.append(hr())

    # Slow queries
    if "slow_queries" in analysis_result and analysis_result["slow_queries"].get("available"):
        report_lines.append("SLOW QUERY ANALYSIS:")
        slow_queries = analysis_result["slow_queries"].get("queries", [])

        if slow_queries:
            report_lines.append(f"- Found {len(slow_queries)} slow queries")
            report_lines.append("\n  Top slow queries:")

            for i, query in enumerate(slow_queries[:3], 1):
                # Truncate long queries
                query_text = query["query"]
                if len(query_text) > 80:
                    query_text = query_text[:77] + "..."

                report_lines.append(f"  {i}. Avg: {query['avg_time_ms']:.2f}ms, Calls: {query['calls']}")
                report_lines.append(f"     {query_text}")

            if len(slow_queries) > 3:
                report_lines.append(f"  ... and {len(slow_queries) - 3} more")
        report_lines.append(hr())

    # Operations performed
    if "operations" in analysis_result:
        vacuum_ops = analysis_result["operations"].get("vacuum", [])
        analyze_ops = analysis_result["operations"].get("analyze", [])
        reindex_ops = analysis_result["operations"].get("reindex", [])

        if vacuum_ops:
            report_lines.append("VACUUM OPERATIONS:")
            report_lines.append(f"- Found {len(vacuum_ops)} tables needing VACUUM")

            if len(vacuum_ops) > 0:
                report_lines.append("\n  Top tables needing VACUUM:")
                for i, op in enumerate(vacuum_ops[:5], 1):
                    report_lines.append(f"  {i}. {op['schema']}.{op['table']} - {op.get('dead_tuple_percent', 0):.1f}% dead tuples")

                if len(vacuum_ops) > 5:
                    report_lines.append(f"  ... and {len(vacuum_ops) - 5} more")
            report_lines.append(hr())

        if analyze_ops:
            report_lines.append("ANALYZE OPERATIONS:")
            report_lines.append(f"- Found {len(analyze_ops)} tables needing ANALYZE")

            if len(analyze_ops) > 0:
                report_lines.append("\n  Top tables needing ANALYZE:")
                for i, op in enumerate(analyze_ops[:5], 1):
                    report_lines.append(f"  {i}. {op['schema']}.{op['table']} - {op.get('modified_tuple_percent', 0):.1f}% modified tuples")

                if len(analyze_ops) > 5:
                    report_lines.append(f"  ... and {len(analyze_ops) - 5} more")
            report_lines.append(hr())

        if reindex_ops:
            report_lines.append("REINDEX OPERATIONS:")
            report_lines.append(f"- Found {len(reindex_ops)} indexes needing REINDEX")

            if len(reindex_ops) > 0:
                report_lines.append("\n  Top indexes needing REINDEX:")
                for i, op in enumerate(reindex_ops[:5], 1):
                    report_lines.append(f"  {i}. {op['schema']}.{op['index']} - size ratio: {op.get('size_ratio', 0):.1f}")

                if len(reindex_ops) > 5:
                    report_lines.append(f"  ... and {len(reindex_ops) - 5} more")
            report_lines.append(hr())

    # Errors if any
    if analysis_result.get("errors"):
        report_lines.append("ERRORS:")
        for i, error in enumerate(analysis_result["errors"][:10], 1):
            report_lines.append(f"  {i}. {error}")

        if len(analysis_result["errors"]) > 10:
            report_lines.append(f"  ... and {len(analysis_result['errors']) - 10} more errors")
        report_lines.append(hr())

    # Recommendations
    report_lines.append("RECOMMENDATIONS:")
    recommendations = []

    # Add recommendation for cache if needed
    if ("cache_hit_analysis" in analysis_result and
            analysis_result["cache_hit_analysis"].get("needs_memory_increase") and
            analysis_result["cache_hit_analysis"].get("recommendation")):
        recommendations.append(analysis_result["cache_hit_analysis"]["recommendation"])

    # Add recommendations for bloated tables
    if ("table_bloat_analysis" in analysis_result and
            analysis_result["table_bloat_analysis"].get("bloated_tables")):
        bloated_count = len(analysis_result["table_bloat_analysis"]["bloated_tables"])
        if bloated_count > 0:
            recommendations.append(
                f"Run VACUUM FULL on {bloated_count} bloated tables during a maintenance window"
            )

    # Add recommendations for unused indexes
    if "index_usage_analysis" in analysis_result:
        unused_count = len(analysis_result["index_usage_analysis"].get("unused_indexes", []))
        if unused_count > 0:
            recommendations.append(
                f"Consider dropping {unused_count} unused indexes to improve write performance"
            )

    # Add general recommendations
    recommendations.append("Schedule regular maintenance with VACUUM and ANALYZE")
    recommendations.append("Monitor index usage regularly to optimize schema")

    # Output recommendations
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            report_lines.append(f"  {i}. {rec}")

    report_text = "\n".join(report_lines)

    # Output to file if requested
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report_text)
            logger.info(f"Report written to {output_file}")
        except Exception as e:
            logger.error(f"Error writing report to {output_file}: {str(e)}")

    # Always print to console
    print("\n" + report_text)


def main() -> int:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="PostgreSQL Database Optimizer - Analyze and optimize PostgreSQL databases",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Environment and connection options
    parser.add_argument('--env', choices=['dev', 'staging', 'production'],
                      default='dev', help='Database environment')
    parser.add_argument('--host', help='Database host (overrides environment config)')
    parser.add_argument('--port', help='Database port')
    parser.add_argument('--dbname', help='Database name')
    parser.add_argument('--user', help='Database user')
    parser.add_argument('--password', help='Database password')

    # Analysis options
    parser.add_argument('--analyze-only', action='store_true',
                      help='Only analyze the database, don\'t perform optimization')
    parser.add_argument('--schema', help='Specific schema to analyze/optimize')
    parser.add_argument('--table', help='Specific table to analyze/optimize')

    # Optimization options
    parser.add_argument('--vacuum-mode', choices=['standard', 'full', 'analyze'],
                      default='standard', help='Type of vacuum to perform')
    parser.add_argument('--reindex', action='store_true',
                      help='Perform reindexing of bloated indexes')
    parser.add_argument('--drop-unused-indexes', action='store_true',
                      help='Drop unused indexes')

    # Threshold options
    parser.add_argument('--vacuum-threshold', type=float,
                      help='Dead tuple percentage threshold for VACUUM')
    parser.add_argument('--analyze-threshold', type=float,
                      help='Modified tuple percentage threshold for ANALYZE')
    parser.add_argument('--bloat-threshold', type=float,
                      help='Size ratio threshold for REINDEX')

    # Output options
    parser.add_argument('--output', help='Output file for report')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')

    # Execution options
    parser.add_argument('--apply', action='store_true',
                      help='Apply recommended optimizations (without this, runs in dry-run mode)')
    parser.add_argument('--force', action='store_true',
                      help='Skip confirmation prompt for optimization operations')

    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

    # Load settings
    settings = load_maintenance_settings()

    # Override settings from arguments
    if args.vacuum_threshold is not None:
        settings["vacuum_threshold"] = args.vacuum_threshold
    if args.analyze_threshold is not None:
        settings["analyze_threshold"] = args.analyze_threshold
    if args.bloat_threshold is not None:
        settings["index_bloat_threshold"] = args.bloat_threshold
        settings["table_bloat_threshold"] = args.bloat_threshold

    # Get database configuration
    try:
        # Start with environment-based configuration
        db_config = get_db_config(args.env)

        # Override with any command-line arguments
        if args.host:
            db_config["host"] = args.host
        if args.port:
            db_config["port"] = args.port
        if args.dbname:
            db_config["database"] = args.dbname
        if args.user:
            db_config["user"] = args.user
        if args.password:
            db_config["password"] = args.password

        logger.info(f"Using database {db_config.get('database')} on {db_config.get('host')}:{db_config.get('port')}")

    except OptimizationError as e:
        logger.error(f"Configuration error: {str(e)}")
        return 1

    try:
        # Analysis phase
        if args.analyze_only:
            logger.info("Running database analysis...")
            result = analyze_db_statistics(
                db_config=db_config,
                schema=args.schema,
                table=args.table,
                settings=settings
            )
        else:
            # Check if we need confirmation
            if args.apply and not args.force:
                print("\n" + "-" * 80)
                print(f"WARNING: This will perform optimization operations on database " +
                      f"{db_config.get('database')} in {args.env} environment.")
                print("Operations may include:")
                print(f"- VACUUM (mode: {args.vacuum_mode})")
                if args.reindex:
                    print("- REINDEX on bloated indexes")
                if args.drop_unused_indexes:
                    print("- DROP unused indexes")
                print("\nThese operations can impact database performance during execution.")
                print("-" * 80)

                confirmation = input("\nTo proceed, type 'OPTIMIZE DATABASE' (all uppercase): ")
                if confirmation != "OPTIMIZE DATABASE":
                    logger.info("Operation cancelled by user")
                    return 0

            # Optimization phase
            logger.info("Running database optimization...")
            result = perform_optimization(
                db_config=db_config,
                schema=args.schema,
                table=args.table,
                vacuum_mode=args.vacuum_mode,
                reindex=args.reindex,
                drop_unused_indexes=args.drop_unused_indexes,
                settings=settings,
                dry_run=not args.apply
            )

        # Generate report
        if not args.json:
            # Determine output file if not specified
            output_file = args.output
            if not output_file and args.apply:
                # Create output file in log directory by default
                optimization_type = "analysis" if args.analyze_only else "optimization"
                output_file = os.path.join(LOG_DIR, f"db-{optimization_type}-report-{TIMESTAMP}.txt")

            # Generate human-readable report
            generate_optimization_report(result, output_file)
        else:
            # Output JSON result
            import json

            # Convert sets to lists for JSON serialization
            def set_to_list(obj):
                if isinstance(obj, set):
                    return list(obj)
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

            print(json.dumps(result, indent=2, default=set_to_list))

        # Return appropriate exit code
        if not result.get("success", False):
            return 1
        return 0

    except Exception as e:
        logger.error(f"Error: {str(e)}")

        if args.verbose:
            import traceback
            traceback.print_exc()

        return 1


if __name__ == "__main__":
    sys.exit(main())
