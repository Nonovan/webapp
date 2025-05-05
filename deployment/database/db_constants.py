"""
Database constants for Cloud Infrastructure Platform.

This module centralizes constants used across database management scripts,
providing consistent values for environments, schemas, user roles, maintenance
settings, and other database-related configurations.
"""

import os
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple

# Base directories and paths
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_CONFIG_PATH = SCRIPT_DIR / "db_config.ini"

# Environment constants
ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]
DEFAULT_ENVIRONMENT = "development"

# Database naming
DEFAULT_DB_NAMES: Dict[str, str] = {
    "development": "cloud_platform_development",
    "staging": "cloud_platform_staging",
    "production": "cloud_platform_production",
    "dr-recovery": "cloud_platform_dr"
}

# Database user roles
DB_ROLES: Dict[str, str] = {
    "app": "cloud_platform_app",         # Application user with write access
    "readonly": "cloud_platform_readonly", # Read-only access for reporting
    "admin": "cloud_platform_admin"       # Administrative access for maintenance
}

# Standard database schemas
DB_SCHEMAS: List[str] = ["public", "cloud", "ics", "security", "audit"]

# Default PostgreSQL extensions to enable
DEFAULT_EXTENSIONS: List[str] = ["pgcrypto", "uuid-ossp", "pg_stat_statements"]

# Connection parameters
DEFAULT_CONNECTION_PARAMS: Dict[str, Any] = {
    "application_name": "cloud_platform",
    "connect_timeout": 10,
    "client_encoding": "utf8",
    "options": "-c statement_timeout=30000"  # 30 second query timeout
}

# Maintenance thresholds
MAINTENANCE_SETTINGS: Dict[str, Any] = {
    "vacuum_threshold": 20,              # Vacuum when >20% of tuples are dead
    "analyze_threshold": 10,             # Analyze when >10% of tuples have changed
    "index_bloat_threshold": 30,         # Reindex when bloat >30%
    "max_connection_percent": 80,        # Alert when connections >80% of max
    "max_transaction_age": 30 * 60,      # Alert for transactions running >30 minutes
    "max_idle_transaction_age": 5 * 60   # Alert for idle transactions >5 minutes
}

# Backup settings
BACKUP_SETTINGS: Dict[str, Any] = {
    "retention_days": {
        "development": 7,                # 7 days retention for development
        "staging": 14,                   # 14 days retention for staging
        "production": 30,                # 30 days retention for production
        "dr-recovery": 30                # 30 days retention for DR
    },
    "compression_level": 6,              # gzip compression level (1-9)
    "backup_timeout": 3600,              # Maximum time for backup in seconds
    "max_parallel_jobs": 4,              # Maximum parallel jobs for pg_dump
    "verify_backups": True,              # Whether to verify backups after creation
    "include_blobs": True,               # Include large objects in backups
    "backup_format": "custom"            # pg_dump format (plain, custom, directory, tar)
}

# Common database metrics
DB_METRICS: List[str] = [
    "active_connections",
    "transaction_rate",
    "cache_hit_ratio",
    "index_usage",
    "table_size",
    "slow_queries",
    "deadlocks"
]

# Monitoring queries
MONITORING_QUERIES: Dict[str, str] = {
    "active_connections": """
        SELECT state, count(*) FROM pg_stat_activity GROUP BY state
    """,
    "cache_hit_ratio": """
        SELECT
          sum(heap_blks_read) as heap_read,
          sum(heap_blks_hit) as heap_hit,
          sum(heap_blks_hit) / NULLIF(sum(heap_blks_hit) + sum(heap_blks_read), 0) as ratio
        FROM pg_statio_user_tables
    """,
    "index_usage": """
        SELECT
          relname,
          idx_scan / (seq_scan + idx_scan) AS idx_scan_pct
        FROM pg_stat_user_tables
        WHERE (idx_scan + seq_scan) > 0
        ORDER BY idx_scan_pct DESC
    """,
    "table_bloat": """
        SELECT
          schemaname, tablename,
          pg_size_pretty(bloat_size) as bloat_size,
          round(bloat_ratio::numeric, 1) as bloat_ratio
        FROM (
          SELECT
            schemaname, tablename,
            (data_length * (bloat_factor - 1))::bigint as bloat_size,
            bloat_factor * 100 as bloat_ratio
          FROM (
            SELECT
              ns.nspname as schemaname,
              tbl.relname as tablename,
              tbl.reltuples,
              tbl.relpages::float,
              (case when tbl.relpages > 0
                then (tbl.relpages/
                  GREATEST(1, (tbl.reltuples/
                    (GREATEST(1, bs * fillfactor / 100.0)))))
                else 0
              end) as bloat_factor,
              GREATEST(tbl.relpages::bigint * bs -
                (tbl.reltuples *
                 GREATEST(1, (CEIL(
                   (CASE WHEN tbl.relhasoids THEN 24 ELSE 8 END +
                   COALESCE(SUM(att.atttypmod - 4), 0)::float +
                   (CASE WHEN SUM(case when attname = 'oid' then 1 else 0 end) > 0 THEN 4 ELSE 0 END)
                   + SUM(CASE WHEN atttypid in (16,17,18,19,20,21,22,23,26,114,142,600,601,602,603,604,628,700,701,702,703,704,718,790,829,869,1042,1043,1082,1083,1114,1184,1186,1266,1560,1562,1700,1790,2950,3614,3802,18961,18962,18963,18964)
                         THEN CEIL((4 + atttypmod - 4) / 8.0)
                         ELSE (CASE WHEN atttypid in (1560, 1562) THEN 4 ELSE 8 END)
                         END))
                   / fillfactor) * fillfactor)
                ), 0)::bigint as data_length,
              bs
            FROM (
              SELECT
                relnamespace,
                relname,
                relhasoids,
                reltuples,
                relpages,
                (SELECT current_setting('block_size')::numeric) AS bs,
                CASE WHEN reloptions LIKE '%fillfactor%'
                  THEN SUBSTRING(reloptions FROM '[0-9]+')::int
                  ELSE 100
                END AS fillfactor
              FROM pg_class
              WHERE relkind = 'r'
            ) as tbl
            JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
            JOIN pg_attribute att ON att.attrelid = tbl.oid AND att.attnum > 0 AND NOT att.attisdropped
            GROUP BY ns.nspname, tbl.relname, tbl.reltuples, tbl.relpages, tbl.relhasoids, bs, fillfactor
          ) as bloat_calc
        ) as bloat_result
        WHERE bloat_ratio > 50
        ORDER BY bloat_ratio DESC
    """
}

# Default initialization parameters
INIT_PARAMS: Dict[str, Any] = {
    "drop_existing": False,
    "create_schemas": True,
    "skip_extensions": False,
    "schema_only": False,
    "verify": True,
    "create_app_user": True,
    "verbose": False
}

# Database script names
SCRIPT_INIT_DB = "init_db.py"
SCRIPT_CREATE_DB = "create_db.py"
SCRIPT_BACKUP_DB = "backup_db.py"
SCRIPT_RESTORE_DB = "restore_db.py"
SCRIPT_ADD_INDEXES = "add_indexes.sh"
SCRIPT_OPTIMIZE = "optimize.sh"

# Log formats
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Exit codes
EXIT_CODE_SUCCESS = 0
EXIT_CODE_ERROR = 1
EXIT_CODE_WARNING = 2
EXIT_CODE_PERMISSION_ERROR = 3
EXIT_CODE_RESOURCE_ERROR = 4
EXIT_CODE_VALIDATION_ERROR = 5
EXIT_CODE_CONFIGURATION_ERROR = 6
EXIT_CODE_OPERATION_CANCELLED = 7

# Version information
__version__ = "0.1.1"
__author__ = "Cloud Infrastructure Platform Team"
