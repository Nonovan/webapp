# Database Maintenance Guide

This document outlines routine maintenance tasks and best practices for maintaining the Cloud Infrastructure Platform database.

## Regular Maintenance Tasks

### Daily Tasks

- **Backup Verification**: Verify that daily backups completed successfully
- **Database Statistics**: Update database statistics

    ```sql
    ANALYZE;
    ```

    ```python
    # Using maintenance.py functions
    from deployment.database import vacuum_analyze, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    vacuum_analyze(db_config, vacuum_mode="analyze", apply=True)
    ```

- **Review Logs**: Check `PostgreSQL` logs for errors or warnings
- **Connection Monitoring**: Monitor database connections

    ```python
    # Using maintenance.py functions
    from deployment.database import monitor_connection_count, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    connection_status = monitor_connection_count(db_config, verbose=True)
    ```

### Weekly Tasks

- **Database Vacuuming**: Run `VACUUM` to reclaim storage and update statistics

    ```sql
    VACUUM ANALYZE;
    ```

    ```python
    # Using maintenance.py functions
    from deployment.database import vacuum_analyze, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    vacuum_analyze(db_config, vacuum_mode="standard", apply=True)
    ```

- **Index Maintenance**: Rebuild fragmented indexes

    ```sql
    REINDEX TABLE table_name;
    ```

    ```python
    # Using maintenance.py functions
    from deployment.database import reindex_database, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    reindex_database(db_config, schema="cloud", table="table_name", apply=True)
    ```

- **Review Long-Running Queries**: Identify and optimize slow queries

    ```sql
    SELECT * FROM pg_stat_activity WHERE state = 'active' ORDER BY query_start ASC;
    ```

    ```python
    # Using maintenance.py functions to monitor active connections
    from deployment.database import monitor_connection_count, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    result = monitor_connection_count(db_config, verbose=True)

    # Review active transactions
    for txn in result["active_transactions"]:
        if txn["query_age_seconds"] > 300:  # Queries running longer than 5 minutes
            print(f"Long query ({txn['query_age_seconds']}s): {txn['query_preview']}")
    ```

### Monthly Tasks

- **Full Database Optimization**: Run full database vacuum and reindex

    ```sql
    VACUUM FULL;
    REINDEX DATABASE cloud_platform_production;
    ```

    ```python
    # Using maintenance.py functions
    from deployment.database import optimize_database, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    result = optimize_database(
        db_config,
        vacuum_mode="full",
        apply=True,
        verbose=True
    )
    ```

- **User Access Review**: Review database users and permissions
- **Storage Capacity Planning**: Check database size and growth rate

    ```sql
    SELECT pg_size_pretty(pg_database_size('cloud_platform_production'));
    ```

- **Table Bloat Check**: Identify tables with significant bloat

    ```python
    # Using maintenance.py functions
    from deployment.database import check_table_bloat, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    result = check_table_bloat(db_config, bloat_threshold=20, verbose=True)

    for table in result["bloated_tables"]:
        print(f"Table {table['schema']}.{table['table']} has {table['bloat_percent']}% bloat ({table['bloat_size']})")
    ```

- **Index Usage Analysis**: Check for unused or rarely used indexes

    ```python
    # Using maintenance.py functions
    from deployment.database import check_index_usage, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    result = check_index_usage(db_config, verbose=True)

    print(f"Found {len(result['unused_indexes'])} unused indexes")
    print(f"Found {len(result['rarely_used_indexes'])} rarely used indexes")
    ```

## Environment-Specific Maintenance Schedule

| Task | Development | Staging | Production |
|------|-------------|---------|------------|
| Analyze statistics | Weekly | Daily | Daily |
| Standard vacuum | On demand | Weekly | Weekly |
| Full vacuum | Monthly | Monthly | Quarterly |
| Reindex | On demand | Monthly | Quarterly |
| Bloat check | Monthly | Bi-weekly | Weekly |
| Index usage analysis | Monthly | Monthly | Monthly |
| Backup verification | Weekly | Daily | Daily |

## Monitoring

### Key Metrics to Monitor

1. **Connection Count**: Track active and idle connections

    ```sql
    SELECT state, count(*) FROM pg_stat_activity GROUP BY state;
    ```

    ```python
    # Using maintenance.py functions
    from deployment.database import monitor_connection_count, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    result = monitor_connection_count(db_config)

    print(f"Connection usage: {result['connection_percent']}% ({result['connection_count']}/{result['max_connections']})")
    for state, count in result["connection_stats"].items():
        print(f"  - {state}: {count}")
    ```

2. **Cache Hit Ratio**: Ensure efficient memory usage (aim for >99%)

    ```sql
    SELECT
      sum(heap_blks_read) as heap_read,
      sum(heap_blks_hit) as heap_hit,
      sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)) as ratio
    FROM pg_statio_user_tables;
    ```

3. **Database Size Growth**: Track database size over time
4. **Transaction Throughput**: Monitor transaction rates during peak periods
5. **Index Usage**: Identify unused or rarely used indexes
6. **Long-Running Transactions**: Monitor for transactions that run too long

    ```python
    # Using maintenance.py functions
    from deployment.database import monitor_connection_count, read_config

    db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
    result = monitor_connection_count(
        db_config,
        max_transaction_age=1800,  # Alert for transactions running > 30 minutes
        max_idle_transaction_age=300  # Alert for idle transactions > 5 minutes
    )

    for alert in result["alerts"]:
        print(f"ALERT: {alert}")
    ```

### Using `maintenance.py` for Monitoring

The `maintenance.py` module provides several functions to help with database monitoring:

```python
# Example monitoring script
from deployment.database import (
    monitor_connection_count,
    check_table_bloat,
    check_index_usage,
    read_config
)

db_config, _, _ = read_config("deployment/database/db_config.ini", "production")

# Check connection status
conn_status = monitor_connection_count(db_config)

# Check for table bloat
bloat_status = check_table_bloat(db_config, bloat_threshold=20)

# Check index usage
index_status = check_index_usage(db_config)

# Output results
print(f"Connection usage: {conn_status['connection_percent']}% of maximum")
print(f"Found {len(bloat_status['bloated_tables'])} tables with significant bloat")
print(f"Found {len(index_status['unused_indexes'])} unused indexes")
```

## Performance Optimization

### Query Performance

1. **Identify Slow Queries**:
    - Enable `pg_stat_statements` extension
    - Review logs for slow queries
    - Use the `Flask-DebugToolbar` in development
2. **Index Optimization**:
    - Ensure proper indexes are in place for common queries
    - Remove unused indexes that slow down writes
3. **Connection Pooling**:
    - Use `PgBouncer` for connection pooling in production

### Configuration Optimization

#### Memory Settings

```plaintext
# For 8GB RAM server
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 64MB
maintenance_work_mem = 256MB
```

#### Write Settings

```plaintext
wal_buffers = 16MB
checkpoint_timeout = 15min
max_wal_size = 1GB
```

#### Query Planning

```plaintext
random_page_cost = 1.1  # For SSD storage
effective_io_concurrency = 200
```

### Automated Optimization

The `optimize_database` function provides comprehensive optimization based on the current state of the database:

```python
from deployment.database import optimize_database, read_config

# Read database configuration
db_config, _, _ = read_config("deployment/database/db_config.ini", "production")

# First run in analysis mode
print("Analyzing optimization opportunities...")
result = optimize_database(
    db_config,
    vacuum_mode="standard",
    apply=False,  # Dry run
    verbose=True,
    vacuum_threshold=MAINTENANCE_SETTINGS["vacuum_threshold"],
    analyze_threshold=MAINTENANCE_SETTINGS["analyze_threshold"],
    bloat_threshold=MAINTENANCE_SETTINGS["index_bloat_threshold"]
)

print(f"Found {result['tables_needing_vacuum']} tables needing vacuum")
print(f"Found {result['tables_needing_analyze']} tables needing analyze")
print(f"Found {result['indexes_needing_reindex']} indexes needing reindex")

# If we want to proceed with optimization
should_apply = input("Apply these optimizations? (y/n): ").lower() == 'y'
if should_apply:
    result = optimize_database(
        db_config,
        vacuum_mode="standard",
        apply=True,
        verbose=True
    )
    print(f"Applied {result['operations_performed']} optimization operations")
```

## Backup and Recovery

See the detailed Backup Strategy document for information on:

- Backup schedules and retention
- Backup verification
- Recovery procedures
- Disaster recovery testing

## Security Best Practices

1. **Access Control**:
    - Use least privilege principle for database users
    - Rotate passwords regularly
    - Use SSL for database connections
2. **Auditing**:
    - Enable `PostgreSQL` auditing
    - Review audit logs regularly
3. **Network Security**:
    - Use VPC and security groups to restrict database access
    - Enable IP-based access restrictions in `pg_hba.conf`
4. **Data Protection**:
    - Encrypt sensitive columns using pgcrypto extension
    - Implement row-level security where appropriate
    - Use application-level data masking for sensitive data

## Scaling Considerations

### Vertical Scaling

- Increase CPU, memory, and storage resources
- Update configuration parameters accordingly
- Adjust maintenance windows and vacuum settings for larger databases

### Horizontal Scaling

- Implement read replicas for read-heavy workloads
- Consider sharding for very large datasets
- Use connection pooling to distribute load

### Connection Scaling

- Configure appropriate `max_connections` value
- Implement connection pooling with `PgBouncer`
- Monitor connection usage to prevent exhaustion
- Set appropriate connection timeouts

## Troubleshooting Common Issues

### Connection Issues

- Verify network connectivity
- Check `pg_hba.conf` for access rules
- Verify credentials
- Check max_connections limit
- Look for connection leaks in application code
- Verify SSL certificate validity if using SSL connections

### Performance Degradation

- Check for blocking queries
- Review recent database changes
- Verify vacuum and analyze are running
- Check disk I/O performance
- Look for index bloat using `check_table_bloat()`
- Monitor for resource contention

```python
# Check for table bloat
from deployment.database import check_table_bloat, read_config

db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
result = check_table_bloat(db_config, verbose=True)

if result["bloated_tables"]:
    print("Consider running VACUUM FULL on these tables during a maintenance window:")
    for table in result["bloated_tables"]:
        print(f"  - {table['schema']}.{table['table']} ({table['bloat_percent']}% bloat)")
```

### High CPU Usage

- Identify resource-intensive queries
- Check for missing indexes
- Optimize query execution plans
- Look for sequential scans on large tables
- Check for excessive connections
- Monitor for non-optimized join operations

## Database Upgrades

1. **Planning**:
    - Schedule maintenance window
    - Perform full backup before upgrading
    - Test upgrade in staging environment
    - Create a detailed rollback plan
2. **Execution**:
    - Follow `PostgreSQL` version-specific upgrade path
    - Validate application compatibility
    - Update monitoring and backup procedures
    - Consider using `pg_upgrade` for minimal downtime
3. **Verification**:
    - Run application tests against upgraded database
    - Verify performance metrics
    - Check for deprecated features or functions
    - Validate all database connections work correctly
    - Verify replication is functioning (if applicable)

## Maintenance Command Reference

### Using Built-in Maintenance Functions

The `maintenance.py` module provides several key functions for database maintenance:

```python
# Import maintenance functions
from deployment.database import (
    optimize_database,
    vacuum_analyze,
    reindex_database,
    monitor_connection_count,
    check_table_bloat,
    check_index_usage,
    read_config
)

# Read database configuration
db_config, _, _ = read_config("deployment/database/db_config.ini", "production")
```

### Common Maintenance Operations

```python
# Basic vacuum (safe to run any time)
vacuum_analyze(db_config, vacuum_mode="standard", apply=True)

# Full vacuum (requires exclusive lock, run during maintenance windows)
vacuum_analyze(db_config, vacuum_mode="full", apply=True)

# Analyze statistics only
vacuum_analyze(db_config, vacuum_mode="analyze", apply=True)

# Reindex specific schema or table
reindex_database(db_config, schema="cloud", apply=True)

# Check current connection count and activity
connection_info = monitor_connection_count(db_config, verbose=True)

# Check for table bloat
bloat_info = check_table_bloat(db_config, verbose=True)

# Check for unused indexes
index_info = check_index_usage(db_config, verbose=True)

# Full database optimization (analyzes needs and performs required operations)
optimize_database(db_config, apply=True, verbose=True)
```

## Integration with Monitoring Systems

The maintenance functions return structured data that can be integrated with monitoring systems:

```python
# Check database connection status
connection_status = monitor_connection_count(db_config)

# Extract metrics for monitoring system
metrics = {
    "db_connection_percent": connection_status["connection_percent"],
    "db_connection_count": connection_status["connection_count"],
    "db_active_transactions": len(connection_status["active_transactions"]),
    "db_idle_transactions": len(connection_status["idle_transactions"])
}

# Alert on high connection usage
if connection_status["connection_percent"] > 80:
    send_alert("High database connection usage", connection_status)
```

For complete function documentation, refer to the docstrings in `maintenance.py` or use the `help()` function:

```python
from deployment.database import optimize_database
help(optimize_database)
```
