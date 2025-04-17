```markdown
# Database Maintenance Guide

This document outlines routine maintenance tasks and best practices for maintaining the Cloud Infrastructure Platform database.

## Regular Maintenance Tasks

### Daily Tasks

- **Backup Verification**: Verify that daily backups completed successfully
- **Database Statistics**: Update database statistics
  ```sql
  ANALYZE;

```

- **Review Logs**: Check PostgreSQL logs for errors or warnings

### Weekly Tasks

- **Database Vacuuming**: Run VACUUM to reclaim storage and update statistics
    
    ```sql
    VACUUM ANALYZE;
    
    ```
    
- **Index Maintenance**: Rebuild fragmented indexes
    
    ```sql
    REINDEX TABLE table_name;
    
    ```
    
- **Review Long-Running Queries**: Identify and optimize slow queries
    
    ```sql
    SELECT * FROM pg_stat_activity WHERE state = 'active' ORDER BY query_start ASC;
    
    ```
    

### Monthly Tasks

- **Full Database Optimization**: Run full database vacuum and reindex
    
    ```sql
    VACUUM FULL;
    REINDEX DATABASE cloud_platform_production;
    
    ```
    
- **User Access Review**: Review database users and permissions
- **Storage Capacity Planning**: Check database size and growth rate
    
    ```sql
    SELECT pg_size_pretty(pg_database_size('cloud_platform_production'));
    
    ```
    

## Monitoring

### Key Metrics to Monitor

1. **Connection Count**:
    
    ```sql
    SELECT count(*) FROM pg_stat_activity;
    
    ```
    
2. **Database Size**:
    
    ```sql
    SELECT pg_size_pretty(pg_database_size('cloud_platform_production'));
    
    ```
    
3. **Table Sizes**:
    
    ```sql
    SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
    FROM pg_catalog.pg_statio_user_tables
    ORDER BY pg_total_relation_size(relid) DESC;
    
    ```
    
4. **Index Usage**:
    
    ```sql
    SELECT s.schemaname, s.relname, s.indexrelname, s.idx_scan,
           pg_size_pretty(pg_relation_size(i.indexrelid)) as index_size
    FROM pg_catalog.pg_stat_user_indexes s
    JOIN pg_catalog.pg_index i ON s.indexrelid = i.indexrelid
    ORDER BY s.idx_scan DESC;
    
    ```
    
5. **Cache Hit Ratio**:
    
    ```sql
    SELECT
      sum(heap_blks_read) as heap_read,
      sum(heap_blks_hit) as heap_hit,
      sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)) as ratio
    FROM pg_statio_user_tables;
    
    ```
    

## Performance Optimization

### Query Performance

1. **Identify Slow Queries**:
    - Enable `pg_stat_statements` extension
    - Review logs for slow queries
    - Use the Flask-DebugToolbar in development
2. **Index Optimization**:
    - Ensure proper indexes are in place for common queries
    - Remove unused indexes that slow down writes
3. **Connection Pooling**:
    - Use PgBouncer for connection pooling in production

### Configuration Optimization

### Memory Settings

```
# For 8GB RAM server
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 64MB
maintenance_work_mem = 256MB

```

### Write Settings

```
wal_buffers = 16MB
checkpoint_timeout = 15min
max_wal_size = 1GB

```

### Query Planning

```
random_page_cost = 1.1  # For SSD storage
effective_io_concurrency = 200

```

## Backup and Recovery

See the detailed Backup Strategy document for information on:

- Backup schedules and retention
- Backup verification
- Recovery procedures

## Security Best Practices

1. **Access Control**:
    - Use least privilege principle for database users
    - Rotate passwords regularly
    - Use SSL for database connections
2. **Auditing**:
    - Enable PostgreSQL auditing
    - Review audit logs regularly
3. **Network Security**:
    - Use VPC and security groups to restrict database access
    - Enable IP-based access restrictions in pg_hba.conf

## Scaling Considerations

### Vertical Scaling

- Increase CPU, memory, and storage resources
- Update configuration parameters accordingly

### Horizontal Scaling

- Implement read replicas for read-heavy workloads
- Consider sharding for very large datasets

### Connection Scaling

- Configure appropriate `max_connections` value
- Implement connection pooling
- Monitor connection usage to prevent exhaustion

## Troubleshooting Common Issues

### Connection Issues

- Verify network connectivity
- Check pg_hba.conf for access rules
- Verify credentials
- Check max_connections limit

### Performance Degradation

- Check for blocking queries
- Review recent database changes
- Verify vacuum and analyze are running
- Check disk I/O performance

### High CPU Usage

- Identify resource-intensive queries
- Check for missing indexes
- Optimize query execution plans

## Database Upgrades

1. **Planning**:
    - Schedule maintenance window
    - Perform full backup before upgrading
    - Test upgrade in staging environment
2. **Execution**:
    - Follow PostgreSQL version-specific upgrade path
    - Validate application compatibility
    - Update monitoring and backup procedures
3. **Verification**:
    - Run application tests against upgraded database
    - Verify performance metrics
    - Check for deprecated features or functions