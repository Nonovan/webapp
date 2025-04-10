
import os
from datetime import datetime
from functools import lru_cache
from typing import Dict, Any
import psutil
from flask import current_app
from sqlalchemy import text
from extensions import metrics, db, cache
from models.user import User

class SystemMetrics:
    @staticmethod
    @lru_cache(maxsize=1)
    def get_system_metrics() -> Dict[str, Any]:
        return {
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'load_avg': os.getloadavg(),
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv
            }
        }

    @staticmethod
    def get_process_metrics() -> Dict[str, Any]:
        process = psutil.Process(os.getpid())
        return {
            'memory_used': process.memory_info().rss / 1024 / 1024,  # MB
            'cpu_percent': process.cpu_percent(),
            'threads': process.num_threads(),
            'open_files': len(process.open_files())
        }

class DatabaseMetrics:
    @staticmethod
    def get_db_metrics() -> Dict[str, Any]:
        with db.engine.connect() as conn:
            metrics = {
                'database_size': conn.execute(text(
                    "SELECT pg_size_pretty(pg_database_size(current_database()))"
                )).scalar(),
                'active_connections': conn.execute(text(
                    "SELECT count(*) FROM pg_stat_activity"
                )).scalar(),
                'deadlocks': conn.execute(text(
                    "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()"
                )).scalar(),
                'cache_hit_ratio': conn.execute(text("""
                    SELECT
                        sum(heap_blks_hit) / nullif(sum(heap_blks_hit) + sum(heap_blks_read),0) * 100
                    FROM pg_statio_user_tables;
                """)).scalar()
            }

        metrics.update({
            'pool_size': len(db.engine.pool._channels),
            'in_use': db.engine.pool.checkedout()
        })

        return metrics

class ApplicationMetrics:
    @staticmethod
    @cache.memoize(timeout=60)
    def get_app_metrics() -> Dict[str, Any]:
        try:
            return {
                'total_users': User.query.count(),
                'active_users': db.session.execute(
                    text("SELECT COUNT(*) FROM users WHERE last_seen > now() - interval '5 minutes'")
                ).scalar(),
                'uptime': str(datetime.utcnow() - current_app.uptime),
                'version': current_app.config.get('VERSION', '1.0.0'),
                'total_requests': metrics.get_metric('requests_total', 0),
                'error_count': metrics.get_metric('errors_total', 0),
                'cache_stats': {
                    'hits': cache.get('hits', 0),
                    'misses': cache.get('misses', 0)
                },
                'response_times': {
                    'avg': metrics.get_metric('response_time_avg', 0),
                    'p95': metrics.get_metric('response_time_p95', 0),
                    'p99': metrics.get_metric('response_time_p99', 0)
                }
            }
        except Exception as e:
            current_app.logger.error(f"Error collecting app metrics: {e}")
            return {}

class EnvironmentalData:
    @staticmethod
    @cache.memoize(timeout=30)
    def get_env_metrics() -> Dict[str, Any]:
        try:
            # Get base metrics
            network = psutil.net_io_counters()
            timestamp = datetime.utcnow()

            return {
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv,
                    'errors_in': network.errin,
                    'errors_out': network.errout,
                    'drops_in': network.dropin,
                    'drops_out': network.dropout
                },
                'load_average': os.getloadavg(),
                'connections': {
                    'total': len(psutil.net_connections()),
                    'established': len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
                },
                'query_metrics': {
                    'total': metrics.get_metric('queries_total', 0),
                    'slow': metrics.get_metric('slow_queries_total', 0),
                    'errors': metrics.get_metric('query_errors_total', 0)
                },
                'timestamp': timestamp.isoformat(),
                'uptime': str(timestamp - current_app.start_time)
            }
        except Exception as e:
            current_app.logger.error(f"Error collecting env metrics: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

@cache.memoize(timeout=60)
def get_all_metrics() -> Dict[str, Any]:
    """Collect all system, database and application metrics."""
    try:
        return {
            'system': SystemMetrics.get_system_metrics(),
            'process': SystemMetrics.get_process_metrics(),
            'database': DatabaseMetrics.get_db_metrics(),
            'application': ApplicationMetrics.get_app_metrics(),
            'environment': EnvironmentalData.get_env_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        current_app.logger.error(f"Error collecting metrics: {e}")
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }