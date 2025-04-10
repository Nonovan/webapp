from datetime import datetime
from functools import wraps
import psutil
from extensions import metrics, db

def track_metrics(name: str):
    """Decorator for tracking endpoint metrics"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            metrics.increment(f'{name}_calls_total')
            with metrics.timer(f'{name}_duration_seconds'):
                return f(*args, **kwargs)
        return wrapped
    return decorator

class SystemMetrics:
    @staticmethod
    def get_system_metrics():
        """Collect system metrics"""
        return {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv
            },
            'timestamp': datetime.utcnow().isoformat()
        }

class DatabaseMetrics:
    @staticmethod
    def get_db_metrics():
        """Collect database metrics"""
        return {
            'active_connections': len(db.engine.pool._channels),
            'total_queries': metrics.get_metric('db_queries_total'),
            'slow_queries': metrics.get_metric('db_slow_queries_total'),
            'query_errors': metrics.get_metric('db_errors_total'),
            'table_sizes': db.session.execute(
                "SELECT relname, pg_size_pretty(pg_total_relation_size(relname::regclass)) FROM pg_stat_user_tables"
            ).fetchall()
        }

class Application:
    pass
