from datetime import datetime
from functools import wraps
import psutil
from typing import Callable, Any, TypeVar, cast
from flask import current_app, request
from extensions import metrics, db

F = TypeVar('F', bound=Callable[..., Any])

def track_metrics(name: str) -> Callable[[F], F]:
    """Decorator for tracking endpoint metrics."""
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            start = datetime.utcnow()
            
            # Track request
            metrics.info(
                'http_requests_total',
                1,
                labels={
                    'method': request.method,
                    'endpoint': request.endpoint
                }
            )

            try:
                result = func(*args, **kwargs)
                
                # Track success
                metrics.info(
                    'http_requests_success_total',
                    1,
                    labels={
                        'method': request.method,
                        'endpoint': request.endpoint
                    }
                )
                
                return result

            except Exception as e:
                # Track error
                metrics.info(
                    'http_errors_total',
                    1,
                    labels={
                        'method': request.method,
                        'status': str(getattr(e, 'code', 500))
                    }
                )
                raise

            finally:
                # Track duration
                duration = (datetime.utcnow() - start).total_seconds()
                metrics.info(
                    f'{name}_duration_seconds',
                    duration,
                    labels={
                        'method': func.__name__
                    }
                )

        return cast(F, wrapped)
    return decorator

class SystemMetrics:
    @staticmethod
    def get_system_metrics() -> dict:
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
    def get_db_metrics() -> dict:
        """Collect database metrics"""
        return {
            'active_connections': db.engine.pool.status()['checkedout'],
            'total_queries': 0,  # Replace with actual logic to fetch total queries
            'slow_queries': 0,  # Replace with actual logic to fetch slow queries
            'query_errors': 0,  # Replace with actual logic to fetch query errors
            'table_sizes': db.session.execute(
                "SELECT relname, pg_size_pretty(pg_total_relation_size(relname::regclass)) FROM pg_stat_user_tables"
            ).fetchall()
        }

class Application:
    pass
