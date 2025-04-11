import os
from datetime import datetime, timedelta
from typing import Dict, Any
import psutil
from flask import current_app
from sqlalchemy import text
from extensions import metrics, db, cache
from models.user import User

class SystemMetrics:
    class MetricsError(Exception):
        """System metrics specific errors."""
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'SYSTEM_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=30)
    def get_system_metrics() -> Dict[str, Any]:
        """Collect system-level metrics."""
        try:
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
        except (psutil.Error, AttributeError, KeyError, TypeError) as e:
            raise SystemMetrics.MetricsError(f"System metrics error: {e}") from e

    @staticmethod
    @cache.memoize(timeout=30)
    def get_process_metrics() -> Dict[str, Any]:
        """Collect process-specific metrics."""
        try:
            process = psutil.Process(os.getpid())
            return {
                'memory_used': process.memory_info().rss / 1024 / 1024,  # MB
                'cpu_percent': process.cpu_percent(),
                'threads': process.num_threads(),
                'open_files': len(process.open_files()),
                'connections': len(process.connections())
            }
        except (psutil.Error, AttributeError) as e:
            raise SystemMetrics.MetricsError(f"Process metrics error: {e}") from e

class DatabaseMetrics:
    class MetricsError(Exception):
        """Database metrics specific errors."""
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'DATABASE_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=30)
    @staticmethod
    @cache.memoize(timeout=30)
    @staticmethod
    def get_db_metrics() -> Dict[str, Any]:
        """Collect database performance metrics."""
        try:
            with db.engine.connect() as conn:
                # Get database metrics
                db_size = conn.execute(text(
                    "SELECT pg_size_pretty(pg_database_size(current_database()))"
                )).scalar()

                active_connections = conn.execute(text(
                    "SELECT count(*) FROM pg_stat_activity"
                )).scalar()

                deadlocks = conn.execute(text(
                    "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()"
                )).scalar()

                # Access pool status through correct attributes
                connection_pool = db.engine.pool
                pool_status = {}

                if hasattr(connection_pool, 'status') and callable(connection_pool.status):
                    pool_status = connection_pool.status()

                # Safely access pool status with proper error handling
                return {
                    'database_size': db_size,
                    'active_connections': active_connections,
                    'deadlocks': deadlocks,
                    'pool_size': pool_status['size'] if isinstance(pool_status, dict) and 'size' in pool_status else 0,
                    'in_use': pool_status['checkedin'] if isinstance(pool_status, dict) and 'checkedin' in pool_status else 0
                }
        except Exception as e:
            raise DatabaseMetrics.MetricsError(f"Database metrics error: {e}") from e

class ApplicationMetrics:
    class MetricsError(Exception):
        """Application metrics specific errors."""
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'APPLICATION_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=60)
    @staticmethod
    @cache.memoize(timeout=60)
    def get_app_metrics() -> Dict[str, Any]:
        """Collect application-specific metrics."""
        try:
            # Access metrics directly or use appropriate method instead of get_metric
            # PrometheusMetrics doesn't have get_metric method
            metric_request_data = 0
            metric_error_data = 0

            # Try to access metrics if they exist in the metrics registry
            if hasattr(metrics, 'registry'):
                for metric in metrics.registry.collect():
                    if metric.name == 'requests_total':
                        for sample in metric.samples:
                            metric_request_data += sample.value
                    if metric.name == 'errors_total':
                        for sample in metric.samples:
                            metric_error_data += sample.value

            return {
                'total_users': User.query.count(),
                'active_users': User.query.filter(
                    User.last_login > (datetime.utcnow() - timedelta(minutes=5))
                ).count(),
                'uptime': str(datetime.utcnow() - current_app.uptime),
                'version': current_app.config.get('VERSION', '1.0.0'),
                'requests_total': metric_request_data,
                'errors_total': metric_error_data
            }
        except Exception as e:
            raise ApplicationMetrics.MetricsError(f"Application metrics error: {e}") from e

class EnvironmentalData:
    class MetricsError(Exception):
        """Environmental metrics specific errors."""
        def __init__(self, message: str) -> None:
            self.message = message
            self.error_code = 'ENVIRONMENTAL_METRICS_ERROR'
            super().__init__(self.message)

    @staticmethod
    @cache.memoize(timeout=30)
    def get_env_metrics() -> Dict[str, Any]:
        """Collect environmental metrics."""
        try:
            return {
                'battery': psutil.sensors_battery()._asdict() if psutil.sensors_battery() else {},
                'network_interfaces': {
                    name: [addr.__dict__ for addr in addrs]
                    for name, addrs in psutil.net_if_addrs().items()
                }
            }
        except Exception as e:
            raise EnvironmentalData.MetricsError(f"Environmental metrics error: {e}") from e

    timestamp = db.Column(db.DateTime, nullable=False)  # Add the timestamp attribute


@cache.memoize(timeout=60)
def get_all_metrics() -> Dict[str, Any]:
    """Collect all system, database and application metrics."""
    try:
        metrics_data = {
            'system': SystemMetrics.get_system_metrics(),
            'process': SystemMetrics.get_process_metrics(),
            'database': DatabaseMetrics.get_db_metrics(),
            'application': ApplicationMetrics.get_app_metrics(),
            'environment': EnvironmentalData.get_env_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }
        metrics.info('metrics_collection_success', 1)
        return metrics_data

    except (SystemMetrics.MetricsError, DatabaseMetrics.MetricsError,
            EnvironmentalData.MetricsError, ApplicationMetrics.MetricsError) as e:
        current_app.logger.error(f"Metrics collection error: {e}")
        metrics.info('metrics_collection_error', 1, labels={'type': e.error_code})
        return {
            'error': str(e),
            'code': e.error_code,
            'timestamp': datetime.utcnow().isoformat()
        }

    except (psutil.Error, AttributeError, KeyError, TypeError, RuntimeError) as e:
        current_app.logger.error(f"Unexpected metrics error: {e}")
        metrics.info('metrics_collection_error', 1, labels={'type': 'unknown'})
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
