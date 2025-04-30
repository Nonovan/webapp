"""
Monitoring Service for the Cloud Infrastructure Platform.

This service provides functionalities related to system monitoring, health checks,
metrics collection, and potentially interacting with alerting systems.
"""

import logging
from typing import Dict, Any, Optional, Tuple, List
from sqlalchemy.exc import SQLAlchemyError
import psutil
from datetime import datetime

# Attempt to import core utilities and extensions
try:
    from flask import current_app
    from extensions import db, cache, metrics
    from core.security.cs_utils import get_security_config
    from core.security.cs_audit import log_security_event
    from core.utils import log_error, log_info, log_warning
    from models.audit_log import AuditLog # Assuming AuditLog might be used
    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False
    # Define dummy functions/classes if core components are missing
    def log_security_event(*args, **kwargs): pass
    def get_security_config(key: str, default: Any = None) -> Any: return default
    def log_error(msg: str, *args): print(f"ERROR: {msg}")
    def log_info(msg: str, *args): print(f"INFO: {msg}")
    def log_warning(msg: str, *args): print(f"WARNING: {msg}")
    class DummyMetrics:
        def increment(self, *args, **kwargs): pass
        def gauge(self, *args, **kwargs): pass
        def summary(self, *args, **kwargs): pass
    metrics = DummyMetrics()
    current_app = None # type: ignore
    db = None # type: ignore
    cache = None # type: ignore
    class AuditLog: # type: ignore
        EVENT_MONITORING_ERROR = "monitoring_error"
        EVENT_HEALTH_CHECK_FAILED = "health_check_failed"

logger = logging.getLogger(__name__)

# Default configuration values (can be overridden by app config)
DEFAULT_CPU_THRESHOLD = 90.0
DEFAULT_MEMORY_THRESHOLD = 90.0
DEFAULT_DISK_THRESHOLD = 90.0

class MonitoringService:
    """
    Provides monitoring-related services like health checks and metrics collection.
    """

    @staticmethod
    def get_system_status(include_security: bool = False) -> Dict[str, Any]:
        """
        Collects and returns the current system status, including basic metrics.

        Args:
            include_security: Whether to include security-related metrics.

        Returns:
            A dictionary containing system status information.
        """
        log_info("Collecting system status...")
        status_data: Dict[str, Any] = {
            'timestamp': datetime.utcnow().isoformat(),
            'system': {},
            'application': {},
            'database': {},
        }

        try:
            # System Metrics
            status_data['system'] = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'load_average': psutil.getloadavg(),
            }
            metrics.gauge('system.cpu.usage', status_data['system']['cpu_percent'])
            metrics.gauge('system.memory.usage', status_data['system']['memory_percent'])
            metrics.gauge('system.disk.usage', status_data['system']['disk_percent'])

            # Application Metrics (Example - replace with actual app metrics)
            if CORE_AVAILABLE and current_app:
                 status_data['application'] = {
                     'environment': current_app.config.get('ENVIRONMENT', 'unknown'),
                     'version': current_app.config.get('VERSION', 'unknown'),
                     # Add more app-specific metrics here
                 }

            # Database Status (Basic check)
            db_healthy, db_details = MonitoringService.check_database_connection()
            status_data['database'] = {
                'status': 'healthy' if db_healthy else 'unhealthy',
                'details': db_details
            }

            # Cache Status (Basic check)
            cache_healthy, cache_details = MonitoringService.check_cache_connection()
            status_data['cache'] = {
                'status': 'healthy' if cache_healthy else 'unhealthy',
                'details': cache_details
            }

            # Security Metrics (Optional)
            if include_security:
                # Placeholder: Integrate with SecurityService or core security functions
                # status_data['security'] = SecurityService.get_security_summary()
                status_data['security'] = {"status": "not_implemented"}


        except Exception as e:
            log_error(f"Failed to collect system status: {e}")
            status_data['error'] = str(e)
            log_security_event(
                event_type=getattr(AuditLog, 'EVENT_MONITORING_ERROR', 'monitoring_error'),
                description=f"Error collecting system status: {e}",
                severity="medium"
            )

        return status_data

    @staticmethod
    def perform_health_check() -> Tuple[bool, Dict[str, Any]]:
        """
        Performs a comprehensive health check of critical system components.

        Returns:
            A tuple containing the overall health status (bool) and detailed results.
        """
        log_info("Performing health check...")
        overall_healthy = True
        details: Dict[str, Any] = {
            'timestamp': datetime.utcnow().isoformat(),
            'components': {}
        }

        # Check Database
        db_healthy, db_details = MonitoringService.check_database_connection()
        details['components']['database'] = {'status': 'healthy' if db_healthy else 'unhealthy', 'details': db_details}
        if not db_healthy: overall_healthy = False

        # Check Cache
        cache_healthy, cache_details = MonitoringService.check_cache_connection()
        details['components']['cache'] = {'status': 'healthy' if cache_healthy else 'unhealthy', 'details': cache_details}
        if not cache_healthy: overall_healthy = False # Cache might be critical

        # Check Filesystem Access (Example)
        fs_healthy, fs_details = MonitoringService.check_filesystem_access()
        details['components']['filesystem'] = {'status': 'healthy' if fs_healthy else 'unhealthy', 'details': fs_details}
        if not fs_healthy: overall_healthy = False

        # Check Resource Thresholds
        res_healthy, res_details = MonitoringService.check_resource_thresholds()
        details['components']['resources'] = {'status': 'healthy' if res_healthy else 'warning', 'details': res_details}
        # Resource warnings might not make the system unhealthy, but degraded

        details['overall_status'] = 'healthy' if overall_healthy else 'unhealthy'

        if not overall_healthy:
            log_warning(f"Health check failed. Details: {details}")
            log_security_event(
                event_type=getattr(AuditLog, 'EVENT_HEALTH_CHECK_FAILED', 'health_check_failed'),
                description="System health check failed.",
                severity="high",
                details=details['components']
            )

        return overall_healthy, details

    @staticmethod
    def check_database_connection() -> Tuple[bool, str]:
        """Checks the database connection."""
        if not db:
            return False, "Database extension not available"
        try:
            # Use a simple query to check connection
            db.session.execute('SELECT 1')
            return True, "Connection successful"
        except SQLAlchemyError as e:
            log_error(f"Database connection check failed: {e}")
            return False, str(e)
        except Exception as e:
            log_error(f"Unexpected error checking database connection: {e}")
            return False, f"Unexpected error: {e}"

    @staticmethod
    def check_cache_connection() -> Tuple[bool, str]:
        """Checks the cache connection (assuming Redis)."""
        if not cache:
            return False, "Cache extension not available"
        try:
            # Use a simple command like PING
            if hasattr(cache, 'ping') and callable(cache.ping):
                if cache.ping():
                    return True, "Connection successful (PING)"
                else:
                    return False, "PING command failed"
            else:
                # Fallback: try setting and getting a key
                cache.set('health_check_key', 'ok', timeout=5)
                if cache.get('health_check_key') == 'ok':
                    return True, "Connection successful (SET/GET)"
                else:
                    return False, "SET/GET check failed"
        except Exception as e:
            log_error(f"Cache connection check failed: {e}")
            return False, str(e)

    @staticmethod
    def check_filesystem_access() -> Tuple[bool, str]:
        """Checks basic filesystem write access in a temporary location."""
        try:
            temp_dir = current_app.config.get('TEMP_FOLDER', '/tmp') if current_app else '/tmp'
            test_file_path = os.path.join(temp_dir, f"health_check_{datetime.utcnow().timestamp()}.tmp")
            with open(test_file_path, "w") as f:
                f.write("health_check")
            os.remove(test_file_path)
            return True, "Write access successful"
        except IOError as e:
            log_error(f"Filesystem access check failed: {e}")
            return False, str(e)
        except Exception as e:
            log_error(f"Unexpected error checking filesystem access: {e}")
            return False, f"Unexpected error: {e}"

    @staticmethod
    def check_resource_thresholds() -> Tuple[bool, Dict[str, Any]]:
        """Checks if system resources are within defined thresholds."""
        details: Dict[str, Any] = {}
        all_ok = True

        try:
            cpu_threshold = float(get_security_config('CPU_THRESHOLD', DEFAULT_CPU_THRESHOLD))
            mem_threshold = float(get_security_config('MEMORY_THRESHOLD', DEFAULT_MEMORY_THRESHOLD))
            disk_threshold = float(get_security_config('DISK_THRESHOLD', DEFAULT_DISK_THRESHOLD))

            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent

            details['cpu'] = {'usage': cpu, 'threshold': cpu_threshold, 'status': 'ok'}
            details['memory'] = {'usage': mem, 'threshold': mem_threshold, 'status': 'ok'}
            details['disk'] = {'usage': disk, 'threshold': disk_threshold, 'status': 'ok'}

            if cpu >= cpu_threshold:
                details['cpu']['status'] = 'warning'
                all_ok = False
                log_warning(f"CPU usage ({cpu}%) exceeds threshold ({cpu_threshold}%)")
            if mem >= mem_threshold:
                details['memory']['status'] = 'warning'
                all_ok = False
                log_warning(f"Memory usage ({mem}%) exceeds threshold ({mem_threshold}%)")
            if disk >= disk_threshold:
                details['disk']['status'] = 'warning'
                all_ok = False
                log_warning(f"Disk usage ({disk}%) exceeds threshold ({disk_threshold}%)")

        except Exception as e:
            log_error(f"Failed to check resource thresholds: {e}")
            details['error'] = str(e)
            all_ok = False # Treat error as failure

        return all_ok, details

    # Potential future methods:
    # @staticmethod
    # def trigger_alert(severity: str, summary: str, details: Dict[str, Any]):
    #     """Integrates with an alerting system (e.g., Alertmanager, PagerDuty)."""
    #     pass

    # @staticmethod
    # def get_metrics_snapshot(categories: Optional[List[str]] = None) -> Dict[str, Any]:
    #     """Collects a snapshot of various metrics categories."""
    #     pass

# Example usage within the service file (for testing/dev)
if __name__ == '__main__':
    import os # Ensure os is imported for filesystem check example
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("Running MonitoringService standalone checks...")

    print("\n--- System Status ---")
    status = MonitoringService.get_system_status(include_security=True)
    import json
    print(json.dumps(status, indent=2))

    print("\n--- Health Check ---")
    healthy, health_details = MonitoringService.perform_health_check()
    print(f"Overall Health: {'Healthy' if healthy else 'Unhealthy'}")
    print(json.dumps(health_details, indent=2))

    print("\n--- Resource Check ---")
    res_ok, res_details = MonitoringService.check_resource_thresholds()
    print(f"Resource Status: {'OK' if res_ok else 'Warning'}")
    print(json.dumps(res_details, indent=2))
