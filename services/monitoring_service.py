"""
Monitoring Service for the Cloud Infrastructure Platform.

This service provides functionalities related to system monitoring, health checks,
metrics collection, and potentially interacting with alerting systems.
"""

import logging
import os
import json
import socket
from typing import Dict, Any, Optional, Tuple, List, Union
from sqlalchemy.exc import SQLAlchemyError
import psutil
import requests
from datetime import datetime, timedelta

# Attempt to import core utilities and extensions
try:
    from flask import current_app, has_app_context
    from extensions import db, cache, metrics
    from core.security.cs_utils import get_security_config
    from core.security.cs_audit import log_security_event
    from core.utils import log_error, log_info, log_warning, log_debug
    from models.security.audit_log import AuditLog
    from services.notification_service import send_system_notification
    CORE_AVAILABLE = True
except ImportError as e:
    CORE_AVAILABLE = False
    # Define dummy functions/classes if core components are missing
    def log_security_event(*args, **kwargs): pass
    def get_security_config(key: str, default: Any = None) -> Any: return default
    def log_error(msg: str, *args): print(f"ERROR: {msg}")
    def log_info(msg: str, *args): print(f"INFO: {msg}")
    def log_warning(msg: str, *args): print(f"WARNING: {msg}")
    def log_debug(msg: str, *args): print(f"DEBUG: {msg}")
    def send_system_notification(*args, **kwargs): pass
    def has_app_context(): return False
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
        EVENT_RESOURCE_THRESHOLD_EXCEEDED = "resource_threshold_exceeded"

logger = logging.getLogger(__name__)

# Default configuration values (can be overridden by app config)
DEFAULT_CPU_THRESHOLD = 90.0
DEFAULT_MEMORY_THRESHOLD = 90.0
DEFAULT_DISK_THRESHOLD = 90.0
DEFAULT_LOAD_THRESHOLD = 2.0
DEFAULT_TIMEOUT = 5
DEFAULT_RETRY_COUNT = 3

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
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'uptime_seconds': int(datetime.now().timestamp() - psutil.boot_time()),
                'network': {
                    'connections': len(psutil.net_connections()),
                }
            }
            metrics.gauge('system.cpu.usage', status_data['system']['cpu_percent'])
            metrics.gauge('system.memory.usage', status_data['system']['memory_percent'])
            metrics.gauge('system.disk.usage', status_data['system']['disk_percent'])
            metrics.gauge('system.load_avg', status_data['system']['load_average'][0])

            # Application Metrics (Example - replace with actual app metrics)
            if CORE_AVAILABLE and has_app_context():
                 status_data['application'] = {
                     'environment': current_app.config.get('ENVIRONMENT', 'unknown'),
                     'version': current_app.config.get('VERSION', 'unknown'),
                     'start_time': getattr(current_app, 'start_time', 'unknown'),
                     'uptime': str(datetime.utcnow() - getattr(current_app, 'start_time', datetime.utcnow()))
                                if hasattr(current_app, 'start_time') else 'unknown',
                 }

                 # Add more app-specific metrics if available
                 try:
                     from extensions import get_app_metrics
                     app_metrics = get_app_metrics()
                     status_data['application'].update(app_metrics)
                 except (ImportError, AttributeError):
                     pass

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

            # Network Status
            network_healthy, network_details = MonitoringService.check_network_connectivity()
            status_data['network'] = {
                'status': 'healthy' if network_healthy else 'unhealthy',
                'details': network_details
            }

            # Security Metrics (Optional)
            if include_security:
                try:
                    from services.security_service import SecurityService
                    security_summary = SecurityService.get_security_summary()
                    status_data['security'] = security_summary
                except (ImportError, AttributeError):
                    status_data['security'] = {"status": "module_not_available"}

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

        # Check Filesystem Access
        fs_healthy, fs_details = MonitoringService.check_filesystem_access()
        details['components']['filesystem'] = {'status': 'healthy' if fs_healthy else 'unhealthy', 'details': fs_details}
        if not fs_healthy: overall_healthy = False

        # Check Resource Thresholds
        res_healthy, res_details = MonitoringService.check_resource_thresholds()
        details['components']['resources'] = {'status': 'healthy' if res_healthy else 'warning', 'details': res_details}
        # Resource warnings might not make the system unhealthy, but degraded

        # Check Network Connectivity
        net_healthy, net_details = MonitoringService.check_network_connectivity()
        details['components']['network'] = {'status': 'healthy' if net_healthy else 'warning', 'details': net_details}
        # Network issues may indicate degraded service, but not completely unhealthy

        details['overall_status'] = 'healthy' if overall_healthy else 'unhealthy'

        if not overall_healthy:
            log_warning(f"Health check failed. Details: {details}")
            log_security_event(
                event_type=getattr(AuditLog, 'EVENT_HEALTH_CHECK_FAILED', 'health_check_failed'),
                description="System health check failed.",
                severity="high",
                details=details['components']
            )

            # Send notification to administrators if configured
            try:
                if CORE_AVAILABLE and has_app_context():
                    admin_notify = current_app.config.get('NOTIFY_ADMINS_ON_HEALTH_FAILURE', False)
                    if admin_notify:
                        admin_ids = MonitoringService._get_admin_user_ids()
                        if admin_ids:
                            component_issues = [
                                f"{comp}: {details['components'][comp]['details']}"
                                for comp in details['components']
                                if details['components'][comp]['status'] != 'healthy'
                            ]
                            send_system_notification(
                                user_ids=admin_ids,
                                message=f"System health check failed. Issues: {', '.join(component_issues)}",
                                title="System Health Alert",
                                priority="high",
                                action_url="/admin/monitoring/health"
                            )
            except Exception as e:
                log_error(f"Failed to send health check notification: {e}")

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
            temp_dir = current_app.config.get('TEMP_FOLDER', '/tmp') if has_app_context() else '/tmp'
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
            load_threshold = float(get_security_config('LOAD_THRESHOLD', DEFAULT_LOAD_THRESHOLD))

            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            load = psutil.getloadavg()[0]  # 1-minute load average

            # Get CPU count to normalize load average
            cpu_count = psutil.cpu_count(logical=True) or 1
            normalized_load = load / cpu_count

            details['cpu'] = {'usage': cpu, 'threshold': cpu_threshold, 'status': 'ok'}
            details['memory'] = {'usage': mem, 'threshold': mem_threshold, 'status': 'ok'}
            details['disk'] = {'usage': disk, 'threshold': disk_threshold, 'status': 'ok'}
            details['load'] = {
                'value': load,
                'normalized': normalized_load,
                'threshold': load_threshold,
                'status': 'ok'
            }

            # Check thresholds and update status accordingly
            threshold_exceeded = False

            if cpu >= cpu_threshold:
                details['cpu']['status'] = 'warning'
                all_ok = False
                threshold_exceeded = True
                log_warning(f"CPU usage ({cpu}%) exceeds threshold ({cpu_threshold}%)")

            if mem >= mem_threshold:
                details['memory']['status'] = 'warning'
                all_ok = False
                threshold_exceeded = True
                log_warning(f"Memory usage ({mem}%) exceeds threshold ({mem_threshold}%)")

            if disk >= disk_threshold:
                details['disk']['status'] = 'warning'
                all_ok = False
                threshold_exceeded = True
                log_warning(f"Disk usage ({disk}%) exceeds threshold ({disk_threshold}%)")

            if normalized_load >= load_threshold:
                details['load']['status'] = 'warning'
                all_ok = False
                threshold_exceeded = True
                log_warning(f"System load ({load}/{cpu_count} cores = {normalized_load:.2f}) exceeds threshold ({load_threshold})")

            # If any threshold was exceeded, log a security event
            if threshold_exceeded:
                log_security_event(
                    event_type=getattr(AuditLog, 'EVENT_RESOURCE_THRESHOLD_EXCEEDED', 'resource_threshold_exceeded'),
                    description="System resource thresholds exceeded.",
                    severity="medium",
                    details=details
                )

        except Exception as e:
            log_error(f"Failed to check resource thresholds: {e}")
            details['error'] = str(e)
            all_ok = False # Treat error as failure

        return all_ok, details

    @staticmethod
    def check_network_connectivity() -> Tuple[bool, Dict[str, Any]]:
        """Checks basic network connectivity."""
        details = {
            'dns_resolution': False,
            'internet_connectivity': False,
            'services': {}
        }

        all_ok = True

        # Check DNS resolution
        try:
            socket.gethostbyname('google.com')
            details['dns_resolution'] = True
        except Exception as e:
            log_warning(f"DNS resolution check failed: {e}")
            details['dns_resolution'] = False
            details['dns_error'] = str(e)
            all_ok = False

        # Check internet connectivity with a simple HTTP request
        try:
            response = requests.get('https://www.google.com', timeout=DEFAULT_TIMEOUT)
            details['internet_connectivity'] = response.status_code == 200
            if not details['internet_connectivity']:
                all_ok = False
                details['internet_error'] = f"Status code: {response.status_code}"
        except Exception as e:
            log_warning(f"Internet connectivity check failed: {e}")
            details['internet_connectivity'] = False
            details['internet_error'] = str(e)
            all_ok = False

        # Check connections to critical services
        services = []

        # Get configured service endpoints
        if CORE_AVAILABLE and has_app_context():
            service_endpoints = current_app.config.get('MONITORED_SERVICES', {})
            for service_name, config in service_endpoints.items():
                host = config.get('host')
                port = config.get('port')
                if host and port:
                    services.append((service_name, host, port))

        # Check each service
        for service_name, host, port in services:
            service_status = MonitoringService._check_tcp_connection(host, port)
            details['services'][service_name] = {
                'host': host,
                'port': port,
                'status': 'up' if service_status else 'down'
            }
            if not service_status:
                all_ok = False

        return all_ok, details

    @staticmethod
    def _check_tcp_connection(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> bool:
        """Checks if a TCP connection can be established to the given host and port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            log_debug(f"TCP connection check to {host}:{port} failed: {e}")
            return False

    @staticmethod
    def trigger_alert(severity: str, summary: str, details: Dict[str, Any]) -> bool:
        """
        Integrates with an alerting system (e.g., Alertmanager, PagerDuty).

        Args:
            severity: Alert severity level ('info', 'warning', 'error', 'critical')
            summary: Brief summary of the alert
            details: Detailed information about the alert

        Returns:
            bool: True if alert was successfully sent, False otherwise
        """
        try:
            # If notification service is available, use it
            if CORE_AVAILABLE:
                admin_ids = MonitoringService._get_admin_user_ids()
                if admin_ids:
                    send_system_notification(
                        user_ids=admin_ids,
                        message=summary,
                        title=f"System Alert: {severity.upper()}",
                        priority=severity,
                        data=details
                    )
                    log_info(f"Alert triggered: {severity} - {summary}")
                    return True

            # External alert integration could be added here
            # For example, sending to Alertmanager, PagerDuty, Slack, etc.

            # For now, just log the alert
            log_warning(f"ALERT [{severity.upper()}]: {summary} - {json.dumps(details)}")
            return True

        except Exception as e:
            log_error(f"Failed to trigger alert: {e}")
            return False

    @staticmethod
    def get_metrics_snapshot(categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collects a snapshot of various metrics categories.

        Args:
            categories: Optional list of metric categories to include
                       (e.g., ['system', 'database', 'application'])

        Returns:
            Dict containing metrics organized by category
        """
        all_categories = {'system', 'application', 'database', 'cache', 'security', 'network'}
        if categories:
            selected_categories = set(categories) & all_categories
        else:
            selected_categories = all_categories

        metrics_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'metrics': {}
        }

        # System metrics
        if 'system' in selected_categories:
            metrics_data['metrics']['system'] = {
                'cpu': {
                    'percent': psutil.cpu_percent(interval=1),
                    'count': psutil.cpu_count(),
                    'load_avg': psutil.getloadavg()
                },
                'memory': {
                    'percent': psutil.virtual_memory().percent,
                    'available_mb': psutil.virtual_memory().available / (1024 * 1024),
                    'total_mb': psutil.virtual_memory().total / (1024 * 1024)
                },
                'disk': {
                    'percent': psutil.disk_usage('/').percent,
                    'free_gb': psutil.disk_usage('/').free / (1024 * 1024 * 1024),
                    'total_gb': psutil.disk_usage('/').total / (1024 * 1024 * 1024)
                },
                'network': {
                    'connections': len(psutil.net_connections())
                }
            }

        # Additional metric categories could be implemented similarly
        # For now, we'll return what we have
        return metrics_data

    @staticmethod
    def _get_admin_user_ids() -> List[int]:
        """
        Gets a list of admin user IDs for notifications.

        Returns:
            List of admin user IDs
        """
        admin_ids = []
        if CORE_AVAILABLE and db:
            try:
                # Try to import User model
                from models.auth.user import User
                from models.auth.role import Role

                # Query for users with admin role
                admin_role = Role.query.filter_by(name='admin').first()
                if admin_role:
                    admin_users = User.query.filter_by(role_id=admin_role.id, status='active').all()
                    admin_ids = [user.id for user in admin_users]

                # Fallback to users with admin in their role field (legacy compatibility)
                if not admin_ids:
                    admin_users = User.query.filter(User.role.like('%admin%')).all()
                    admin_ids = [user.id for user in admin_users]
            except (ImportError, SQLAlchemyError) as e:
                log_warning(f"Failed to retrieve admin users: {e}")

        return admin_ids

    @staticmethod
    def monitor_service_endpoints(timeout: int = DEFAULT_TIMEOUT, retry_count: int = DEFAULT_RETRY_COUNT) -> Dict[str, Any]:
        """
        Monitors the health of configured service endpoints.

        Args:
            timeout: Timeout in seconds for each service check
            retry_count: Number of retries per endpoint before marking as failed

        Returns:
            Dict containing endpoint status information
        """
        if not CORE_AVAILABLE or not has_app_context():
            return {"error": "Core components not available"}

        service_endpoints = current_app.config.get('SERVICE_ENDPOINTS', {})
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'endpoints': {},
            'healthy_count': 0,
            'total_count': len(service_endpoints)
        }

        for name, config in service_endpoints.items():
            url = config.get('url')
            if not url:
                continue

            method = config.get('method', 'GET')
            headers = config.get('headers', {})
            expected_status = config.get('expected_status', 200)

            endpoint_result = {
                'url': url,
                'status': 'failed',
                'response_time_ms': None,
                'retry_count': 0
            }

            # Perform the check with retries
            for attempt in range(retry_count):
                try:
                    start_time = datetime.now()
                    response = requests.request(
                        method=method,
                        url=url,
                        headers=headers,
                        timeout=timeout
                    )
                    elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000

                    endpoint_result['status_code'] = response.status_code
                    endpoint_result['response_time_ms'] = elapsed_ms

                    if response.status_code == expected_status:
                        endpoint_result['status'] = 'healthy'
                        results['healthy_count'] += 1
                        break
                    else:
                        endpoint_result['status'] = 'failed'
                        endpoint_result['retry_count'] = attempt + 1
                        log_warning(f"Service endpoint {name} check failed: " +
                                   f"Expected status {expected_status}, got {response.status_code}")
                except requests.RequestException as e:
                    endpoint_result['status'] = 'failed'
                    endpoint_result['error'] = str(e)
                    endpoint_result['retry_count'] = attempt + 1
                    log_warning(f"Service endpoint {name} check failed: {e}")

            results['endpoints'][name] = endpoint_result

        return results


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

    print("\n--- Network Check ---")
    net_ok, net_details = MonitoringService.check_network_connectivity()
    print(f"Network Status: {'OK' if net_ok else 'Warning'}")
    print(json.dumps(net_details, indent=2))
