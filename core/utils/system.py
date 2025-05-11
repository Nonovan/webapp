"""
System utility functions for Cloud Infrastructure Platform.

This module provides system resource monitoring, process information gathering,
request context extraction, and performance measurement utilities. These functions
help with monitoring system health, diagnosing performance issues, and providing
operational metrics.
"""

import base64
import glob
import hashlib
import json
import logging
import os
import pwd
import socket
import stat
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple, Union, NamedTuple

import psutil
from flask import current_app, g, has_app_context, has_request_context, request

from .date_time import format_timestamp
from .logging_utils import log_error, log_warning
from .core_utils_constants import (
    # System operation constants
    DEFAULT_TIMEOUT,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    DEFAULT_PROCESS_TIMEOUT,
    DEFAULT_LOCK_TIMEOUT,
    DEFAULT_MAX_PROCESSES,
    DEFAULT_MAX_THREADS,
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_OPEN_FILES,
    CPU_WARNING_THRESHOLD,
    MEMORY_WARNING_THRESHOLD,
    DISK_WARNING_THRESHOLD,
    OPEN_FILES_WARNING_THRESHOLD,
    DEFAULT_MONITOR_INTERVAL,
    DEFAULT_SLOW_THRESHOLD,

    # File operation constant
    DEFAULT_CHUNK_SIZE
)

# Type definitions
ResourceMetrics = Dict[str, Any]
ProcessInfo = Dict[str, Any]
RequestContext = Dict[str, Any]

# Setup module-level logger
logger = logging.getLogger(__name__)


class Timer(NamedTuple):
    """Timer class for execution time measurements."""
    duration: float


def get_system_resources() -> ResourceMetrics:
    """
    Get current system resource usage.

    Returns:
        Dictionary containing CPU, memory, and disk usage information with warnings
        when thresholds are exceeded.

    Example:
        {
            'cpu': {'percent': 12.5, 'count': 8},
            'memory': {'total': 16777216, 'available': 8388608, 'percent': 50.0},
            'disk': {'total': 1073741824, 'used': 536870912, 'percent': 50.0},
            'timestamp': '2023-01-01T12:00:00+00:00',
            'warnings': ['Disk usage above threshold: 92%']
        }
    """
    try:
        # Collect basic system metrics safely
        warnings = []

        # Get CPU information with a short interval for responsiveness
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count_logical = psutil.cpu_count(logical=True)
            cpu_count_physical = psutil.cpu_count(logical=False) or 1  # Fallback if None

            if cpu_percent > CPU_WARNING_THRESHOLD:
                warnings.append(f"CPU usage above threshold: {cpu_percent}%")

            cpu_info = {
                'percent': cpu_percent,
                'count': cpu_count_logical,
                'physical_count': cpu_count_physical,
                'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else None
            }
        except Exception as e:
            logger.debug(f"Error collecting CPU metrics: {e}")
            cpu_info = {'error': str(e)}

        # Get memory information
        try:
            mem = psutil.virtual_memory()
            memory_info = {
                'total': mem.total,
                'available': mem.available,
                'used': mem.used,
                'percent': mem.percent,
                'total_gb': round(mem.total / (1024**3), 2),
                'available_gb': round(mem.available / (1024**3), 2)
            }

            if mem.percent > MEMORY_WARNING_THRESHOLD:
                warnings.append(f"Memory usage above threshold: {mem.percent}%")
        except Exception as e:
            logger.debug(f"Error collecting memory metrics: {e}")
            memory_info = {'error': str(e)}

        # Get disk information
        try:
            disk_info = psutil.disk_usage('/')
            disk_data = {
                'total': disk_info.total,
                'used': disk_info.used,
                'free': disk_info.free,
                'percent': disk_info.percent,
                'total_gb': round(disk_info.total / (1024**3), 2),
                'free_gb': round(disk_info.free / (1024**3), 2)
            }

            if disk_info.percent > DISK_WARNING_THRESHOLD:
                warnings.append(f"Disk usage above threshold: {disk_info.percent}%")
        except Exception as e:
            logger.debug(f"Error collecting disk metrics: {e}")
            disk_data = {'error': str(e)}

        # Get network information
        try:
            try:
                net_connections = len(psutil.net_connections(kind='inet'))
            except (psutil.AccessDenied, psutil.Error):
                net_connections = -1

            network_info = {
                'connections': net_connections,
                'interfaces': list(psutil.net_if_addrs().keys()),
                'hostname': socket.gethostname()
            }

            if net_connections > DEFAULT_MAX_CONNECTIONS:
                warnings.append(f"High number of network connections: {net_connections}")
        except Exception as e:
            logger.debug(f"Error collecting network metrics: {e}")
            network_info = {'error': str(e)}

        # Build the complete resource metrics
        resources = {
            'cpu': cpu_info,
            'memory': memory_info,
            'disk': disk_data,
            'network': network_info,
            'timestamp': format_timestamp(),
            'platform': {
                'system': os.name,
                'node': socket.gethostname(),
                'release': os.uname().release if hasattr(os, 'uname') else 'unknown',
            }
        }

        # Add boot time if available
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
            resources['boot_time'] = boot_time.isoformat()

            # Calculate uptime in seconds
            uptime = (datetime.now(timezone.utc) - boot_time).total_seconds()
            resources['uptime_seconds'] = int(uptime)
        except (AttributeError, OSError) as e:
            logger.debug(f"Error getting boot time: {e}")

        # Add warnings if any thresholds were exceeded
        if warnings:
            resources['warnings'] = warnings

        return resources
    except Exception as e:
        log_error(f"Error collecting system resources: {e}")
        return {
            'error': str(e),
            'timestamp': format_timestamp(),
            'status': 'error'
        }


def get_process_info() -> ProcessInfo:
    """
    Get information about the current process.

    Returns:
        Dictionary containing process memory usage, threads, and connections with
        warnings when thresholds are exceeded.

    Example:
        {
            'memory': {'bytes': 123456789, 'mb': 120.5, 'percent': 3.2},
            'cpu_percent': 2.5,
            'threads': 4,
            'connections': 8,
            'open_files': 15,
            'start_time': '2023-01-01T12:00:00+00:00',
            'timestamp': '2023-01-01T12:30:00+00:00',
            'warnings': ['Open files count approaching limit: 850/1000']
        }
    """
    try:
        process = psutil.Process()
        warnings = []

        # Calculate memory in different formats for better visibility
        try:
            mem_info = process.memory_info()
            memory_bytes = mem_info.rss
            memory_mb = memory_bytes / (1024 * 1024)
            memory_percent = process.memory_percent()
            memory_info = {
                'bytes': memory_bytes,
                'mb': round(memory_mb, 2),
                'percent': round(memory_percent, 2)
            }
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Error collecting process memory info: {e}")
            memory_info = {'error': str(e)}

        # Get file and connection information safely
        try:
            open_files = len(process.open_files())
            if open_files > DEFAULT_MAX_OPEN_FILES * (OPEN_FILES_WARNING_THRESHOLD / 100):
                warnings.append(f"Open files count approaching limit: {open_files}/{DEFAULT_MAX_OPEN_FILES}")
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Error collecting open files info: {e}")
            open_files = -1

        try:
            connections = len(process.connections())
            if connections > DEFAULT_MAX_CONNECTIONS * 0.8:  # Warning at 80% of limit
                warnings.append(f"Connection count approaching limit: {connections}/{DEFAULT_MAX_CONNECTIONS}")
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Error collecting connection info: {e}")
            connections = -1

        # Get CPU usage with a small interval for accuracy
        try:
            cpu_percent = process.cpu_percent(interval=0.1)
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Error collecting CPU usage: {e}")
            cpu_percent = None

        # Get thread count and check threshold
        try:
            num_threads = process.num_threads()
            if num_threads > DEFAULT_MAX_THREADS * 0.8:
                warnings.append(f"Thread count approaching limit: {num_threads}/{DEFAULT_MAX_THREADS}")
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Error collecting thread count: {e}")
            num_threads = -1

        # Collect basic process information
        process_info = {
            'pid': process.pid,
            'memory': memory_info,
            'cpu_percent': cpu_percent,
            'threads': num_threads,
            'connections': connections,
            'open_files': open_files,
            'status': process.status(),
            'cmdline': process.cmdline(),
            'timestamp': format_timestamp()
        }

        # Add username if available
        try:
            process_info['username'] = process.username()
        except (psutil.AccessDenied, psutil.Error):
            pass

        # Add start time if available
        try:
            process_info['start_time'] = datetime.fromtimestamp(
                process.create_time(), tz=timezone.utc
            ).isoformat()

            # Calculate process uptime in seconds
            uptime = (datetime.now(timezone.utc) -
                     datetime.fromtimestamp(process.create_time(), tz=timezone.utc)).total_seconds()
            process_info['uptime_seconds'] = int(uptime)
        except (psutil.AccessDenied, psutil.Error) as e:
            logger.debug(f"Error getting process creation time: {e}")

        # Add parent process information if available
        try:
            parent = process.parent()
            if parent:
                process_info['parent'] = {
                    'pid': parent.pid,
                    'name': parent.name(),
                    'status': parent.status()
                }
        except (psutil.AccessDenied, psutil.Error, psutil.NoSuchProcess) as e:
            logger.debug(f"Error getting parent process info: {e}")

        # Add warnings if any thresholds were exceeded
        if warnings:
            process_info['warnings'] = warnings

        return process_info
    except (psutil.Error, OSError) as e:
        log_error(f"Error collecting process info: {e}")
        return {
            'error': str(e),
            'timestamp': format_timestamp(),
            'status': 'error'
        }


def get_request_context() -> RequestContext:
    """
    Get information about the current request context.

    Returns:
        Dictionary containing request context information including request ID,
        user information, authentication status, and request metrics.

    Example:
        {
            'method': 'POST',
            'path': '/api/v1/resources',
            'remote_addr': '192.168.1.1',
            'user_agent': 'Mozilla/5.0...',
            'request_id': 'req-123456-789',
            'user_id': 'user123',
            'timestamp': '2023-01-01T12:00:00+00:00'
        }
    """
    context = {
        'timestamp': format_timestamp()
    }

    try:
        # Add app context information if available
        if has_app_context():
            try:
                context['app_name'] = current_app.name
                if hasattr(current_app, 'config'):
                    context['environment'] = current_app.config.get('ENV', 'unknown')
                    context['debug_mode'] = current_app.config.get('DEBUG', False)
            except Exception as e:
                logger.debug(f"Error getting app context: {e}")

        # Add request context information if available
        if has_request_context():
            try:
                # Basic request information
                context.update({
                    'method': request.method,
                    'path': request.path,
                    'endpoint': request.endpoint,
                    'remote_addr': request.remote_addr,
                    'content_type': request.content_type,
                    'content_length': request.content_length,
                    'user_agent': str(request.user_agent) if request.user_agent else None,
                    'referrer': request.referrer,
                    'secure': request.is_secure,
                })

                # Add request scheme and host
                context['url'] = request.url
                context['base_url'] = request.base_url

                # Add client information where available
                if hasattr(request, 'access_route') and request.access_route:
                    context['client_ip'] = request.access_route[0]

                # Add request headers (excluding sensitive ones)
                sensitive_headers = {'authorization', 'cookie', 'x-api-key', 'api-key'}
                safe_headers = {}

                for header, value in request.headers.items():
                    header_lower = header.lower()
                    if header_lower not in sensitive_headers:
                        safe_headers[header] = value
                    else:
                        safe_headers[header] = '[REDACTED]'

                context['headers'] = safe_headers
            except Exception as e:
                logger.debug(f"Error collecting request information: {e}")

        # Try to get request ID from various locations
        if has_request_context():
            # Check for request ID in Flask global
            if hasattr(g, 'request_id'):
                context['request_id'] = g.request_id
            # Check for request ID in headers
            elif request.headers.get('X-Request-ID'):
                context['request_id'] = request.headers.get('X-Request-ID')
            # Check for request ID in the request
            elif hasattr(request, 'id'):
                context['request_id'] = request.id

        # Try to get user information from various locations
        if has_request_context() and hasattr(g, 'user'):
            if isinstance(g.user, dict):
                if 'id' in g.user:
                    context['user_id'] = g.user['id']
                if 'email' in g.user:
                    context['user_email'] = g.user['email']
            elif hasattr(g.user, 'id'):
                context['user_id'] = g.user.id
                if hasattr(g.user, 'email'):
                    context['user_email'] = g.user.email
        elif has_app_context() and has_request_context():
            # Try session-based user ID
            from flask import session
            if 'user_id' in session:
                context['user_id'] = session['user_id']
            elif 'user' in session and isinstance(session['user'], dict) and 'id' in session['user']:
                context['user_id'] = session['user']['id']

        return context
    except Exception as e:
        log_error(f"Error collecting request context: {e}")
        return {
            'error': str(e),
            'timestamp': format_timestamp(),
            'status': 'error'
        }


def get_redis_client():
    """
    Get Redis client instance from current Flask app with proper connection pooling.

    This function attempts to retrieve a Redis client instance from the current
    Flask application context in various common configurations.

    Returns:
        Redis client instance or None if not available

    Example:
        redis = get_redis_client()
        if redis:
            redis.set('key', 'value', ex=3600)
            value = redis.get('key')
    """
    if not has_app_context():
        return None

    try:
        # Check various common locations for Redis client

        # Direct redis attribute
        if hasattr(current_app, 'redis'):
            return current_app.redis

        # Extensions dictionary
        if hasattr(current_app, 'extensions') and current_app.extensions:
            # Flask-Redis extension
            if 'redis' in current_app.extensions:
                return current_app.extensions['redis']

            # Redis in cache extension
            if 'cache' in current_app.extensions and hasattr(current_app.extensions['cache'], 'redis'):
                return current_app.extensions['cache'].redis

        # Check common configuration patterns
        if hasattr(current_app, 'config'):
            # Try to create a Redis client from connection URL if available
            if 'REDIS_URL' in current_app.config:
                try:
                    import redis
                    return redis.from_url(
                        current_app.config['REDIS_URL'],
                        decode_responses=True,
                        socket_timeout=DEFAULT_CONNECT_TIMEOUT,
                        socket_connect_timeout=DEFAULT_CONNECT_TIMEOUT
                    )
                except (ImportError, Exception) as e:
                    logger.debug(f"Could not create Redis client from URL: {e}")

        return None
    except Exception as e:
        logger.debug(f"Error getting Redis client: {e}")
        return None


@contextmanager
def measure_execution_time() -> Generator[Timer, None, None]:
    """
    Context manager to measure execution time of a code block.

    The measure_execution_time context manager provides a simple way to measure
    how long a section of code takes to execute. It uses monotonic time for
    accurate measurements regardless of system clock changes.

    This context manager yields an object with a 'duration' property that
    gets updated when the context block exits.

    Yields:
        Timer object with a 'duration' attribute (seconds)

    Example:
        with measure_execution_time() as timer:
            # Code to measure
            time.sleep(1)
        print(f"Operation took {timer.duration:.2f} seconds")

        # You can also log slow operations
        if timer.duration > 5.0:
            logger.warning(f"Operation too slow: {timer.duration:.2f}s")
    """
    timer = {'duration': 0.0}
    start_time = time.monotonic()  # Use monotonic for more accurate timing

    try:
        # Create a named tuple with a mutable duration field for the caller to access
        yield Timer(duration=0.0)
    finally:
        duration = time.monotonic() - start_time
        timer['duration'] = duration
        # We can't modify the namedtuple after creation, but Python will look up
        # the attribute dynamically, so we can update the calling scope's value
        # through this closure
        Timer.duration = duration


def get_application_metrics(app=None) -> Dict[str, Any]:
    """
    Get application-specific metrics from Flask application.

    Args:
        app: Flask application (uses current_app if None)

    Returns:
        Dictionary containing application metrics and health indicators

    Example:
        {
            'routes_count': 25,
            'views_count': 15,
            'extensions': ['sqlalchemy', 'migrate', 'redis'],
            'has_error_handlers': True,
            'has_request_hooks': True,
            'blueprints': ['main', 'auth', 'api'],
            'static_folder_exists': True,
            'config': {
                'TESTING': False,
                'DEBUG': False,
                'ENV': 'production'
            },
            'timestamp': '2023-01-01T12:00:00+00:00'
        }
    """
    if not has_app_context() and app is None:
        return {
            'error': 'No Flask application context',
            'timestamp': format_timestamp()
        }

    try:
        # Get application instance
        application = app or current_app

        # Basic application info
        metrics = {
            'name': application.name,
            'import_name': application.import_name,
            'timestamp': format_timestamp()
        }

        # Count routes
        if hasattr(application, 'url_map'):
            metrics['routes_count'] = len(list(application.url_map.iter_rules()))

        # Check extensions
        if hasattr(application, 'extensions'):
            metrics['extensions'] = list(application.extensions.keys())

        # Count and list blueprints
        if hasattr(application, 'blueprints'):
            metrics['blueprints'] = list(application.blueprints.keys())
            metrics['blueprints_count'] = len(application.blueprints)

        # Check for error handlers
        if hasattr(application, 'error_handler_spec'):
            has_handlers = any(
                bool(handlers) for handlers in application.error_handler_spec.values()
            )
            metrics['has_error_handlers'] = has_handlers

        # Check request hooks
        hooks = ['before_request', 'after_request', 'teardown_request']
        has_hooks = any(
            bool(getattr(application, f'{hook}_funcs', [])) for hook in hooks
        )
        metrics['has_request_hooks'] = has_hooks

        # Check static folder
        if hasattr(application, 'static_folder'):
            metrics['static_folder_exists'] = (
                application.static_folder is not None and
                os.path.isdir(application.static_folder)
            )

        # Safe config values (non-sensitive)
        safe_config_keys = {
            'DEBUG', 'TESTING', 'ENV', 'PREFERRED_URL_SCHEME',
            'PERMANENT_SESSION_LIFETIME', 'PROPAGATE_EXCEPTIONS',
            'PRESERVE_CONTEXT_ON_EXCEPTION', 'SESSION_COOKIE_SECURE',
            'SESSION_COOKIE_HTTPONLY', 'SESSION_COOKIE_SAMESITE',
            'TRAP_HTTP_EXCEPTIONS', 'TRAP_BAD_REQUEST_ERRORS',
            'EXPLAIN_TEMPLATE_LOADING', 'TEMPLATES_AUTO_RELOAD',
            'MAX_CONTENT_LENGTH'
        }

        if hasattr(application, 'config'):
            safe_config = {}
            for key in safe_config_keys:
                if key in application.config:
                    value = application.config[key]
                    # Convert non-JSON-serializable types to strings
                    if not isinstance(value, (str, int, float, bool, type(None), list, dict)):
                        value = str(value)
                    safe_config[key] = value
            metrics['config'] = safe_config

        return metrics
    except Exception as e:
        log_error(f"Error collecting application metrics: {e}")
        return {
            'error': str(e),
            'timestamp': format_timestamp()
        }


def generate_system_health_report() -> Dict[str, Any]:
    """
    Generate a comprehensive system health report.

    Returns:
        Dictionary containing system health information across multiple dimensions

    Example:
        {
            'status': 'healthy',  # or 'warning' or 'critical'
            'system': {...},  # System resource metrics
            'process': {...},  # Process information
            'application': {...},  # Application metrics
            'warnings': ['Disk usage above threshold: 92%'],
            'timestamp': '2023-01-01T12:00:00+00:00'
        }
    """
    # Collect metrics from various sources
    system_resources = get_system_resources()
    process_info = get_process_info()

    # Default status is healthy
    status = 'healthy'
    all_warnings = []

    # Collect warnings from system resources
    if 'warnings' in system_resources:
        all_warnings.extend(system_resources['warnings'])
        status = 'warning'

    # Check for critical errors in system resources
    if 'error' in system_resources:
        all_warnings.append(f"System resource error: {system_resources['error']}")
        status = 'warning'

    # Check for critical disk space
    if ('disk' in system_resources and
            isinstance(system_resources['disk'], dict) and
            'percent' in system_resources['disk'] and
            system_resources['disk']['percent'] > 95):
        all_warnings.append(f"Critical disk space: {system_resources['disk']['percent']}% used")
        status = 'critical'

    # Check for critical memory usage
    if ('memory' in system_resources and
            isinstance(system_resources['memory'], dict) and
            'percent' in system_resources['memory'] and
            system_resources['memory']['percent'] > 95):
        all_warnings.append(f"Critical memory usage: {system_resources['memory']['percent']}% used")
        status = 'critical'

    # Collect warnings from process info
    if 'warnings' in process_info:
        all_warnings.extend(process_info['warnings'])
        if status == 'healthy':
            status = 'warning'

    # Check for process errors
    if 'error' in process_info:
        all_warnings.append(f"Process info error: {process_info['error']}")
        if status == 'healthy':
            status = 'warning'

    # Try to get application metrics if in app context
    app_metrics = {}
    if has_app_context():
        app_metrics = get_application_metrics()
        if 'error' in app_metrics:
            all_warnings.append(f"Application metrics error: {app_metrics['error']}")
            if status == 'healthy':
                status = 'warning'

    # Compile the health report
    health_report = {
        'status': status,
        'system': system_resources,
        'process': process_info,
        'timestamp': format_timestamp()
    }

    # Add application metrics if available
    if app_metrics and 'error' not in app_metrics:
        health_report['application'] = app_metrics

    # Add warnings if any
    if all_warnings:
        health_report['warnings'] = all_warnings

    # Add recommendation if in critical state
    if status == 'critical':
        health_report['recommendation'] = "Immediate action required - system resources critically low"
    elif status == 'warning':
        health_report['recommendation'] = "Monitor system closely - resource issues detected"

    return health_report


# Export public functions and constants
__all__ = [
    'get_system_resources',
    'get_process_info',
    'get_request_context',
    'get_redis_client',
    'measure_execution_time',
    'get_application_metrics',
    'generate_system_health_report',
    'Timer',
    # Types
    'ResourceMetrics',
    'ProcessInfo',
    'RequestContext',
]
