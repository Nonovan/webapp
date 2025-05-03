import base64
import glob
import hashlib
import json
import logging
import os
import pwd
import stat
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import psutil
from flask import current_app, g, has_app_context, has_request_context, request

from .date_time import format_timestamp
from .logging_utils import log_error

# Type definitions
FileMetadata = Dict[str, Any]
ResourceMetrics = Dict[str, Any]
FileChangeInfo = Dict[str, Any]

# Constants
DEFAULT_HASH_ALGORITHM = 'sha256'
SMALL_FILE_THRESHOLD = 10240  # 10KB
EXECUTABLE_PATTERNS = ['*.so', '*.dll', '*.exe', '*.bin', '*.sh']
CRITICAL_FILE_PATTERNS = ['*.py', 'config.*', '.env*', '*.ini', 'requirements.txt', '*.sh', '*.key', '*.pem']
ALLOWED_HIDDEN_FILES = ['.env', '.gitignore', '.dockerignore']
DEFAULT_READ_CHUNK_SIZE = 4096  # 4KB chunks for file reading
SUSPICIOUS_PATTERNS = ['backdoor', 'hack', 'exploit', 'rootkit', 'trojan', 'payload', 'malware']
SENSITIVE_EXTENSIONS = ['.key', '.pem', '.p12', '.pfx', '.keystore', '.jks', '.env', '.secret']

# Setup module-level logger
logger = logging.getLogger(__name__)


def get_system_resources() -> ResourceMetrics:
    """
    Get current system resource usage.

    Returns:
        Dictionary containing CPU, memory, and disk usage information

    Example:
        {
            'cpu': {'percent': 12.5, 'count': 8},
            'memory': {'total': 16777216, 'available': 8388608, 'percent': 50.0},
            'disk': {'total': 1073741824, 'used': 536870912, 'percent': 50.0},
            'timestamp': '2023-01-01T12:00:00+00:00'
        }
    """
    try:
        disk_info = psutil.disk_usage('/')

        resources = {
            'cpu': {
                'percent': psutil.cpu_percent(interval=0.1),  # Reduced interval for responsiveness
                'count': psutil.cpu_count(logical=True),
                'physical_count': psutil.cpu_count(logical=False),
                'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else None
            },
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'used': psutil.virtual_memory().used,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': disk_info.total,
                'used': disk_info.used,
                'free': disk_info.free,
                'percent': disk_info.percent,
                'total_gb': round(disk_info.total / (1024**3), 2),
                'free_gb': round(disk_info.free / (1024**3), 2)
            },
            'network': {
                'connections': len(psutil.net_connections(kind='inet')),
                'interfaces': list(psutil.net_if_addrs().keys())
            },
            'timestamp': format_timestamp()
        }

        # Add boot time if available
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
            resources['boot_time'] = boot_time.isoformat()
        except (AttributeError, OSError):
            pass

        return resources
    except (psutil.Error, OSError) as e:
        log_error(f"Error collecting system resources: {e}")
        return {'error': str(e), 'timestamp': format_timestamp()}


def get_process_info() -> Dict[str, Any]:
    """
    Get information about the current process.

    Returns:
        Dictionary containing process memory usage, threads, and connections

    Example:
        {
            'memory_mb': 120.5,
            'threads': 4,
            'connections': 8,
            'open_files': 15,
            'start_time': '2023-01-01T12:00:00+00:00',
            'timestamp': '2023-01-01T12:30:00+00:00'
        }
    """
    try:
        process = psutil.Process()

        # Calculate memory in different formats for better visibility
        memory_bytes = process.memory_info().rss
        memory_mb = memory_bytes / (1024 * 1024)
        memory_percent = process.memory_percent()

        # Get file and connection information safely
        try:
            open_files = len(process.open_files())
        except (psutil.AccessDenied, psutil.Error):
            open_files = -1

        try:
            connections = len(process.connections())
        except (psutil.AccessDenied, psutil.Error):
            connections = -1

        # Get CPU usage with a small interval for accuracy
        try:
            cpu_percent = process.cpu_percent(interval=0.1)
        except (psutil.AccessDenied, psutil.Error):
            cpu_percent = None

        return {
            'pid': process.pid,
            'memory': {
                'bytes': memory_bytes,
                'mb': memory_mb,
                'percent': memory_percent
            },
            'cpu_percent': cpu_percent,
            'threads': process.num_threads(),
            'connections': connections,
            'open_files': open_files,
            'username': process.username(),
            'status': process.status(),
            'start_time': datetime.fromtimestamp(
                process.create_time(), tz=timezone.utc
            ).isoformat(),
            'timestamp': format_timestamp()
        }
    except (psutil.Error, OSError) as e:
        log_error(f"Error collecting process info: {e}")
        return {'error': str(e), 'timestamp': format_timestamp()}


def get_request_context() -> Dict[str, Any]:
    """
    Get information about the current request context.

    Returns:
        Dictionary containing request context information
    """
    context = {
        'timestamp': format_timestamp()
    }

    if has_request_context():
        context.update({
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_agent': str(request.user_agent) if request.user_agent else None
        })

        # Add request ID if available
        if hasattr(g, 'request_id'):
            context['request_id'] = g.request_id

        # Add user ID if available
        if hasattr(g, 'user_id'):
            context['user_id'] = g.user_id

    return context


def get_redis_client():
    """
    Get Redis client instance from current Flask app or return None.

    Returns:
        Redis client instance or None if not available
    """
    if has_app_context():
        if hasattr(current_app, 'redis'):
            return current_app.redis

        if hasattr(current_app.extensions, 'redis'):
            return current_app.extensions.get('redis')

    return None


@contextmanager
def measure_execution_time() -> Generator[None, None, float]:
    """
    Context manager to measure execution time of a code block.

    Returns:
        float: Execution time in seconds

    Example:
        with measure_execution_time() as elapsed:
            # Code to measure
            time.sleep(1)
        print(f"Operation took {elapsed} seconds")
    """
    start_time = time.monotonic()  # Use monotonic for more accurate timing
    try:
        yield
    finally:
        execution_time = time.monotonic() - start_time

    return execution_time
