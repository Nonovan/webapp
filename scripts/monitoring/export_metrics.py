#!/usr/bin/env python3
"""
Export system and application metrics for Cloud Infrastructure Platform.
Supports multiple output formats (Prometheus, JSON, CSV) and collection methods.

This script can collect metrics in two ways:
1. Through the Flask application API (requires app to be running)
2. Directly from the system (works even when app is down)

Examples:
  # Export metrics in JSON format to stdout:
  ./export_metrics.py
  
  # Export metrics in Prometheus format to a file:
  ./export_metrics.py --format prometheus --output /var/log/metrics/metrics.prom
  
  # Force direct system collection (bypassing the app):
  ./export_metrics.py --direct
"""

import os
import sys
import json
import time
import argparse
import logging
import subprocess
import errno
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Union
import requests

from core.factory import create_app


# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "logs" / "metrics"
LOG_FILE = Path("/var/log/cloud-platform/metrics_export.log")
APP_URL = "http://localhost:5000"

# Ensure directories exist
DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("metrics_export")

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil module not available, system metrics will be limited")

try:
    from app import create_app
    from extensions import metrics as app_metrics
    APP_IMPORTS_AVAILABLE = True
except ImportError:
    APP_IMPORTS_AVAILABLE = False
    logger.warning("App imports not available, using direct collection only")


def collect_system_metrics() -> Dict[str, Any]:
    """Collect system-level metrics using psutil if available."""
    metrics = {}
    
    if not PSUTIL_AVAILABLE:
        logger.warning("psutil not available, collecting limited system metrics")
        try:
            # Basic metrics using /proc filesystem
            with open('/proc/loadavg', 'r', encoding='utf-8') as f:
                load = f.read().strip().split()
                metrics["load_avg_1min"] = float(load[0])
                metrics["load_avg_5min"] = float(load[1])
                metrics["load_avg_15min"] = float(load[2])
            
            # Memory info
            with open('/proc/meminfo', 'r', encoding='utf-8') as f:
                mem_info = {}
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        value = value.strip().split()[0]  # Remove unit
                        mem_info[key.strip()] = int(value)
                
                metrics["memory_total"] = mem_info.get('MemTotal', 0) * 1024  # KB to bytes
                metrics["memory_free"] = mem_info.get('MemFree', 0) * 1024
                metrics["memory_available"] = mem_info.get('MemAvailable', 0) * 1024
                metrics["memory_used"] = metrics["memory_total"] - metrics["memory_available"]
                if metrics["memory_total"] > 0:
                    metrics["memory_percent"] = 100 * metrics["memory_used"] / metrics["memory_total"]
                else:
                    metrics["memory_percent"] = 0
            
            # Disk usage
            disk = subprocess.run(['df', '/'], capture_output=True, text=True, check=True).stdout
            if disk:
                lines = disk.strip().split('\n')
                if len(lines) >= 2:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        metrics["disk_total"] = int(parts[1]) * 1024  # KB to bytes
                        metrics["disk_used"] = int(parts[2]) * 1024
                        metrics["disk_free"] = int(parts[3]) * 1024
                        metrics["disk_percent"] = float(parts[4].rstrip('%'))
            
        except (FileNotFoundError, ValueError, subprocess.CalledProcessError) as e:
            logger.error("Error collecting basic system metrics: %s", e)
        
        return metrics
    
    # Enhanced metrics with psutil available
    try:
        # CPU metrics
        metrics["cpu_percent"] = psutil.cpu_percent(interval=1)
        cpu_times = psutil.cpu_times_percent(interval=0.1)
        metrics["cpu_user"] = cpu_times.user
        metrics["cpu_system"] = cpu_times.system
        metrics["cpu_idle"] = cpu_times.idle
        metrics["load_avg_1min"], metrics["load_avg_5min"], metrics["load_avg_15min"] = psutil.getloadavg()
        
        # Memory metrics
        memory = psutil.virtual_memory()
        metrics["memory_total"] = memory.total
        metrics["memory_available"] = memory.available
        metrics["memory_used"] = memory.used
        metrics["memory_percent"] = memory.percent
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        metrics["disk_total"] = disk.total
        metrics["disk_used"] = disk.used
        metrics["disk_free"] = disk.free
        metrics["disk_percent"] = disk.percent
        
        # Network metrics
        net_io = psutil.net_io_counters()
        metrics["net_bytes_sent"] = net_io.bytes_sent
        metrics["net_bytes_recv"] = net_io.bytes_recv
        metrics["net_packets_sent"] = net_io.packets_sent
        metrics["net_packets_recv"] = net_io.packets_recv
        
        # Process metrics
        process_count = len(psutil.pids())
        metrics["process_count"] = process_count
        
    except (psutil.Error, ValueError, OSError) as e:
        logger.error("Error collecting system metrics with psutil: %s", e)
    
    return metrics


def collect_application_metrics() -> Dict[str, Any]:
    """Collect application-specific metrics."""
    metrics = {}
    
    try:
        # Try to connect to the application's metrics endpoint
        response = requests.get(f"{APP_URL}/api/metrics", timeout=5)
        if response.status_code == 200:
            app_metrics = response.json()
            if isinstance(app_metrics, dict) and "data" in app_metrics:
                app_metrics = app_metrics["data"]
                
            # Flatten nested dictionaries with dot notation
            flat_metrics = {}
            for key, value in app_metrics.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if not isinstance(sub_value, (dict, list)):
                            flat_metrics[f"app_{key}_{sub_key}"] = sub_value
                elif not isinstance(value, (dict, list)):
                    flat_metrics[f"app_{key}"] = value
                    
            metrics.update(flat_metrics)
        else:
            logger.warning("Failed to get application metrics: HTTP %s", response.status_code)
    except (requests.RequestException, ValueError, KeyError) as e:
        logger.warning("Error collecting application metrics via API: %s", e)
        
        # Fallback to basic process stats for the application
        if PSUTIL_AVAILABLE:
            try:
                # Find Python processes related to the application
                python_procs = []
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    if proc.info['name'] == 'python' and any('app.py' in arg for arg in (proc.info['cmdline'] or [])):
                        python_procs.append(proc)
                
                if python_procs:
                    # Get metrics from the main application process
                    app_process = python_procs[0]
                    metrics["app_process_cpu_percent"] = app_process.cpu_percent()
                    metrics["app_process_memory_percent"] = app_process.memory_percent()
                    metrics["app_process_threads"] = app_process.num_threads()
                    metrics["app_process_count"] = len(python_procs)
                    
                    # Get open files count
                    try:
                        metrics["app_open_files"] = len(app_process.open_files())
                    except Exception:
                        pass
                        
                    # Get connections count
                    try:
                        metrics["app_connections"] = len(app_process.connections())
                    except Exception:
                        pass
            except Exception as proc_err:
                logger.warning("Error collecting process metrics: %s", proc_err)
    
    return metrics


def collect_database_metrics() -> Dict[str, Any]:
    """Collect database metrics if available."""
    metrics = {}
    
    try:
        # Use psql to get PostgreSQL stats
        if os.path.exists('/usr/bin/psql'):
            # Get connection count
            cmd = ["psql", "-t", "-c", "SELECT count(*) FROM pg_stat_activity;"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                metrics["db_connections"] = int(result.stdout.strip())
            
            # Get database size
            cmd = ["psql", "-t", "-c", "SELECT pg_database_size('cloud_platform');"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                metrics["db_size_bytes"] = int(result.stdout.strip())
            
            # Get transaction metrics
            cmd = ["psql", "-t", "-c", "SELECT xact_commit, xact_rollback FROM pg_stat_database WHERE datname='cloud_platform';"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                commits, rollbacks = result.stdout.strip().split('|')
                metrics["db_commits"] = int(commits.strip())
                metrics["db_rollbacks"] = int(rollbacks.strip())
    except (subprocess.CalledProcessError, ValueError, OSError) as e:
        logger.debug("Could not collect database metrics: %s", e)
        
    return metrics


def collect_metrics_via_app() -> Dict[str, Any]:
    """Collect metrics through the Flask application context."""
    if not APP_IMPORTS_AVAILABLE:
        logger.error("Cannot collect metrics via app - required modules not available")
        return {}
        
    try:
        # Create app with specific configuration for metrics collection
        app = create_app({
            'METRICS_ENABLED': True,
            'TESTING': False,
            'SERVER_NAME': None  # Don't set server name to avoid URL generation issues
        })
        
        with app.app_context():
            # Check if metrics export function is available
            if hasattr(app_metrics, 'export_metrics'):
                return app_metrics.export_metrics()
            elif hasattr(app_metrics, 'get_all_metrics'):
                # This appears to be more commonly used in your codebase
                return app_metrics.get_all_metrics()
            else:
                # Try to get metrics directly from the registry
                metrics_data = {}
                if hasattr(app_metrics, 'registry'):
                    for metric in app_metrics.registry.collect():
                        for sample in metric.samples:
                            metric_name = sample.name
                            metric_value = sample.value
                            if isinstance(metric_value, (int, float)):
                                metrics_data[metric_name] = metric_value
                
                if not metrics_data:
                    logger.warning("No export_metrics method found on app_metrics, collected empty set")
                
                return metrics_data
    except ImportError as e:
        logger.error("Import error when collecting metrics via application: %s", e)
        return {}
    except AttributeError as e:
        logger.error("Attribute error when collecting metrics via application: %s", e)
        return {}
    except (RuntimeError, ValueError, KeyError) as e:
        logger.error("Error collecting metrics via application: %s", e)
        return {}


def collect_metrics_directly() -> Dict[str, Any]:
    """Collect metrics directly from the system."""
    metrics = {}
    
    # Collect metrics from various sources
    system_metrics = collect_system_metrics()
    app_metrics = collect_application_metrics()
    db_metrics = collect_database_metrics()
    
    # Add timestamp and host info
    metrics["timestamp"] = datetime.now().isoformat()
    metrics["hostname"] = os.uname().nodename
    
    # Merge all metrics
    metrics.update(system_metrics)
    metrics.update(app_metrics)
    metrics.update(db_metrics)
    
    return metrics


def format_prometheus(metrics: Dict[str, Any], prefix: str = "cloud_platform_") -> str:
    """Format metrics in Prometheus exposition format."""
    timestamp_ms = int(time.time() * 1000)
    output = []
    
    for key, value in metrics.items():
        # Skip non-numeric values and timestamp/hostname
        if not isinstance(value, (int, float)) or key in ('timestamp', 'hostname'):
            continue
            
        metric_name = f"{prefix}{key}"
        
        # Add type hint comment for metric
        if key.endswith("_percent"):
            output.append(f"# TYPE {metric_name} gauge")
        elif key.startswith("cpu_") or key.startswith("memory_") or key.startswith("disk_"):
            output.append(f"# TYPE {metric_name} gauge")
        elif key.startswith("net_bytes_") or key.startswith("net_packets_"):
            output.append(f"# TYPE {metric_name} counter")
        else:
            output.append(f"# TYPE {metric_name} gauge")
        
        # Add metric value with timestamp
        output.append(f"{metric_name} {value} {timestamp_ms}")
    
    return "\n".join(output)


def format_json(metrics: Dict[str, Any]) -> str:
    """Format metrics as JSON."""
    return json.dumps(metrics, indent=2)


def format_csv(metrics: Dict[str, Any]) -> str:
    """Format metrics as CSV."""
    header = ",".join(metrics.keys())
    values = ",".join(str(v) for v in metrics.values())
    return f"{header}\n{values}"


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Export system and application metrics.')
    parser.add_argument('--format', choices=['prometheus', 'json', 'csv'], default='json',
                        help='Output format (default: json)')
    parser.add_argument('--output', default=None,
                        help='Output file (default: stdout)')
    parser.add_argument('--direct', action='store_true',
                        help='Collect metrics directly without using the application API')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress informational output')
    args = parser.parse_args()
    
    if not args.quiet:
        logger.info("Starting metrics export in %s format", args.format)
    
    # Collect metrics using appropriate method
    if args.direct or not APP_IMPORTS_AVAILABLE:
        if not args.quiet:
            logger.info("Collecting metrics directly from system")
        metrics_data = collect_metrics_directly()
    else:
        if not args.quiet:
            logger.info("Collecting metrics via application")
        metrics_data = collect_metrics_via_app()
        
        # If app collection fails, fall back to direct collection
        if not metrics_data:
            logger.warning("App-based collection failed, falling back to direct collection")
            metrics_data = collect_metrics_directly()
    
    # Format according to requested format
    if args.format == 'prometheus':
        output = format_prometheus(metrics_data)
    elif args.format == 'json':
        output = format_json(metrics_data)
    else:  # csv
        output = format_csv(metrics_data)
    
    # Write output to file or stdout
    if args.output:
        try:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(output)
            if not args.quiet:
                logger.info("Metrics exported to %s", output_path)
        except Exception as e:
            logger.error("Error writing metrics to %s: %s", args.output, e)
            logger.error("Failed to write to file, check permissions and disk space")
            return 1
    else:
        try:
            print(output)
        except IOError as e:
            # Handle broken pipe errors (when piping to another command that exits early)
            if e.errno == errno.EPIPE:
                logger.debug("Broken pipe when writing to stdout")
                return 0
            raise
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(130)  # Standard exit code for SIGINT
