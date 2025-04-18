#!/usr/bin/env python3
"""
Export system and application metrics for Cloud Infrastructure Platform.
Supports multiple output formats (Prometheus, JSON, CSV).
"""

import os
import sys
import json
import time
import argparse
import logging
import subprocess
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Union

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "logs" / "metrics"
LOG_FILE = Path("/var/log/cloud-platform/metrics_export.log")

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


def collect_system_metrics() -> Dict[str, Any]:
    """Collect system-level metrics."""
    metrics = {}
    
    # CPU metrics
    metrics["cpu_percent"] = psutil.cpu_percent(interval=1)
    cpu_times = psutil.cpu_times_percent(interval=1)
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
    
    return metrics


def collect_application_metrics() -> Dict[str, Any]:
    """Collect application-specific metrics."""
    metrics = {}
    
    try:
        # Try to connect to the application's metrics endpoint
        import requests
        response = requests.get("http://localhost:5000/api/metrics", timeout=5)
        if response.status_code == 200:
            app_metrics = response.json()
            for key, value in app_metrics.items():
                metrics[f"app_{key}"] = value
        else:
            logger.warning(f"Failed to get application metrics: HTTP {response.status_code}")
    except Exception as e:
        logger.warning(f"Error collecting application metrics: {e}")
        
        # Fallback to basic process stats for the application
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
            logger.warning(f"Error collecting process metrics: {proc_err}")
    
    return metrics


def collect_nginx_metrics() -> Dict[str, Any]:
    """Collect NGINX metrics if available."""
    metrics = {}
    
    try:
        # Try to get NGINX stats from stub_status module
        import requests
        response = requests.get("http://localhost/nginx_status", timeout=2)
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            # Extract active connections
            metrics["nginx_active_connections"] = int(lines[0].split(':')[1].strip())
            
            # Extract connection metrics
            conn_metrics = lines[2].strip().split()
            metrics["nginx_accepts"] = int(conn_metrics[0])
            metrics["nginx_handled"] = int(conn_metrics[1])
            metrics["nginx_requests"] = int(conn_metrics[2])
            
            # Extract connection states
            states = lines[3].strip().split()
            metrics["nginx_reading"] = int(states[1])
            metrics["nginx_writing"] = int(states[3])
            metrics["nginx_waiting"] = int(states[5])
    except Exception as e:
        logger.debug(f"Could not collect NGINX metrics: {e}")
        
    return metrics


def collect_database_metrics() -> Dict[str, Any]:
    """Collect database metrics if available."""
    metrics = {}
    
    try:
        # Use psql to get PostgreSQL stats
        if os.path.exists('/usr/bin/psql'):
            # Get connection count
            cmd = ["psql", "-t", "-c", "SELECT count(*) FROM pg_stat_activity;"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                metrics["db_connections"] = int(result.stdout.strip())
            
            # Get database size
            cmd = ["psql", "-t", "-c", "SELECT pg_database_size('cloud_platform');"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                metrics["db_size_bytes"] = int(result.stdout.strip())
            
            # Get transaction metrics
            cmd = ["psql", "-t", "-c", "SELECT xact_commit, xact_rollback FROM pg_stat_database WHERE datname='cloud_platform';"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                commits, rollbacks = result.stdout.strip().split('|')
                metrics["db_commits"] = int(commits.strip())
                metrics["db_rollbacks"] = int(rollbacks.strip())
    except Exception as e:
        logger.debug(f"Could not collect database metrics: {e}")
        
    return metrics


def format_prometheus(metrics: Dict[str, Any], prefix: str = "cloudplatform_") -> str:
    """Format metrics in Prometheus exposition format."""
    timestamp_ms = int(time.time() * 1000)
    output = []
    
    for key, value in metrics.items():
        metric_name = f"{prefix}{key}"
        
        # Skip non-numeric values
        if not isinstance(value, (int, float)):
            continue
            
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
    metrics["timestamp"] = datetime.now().isoformat()
    metrics["hostname"] = os.uname().nodename
    return json.dumps(metrics, indent=2)


def format_csv(metrics: Dict[str, Any]) -> str:
    """Format metrics as CSV."""
    metrics["timestamp"] = datetime.now().isoformat()
    metrics["hostname"] = os.uname().nodename
    
    header = ",".join(metrics.keys())
    values = ",".join(str(v) for v in metrics.values())
    return f"{header}\n{values}"


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Export system and application metrics.')
    parser.add_argument('--format', choices=['prometheus', 'json', 'csv'], default='prometheus',
                        help='Output format (default: prometheus)')
    parser.add_argument('--output', default=None,
                        help=f'Output file (default: {DEFAULT_OUTPUT_DIR}/metrics_YYYYMMDD_HHMMSS.{format})')
    args = parser.parse_args()
    
    logger.info(f"Starting metrics export in {args.format} format")
    
    # Collect all metrics
    metrics = {}
    metrics.update(collect_system_metrics())
    metrics.update(collect_application_metrics())
    metrics.update(collect_nginx_metrics())
    metrics.update(collect_database_metrics())
    
    # Format according to requested format
    if args.format == 'prometheus':
        output = format_prometheus(metrics)
        extension = 'prom'
    elif args.format == 'json':
        output = format_json(metrics)
        extension = 'json'
    else:  # csv
        output = format_csv(metrics)
        extension = 'csv'
    
    # Determine output file
    if args.output:
        output_file = Path(args.output)
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = DEFAULT_OUTPUT_DIR / f"metrics_{timestamp}.{extension}"
    
    # Write output
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(output)
        logger.info(f"Metrics exported to {output_file}")
    except Exception as e:
        logger.error(f"Error writing metrics to {output_file}: {e}")
        print(output)  # Fallback to stdout
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
