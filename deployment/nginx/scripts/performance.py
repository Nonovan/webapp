#!/usr/bin/env python3
"""
Performance optimization utilities for NGINX configurations.

This module provides functions to calculate and apply optimal NGINX performance
settings based on system resources and environment type (development, staging,
production, dr-recovery). It includes utilities for generating performance-optimized
configuration files and verifying current settings.
"""

import os
import sys
import subprocess
import argparse
import logging
import re
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

# Default paths
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
NGINX_ROOT = Path("/etc/nginx")

# Default settings
DEFAULT_WORKER_CONNECTIONS = 1024
DEFAULT_KEEPALIVE_TIMEOUT = 65
DEFAULT_KEEPALIVE_REQUESTS = 1000
DEFAULT_WORKER_PROCESSES = "auto"

# Configure logging
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("nginx-performance")


def get_cpu_count() -> int:
    """
    Get the number of CPU cores available on the system.

    Returns:
        int: Number of CPU cores
    """
    try:
        # Try to get CPU count from /proc/cpuinfo
        if os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo", "r") as f:
                return len(re.findall(r"^processor\s+:", f.read(), re.M))

        # Fall back to Python's multiprocessing module
        import multiprocessing
        return multiprocessing.cpu_count()
    except Exception as e:
        logger.warning(f"Failed to determine CPU count: {e}")
        return 1  # Safe fallback


def get_total_memory() -> int:
    """
    Get total system memory in MB.

    Returns:
        int: Total memory in MB
    """
    try:
        # Try to get memory info from /proc/meminfo
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r") as f:
                mem_info = f.read()
                mem_total = re.search(r"MemTotal:\s+(\d+)", mem_info)
                if mem_total:
                    return int(mem_total.group(1)) // 1024  # Convert KB to MB

        # Fall back to platform-specific approaches
        if sys.platform == "darwin":  # macOS
            cmd = ["sysctl", "-n", "hw.memsize"]
            output = subprocess.check_output(cmd, universal_newlines=True).strip()
            return int(output) // (1024 * 1024)  # Convert bytes to MB
        elif sys.platform == "linux":
            import resource
            return resource.getpagesize() * resource.getphyspages() // (1024 * 1024)

        # Last resort
        return 4096  # Assume 4GB as a safe default
    except Exception as e:
        logger.warning(f"Failed to determine total memory: {e}")
        return 4096  # Assume 4GB as a safe default


def calculate_worker_processes(environment: str = "production") -> str:
    """
    Calculate optimal worker processes based on CPU count and environment.

    Args:
        environment: Target environment (production, staging, development, dr-recovery)

    Returns:
        str: Optimal worker processes setting
    """
    cpu_count = get_cpu_count()

    if environment == "production":
        # Use all available cores for production
        return str(cpu_count)
    elif environment == "staging":
        # Use 75% of cores (rounded up) for staging
        return str(max(1, (cpu_count * 3 + 3) // 4))
    elif environment == "dr-recovery":
        # Use 50% of cores for DR to leave resources for other critical systems
        return str(max(1, cpu_count // 2))
    else:
        # Development - use half of available cores (min 1)
        return str(max(1, (cpu_count + 1) // 2))


def calculate_worker_connections(environment: str = "production") -> int:
    """
    Calculate optimal worker connections based on memory and environment.

    Args:
        environment: Target environment (production, staging, development, dr-recovery)

    Returns:
        int: Optimal worker connections setting
    """
    mem_total = get_total_memory()
    cpu_count = get_cpu_count()
    worker_processes = int(calculate_worker_processes(environment))

    # Each connection uses approximately 2-3KB of memory
    # Reserve 20% of memory for the OS and other processes
    available_mem = mem_total * 80 // 100
    max_conn_by_mem = available_mem * 1024 // 3 // worker_processes

    # Set reasonable limits based on environment
    if environment == "production":
        if max_conn_by_mem > 10000:
            return 10000  # Cap at 10,000 connections per worker
        elif max_conn_by_mem < 1024:
            return 1024   # Minimum of 1,024 connections
        else:
            return max_conn_by_mem
    elif environment == "staging":
        if max_conn_by_mem > 8192:
            return 8192
        elif max_conn_by_mem < 1024:
            return 1024
        else:
            return max_conn_by_mem
    elif environment == "dr-recovery":
        # Lower connections for DR to ensure stability
        if max_conn_by_mem > 5000:
            return 5000
        else:
            return max(1024, max_conn_by_mem // 2)
    else:  # Development
        # Lower connections for dev to avoid resource contention
        return 768


def calculate_client_body_buffer_size(environment: str = "production") -> str:
    """
    Calculate optimal client body buffer size based on memory and environment.

    Args:
        environment: Target environment (production, staging, development, dr-recovery)

    Returns:
        str: Optimal client body buffer size setting
    """
    mem_total = get_total_memory()

    if environment == "production":
        if mem_total > 8192:  # More than 8GB
            return "64k"
        elif mem_total > 4096:  # 4-8GB
            return "32k"
        else:  # Less than 4GB
            return "16k"
    elif environment == "staging":
        if mem_total > 4096:  # More than 4GB
            return "32k"
        else:
            return "16k"
    elif environment == "dr-recovery":
        # Smaller buffers for DR to conserve memory
        return "16k"
    else:  # Development
        return "8k"


def calculate_keepalive_settings(environment: str = "production") -> Tuple[int, int]:
    """
    Calculate optimal keepalive settings based on environment.

    Args:
        environment: Target environment (production, staging, development, dr-recovery)

    Returns:
        Tuple[int, int]: Tuple of (keepalive_timeout, keepalive_requests)
    """
    if environment == "production":
        timeout = 65
        requests = 10000
    elif environment == "staging":
        timeout = 65
        requests = 5000
    elif environment == "dr-recovery":
        # Shorter timeout and fewer requests for DR
        timeout = 30
        requests = 1000
    else:  # Development
        timeout = 75
        requests = 1000

    return timeout, requests


def generate_performance_config(
    worker_processes: str,
    worker_connections: int,
    client_body_buffer_size: str,
    keepalive_timeout: int,
    keepalive_requests: int,
    environment: str = "production"
) -> str:
    """
    Generate NGINX performance configuration content.

    Args:
        worker_processes: Number of worker processes
        worker_connections: Number of worker connections
        client_body_buffer_size: Client body buffer size
        keepalive_timeout: Keepalive timeout in seconds
        keepalive_requests: Number of keepalive requests
        environment: Target environment

    Returns:
        str: Configuration file content
    """
    return f"""# Performance Configuration for NGINX
# Environment: {environment}
# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# This file is automatically generated - DO NOT EDIT MANUALLY

# Worker processes and connections
worker_processes {worker_processes};

events {{
    worker_connections {worker_connections};
    multi_accept on;
    use epoll;
}}

http {{
    # Buffers and timeouts
    client_body_buffer_size {client_body_buffer_size};
    client_max_body_size 100m;
    client_body_timeout 60s;
    client_header_buffer_size 2k;
    client_header_timeout 60s;
    large_client_header_buffers 4 8k;
    keepalive_timeout {keepalive_timeout};
    keepalive_requests {keepalive_requests};
    send_timeout 60s;

    # TCP optimization
    tcp_nodelay on;
    tcp_nopush on;

    # File IO operations
    sendfile on;
    aio on;
    directio 512;

    # Caching settings
    open_file_cache max=10000 inactive=30s;
    open_file_cache_valid 60s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
}}
"""


def check_current_config() -> Dict[str, Any]:
    """
    Check current NGINX configuration settings.

    Returns:
        Dict[str, Any]: Dictionary of current settings
    """
    results = {
        "worker_processes": "Not set",
        "worker_connections": DEFAULT_WORKER_CONNECTIONS,
        "client_body_buffer_size": "Not set",
        "keepalive_timeout": DEFAULT_KEEPALIVE_TIMEOUT,
        "keepalive_requests": DEFAULT_KEEPALIVE_REQUESTS
    }

    try:
        # Run nginx -T to dump configuration
        output = subprocess.check_output(
            ["nginx", "-T"],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        # Extract settings using regular expressions
        worker_processes = re.search(r"worker_processes\s+(\S+);", output)
        if worker_processes:
            results["worker_processes"] = worker_processes.group(1)

        worker_connections = re.search(r"worker_connections\s+(\d+);", output)
        if worker_connections:
            results["worker_connections"] = int(worker_connections.group(1))

        client_body_buffer = re.search(r"client_body_buffer_size\s+(\S+);", output)
        if client_body_buffer:
            results["client_body_buffer_size"] = client_body_buffer.group(1)

        keepalive_timeout = re.search(r"keepalive_timeout\s+(\d+);", output)
        if keepalive_timeout:
            results["keepalive_timeout"] = int(keepalive_timeout.group(1))

        keepalive_requests = re.search(r"keepalive_requests\s+(\d+);", output)
        if keepalive_requests:
            results["keepalive_requests"] = int(keepalive_requests.group(1))

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to check NGINX configuration: {e}")

    return results


def apply_performance_settings(
    environment: str,
    worker_processes: str,
    worker_connections: int,
    client_body_buffer_size: str,
    keepalive_timeout: int,
    keepalive_requests: int,
    nginx_root: Path = NGINX_ROOT,
    dry_run: bool = False
) -> bool:
    """
    Apply performance settings to NGINX configuration.

    Args:
        environment: Target environment
        worker_processes: Number of worker processes
        worker_connections: Number of worker connections
        client_body_buffer_size: Client body buffer size setting
        keepalive_timeout: Keepalive timeout in seconds
        keepalive_requests: Number of keepalive requests
        nginx_root: NGINX root directory
        dry_run: Only print what would be done without making changes

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Generate configuration
        config_content = generate_performance_config(
            worker_processes,
            worker_connections,
            client_body_buffer_size,
            keepalive_timeout,
            keepalive_requests,
            environment
        )

        # Define the target file
        config_file = nginx_root / "conf.d" / "performance.conf"

        if dry_run:
            logger.info(f"Would write performance configuration to {config_file}")
            logger.info("Configuration content:")
            for line in config_content.split('\n'):
                logger.info(f"  {line}")
            return True

        # Create backup if the file exists
        if config_file.exists():
            backup_path = config_file.with_suffix(f".bak.{datetime.now().strftime('%Y%m%d%H%M%S')}")
            shutil.copy2(config_file, backup_path)
            logger.info(f"Created backup of existing configuration at {backup_path}")

        # Ensure directory exists
        config_file.parent.mkdir(parents=True, exist_ok=True)

        # Write the configuration
        with open(config_file, 'w') as f:
            f.write(config_content)

        logger.info(f"Generated performance configuration at {config_file}")

        # Test NGINX configuration
        try:
            subprocess.run(["nginx", "-t"], check=True, capture_output=True)
            logger.info("NGINX configuration test passed")

            # Reload NGINX
            subprocess.run(["systemctl", "reload", "nginx"], check=True)
            logger.info("NGINX reloaded successfully with new performance settings")

        except subprocess.CalledProcessError as e:
            logger.error(f"NGINX configuration test failed: {e.stderr.decode() if e.stderr else e}")
            logger.error("Rolling back changes...")

            # Remove the generated file
            if config_file.exists():
                config_file.unlink()

            logger.error("Performance optimization failed. Changes were rolled back.")
            return False

        return True

    except Exception as e:
        logger.error(f"Failed to apply performance settings: {e}")
        return False


def setup_argparse() -> argparse.Namespace:
    """Configure and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Optimize NGINX performance settings for Cloud Infrastructure Platform"
    )
    parser.add_argument(
        "--environment", "-e",
        choices=["development", "staging", "production", "dr-recovery"],
        default="production",
        help="Target environment (default: production)"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply recommended settings (without this, only shows recommendations)"
    )
    parser.add_argument(
        "--nginx-root",
        type=Path,
        default=NGINX_ROOT,
        help=f"NGINX root directory (default: {NGINX_ROOT})"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point for the script."""
    # Import datetime here to avoid circular imports
    from datetime import datetime

    args = setup_argparse()

    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")

    environment = args.environment

    logger.info(f"Running NGINX performance optimization for {environment} environment")

    # Check if NGINX is installed
    try:
        subprocess.run(["nginx", "-v"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("NGINX is not installed or not in PATH")
        return 1

    # Get system information
    mem_total = get_total_memory()
    cpu_count = get_cpu_count()

    logger.info("System information:")
    logger.info(f"  - Total memory: {mem_total} MB")
    logger.info(f"  - CPU cores: {cpu_count}")

    # Check current configuration
    current_config = check_current_config()

    logger.info("Current NGINX configuration:")
    logger.info(f"  - worker_processes: {current_config['worker_processes']}")
    logger.info(f"  - worker_connections: {current_config['worker_connections']}")
    logger.info(f"  - client_body_buffer_size: {current_config['client_body_buffer_size']}")
    logger.info(f"  - keepalive_timeout: {current_config['keepalive_timeout']}")
    logger.info(f"  - keepalive_requests: {current_config['keepalive_requests']}")

    # Calculate optimal settings
    optimal_worker_processes = calculate_worker_processes(environment)
    optimal_worker_connections = calculate_worker_connections(environment)
    optimal_client_body_buffer_size = calculate_client_body_buffer_size(environment)
    optimal_keepalive_timeout, optimal_keepalive_requests = calculate_keepalive_settings(environment)

    logger.info("Recommended settings:")
    logger.info(f"  - worker_processes: {optimal_worker_processes}")
    logger.info(f"  - worker_connections: {optimal_worker_connections}")
    logger.info(f"  - client_body_buffer_size: {optimal_client_body_buffer_size}")
    logger.info(f"  - keepalive_timeout: {optimal_keepalive_timeout}")
    logger.info(f"  - keepalive_requests: {optimal_keepalive_requests}")

    # Apply settings if requested
    if args.apply:
        logger.info("Applying recommended settings...")

        success = apply_performance_settings(
            environment,
            optimal_worker_processes,
            optimal_worker_connections,
            optimal_client_body_buffer_size,
            optimal_keepalive_timeout,
            optimal_keepalive_requests,
            args.nginx_root,
            args.dry_run
        )

        if not success:
            logger.error("Failed to apply performance settings")
            return 1
    else:
        logger.info("To apply these settings, run the script with --apply")

    return 0


if __name__ == "__main__":
    # Import datetime here to ensure it's imported when used in generate_performance_config
    from datetime import datetime
    sys.exit(main())
