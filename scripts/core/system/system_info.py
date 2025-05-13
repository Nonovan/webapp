#!/usr/bin/env python3
# filepath: scripts/core/system/system_info.py
"""
System Information Collection Module

This module provides comprehensive system information collection capabilities for
the Cloud Infrastructure Platform. It gathers details about hardware, operating system,
network configuration, services, and other system components needed for operations,
diagnostics, and monitoring.

The module is designed to be cross-platform compatible with specific optimizations
for Linux, macOS, and Windows environments. It implements secure data collection
practices and provides configurable detail levels to support various operational needs.
"""

import datetime
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import requests
import yaml
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any, Callable

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Try to import core modules if available
try:
    from scripts.core.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

try:
    from scripts.core.error_handler import handle_error, ErrorCategory
    ERROR_HANDLER_AVAILABLE = True
except ImportError:
    logger.warning("Error handler not available, using basic error handling")
    ERROR_HANDLER_AVAILABLE = False

try:
    from scripts.core.environment import get_current_environment
    ENVIRONMENT_AVAILABLE = True
except ImportError:
    logger.warning("Environment module not available, using basic environment detection")
    ENVIRONMENT_AVAILABLE = False

    def get_current_environment():
        """Fallback environment detection if environment module is unavailable."""
        return os.environ.get('ENVIRONMENT', 'development')

try:
    from scripts.core.config_loader import load_config
    CONFIG_LOADER_AVAILABLE = True
except ImportError:
    logger.warning("Config loader not available, using default configuration")
    CONFIG_LOADER_AVAILABLE = False

# Constants
DEFAULT_REPORT_DIR = "/var/log/cloud-platform/system"
DEFAULT_TIMEOUT = 5  # seconds
DEFAULT_CMD_TIMEOUT = 10  # seconds
DEFAULT_CACHE_DURATION = 300  # seconds
MAX_FILE_SIZE = 1024 * 1024 * 50  # 50MB max for file operations


class SystemCapability(str, Enum):
    """Enumeration of system capabilities that can be detected."""
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    SYSTEMD = "systemd"
    SELINUX = "selinux"
    APPARMOR = "apparmor"
    FIREWALLD = "firewalld"
    IPTABLES = "iptables"
    UFW = "ufw"
    JOURNALD = "journald"
    NETWORK_MANAGER = "network_manager"
    VIRTUALIZATION = "virtualization"


class SystemInfoError(Exception):
    """Base exception for system info module errors."""
    pass


class SystemInfoTimeoutError(SystemInfoError):
    """Exception raised when a system information operation times out."""
    pass


class SystemInfoPermissionError(SystemInfoError):
    """Exception raised when permission is denied for system information collection."""
    pass


class SystemInfoUnavailableError(SystemInfoError):
    """Exception raised when requested system information is unavailable."""
    pass


class SystemInfo:
    """
    System information collection and reporting class.

    This class provides methods to collect detailed information about the system,
    including hardware, operating system, network configuration, services, and other
    system components.
    """

    def __init__(self,
                 include_sensitive: bool = False,
                 cache_duration: int = DEFAULT_CACHE_DURATION,
                 config_path: Optional[str] = None):
        """
        Initialize the SystemInfo instance.

        Args:
            include_sensitive: Whether to include sensitive information in reports
            cache_duration: How long to cache collected information in seconds
            config_path: Optional path to configuration file
        """
        self._include_sensitive = include_sensitive
        self._cache_duration = cache_duration
        self._cache = {}
        self._cache_timestamps = {}
        self._cache_initialized = False
        self._config_path = config_path
        self._config = {}
        self._capabilities = None
        self._platform = self._detect_platform()
        self._virtualized = None

        # Load configuration if available
        self._load_configuration()

    def _load_configuration(self) -> None:
        """Load configuration from file if available."""
        if not CONFIG_LOADER_AVAILABLE:
            return

        try:
            config_file = self._config_path or "config/system/system_info.yaml"
            config = load_config(config_file)
            if config:
                self._config = config
                logger.debug(f"Loaded system info configuration from {config_file}")
        except Exception as e:
            logger.warning(f"Failed to load system info configuration: {e}")

    def _detect_platform(self) -> Dict[str, str]:
        """
        Detect the current platform and operating system details.

        Returns:
            Dictionary with platform information
        """
        platform_info = {
            "system": platform.system().lower(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "architecture": platform.architecture()[0],
            "python_version": platform.python_version()
        }

        # Add distribution info if available (Linux)
        try:
            if platform_info["system"] == "linux":
                # Try to get Linux distribution details
                try:
                    import distro
                    platform_info["distribution"] = distro.name(pretty=True)
                    platform_info["distribution_name"] = distro.name()
                    platform_info["distribution_version"] = distro.version()
                    platform_info["distribution_codename"] = distro.codename()
                except ImportError:
                    # Fallback if distro module is not available
                    if os.path.exists("/etc/os-release"):
                        with open("/etc/os-release", "r") as f:
                            os_release = {}
                            for line in f:
                                if "=" in line:
                                    key, value = line.rstrip().split("=", 1)
                                    os_release[key] = value.strip('"')

                        platform_info["distribution"] = os_release.get("PRETTY_NAME", "")
                        platform_info["distribution_name"] = os_release.get("NAME", "")
                        platform_info["distribution_version"] = os_release.get("VERSION_ID", "")
                        platform_info["distribution_codename"] = os_release.get("VERSION_CODENAME", "")
        except Exception as e:
            logger.debug(f"Error getting distribution info: {e}")

        return platform_info

    def _is_cache_valid(self, key: str) -> bool:
        """
        Check if cached information is still valid.

        Args:
            key: Cache key to check

        Returns:
            True if the cache is valid, False otherwise
        """
        if key not in self._cache or key not in self._cache_timestamps:
            return False

        now = datetime.datetime.now().timestamp()
        return now - self._cache_timestamps[key] < self._cache_duration

    def _cache_result(self, key: str, value: Any) -> None:
        """
        Cache a result for future use.

        Args:
            key: Cache key
            value: Value to cache
        """
        self._cache[key] = value
        self._cache_timestamps[key] = datetime.datetime.now().timestamp()

    def _execute_command(self, command: List[str], timeout: int = DEFAULT_CMD_TIMEOUT) -> Tuple[str, str, int]:
        """
        Execute a system command with timeout and return its output.

        Args:
            command: Command to execute as a list of arguments
            timeout: Command timeout in seconds

        Returns:
            Tuple of (stdout, stderr, return_code)

        Raises:
            SystemInfoTimeoutError: If the command times out
            SystemInfoPermissionError: If permission is denied
        """
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            stdout, stderr = process.communicate(timeout=timeout)
            return stdout, stderr, process.returncode

        except subprocess.TimeoutExpired:
            # Make sure to kill the process if it times out
            try:
                process.kill()
                _, _ = process.communicate()
            except:
                pass

            logger.warning(f"Command timed out after {timeout}s: {' '.join(command)}")
            raise SystemInfoTimeoutError(f"Command timed out after {timeout}s: {' '.join(command)}")

        except PermissionError:
            logger.warning(f"Permission denied for command: {' '.join(command)}")
            raise SystemInfoPermissionError(f"Permission denied for command: {' '.join(command)}")

    def get_os_info(self) -> Dict[str, Any]:
        """
        Get detailed operating system information.

        Returns:
            Dictionary with OS information
        """
        # Check cache first
        cache_key = "os_info"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        # Start with basic platform info
        os_info = self._platform.copy()

        # Add boot time information if available
        try:
            if PSUTIL_AVAILABLE:
                boot_timestamp = psutil.boot_time()
                boot_time = datetime.datetime.fromtimestamp(boot_timestamp).isoformat()
                uptime_seconds = datetime.datetime.now().timestamp() - boot_timestamp

                os_info["boot_time"] = boot_time
                os_info["uptime_seconds"] = int(uptime_seconds)
                os_info["uptime_formatted"] = self._format_uptime(uptime_seconds)
        except Exception as e:
            logger.debug(f"Error getting boot time: {e}")

        # Get hostname
        try:
            os_info["hostname"] = socket.gethostname()
            # Try to get FQDN if possible
            try:
                os_info["fqdn"] = socket.getfqdn()
            except:
                pass
        except Exception as e:
            logger.debug(f"Error getting hostname: {e}")

        # Get locale and timezone if available
        try:
            import locale
            os_info["locale"] = locale.getdefaultlocale()[0]
        except Exception as e:
            logger.debug(f"Error getting locale: {e}")

        try:
            # Get timezone and UTC offset
            import time
            os_info["timezone"] = time.tzname[0]
            os_info["timezone_utc_offset"] = time.timezone
        except Exception as e:
            logger.debug(f"Error getting timezone: {e}")

        # Get virtualization info
        virtualized = self.is_virtualized()
        if virtualized:
            os_info["virtualized"] = True
            os_info["virtualization_type"] = self.get_virtualization_type()
        else:
            os_info["virtualized"] = False

        # Get container info
        if self.is_containerized():
            os_info["containerized"] = True
            os_info["container_type"] = self.get_container_type()
        else:
            os_info["containerized"] = False

        # Add kernel parameters on Linux
        if os_info["system"] == "linux":
            try:
                # Get kernel parameters for Linux
                if os.path.exists("/proc/cmdline"):
                    with open("/proc/cmdline", "r") as f:
                        cmdline = f.read().strip()
                        os_info["kernel_parameters"] = cmdline
            except Exception as e:
                logger.debug(f"Error reading kernel parameters: {e}")

        # Cache result
        self._cache_result(cache_key, os_info)
        return os_info

    def _format_uptime(self, uptime_seconds: float) -> str:
        """
        Format uptime in seconds to a human-readable string.

        Args:
            uptime_seconds: Uptime in seconds

        Returns:
            Formatted uptime string
        """
        days, remainder = divmod(int(uptime_seconds), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        parts = []
        if days > 0:
            parts.append(f"{days} day{'s' if days != 1 else ''}")
        if hours > 0 or days > 0:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes > 0 or hours > 0 or days > 0:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        if not parts:
            parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

        return ", ".join(parts)

    def get_kernel_version(self) -> str:
        """
        Get detailed kernel version information.

        Returns:
            Kernel version string
        """
        # Check cache first
        cache_key = "kernel_version"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        kernel_version = self._platform["release"]

        # On Linux, try to get more detailed information
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["uname", "-r"])
                if exit_code == 0:
                    kernel_version = stdout.strip()
            except Exception as e:
                logger.debug(f"Error getting detailed kernel version: {e}")

        # On macOS, try to get Darwin version
        elif self._platform["system"] == "darwin":
            try:
                stdout, _, exit_code = self._execute_command(["uname", "-v"])
                if exit_code == 0:
                    kernel_version = f"{kernel_version} ({stdout.strip()})"
            except Exception as e:
                logger.debug(f"Error getting macOS kernel version: {e}")

        # Cache the result
        self._cache_result(cache_key, kernel_version)
        return kernel_version

    def get_hostname(self) -> str:
        """
        Get the system hostname.

        Returns:
            Hostname string
        """
        return socket.gethostname()

    def get_cpu_info(self) -> Dict[str, Any]:
        """
        Get detailed CPU information.

        Returns:
            Dictionary with CPU information
        """
        # Check cache first
        cache_key = "cpu_info"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        cpu_info = {
            "count_logical": os.cpu_count() or 0,
            "architecture": platform.machine()
        }

        # Use psutil for more detailed information if available
        if PSUTIL_AVAILABLE:
            try:
                cpu_info["count_physical"] = psutil.cpu_count(logical=False) or cpu_info["count_logical"]

                # CPU frequency
                freq = psutil.cpu_freq()
                if freq:
                    if freq.current:
                        cpu_info["frequency_mhz"] = round(freq.current, 2)
                    if freq.min:
                        cpu_info["frequency_min_mhz"] = round(freq.min, 2)
                    if freq.max:
                        cpu_info["frequency_max_mhz"] = round(freq.max, 2)

                # CPU usage
                cpu_info["usage_percent"] = psutil.cpu_percent(interval=0.1)

                # CPU load
                if hasattr(psutil, "getloadavg"):
                    load_avg = psutil.getloadavg()
                    cpu_info["load_avg_1min"] = load_avg[0]
                    cpu_info["load_avg_5min"] = load_avg[1]
                    cpu_info["load_avg_15min"] = load_avg[2]
                elif hasattr(os, "getloadavg"):
                    load_avg = os.getloadavg()
                    cpu_info["load_avg_1min"] = load_avg[0]
                    cpu_info["load_avg_5min"] = load_avg[1]
                    cpu_info["load_avg_15min"] = load_avg[2]
            except Exception as e:
                logger.debug(f"Error getting detailed CPU info via psutil: {e}")

        # Platform-specific CPU info collection
        if self._platform["system"] == "linux":
            try:
                # Try to get CPU model info from /proc/cpuinfo
                if os.path.exists("/proc/cpuinfo"):
                    with open("/proc/cpuinfo", "r") as f:
                        cpuinfo = f.read()

                        # Get CPU model
                        model_name = re.search(r"model name\s+:\s+(.*)", cpuinfo)
                        if model_name:
                            cpu_info["model"] = model_name.group(1)

                        # Get CPU vendor
                        vendor = re.search(r"vendor_id\s+:\s+(.*)", cpuinfo)
                        if vendor:
                            cpu_info["vendor"] = vendor.group(1)

                        # Get CPU flags
                        flags = re.search(r"flags\s+:\s+(.*)", cpuinfo)
                        if flags:
                            cpu_info["flags"] = flags.group(1).split()
            except Exception as e:
                logger.debug(f"Error reading /proc/cpuinfo: {e}")

            # Get CPU vulnerabilities (Linux 4.15+)
            try:
                vulnerabilities = {}
                cpu_vulns_dir = "/sys/devices/system/cpu/vulnerabilities/"
                if os.path.isdir(cpu_vulns_dir):
                    for vuln_file in os.listdir(cpu_vulns_dir):
                        vuln_path = os.path.join(cpu_vulns_dir, vuln_file)
                        if os.path.isfile(vuln_path):
                            try:
                                with open(vuln_path, "r") as f:
                                    vulnerabilities[vuln_file] = f.read().strip()
                            except Exception:
                                pass

                    if vulnerabilities:
                        cpu_info["vulnerabilities"] = vulnerabilities
            except Exception as e:
                logger.debug(f"Error getting CPU vulnerabilities: {e}")

        elif self._platform["system"] == "darwin":
            try:
                # Use sysctl on macOS
                stdout, _, exit_code = self._execute_command(["sysctl", "-n", "machdep.cpu.brand_string"])
                if exit_code == 0:
                    cpu_info["model"] = stdout.strip()

                # Get vendor
                stdout, _, exit_code = self._execute_command(["sysctl", "-n", "machdep.cpu.vendor"])
                if exit_code == 0:
                    cpu_info["vendor"] = stdout.strip()
            except Exception as e:
                logger.debug(f"Error getting macOS CPU info: {e}")

        elif self._platform["system"] == "windows":
            try:
                # On Windows, try to use WMI for CPU info
                import wmi
                w = wmi.WMI()
                for processor in w.Win32_Processor():
                    cpu_info["model"] = processor.Name
                    cpu_info["vendor"] = processor.Manufacturer
                    cpu_info["frequency_mhz"] = processor.MaxClockSpeed
                    break
            except Exception as e:
                logger.debug(f"Error getting Windows CPU info: {e}")

        # Cache the result
        self._cache_result(cache_key, cpu_info)
        return cpu_info

    def get_cpu_count(self) -> int:
        """
        Get the number of logical CPU cores.

        Returns:
            Number of logical CPU cores
        """
        # Use the faster os.cpu_count() directly for this simple query
        return os.cpu_count() or 0

    def get_memory_info(self) -> Dict[str, Any]:
        """
        Get detailed system memory information.

        Returns:
            Dictionary with memory information
        """
        # Check cache first
        cache_key = "memory_info"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        memory_info = {}

        # Use psutil for memory information if available
        if PSUTIL_AVAILABLE:
            try:
                virtual_mem = psutil.virtual_memory()
                memory_info["total"] = virtual_mem.total
                memory_info["available"] = virtual_mem.available
                memory_info["used"] = virtual_mem.used
                memory_info["free"] = virtual_mem.free
                memory_info["percent_used"] = virtual_mem.percent

                # Convert to human-readable sizes
                memory_info["total_gb"] = round(virtual_mem.total / (1024**3), 2)
                memory_info["available_gb"] = round(virtual_mem.available / (1024**3), 2)
                memory_info["used_gb"] = round(virtual_mem.used / (1024**3), 2)
                memory_info["free_gb"] = round(virtual_mem.free / (1024**3), 2)

                # Swap information
                try:
                    swap = psutil.swap_memory()
                    memory_info["swap"] = {
                        "total": swap.total,
                        "used": swap.used,
                        "free": swap.free,
                        "percent_used": swap.percent,
                        "total_gb": round(swap.total / (1024**3), 2),
                        "used_gb": round(swap.used / (1024**3), 2),
                        "free_gb": round(swap.free / (1024**3), 2)
                    }
                except Exception as e:
                    logger.debug(f"Error getting swap info: {e}")
            except Exception as e:
                logger.debug(f"Error getting memory info via psutil: {e}")

        # Platform-specific memory info collection for fallback
        if not memory_info:
            if self._platform["system"] == "linux":
                try:
                    # Get memory info from /proc/meminfo on Linux
                    if os.path.exists("/proc/meminfo"):
                        with open("/proc/meminfo", "r") as f:
                            meminfo = f.read()

                            # Parse MemTotal
                            mem_total = re.search(r"MemTotal:\s+(\d+)", meminfo)
                            if mem_total:
                                total_kb = int(mem_total.group(1))
                                memory_info["total"] = total_kb * 1024
                                memory_info["total_gb"] = round(total_kb / (1024**2), 2)

                            # Parse MemAvailable or MemFree
                            mem_avail = re.search(r"MemAvailable:\s+(\d+)", meminfo)
                            if mem_avail:
                                avail_kb = int(mem_avail.group(1))
                                memory_info["available"] = avail_kb * 1024
                                memory_info["available_gb"] = round(avail_kb / (1024**2), 2)
                            else:
                                # Fallback to MemFree if MemAvailable is not available
                                mem_free = re.search(r"MemFree:\s+(\d+)", meminfo)
                                if mem_free:
                                    free_kb = int(mem_free.group(1))
                                    memory_info["free"] = free_kb * 1024
                                    memory_info["free_gb"] = round(free_kb / (1024**2), 2)

                            # Calculate used memory if we have both total and available/free
                            if "total" in memory_info:
                                if "available" in memory_info:
                                    memory_info["used"] = memory_info["total"] - memory_info["available"]
                                    memory_info["used_gb"] = round(memory_info["used"] / (1024**3), 2)
                                    memory_info["percent_used"] = round(memory_info["used"] / memory_info["total"] * 100, 1)
                                elif "free" in memory_info:
                                    memory_info["used"] = memory_info["total"] - memory_info["free"]
                                    memory_info["used_gb"] = round(memory_info["used"] / (1024**3), 2)
                                    memory_info["percent_used"] = round(memory_info["used"] / memory_info["total"] * 100, 1)

                            # Parse SwapTotal and SwapFree
                            swap_total = re.search(r"SwapTotal:\s+(\d+)", meminfo)
                            swap_free = re.search(r"SwapFree:\s+(\d+)", meminfo)

                            if swap_total and swap_free:
                                swap_total_kb = int(swap_total.group(1))
                                swap_free_kb = int(swap_free.group(1))
                                swap_used_kb = swap_total_kb - swap_free_kb

                                memory_info["swap"] = {
                                    "total": swap_total_kb * 1024,
                                    "free": swap_free_kb * 1024,
                                    "used": swap_used_kb * 1024,
                                    "total_gb": round(swap_total_kb / (1024**2), 2),
                                    "free_gb": round(swap_free_kb / (1024**2), 2),
                                    "used_gb": round(swap_used_kb / (1024**2), 2),
                                }

                                if swap_total_kb > 0:
                                    memory_info["swap"]["percent_used"] = round(swap_used_kb / swap_total_kb * 100, 1)

                except Exception as e:
                    logger.debug(f"Error reading /proc/meminfo: {e}")

            elif self._platform["system"] == "darwin":
                try:
                    # Use vm_stat on macOS
                    stdout, _, exit_code = self._execute_command(["vm_stat"])
                    if exit_code == 0:
                        vm_stat = stdout.strip()
                        page_size_match = re.search(r"page size of (\d+) bytes", vm_stat)
                        page_size = int(page_size_match.group(1)) if page_size_match else 4096

                        pages_free_match = re.search(r"Pages free:\s+(\d+)", vm_stat)
                        pages_active_match = re.search(r"Pages active:\s+(\d+)", vm_stat)
                        pages_inactive_match = re.search(r"Pages inactive:\s+(\d+)", vm_stat)
                        pages_speculative_match = re.search(r"Pages speculative:\s+(\d+)", vm_stat)
                        pages_wired_match = re.search(r"Pages wired down:\s+(\d+)", vm_stat)

                        if pages_free_match and pages_active_match and pages_inactive_match and pages_wired_match:
                            pages_free = int(pages_free_match.group(1))
                            pages_active = int(pages_active_match.group(1))
                            pages_inactive = int(pages_inactive_match.group(1))
                            pages_speculative = int(pages_speculative_match.group(1)) if pages_speculative_match else 0
                            pages_wired = int(pages_wired_match.group(1))

                            # Get total memory from sysctl
                            total_stdout, _, total_exit_code = self._execute_command(["sysctl", "-n", "hw.memsize"])
                            if total_exit_code == 0:
                                total_bytes = int(total_stdout.strip())
                                memory_info["total"] = total_bytes
                                memory_info["total_gb"] = round(total_bytes / (1024**3), 2)

                                # Calculate free and used memory
                                free_bytes = (pages_free + pages_inactive + pages_speculative) * page_size
                                used_bytes = (pages_active + pages_wired) * page_size

                                memory_info["free"] = free_bytes
                                memory_info["used"] = used_bytes
                                memory_info["available"] = free_bytes

                                memory_info["free_gb"] = round(free_bytes / (1024**3), 2)
                                memory_info["used_gb"] = round(used_bytes / (1024**3), 2)
                                memory_info["available_gb"] = round(free_bytes / (1024**3), 2)

                                memory_info["percent_used"] = round(used_bytes / total_bytes * 100, 1)

                    # Get swap information
                    swap_stdout, _, swap_exit_code = self._execute_command(["sysctl", "-n", "vm.swapusage"])
                    if swap_exit_code == 0:
                        swap_info = swap_stdout.strip()
                        total_match = re.search(r"total = (\d+\.\d+)([MGT])", swap_info)
                        used_match = re.search(r"used = (\d+\.\d+)([MGT])", swap_info)
                        free_match = re.search(r"free = (\d+\.\d+)([MGT])", swap_info)

                        if total_match and used_match and free_match:
                            total_value = float(total_match.group(1))
                            total_unit = total_match.group(2)
                            used_value = float(used_match.group(1))
                            used_unit = used_match.group(2)
                            free_value = float(free_match.group(1))
                            free_unit = free_match.group(2)

                            # Convert to bytes
                            unit_multiplier = {
                                "M": 1024**2,
                                "G": 1024**3,
                                "T": 1024**4
                            }

                            total_bytes = total_value * unit_multiplier.get(total_unit, 1)
                            used_bytes = used_value * unit_multiplier.get(used_unit, 1)
                            free_bytes = free_value * unit_multiplier.get(free_unit, 1)

                            memory_info["swap"] = {
                                "total": total_bytes,
                                "used": used_bytes,
                                "free": free_bytes,
                                "total_gb": round(total_bytes / (1024**3), 2),
                                "used_gb": round(used_bytes / (1024**3), 2),
                                "free_gb": round(free_bytes / (1024**3), 2)
                            }

                            if total_bytes > 0:
                                memory_info["swap"]["percent_used"] = round(used_bytes / total_bytes * 100, 1)

                except Exception as e:
                    logger.debug(f"Error getting macOS memory info: {e}")

            elif self._platform["system"] == "windows":
                try:
                    # On Windows, try to use WMI for memory info
                    import wmi
                    w = wmi.WMI()
                    for os_info in w.Win32_OperatingSystem():
                        total_bytes = int(os_info.TotalVisibleMemorySize) * 1024
                        free_bytes = int(os_info.FreePhysicalMemory) * 1024
                        used_bytes = total_bytes - free_bytes

                        memory_info["total"] = total_bytes
                        memory_info["free"] = free_bytes
                        memory_info["used"] = used_bytes
                        memory_info["available"] = free_bytes

                        memory_info["total_gb"] = round(total_bytes / (1024**3), 2)
                        memory_info["free_gb"] = round(free_bytes / (1024**3), 2)
                        memory_info["used_gb"] = round(used_bytes / (1024**3), 2)
                        memory_info["available_gb"] = round(free_bytes / (1024**3), 2)

                        memory_info["percent_used"] = round(used_bytes / total_bytes * 100, 1)
                        break

                    # Get swap information (page file)
                    pagefile_info = {}
                    for pagefile in w.Win32_PageFileUsage():
                        pagefile_total = int(pagefile.AllocatedBaseSize) * 1024 * 1024
                        pagefile_used = int(pagefile.CurrentUsage) * 1024 * 1024
                        pagefile_free = pagefile_total - pagefile_used

                        pagefile_info["total"] = pagefile_total
                        pagefile_info["used"] = pagefile_used
                        pagefile_info["free"] = pagefile_free

                        pagefile_info["total_gb"] = round(pagefile_total / (1024**3), 2)
                        pagefile_info["used_gb"] = round(pagefile_used / (1024**3), 2)
                        pagefile_info["free_gb"] = round(pagefile_free / (1024**3), 2)

                        if pagefile_total > 0:
                            pagefile_info["percent_used"] = round(pagefile_used / pagefile_total * 100, 1)
                        break

                    if pagefile_info:
                        memory_info["swap"] = pagefile_info

                except Exception as e:
                    logger.debug(f"Error getting Windows memory info: {e}")

        # Cache the result
        self._cache_result(cache_key, memory_info)
        return memory_info

    def get_total_memory(self) -> int:
        """
        Get the total system memory in MB.

        Returns:
            Total memory in MB
        """
        memory_info = self.get_memory_info()
        if "total" in memory_info:
            return round(memory_info["total"] / (1024 * 1024))
        return 0

    def get_disk_info(self, path: str = "/") -> Dict[str, Any]:
        """
        Get disk usage information for a specified path.

        Args:
            path: Path to get disk information for

        Returns:
            Dictionary with disk information
        """
        # Check cache first with path as part of the key
        cache_key = f"disk_info_{path}"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        disk_info = {}

        # Use psutil for disk information if available
        if PSUTIL_AVAILABLE:
            try:
                usage = psutil.disk_usage(path)
                disk_info["total"] = usage.total
                disk_info["used"] = usage.used
                disk_info["free"] = usage.free
                disk_info["percent_used"] = usage.percent

                # Convert to human-readable sizes
                disk_info["total_gb"] = round(usage.total / (1024**3), 2)
                disk_info["used_gb"] = round(usage.used / (1024**3), 2)
                disk_info["free_gb"] = round(usage.free / (1024**3), 2)

                # Get the mount point and device
                for partition in psutil.disk_partitions():
                    if path.startswith(partition.mountpoint):
                        disk_info["mountpoint"] = partition.mountpoint
                        disk_info["device"] = partition.device
                        disk_info["fstype"] = partition.fstype
                        if hasattr(partition, "opts"):
                            disk_info["options"] = partition.opts
                        break
            except Exception as e:
                logger.debug(f"Error getting disk info via psutil for {path}: {e}")

        # Platform-specific disk info collection as fallback
        if not disk_info:
            if self._platform["system"] == "linux" or self._platform["system"] == "darwin":
                try:
                    # Use df for Unix-like systems
                    stdout, _, exit_code = self._execute_command(["df", "-k", path])
                    if exit_code == 0:
                        lines = stdout.strip().split("\n")
                        if len(lines) > 1:
                            fields = lines[1].split()
                            if len(fields) >= 6:
                                # Fields: Filesystem 1K-blocks Used Available Use% Mounted on
                                total_kb = int(fields[1])
                                used_kb = int(fields[2])
                                free_kb = int(fields[3])

                                disk_info["total"] = total_kb * 1024
                                disk_info["used"] = used_kb * 1024
                                disk_info["free"] = free_kb * 1024

                                disk_info["total_gb"] = round(total_kb / (1024**2), 2)
                                disk_info["used_gb"] = round(used_kb / (1024**2), 2)
                                disk_info["free_gb"] = round(free_kb / (1024**2), 2)

                                percent_used = fields[4].rstrip("%")
                                disk_info["percent_used"] = float(percent_used)

                                disk_info["device"] = fields[0]
                                disk_info["mountpoint"] = fields[5]

                except Exception as e:
                    logger.debug(f"Error getting disk info via df for {path}: {e}")

            elif self._platform["system"] == "windows":
                try:
                    # Windows disk info via wmi
                    import wmi
                    w = wmi.WMI()
                    drive_letter = os.path.splitdrive(os.path.abspath(path))[0]
                    if drive_letter:
                        for drive in w.Win32_LogicalDisk(DeviceID=drive_letter):
                            total_bytes = int(drive.Size)
                            free_bytes = int(drive.FreeSpace)
                            used_bytes = total_bytes - free_bytes

                            disk_info["total"] = total_bytes
                            disk_info["free"] = free_bytes
                            disk_info["used"] = used_bytes

                            disk_info["total_gb"] = round(total_bytes / (1024**3), 2)
                            disk_info["free_gb"] = round(free_bytes / (1024**3), 2)
                            disk_info["used_gb"] = round(used_bytes / (1024**3), 2)

                            disk_info["percent_used"] = round(used_bytes / total_bytes * 100, 1) if total_bytes > 0 else 0

                            disk_info["device"] = drive.DeviceID
                            disk_info["mountpoint"] = drive.DeviceID
                            disk_info["fstype"] = drive.FileSystem
                            break

                except Exception as e:
                    logger.debug(f"Error getting Windows disk info for {path}: {e}")

        # Cache the result
        self._cache_result(cache_key, disk_info)
        return disk_info

    def get_disk_partitions(self) -> List[Dict[str, Any]]:
        """
        Get information about all disk partitions.

        Returns:
            List of dictionaries with partition information
        """
        # Check cache first
        cache_key = "disk_partitions"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        partitions = []

        # Use psutil for disk partitions if available
        if PSUTIL_AVAILABLE:
            try:
                for partition in psutil.disk_partitions(all=True):
                    partition_info = {
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype
                    }

                    # Add options if available
                    if hasattr(partition, "opts"):
                        partition_info["options"] = partition.opts

                    # Try to get usage information
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        partition_info["total"] = usage.total
                        partition_info["used"] = usage.used
                        partition_info["free"] = usage.free
                        partition_info["percent_used"] = usage.percent

                        # Convert to human-readable sizes
                        partition_info["total_gb"] = round(usage.total / (1024**3), 2)
                        partition_info["used_gb"] = round(usage.used / (1024**3), 2)
                        partition_info["free_gb"] = round(usage.free / (1024**3), 2)
                    except Exception:
                        # Some mountpoints may not be accessible
                        pass

                    partitions.append(partition_info)
            except Exception as e:
                logger.debug(f"Error getting disk partitions via psutil: {e}")

        # Platform-specific disk partitions collection as fallback
        if not partitions:
            if self._platform["system"] == "linux" or self._platform["system"] == "darwin":
                try:
                    # Use df for Unix-like systems
                    stdout, _, exit_code = self._execute_command(["df", "-k", "-T"])
                    if exit_code == 0:
                        lines = stdout.strip().split("\n")[1:]  # Skip header
                        for line in lines:
                            fields = line.split()
                            if len(fields) >= 7:
                                # Fields: Filesystem Type 1K-blocks Used Available Use% Mounted on
                                device = fields[0]
                                fstype = fields[1]
                                total_kb = int(fields[2]) if fields[2].isdigit() else 0
                                used_kb = int(fields[3]) if fields[3].isdigit() else 0
                                free_kb = int(fields[4]) if fields[4].isdigit() else 0
                                percent_used = fields[5].rstrip("%")
                                mountpoint = fields[6]

                                partition_info = {
                                    "device": device,
                                    "mountpoint": mountpoint,
                                    "fstype": fstype,
                                    "total": total_kb * 1024,
                                    "used": used_kb * 1024,
                                    "free": free_kb * 1024,
                                    "percent_used": float(percent_used) if percent_used.replace(".", "", 1).isdigit() else 0,
                                    "total_gb": round(total_kb / (1024**2), 2),
                                    "used_gb": round(used_kb / (1024**2), 2),
                                    "free_gb": round(free_kb / (1024**2), 2)
                                }

                                partitions.append(partition_info)

                except Exception as e:
                    logger.debug(f"Error getting disk partitions via df: {e}")

            elif self._platform["system"] == "windows":
                try:
                    # Windows disk partitions via wmi
                    import wmi
                    w = wmi.WMI()
                    for drive in w.Win32_LogicalDisk():
                        partition_info = {
                            "device": drive.DeviceID,
                            "mountpoint": drive.DeviceID,
                            "fstype": drive.FileSystem if hasattr(drive, "FileSystem") else "Unknown"
                        }

                        # Try to get size information
                        if hasattr(drive, "Size") and drive.Size:
                            total_bytes = int(drive.Size)
                            free_bytes = int(drive.FreeSpace) if hasattr(drive, "FreeSpace") and drive.FreeSpace else 0
                            used_bytes = total_bytes - free_bytes

                            partition_info["total"] = total_bytes
                            partition_info["free"] = free_bytes
                            partition_info["used"] = used_bytes

                            partition_info["total_gb"] = round(total_bytes / (1024**3), 2)
                            partition_info["free_gb"] = round(free_bytes / (1024**3), 2)
                            partition_info["used_gb"] = round(used_bytes / (1024**3), 2)

                            partition_info["percent_used"] = round(used_bytes / total_bytes * 100, 1) if total_bytes > 0 else 0

                        partitions.append(partition_info)

                except Exception as e:
                    logger.debug(f"Error getting Windows disk partitions: {e}")

        # Cache the result
        self._cache_result(cache_key, partitions)
        return partitions

    def get_network_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get network interfaces and configuration information.

        Returns:
            Dictionary with network information, keyed by interface name
        """
        # Check cache first
        cache_key = "network_info"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        network_info = {}

        # Use psutil for network information if available
        if PSUTIL_AVAILABLE:
            try:
                # Get all network interfaces
                net_if_addrs = psutil.net_if_addrs()
                net_if_stats = psutil.net_if_stats() if hasattr(psutil, "net_if_stats") else {}

                for interface, addrs in net_if_addrs.items():
                    interface_info = {
                        "addresses": []
                    }

                    # Add interface statistics if available
                    if interface in net_if_stats:
                        stats = net_if_stats[interface]
                        interface_info["is_up"] = stats.isup
                        if hasattr(stats, "speed"):
                            interface_info["speed"] = stats.speed
                        if hasattr(stats, "duplex"):
                            interface_info["duplex"] = stats.duplex
                        if hasattr(stats, "mtu"):
                            interface_info["mtu"] = stats.mtu

                    # Process addresses
                    ipv4_addresses = []
                    ipv6_addresses = []
                    mac_address = None

                    for addr in addrs:
                        addr_info = {}
                        if addr.family == socket.AF_INET:  # IPv4
                            addr_info = {
                                "address": addr.address,
                                "netmask": addr.netmask,
                                "broadcast": addr.broadcast if hasattr(addr, "broadcast") else None,
                                "family": "IPv4"
                            }
                            ipv4_addresses.append(addr_info)
                        elif addr.family == socket.AF_INET6:  # IPv6
                            addr_info = {
                                "address": addr.address,
                                "netmask": addr.netmask if hasattr(addr, "netmask") else None,
                                "family": "IPv6"
                            }
                            ipv6_addresses.append(addr_info)
                        elif getattr(addr, "family", None) == psutil.AF_LINK:  # MAC address
                            mac_address = addr.address
                            interface_info["mac"] = mac_address

                    # Add IP addresses to interface info
                    if ipv4_addresses:
                        interface_info["ipv4"] = ipv4_addresses
                        interface_info["ip"] = ipv4_addresses[0]["address"]  # Primary IPv4

                    if ipv6_addresses:
                        interface_info["ipv6"] = ipv6_addresses

                    interface_info["addresses"] = ipv4_addresses + ipv6_addresses

                    # Add to network_info
                    network_info[interface] = interface_info

                # Add network traffic statistics if available
                try:
                    net_io_counters = psutil.net_io_counters(pernic=True)
                    for interface, counters in net_io_counters.items():
                        if interface in network_info:
                            network_info[interface]["stats"] = {
                                "bytes_sent": counters.bytes_sent,
                                "bytes_recv": counters.bytes_recv,
                                "packets_sent": counters.packets_sent,
                                "packets_recv": counters.packets_recv,
                                "errin": counters.errin if hasattr(counters, "errin") else 0,
                                "errout": counters.errout if hasattr(counters, "errout") else 0,
                                "dropin": counters.dropin if hasattr(counters, "dropin") else 0,
                                "dropout": counters.dropout if hasattr(counters, "dropout") else 0
                            }
                except Exception as e:
                    logger.debug(f"Error getting network traffic stats: {e}")

                # Add connection information if available
                try:
                    connections = psutil.net_connections()
                    conn_count = {
                        "total": len(connections),
                        "established": 0,
                        "listen": 0,
                        "time_wait": 0,
                        "close_wait": 0,
                        "other": 0
                    }

                    for conn in connections:
                        status = conn.status.lower() if hasattr(conn, "status") else "other"
                        if status == "established":
                            conn_count["established"] += 1
                        elif status == "listen":
                            conn_count["listen"] += 1
                        elif status == "time_wait":
                            conn_count["time_wait"] += 1
                        elif status == "close_wait":
                            conn_count["close_wait"] += 1
                        else:
                            conn_count["other"] += 1

                    network_info["connections"] = conn_count
                except Exception as e:
                    logger.debug(f"Error getting network connections: {e}")

            except Exception as e:
                logger.debug(f"Error getting network info via psutil: {e}")

        # Platform-specific network info collection as fallback
        if not network_info:
            if self._platform["system"] == "linux":
                try:
                    # Use ip command on Linux
                    stdout, _, exit_code = self._execute_command(["ip", "addr", "show"])
                    if exit_code == 0:
                        current_interface = None
                        for line in stdout.strip().split("\n"):
                            # Interface line
                            if line[0].isdigit():
                                match = re.match(r'^\d+:\s+([^:]+):', line)
                                if match:
                                    current_interface = match.group(1)
                                    network_info[current_interface] = {
                                        "addresses": [],
                                        "is_up": "UP" in line
                                    }

                                    # Extract MTU if present
                                    mtu_match = re.search(r'mtu\s+(\d+)', line)
                                    if mtu_match:
                                        network_info[current_interface]["mtu"] = int(mtu_match.group(1))

                            # MAC address line
                            elif current_interface and "link/ether" in line:
                                match = re.search(r'link/ether\s+([0-9a-f:]+)', line)
                                if match:
                                    network_info[current_interface]["mac"] = match.group(1)

                            # IPv4 address line
                            elif current_interface and "inet " in line:
                                match = re.search(r'inet\s+([0-9.]+)/(\d+)', line)
                                if match:
                                    addr = match.group(1)
                                    prefix = int(match.group(2))
                                    netmask = self._prefix_to_netmask(prefix)

                                    # Store IPv4 info
                                    ipv4_info = {
                                        "address": addr,
                                        "netmask": netmask,
                                        "family": "IPv4"
                                    }

                                    # Extract broadcast if present
                                    brd_match = re.search(r'brd\s+([0-9.]+)', line)
                                    if brd_match:
                                        ipv4_info["broadcast"] = brd_match.group(1)

                                    if "ipv4" not in network_info[current_interface]:
                                        network_info[current_interface]["ipv4"] = []
                                    network_info[current_interface]["ipv4"].append(ipv4_info)
                                    network_info[current_interface]["addresses"].append(ipv4_info)

                                    # Set primary IP if not already set
                                    if "ip" not in network_info[current_interface]:
                                        network_info[current_interface]["ip"] = addr

                            # IPv6 address line
                            elif current_interface and "inet6 " in line:
                                match = re.search(r'inet6\s+([0-9a-f:]+)/(\d+)', line)
                                if match:
                                    addr = match.group(1)
                                    prefix = match.group(2)

                                    # Store IPv6 info
                                    ipv6_info = {
                                        "address": addr,
                                        "netmask": None,  # IPv6 uses prefix length instead
                                        "prefix_length": prefix,
                                        "family": "IPv6"
                                    }

                                    if "ipv6" not in network_info[current_interface]:
                                        network_info[current_interface]["ipv6"] = []
                                    network_info[current_interface]["ipv6"].append(ipv6_info)
                                    network_info[current_interface]["addresses"].append(ipv6_info)

                except Exception as e:
                    logger.debug(f"Error getting network info via ip command: {e}")

            elif self._platform["system"] == "darwin":
                try:
                    # Use ifconfig on macOS
                    stdout, _, exit_code = self._execute_command(["ifconfig"])
                    if exit_code == 0:
                        current_interface = None
                        for line in stdout.strip().split("\n"):
                            # Interface line
                            if not line.startswith("\t") and ":" in line:
                                match = re.match(r'^([^:]+):', line)
                                if match:
                                    current_interface = match.group(1)
                                    network_info[current_interface] = {
                                        "addresses": [],
                                        "is_up": "UP" in line.upper()
                                    }

                                    # Extract MTU if present
                                    mtu_match = re.search(r'mtu\s+(\d+)', line)
                                    if mtu_match:
                                        network_info[current_interface]["mtu"] = int(mtu_match.group(1))

                            # MAC address (ether) line
                            elif current_interface and "\tether " in line:
                                match = re.search(r'ether\s+([0-9a-f:]+)', line)
                                if match:
                                    network_info[current_interface]["mac"] = match.group(1)

                            # IPv4 address (inet) line
                            elif current_interface and "\tinet " in line:
                                match = re.search(r'inet\s+([0-9.]+)\s+netmask\s+0x([0-9a-f]+)', line)
                                if match:
                                    addr = match.group(1)
                                    netmask_hex = match.group(2)
                                    netmask = self._hex_to_ip(netmask_hex)

                                    # Store IPv4 info
                                    ipv4_info = {
                                        "address": addr,
                                        "netmask": netmask,
                                        "family": "IPv4"
                                    }

                                    # Extract broadcast if present
                                    brd_match = re.search(r'broadcast\s+([0-9.]+)', line)
                                    if brd_match:
                                        ipv4_info["broadcast"] = brd_match.group(1)

                                    if "ipv4" not in network_info[current_interface]:
                                        network_info[current_interface]["ipv4"] = []
                                    network_info[current_interface]["ipv4"].append(ipv4_info)
                                    network_info[current_interface]["addresses"].append(ipv4_info)

                                    # Set primary IP if not already set
                                    if "ip" not in network_info[current_interface]:
                                        network_info[current_interface]["ip"] = addr

                            # IPv6 address (inet6) line
                            elif current_interface and "\tinet6 " in line:
                                match = re.search(r'inet6\s+([0-9a-f:]+)(\s+prefixlen\s+(\d+))?', line)
                                if match:
                                    addr = match.group(1)
                                    prefix = match.group(3) if match.group(3) else "128"

                                    # Store IPv6 info
                                    ipv6_info = {
                                        "address": addr,
                                        "netmask": None,
                                        "prefix_length": prefix,
                                        "family": "IPv6"
                                    }

                                    if "ipv6" not in network_info[current_interface]:
                                        network_info[current_interface]["ipv6"] = []
                                    network_info[current_interface]["ipv6"].append(ipv6_info)
                                    network_info[current_interface]["addresses"].append(ipv6_info)

                except Exception as e:
                    logger.debug(f"Error getting network info via ifconfig: {e}")

            elif self._platform["system"] == "windows":
                try:
                    # Windows network info via wmi
                    import wmi
                    w = wmi.WMI()

                    # Get network adapters and their configuration
                    for adapter in w.Win32_NetworkAdapter():
                        if adapter.NetEnabled:
                            interface_name = adapter.NetConnectionID
                            if interface_name:
                                interface_info = {
                                    "addresses": [],
                                    "is_up": adapter.NetEnabled,
                                    "mac": adapter.MACAddress if adapter.MACAddress else None,
                                    "speed": adapter.Speed if hasattr(adapter, "Speed") and adapter.Speed else None
                                }

                                # Get IP addresses for this adapter
                                for addr in w.Win32_NetworkAdapterConfiguration(InterfaceIndex=adapter.InterfaceIndex):
                                    if addr.IPEnabled:
                                        # IPv4 addresses
                                        if addr.IPAddress and addr.IPAddress[0]:
                                            ipv4_addresses = []
                                            for i, ip in enumerate(addr.IPAddress):
                                                if ":" not in ip:  # Skip IPv6 addresses
                                                    ipv4_info = {
                                                        "address": ip,
                                                        "family": "IPv4"
                                                    }

                                                    # Add netmask if available
                                                    if addr.IPSubnet and i < len(addr.IPSubnet):
                                                        ipv4_info["netmask"] = addr.IPSubnet[i]

                                                    ipv4_addresses.append(ipv4_info)
                                                    interface_info["addresses"].append(ipv4_info)

                                            if ipv4_addresses:
                                                interface_info["ipv4"] = ipv4_addresses
                                                interface_info["ip"] = ipv4_addresses[0]["address"]

                                        # IPv6 addresses
                                        ipv6_addresses = []
                                        if hasattr(addr, "IPAddress") and addr.IPAddress:
                                            for ip in addr.IPAddress:
                                                if ":" in ip:  # Only IPv6 addresses
                                                    ipv6_info = {
                                                        "address": ip,
                                                        "family": "IPv6"
                                                    }
                                                    ipv6_addresses.append(ipv6_info)
                                                    interface_info["addresses"].append(ipv6_info)

                                        if ipv6_addresses:
                                            interface_info["ipv6"] = ipv6_addresses

                                network_info[interface_name] = interface_info

                except Exception as e:
                    logger.debug(f"Error getting Windows network info: {e}")

        # Cache the result
        self._cache_result(cache_key, network_info)
        return network_info

    def _prefix_to_netmask(self, prefix: int) -> str:
        """
        Convert a CIDR prefix to a netmask.

        Args:
            prefix: CIDR prefix length (0-32)

        Returns:
            Netmask as string (e.g. "255.255.255.0")
        """
        try:
            # Create a netmask from the prefix
            netmask_bits = 0xffffffff ^ (1 << 32 - prefix) - 1
            return socket.inet_ntoa(netmask_bits.to_bytes(4, byteorder="big"))
        except Exception:
            return ""

    def _hex_to_ip(self, hex_str: str) -> str:
        """
        Convert a hexadecimal string to an IP address.

        Args:
            hex_str: Hexadecimal string (e.g. "ffffff00")

        Returns:
            IP address as string (e.g. "255.255.255.0")
        """
        try:
            # Convert hexadecimal string to integer
            hex_int = int(hex_str, 16)

            # Convert integer to bytes and then to IP address
            return socket.inet_ntoa(hex_int.to_bytes(4, byteorder="big"))
        except Exception as e:
            logger.debug(f"Error converting hex to IP: {e}")
            return ""

    def is_virtualized(self) -> bool:
        """
        Check if the system is running in a virtualized environment.

        Returns:
            True if virtualized, False otherwise
        """
        # Return cached value if available
        if self._virtualized is not None:
            return self._virtualized

        virtualized = False

        # Check for common virtualization indicators
        if self._platform["system"] == "linux":
            # Check DMI for virtualization indicators
            try:
                if os.path.exists("/sys/devices/virtual/dmi/id/product_name"):
                    with open("/sys/devices/virtual/dmi/id/product_name", "r") as f:
                        product_name = f.read().strip().lower()
                        if any(name in product_name for name in [
                            "vmware", "virtualbox", "kvm", "xen", "qemu", "hyper-v",
                            "virtual machine", "amazon ec2"
                        ]):
                            virtualized = True
            except Exception as e:
                logger.debug(f"Error checking DMI product name: {e}")

            # Check /proc/cpuinfo for hypervisor flag
            try:
                if not virtualized and os.path.exists("/proc/cpuinfo"):
                    with open("/proc/cpuinfo", "r") as f:
                        cpuinfo = f.read().lower()
                        if "hypervisor" in cpuinfo or "vmware" in cpuinfo:
                            virtualized = True
            except Exception as e:
                logger.debug(f"Error checking /proc/cpuinfo: {e}")

            # Check systemd-detect-virt if available
            try:
                if not virtualized:
                    stdout, _, exit_code = self._execute_command(["systemd-detect-virt"])
                    if exit_code == 0 and stdout.strip() not in ["none", ""]:
                        virtualized = True
            except Exception as e:
                logger.debug(f"Error executing systemd-detect-virt: {e}")

        elif self._platform["system"] == "darwin":
            # Check for common macOS virtualization
            try:
                stdout, _, exit_code = self._execute_command(["sysctl", "-n", "machdep.cpu.features"])
                if exit_code == 0 and "VMM" in stdout:
                    virtualized = True
            except Exception as e:
                logger.debug(f"Error checking macOS CPU features: {e}")

            # Check for common virtualization hardware models
            try:
                if not virtualized:
                    stdout, _, exit_code = self._execute_command(["sysctl", "-n", "hw.model"])
                    if exit_code == 0 and ("VMware" in stdout or "Virtual" in stdout):
                        virtualized = True
            except Exception as e:
                logger.debug(f"Error checking macOS hardware model: {e}")

        elif self._platform["system"] == "windows":
            # Check for Windows virtualization via WMI
            try:
                import wmi
                w = wmi.WMI()

                # Check computer system
                for system in w.Win32_ComputerSystem():
                    if system.Model and any(model in system.Model for model in [
                        "VMware", "VirtualBox", "Virtual Machine", "HVM domU", "KVM"
                    ]):
                        virtualized = True
                        break

                # Check BIOS information if still not determined
                if not virtualized:
                    for bios in w.Win32_BIOS():
                        if bios.Manufacturer and any(vendor in bios.Manufacturer for vendor in [
                            "VMware", "innotek", "QEMU", "Xen", "Microsoft Corporation"
                        ]):
                            virtualized = True
                            break
            except Exception as e:
                logger.debug(f"Error checking Windows virtualization via WMI: {e}")

        # Use psutil as a fallback
        if not virtualized and PSUTIL_AVAILABLE:
            try:
                virtualization = psutil.virtual_memory().total < 1024 * 1024 * 1024 * 4  # < 4GB RAM is suspicious
                if virtualization:
                    # Check CPU count; most VMs have fewer cores
                    if psutil.cpu_count(logical=False) < 3:
                        virtualized = True
            except Exception as e:
                logger.debug(f"Error checking virtualization via psutil: {e}")

        # Cache result
        self._virtualized = virtualized
        return virtualized

    def get_virtualization_type(self) -> str:
        """
        Get the virtualization technology being used.

        Returns:
            Virtualization type as string (e.g., "kvm", "vmware", "xen")
            or empty string if not virtualized or unable to determine.
        """
        if not self.is_virtualized():
            return ""

        virt_type = ""

        if self._platform["system"] == "linux":
            # Try systemd-detect-virt first
            try:
                stdout, _, exit_code = self._execute_command(["systemd-detect-virt"])
                if exit_code == 0 and stdout.strip() not in ["none", ""]:
                    virt_type = stdout.strip()
            except Exception as e:
                logger.debug(f"Error executing systemd-detect-virt: {e}")

            # Check DMI product information
            if not virt_type:
                try:
                    if os.path.exists("/sys/devices/virtual/dmi/id/product_name"):
                        with open("/sys/devices/virtual/dmi/id/product_name", "r") as f:
                            product = f.read().strip().lower()
                            if "vmware" in product:
                                virt_type = "vmware"
                            elif "virtualbox" in product:
                                virt_type = "virtualbox"
                            elif "kvm" in product:
                                virt_type = "kvm"
                            elif "xen" in product:
                                virt_type = "xen"
                            elif "hyper-v" in product:
                                virt_type = "hyper-v"
                            elif "amazon ec2" in product:
                                virt_type = "aws"
                except Exception as e:
                    logger.debug(f"Error checking DMI product name: {e}")

            # Try lscpu as another option
            if not virt_type:
                try:
                    stdout, _, exit_code = self._execute_command(["lscpu"])
                    if exit_code == 0:
                        match = re.search(r"Hypervisor vendor:\s+(.+)", stdout)
                        if match:
                            hypervisor = match.group(1).lower()
                            if "kvm" in hypervisor:
                                virt_type = "kvm"
                            elif "vmware" in hypervisor:
                                virt_type = "vmware"
                            elif "microsoft" in hypervisor:
                                virt_type = "hyper-v"
                            elif "xen" in hypervisor:
                                virt_type = "xen"
                            else:
                                virt_type = hypervisor
                except Exception as e:
                    logger.debug(f"Error executing lscpu: {e}")

        elif self._platform["system"] == "darwin":
            # Check for common macOS virtualization
            try:
                stdout, _, exit_code = self._execute_command(["sysctl", "-n", "hw.model"])
                if exit_code == 0:
                    if "VMware" in stdout:
                        virt_type = "vmware"
                    elif "VirtualBox" in stdout:
                        virt_type = "virtualbox"
                    elif "Parallels" in stdout:
                        virt_type = "parallels"
            except Exception as e:
                logger.debug(f"Error checking macOS virtualization type: {e}")

        elif self._platform["system"] == "windows":
            # Check for Windows virtualization via WMI
            try:
                import wmi
                w = wmi.WMI()

                # Check computer system
                for system in w.Win32_ComputerSystem():
                    if system.Model:
                        model = system.Model.lower()
                        if "vmware" in model:
                            virt_type = "vmware"
                        elif "virtualbox" in model:
                            virt_type = "virtualbox"
                        elif "hyper-v" in model:
                            virt_type = "hyper-v"
                        elif "kvm" in model:
                            virt_type = "kvm"
                        elif "xen" in model:
                            virt_type = "xen"

                # Check BIOS information if still not determined
                if not virt_type:
                    for bios in w.Win32_BIOS():
                        if bios.Manufacturer:
                            mfg = bios.Manufacturer.lower()
                            if "vmware" in mfg:
                                virt_type = "vmware"
                            elif "innotek" in mfg:  # VirtualBox
                                virt_type = "virtualbox"
                            elif "microsoft" in mfg:
                                virt_type = "hyper-v"
                            elif "xen" in mfg:
                                virt_type = "xen"
            except Exception as e:
                logger.debug(f"Error checking Windows virtualization type: {e}")

        return virt_type

    def is_containerized(self) -> bool:
        """
        Check if the system is running inside a container.

        Returns:
            True if inside a container, False otherwise
        """
        # Check if running inside a container
        container = False

        # Check for common container indicators
        if self._platform["system"] == "linux":
            # Check for Docker
            try:
                if os.path.exists("/.dockerenv"):
                    return True
            except Exception:
                pass

            # Check for containerd or other OCI runtimes
            try:
                with open("/proc/1/cgroup", "r") as f:
                    cgroups = f.read()
                    if any(x in cgroups for x in ["docker", "kubepods", "container", "lxc"]):
                        return True
            except Exception:
                pass

            # Check for Kubernetes service account
            try:
                if os.path.exists("/var/run/secrets/kubernetes.io"):
                    return True
            except Exception:
                pass

        return container

    def get_container_type(self) -> str:
        """
        Get the type of container technology being used.

        Returns:
            Container type (e.g., "docker", "lxc", "kubernetes") or empty string
        """
        if not self.is_containerized():
            return ""

        container_type = ""

        if self._platform["system"] == "linux":
            # Check for Docker
            try:
                if os.path.exists("/.dockerenv"):
                    container_type = "docker"
            except Exception:
                pass

            # Check cgroups for container information
            if not container_type:
                try:
                    with open("/proc/1/cgroup", "r") as f:
                        cgroups = f.read().lower()
                        if "docker" in cgroups:
                            container_type = "docker"
                        elif "kubepods" in cgroups:
                            container_type = "kubernetes"
                        elif "lxc" in cgroups:
                            container_type = "lxc"
                except Exception:
                    pass

            # Check for Kubernetes service account
            if not container_type and os.path.exists("/var/run/secrets/kubernetes.io"):
                container_type = "kubernetes"

        return container_type

    def has_capability(self, capability: SystemCapability) -> bool:
        """
        Check if the system has a specific capability.

        Args:
            capability: The SystemCapability to check

        Returns:
            True if the capability is available, False otherwise
        """
        # Initialize capabilities dictionary if not already done
        if self._capabilities is None:
            self._capabilities = {}
            self._detect_capabilities()

        # Return the cached capability status
        return self._capabilities.get(capability, False)

    def _detect_capabilities(self) -> None:
        """Detect all system capabilities and store them in the cache."""
        # Docker capability
        self._capabilities[SystemCapability.DOCKER] = self._check_docker_capability()

        # Kubernetes capability
        self._capabilities[SystemCapability.KUBERNETES] = self._check_kubernetes_capability()

        # Cloud provider capabilities
        self._capabilities[SystemCapability.AWS] = self._check_aws_capability()
        self._capabilities[SystemCapability.AZURE] = self._check_azure_capability()
        self._capabilities[SystemCapability.GCP] = self._check_gcp_capability()

        # System service capabilities
        self._capabilities[SystemCapability.SYSTEMD] = self._check_systemd_capability()
        self._capabilities[SystemCapability.SELINUX] = self._check_selinux_capability()
        self._capabilities[SystemCapability.APPARMOR] = self._check_apparmor_capability()
        self._capabilities[SystemCapability.FIREWALLD] = self._check_firewalld_capability()
        self._capabilities[SystemCapability.IPTABLES] = self._check_iptables_capability()
        self._capabilities[SystemCapability.UFW] = self._check_ufw_capability()
        self._capabilities[SystemCapability.JOURNALD] = self._check_journald_capability()
        self._capabilities[SystemCapability.NETWORK_MANAGER] = self._check_network_manager_capability()

        # Virtualization capability (already detected)
        self._capabilities[SystemCapability.VIRTUALIZATION] = self.is_virtualized()

    def _check_docker_capability(self) -> bool:
        """Check if Docker is available on the system."""
        # Check if docker command is available
        try:
            stdout, _, exit_code = self._execute_command(["docker", "info"])
            if exit_code == 0:
                return True

            # Try checking for the docker socket
            if os.path.exists("/var/run/docker.sock"):
                return True
        except Exception:
            pass

        # For Windows, check for Docker service
        if self._platform["system"] == "windows":
            try:
                import wmi
                w = wmi.WMI()
                for service in w.Win32_Service(Name="docker"):
                    return True
            except Exception:
                pass

        return False

    def _check_kubernetes_capability(self) -> bool:
        """Check if Kubernetes is available on the system."""
        # Check if kubectl command is available
        try:
            stdout, _, exit_code = self._execute_command(["kubectl", "version", "--client"])
            if exit_code == 0:
                return True
        except Exception:
            pass

        # Check for Kubernetes configuration
        if os.path.exists(os.path.expanduser("~/.kube/config")):
            return True

        # Check if we're running inside Kubernetes
        if os.path.exists("/var/run/secrets/kubernetes.io"):
            return True

        return False

    def _check_aws_capability(self) -> bool:
        """Check if AWS is available or if running on AWS."""
        # Check for AWS CLI
        try:
            stdout, _, exit_code = self._execute_command(["aws", "--version"])
            if exit_code == 0:
                return True
        except Exception:
            pass

        # Check if running on AWS EC2
        try:
            # AWS metadata service
            if os.path.exists("/sys/hypervisor/uuid"):
                with open("/sys/hypervisor/uuid", "r") as f:
                    uuid = f.read().strip()
                    if uuid.startswith("ec2"):
                        return True
        except Exception:
            pass

        # Check for AWS environment variables
        if any(env in os.environ for env in [
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"
        ]):
            return True

        return False

    def _check_azure_capability(self) -> bool:
        """Check if Azure is available or if running on Azure."""
        # Check for Azure CLI
        try:
            stdout, _, exit_code = self._execute_command(["az", "--version"])
            if exit_code == 0:
                return True
        except Exception:
            pass

        # Check for Azure environment indicators
        if os.path.exists("/var/lib/waagent"):
            return True

        # Check for Azure environment variables
        if any(env.startswith("AZURE_") for env in os.environ):
            return True

        return False

    def _check_gcp_capability(self) -> bool:
        """Check if GCP is available or if running on GCP."""
        # Check for gcloud CLI
        try:
            stdout, _, exit_code = self._execute_command(["gcloud", "--version"])
            if exit_code == 0:
                return True
        except Exception:
            pass

        # Check for GCP metadata service (for GCE)
        try:
            response = requests.get(
                "http://metadata.google.internal/computeMetadata/v1/instance/",
                headers={"Metadata-Flavor": "Google"},
                timeout=1
            )
            if response.status_code == 200:
                return True
        except Exception:
            pass

        # Check for GCP environment variables
        if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
            return True

        return False

    def _check_systemd_capability(self) -> bool:
        """Check if systemd is available on the system."""
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["systemctl", "--version"])
                if exit_code == 0:
                    return True
            except Exception:
                pass

            # Check for the systemd directory
            if os.path.exists("/run/systemd/system"):
                return True

        return False

    def _check_selinux_capability(self) -> bool:
        """Check if SELinux is available on the system."""
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["getenforce"])
                if exit_code == 0:
                    return True
            except Exception:
                pass

            # Check for SELinux configuration
            if os.path.exists("/etc/selinux/config"):
                return True

        return False

    def _check_apparmor_capability(self) -> bool:
        """Check if AppArmor is available on the system."""
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["apparmor_status"])
                if exit_code == 0:
                    return True
            except Exception:
                pass

            # Check for AppArmor directory
            if os.path.exists("/sys/kernel/security/apparmor"):
                return True

        return False

    def _check_firewalld_capability(self) -> bool:
        """Check if firewalld is available on the system."""
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["firewall-cmd", "--state"])
                if exit_code == 0:
                    return True
            except Exception:
                pass

            # Check for firewalld service
            if os.path.exists("/usr/sbin/firewalld"):
                return True

        return False

    def _check_iptables_capability(self) -> bool:
        """Check if iptables is available on the system."""
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["iptables", "--version"])
                if exit_code == 0:
                    return True
            except Exception:
                pass

        return False

    def _check_ufw_capability(self) -> bool:
        """Check if UFW (Uncomplicated Firewall) is available on the system."""
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["ufw", "status"])
                if exit_code == 0:
                    return True
            except Exception:
                pass

            # Check for UFW configuration
            if os.path.exists("/etc/ufw/ufw.conf"):
                return True

        return False

    def _check_journald_capability(self) -> bool:
        """Check if journald is available on the system."""
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["journalctl", "--version"])
                if exit_code == 0:
                    return True
            except Exception:
                pass

            # Check for journald directory
            if os.path.exists("/run/systemd/journal"):
                return True

        return False

    def _check_network_manager_capability(self) -> bool:
        """Check if NetworkManager is available on the system."""
        if self._platform["system"] == "linux":
            try:
                stdout, _, exit_code = self._execute_command(["nmcli", "--version"])
                if exit_code == 0:
                    return True
            except Exception:
                pass

            # Check for NetworkManager service
            if os.path.exists("/usr/sbin/NetworkManager"):
                return True

        return False

    def is_service_running(self, service_name: str) -> bool:
        """
        Check if a system service is running.

        Args:
            service_name: Name of the service to check

        Returns:
            True if service is running, False otherwise
        """
        if self._platform["system"] == "linux":
            # Try systemctl if systemd is available
            if self.has_capability(SystemCapability.SYSTEMD):
                try:
                    stdout, _, exit_code = self._execute_command(
                        ["systemctl", "is-active", service_name]
                    )
                    return exit_code == 0 and stdout.strip() == "active"
                except Exception:
                    pass

            # Try service command as fallback
            try:
                stdout, _, exit_code = self._execute_command(
                    ["service", service_name, "status"]
                )
                return exit_code == 0 and "running" in stdout.lower()
            except Exception:
                pass

        elif self._platform["system"] == "darwin":
            # Check launchd services on macOS
            try:
                stdout, _, exit_code = self._execute_command(
                    ["launchctl", "list", service_name]
                )
                return exit_code == 0
            except Exception:
                pass

        elif self._platform["system"] == "windows":
            # Check Windows services
            try:
                import wmi
                w = wmi.WMI()
                for service in w.Win32_Service(Name=service_name):
                    return service.State == "Running"
            except Exception:
                pass

        return False

    def get_service_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of common system services.

        Returns:
            Dictionary of service statuses keyed by service name
        """
        # Check cache first
        cache_key = "service_status"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        services = {}
        common_services = [
            # Web servers
            "nginx", "apache2", "httpd",
            # Databases
            "mysql", "postgresql", "mongodb", "redis-server",
            # Message queues
            "rabbitmq-server", "kafka",
            # Monitoring
            "prometheus", "grafana-server", "node_exporter",
            # Other common services
            "ssh", "sshd", "docker"
        ]

        for service in common_services:
            running = self.is_service_running(service)
            if running:
                services[service] = {
                    "running": True,
                    "status": "running"
                }

                # Try to get more details based on the service type
                if service in ["nginx", "apache2", "httpd"]:
                    services[service]["type"] = "web_server"
                elif service in ["mysql", "postgresql", "mongodb"]:
                    services[service]["type"] = "database"
                elif service in ["redis-server"]:
                    services[service]["type"] = "cache"
                elif service in ["rabbitmq-server", "kafka"]:
                    services[service]["type"] = "message_queue"
                elif service in ["prometheus", "grafana-server", "node_exporter"]:
                    services[service]["type"] = "monitoring"
                elif service in ["ssh", "sshd"]:
                    services[service]["type"] = "remote_access"
                elif service == "docker":
                    services[service]["type"] = "container_runtime"

        # Cache the result
        self._cache_result(cache_key, services)
        return services

    def get_installed_packages(self, limit: int = 100) -> List[Dict[str, str]]:
        """
        Get information about installed packages.

        Args:
            limit: Maximum number of packages to return (0 for all)

        Returns:
            List of dictionaries with package information
        """
        # Check cache first
        cache_key = f"installed_packages_{limit}"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        packages = []

        if self._platform["system"] == "linux":
            # Determine package manager
            if shutil.which("dpkg"):
                # Debian/Ubuntu
                try:
                    stdout, _, exit_code = self._execute_command(["dpkg-query", "-W", "-f=${Package}|${Version}|${Status}\n"])
                    if exit_code == 0:
                        for line in stdout.strip().split("\n"):
                            parts = line.split("|")
                            if len(parts) >= 3 and "installed" in parts[2]:
                                package = {"name": parts[0], "version": parts[1], "manager": "dpkg"}
                                packages.append(package)
                except Exception as e:
                    logger.debug(f"Error getting dpkg packages: {e}")

            elif shutil.which("rpm"):
                # RHEL/CentOS/Fedora
                try:
                    stdout, _, exit_code = self._execute_command(["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}\n"])
                    if exit_code == 0:
                        for line in stdout.strip().split("\n"):
                            parts = line.split("|")
                            if len(parts) == 2:
                                package = {"name": parts[0], "version": parts[1], "manager": "rpm"}
                                packages.append(package)
                except Exception as e:
                    logger.debug(f"Error getting rpm packages: {e}")

        elif self._platform["system"] == "darwin":
            # macOS - check Homebrew
            if shutil.which("brew"):
                try:
                    stdout, _, exit_code = self._execute_command(["brew", "list", "--versions"])
                    if exit_code == 0:
                        for line in stdout.strip().split("\n"):
                            parts = line.split()
                            if len(parts) >= 2:
                                package = {"name": parts[0], "version": parts[1], "manager": "homebrew"}
                                packages.append(package)
                except Exception as e:
                    logger.debug(f"Error getting homebrew packages: {e}")

        elif self._platform["system"] == "windows":
            # Windows - try to get installed programs from registry
            try:
                import winreg
                import wmi

                w = wmi.WMI()
                for product in w.Win32_Product():
                    package = {"name": product.Name, "version": product.Version, "manager": "windows"}
                    packages.append(package)
            except Exception as e:
                logger.debug(f"Error getting Windows installed packages: {e}")

        # Apply limit if specified
        if limit > 0 and len(packages) > limit:
            packages = packages[:limit]

        # Cache the result
        self._cache_result(cache_key, packages)
        return packages

    def get_public_ip(self) -> Optional[str]:
        """
        Get the public IP address of the system.

        Returns:
            Public IP address as string or None if unable to determine
        """
        # Check cache first
        cache_key = "public_ip"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        public_ip = None

        # Try multiple services for redundancy
        services = [
            "https://api.ipify.org",
            "https://ifconfig.co/ip",
            "https://ipinfo.io/ip",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com"
        ]

        # Try to get the public IP
        for service in services:
            try:
                response = requests.get(service, timeout=3)
                if response.status_code == 200:
                    ip = response.text.strip()
                    # Validate IP format
                    try:
                        socket.inet_aton(ip)
                        public_ip = ip
                        break
                    except:
                        continue
            except Exception:
                continue

        # Cache the result
        if public_ip:
            self._cache_result(cache_key, public_ip)

        return public_ip

    def get_container_info(self) -> List[Dict[str, Any]]:
        """
        Get information about running containers if Docker is available.

        Returns:
            List of dictionaries with container information
        """
        # Check cache first
        cache_key = "container_info"
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        containers = []

        # Check if Docker is available
        if self.has_capability(SystemCapability.DOCKER):
            try:
                stdout, _, exit_code = self._execute_command(["docker", "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"])
                if exit_code == 0:
                    for line in stdout.strip().split("\n"):
                        if not line:
                            continue
                        parts = line.split("|")
                        if len(parts) >= 5:
                            container = {
                                "id": parts[0],
                                "name": parts[1],
                                "image": parts[2],
                                "status": parts[3],
                                "ports": parts[4]
                            }
                            containers.append(container)
            except Exception as e:
                logger.debug(f"Error getting Docker containers: {e}")

        # Cache the result
        self._cache_result(cache_key, containers)
        return containers

    def generate_report(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Generate a comprehensive system report.

        Args:
            include_sensitive: Whether to include sensitive information

        Returns:
            Dictionary with complete system information
        """
        # Override the instance setting if explicitly requested
        old_include_sensitive = self._include_sensitive
        if include_sensitive:
            self._include_sensitive = True

        try:
            report = {
                "generated_at": datetime.datetime.now().isoformat(),
                "os": self.get_os_info(),
                "kernel": self.get_kernel_version(),
                "cpu": self.get_cpu_info(),
                "memory": self.get_memory_info(),
                "disk": {
                    "partitions": self.get_disk_partitions(),
                    "root": self.get_disk_info("/")
                },
                "network": self.get_network_info(),
                "virtualization": {
                    "virtualized": self.is_virtualized(),
                    "type": self.get_virtualization_type() if self.is_virtualized() else None
                },
                "container": {
                    "containerized": self.is_containerized(),
                    "type": self.get_container_type() if self.is_containerized() else None
                },
                "capabilities": {cap.value: self.has_capability(cap) for cap in SystemCapability}
            }

            # Add services if available
            services = self.get_service_status()
            if services:
                report["services"] = services

            # Add public IP if available
            public_ip = self.get_public_ip()
            if public_ip:
                report["network"]["public_ip"] = public_ip

            # Include containers only if Docker is available
            if self.has_capability(SystemCapability.DOCKER):
                report["containers"] = self.get_container_info()

            # Include packages information (limited to reduce size)
            report["packages"] = self.get_installed_packages(limit=20)

            return report
        finally:
            # Restore original setting
            self._include_sensitive = old_include_sensitive

    def save_report(self, report: Dict[str, Any], file_path: str) -> bool:
        """
        Save a system report to a file.

        Args:
            report: System report to save
            file_path: Path to save the report to

        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

            # Write report to file
            with open(file_path, "w") as f:
                json.dump(report, f, indent=2, default=str)

            # Set secure permissions
            try:
                os.chmod(file_path, 0o640)
            except Exception:
                pass

            logger.info(f"System report saved to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving system report: {e}")
            return False

    def get_health_check(self) -> Dict[str, Any]:
        """
        Get a simple health check of the system.

        Returns:
            Dictionary with health status information
        """
        health = {
            "status": "healthy",
            "timestamp": datetime.datetime.now().isoformat(),
            "checks": {}
        }

        # Check CPU load
        try:
            cpu_info = self.get_cpu_info()
            if "usage_percent" in cpu_info:
                cpu_status = "healthy" if cpu_info["usage_percent"] < 80 else "warning"
                if cpu_info["usage_percent"] > 95:
                    cpu_status = "critical"

                health["checks"]["cpu"] = {
                    "status": cpu_status,
                    "usage_percent": cpu_info["usage_percent"]
                }

                # Add CPU load averages if available
                if "load_avg_1min" in cpu_info:
                    health["checks"]["cpu"]["load_1min"] = cpu_info["load_avg_1min"]
                    health["checks"]["cpu"]["load_5min"] = cpu_info["load_avg_5min"]
                    health["checks"]["cpu"]["load_15min"] = cpu_info["load_avg_15min"]
        except Exception as e:
            health["checks"]["cpu"] = {"status": "unknown", "error": str(e)}

        # Check memory
        try:
            memory_info = self.get_memory_info()
            if "percent_used" in memory_info:
                memory_status = "healthy" if memory_info["percent_used"] < 80 else "warning"
                if memory_info["percent_used"] > 95:
                    memory_status = "critical"

                health["checks"]["memory"] = {
                    "status": memory_status,
                    "usage_percent": memory_info["percent_used"]
                }

                # Add swap information if available
                if "swap" in memory_info and "percent_used" in memory_info["swap"]:
                    swap_status = "healthy"
                    if memory_info["swap"]["percent_used"] > 60:
                        swap_status = "warning"
                    if memory_info["swap"]["percent_used"] > 90:
                        swap_status = "critical"

                    health["checks"]["swap"] = {
                        "status": swap_status,
                        "usage_percent": memory_info["swap"]["percent_used"]
                    }
        except Exception as e:
            health["checks"]["memory"] = {"status": "unknown", "error": str(e)}

        # Check disk
        try:
            disk_info = self.get_disk_info("/")
            if "percent_used" in disk_info:
                disk_status = "healthy" if disk_info["percent_used"] < 80 else "warning"
                if disk_info["percent_used"] > 90:
                    disk_status = "critical"

                health["checks"]["disk"] = {
                    "status": disk_status,
                    "usage_percent": disk_info["percent_used"]
                }
        except Exception as e:
            health["checks"]["disk"] = {"status": "unknown", "error": str(e)}

        # Determine overall status based on individual checks
        if any(check["status"] == "critical" for check in health["checks"].values() if isinstance(check, dict)):
            health["status"] = "critical"
        elif any(check["status"] == "warning" for check in health["checks"].values() if isinstance(check, dict)):
            health["status"] = "warning"

        return health


def get_system_info() -> Dict[str, Any]:
    """
    Get basic system information as a convenience function.

    Returns:
        Dictionary with basic system information
    """
    system_info = SystemInfo()
    return {
        "os": system_info.get_os_info(),
        "cpu": {
            "count": system_info.get_cpu_count(),
            "model": system_info.get_cpu_info().get("model", "Unknown")
        },
        "memory": {
            "total_gb": system_info.get_memory_info().get("total_gb", 0),
            "percent_used": system_info.get_memory_info().get("percent_used", 0)
        },
        "disk": {
            "total_gb": system_info.get_disk_info("/").get("total_gb", 0),
            "percent_used": system_info.get_disk_info("/").get("percent_used", 0)
        },
        "hostname": system_info.get_hostname(),
        "kernel": system_info.get_kernel_version()
    }


if __name__ == "__main__":
    """
    Run as a command-line utility if executed directly.
    Outputs system information report in JSON format.
    """
    import argparse

    parser = argparse.ArgumentParser(description="System information collection utility")
    parser.add_argument("--save", help="Save the report to the specified file path")
    parser.add_argument("--sensitive", action="store_true", help="Include sensitive information in the report")
    parser.add_argument("--format", choices=["json", "yaml"], default="json", help="Output format (default: json)")

    args = parser.parse_args()

    # Create SystemInfo instance
    sys_info = SystemInfo(include_sensitive=args.sensitive)

    # Generate report
    report = sys_info.generate_report()

    # Save report if requested
    if args.save:
        success = sys_info.save_report(report, args.save)
        if success:
            print(f"Report saved to {args.save}")
        else:
            print(f"Error saving report to {args.save}")

    # Print report to console
    if args.format == "yaml":
        try:
            print(yaml.dump(report, default_flow_style=False))
        except ImportError:
            print("YAML output requires PyYAML. Install it with: pip install pyyaml")
            print(json.dumps(report, indent=2, default=str))
    else:
        print(json.dumps(report, indent=2, default=str))
