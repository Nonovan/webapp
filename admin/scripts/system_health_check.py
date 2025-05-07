"""
System Health Check Utility

This script provides health checking utilities for the Cloud Infrastructure Platform,
enabling system administrators to verify the health and proper functioning of system
components, resource usage, security configurations, and services.

The tool generates comprehensive health reports and can verify compliance with
system requirements and operational standards. All checks include proper error
handling and detailed logging for comprehensive system monitoring.
"""

import argparse
import datetime
import json
import logging
import os
import platform
import socket
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set, Callable

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Setup logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Constants
DEFAULT_TIMEOUT = 10
DEFAULT_DISK_THRESHOLD = 85
DEFAULT_MEMORY_THRESHOLD = 80
DEFAULT_CPU_THRESHOLD = 75
DEFAULT_REPORT_FORMAT = "text"

# Script path constants
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent
REPORT_DIR = PROJECT_ROOT / "reports" / "health"


__all__ = [
    # Core functions
    "run_health_check",
    "generate_health_report",
    "check_system_resources",
    "verify_services_status",
    "check_security_compliance",

    # Helper functions
    "check_tcp_connection",
    "check_endpoint",
    "check_dns_resolution",

    # Classes
    "HealthChecker",
    "Status",

    # Constants
    "DEFAULT_TIMEOUT",
    "DEFAULT_DISK_THRESHOLD",
    "DEFAULT_MEMORY_THRESHOLD",
    "DEFAULT_CPU_THRESHOLD",
    "DEFAULT_REPORT_FORMAT",

    # Main entry point
    "main"
]


# Status enums
class Status(Enum):
    """Health check status values."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class HealthChecker:
    """Main health check class that performs system diagnostics and generates reports."""

    def __init__(self, environment: str = "production", region: str = "primary"):
        """
        Initialize the health checker.

        Args:
            environment: Target environment (e.g., production, development)
            region: Region to check (e.g., primary, secondary)
        """
        self.environment = environment
        self.region = region
        self.timestamp = datetime.datetime.now().isoformat()
        self.results = {}
        self.overall_status = Status.HEALTHY

        # Load environment-specific configurations
        self.config = self._load_environment_config()

        # Create report directory if it doesn't exist
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def _load_environment_config(self) -> Dict[str, Any]:
        """Load environment-specific configuration."""
        config_path = PROJECT_ROOT / "config" / "environments" / f"{self.environment}.json"
        default_config = {
            "api_endpoint": "https://api.example.com",
            "web_endpoint": "https://example.com",
            "db_host": "localhost",
            "db_port": 5432,
            "redis_host": "localhost",
            "redis_port": 6379
        }

        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
                return default_config
        else:
            logger.warning(f"Config file not found at {config_path}, using defaults")
            return default_config

    def run_checks(self) -> Dict[str, Any]:
        """
        Run all health checks and return the results.

        Returns:
            Dict[str, Any]: Comprehensive results of all health checks
        """
        # Run system resource checks
        self._check_system_resources()

        # Check services
        self._check_services()

        # Check security compliance
        self._check_security_compliance()

        # Check database connectivity
        self._check_database()

        # Check API endpoints
        self._check_api_endpoints()

        # Return complete results
        return {
            "status": self.overall_status.value,
            "timestamp": self.timestamp,
            "environment": self.environment,
            "region": self.region,
            "checks": self.results
        }

    def _check_system_resources(self) -> None:
        """Check system resource usage."""
        resources = {}

        # Check if psutil is available
        if not PSUTIL_AVAILABLE:
            resources["status"] = Status.UNKNOWN.value
            resources["error"] = "psutil module not available, cannot check system resources"
            self.results["system_resources"] = resources
            return

        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.5)
            resources["cpu"] = {
                "percent": cpu_percent,
                "status": self._determine_status(
                    cpu_percent,
                    DEFAULT_CPU_THRESHOLD,
                    DEFAULT_CPU_THRESHOLD + 10
                )
            }

            # Get memory usage
            memory = psutil.virtual_memory()
            resources["memory"] = {
                "percent": memory.percent,
                "available_mb": round(memory.available / (1024 * 1024), 2),
                "total_mb": round(memory.total / (1024 * 1024), 2),
                "status": self._determine_status(
                    memory.percent,
                    DEFAULT_MEMORY_THRESHOLD,
                    DEFAULT_MEMORY_THRESHOLD + 10
                )
            }

            # Get disk usage
            disk = psutil.disk_usage('/')
            resources["disk"] = {
                "percent": disk.percent,
                "free_gb": round(disk.free / (1024 * 1024 * 1024), 2),
                "total_gb": round(disk.total / (1024 * 1024 * 1024), 2),
                "status": self._determine_status(
                    disk.percent,
                    DEFAULT_DISK_THRESHOLD,
                    DEFAULT_DISK_THRESHOLD + 10
                )
            }

            # Get system load (Unix-like systems only)
            if hasattr(os, 'getloadavg'):
                load_avg = os.getloadavg()
                resources["load_average"] = {
                    "1min": load_avg[0],
                    "5min": load_avg[1],
                    "15min": load_avg[2],
                    "status": self._determine_status(
                        load_avg[0] / os.cpu_count() * 100,
                        75,  # Warning at 75% of CPU cores
                        100  # Critical at 100% of CPU cores
                    )
                }

            # Determine overall resource status
            status = Status.HEALTHY
            for resource in resources.values():
                if isinstance(resource, dict) and "status" in resource:
                    if resource["status"] == Status.CRITICAL.value:
                        status = Status.CRITICAL
                        break
                    elif resource["status"] == Status.WARNING.value and status != Status.CRITICAL:
                        status = Status.WARNING

            resources["status"] = status.value
            self.results["system_resources"] = resources

            # Update overall status
            if status == Status.CRITICAL:
                self.overall_status = Status.CRITICAL
            elif status == Status.WARNING and self.overall_status != Status.CRITICAL:
                self.overall_status = Status.WARNING

        except Exception as e:
            logger.error(f"Error checking system resources: {e}")
            resources["status"] = Status.UNKNOWN.value
            resources["error"] = str(e)
            self.results["system_resources"] = resources

    def _determine_status(self, value: float, warning_threshold: float, critical_threshold: float) -> str:
        """
        Determine status based on value and thresholds.

        Args:
            value: The measured value
            warning_threshold: Threshold for warning status
            critical_threshold: Threshold for critical status

        Returns:
            str: Status value
        """
        if value >= critical_threshold:
            return Status.CRITICAL.value
        elif value >= warning_threshold:
            return Status.WARNING.value
        else:
            return Status.HEALTHY.value

    def _check_services(self) -> None:
        """Check critical service status."""
        services = {}

        try:
            # Check if critical services are running
            critical_services = self._identify_critical_services()
            services["critical_services"] = critical_services

            # Check network services
            services["network"] = self._check_network_connectivity()

            # Check database replication if applicable
            if self.region == "secondary":
                services["db_replication"] = self._check_db_replication()

            # Determine overall service status
            status = Status.HEALTHY
            for service_group, service_status in services.items():
                if isinstance(service_status, dict) and "status" in service_status:
                    if service_status["status"] == Status.CRITICAL.value:
                        status = Status.CRITICAL
                        break
                    elif service_status["status"] == Status.WARNING.value and status != Status.CRITICAL:
                        status = Status.WARNING

            services["status"] = status.value
            self.results["services"] = services

            # Update overall status
            if status == Status.CRITICAL:
                self.overall_status = Status.CRITICAL
            elif status == Status.WARNING and self.overall_status != Status.CRITICAL:
                self.overall_status = Status.WARNING

        except Exception as e:
            logger.error(f"Error checking services: {e}")
            services["status"] = Status.UNKNOWN.value
            services["error"] = str(e)
            self.results["services"] = services

    def _identify_critical_services(self) -> Dict[str, Any]:
        """Identify and check critical system services."""
        result = {"running": [], "stopped": [], "status": Status.HEALTHY.value}

        if not PSUTIL_AVAILABLE:
            result["status"] = Status.UNKNOWN.value
            result["error"] = "psutil module not available"
            return result

        try:
            # Define critical services based on platform
            critical_patterns = []
            if platform.system() == "Linux":
                critical_patterns = ["systemd", "sshd", "nginx", "httpd", "apache2", "postgresql", "mysql", "redis"]
            elif platform.system() == "Darwin":  # macOS
                critical_patterns = ["launchd", "sshd", "nginx", "httpd", "postgres", "mysql", "redis"]
            elif platform.system() == "Windows":
                critical_patterns = ["System", "sshd", "nginx", "httpd", "postgresql", "mysql", "redis"]

            # Check if critical services are running
            running_services = []
            stopped_services = []

            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower() if proc_info['name'] else ""

                    # Check name against critical patterns
                    for pattern in critical_patterns:
                        if pattern.lower() in proc_name:
                            running_services.append(pattern)
                            break

                    # Check command line for service names that might not be in the process name
                    if proc_info['cmdline']:
                        cmdline = ' '.join([str(cmd).lower() for cmd in proc_info['cmdline']])
                        for pattern in critical_patterns:
                            if pattern not in running_services and pattern.lower() in cmdline:
                                running_services.append(pattern)
                                break

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Find which critical services are not running
            for service in critical_patterns:
                if service not in running_services and service not in ["systemd", "launchd", "System"]:
                    stopped_services.append(service)

            # Set result
            result["running"] = sorted(list(set(running_services)))
            result["stopped"] = sorted(list(set(stopped_services)))

            if len(stopped_services) > 0:
                result["status"] = Status.WARNING.value
                if any(s in stopped_services for s in ["nginx", "httpd", "apache2", "postgresql", "mysql"]):
                    result["status"] = Status.CRITICAL.value

            return result

        except Exception as e:
            logger.error(f"Error identifying critical services: {e}")
            result["status"] = Status.UNKNOWN.value
            result["error"] = str(e)
            return result

    def _check_network_connectivity(self) -> Dict[str, Any]:
        """Check network connectivity to critical endpoints."""
        result = {"endpoints": {}, "status": Status.HEALTHY.value}

        try:
            # Check DNS resolution
            dns_result = self._check_dns_resolution()
            result["dns"] = dns_result

            # Check key endpoints
            endpoints = [
                ("api", self.config.get("api_endpoint", "https://api.example.com")),
                ("web", self.config.get("web_endpoint", "https://example.com")),
                ("external", "https://www.google.com")  # External connectivity check
            ]

            for name, url in endpoints:
                endpoint_result = self._check_endpoint(url)
                result["endpoints"][name] = endpoint_result

                # Update network status based on endpoint results
                if endpoint_result["status"] == Status.CRITICAL.value:
                    result["status"] = Status.CRITICAL.value
                elif endpoint_result["status"] == Status.WARNING.value and result["status"] != Status.CRITICAL.value:
                    result["status"] = Status.WARNING.value

            return result

        except Exception as e:
            logger.error(f"Error checking network connectivity: {e}")
            result["status"] = Status.UNKNOWN.value
            result["error"] = str(e)
            return result

    def _check_dns_resolution(self) -> Dict[str, Any]:
        """Check DNS resolution."""
        result = {"status": Status.HEALTHY.value}

        try:
            # Get hostname from API endpoint
            api_url = self.config.get("api_endpoint", "https://api.example.com")
            hostname = api_url.replace("https://", "").replace("http://", "").split("/")[0]

            # Try to resolve hostname
            try:
                ip_address = socket.gethostbyname(hostname)
                result["resolved"] = True
                result["hostname"] = hostname
                result["ip"] = ip_address
            except socket.gaierror:
                result["resolved"] = False
                result["hostname"] = hostname
                result["status"] = Status.CRITICAL.value

            return result

        except Exception as e:
            logger.error(f"Error checking DNS resolution: {e}")
            result["status"] = Status.UNKNOWN.value
            result["error"] = str(e)
            return result

    def _check_endpoint(self, url: str) -> Dict[str, Any]:
        """Check if endpoint is reachable and responding properly."""
        success, result = check_endpoint(url)
        return result

    def _check_db_replication(self) -> Dict[str, Any]:
        """Check database replication status."""
        result = {"status": Status.UNKNOWN.value, "message": "DB replication check not implemented yet"}

        # In a real implementation, this would connect to the database and check replication lag
        # For now, this is a stub that returns unknown status

        return result

    def _check_security_compliance(self) -> None:
        """Check security compliance status."""
        security = {}

        try:
            # Check file integrity
            security["file_integrity"] = self._check_file_integrity()

            # Check security configurations
            security["security_configs"] = self._check_security_configs()

            # Check SSL certificates
            security["ssl_certificates"] = self._check_ssl_certificates()

            # Determine overall security status
            status = Status.HEALTHY
            for check_name, check_result in security.items():
                if isinstance(check_result, dict) and "status" in check_result:
                    if check_result["status"] == Status.CRITICAL.value:
                        status = Status.CRITICAL
                        break
                    elif check_result["status"] == Status.WARNING.value and status != Status.CRITICAL:
                        status = Status.WARNING

            security["status"] = status.value
            self.results["security"] = security

            # Update overall status
            if status == Status.CRITICAL:
                self.overall_status = Status.CRITICAL
            elif status == Status.WARNING and self.overall_status != Status.CRITICAL:
                self.overall_status = Status.WARNING

        except Exception as e:
            logger.error(f"Error checking security compliance: {e}")
            security["status"] = Status.UNKNOWN.value
            security["error"] = str(e)
            self.results["security"] = security

    def _check_file_integrity(self) -> Dict[str, Any]:
        """Check file integrity status."""
        result = {"status": Status.HEALTHY.value}

        try:
            # Get file integrity script path
            integrity_script = PROJECT_ROOT / "scripts" / "security" / "verify_files.py"

            # If file integrity script exists, try to run it
            if integrity_script.exists():
                cmd = [sys.executable, str(integrity_script), "--environment", self.environment, "--region", self.region, "--quiet"]
                import subprocess
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=DEFAULT_TIMEOUT
                )

                if process.returncode == 0:
                    result["message"] = "File integrity check passed"
                else:
                    result["status"] = Status.CRITICAL.value
                    result["message"] = "File integrity check failed"
                    result["details"] = process.stderr.strip() or process.stdout.strip()
            else:
                result["status"] = Status.WARNING.value
                result["message"] = f"File integrity script not found at {integrity_script}"

            return result

        except subprocess.TimeoutExpired:
            result["status"] = Status.WARNING.value
            result["error"] = "File integrity check timed out"
            return result
        except Exception as e:
            logger.error(f"Error checking file integrity: {e}")
            result["status"] = Status.UNKNOWN.value
            result["error"] = str(e)
            return result

    def _check_security_configs(self) -> Dict[str, Any]:
        """Check security configurations."""
        result = {"status": Status.HEALTHY.value}

        try:
            # Check for key security settings
            security_checks = []

            # In a real implementation, this would check for actual security configurations
            # For now, this is a stub that returns healthy status

            return result

        except Exception as e:
            logger.error(f"Error checking security configurations: {e}")
            result["status"] = Status.UNKNOWN.value
            result["error"] = str(e)
            return result

    def _check_ssl_certificates(self) -> Dict[str, Any]:
        """Check SSL certificate validity."""
        result = {"status": Status.HEALTHY.value, "certificates": {}}

        try:
            # Get endpoints to check
            endpoints = [
                ("api", self.config.get("api_endpoint", "https://api.example.com")),
                ("web", self.config.get("web_endpoint", "https://example.com"))
            ]

            import socket
            import ssl
            import datetime

            for name, url in endpoints:
                try:
                    # Extract hostname from URL
                    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

                    # Get SSL certificate
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, 443), timeout=DEFAULT_TIMEOUT) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()

                    # Extract certificate details
                    not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (not_after - datetime.datetime.utcnow()).days

                    cert_result = {
                        "hostname": hostname,
                        "expiration": not_after.isoformat(),
                        "days_remaining": days_remaining,
                        "status": Status.HEALTHY.value
                    }

                    # Check expiration
                    if days_remaining < 0:
                        cert_result["status"] = Status.CRITICAL.value
                    elif days_remaining < 30:
                        cert_result["status"] = Status.WARNING.value

                    result["certificates"][name] = cert_result

                    # Update overall status based on certificate status
                    if cert_result["status"] == Status.CRITICAL.value:
                        result["status"] = Status.CRITICAL.value
                    elif cert_result["status"] == Status.WARNING.value and result["status"] != Status.CRITICAL.value:
                        result["status"] = Status.WARNING.value

                except Exception as e:
                    result["certificates"][name] = {
                        "hostname": hostname if 'hostname' in locals() else url,
                        "status": Status.CRITICAL.value,
                        "error": str(e)
                    }
                    result["status"] = Status.CRITICAL.value

            return result

        except Exception as e:
            logger.error(f"Error checking SSL certificates: {e}")
            result["status"] = Status.UNKNOWN.value
            result["error"] = str(e)
            return result

    def _check_database(self) -> None:
        """Check database connectivity and status."""
        db = {}

        try:
            # Try to connect to database
            db_host = self.config.get("db_host", "localhost")
            db_port = self.config.get("db_port", 5432)

            # Check if database port is reachable
            success, db["connectivity"] = check_tcp_connection(db_host, db_port)

            # Determine overall database status
            if db.get("connectivity", {}).get("status") == Status.CRITICAL.value:
                db["status"] = Status.CRITICAL.value
            elif db.get("connectivity", {}).get("status") == Status.WARNING.value:
                db["status"] = Status.WARNING.value
            else:
                db["status"] = Status.HEALTHY.value

            self.results["database"] = db

            # Update overall status
            if db["status"] == Status.CRITICAL.value:
                self.overall_status = Status.CRITICAL
            elif db["status"] == Status.WARNING.value and self.overall_status != Status.CRITICAL:
                self.overall_status = Status.WARNING

        except Exception as e:
            logger.error(f"Error checking database: {e}")
            db["status"] = Status.UNKNOWN.value
            db["error"] = str(e)
            self.results["database"] = db

    def _check_api_endpoints(self) -> None:
        """Check API endpoints health."""
        api = {"endpoints": {}, "status": Status.HEALTHY.value}

        if not REQUESTS_AVAILABLE:
            api["status"] = Status.UNKNOWN.value
            api["error"] = "requests module not available"
            self.results["api"] = api
            return

        try:
            # Define key API endpoints to check
            api_base = self.config.get("api_endpoint", "https://api.example.com")
            endpoints = [
                ("health", f"{api_base}/health"),
                ("version", f"{api_base}/api/version"),
                ("status", f"{api_base}/api/status")
            ]

            for name, url in endpoints:
                success, endpoint_result = check_endpoint(url)
                api["endpoints"][name] = endpoint_result

                # Update API status based on endpoint results
                if endpoint_result["status"] == Status.CRITICAL.value and name == "health":
                    api["status"] = Status.CRITICAL.value
                elif endpoint_result["status"] == Status.WARNING.value and api["status"] != Status.CRITICAL.value:
                    api["status"] = Status.WARNING.value

            self.results["api"] = api

            # Update overall status
            if api["status"] == Status.CRITICAL.value:
                self.overall_status = Status.CRITICAL
            elif api["status"] == Status.WARNING.value and self.overall_status != Status.CRITICAL:
                self.overall_status = Status.WARNING

        except Exception as e:
            logger.error(f"Error checking API endpoints: {e}")
            api["status"] = Status.UNKNOWN.value
            api["error"] = str(e)
            self.results["api"] = api


# Public API functions
def run_health_check(
    environment: str = "production",
    region: str = "primary",
    detailed: bool = False,
    report_format: str = DEFAULT_REPORT_FORMAT,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run a health check and return the results.

    Args:
        environment: Target environment (e.g., production, development)
        region: Region to check (e.g., primary, secondary)
        detailed: Whether to include detailed information
        report_format: Format for the report ('text', 'json', or 'html')
        output_file: Path to save the report (optional)

    Returns:
        Dict[str, Any]: Health check results
    """
    try:
        # Create checker instance
        checker = HealthChecker(environment=environment, region=region)

        # Run health checks
        results = checker.run_checks()

        # Generate report if requested
        if output_file:
            checker.generate_report(output_format=report_format, output_file=output_file)

        return results

    except Exception as e:
        logger.error(f"Error running health check: {e}")
        return {
            "status": "critical",
            "timestamp": datetime.datetime.now().isoformat(),
            "environment": environment,
            "region": region,
            "error": str(e)
        }


def generate_health_report(
    results: Dict[str, Any],
    report_format: str = DEFAULT_REPORT_FORMAT,
    output_file: Optional[str] = None
) -> str:
    """
    Generate a health check report from results.

    Args:
        results: Health check results
        report_format: Format for the report ('text', 'json', or 'html')
        output_file: Path to save the report (optional)

    Returns:
        str: Generated report content
    """
    try:
        # Use the HealthChecker's report generation
        # Create a mock HealthChecker with the results
        checker = HealthChecker(
            environment=results.get('environment', 'production'),
            region=results.get('region', 'primary')
        )
        checker.timestamp = results.get('timestamp', datetime.datetime.now().isoformat())
        checker.overall_status = Status(results.get('status', 'unknown'))
        checker.results = results.get('checks', {})

        # Generate and return report
        return checker.generate_report(output_format=report_format, output_file=output_file)

    except Exception as e:
        logger.error(f"Error generating health report: {e}")
        error_report = f"Error generating health report: {e}\n\nRaw results:\n{json.dumps(results, indent=2)}"

        if output_file:
            try:
                output_path = Path(output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)

                with open(output_path, 'w') as f:
                    f.write(error_report)
                logger.info(f"Error report saved to {output_path}")
            except IOError as e:
                logger.error(f"Failed to write error report to {output_path}: {e}")

        return error_report


def check_system_resources(thresholds: Optional[Dict[str, int]] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Check system resource usage against thresholds.

    Args:
        thresholds: Dictionary with thresholds for 'cpu', 'memory', and 'disk' (percentages)

    Returns:
        Tuple[bool, Dict[str, Any]]: Success status and resource information
    """
    # Use default thresholds if not provided
    if thresholds is None:
        thresholds = {
            'cpu': DEFAULT_CPU_THRESHOLD,
            'memory': DEFAULT_MEMORY_THRESHOLD,
            'disk': DEFAULT_DISK_THRESHOLD
        }

    try:
        # Create checker instance to reuse resource checking code
        checker = HealthChecker()
        checker._check_system_resources()

        # Get results
        resources = checker.results.get('system_resources', {})

        # Check status - healthy unless critical issues found
        status = resources.get('status', Status.UNKNOWN.value) != Status.CRITICAL.value

        return status, resources

    except Exception as e:
        logger.error(f"Error checking system resources: {e}")
        return False, {
            "status": Status.CRITICAL.value,
            "error": str(e)
        }


def verify_services_status(environment: str = "production", region: str = "primary") -> Tuple[bool, Dict[str, Any]]:
    """
    Verify the status of critical system services.

    Args:
        environment: Target environment (e.g., production, development)
        region: Region to check (e.g., primary, secondary)

    Returns:
        Tuple[bool, Dict[str, Any]]: Success status and service status information
    """
    try:
        # Create checker instance
        checker = HealthChecker(environment=environment, region=region)

        # Check services
        checker._check_services()

        # Get results
        services = checker.results.get('services', {})

        # Check status - healthy unless critical issues found
        status = services.get('status', Status.UNKNOWN.value) != Status.CRITICAL.value

        return status, services

    except Exception as e:
        logger.error(f"Error verifying service status: {e}")
        return False, {
            "status": Status.CRITICAL.value,
            "error": str(e)
        }


def check_security_compliance(environment: str = "production", region: str = "primary") -> Tuple[bool, Dict[str, Any]]:
    """
    Check system security compliance status.

    Args:
        environment: Target environment (e.g., production, development)
        region: Region to check (e.g., primary, secondary)

    Returns:
        Tuple[bool, Dict[str, Any]]: Compliance status and detailed security information
    """
    try:
        # Create checker instance
        checker = HealthChecker(environment=environment, region=region)

        # Check security compliance
        checker._check_security_compliance()

        # Get results
        security = checker.results.get('security', {})

        # Check status - compliant unless critical issues found
        compliant = security.get('status', Status.UNKNOWN.value) != Status.CRITICAL.value

        return compliant, security

    except Exception as e:
        logger.error(f"Error checking security compliance: {e}")
        return False, {
            "status": Status.CRITICAL.value,
            "error": str(e)
        }


def check_tcp_connection(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, Dict[str, Any]]:
    """
    Check TCP connection to a host and port.

    Args:
        host: Target hostname or IP address
        port: Target port number
        timeout: Connection timeout in seconds (default: value from DEFAULT_TIMEOUT)

    Returns:
        Tuple[bool, Dict[str, Any]]: Success status and connection information
    """
    result = {"host": host, "port": port, "status": Status.HEALTHY.value}

    try:
        # Try to connect to host:port
        start_time = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        response_time = time.time() - start_time

        result["response_time_ms"] = round(response_time * 1000, 2)

        # Check response time
        if response_time > 1.0:
            result["status"] = Status.WARNING.value

        return True, result

    except socket.timeout:
        result["status"] = Status.WARNING.value
        result["error"] = "Connection timed out"
        return False, result
    except socket.error as e:
        result["status"] = Status.CRITICAL.value
        result["error"] = str(e)
        return False, result
    except Exception as e:
        logger.error(f"Error checking TCP connection to {host}:{port}: {e}")
        result["status"] = Status.UNKNOWN.value
        result["error"] = str(e)
        return False, result


def check_endpoint(url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, Dict[str, Any]]:
    """
    Check if HTTP/HTTPS endpoint is reachable and responding properly.

    Args:
        url: Target URL to check
        timeout: Request timeout in seconds (default: value from DEFAULT_TIMEOUT)

    Returns:
        Tuple[bool, Dict[str, Any]]: Success status and endpoint information
    """
    result = {"url": url, "status": Status.HEALTHY.value}

    if not REQUESTS_AVAILABLE:
        result["status"] = Status.UNKNOWN.value
        result["error"] = "requests module not available"
        return False, result

    try:
        # Try to connect to endpoint
        start_time = time.time()
        response = requests.get(url, timeout=timeout, verify=True)
        response_time = time.time() - start_time

        result["response_code"] = response.status_code
        result["response_time_ms"] = round(response_time * 1000, 2)

        # Check response code
        if response.status_code >= 500:
            result["status"] = Status.CRITICAL.value
            return False, result
        elif response.status_code >= 400:
            result["status"] = Status.WARNING.value
            return 200 <= response.status_code < 400, result

        # Check response time
        if response_time > 2.0:
            result["status"] = Status.WARNING.value

        return 200 <= response.status_code < 400, result

    except requests.exceptions.SSLError:
        result["status"] = Status.CRITICAL.value
        result["error"] = "SSL certificate validation failed"
        return False, result
    except requests.exceptions.ConnectionError:
        result["status"] = Status.CRITICAL.value
        result["error"] = "Connection failed"
        return False, result
    except requests.exceptions.Timeout:
        result["status"] = Status.WARNING.value
        result["error"] = "Request timed out"
        return False, result
    except requests.exceptions.RequestException as e:
        result["status"] = Status.CRITICAL.value
        result["error"] = str(e)
        return False, result
    except Exception as e:
        logger.error(f"Error checking endpoint {url}: {e}")
        result["status"] = Status.UNKNOWN.value
        result["error"] = str(e)
        return False, result


def check_dns_resolution(hostname: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Check if a hostname can be resolved via DNS.

    Args:
        hostname: Hostname to resolve

    Returns:
        Tuple[bool, Dict[str, Any]]: Success status and resolution information
    """
    result = {"hostname": hostname, "status": Status.HEALTHY.value}

    try:
        # Try to resolve hostname
        ip_address = socket.gethostbyname(hostname)
        result["resolved"] = True
        result["ip"] = ip_address
        return True, result
    except socket.gaierror:
        result["resolved"] = False
        result["status"] = Status.CRITICAL.value
        result["error"] = "DNS resolution failed"
        return False, result
    except Exception as e:
        logger.error(f"Error resolving hostname {hostname}: {e}")
        result["status"] = Status.UNKNOWN.value
        result["error"] = str(e)
        return False, result


def main():
    """Command line entry point for health check script."""
    parser = argparse.ArgumentParser(description='System Health Check Utility')
    parser.add_argument('--environment', '-e', default='production', help='Target environment')
    parser.add_argument('--region', '-r', default='primary', help='Region to check')
    parser.add_argument('--format', '-f', choices=['text', 'json', 'html'], default='text', help='Report format')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--service-check', '-s', action='store_true', help='Check service status only')
    parser.add_argument('--resource-check', '-r', action='store_true', help='Check system resources only')
    parser.add_argument('--security-check', '-c', action='store_true', help='Check security compliance only')

    args = parser.parse_args()

    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Run specific check based on flags
    if args.service_check:
        status, result = verify_services_status(args.environment, args.region)
        print(json.dumps(result, indent=2))
        return 0 if status else 1
    elif args.resource_check:
        status, result = check_system_resources()
        print(json.dumps(result, indent=2))
        return 0 if status else 1
    elif args.security_check:
        status, result = check_security_compliance(args.environment, args.region)
        print(json.dumps(result, indent=2))
        return 0 if status else 1
    else:
        # Run full health check
        results = run_health_check(
            environment=args.environment,
            region=args.region,
            report_format=args.format,
            output_file=args.output
        )

        # Print report to stdout if no output file specified
        if not args.output and args.format != 'json':
            checker = HealthChecker(environment=args.environment, region=args.region)
            checker.timestamp = results.get('timestamp', datetime.datetime.now().isoformat())
            checker.overall_status = Status(results.get('status', 'unknown'))
            checker.results = results.get('checks', {})
            print(checker.generate_report(output_format=args.format))
        elif args.format == 'json' and not args.output:
            print(json.dumps(results, indent=2))

        # Return exit code based on status
        return 0 if results.get('status') == 'healthy' else 1


if __name__ == '__main__':
    sys.exit(main())
