"""
Resource Monitor Module for Cloud Infrastructure Platform

This module provides comprehensive resource monitoring capabilities including
CPU, memory, disk, and network monitoring with customizable thresholds,
historical data collection, and alert management.
"""

import os
import sys
import time
import json
import socket
import logging
import platform
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Union, Callable, Tuple, Set
from pathlib import Path
import tempfile
import uuid

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import boto3
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import MetricsQueryClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import monitoring_v3
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

# Try to import internal modules with graceful fallbacks
try:
    from scripts.core.logger import Logger
    logger = Logger.get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

try:
    from scripts.core.error_handler import handle_error, ErrorCategory
    ERROR_HANDLER_AVAILABLE = True
except ImportError:
    ERROR_HANDLER_AVAILABLE = False
    logger.warning("Error handler not available, using basic error handling")

    def handle_error(error, category=None, context=None):
        """Simple error handler fallback."""
        logger.error(f"Error: {error}, Context: {context}")

try:
    from core.environment import get_environment
    ENVIRONMENT_AVAILABLE = True
except ImportError:
    ENVIRONMENT_AVAILABLE = False
    logger.warning("Environment module not available, using default environment")

    def get_environment() -> str:
        """Simple environment detector fallback."""
        return os.environ.get("ENVIRONMENT", "development")

try:
    from scripts.core.notification import send_notification
    NOTIFICATION_AVAILABLE = True
except ImportError:
    NOTIFICATION_AVAILABLE = False
    logger.warning("Notification module not available, using logging for alerts")

    def send_notification(subject: str, message: str, recipients: List[str], priority: str = "normal"):
        """Simple notification fallback using logging."""
        logger.warning(f"ALERT [{priority.upper()}]: {subject} - {message} (to: {recipients})")

try:
    from scripts.core.config_loader import load_config
    CONFIG_LOADER_AVAILABLE = True
except ImportError:
    CONFIG_LOADER_AVAILABLE = False
    logger.warning("Config loader not available, using default configuration")

    def load_config(config_path: str = None) -> Dict[str, Any]:
        """Simple config loader fallback."""
        return {}


# Constants for resource monitoring
DEFAULT_CPU_THRESHOLD = 80.0  # percent
DEFAULT_MEMORY_THRESHOLD = 80.0  # percent
DEFAULT_DISK_THRESHOLD = 80.0  # percent
DEFAULT_NETWORK_THRESHOLD = 80.0  # percent utilization
DEFAULT_LOAD_THRESHOLD = 1.0  # normalized by CPU count
DEFAULT_INTERVAL = 60  # seconds
DEFAULT_RETENTION_DAYS = 30
DEFAULT_METRICS_DIRECTORY = "/var/log/cloud-platform/metrics"
DEFAULT_ALERT_COOLDOWN = 300  # seconds between repeated alerts
DEFAULT_METRICS_FORMAT = "json"
DEFAULT_CONFIG_PATH = "/etc/cloud-platform/resource_monitor.conf"
DEFAULT_METRIC_BATCH_SIZE = 50  # number of metrics to store in a batch for efficiency
CLOUD_PROVIDER_POLL_INTERVAL = 300  # seconds between cloud provider metric polls
MAX_DATAPOINTS = 43200  # maximum number of datapoints to keep in memory (30 days @ 1min interval)


class AlertLevel:
    """Alert level definitions for resource monitoring."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class MetricCategory:
    """Categories of metrics that can be collected."""
    SYSTEM = "system"
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    PROCESS = "process"
    CLOUD = "cloud"
    CUSTOM = "custom"


class ResourceMonitor:
    """
    Monitors system resources and provides alerting capabilities.

    This class provides functionality to monitor CPU, memory, disk, and network usage
    with customizable thresholds, historical data tracking, and alert management.
    It integrates with cloud providers to collect cloud-specific metrics and provides
    a unified interface for resource monitoring across environments.
    """

    def __init__(
        self,
        cpu_threshold: float = DEFAULT_CPU_THRESHOLD,
        memory_threshold: float = DEFAULT_MEMORY_THRESHOLD,
        disk_threshold: float = DEFAULT_DISK_THRESHOLD,
        network_threshold: float = DEFAULT_NETWORK_THRESHOLD,
        load_threshold: float = DEFAULT_LOAD_THRESHOLD,
        interval: int = DEFAULT_INTERVAL,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        metrics_directory: str = DEFAULT_METRICS_DIRECTORY,
        config_path: str = DEFAULT_CONFIG_PATH,
        alert_cooldown: int = DEFAULT_ALERT_COOLDOWN,
        initialize: bool = True
    ):
        """
        Initialize the resource monitor with specified thresholds and settings.

        Args:
            cpu_threshold: CPU usage threshold percentage
            memory_threshold: Memory usage threshold percentage
            disk_threshold: Disk usage threshold percentage
            network_threshold: Network utilization threshold percentage
            load_threshold: System load threshold (normalized by CPU count)
            interval: Monitoring interval in seconds
            retention_days: Number of days to retain historical metrics
            metrics_directory: Directory to store historical metrics
            config_path: Path to configuration file
            alert_cooldown: Minimum time between repeated alerts in seconds
            initialize: Whether to initialize monitoring on creation
        """
        # Store thresholds
        self.cpu_threshold = cpu_threshold
        self.memory_threshold = memory_threshold
        self.disk_threshold = disk_threshold
        self.network_threshold = network_threshold
        self.load_threshold = load_threshold

        # Store settings
        self.interval = interval
        self.retention_days = retention_days
        self.metrics_directory = Path(metrics_directory)
        self.alert_cooldown = alert_cooldown

        # Initialize internal state
        self._stop_monitoring = threading.Event()
        self._monitoring_thread = None
        self._cloud_monitoring_thread = None
        self._last_alerts = {}  # Track last alert time by metric type
        self._metrics_data = {
            MetricCategory.CPU: [],
            MetricCategory.MEMORY: [],
            MetricCategory.DISK: [],
            MetricCategory.NETWORK: [],
            MetricCategory.PROCESS: [],
            MetricCategory.CLOUD: [],
            MetricCategory.CUSTOM: []
        }
        self._metrics_lock = threading.Lock()
        self._historical_data = {}  # For longer-term storage
        self._environment = get_environment() if ENVIRONMENT_AVAILABLE else "development"

        # Load configuration
        self.config = self._load_configuration(config_path)

        # Apply configuration overrides
        self._apply_configuration()

        # Ensure metrics directory exists
        os.makedirs(self.metrics_directory, exist_ok=True)

        # Initialize platform-specific monitoring
        self.platform_system = platform.system().lower()
        self._setup_platform_specific()

        # Validate dependencies
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil is not available, some monitoring features will be limited")

        # Set up cloud provider monitoring if available
        self.cloud_providers = self._setup_cloud_providers()

        # Start monitoring if requested
        if initialize:
            self.start_monitoring()

    def _load_configuration(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from file with fallback to environment variables.

        Args:
            config_path: Path to configuration file

        Returns:
            Configuration dictionary
        """
        config = {}

        # Try to load configuration file
        if CONFIG_LOADER_AVAILABLE:
            try:
                config = load_config(config_path)
            except Exception as e:
                logger.warning(f"Failed to load configuration from {config_path}: {e}")

        # Apply environment variable overrides
        config["cpu_threshold"] = float(os.environ.get(
            "RESOURCE_MONITOR_CPU_THRESHOLD",
            config.get("cpu_threshold", self.cpu_threshold)
        ))

        config["memory_threshold"] = float(os.environ.get(
            "RESOURCE_MONITOR_MEMORY_THRESHOLD",
            config.get("memory_threshold", self.memory_threshold)
        ))

        config["disk_threshold"] = float(os.environ.get(
            "RESOURCE_MONITOR_DISK_THRESHOLD",
            config.get("disk_threshold", self.disk_threshold)
        ))

        config["network_threshold"] = float(os.environ.get(
            "RESOURCE_MONITOR_NETWORK_THRESHOLD",
            config.get("network_threshold", self.network_threshold)
        ))

        config["load_threshold"] = float(os.environ.get(
            "RESOURCE_MONITOR_LOAD_THRESHOLD",
            config.get("load_threshold", self.load_threshold)
        ))

        config["interval"] = int(os.environ.get(
            "RESOURCE_MONITOR_INTERVAL",
            config.get("interval", self.interval)
        ))

        config["retention_days"] = int(os.environ.get(
            "RESOURCE_MONITOR_RETENTION_DAYS",
            config.get("retention_days", self.retention_days)
        ))

        config["alert_recipients"] = os.environ.get(
            "RESOURCE_MONITOR_ALERT_RECIPIENTS",
            config.get("alert_recipients", "")
        ).split(",")

        config["metrics_directory"] = os.environ.get(
            "RESOURCE_MONITOR_METRICS_DIRECTORY",
            config.get("metrics_directory", str(self.metrics_directory))
        )

        config["alert_cooldown"] = int(os.environ.get(
            "RESOURCE_MONITOR_ALERT_COOLDOWN",
            config.get("alert_cooldown", self.alert_cooldown)
        ))

        # Environment-specific configuration
        env = self._environment
        if f"{env}_cpu_threshold" in config:
            config["cpu_threshold"] = float(config[f"{env}_cpu_threshold"])

        if f"{env}_memory_threshold" in config:
            config["memory_threshold"] = float(config[f"{env}_memory_threshold"])

        if f"{env}_disk_threshold" in config:
            config["disk_threshold"] = float(config[f"{env}_disk_threshold"])

        if f"{env}_network_threshold" in config:
            config["network_threshold"] = float(config[f"{env}_network_threshold"])

        if f"{env}_load_threshold" in config:
            config["load_threshold"] = float(config[f"{env}_load_threshold"])

        return config

    def _apply_configuration(self) -> None:
        """Apply loaded configuration to instance settings."""
        if "cpu_threshold" in self.config:
            self.cpu_threshold = float(self.config["cpu_threshold"])

        if "memory_threshold" in self.config:
            self.memory_threshold = float(self.config["memory_threshold"])

        if "disk_threshold" in self.config:
            self.disk_threshold = float(self.config["disk_threshold"])

        if "network_threshold" in self.config:
            self.network_threshold = float(self.config["network_threshold"])

        if "load_threshold" in self.config:
            self.load_threshold = float(self.config["load_threshold"])

        if "interval" in self.config:
            self.interval = int(self.config["interval"])

        if "retention_days" in self.config:
            self.retention_days = int(self.config["retention_days"])

        if "metrics_directory" in self.config:
            self.metrics_directory = Path(self.config["metrics_directory"])

        if "alert_cooldown" in self.config:
            self.alert_cooldown = int(self.config["alert_cooldown"])

    def _setup_platform_specific(self) -> None:
        """Configure platform-specific monitoring settings."""
        if self.platform_system == "linux":
            self._setup_linux_monitoring()
        elif self.platform_system == "darwin":
            self._setup_mac_monitoring()
        elif self.platform_system == "windows":
            self._setup_windows_monitoring()
        else:
            logger.warning(f"Unsupported platform: {self.platform_system}")

    def _setup_linux_monitoring(self) -> None:
        """Set up Linux-specific monitoring."""
        logger.debug("Setting up Linux-specific monitoring")
        # Linux-specific monitoring setup could go here
        pass

    def _setup_mac_monitoring(self) -> None:
        """Set up macOS-specific monitoring."""
        logger.debug("Setting up macOS-specific monitoring")
        # macOS-specific monitoring setup could go here
        pass

    def _setup_windows_monitoring(self) -> None:
        """Set up Windows-specific monitoring."""
        logger.debug("Setting up Windows-specific monitoring")
        # Windows-specific monitoring setup could go here
        pass

    def _setup_cloud_providers(self) -> Dict[str, Any]:
        """
        Initialize cloud provider connections for metric collection.

        Returns:
            Dictionary of cloud provider clients
        """
        providers = {}

        # AWS setup
        if AWS_AVAILABLE:
            try:
                providers["aws"] = {
                    "cloudwatch": boto3.client("cloudwatch"),
                    "enabled": True
                }
                logger.debug("AWS CloudWatch monitoring initialized")
            except Exception as e:
                providers["aws"] = {"enabled": False, "error": str(e)}
                logger.warning(f"Failed to initialize AWS CloudWatch: {e}")
        else:
            providers["aws"] = {"enabled": False, "error": "boto3 not installed"}

        # Azure setup
        if AZURE_AVAILABLE:
            try:
                credential = DefaultAzureCredential()
                providers["azure"] = {
                    "metrics_client": MetricsQueryClient(credential),
                    "enabled": True
                }
                logger.debug("Azure Monitor initialized")
            except Exception as e:
                providers["azure"] = {"enabled": False, "error": str(e)}
                logger.warning(f"Failed to initialize Azure Monitor: {e}")
        else:
            providers["azure"] = {"enabled": False, "error": "Azure SDK not installed"}

        # GCP setup
        if GCP_AVAILABLE:
            try:
                client = monitoring_v3.MetricServiceClient()
                providers["gcp"] = {
                    "metrics_client": client,
                    "enabled": True
                }
                logger.debug("Google Cloud Monitoring initialized")
            except Exception as e:
                providers["gcp"] = {"enabled": False, "error": str(e)}
                logger.warning(f"Failed to initialize GCP Monitoring: {e}")
        else:
            providers["gcp"] = {"enabled": False, "error": "GCP SDK not installed"}

        return providers

    def start_monitoring(self) -> bool:
        """
        Start the resource monitoring in a background thread.

        Returns:
            True if monitoring started successfully, False otherwise
        """
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            logger.warning("Monitoring already running")
            return False

        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="ResourceMonitorThread",
            daemon=True
        )
        self._monitoring_thread.start()

        # Start cloud monitoring if any provider is available
        cloud_enabled = any(provider.get("enabled", False) for provider in self.cloud_providers.values())
        if cloud_enabled:
            self._cloud_monitoring_thread = threading.Thread(
                target=self._cloud_monitoring_loop,
                name="CloudMonitorThread",
                daemon=True
            )
            self._cloud_monitoring_thread.start()

        logger.info(f"Resource monitoring started with interval {self.interval}s")
        return True

    def stop_monitoring(self) -> None:
        """Stop the resource monitoring process."""
        if not self._monitoring_thread:
            logger.warning("Monitoring not running")
            return

        self._stop_monitoring.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)

        if self._cloud_monitoring_thread:
            self._cloud_monitoring_thread.join(timeout=5)

        logger.info("Resource monitoring stopped")

    def _monitoring_loop(self) -> None:
        """Main monitoring loop that collects metrics at regular intervals."""
        logger.debug("Starting monitoring loop")

        last_cleanup_time = time.time()
        cleanup_interval = 3600  # Clean up old metrics every hour

        while not self._stop_monitoring.is_set():
            try:
                start_time = time.time()

                # Collect system metrics
                self._collect_system_metrics()

                # Check thresholds and alert if necessary
                self._check_thresholds()

                # Save metrics to disk periodically
                current_time = time.time()
                if current_time - last_cleanup_time > cleanup_interval:
                    self._save_metrics_to_disk()
                    self._cleanup_old_metrics()
                    last_cleanup_time = current_time

                # Calculate sleep time, accounting for the time taken to collect metrics
                elapsed = time.time() - start_time
                sleep_time = max(0.1, self.interval - elapsed)

                # Sleep until next collection interval or until stopped
                self._stop_monitoring.wait(sleep_time)

            except Exception as e:
                if ERROR_HANDLER_AVAILABLE:
                    handle_error(e, ErrorCategory.MONITORING, "Resource monitoring loop")
                else:
                    logger.error(f"Error in monitoring loop: {e}", exc_info=True)

                # Sleep a bit before retrying to prevent tight error loops
                time.sleep(5)

    def _cloud_monitoring_loop(self) -> None:
        """Separate loop for collecting cloud provider metrics."""
        logger.debug("Starting cloud monitoring loop")

        while not self._stop_monitoring.is_set():
            try:
                # Collect cloud metrics
                self._collect_cloud_metrics()

                # Sleep until next collection or until stopped
                self._stop_monitoring.wait(CLOUD_PROVIDER_POLL_INTERVAL)

            except Exception as e:
                if ERROR_HANDLER_AVAILABLE:
                    handle_error(e, ErrorCategory.MONITORING, "Cloud monitoring loop")
                else:
                    logger.error(f"Error in cloud monitoring loop: {e}", exc_info=True)

                # Sleep a bit before retrying
                time.sleep(60)

    def _collect_system_metrics(self) -> None:
        """Collect system resource metrics and store them."""
        if not PSUTIL_AVAILABLE:
            logger.debug("Skipping system metrics collection: psutil not available")
            return

        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            metrics = {
                "timestamp": timestamp,
                "type": "system_metrics"
            }

            # CPU metrics
            cpu_metrics = self.get_cpu_info()
            metrics["cpu"] = cpu_metrics

            # Memory metrics
            memory_metrics = self.get_memory_info()
            metrics["memory"] = memory_metrics

            # Disk metrics
            disk_metrics = self.get_disk_info()
            metrics["disk"] = disk_metrics

            # Network metrics
            network_metrics = self.get_network_info()
            metrics["network"] = network_metrics

            # Process metrics - get top processes by CPU and memory
            process_metrics = self.get_process_info()
            metrics["processes"] = process_metrics

            # Store metrics in memory
            with self._metrics_lock:
                self._metrics_data[MetricCategory.CPU].append({
                    "timestamp": timestamp,
                    "values": cpu_metrics
                })
                self._metrics_data[MetricCategory.MEMORY].append({
                    "timestamp": timestamp,
                    "values": memory_metrics
                })
                self._metrics_data[MetricCategory.DISK].append({
                    "timestamp": timestamp,
                    "values": disk_metrics
                })
                self._metrics_data[MetricCategory.NETWORK].append({
                    "timestamp": timestamp,
                    "values": network_metrics
                })
                self._metrics_data[MetricCategory.PROCESS].append({
                    "timestamp": timestamp,
                    "values": process_metrics
                })

                # Trim oldest data if we have too many points
                for category in self._metrics_data:
                    if len(self._metrics_data[category]) > MAX_DATAPOINTS:
                        self._metrics_data[category] = self._metrics_data[category][-MAX_DATAPOINTS:]

            # Record specific metrics for historical tracking
            self.record_metric("cpu_percent", cpu_metrics["usage_percent"])
            self.record_metric("memory_percent", memory_metrics["percent_used"])
            self.record_metric("disk_percent", disk_metrics["percent_used"])

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "System metrics collection")
            else:
                logger.error(f"Error collecting system metrics: {e}", exc_info=True)

    def _collect_cloud_metrics(self) -> None:
        """Collect metrics from cloud providers."""
        timestamp = datetime.now(timezone.utc).isoformat()
        cloud_metrics = {
            "timestamp": timestamp,
            "providers": {}
        }

        # AWS CloudWatch metrics
        if self.cloud_providers.get("aws", {}).get("enabled", False):
            try:
                aws_metrics = self._collect_aws_metrics()
                cloud_metrics["providers"]["aws"] = aws_metrics
            except Exception as e:
                logger.error(f"Error collecting AWS metrics: {e}")
                cloud_metrics["providers"]["aws"] = {"error": str(e)}

        # Azure Monitor metrics
        if self.cloud_providers.get("azure", {}).get("enabled", False):
            try:
                azure_metrics = self._collect_azure_metrics()
                cloud_metrics["providers"]["azure"] = azure_metrics
            except Exception as e:
                logger.error(f"Error collecting Azure metrics: {e}")
                cloud_metrics["providers"]["azure"] = {"error": str(e)}

        # GCP Monitoring metrics
        if self.cloud_providers.get("gcp", {}).get("enabled", False):
            try:
                gcp_metrics = self._collect_gcp_metrics()
                cloud_metrics["providers"]["gcp"] = gcp_metrics
            except Exception as e:
                logger.error(f"Error collecting GCP metrics: {e}")
                cloud_metrics["providers"]["gcp"] = {"error": str(e)}

        # Store cloud metrics
        with self._metrics_lock:
            self._metrics_data[MetricCategory.CLOUD].append({
                "timestamp": timestamp,
                "values": cloud_metrics
            })

            # Trim oldest data if we have too many points
            if len(self._metrics_data[MetricCategory.CLOUD]) > MAX_DATAPOINTS:
                self._metrics_data[MetricCategory.CLOUD] = (
                    self._metrics_data[MetricCategory.CLOUD][-MAX_DATAPOINTS:]
                )

    def _collect_aws_metrics(self) -> Dict[str, Any]:
        """
        Collect metrics from AWS CloudWatch.

        Returns:
            AWS CloudWatch metrics
        """
        if not self.cloud_providers.get("aws", {}).get("enabled", False):
            return {"error": "AWS CloudWatch not available"}

        cloudwatch = self.cloud_providers["aws"]["cloudwatch"]
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=10)

        # Define metrics to collect based on environment configuration
        metrics_config = self.config.get("aws_metrics", [
            {"namespace": "AWS/EC2", "metric_name": "CPUUtilization"},
            {"namespace": "AWS/RDS", "metric_name": "CPUUtilization"},
            {"namespace": "AWS/Lambda", "metric_name": "Invocations"},
            {"namespace": "AWS/Lambda", "metric_name": "Errors"},
        ])

        metrics_data = {}

        for metric_config in metrics_config:
            namespace = metric_config["namespace"]
            metric_name = metric_config["metric_name"]
            dimensions = metric_config.get("dimensions", [])

            try:
                response = cloudwatch.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric_name,
                    Dimensions=dimensions,
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=300,  # 5-minute period
                    Statistics=['Average', 'Maximum']
                )

                datapoints = response.get("Datapoints", [])
                if datapoints:
                    # Sort by timestamp
                    datapoints.sort(key=lambda x: x["Timestamp"])

                    # Store in metrics structure
                    metric_key = f"{namespace}/{metric_name}"
                    metrics_data[metric_key] = {
                        "datapoints": [
                            {
                                "timestamp": dp["Timestamp"].isoformat(),
                                "average": dp.get("Average"),
                                "maximum": dp.get("Maximum")
                            }
                            for dp in datapoints
                        ],
                        "unit": response.get("Datapoints", [{}])[0].get("Unit", "None")
                        if response.get("Datapoints") else "None"
                    }
            except Exception as e:
                metrics_data[f"{namespace}/{metric_name}"] = {"error": str(e)}

        return metrics_data

    def _collect_azure_metrics(self) -> Dict[str, Any]:
        """
        Collect metrics from Azure Monitor.

        Returns:
            Azure Monitor metrics
        """
        if not self.cloud_providers.get("azure", {}).get("enabled", False):
            return {"error": "Azure Monitor not available"}

        metrics_client = self.cloud_providers["azure"]["metrics_client"]
        metrics_data = {}

        # Define resources to monitor based on environment configuration
        resources_config = self.config.get("azure_resources", [])

        # Use default resource if none specified
        if not resources_config and "azure_subscription_id" in self.config:
            subscription_id = self.config["azure_subscription_id"]
            resources_config = [
                {
                    "resource_id": f"/subscriptions/{subscription_id}/resourceGroups/*/providers/Microsoft.Compute/virtualMachines/*",
                    "metrics": ["Percentage CPU", "Available Memory Bytes"]
                }
            ]

        # Return empty dict if no resources to monitor
        if not resources_config:
            return {}

        for resource_config in resources_config:
            resource_id = resource_config["resource_id"]
            metrics_to_query = resource_config["metrics"]

            try:
                for metric_name in metrics_to_query:
                    response = metrics_client.query_resource(
                        resource_id,
                        [metric_name],
                        timespan=timedelta(hours=1)
                    )

                    # Extract metric data
                    metric_data = []
                    for metric in response.metrics:
                        for time_series in metric.timeseries:
                            for data_point in time_series.data:
                                if data_point.time_stamp and (data_point.average is not None or data_point.total is not None):
                                    metric_data.append({
                                        "timestamp": data_point.time_stamp.isoformat(),
                                        "average": data_point.average,
                                        "total": data_point.total,
                                        "count": data_point.count
                                    })

                    metrics_data[f"{resource_id}/{metric_name}"] = {
                        "datapoints": metric_data
                    }
            except Exception as e:
                metrics_data[f"{resource_id}"] = {"error": str(e)}

        return metrics_data

    def _collect_gcp_metrics(self) -> Dict[str, Any]:
        """
        Collect metrics from Google Cloud Monitoring.

        Returns:
            GCP Monitoring metrics
        """
        if not self.cloud_providers.get("gcp", {}).get("enabled", False):
            return {"error": "GCP Monitoring not available"}

        client = self.cloud_providers["gcp"]["metrics_client"]
        metrics_data = {}

        # Define metrics based on configuration
        metrics_config = self.config.get("gcp_metrics", [
            {"metric_type": "compute.googleapis.com/instance/cpu/utilization"},
            {"metric_type": "compute.googleapis.com/instance/memory/percent_used"}
        ])

        if "gcp_project_id" not in self.config:
            return {"error": "GCP project ID not configured"}

        project_id = self.config["gcp_project_id"]
        project_name = f"projects/{project_id}"

        # Current time in GCP format
        now = time.time()
        seconds = int(now)
        nanos = int((now - seconds) * 10**9)
        end_time = monitoring_v3.TimeInterval(
            {
                "end_time": {"seconds": seconds, "nanos": nanos},
                "start_time": {"seconds": seconds - 3600, "nanos": nanos},  # 1 hour ago
            }
        )

        for metric_config in metrics_config:
            metric_type = metric_config["metric_type"]

            try:
                results = client.list_time_series(
                    request={
                        "name": project_name,
                        "filter": f'metric.type="{metric_type}"',
                        "interval": end_time,
                        "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                    }
                )

                # Process and store the results
                time_series_data = []

                for time_series in results:
                    resource_labels = dict(time_series.resource.labels)
                    metric_labels = dict(time_series.metric.labels)

                    # Extract datapoints
                    datapoints = []
                    for point in time_series.points:
                        timestamp = point.interval.end_time.seconds
                        value = point.value.double_value

                        datapoints.append({
                            "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
                            "value": value
                        })

                    time_series_data.append({
                        "resource": resource_labels,
                        "metric_labels": metric_labels,
                        "datapoints": datapoints
                    })

                metrics_data[metric_type] = {"time_series": time_series_data}

            except Exception as e:
                metrics_data[metric_type] = {"error": str(e)}

        return metrics_data

    def _check_thresholds(self) -> None:
        """Check current metrics against thresholds and trigger alerts if needed."""
        try:
            # Get latest metrics
            cpu_metrics = self.get_cpu_info()
            memory_metrics = self.get_memory_info()
            disk_metrics = self.get_disk_info()
            network_metrics = self.get_network_info()

            # Check CPU threshold
            cpu_percent = cpu_metrics.get("usage_percent", 0)
            if cpu_percent >= self.cpu_threshold:
                self._send_threshold_alert(
                    "CPU",
                    f"CPU usage at {cpu_percent:.1f}% exceeds threshold of {self.cpu_threshold}%",
                    cpu_percent,
                    self.cpu_threshold,
                    AlertLevel.WARNING if cpu_percent < self.cpu_threshold * 1.25 else AlertLevel.CRITICAL
                )

            # Check memory threshold
            memory_percent = memory_metrics.get("percent_used", 0)
            if memory_percent >= self.memory_threshold:
                self._send_threshold_alert(
                    "Memory",
                    f"Memory usage at {memory_percent:.1f}% exceeds threshold of {self.memory_threshold}%",
                    memory_percent,
                    self.memory_threshold,
                    AlertLevel.WARNING if memory_percent < self.memory_threshold * 1.25 else AlertLevel.CRITICAL
                )

            # Check disk threshold
            disk_percent = disk_metrics.get("percent_used", 0)
            if disk_percent >= self.disk_threshold:
                self._send_threshold_alert(
                    "Disk",
                    f"Disk usage at {disk_percent:.1f}% exceeds threshold of {self.disk_threshold}%",
                    disk_percent,
                    self.disk_threshold,
                    AlertLevel.WARNING if disk_percent < self.disk_threshold * 1.1 else AlertLevel.CRITICAL
                )

            # Check load threshold (normalized by CPU count)
            if "load_avg_1min" in cpu_metrics and "cpu_count" in cpu_metrics:
                load_avg = cpu_metrics["load_avg_1min"]
                cpu_count = cpu_metrics["cpu_count"]
                normalized_load = load_avg / cpu_count if cpu_count > 0 else 0

                if normalized_load >= self.load_threshold:
                    self._send_threshold_alert(
                        "Load",
                        f"System load average at {load_avg:.2f} ({normalized_load:.2f}/core) exceeds threshold of {self.load_threshold}/core",
                        normalized_load,
                        self.load_threshold,
                        AlertLevel.WARNING if normalized_load < self.load_threshold * 1.5 else AlertLevel.CRITICAL
                    )

            # Check network utilization if available
            if "utilization_percent" in network_metrics:
                network_utilization = network_metrics["utilization_percent"]
                if network_utilization >= self.network_threshold:
                    self._send_threshold_alert(
                        "Network",
                        f"Network utilization at {network_utilization:.1f}% exceeds threshold of {self.network_threshold}%",
                        network_utilization,
                        self.network_threshold,
                        AlertLevel.WARNING if network_utilization < self.network_threshold * 1.25 else AlertLevel.CRITICAL
                    )

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Threshold checking")
            else:
                logger.error(f"Error checking thresholds: {e}", exc_info=True)

    def _send_threshold_alert(
        self,
        metric_type: str,
        message: str,
        current_value: float,
        threshold: float,
        level: str = AlertLevel.WARNING
    ) -> None:
        """
        Send an alert when a threshold is exceeded, with cooldown to prevent alert storms.

        Args:
            metric_type: Type of metric that triggered the alert
            message: Alert message
            current_value: Current metric value
            threshold: Threshold that was exceeded
            level: Alert level (warning, critical, etc.)
        """
        # Check cooldown period to avoid alert storms
        current_time = time.time()
        last_alert_time = self._last_alerts.get(metric_type, 0)

        if current_time - last_alert_time < self.alert_cooldown:
            logger.debug(f"Skipping {metric_type} alert due to cooldown period")
            return

        # Update last alert time
        self._last_alerts[metric_type] = current_time

        # Prepare alert data
        hostname = socket.gethostname()
        environment = self._environment
        subject = f"[{level.upper()}] {environment.upper()} - {hostname} - {metric_type} threshold exceeded"

        detailed_message = f"""
Resource Monitor Alert:
----------------------
Host: {hostname}
Environment: {environment}
Metric: {metric_type}
Current Value: {current_value:.2f}
Threshold: {threshold:.2f}
Level: {level.upper()}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Message: {message}
"""

        # Get recipients from config
        recipients = self.config.get("alert_recipients", [])
        if not recipients:
            logger.warning(f"No alert recipients configured, logging {level} alert: {message}")

        # Send notification
        if NOTIFICATION_AVAILABLE and recipients:
            send_notification(subject, detailed_message, recipients, priority=level)
        else:
            log_level = logging.WARNING if level == AlertLevel.WARNING else logging.ERROR
            logger.log(log_level, f"ALERT [{level.upper()}]: {message}")

    def _save_metrics_to_disk(self) -> None:
        """Save collected metrics to disk for long-term storage."""
        if not self.metrics_directory.exists():
            try:
                self.metrics_directory.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create metrics directory: {e}")
                return

        # Generate a timestamp for the filename
        date_str = datetime.now().strftime("%Y-%m-%d")
        current_hour = datetime.now().hour
        filepath = self.metrics_directory / f"metrics_{date_str}_{current_hour:02d}.json"

        try:
            # Create a copy of the metrics data to avoid lock contention
            with self._metrics_lock:
                metrics_copy = {}
                for category, data in self._metrics_data.items():
                    metrics_copy[category] = data[-DEFAULT_METRIC_BATCH_SIZE:] if data else []

            # Write metrics to file, appending if file exists
            metrics_to_save = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": socket.gethostname(),
                "environment": self._environment,
                "metrics": metrics_copy
            }

            # Use tempfile to ensure atomic write
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tf:
                json.dump(metrics_to_save, tf, default=str)
                temp_filename = tf.name

            # Move the temporary file to the final destination
            if sys.platform == 'win32':
                # Windows doesn't allow replacing an open file
                if filepath.exists():
                    filepath.unlink()
                os.rename(temp_filename, filepath)
            else:
                # Unix-like OS can safely replace
                os.rename(temp_filename, filepath)

            logger.debug(f"Saved metrics to {filepath}")

            # Clear the in-memory metrics for categories we've saved
            with self._metrics_lock:
                for category in self._metrics_data:
                    if len(self._metrics_data[category]) > DEFAULT_METRIC_BATCH_SIZE:
                        self._metrics_data[category] = self._metrics_data[category][-DEFAULT_METRIC_BATCH_SIZE:]

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Saving metrics to disk")
            else:
                logger.error(f"Error saving metrics to disk: {e}", exc_info=True)

            # Try to clean up the temporary file if it exists
            try:
                if os.path.exists(temp_filename):
                    os.unlink(temp_filename)
            except:
                pass

    def _cleanup_old_metrics(self) -> None:
        """Clean up metrics files that are older than the retention period."""
        retention_date = datetime.now() - timedelta(days=self.retention_days)

        # Iterate through all metrics files
        try:
            for path in self.metrics_directory.glob("metrics_*.json"):
                # Extract date from filename
                try:
                    # Expected format: metrics_YYYY-MM-DD_HH.json
                    date_str = path.stem.split('_')[1]
                    file_date = datetime.strptime(date_str, "%Y-%m-%d")

                    # Delete if older than retention period
                    if file_date < retention_date:
                        path.unlink()
                        logger.debug(f"Deleted old metrics file: {path}")
                except (ValueError, IndexError):
                    # If we can't parse the date, skip this file
                    logger.warning(f"Could not parse date from metrics filename: {path}")
                    continue

        except Exception as e:
            logger.error(f"Error cleaning up old metrics: {e}")

    def get_cpu_info(self) -> Dict[str, Any]:
        """
        Get current CPU usage information.

        Returns:
            Dictionary with CPU metrics
        """
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}

        try:
            # Get CPU usage percentage with minimal interval for responsiveness
            cpu_percent = psutil.cpu_percent(interval=0.1)

            cpu_info = {
                "usage_percent": cpu_percent,
                "cpu_count": psutil.cpu_count(logical=False),
                "cpu_count_logical": psutil.cpu_count(logical=True)
            }

            # Get CPU load averages on Unix-like systems
            if hasattr(os, 'getloadavg'):
                load_avg = os.getloadavg()
                cpu_info.update({
                    "load_avg_1min": load_avg[0],
                    "load_avg_5min": load_avg[1],
                    "load_avg_15min": load_avg[2]
                })

            # Add CPU frequency if available
            try:
                cpu_freq = psutil.cpu_freq()
                if cpu_freq:
                    cpu_info.update({
                        "frequency_current": cpu_freq.current,
                        "frequency_min": cpu_freq.min,
                        "frequency_max": cpu_freq.max
                    })
            except (AttributeError, NotImplementedError):
                pass

            # Get per-CPU usage if available
            try:
                per_cpu = psutil.cpu_percent(interval=0.1, percpu=True)
                cpu_info["per_cpu_percent"] = per_cpu
            except:
                pass

            # Get CPU times for different categories
            try:
                cpu_times = psutil.cpu_times_percent()
                cpu_info.update({
                    "time_user_percent": cpu_times.user,
                    "time_system_percent": cpu_times.system,
                    "time_idle_percent": cpu_times.idle
                })

                # Add platform-specific fields
                if hasattr(cpu_times, 'iowait'):
                    cpu_info["time_iowait_percent"] = cpu_times.iowait

                if hasattr(cpu_times, 'nice'):
                    cpu_info["time_nice_percent"] = cpu_times.nice
            except:
                pass

            return cpu_info

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "CPU info collection")
            else:
                logger.error(f"Error getting CPU info: {e}", exc_info=True)

            return {"error": str(e)}

    def get_memory_info(self) -> Dict[str, Any]:
        """
        Get current memory usage information.

        Returns:
            Dictionary with memory metrics
        """
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}

        try:
            # Get virtual memory (RAM) info
            vm = psutil.virtual_memory()

            memory_info = {
                "total_bytes": vm.total,
                "available_bytes": vm.available,
                "used_bytes": vm.used,
                "free_bytes": vm.free,
                "percent_used": vm.percent,

                # Add human-readable values
                "total_gb": round(vm.total / (1024**3), 2),
                "available_gb": round(vm.available / (1024**3), 2),
                "used_gb": round(vm.used / (1024**3), 2),
                "free_gb": round(vm.free / (1024**3), 2)
            }

            # Add swap information if available
            try:
                swap = psutil.swap_memory()
                memory_info["swap"] = {
                    "total_bytes": swap.total,
                    "used_bytes": swap.used,
                    "free_bytes": swap.free,
                    "percent_used": swap.percent,
                    "total_gb": round(swap.total / (1024**3), 2),
                    "used_gb": round(swap.used / (1024**3), 2),
                    "free_gb": round(swap.free / (1024**3), 2)
                }
            except:
                pass

            return memory_info

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Memory info collection")
            else:
                logger.error(f"Error getting memory info: {e}", exc_info=True)

            return {"error": str(e)}

    def get_disk_info(self, path: str = "/") -> Dict[str, Any]:
        """
        Get disk usage information for a specific path.

        Args:
            path: Path to get disk usage for

        Returns:
            Dictionary with disk metrics
        """
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}

        try:
            disk_usage = psutil.disk_usage(path)

            disk_info = {
                "path": path,
                "total_bytes": disk_usage.total,
                "used_bytes": disk_usage.used,
                "free_bytes": disk_usage.free,
                "percent_used": disk_usage.percent,

                # Add human-readable values
                "total_gb": round(disk_usage.total / (1024**3), 2),
                "used_gb": round(disk_usage.used / (1024**3), 2),
                "free_gb": round(disk_usage.free / (1024**3), 2)
            }

            # Add disk I/O stats if available
            try:
                io_counters = psutil.disk_io_counters()
                disk_info["io"] = {
                    "read_count": io_counters.read_count,
                    "write_count": io_counters.write_count,
                    "read_bytes": io_counters.read_bytes,
                    "write_bytes": io_counters.write_bytes,
                    "read_time_ms": io_counters.read_time,
                    "write_time_ms": io_counters.write_time
                }
            except (AttributeError, NotImplementedError, PermissionError):
                pass

            # Get disk partitions
            try:
                partitions = []
                for partition in psutil.disk_partitions(all=False):
                    partitions.append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "opts": partition.opts
                    })
                disk_info["partitions"] = partitions
            except (AttributeError, NotImplementedError, PermissionError):
                pass

            return disk_info

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Disk info collection")
            else:
                logger.error(f"Error getting disk info: {e}", exc_info=True)

            return {"error": str(e)}

    def get_network_info(self) -> Dict[str, Any]:
        """
        Get network usage information.

        Returns:
            Dictionary with network metrics
        """
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}

        try:
            # Get network I/O stats
            io_counters = psutil.net_io_counters()

            network_info = {
                "bytes_sent": io_counters.bytes_sent,
                "bytes_recv": io_counters.bytes_recv,
                "packets_sent": io_counters.packets_sent,
                "packets_recv": io_counters.packets_recv,
                "errin": io_counters.errin,
                "errout": io_counters.errout,
                "dropin": io_counters.dropin,
                "dropout": io_counters.dropout
            }

            # Calculate human-readable values
            network_info.update({
                "bytes_sent_mb": round(io_counters.bytes_sent / (1024**2), 2),
                "bytes_recv_mb": round(io_counters.bytes_recv / (1024**2), 2)
            })

            # Get network interfaces
            interfaces = {}
            for iface_name, iface_stats in psutil.net_if_stats().items():
                interfaces[iface_name] = {
                    "isup": iface_stats.isup,
                    "duplex": iface_stats.duplex,
                    "speed": iface_stats.speed,
                    "mtu": iface_stats.mtu
                }

                # Get the interface addresses
                iface_addresses = []
                for addr in psutil.net_if_addrs().get(iface_name, []):
                    addr_info = {
                        "family": addr.family,
                        "address": addr.address
                    }

                    if addr.netmask:
                        addr_info["netmask"] = addr.netmask

                    if addr.broadcast:
                        addr_info["broadcast"] = addr.broadcast

                    iface_addresses.append(addr_info)

                interfaces[iface_name]["addresses"] = iface_addresses

                # Get per-interface IO stats if available
                try:
                    per_nic_stats = psutil.net_io_counters(pernic=True)
                    if iface_name in per_nic_stats:
                        nic_stats = per_nic_stats[iface_name]
                        interfaces[iface_name]["io"] = {
                            "bytes_sent": nic_stats.bytes_sent,
                            "bytes_recv": nic_stats.bytes_recv,
                            "packets_sent": nic_stats.packets_sent,
                            "packets_recv": nic_stats.packets_recv,
                            "bytes_sent_mb": round(nic_stats.bytes_sent / (1024**2), 2),
                            "bytes_recv_mb": round(nic_stats.bytes_recv / (1024**2), 2)
                        }
                except (AttributeError, NotImplementedError, PermissionError):
                    pass

            network_info["interfaces"] = interfaces

            # Get connection stats if available
            try:
                # Count connections by status
                conn_status = {}
                for conn in psutil.net_connections(kind='inet'):
                    status = conn.status
                    conn_status[status] = conn_status.get(status, 0) + 1

                network_info["connections"] = {
                    "total": sum(conn_status.values()),
                    "by_status": conn_status
                }
            except (AttributeError, NotImplementedError, PermissionError):
                pass

            return network_info

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Network info collection")
            else:
                logger.error(f"Error getting network info: {e}", exc_info=True)

            return {"error": str(e)}

    def get_process_info(self, top_n: int = 5) -> Dict[str, Any]:
        """
        Get information about top processes by CPU and memory usage.

        Args:
            top_n: Number of top processes to return

        Returns:
            Dictionary with process metrics
        """
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}

        try:
            # Get all processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'create_time']):
                try:
                    # Get per-process info
                    proc_info = proc.info

                    # Skip processes with 0 CPU and minimal memory usage to reduce noise
                    if (proc_info['cpu_percent'] < 0.1 and
                            proc_info['memory_percent'] < 0.1):
                        continue

                    # Calculate process uptime
                    if 'create_time' in proc_info:
                        proc_info['uptime'] = time.time() - proc_info['create_time']

                    processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Sort processes by CPU and memory usage
            top_cpu_processes = sorted(processes, key=lambda p: p.get('cpu_percent', 0), reverse=True)[:top_n]
            top_memory_processes = sorted(processes, key=lambda p: p.get('memory_percent', 0), reverse=True)[:top_n]

            # Format the results
            result = {
                "total_count": len(processes),
                "by_cpu": [
                    {
                        "pid": p.get('pid'),
                        "name": p.get('name'),
                        "username": p.get('username'),
                        "cpu_percent": p.get('cpu_percent'),
                        "memory_percent": p.get('memory_percent'),
                        "uptime_seconds": p.get('uptime')
                    } for p in top_cpu_processes
                ],
                "by_memory": [
                    {
                        "pid": p.get('pid'),
                        "name": p.get('name'),
                        "username": p.get('username'),
                        "cpu_percent": p.get('cpu_percent'),
                        "memory_percent": p.get('memory_percent'),
                        "uptime_seconds": p.get('uptime')
                    } for p in top_memory_processes
                ]
            }

            return result

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Process info collection")
            else:
                logger.error(f"Error getting process info: {e}", exc_info=True)

            return {"error": str(e)}

    def get_cpu_usage(self) -> float:
        """
        Get current CPU usage percentage.

        Returns:
            CPU usage as a percentage (0-100)
        """
        cpu_info = self.get_cpu_info()
        return cpu_info.get("usage_percent", 0.0)

    def get_memory_usage(self) -> float:
        """
        Get current memory usage percentage.

        Returns:
            Memory usage as a percentage (0-100)
        """
        memory_info = self.get_memory_info()
        return memory_info.get("percent_used", 0.0)

    def get_disk_usage(self, path: str = "/") -> float:
        """
        Get current disk usage percentage for a specific path.

        Args:
            path: Path to get disk usage for

        Returns:
            Disk usage as a percentage (0-100)
        """
        disk_info = self.get_disk_info(path)
        return disk_info.get("percent_used", 0.0)

    def get_load_average(self) -> float:
        """
        Get system load average (1 minute).

        Returns:
            1-minute load average or 0.0 if not available
        """
        cpu_info = self.get_cpu_info()
        return cpu_info.get("load_avg_1min", 0.0)

    def is_cpu_critical(self) -> bool:
        """
        Check if CPU usage is at a critical level.

        Returns:
            True if CPU usage exceeds threshold, False otherwise
        """
        cpu_usage = self.get_cpu_usage()
        return cpu_usage >= self.cpu_threshold

    def is_memory_critical(self) -> bool:
        """
        Check if memory usage is at a critical level.

        Returns:
            True if memory usage exceeds threshold, False otherwise
        """
        memory_usage = self.get_memory_usage()
        return memory_usage >= self.memory_threshold

    def is_disk_critical(self, path: str = "/") -> bool:
        """
        Check if disk usage is at a critical level.

        Args:
            path: Path to check disk usage for

        Returns:
            True if disk usage exceeds threshold, False otherwise
        """
        disk_usage = self.get_disk_usage(path)
        return disk_usage >= self.disk_threshold

    def record_metric(self, name: str, value: Any, retention_days: Optional[int] = None) -> bool:
        """
        Record a custom metric for historical tracking.

        Args:
            name: Metric name
            value: Metric value
            retention_days: Optional override for retention days

        Returns:
            True if metric was recorded successfully, False otherwise
        """
        retention = retention_days if retention_days is not None else self.retention_days

        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            metric_data = {
                "name": name,
                "value": value,
                "timestamp": timestamp
            }

            # Store in memory for short-term usage
            with self._metrics_lock:
                self._metrics_data[MetricCategory.CUSTOM].append({
                    "timestamp": timestamp,
                    "values": metric_data
                })

                # Trim oldest data if we have too many points
                if len(self._metrics_data[MetricCategory.CUSTOM]) > MAX_DATAPOINTS:
                    self._metrics_data[MetricCategory.CUSTOM] = (
                        self._metrics_data[MetricCategory.CUSTOM][-MAX_DATAPOINTS:]
                    )

            # Store in historical data
            if name not in self._historical_data:
                self._historical_data[name] = []

            self._historical_data[name].append({
                "timestamp": timestamp,
                "value": value
            })

            # Trim historical data based on retention period
            if len(self._historical_data[name]) > MAX_DATAPOINTS:
                self._historical_data[name] = self._historical_data[name][-MAX_DATAPOINTS:]

            # Periodically save to disk - can be improved with batching
            current_time = time.time()
            if current_time % 60 < self.interval:  # Save approximately every minute
                self._save_historical_metric(name)

            return True

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, f"Recording metric {name}")
            else:
                logger.error(f"Error recording metric {name}: {e}", exc_info=True)

            return False

    def _save_historical_metric(self, name: str) -> None:
        """
        Save a historical metric to disk.

        Args:
            name: Metric name to save
        """
        if name not in self._historical_data or not self._historical_data[name]:
            return

        # Generate a filename
        date_str = datetime.now().strftime("%Y-%m-%d")
        filename = name.replace(" ", "_").replace("/", "_").replace("\\", "_")
        filepath = self.metrics_directory / f"metric_{filename}_{date_str}.json"

        try:
            # Create a copy of the data to avoid lock contention
            data_copy = self._historical_data[name].copy()

            # Write to disk using temp file to ensure atomic writes
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tf:
                metric_data = {
                    "name": name,
                    "hostname": socket.gethostname(),
                    "environment": self._environment,
                    "data": data_copy
                }
                json.dump(metric_data, tf, default=str)
                temp_filename = tf.name

            # Move the temporary file to the final destination
            if sys.platform == 'win32':
                # Windows doesn't allow replacing an open file
                if filepath.exists():
                    filepath.unlink()
                os.rename(temp_filename, filepath)
            else:
                # Unix-like OS can safely replace
                os.rename(temp_filename, filepath)

            logger.debug(f"Saved metric {name} to {filepath}")

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, f"Saving historical metric {name}")
            else:
                logger.error(f"Error saving historical metric {name}: {e}", exc_info=True)

            # Try to clean up the temporary file if it exists
            try:
                if 'temp_filename' in locals() and os.path.exists(temp_filename):
                    os.unlink(temp_filename)
            except:
                pass

    def get_historical_metrics(
        self,
        metric_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Get historical metrics from memory and disk.

        Args:
            metric_name: Optional metric name to filter by
            start_time: Optional start time for metrics
            end_time: Optional end time for metrics
            limit: Maximum number of data points to return

        Returns:
            Dictionary with historical metrics
        """
        result = {"metrics": {}}

        try:
            # Use now as default end time
            if not end_time:
                end_time = datetime.now(timezone.utc)

            # Default start time is 24 hours ago if not provided
            if not start_time:
                start_time = end_time - timedelta(hours=24)

            # Format timestamps for comparisons
            start_timestamp = start_time.isoformat()
            end_timestamp = end_time.isoformat()

            # If a specific metric name is requested
            if metric_name:
                # Check in-memory data first
                if metric_name in self._historical_data:
                    data_points = [
                        dp for dp in self._historical_data[metric_name]
                        if start_timestamp <= dp["timestamp"] <= end_timestamp
                    ]
                    # Sort by timestamp and limit results
                    data_points = sorted(data_points, key=lambda dp: dp["timestamp"])[-limit:]
                    result["metrics"][metric_name] = data_points

                # Check disk for historical data if not enough in memory
                if metric_name not in result["metrics"] or len(result["metrics"][metric_name]) < limit:
                    self._load_historical_metric_from_disk(metric_name, start_time, end_time, limit, result)
            else:
                # If no specific metric, return all metrics
                for name in self._historical_data.keys():
                    data_points = [
                        dp for dp in self._historical_data[name]
                        if start_timestamp <= dp["timestamp"] <= end_timestamp
                    ]
                    # Sort by timestamp and limit results
                    data_points = sorted(data_points, key=lambda dp: dp["timestamp"])[-limit:]
                    if data_points:  # Only include non-empty metrics
                        result["metrics"][name] = data_points

                # Try to find additional metrics on disk
                self._load_all_historical_metrics_from_disk(start_time, end_time, limit, result)

            # Add metadata
            result["metadata"] = {
                "start_time": start_timestamp,
                "end_time": end_timestamp,
                "requested_limit": limit,
                "hostname": socket.gethostname(),
                "environment": self._environment,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }

            return result

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Retrieving historical metrics")
            else:
                logger.error(f"Error retrieving historical metrics: {e}", exc_info=True)

            return {
                "metrics": {},
                "error": str(e),
                "metadata": {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "success": False
                }
            }

    def _load_historical_metric_from_disk(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
        result: Dict[str, Any]
    ) -> None:
        """
        Load historical metric data from disk for a specific metric.

        Args:
            metric_name: Name of the metric to load
            start_time: Start time for filtering metrics
            end_time: End time for filtering metrics
            limit: Maximum number of data points to return
            result: Result dictionary to update with loaded metrics
        """
        try:
            # Safe filename conversion
            filename = metric_name.replace(" ", "_").replace("/", "_").replace("\\", "_")

            # Check files for each possible day in the range
            current_date = start_time.date()
            end_date = end_time.date()
            data_points = []

            while current_date <= end_date:
                date_str = current_date.strftime("%Y-%m-%d")
                filepath = self.metrics_directory / f"metric_{filename}_{date_str}.json"

                if filepath.exists():
                    try:
                        with open(filepath, 'r') as f:
                            file_data = json.load(f)

                            if "data" in file_data:
                                # Filter by timestamp range
                                filtered_points = [
                                    dp for dp in file_data["data"]
                                    if start_time.isoformat() <= dp["timestamp"] <= end_time.isoformat()
                                ]
                                data_points.extend(filtered_points)
                    except (json.JSONDecodeError, IOError) as e:
                        logger.warning(f"Error reading metric file {filepath}: {e}")

                # Move to next day
                current_date += timedelta(days=1)

            # Sort and limit results
            if data_points:
                data_points = sorted(data_points, key=lambda dp: dp["timestamp"])
                # If we already have some in-memory points, combine them
                if metric_name in result["metrics"]:
                    existing_points = result["metrics"][metric_name]
                    # Combine lists, sort, and apply limit
                    combined = sorted(
                        existing_points + data_points,
                        key=lambda dp: dp["timestamp"]
                    )[-limit:]
                    result["metrics"][metric_name] = combined
                else:
                    result["metrics"][metric_name] = data_points[-limit:]

        except Exception as e:
            logger.error(f"Error loading historical metric {metric_name} from disk: {e}", exc_info=True)

    def _load_all_historical_metrics_from_disk(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int,
        result: Dict[str, Any]
    ) -> None:
        """
        Load all historical metrics from disk within a time range.

        Args:
            start_time: Start time for filtering metrics
            end_time: End time for filtering metrics
            limit: Maximum number of data points per metric
            result: Result dictionary to update with loaded metrics
        """
        try:
            # Find all metric files in the metrics directory
            metric_files = list(self.metrics_directory.glob("metric_*_*.json"))

            for filepath in metric_files:
                try:
                    # Extract metric name from filename
                    # Format: metric_NAME_YYYY-MM-DD.json
                    parts = filepath.stem.split('_', 1)  # Split on first underscore
                    if len(parts) > 1:
                        # The remaining part may include the date and underscores in the metric name
                        metric_with_date = parts[1]
                        # Find the last 10 characters which should be the date YYYY-MM-DD
                        if len(metric_with_date) > 10:
                            date_part = metric_with_date[-10:]
                            # Check if it matches date format
                            try:
                                datetime.strptime(date_part, "%Y-%m-%d")
                                # If it does, metric name is everything before the date
                                metric_name = metric_with_date[:-11]  # -11 to account for the underscore before date
                            except ValueError:
                                # If not a valid date, use the whole string as the metric name
                                metric_name = metric_with_date
                        else:
                            # Too short to contain a date, use as is
                            metric_name = metric_with_date
                    else:
                        # Invalid filename format, skip
                        continue

                    # Skip if we already have this metric fully populated
                    if metric_name in result["metrics"] and len(result["metrics"][metric_name]) >= limit:
                        continue

                    # Read the file
                    with open(filepath, 'r') as f:
                        file_data = json.load(f)

                        if "data" in file_data:
                            # Filter by timestamp range
                            filtered_points = [
                                dp for dp in file_data["data"]
                                if start_time.isoformat() <= dp["timestamp"] <= end_time.isoformat()
                            ]

                            if filtered_points:
                                # Add or combine with existing data
                                if metric_name in result["metrics"]:
                                    existing_points = result["metrics"][metric_name]
                                    # Combine lists, sort, and apply limit
                                    combined = sorted(
                                        existing_points + filtered_points,
                                        key=lambda dp: dp["timestamp"]
                                    )[-limit:]
                                    result["metrics"][metric_name] = combined
                                else:
                                    result["metrics"][metric_name] = filtered_points[-limit:]

                except Exception as e:
                    logger.warning(f"Error processing metric file {filepath}: {e}")

        except Exception as e:
            logger.error(f"Error loading all historical metrics from disk: {e}", exc_info=True)

    def get_resource_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current system resource usage.

        Returns:
            Dictionary with summary of resource utilization
        """
        try:
            # Get current resource info
            cpu_info = self.get_cpu_info()
            memory_info = self.get_memory_info()
            disk_info = self.get_disk_info()
            network_info = self.get_network_info()

            # Create a summary with key metrics
            summary = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": socket.gethostname(),
                "environment": self._environment,
                "resources": {
                    "cpu": {
                        "usage_percent": cpu_info.get("usage_percent", 0),
                        "core_count": cpu_info.get("cpu_count_logical", 1),
                        "critical": cpu_info.get("usage_percent", 0) >= self.cpu_threshold
                    },
                    "memory": {
                        "usage_percent": memory_info.get("percent_used", 0),
                        "total_gb": memory_info.get("total_gb", 0),
                        "used_gb": memory_info.get("used_gb", 0),
                        "critical": memory_info.get("percent_used", 0) >= self.memory_threshold
                    },
                    "disk": {
                        "usage_percent": disk_info.get("percent_used", 0),
                        "total_gb": disk_info.get("total_gb", 0),
                        "free_gb": disk_info.get("free_gb", 0),
                        "critical": disk_info.get("percent_used", 0) >= self.disk_threshold
                    }
                },
                "status": "healthy"
            }

            # Add load average if available
            if "load_avg_1min" in cpu_info:
                summary["resources"]["load"] = {
                    "load_1min": cpu_info["load_avg_1min"],
                    "load_5min": cpu_info.get("load_avg_5min", 0),
                    "load_15min": cpu_info.get("load_avg_15min", 0),
                    "per_core": cpu_info["load_avg_1min"] / max(cpu_info.get("cpu_count", 1), 1),
                    "critical": (cpu_info["load_avg_1min"] / max(cpu_info.get("cpu_count", 1), 1)) >= self.load_threshold
                }

            # Add network throughput if available
            if "bytes_sent" in network_info and "bytes_recv" in network_info:
                summary["resources"]["network"] = {
                    "sent_mb": network_info.get("bytes_sent_mb", 0),
                    "received_mb": network_info.get("bytes_recv_mb", 0),
                    "connections": network_info.get("connections", {}).get("total", 0)
                }

            # Add top processes if available
            processes = self.get_process_info(top_n=3)
            if "by_cpu" in processes:
                summary["top_processes"] = {
                    "by_cpu": processes["by_cpu"][:3],
                    "by_memory": processes["by_memory"][:3]
                }

            # Determine overall status based on thresholds
            if (summary["resources"]["cpu"].get("critical", False) or
                summary["resources"]["memory"].get("critical", False) or
                summary["resources"]["disk"].get("critical", False) or
                summary["resources"].get("load", {}).get("critical", False)):
                summary["status"] = "critical"
            elif (cpu_info.get("usage_percent", 0) >= self.cpu_threshold * 0.8 or
                    memory_info.get("percent_used", 0) >= self.memory_threshold * 0.8 or
                    disk_info.get("percent_used", 0) >= self.disk_threshold * 0.8):
                summary["status"] = "warning"

            return summary

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Getting resource summary")
            else:
                logger.error(f"Error getting resource summary: {e}", exc_info=True)

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "error",
                "error": str(e)
            }

    def generate_report(self, include_history: bool = True, history_hours: int = 24) -> Dict[str, Any]:
        """
        Generate a comprehensive resource monitoring report.

        Args:
            include_history: Whether to include historical metrics
            history_hours: How many hours of historical data to include

        Returns:
            Dictionary with comprehensive monitoring report
        """
        try:
            report = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": socket.gethostname(),
                "environment": self._environment,
                "report_id": str(uuid.uuid4()),
                "current": self.get_resource_summary()
            }

            # Add cloud provider information if available
            cloud_info = {}
            for provider, info in self.cloud_providers.items():
                if info.get("enabled", False):
                    cloud_info[provider] = {"available": True}
                else:
                    cloud_info[provider] = {
                        "available": False,
                        "reason": info.get("error", "Not configured")
                    }

            if cloud_info:
                report["cloud_providers"] = cloud_info

            # Add thresholds section
            report["thresholds"] = {
                "cpu_percent": self.cpu_threshold,
                "memory_percent": self.memory_threshold,
                "disk_percent": self.disk_threshold,
                "load_average": self.load_threshold,
                "network_percent": self.network_threshold
            }

            # Add configuration information
            report["configuration"] = {
                "interval": self.interval,
                "retention_days": self.retention_days,
                "metrics_directory": str(self.metrics_directory),
                "platform": self.platform_system
            }

            # Add historical data if requested
            if include_history:
                end_time = datetime.now(timezone.utc)
                start_time = end_time - timedelta(hours=history_hours)

                # Get CPU, memory, disk usage history
                cpu_history = self.get_historical_metrics("cpu_percent", start_time, end_time, 100)
                memory_history = self.get_historical_metrics("memory_percent", start_time, end_time, 100)
                disk_history = self.get_historical_metrics("disk_percent", start_time, end_time, 100)

                report["history"] = {
                    "range": {
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat(),
                        "hours": history_hours
                    },
                    "metrics": {
                        "cpu": cpu_history.get("metrics", {}).get("cpu_percent", []),
                        "memory": memory_history.get("metrics", {}).get("memory_percent", []),
                        "disk": disk_history.get("metrics", {}).get("disk_percent", [])
                    }
                }

                # Calculate min, max, avg for each metric if data is available
                for metric_name, data_list in report["history"]["metrics"].items():
                    if data_list:
                        values = [float(dp["value"]) for dp in data_list if "value" in dp]
                        if values:
                            report["history"]["metrics"][f"{metric_name}_stats"] = {
                                "min": min(values),
                                "max": max(values),
                                "avg": sum(values) / len(values),
                                "samples": len(values)
                            }

            return report

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, "Generating report")
            else:
                logger.error(f"Error generating report: {e}", exc_info=True)

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "error",
                "error": str(e)
            }

    def send_alert(self, alert_type: str, message: str, priority: str = "normal") -> bool:
        """
        Send a custom alert through the notification system.

        Args:
            alert_type: Type of alert
            message: Alert message
            priority: Alert priority level

        Returns:
            True if alert was sent successfully, False otherwise
        """
        try:
            # Prepare alert data
            hostname = socket.gethostname()
            environment = self._environment
            subject = f"[{priority.upper()}] {environment.upper()} - {hostname} - {alert_type}"

            detailed_message = f"""
Resource Monitor Alert:
----------------------
Host: {hostname}
Environment: {environment}
Type: {alert_type}
Level: {priority.upper()}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Message: {message}
            """

            # Get recipients from config
            recipients = self.config.get("alert_recipients", [])
            if not recipients:
                logger.warning(f"No alert recipients configured, logging {priority} alert: {message}")

            # Send notification
            if NOTIFICATION_AVAILABLE and recipients:
                send_notification(subject, detailed_message, recipients, priority=priority)
                return True
            else:
                log_level = logging.WARNING if priority == AlertLevel.WARNING else logging.ERROR
                logger.log(log_level, f"ALERT [{priority.upper()}]: {message}")
                return False

        except Exception as e:
            logger.error(f"Error sending alert: {e}", exc_info=True)
            return False

    def export_metrics(self, format_type: str = "json", output_file: Optional[str] = None) -> Optional[str]:
        """
        Export current metrics in the specified format.

        Args:
            format_type: Format type ('json', 'prometheus', 'csv')
            output_file: Optional file path to write metrics to

        Returns:
            String representation of metrics or None if writing to file
        """
        try:
            # Get all current metrics
            cpu_metrics = self.get_cpu_info()
            memory_metrics = self.get_memory_info()
            disk_metrics = self.get_disk_info()
            network_metrics = self.get_network_info()
            process_info = self.get_process_info(top_n=10)

            # Format based on the requested type
            if format_type.lower() == "json":
                metrics_data = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "hostname": socket.gethostname(),
                    "environment": self._environment,
                    "metrics": {
                        "cpu": cpu_metrics,
                        "memory": memory_metrics,
                        "disk": disk_metrics,
                        "network": network_metrics,
                        "processes": {
                            "top_by_cpu": process_info.get("by_cpu", []),
                            "top_by_memory": process_info.get("by_memory", [])
                        }
                    }
                }

                result = json.dumps(metrics_data, indent=2, default=str)

            elif format_type.lower() == "prometheus":
                # Create Prometheus format metrics
                lines = []
                timestamp_ms = int(time.time() * 1000)

                # CPU metrics
                lines.append(f"# HELP system_cpu_usage_percent CPU usage percentage")
                lines.append(f"# TYPE system_cpu_usage_percent gauge")
                lines.append(f"system_cpu_usage_percent {cpu_metrics.get('usage_percent', 0)} {timestamp_ms}")

                if "time_user_percent" in cpu_metrics:
                    lines.append(f"# HELP system_cpu_user_percent CPU user time percentage")
                    lines.append(f"# TYPE system_cpu_user_percent gauge")
                    lines.append(f"system_cpu_user_percent {cpu_metrics.get('time_user_percent', 0)} {timestamp_ms}")

                if "time_system_percent" in cpu_metrics:
                    lines.append(f"# HELP system_cpu_system_percent CPU system time percentage")
                    lines.append(f"# TYPE system_cpu_system_percent gauge")
                    lines.append(f"system_cpu_system_percent {cpu_metrics.get('time_system_percent', 0)} {timestamp_ms}")

                if "load_avg_1min" in cpu_metrics:
                    lines.append(f"# HELP system_load_avg_1min System load average over 1 minute")
                    lines.append(f"# TYPE system_load_avg_1min gauge")
                    lines.append(f"system_load_avg_1min {cpu_metrics.get('load_avg_1min', 0)} {timestamp_ms}")

                # Memory metrics
                lines.append(f"# HELP system_memory_usage_percent Memory usage percentage")
                lines.append(f"# TYPE system_memory_usage_percent gauge")
                lines.append(f"system_memory_usage_percent {memory_metrics.get('percent_used', 0)} {timestamp_ms}")

                lines.append(f"# HELP system_memory_total_bytes Total memory in bytes")
                lines.append(f"# TYPE system_memory_total_bytes gauge")
                lines.append(f"system_memory_total_bytes {memory_metrics.get('total_bytes', 0)} {timestamp_ms}")

                lines.append(f"# HELP system_memory_used_bytes Used memory in bytes")
                lines.append(f"# TYPE system_memory_used_bytes gauge")
                lines.append(f"system_memory_used_bytes {memory_metrics.get('used_bytes', 0)} {timestamp_ms}")

                # Disk metrics
                lines.append(f"# HELP system_disk_usage_percent Disk usage percentage")
                lines.append(f"# TYPE system_disk_usage_percent gauge")
                lines.append(f"system_disk_usage_percent{{path=\"{disk_metrics.get('path', '/')}\"}} {disk_metrics.get('percent_used', 0)} {timestamp_ms}")

                lines.append(f"# HELP system_disk_total_bytes Total disk space in bytes")
                lines.append(f"# TYPE system_disk_total_bytes gauge")
                lines.append(f"system_disk_total_bytes{{path=\"{disk_metrics.get('path', '/')}\"}} {disk_metrics.get('total_bytes', 0)} {timestamp_ms}")

                lines.append(f"# HELP system_disk_free_bytes Free disk space in bytes")
                lines.append(f"# TYPE system_disk_free_bytes gauge")
                lines.append(f"system_disk_free_bytes{{path=\"{disk_metrics.get('path', '/')}\"}} {disk_metrics.get('free_bytes', 0)} {timestamp_ms}")

                # Network metrics
                lines.append(f"# HELP system_network_bytes_sent Total network bytes sent")
                lines.append(f"# TYPE system_network_bytes_sent counter")
                lines.append(f"system_network_bytes_sent {network_metrics.get('bytes_sent', 0)} {timestamp_ms}")

                lines.append(f"# HELP system_network_bytes_received Total network bytes received")
                lines.append(f"# TYPE system_network_bytes_received counter")
                lines.append(f"system_network_bytes_received {network_metrics.get('bytes_recv', 0)} {timestamp_ms}")

                result = "\n".join(lines)

            elif format_type.lower() == "csv":
                # Create CSV format
                lines = ["timestamp,metric,value"]
                timestamp = datetime.now(timezone.utc).isoformat()

                # Add CPU metrics
                lines.append(f"{timestamp},cpu.usage_percent,{cpu_metrics.get('usage_percent', 0)}")
                if "load_avg_1min" in cpu_metrics:
                    lines.append(f"{timestamp},cpu.load_avg_1min,{cpu_metrics.get('load_avg_1min', 0)}")

                # Add memory metrics
                lines.append(f"{timestamp},memory.percent_used,{memory_metrics.get('percent_used', 0)}")
                lines.append(f"{timestamp},memory.total_gb,{memory_metrics.get('total_gb', 0)}")
                lines.append(f"{timestamp},memory.used_gb,{memory_metrics.get('used_gb', 0)}")

                # Add disk metrics
                lines.append(f"{timestamp},disk.percent_used,{disk_metrics.get('percent_used', 0)}")
                lines.append(f"{timestamp},disk.total_gb,{disk_metrics.get('total_gb', 0)}")
                lines.append(f"{timestamp},disk.free_gb,{disk_metrics.get('free_gb', 0)}")

                # Add network metrics
                lines.append(f"{timestamp},network.bytes_sent_mb,{network_metrics.get('bytes_sent_mb', 0)}")
                lines.append(f"{timestamp},network.bytes_recv_mb,{network_metrics.get('bytes_recv_mb', 0)}")

                result = "\n".join(lines)

            else:
                raise ValueError(f"Unsupported format type: {format_type}")

            # Write to file if output_file is specified
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(result)
                logger.info(f"Metrics exported to {output_file} in {format_type} format")
                return None

            return result

        except Exception as e:
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, ErrorCategory.MONITORING, f"Exporting metrics to {format_type}")
            else:
                logger.error(f"Error exporting metrics to {format_type}: {e}", exc_info=True)

            return None

    def __str__(self) -> str:
        """Return string representation of the resource monitor."""
        status = self.get_resource_summary()
        return f"ResourceMonitor({self._environment}): CPU={status['resources']['cpu']['usage_percent']:.1f}%, " + \
                f"Memory={status['resources']['memory']['usage_percent']:.1f}%, " + \
                f"Disk={status['resources']['disk']['usage_percent']:.1f}%, " + \
                f"Status={status['status']}"
