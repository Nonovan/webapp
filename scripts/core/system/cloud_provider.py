#!/usr/bin/env python3
# filepath: scripts/core/system/cloud_provider.py
"""
Cloud Provider Abstraction Module for Cloud Infrastructure Platform.

This module implements a unified interface for interacting with multiple cloud providers
(AWS, Azure, GCP) and manages cloud resources, authentication, and operations. It provides
consistent functionality across providers with appropriate error handling, retries,
and circuit breaker patterns to ensure robust cloud operations.

Key features:
- Multi-cloud provider support with unified interface
- Authentication and credential management
- Resource provisioning and management
- Cost optimization capabilities
- Retry mechanisms with exponential backoff
- Circuit breaker patterns to prevent cascading failures
- Secure credential handling and storage
- Cross-provider resource abstraction
- Provider-specific operation handling
- Metrics collection and monitoring
"""

import os
import sys
import time
import json
import logging
import uuid
import socket
import tempfile
import requests
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Union, Tuple, Callable, Set, TypeVar, Generic
from functools import wraps
import threading
import queue
from urllib.parse import urlparse

# Try to import core modules if available
try:
    from scripts.core.logger import Logger
    logger = Logger.get_logger(__name__)
except ImportError:
    # Fallback logging if core logger is not available
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

try:
    from scripts.core.error_handler import handle_error, ErrorCategory, CircuitBreaker
    ERROR_HANDLER_AVAILABLE = True
except ImportError:
    logger.warning("Error handler not available, using basic error handling")
    ERROR_HANDLER_AVAILABLE = False

try:
    from scripts.core.environment import get_current_environment, is_production
    ENVIRONMENT_AVAILABLE = True
except ImportError:
    logger.warning("Environment module not available, using default environment")
    ENVIRONMENT_AVAILABLE = False

    def get_current_environment():
        return os.environ.get("ENVIRONMENT", "development")

    def is_production():
        return get_current_environment() == "production"

try:
    from scripts.core.config_loader import ConfigLoader, load_config
    CONFIG_LOADER_AVAILABLE = True
except ImportError:
    logger.warning("Config loader not available, using default settings")
    CONFIG_LOADER_AVAILABLE = False

try:
    from scripts.core.security.crypto import encrypt_data, decrypt_data
    CRYPTO_AVAILABLE = True
except ImportError:
    logger.warning("Crypto module not available, credentials will not be encrypted")
    CRYPTO_AVAILABLE = False

try:
    from scripts.core.notification import send_notification
    NOTIFICATION_AVAILABLE = True
except ImportError:
    logger.warning("Notification system not available")
    NOTIFICATION_AVAILABLE = False


# Constants
DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_RETRIES = 3
DEFAULT_RETRY_DELAY = 1  # seconds
DEFAULT_RETRY_BACKOFF_FACTOR = 2
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5  # failures
DEFAULT_CIRCUIT_BREAKER_TIMEOUT = 60  # seconds
DEFAULT_CACHE_TIMEOUT = 300  # seconds
DEFAULT_METRICS_INTERVAL = 300  # seconds
DEFAULT_BILLING_PERIOD = 30  # days
DEFAULT_RESOURCE_LIMIT = 1000  # max resources to return
DEFAULT_CONFIG_PATH = "config/cloud_providers"

# Provider types
class ProviderType(str, Enum):
    """Cloud provider types supported by this module."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    CUSTOM = "custom"


# Resource statuses
class ResourceStatus(str, Enum):
    """Common resource statuses across cloud providers."""
    PENDING = "pending"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    STOPPED = "stopped"
    TERMINATED = "terminated"
    ERROR = "error"
    UNKNOWN = "unknown"


# Resource types
class ResourceType(str, Enum):
    """Common resource types across cloud providers."""
    VM = "vm"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    LOADBALANCER = "loadbalancer"
    QUEUE = "queue"
    CACHE = "cache"
    CUSTOM = "custom"


# Provider operation errors
class ProviderError(Exception):
    """Base exception for provider operations."""
    pass


class AuthenticationError(ProviderError):
    """Exception raised for authentication failures."""
    pass


class ResourceNotFoundError(ProviderError):
    """Exception raised when a resource is not found."""
    pass


class ResourceLimitExceeded(ProviderError):
    """Exception raised when resource limits are exceeded."""
    pass


class ProviderAPIError(ProviderError):
    """Exception raised for provider API errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, provider: Optional[str] = None):
        self.status_code = status_code
        self.provider = provider
        super().__init__(message)


# Circuit breaker implementation if not available from error_handler
if not ERROR_HANDLER_AVAILABLE:
    class CircuitBreaker:
        """Circuit breaker implementation to prevent cascading failures."""

        def __init__(self, name: str, failure_threshold: int = DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
                   recovery_timeout: int = DEFAULT_CIRCUIT_BREAKER_TIMEOUT):
            self.name = name
            self.failure_threshold = failure_threshold
            self.recovery_timeout = recovery_timeout
            self.failures = 0
            self.last_failure_time = None
            self.state = "closed"  # closed, open, half-open
            self._lock = threading.RLock()

        def __call__(self, func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                with self._lock:
                    # Check if circuit is open
                    if self.state == "open":
                        if self.last_failure_time is None or \
                           (datetime.now() - self.last_failure_time).total_seconds() > self.recovery_timeout:
                            # Move to half-open state
                            self.state = "half-open"
                            logger.info(f"Circuit {self.name} moved to half-open state")
                        else:
                            # Circuit is still open, fail fast
                            raise ProviderError(f"Circuit {self.name} is open, failing fast")

                    try:
                        result = func(*args, **kwargs)

                        # If we were in half-open state, success closes the circuit
                        if self.state == "half-open":
                            self.state = "closed"
                            self.failures = 0
                            logger.info(f"Circuit {self.name} closed after successful operation")

                        return result

                    except Exception as e:
                        # Increment failure count
                        self.failures += 1
                        self.last_failure_time = datetime.now()

                        # Check if we should open the circuit
                        if self.failures >= self.failure_threshold:
                            prev_state = self.state
                            self.state = "open"
                            if prev_state != "open":
                                logger.warning(f"Circuit {self.name} opened after {self.failures} failures")

                                if NOTIFICATION_AVAILABLE:
                                    send_notification(
                                        f"Circuit {self.name} opened",
                                        f"Cloud provider circuit breaker {self.name} opened after {self.failures} failures",
                                        priority="high",
                                        category="cloud"
                                    )

                        # Re-raise the exception
                        raise

            return wrapper


# Retry decorator with exponential backoff
def retry_with_backoff(max_retries: int = DEFAULT_RETRIES,
                      initial_delay: float = DEFAULT_RETRY_DELAY,
                      backoff_factor: float = DEFAULT_RETRY_BACKOFF_FACTOR,
                      exceptions: tuple = (ProviderAPIError,)):
    """
    Retry decorator with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries in seconds
        backoff_factor: Backoff factor for delay calculation
        exceptions: Tuple of exceptions to catch and retry

    Returns:
        Function result after successful execution or last exception
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retry_count = 0
            delay = initial_delay
            last_exception = None

            while retry_count < max_retries:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    # Only retry on specified exceptions
                    last_exception = e
                    retry_count += 1

                    # Calculate next delay with exponential backoff and some jitter
                    jitter = (0.8 + 0.4 * (hash(str(args) + str(time.time())) % 100) / 100)
                    next_delay = delay * jitter

                    if retry_count < max_retries:
                        logger.warning(f"Retry {retry_count}/{max_retries} after error: {str(e)}. Waiting {next_delay:.2f}s")
                        time.sleep(next_delay)
                        delay *= backoff_factor
                    else:
                        logger.error(f"Max retries ({max_retries}) exceeded with error: {str(e)}")
                except Exception as e:
                    # Don't retry on other exceptions
                    logger.error(f"Non-retryable error: {str(e)}")
                    raise

            # If we've exhausted retries, re-raise the last exception
            if last_exception:
                raise last_exception
            else:
                raise RuntimeError("Retry attempts exhausted but no exception was captured.")

        return wrapper
    return decorator


class CloudProvider:
    """
    Abstract base class for cloud providers with unified interface.

    This class provides a common interface for interacting with different
    cloud providers, handling authentication, resource management, and operations.
    """

    # Cache for provider instances
    _provider_instances = {}
    _provider_cache_lock = threading.RLock()

    # Cache for resources to reduce API calls
    _resource_cache = {}
    _cache_timestamps = {}

    @classmethod
    def get_provider(cls, provider_type: str, region: Optional[str] = None,
                    credentials: Optional[Dict[str, Any]] = None,
                    config: Optional[Dict[str, Any]] = None) -> 'CloudProvider':
        """
        Factory method to get a provider instance.

        Args:
            provider_type: The cloud provider type (aws, azure, gcp)
            region: Optional region to use
            credentials: Optional credentials to use (if not using default)
            config: Optional configuration parameters

        Returns:
            CloudProvider: An instance of the appropriate provider class

        Raises:
            ProviderError: If the provider type is not supported
        """
        provider_type = provider_type.lower()
        cache_key = f"{provider_type}:{region or 'default'}"

        with cls._provider_cache_lock:
            # Check if we have a cached instance
            if cache_key in cls._provider_instances:
                # Check if we need to refresh credentials
                provider = cls._provider_instances[cache_key]
                if not provider.is_authenticated() and credentials:
                    provider.set_credentials(credentials)
                return provider

            # Create a new provider instance
            if provider_type == ProviderType.AWS:
                from .providers.aws_provider import AWSProvider
                provider = AWSProvider(region=region, credentials=credentials, config=config)
            elif provider_type == ProviderType.AZURE:
                from .providers.azure_provider import AzureProvider
                provider = AzureProvider(region=region, credentials=credentials, config=config)
            elif provider_type == ProviderType.GCP:
                from .providers.gcp_provider import GCPProvider
                provider = GCPProvider(region=region, credentials=credentials, config=config)
            else:
                raise ProviderError(f"Unsupported provider type: {provider_type}")

            # Cache the provider instance
            cls._provider_instances[cache_key] = provider
            return provider

    @classmethod
    def clear_cache(cls, provider_type: Optional[str] = None, region: Optional[str] = None):
        """
        Clear the provider instance cache.

        Args:
            provider_type: Optional provider type to clear
            region: Optional region to clear
        """
        with cls._provider_cache_lock:
            if provider_type and region:
                cache_key = f"{provider_type}:{region}"
                if cache_key in cls._provider_instances:
                    del cls._provider_instances[cache_key]
            elif provider_type:
                # Clear all instances for the provider
                keys_to_remove = [k for k in cls._provider_instances if k.startswith(f"{provider_type}:")]
                for key in keys_to_remove:
                    del cls._provider_instances[key]
            else:
                # Clear all instances
                cls._provider_instances.clear()

            # Clear resource cache as well
            cls._resource_cache.clear()
            cls._cache_timestamps.clear()

    @classmethod
    def list_available_providers(cls) -> List[str]:
        """
        Get a list of available cloud providers.

        Returns:
            List of provider types that can be used
        """
        providers = []

        # Check AWS provider
        try:
            import boto3
            providers.append(ProviderType.AWS)
        except ImportError:
            pass

        # Check Azure provider
        try:
            from azure.identity import DefaultAzureCredential
            providers.append(ProviderType.AZURE)
        except ImportError:
            pass

        # Check GCP provider
        try:
            from google.cloud import storage
            providers.append(ProviderType.GCP)
        except ImportError:
            pass

        return providers

    def __init__(self, provider_type: str, region: Optional[str] = None,
                credentials: Optional[Dict[str, Any]] = None,
                config: Optional[Dict[str, Any]] = None):
        """
        Initialize a cloud provider.

        Args:
            provider_type: The cloud provider type
            region: Optional region to use
            credentials: Optional credentials to use
            config: Optional configuration parameters
        """
        self.provider_type = provider_type
        self.region = region
        self._credentials = credentials
        self._config = config or {}
        self._authenticated = False
        self._last_auth_time = None
        self._auth_expiry = None

        # Load configuration if available
        self._load_configuration()

        # Initialize provider-specific clients
        self._initialize_clients()

    def _load_configuration(self):
        """
        Load provider configuration from config files.
        """
        if CONFIG_LOADER_AVAILABLE:
            try:
                # Try to load provider-specific configuration
                config_file = f"{DEFAULT_CONFIG_PATH}/{self.provider_type}.yaml"
                self._loaded_config = load_config(config_file) or {}

                # Merge with provided config, with provided config taking precedence
                if self._loaded_config:
                    merged_config = dict(self._loaded_config)
                    merged_config.update(self._config)
                    self._config = merged_config

                # Apply environment-specific configuration
                if ENVIRONMENT_AVAILABLE:
                    env = get_current_environment()
                    if env in self._config:
                        # Update with environment-specific settings
                        env_config = self._config[env]
                        for key, value in env_config.items():
                            if key != env:  # Avoid recursion
                                self._config[key] = value

                logger.debug(f"Loaded configuration for provider {self.provider_type}")
            except Exception as e:
                logger.warning(f"Failed to load configuration for provider {self.provider_type}: {e}")

    def _initialize_clients(self):
        """
        Initialize provider-specific clients.

        This method should be implemented by provider-specific classes.
        """
        raise NotImplementedError("Subclasses must implement initialize_clients")

    def is_authenticated(self) -> bool:
        """
        Check if the provider is authenticated.

        Returns:
            True if authenticated, False otherwise
        """
        # Check if authentication has expired
        if self._authenticated and self._auth_expiry:
            if datetime.now() > self._auth_expiry:
                self._authenticated = False

        return self._authenticated

    def authenticate(self) -> bool:
        """
        Authenticate with the provider.

        Returns:
            True if authentication was successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement authenticate")

    def set_credentials(self, credentials: Dict[str, Any]) -> bool:
        """
        Set credentials for the provider.

        Args:
            credentials: The credentials to use

        Returns:
            True if credentials were set successfully, False otherwise
        """
        try:
            # Store credentials securely if crypto is available
            if CRYPTO_AVAILABLE:
                self._credentials = json.loads(decrypt_data(json.dumps(credentials)))
            else:
                self._credentials = credentials

            # Reset authentication state
            self._authenticated = False
            self._last_auth_time = None
            self._auth_expiry = None

            # Try to authenticate with the new credentials
            return self.authenticate()
        except Exception as e:
            logger.error(f"Error setting credentials for {self.provider_type}: {e}")
            if ERROR_HANDLER_AVAILABLE:
                handle_error(e, f"Error setting credentials for {self.provider_type}",
                           category=ErrorCategory.CLOUD)
            return False

    def get_credentials(self) -> Optional[Dict[str, Any]]:
        """
        Get the current credentials.

        Returns:
            The current credentials or None
        """
        return self._credentials

    def get_regions(self) -> List[str]:
        """
        Get available regions for the provider.

        Returns:
            List of region names
        """
        raise NotImplementedError("Subclasses must implement get_regions")

    @retry_with_backoff()
    def list_resources(self, resource_type: str, region: Optional[str] = None,
                      filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        List resources of the specified type.

        Args:
            resource_type: The type of resources to list
            region: Optional region to list resources from
            filters: Optional filters to apply

        Returns:
            List of resources as dictionaries
        """
        raise NotImplementedError("Subclasses must implement list_resources")

    @retry_with_backoff()
    def get_resource(self, resource_id: str, resource_type: str = None,
                   region: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a specific resource by ID.

        Args:
            resource_id: The ID of the resource to get
            resource_type: Optional resource type
            region: Optional region

        Returns:
            Resource details as a dictionary

        Raises:
            ResourceNotFoundError: If the resource is not found
        """
        raise NotImplementedError("Subclasses must implement get_resource")

    @retry_with_backoff(exceptions=(ProviderAPIError, ResourceLimitExceeded))
    def provision_resource(self, resource_type: str, **kwargs) -> Dict[str, Any]:
        """
        Provision a new resource.

        Args:
            resource_type: The type of resource to provision
            **kwargs: Resource-specific parameters

        Returns:
            Details of the provisioned resource

        Raises:
            ProviderAPIError: If the provider API returns an error
            ResourceLimitExceeded: If resource limits are exceeded
        """
        raise NotImplementedError("Subclasses must implement provision_resource")

    @retry_with_backoff()
    def update_resource(self, resource_id: str, resource_type: str = None,
                      region: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Update an existing resource.

        Args:
            resource_id: The ID of the resource to update
            resource_type: Optional resource type
            region: Optional region
            **kwargs: Resource properties to update

        Returns:
            Updated resource details

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement update_resource")

    @retry_with_backoff()
    def delete_resource(self, resource_id: str, resource_type: str = None,
                      region: Optional[str] = None, force: bool = False) -> bool:
        """
        Delete an existing resource.

        Args:
            resource_id: The ID of the resource to delete
            resource_type: Optional resource type
            region: Optional region
            force: Whether to force deletion

        Returns:
            True if the resource was deleted, False otherwise

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement delete_resource")

    @retry_with_backoff()
    def get_resource_status(self, resource_id: str, resource_type: str = None,
                          region: Optional[str] = None) -> str:
        """
        Get the status of a resource.

        Args:
            resource_id: The ID of the resource
            resource_type: Optional resource type
            region: Optional region

        Returns:
            Resource status as a string

        Raises:
            ResourceNotFoundError: If the resource is not found
        """
        resource = self.get_resource(resource_id, resource_type, region)
        return resource.get("status", ResourceStatus.UNKNOWN)

    def wait_for_resource_status(self, resource_id: str, target_status: Union[str, List[str]],
                               resource_type: str = None, region: Optional[str] = None,
                               timeout: int = 300, interval: int = 10) -> bool:
        """
        Wait for a resource to reach the target status.

        Args:
            resource_id: The ID of the resource
            target_status: The target status or list of statuses
            resource_type: Optional resource type
            region: Optional region
            timeout: Maximum time to wait in seconds
            interval: Check interval in seconds

        Returns:
            True if the resource reached the target status, False if timed out

        Raises:
            ResourceNotFoundError: If the resource is not found
        """
        if isinstance(target_status, str):
            target_status = [target_status]

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                status = self.get_resource_status(resource_id, resource_type, region)
                if status in target_status:
                    return True

                logger.debug(f"Resource {resource_id} is in status {status}, waiting for {target_status}")
                time.sleep(interval)
            except ResourceNotFoundError:
                # If we're waiting for the resource to be deleted
                if "terminated" in target_status or "deleted" in target_status:
                    return True
                raise

        logger.warning(f"Timed out waiting for resource {resource_id} to reach status {target_status}")
        return False

    @retry_with_backoff()
    def start_resource(self, resource_id: str, resource_type: str = None,
                     region: Optional[str] = None) -> bool:
        """
        Start a stopped resource.

        Args:
            resource_id: The ID of the resource
            resource_type: Optional resource type
            region: Optional region

        Returns:
            True if the operation was successful, False otherwise

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement start_resource")

    @retry_with_backoff()
    def stop_resource(self, resource_id: str, resource_type: str = None,
                    region: Optional[str] = None, force: bool = False) -> bool:
        """
        Stop a running resource.

        Args:
            resource_id: The ID of the resource
            resource_type: Optional resource type
            region: Optional region
            force: Whether to force stop

        Returns:
            True if the operation was successful, False otherwise

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement stop_resource")

    @retry_with_backoff()
    def restart_resource(self, resource_id: str, resource_type: str = None,
                       region: Optional[str] = None, force: bool = False) -> bool:
        """
        Restart a resource.

        Args:
            resource_id: The ID of the resource
            resource_type: Optional resource type
            region: Optional region
            force: Whether to force restart

        Returns:
            True if the operation was successful, False otherwise

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        # Default implementation: stop then start
        if self.stop_resource(resource_id, resource_type, region, force):
            # Wait for the resource to stop
            self.wait_for_resource_status(resource_id, ResourceStatus.STOPPED, resource_type, region)
            return self.start_resource(resource_id, resource_type, region)
        return False

    @retry_with_backoff()
    def get_resource_metrics(self, resource_id: str, metric_names: Optional[List[str]] = None,
                          start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
                          period: int = 300, resource_type: str = None,
                          region: Optional[str] = None) -> Dict[str, Any]:
        """
        Get metrics for a resource.

        Args:
            resource_id: The ID of the resource
            metric_names: Optional list of metric names to retrieve
            start_time: Optional start time for metrics
            end_time: Optional end time for metrics
            period: Period for metrics in seconds
            resource_type: Optional resource type
            region: Optional region

        Returns:
            Dictionary of metrics

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement get_resource_metrics")

    @retry_with_backoff()
    def get_billing_metrics(self, resource_id: Optional[str] = None,
                          period: Optional[Union[int, str]] = DEFAULT_BILLING_PERIOD,
                          resource_type: Optional[str] = None,
                          region: Optional[str] = None,
                          detailed: bool = False) -> Dict[str, Any]:
        """
        Get billing metrics for resources.

        Args:
            resource_id: Optional resource ID to get metrics for
            period: Period for metrics in days or as a string (e.g., "current-month")
            resource_type: Optional resource type
            region: Optional region
            detailed: Whether to include detailed cost breakdown

        Returns:
            Dictionary of billing metrics

        Raises:
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement get_billing_metrics")

    @retry_with_backoff()
    def create_snapshot(self, resource_id: str, snapshot_name: Optional[str] = None,
                      resource_type: str = None, region: Optional[str] = None,
                      tags: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Create a snapshot of a resource.

        Args:
            resource_id: The ID of the resource
            snapshot_name: Optional name for the snapshot
            resource_type: Optional resource type
            region: Optional region
            tags: Optional tags for the snapshot

        Returns:
            Snapshot details

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement create_snapshot")

    @retry_with_backoff()
    def list_snapshots(self, resource_id: Optional[str] = None,
                     resource_type: Optional[str] = None,
                     region: Optional[str] = None,
                     filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        List available snapshots.

        Args:
            resource_id: Optional resource ID to list snapshots for
            resource_type: Optional resource type
            region: Optional region
            filters: Optional filters to apply

        Returns:
            List of snapshots

        Raises:
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement list_snapshots")

    @retry_with_backoff()
    def restore_snapshot(self, snapshot_id: str, resource_id: Optional[str] = None,
                       new_resource_name: Optional[str] = None,
                       region: Optional[str] = None) -> Dict[str, Any]:
        """
        Restore a resource from a snapshot.

        Args:
            snapshot_id: The ID of the snapshot
            resource_id: Optional resource ID to restore to
            new_resource_name: Optional name for a new resource
            region: Optional region

        Returns:
            Restored resource details

        Raises:
            ResourceNotFoundError: If the snapshot is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement restore_snapshot")

    @retry_with_backoff()
    def get_tags(self, resource_id: str, resource_type: Optional[str] = None,
               region: Optional[str] = None) -> Dict[str, str]:
        """
        Get tags for a resource.

        Args:
            resource_id: The ID of the resource
            resource_type: Optional resource type
            region: Optional region

        Returns:
            Dictionary of tags

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement get_tags")

    @retry_with_backoff()
    def set_tags(self, resource_id: str, tags: Dict[str, str],
               resource_type: Optional[str] = None,
               region: Optional[str] = None) -> bool:
        """
        Set tags for a resource.

        Args:
            resource_id: The ID of the resource
            tags: Dictionary of tags to set
            resource_type: Optional resource type
            region: Optional region

        Returns:
            True if successful, False otherwise

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement set_tags")

    @retry_with_backoff()
    def get_resource_logs(self, resource_id: str, start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None, limit: int = 100,
                        filter_pattern: Optional[str] = None, resource_type: Optional[str] = None,
                        region: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get logs for a resource.

        Args:
            resource_id: The ID of the resource
            start_time: Optional start time for logs
            end_time: Optional end time for logs
            limit: Maximum number of log entries to return
            filter_pattern: Optional filter pattern for logs
            resource_type: Optional resource type
            region: Optional region

        Returns:
            List of log entries

        Raises:
            ResourceNotFoundError: If the resource is not found
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement get_resource_logs")

    @retry_with_backoff()
    def get_resources_by_tag(self, tag_name: str, tag_value: Optional[str] = None,
                           resource_type: Optional[str] = None,
                           region: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find resources by tag.

        Args:
            tag_name: Tag name to search for
            tag_value: Optional tag value to match
            resource_type: Optional resource type to filter by
            region: Optional region to search in

        Returns:
            List of matching resources

        Raises:
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement get_resources_by_tag")

    @retry_with_backoff()
    def get_resource_types(self) -> List[str]:
        """
        Get supported resource types for this provider.

        Returns:
            List of supported resource types
        """
        raise NotImplementedError("Subclasses must implement get_resource_types")

    @retry_with_backoff()
    def get_provider_status(self) -> Dict[str, Any]:
        """
        Get the current status of the provider.

        Returns:
            Dictionary with provider status information
        """
        raise NotImplementedError("Subclasses must implement get_provider_status")

    @retry_with_backoff()
    def execute_action(self, action: str, resource_id: Optional[str] = None,
                     resource_type: Optional[str] = None, region: Optional[str] = None,
                     **kwargs) -> Any:
        """
        Execute a provider-specific action.

        Args:
            action: The action to execute
            resource_id: Optional resource ID
            resource_type: Optional resource type
            region: Optional region
            **kwargs: Action-specific parameters

        Returns:
            Action result, varies by action

        Raises:
            ProviderAPIError: If the provider API returns an error
        """
        raise NotImplementedError("Subclasses must implement execute_action")

    def get_cost_optimization_recommendations(self, resource_type: Optional[str] = None,
                                            region: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get cost optimization recommendations.

        Args:
            resource_type: Optional resource type to get recommendations for
            region: Optional region

        Returns:
            List of recommendations
        """
        raise NotImplementedError("Subclasses must implement get_cost_optimization_recommendations")


# Import specific provider implementations
# These are implemented in separate files to keep this file manageable
#
# AWS Provider: ./providers/aws_provider.py
# Azure Provider: ./providers/azure_provider.py
# GCP Provider: ./providers/gcp_provider.py
#
# The imports are intentionally placed at the end to avoid circular imports


def detect_cloud_provider() -> Optional[str]:
    """
    Auto-detect the current cloud environment.

    Returns:
        Provider type string or None if not detected
    """
    # Check for AWS
    try:
        # Try EC2 metadata service
        response = requests.get("http://169.254.169.254/latest/meta-data/", timeout=0.5)
        if response.status_code == 200:
            return ProviderType.AWS
    except Exception:
        pass

    # Check for Azure
    try:
        # Try Azure Instance Metadata Service
        headers = {"Metadata": "true"}
        response = requests.get("http://169.254.169.254/metadata/instance",
                              headers=headers, params={"api-version": "2021-02-01"}, timeout=0.5)
        if response.status_code == 200:
            return ProviderType.AZURE
    except Exception:
        pass

    # Check for GCP
    try:
        # Try GCP metadata service
        headers = {"Metadata-Flavor": "Google"}
        response = requests.get("http://metadata.google.internal/computeMetadata/v1/",
                              headers=headers, timeout=0.5)
        if response.status_code == 200:
            return ProviderType.GCP
    except Exception:
        pass

    # Fallback to environment variable
    env_provider = os.environ.get("CLOUD_PROVIDER")
    if env_provider:
        return env_provider.lower()

    return None


if __name__ == "__main__":
    """
    Command-line interface for the cloud provider module.

    Usage:
        python -m scripts.core.system.cloud_provider <command> [options]

    Commands:
        detect              - Detect the current cloud environment
        list-providers      - List available provider implementations
        list-regions        - List regions for a provider
        list-resources      - List resources for a provider
        get-resource        - Get details for a specific resource
        get-metrics         - Get metrics for a resource
    """
    import argparse

    parser = argparse.ArgumentParser(description="Cloud Provider Module CLI")
    parser.add_argument("--log-level", default="INFO", help="Set the log level")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Detect command
    detect_parser = subparsers.add_parser("detect", help="Detect current cloud environment")

    # List providers command
    list_providers_parser = subparsers.add_parser("list-providers", help="List available providers")

    # List regions command
    list_regions_parser = subparsers.add_parser("list-regions", help="List regions for a provider")
    list_regions_parser.add_argument("provider", help="Provider type (aws, azure, gcp)")
    list_regions_parser.add_argument("--region", help="Provider region")

    # List resources command
    list_resources_parser = subparsers.add_parser("list-resources", help="List resources for a provider")
    list_resources_parser.add_argument("provider", help="Provider type (aws, azure, gcp)")
    list_resources_parser.add_argument("resource_type", help="Resource type to list")
    list_resources_parser.add_argument("--region", help="Provider region")
    list_resources_parser.add_argument("--filter", help="Filter as JSON string")

    # Get resource command
    get_resource_parser = subparsers.add_parser("get-resource", help="Get resource details")
    get_resource_parser.add_argument("provider", help="Provider type (aws, azure, gcp)")
    get_resource_parser.add_argument("resource_id", help="Resource ID")
    get_resource_parser.add_argument("--resource-type", help="Resource type")
    get_resource_parser.add_argument("--region", help="Provider region")

    # Get metrics command
    get_metrics_parser = subparsers.add_parser("get-metrics", help="Get resource metrics")
    get_metrics_parser.add_argument("provider", help="Provider type (aws, azure, gcp)")
    get_metrics_parser.add_argument("resource_id", help="Resource ID")
    get_metrics_parser.add_argument("--resource-type", help="Resource type")
    get_metrics_parser.add_argument("--region", help="Provider region")
    get_metrics_parser.add_argument("--period", type=int, default=300, help="Metrics period in seconds")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="[%(asctime)s] %(levelname)s: %(message)s"
    )

    if args.command == "detect":
        provider = detect_cloud_provider()
        print(f"Detected cloud provider: {provider or 'None'}")

    elif args.command == "list-providers":
        providers = CloudProvider.list_available_providers()
        print("Available providers:")
        for provider in providers:
            print(f"- {provider}")

    elif args.command == "list-regions":
        try:
            provider = CloudProvider.get_provider(args.provider, region=args.region)
            regions = provider.get_regions()
            print(f"Regions for {args.provider}:")
            for region in regions:
                print(f"- {region}")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "list-resources":
        try:
            provider = CloudProvider.get_provider(args.provider, region=args.region)
            filters = json.loads(args.filter) if args.filter else None
            resources = provider.list_resources(args.resource_type, region=args.region, filters=filters)
            print(f"Resources ({args.resource_type}) for {args.provider}:")
            for resource in resources:
                print(f"- {resource.get('id', 'N/A')}: {resource.get('name', 'N/A')} ({resource.get('status', 'unknown')})")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "get-resource":
        try:
            provider = CloudProvider.get_provider(args.provider, region=args.region)
            resource = provider.get_resource(
                args.resource_id,
                resource_type=args.resource_type,
                region=args.region
            )
            print(f"Resource details for {args.resource_id}:")
            print(json.dumps(resource, indent=2))
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "get-metrics":
        try:
            provider = CloudProvider.get_provider(args.provider, region=args.region)
            metrics = provider.get_resource_metrics(
                args.resource_id,
                resource_type=args.resource_type,
                region=args.region,
                period=args.period
            )
            print(f"Metrics for {args.resource_id}:")
            print(json.dumps(metrics, indent=2))
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    else:
        parser.print_help()
