#!/usr/bin/env python3
# filepath: scripts/core/system/init.py
"""
System Module Initialization

This module provides centralized initialization for the system components in the
Cloud Infrastructure Platform. It handles component startup, dependency resolution,
and configuration loading for all system-related functionality.

The initialization sequence ensures that all system components are properly
configured at runtime, with appropriate fallbacks and graceful degradation when
dependencies are unavailable. It implements environment-specific configurations
and properly integrates with the platform's core logging, error handling, and
notification systems.

Key features:
- Component dependency resolution
- Cloud provider initialization
- Resource monitoring setup
- System information collection configuration
- Cross-platform compatibility handling
- Component status tracking
- Environment-specific configuration
"""

import os
import sys
import logging
import argparse
import psutil
import requests
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union, Any

# Ensure the scripts package is in path for imports
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

# Component availability tracking
CLOUD_PROVIDER_AVAILABLE = False
RESOURCE_MONITOR_AVAILABLE = False
SYSTEM_INFO_AVAILABLE = False
CORE_LOGGER_AVAILABLE = False
ERROR_HANDLER_AVAILABLE = False
CONFIG_LOADER_AVAILABLE = False
ENVIRONMENT_AVAILABLE = False
NOTIFICATION_AVAILABLE = False
CRYPTO_AVAILABLE = False

# Default configurations
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_CONFIG_PATH = "config/system"
DEFAULT_SYSTEM_CONFIG_FILE = "system.yaml"
DEFAULT_METRICS_DIR = "/var/lib/cloud-platform/metrics"
SYSTEM_LOG_FILE = "/var/log/cloud-platform/system.log"

# Initialize minimal logger for bootstrapping
logger = logging.getLogger("system.init")


def setup_minimal_logging(level: str = DEFAULT_LOG_LEVEL) -> None:
    """
    Set up minimal logging before core logger is available.

    Args:
        level: Log level to use
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout
    )
    logger.setLevel(log_level)


def initialize_system_components(
    log_level: str = DEFAULT_LOG_LEVEL,
    config_path: Optional[str] = None,
    skip_unavailable: bool = True
) -> Tuple[bool, List[str]]:
    """
    Initialize all system components with appropriate dependency resolution.

    Args:
        log_level: Logging level
        config_path: Optional path to configuration directory
        skip_unavailable: Whether to continue if some components are unavailable

    Returns:
        Tuple of (success, list_of_errors)
    """
    global CLOUD_PROVIDER_AVAILABLE, RESOURCE_MONITOR_AVAILABLE, SYSTEM_INFO_AVAILABLE
    global CORE_LOGGER_AVAILABLE, ERROR_HANDLER_AVAILABLE, CONFIG_LOADER_AVAILABLE
    global ENVIRONMENT_AVAILABLE, NOTIFICATION_AVAILABLE, CRYPTO_AVAILABLE

    errors = []

    # Set up minimal logging for initialization
    setup_minimal_logging(log_level)

    logger.info(f"Initializing system components (log level: {log_level})")

    # Step 1: Initialize core logger if available
    try:
        from scripts.core.logger import Logger, setup_logging
        setup_logging(level=log_level)
        CORE_LOGGER_AVAILABLE = True
        logger.debug("Core logger initialized")
    except ImportError as e:
        errors.append(f"Failed to import core logger: {e}")
        logger.warning(f"Core logger import failed: {e}")

    # Step 2: Initialize environment if available
    if CORE_LOGGER_AVAILABLE:
        try:
            from scripts.core.environment import get_current_environment, Environment
            environment = get_current_environment()
            ENVIRONMENT_AVAILABLE = True
            logger.debug(f"Environment module initialized: {environment}")
        except ImportError as e:
            errors.append(f"Failed to import environment module: {e}")
            logger.warning(f"Environment module import failed: {e}")

    # Step 3: Initialize config loader if available
    if CORE_LOGGER_AVAILABLE:
        try:
            from scripts.core.config_loader import load_config, ConfigLoader
            config_file = os.path.join(config_path or DEFAULT_CONFIG_PATH, DEFAULT_SYSTEM_CONFIG_FILE)
            CONFIG_LOADER_AVAILABLE = True
            logger.debug(f"Config loader initialized (config: {config_file})")
        except ImportError as e:
            errors.append(f"Failed to import config_loader module: {e}")
            logger.warning(f"Config loader module import failed: {e}")

    # Step 4: Initialize error handler if available
    if CORE_LOGGER_AVAILABLE:
        try:
            from scripts.core.error_handler import handle_error, ErrorCategory
            ERROR_HANDLER_AVAILABLE = True
            logger.debug("Error handler initialized")
        except ImportError as e:
            errors.append(f"Failed to import error_handler module: {e}")
            logger.warning(f"Error handler import failed: {e}")

    # Step 5: Initialize notification system if available
    if CORE_LOGGER_AVAILABLE and CONFIG_LOADER_AVAILABLE:
        try:
            from scripts.core.notification import send_notification
            NOTIFICATION_AVAILABLE = True
            logger.debug("Notification system initialized")
        except ImportError as e:
            errors.append(f"Failed to import notification module: {e}")
            logger.warning(f"Notification system import failed: {e}")

    # Step 6: Initialize crypto module if available (for secure credentials)
    if CORE_LOGGER_AVAILABLE and ERROR_HANDLER_AVAILABLE:
        try:
            from scripts.core.security.crypto import encrypt_data, decrypt_data
            CRYPTO_AVAILABLE = True
            logger.debug("Crypto module initialized")
        except ImportError as e:
            errors.append(f"Failed to import crypto module: {e}")
            logger.warning(f"Crypto module import failed, secure credential handling unavailable: {e}")

    # Step 7: Initialize system_info module
    try:
        from scripts.core.system.system_info import SystemInfo

        # Create system info instance with default settings
        system_config = {}
        if CONFIG_LOADER_AVAILABLE:
            try:
                system_config = load_config(os.path.join(DEFAULT_CONFIG_PATH, "system_info.yaml")) or {}
            except Exception as e:
                logger.warning(f"Failed to load system_info configuration: {e}")

        # Initialize system info
        SYSTEM_INFO_AVAILABLE = True
        logger.info("System info module initialized")
    except ImportError as e:
        error_msg = f"Failed to import system_info module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if not skip_unavailable:
            return (False, errors)
    except Exception as e:
        error_msg = f"Failed to initialize system_info module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            from scripts.core.error_handler import ErrorCategory
            handle_error(e, category=ErrorCategory.SYSTEM)
        if not skip_unavailable:
            return (False, errors)

    # Step 8: Initialize resource_monitor module
    try:
        from scripts.core.system.resource_monitor import ResourceMonitor

        # Load resource monitor configuration if available
        monitor_config = {}
        if CONFIG_LOADER_AVAILABLE:
            try:
                monitor_config = load_config(os.path.join(DEFAULT_CONFIG_PATH, "resource_monitor.yaml")) or {}

                # Create metrics directory if it doesn't exist
                metrics_dir = monitor_config.get("METRICS_DIR", DEFAULT_METRICS_DIR)
                if not os.path.exists(metrics_dir):
                    os.makedirs(metrics_dir, exist_ok=True)
                    logger.info(f"Created metrics directory: {metrics_dir}")
            except Exception as e:
                logger.warning(f"Failed to load resource_monitor configuration: {e}")

        RESOURCE_MONITOR_AVAILABLE = True
        logger.info("Resource monitor module initialized")
    except ImportError as e:
        error_msg = f"Failed to import resource_monitor module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if not skip_unavailable:
            return (False, errors)
    except Exception as e:
        error_msg = f"Failed to initialize resource_monitor module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            from scripts.core.error_handler import ErrorCategory
            handle_error(e, category=ErrorCategory.SYSTEM)
        if not skip_unavailable:
            return (False, errors)

    # Step 9: Initialize cloud_provider module
    try:
        from scripts.core.system.cloud_provider import CloudProvider

        # Load cloud provider configuration if available
        provider_config = {}
        if CONFIG_LOADER_AVAILABLE:
            try:
                provider_config = load_config(os.path.join(DEFAULT_CONFIG_PATH, "cloud_provider.yaml")) or {}
            except Exception as e:
                logger.warning(f"Failed to load cloud_provider configuration: {e}")

        # Initialize cloud providers
        if ENVIRONMENT_AVAILABLE and CONFIG_LOADER_AVAILABLE:
            # Initialize appropriate providers based on environment
            from scripts.core.environment import is_production, is_staging, is_development

            # Initialize providers differently based on environment
            if is_production():
                logger.info("Initializing cloud providers for production environment")
                # Production typically has more restricted permissions and uses IAM roles
            elif is_staging():
                logger.info("Initializing cloud providers for staging environment")
                # Staging uses test accounts with limited resources
            else:
                logger.info("Initializing cloud providers for development environment")
                # Development may use local emulators or sandboxed environments

        CLOUD_PROVIDER_AVAILABLE = True
        logger.info("Cloud provider module initialized")
    except ImportError as e:
        error_msg = f"Failed to import cloud_provider module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if not skip_unavailable:
            return (False, errors)
    except Exception as e:
        error_msg = f"Failed to initialize cloud_provider module: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            from scripts.core.error_handler import ErrorCategory
            handle_error(e, category=ErrorCategory.CLOUD_PROVIDER)
        if not skip_unavailable:
            return (False, errors)

    # Return the initialization status
    success = (len(errors) == 0)

    # Log initialization result
    if success:
        logger.info("All system components initialized successfully")
        if NOTIFICATION_AVAILABLE:
            from scripts.core.notification import send_notification
            try:
                send_notification(
                    "System Module Initialized",
                    "All system components successfully initialized",
                    priority="low",
                    category="system"
                )
            except Exception as e:
                logger.warning(f"Failed to send initialization notification: {e}")
    else:
        logger.warning(f"Some system components failed to initialize ({len(errors)} errors)")

    return (success, errors)


def get_system_component_status() -> Dict[str, bool]:
    """
    Get availability status of all system components.

    Returns:
        Dictionary mapping component names to availability status
    """
    return {
        "cloud_provider": CLOUD_PROVIDER_AVAILABLE,
        "resource_monitor": RESOURCE_MONITOR_AVAILABLE,
        "system_info": SYSTEM_INFO_AVAILABLE,
        "core_logger": CORE_LOGGER_AVAILABLE,
        "error_handler": ERROR_HANDLER_AVAILABLE,
        "config_loader": CONFIG_LOADER_AVAILABLE,
        "environment": ENVIRONMENT_AVAILABLE,
        "notification": NOTIFICATION_AVAILABLE,
        "crypto": CRYPTO_AVAILABLE
    }


def verify_system_prerequisites() -> Dict[str, Dict[str, Any]]:
    """
    Verify that all system prerequisites are met.

    Returns:
        Dictionary of verification results by component category
    """
    results = {
        "dependencies": {"status": False, "issues": [], "passed": []},
        "configuration": {"status": False, "issues": [], "passed": []},
        "permissions": {"status": False, "issues": [], "passed": []},
        "connectivity": {"status": False, "issues": [], "passed": []},
    }

    # Check dependencies
    try:
        # Check Python version
        import platform
        py_version = platform.python_version_tuple()
        if int(py_version[0]) < 3 or (int(py_version[0]) == 3 and int(py_version[1]) < 6):
            results["dependencies"]["issues"].append(f"Python version too old: {platform.python_version()}, need 3.6+")
        else:
            results["dependencies"]["passed"].append(f"Python version: {platform.python_version()}")

        # Check for required modules
        required_modules = [
            "json", "yaml", "psutil", "requests", "cryptography", "datetime",
            "socket", "subprocess", "threading"
        ]

        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
                results["dependencies"]["passed"].append(f"Module present: {module}")
            except ImportError:
                missing_modules.append(module)

        if missing_modules:
            results["dependencies"]["issues"].append(f"Missing modules: {', '.join(missing_modules)}")

        # Set status based on issues
        results["dependencies"]["status"] = len(results["dependencies"]["issues"]) == 0
    except Exception as e:
        results["dependencies"]["issues"].append(f"Error checking dependencies: {e}")

    # Check configuration
    try:
        if CONFIG_LOADER_AVAILABLE:
            from scripts.core.config_loader import load_config, ConfigError

            # Check main system configuration
            try:
                config = load_config(os.path.join(DEFAULT_CONFIG_PATH, DEFAULT_SYSTEM_CONFIG_FILE))
                if config:
                    results["configuration"]["passed"].append("Main system configuration loaded")
                else:
                    results["configuration"]["issues"].append("Main system configuration empty or not found")
            except ConfigError as e:
                results["configuration"]["issues"].append(f"Error loading system configuration: {e}")

            # Check component configurations
            for component in ["system_info", "resource_monitor", "cloud_provider"]:
                try:
                    config = load_config(os.path.join(DEFAULT_CONFIG_PATH, f"{component}.yaml"))
                    if config:
                        results["configuration"]["passed"].append(f"{component} configuration loaded")
                    else:
                        results["configuration"]["issues"].append(f"{component} configuration empty or not found")
                except ConfigError:
                    # Skip if config file doesn't exist - might be optional
                    pass
                except Exception as e:
                    results["configuration"]["issues"].append(f"Error loading {component} configuration: {e}")
        else:
            results["configuration"]["issues"].append("Configuration loader not available")

        # Set status based on issues
        results["configuration"]["status"] = len(results["configuration"]["issues"]) == 0
    except Exception as e:
        results["configuration"]["issues"].append(f"Error checking configuration: {e}")

    # Check permissions
    try:
        # Check metrics directory
        metrics_dir = DEFAULT_METRICS_DIR
        if CONFIG_LOADER_AVAILABLE:
            from scripts.core.config_loader import load_config
            try:
                config = load_config(os.path.join(DEFAULT_CONFIG_PATH, "resource_monitor.yaml"))
                if config:
                    metrics_dir = config.get("METRICS_DIR", DEFAULT_METRICS_DIR)
            except Exception:
                pass

        # Check write access to metrics directory
        try:
            if not os.path.exists(metrics_dir):
                try:
                    os.makedirs(metrics_dir, exist_ok=True)
                    results["permissions"]["passed"].append(f"Created metrics directory: {metrics_dir}")
                except PermissionError:
                    results["permissions"]["issues"].append(f"Cannot create metrics directory: {metrics_dir}")
                except Exception as e:
                    results["permissions"]["issues"].append(f"Error creating metrics directory: {e}")
            else:
                # Try to write a test file
                test_file = os.path.join(metrics_dir, ".test_write_permission")
                try:
                    with open(test_file, "w") as f:
                        f.write("test")
                    os.remove(test_file)
                    results["permissions"]["passed"].append(f"Write access to metrics directory: {metrics_dir}")
                except PermissionError:
                    results["permissions"]["issues"].append(f"No write access to metrics directory: {metrics_dir}")
                except Exception as e:
                    results["permissions"]["issues"].append(f"Error testing write access: {e}")
        except Exception as e:
            results["permissions"]["issues"].append(f"Error checking metrics directory: {e}")

        # Check if we can read system information
        try:
            # Basic system info checks
            psutil.cpu_percent()
            psutil.virtual_memory()
            psutil.disk_usage('/')
            results["permissions"]["passed"].append("Can read system information via psutil")
        except ImportError:
            results["permissions"]["issues"].append("psutil module not available")
        except Exception as e:
            results["permissions"]["issues"].append(f"Cannot read system information: {e}")

        # Set status based on issues
        results["permissions"]["status"] = len(results["permissions"]["issues"]) == 0
    except Exception as e:
        results["permissions"]["issues"].append(f"Error checking permissions: {e}")

    # Check connectivity
    try:
        import socket
        from urllib3.exceptions import InsecureRequestWarning
        import urllib3

        # Suppress only the single InsecureRequestWarning
        urllib3.disable_warnings(InsecureRequestWarning)

        # Test internet connectivity (needed for cloud providers)
        try:
            # Try to resolve DNS
            socket.gethostbyname("www.google.com")
            results["connectivity"]["passed"].append("DNS resolution working")
        except socket.gaierror:
            results["connectivity"]["issues"].append("Cannot resolve DNS names")
        except Exception as e:
            results["connectivity"]["issues"].append(f"DNS error: {e}")

        # Test HTTPS connectivity
        try:
            requests.get("https://www.google.com", timeout=5, verify=False)
            results["connectivity"]["passed"].append("HTTPS connectivity working")
        except requests.exceptions.RequestException as e:
            results["connectivity"]["issues"].append(f"HTTPS connectivity failed: {e}")

        # Test cloud provider endpoints if module available
        if CLOUD_PROVIDER_AVAILABLE:
            from scripts.core.system.cloud_provider import CloudProvider

            # Test AWS connectivity
            try:
                CloudProvider.test_connectivity("aws")
                results["connectivity"]["passed"].append("AWS connectivity working")
            except Exception as e:
                results["connectivity"]["issues"].append(f"AWS connectivity failed: {e}")

            # Test Azure connectivity
            try:
                CloudProvider.test_connectivity("azure")
                results["connectivity"]["passed"].append("Azure connectivity working")
            except Exception as e:
                results["connectivity"]["issues"].append(f"Azure connectivity failed: {e}")

            # Test GCP connectivity
            try:
                CloudProvider.test_connectivity("gcp")
                results["connectivity"]["passed"].append("GCP connectivity working")
            except Exception as e:
                results["connectivity"]["issues"].append(f"GCP connectivity failed: {e}")

        # Set status based on issues
        results["connectivity"]["status"] = len(results["connectivity"]["issues"]) == 0
    except Exception as e:
        results["connectivity"]["issues"].append(f"Error checking connectivity: {e}")

    return results


def setup_system_cli_parser() -> argparse.ArgumentParser:
    """
    Set up command-line argument parser for the system initialization script.

    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(description="System Module Initialization")

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=DEFAULT_LOG_LEVEL,
        help="Set the logging level"
    )

    parser.add_argument(
        "--config-path",
        default=DEFAULT_CONFIG_PATH,
        help="Path to the configuration directory"
    )

    parser.add_argument(
        "--skip-unavailable",
        action="store_true",
        help="Skip initialization of unavailable components"
    )

    parser.add_argument(
        "--check-prerequisites",
        action="store_true",
        help="Check system prerequisites"
    )

    parser.add_argument(
        "--status",
        action="store_true",
        help="Print status of system components"
    )

    return parser


def main() -> int:
    """
    Main entry point for system module initialization.

    Returns:
        Exit code: 0 for success, 1 for errors
    """
    parser = setup_system_cli_parser()
    args = parser.parse_args()

    # Set up logging
    setup_minimal_logging(args.log_level)

    # Check prerequisites if requested
    if args.check_prerequisites:
        prereq_results = verify_system_prerequisites()
        print("System Prerequisites Check:")
        all_ok = True

        for category, result in prereq_results.items():
            status_str = "✅ PASS" if result["status"] else "❌ FAIL"
            print(f"{category.upper()}: {status_str}")

            if result["issues"]:
                print("  Issues:")
                for issue in result["issues"]:
                    print(f"  - {issue}")
                all_ok = False

            if result["passed"]:
                print("  Passed:")
                for passed in result["passed"]:
                    print(f"  - {passed}")

            print()

        return 0 if all_ok else 1

    # Print component status if requested
    if args.status:
        status = get_system_component_status()
        print("System Component Status:")
        for component, available in status.items():
            status_str = "✅ Available" if available else "❌ Unavailable"
            print(f"{component}: {status_str}")

        all_available = all(status.values())
        return 0 if all_available else 1

    # Initialize system components
    success, errors = initialize_system_components(
        log_level=args.log_level,
        config_path=args.config_path,
        skip_unavailable=args.skip_unavailable
    )

    # Print errors if any
    if errors:
        print("System initialization errors:")
        for error in errors:
            print(f"  - {error}")

    # Return appropriate exit code
    return 0 if success else 1


# Initialize the module when imported
if __name__ != "__main__":
    setup_minimal_logging()
    status = get_system_component_status()
    if not any(status.values()):
        # Only initialize automatically if no components are initialized yet
        initialize_system_components(skip_unavailable=True)


# Run main function if called directly
if __name__ == "__main__":
    sys.exit(main())
