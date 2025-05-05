"""
NGINX Script Utilities for Cloud Infrastructure Platform.

This package provides utilities for installing, configuring, testing, and managing
NGINX web server configurations for the Cloud Infrastructure Platform. It supports
environment-specific configurations, security hardening, performance optimization,
and safe configuration updates.
"""

import os
import logging
from typing import Dict, Any, List, Optional

# Get logger for this package
logger = logging.getLogger(__name__)

# Try to import the modules to expose their functions
try:
    from .nginx_reload import reload_nginx, restart_nginx, backup_config, test_config, verify_nginx_responding
except ImportError as e:
    logger.debug(f"Could not import nginx_reload module: {e}")

try:
    from .install_configs import (
        install_config_files, backup_config as backup_install_config,
        generate_config, copy_file, create_symlink, ensure_directory,
        install_environment_config
    )
except ImportError as e:
    logger.debug(f"Could not import install_configs module: {e}")

try:
    from .setup_modsecurity import (
        install_owasp_crs, install_custom_waf_rules, create_modsec_config,
        enable_modsecurity, disable_modsecurity, check_modsec_installed,
        check_modsec_enabled, create_status_page, configure_logrotate
    )
except ImportError as e:
    logger.debug(f"Could not import setup_modsecurity module: {e}")

try:
    from .performance import (
        get_cpu_count, get_total_memory, calculate_worker_processes,
        calculate_worker_connections, calculate_client_body_buffer_size,
        calculate_keepalive_settings, generate_performance_config,
        check_current_config, apply_performance_settings
    )
except ImportError as e:
    logger.debug(f"Could not import performance module: {e}")

try:
    from .test_config import (
        validate_nginx_installation, check_ssl_certificates, check_security_headers,
        check_security_configs, check_environment_configs, check_modsecurity_waf,
        check_https_redirect, check_custom_log_format, generate_report
    )
except ImportError as e:
    logger.debug(f"Could not import test_config module: {e}")

try:
    from .create_dhparams import generate_dhparams, check_existing_params
except ImportError as e:
    logger.debug(f"Could not import create_dhparams module: {e}")

try:
    from .nginx_constants import (
        ENVIRONMENT_SETTINGS, DEFAULT_SSL_CIPHERS, REQUIRED_SECURITY_HEADERS,
        SECURE_SSL_PROTOCOLS, INSECURE_SSL_PROTOCOLS
    )
except ImportError as e:
    logger.debug(f"Could not import nginx_constants module: {e}")

# Constants
NGINX_ROOT = "/etc/nginx"
DEFAULT_BACKUP_DIR = "/var/backups/nginx-configs"
ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]

# Package metadata
__version__ = "1.0.0"
__author__ = "Cloud Infrastructure Platform Team"

# Define what is available for import from this package
__all__ = [
    # Core NGINX utilities
    "reload_nginx",
    "restart_nginx",
    "backup_config",
    "test_config",
    "verify_nginx_responding",

    # Installation utilities
    "install_config_files",
    "install_environment_config",
    "generate_config",
    "copy_file",
    "create_symlink",
    "ensure_directory",

    # ModSecurity WAF utilities
    "install_owasp_crs",
    "install_custom_waf_rules",
    "create_modsec_config",
    "enable_modsecurity",
    "disable_modsecurity",
    "check_modsec_installed",
    "check_modsec_enabled",
    "create_status_page",
    "configure_logrotate",

    # Performance optimization utilities
    "get_cpu_count",
    "get_total_memory",
    "calculate_worker_processes",
    "calculate_worker_connections",
    "calculate_client_body_buffer_size",
    "calculate_keepalive_settings",
    "generate_performance_config",
    "check_current_config",
    "apply_performance_settings",

    # Configuration testing utilities
    "validate_nginx_installation",
    "check_ssl_certificates",
    "check_security_headers",
    "check_security_configs",
    "check_environment_configs",
    "check_modsecurity_waf",
    "check_https_redirect",
    "check_custom_log_format",
    "generate_report",

    # SSL utilities
    "generate_dhparams",
    "check_existing_params",

    # Configuration constants
    "ENVIRONMENT_SETTINGS",
    "DEFAULT_SSL_CIPHERS",
    "REQUIRED_SECURITY_HEADERS",
    "SECURE_SSL_PROTOCOLS",
    "INSECURE_SSL_PROTOCOLS",

    # Constants
    "NGINX_ROOT",
    "DEFAULT_BACKUP_DIR",
    "ENVIRONMENTS",
    "__version__",
    "__author__"
]
