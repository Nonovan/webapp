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
    from .nginx_reload import (
        reload_nginx, restart_nginx, backup_config, test_config, verify_nginx_responding,
        check_config_changes, check_nginx_installed, check_nginx_running,
        check_ssl_certs, check_nginx_status
    )
except ImportError as e:
    logger.debug(f"Could not import nginx_reload module: {e}")

try:
    from .install_configs import (
        install_config_files, backup_config as backup_install_config,
        generate_config, copy_file, create_symlink, ensure_directory,
        install_environment_config, test_config as install_test_config
    )
except ImportError as e:
    logger.debug(f"Could not import install_configs module: {e}")

try:
    from .setup_modsecurity import (
        install_owasp_crs, install_custom_waf_rules, create_modsec_config,
        enable_modsecurity, disable_modsecurity, check_modsec_installed,
        check_modsec_enabled, create_status_page, configure_logrotate,
        setup_modsecurity, test_nginx_config
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
        check_https_redirect, check_custom_log_format, generate_report,
        find_config_files, check_ssl_protocols, check_server_tokens, check_rate_limiting,
        check_dh_parameters, check_client_certificate_validation, test_basic_syntax,
        get_nginx_version
    )
except ImportError as e:
    logger.debug(f"Could not import test_config module: {e}")

try:
    from .create_dhparams import (
        generate_dhparams, check_existing_params, update_ssl_params,
        update_ssl_conf, test_nginx_config as dhparams_test_nginx
    )
except ImportError as e:
    logger.debug(f"Could not import create_dhparams module: {e}")

try:
    from .nginx_constants import (
        ENVIRONMENT_SETTINGS, DEFAULT_SSL_CIPHERS, REQUIRED_SECURITY_HEADERS,
        SECURE_SSL_PROTOCOLS, INSECURE_SSL_PROTOCOLS, DEFAULT_TEMPLATES_DIR,
        DEFAULT_OUTPUT_DIR, DEFAULT_CONFIG_DIR, DEFAULT_INCLUDES_DIR,
        DEFAULT_CONFD_DIR, DEFAULT_RATE_LIMIT, DEFAULT_RATE_LIMIT_BURST,
        DEFAULT_AUTH_RATE_LIMIT, DEFAULT_AUTH_RATE_LIMIT_BURST, SENSITIVE_VARIABLES,
        CERT_DIR, KEY_DIR, DHPARAM_FILE
    )
except ImportError as e:
    logger.debug(f"Could not import nginx_constants module: {e}")

try:
    from .setup_ssl import (
        create_self_signed_cert, create_letsencrypt_cert, import_certificates,
        configure_ssl, verify_certificate, reload_nginx as ssl_reload_nginx,
        setup_server_block, backup_certificates, handle_existing_certificates
    )
except ImportError as e:
    logger.debug(f"Could not import setup_ssl module: {e}")

try:
    from .generate_config import (
        load_environment_config, create_template_context, validate_context,
        render_template, process_templates, setup_includes, validate_nginx_config,
        verify_environment_templates
    )
except ImportError as e:
    logger.debug(f"Could not import generate_config module: {e}")

# Constants
NGINX_ROOT = "/etc/nginx"
DEFAULT_BACKUP_DIR = "/var/backups/nginx-configs"
ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]

# Package metadata
__version__ = "0.1.1"
__author__ = "Cloud Infrastructure Platform Team"

# Define what is available for import from this package
__all__ = [
    # Core NGINX utilities
    "reload_nginx",
    "restart_nginx",
    "backup_config",
    "test_config",
    "verify_nginx_responding",
    "check_config_changes",
    "check_nginx_installed",
    "check_nginx_running",
    "check_ssl_certs",
    "check_nginx_status",

    # Installation utilities
    "install_config_files",
    "install_environment_config",
    "generate_config",
    "copy_file",
    "create_symlink",
    "ensure_directory",
    "backup_install_config",
    "install_test_config",

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
    "setup_modsecurity",
    "test_nginx_config",

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
    "find_config_files",
    "check_ssl_protocols",
    "check_server_tokens",
    "check_rate_limiting",
    "check_dh_parameters",
    "check_client_certificate_validation",
    "test_basic_syntax",
    "get_nginx_version",

    # SSL utilities
    "generate_dhparams",
    "check_existing_params",
    "update_ssl_params",
    "update_ssl_conf",
    "dhparams_test_nginx",
    "create_self_signed_cert",
    "create_letsencrypt_cert",
    "import_certificates",
    "configure_ssl",
    "verify_certificate",
    "ssl_reload_nginx",
    "setup_server_block",
    "backup_certificates",
    "handle_existing_certificates",

    # Configuration generation utilities
    "load_environment_config",
    "create_template_context",
    "validate_context",
    "render_template",
    "process_templates",
    "setup_includes",
    "validate_nginx_config",
    "verify_environment_templates",

    # Configuration constants
    "ENVIRONMENT_SETTINGS",
    "DEFAULT_SSL_CIPHERS",
    "REQUIRED_SECURITY_HEADERS",
    "SECURE_SSL_PROTOCOLS",
    "INSECURE_SSL_PROTOCOLS",
    "DEFAULT_TEMPLATES_DIR",
    "DEFAULT_OUTPUT_DIR",
    "DEFAULT_CONFIG_DIR",
    "DEFAULT_INCLUDES_DIR",
    "DEFAULT_CONFD_DIR",
    "DEFAULT_RATE_LIMIT",
    "DEFAULT_RATE_LIMIT_BURST",
    "DEFAULT_AUTH_RATE_LIMIT",
    "DEFAULT_AUTH_RATE_LIMIT_BURST",
    "SENSITIVE_VARIABLES",
    "CERT_DIR",
    "KEY_DIR",
    "DHPARAM_FILE",

    # Constants
    "NGINX_ROOT",
    "DEFAULT_BACKUP_DIR",
    "ENVIRONMENTS",
    "__version__",
    "__author__"
]
