#!/usr/bin/env python3
"""
Constants for NGINX configuration management scripts.

This module defines common constants used across the NGINX configuration
management scripts for the Cloud Infrastructure Platform.
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple, Set

# Base directories
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
NGINX_ROOT = Path("/etc/nginx")

# Configuration directories
SITES_AVAILABLE = NGINX_ROOT / "sites-available"
SITES_ENABLED = NGINX_ROOT / "sites-enabled"
CONF_DIR = NGINX_ROOT / "conf.d"
INCLUDES_DIR = NGINX_ROOT / "includes"
BACKUP_DIR = Path("/var/backups/nginx-configs")

# Environment constants
ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]
DEFAULT_ENVIRONMENT = "production"

# File extensions
CONFIG_EXTENSIONS = [".env", ".json", ".yaml", ".yml"]
TEMPLATE_EXTENSION = ".template"
CONF_EXTENSION = ".conf"

# Security constants
REQUIRED_SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy"
]

SECURE_SSL_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]
INSECURE_SSL_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]

# Certificate default locations
CERT_DIR = Path("/etc/ssl/certs")
KEY_DIR = Path("/etc/ssl/private")
DHPARAM_FILE = NGINX_ROOT / "dhparams.pem"

# ModSecurity paths
MODSEC_DIR = NGINX_ROOT / "modsecurity"
CRS_DIR = MODSEC_DIR / "owasp-crs"
WAF_RULES_DIR = MODSEC_DIR / "rules"

# Performance defaults
DEFAULT_WORKER_PROCESSES = "auto"
DEFAULT_WORKER_CONNECTIONS = 1024
DEFAULT_KEEPALIVE_TIMEOUT = 65
DEFAULT_KEEPALIVE_REQUESTS = 1000
DEFAULT_CLIENT_BODY_BUFFER_SIZE = "16k"

# Environment-specific overrides
ENVIRONMENT_SETTINGS: Dict[str, Dict[str, str]] = {
    "development": {
        "CACHE_CONTROL": "no-cache",
        "KEEPALIVE_TIMEOUT": "120",
        "LOG_LEVEL": "debug",
        "RATE_LIMIT": "20r/s",
        "WORKER_PROCESSES": "1"
    },
    "staging": {
        "CACHE_CONTROL": "public, max-age=3600",
        "KEEPALIVE_TIMEOUT": "65",
        "LOG_LEVEL": "info",
        "RATE_LIMIT": "30r/s",
        "WORKER_PROCESSES": "auto"
    },
    "production": {
        "CACHE_CONTROL": "public, max-age=86400",
        "KEEPALIVE_TIMEOUT": "65",
        "LOG_LEVEL": "warn",
        "RATE_LIMIT": "10r/s",
        "WORKER_PROCESSES": "auto"
    },
    "dr-recovery": {
        "CACHE_CONTROL": "no-store",
        "KEEPALIVE_TIMEOUT": "30",
        "LOG_LEVEL": "warn",
        "RATE_LIMIT": "5r/s",
        "WORKER_PROCESSES": "auto"
    }
}

# Default SSL parameters
DEFAULT_SSL_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
)

# Template defaults
DEFAULT_TEMPLATES_DIR = "../templates"
DEFAULT_OUTPUT_DIR = "../sites-available"
DEFAULT_CONFIG_DIR = "../../environments"
DEFAULT_INCLUDES_DIR = "../includes"
DEFAULT_CONFD_DIR = "../conf.d"

# Rate limiting defaults
DEFAULT_RATE_LIMIT = "10r/s"
DEFAULT_RATE_LIMIT_BURST = "20"
DEFAULT_AUTH_RATE_LIMIT = "5r/s"
DEFAULT_AUTH_RATE_LIMIT_BURST = "10"

# Sensitive configuration variables that require validation
SENSITIVE_VARIABLES = [
    "DOMAIN_NAME",
    "SSL_CERTIFICATE_PATH",
    "SSL_KEY_PATH"
]

# Exit codes
EXIT_CODE_SUCCESS = 0
EXIT_CODE_ERROR = 1
EXIT_CODE_WARNING = 2

# Script names
SCRIPT_GENERATE_CONFIG = "generate_config.py"
SCRIPT_INSTALL_CONFIGS = "install_configs.py"
SCRIPT_TEST_CONFIG = "test_config.py"
SCRIPT_NGINX_RELOAD = "nginx-reload.sh"
SCRIPT_PERFORMANCE = "performance.sh"
SCRIPT_SETUP_SSL = "setup-ssl.sh"
SCRIPT_SETUP_MODSECURITY = "setup-modsecurity.sh"

# Log formats
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Version info
__version__ = "1.0.0"
__author__ = "Cloud Infrastructure Platform Team"
