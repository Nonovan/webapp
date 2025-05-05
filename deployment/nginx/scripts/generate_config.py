#!/usr/bin/env python3
"""
Generate NGINX configuration files from templates for Cloud Infrastructure Platform.

This script generates environment-specific NGINX configuration files using templates
in the templates directory and environment-specific settings.
"""

import os
import sys
import json
import argparse
import shutil
import logging
from datetime import datetime
import re
import hashlib
import yaml
from typing import Dict, Any, List, Optional, Set, Tuple
from pathlib import Path

# Default paths
DEFAULT_TEMPLATES_DIR = "../templates"
DEFAULT_OUTPUT_DIR = "../sites-available"
DEFAULT_CONFIG_DIR = "../../environments"
DEFAULT_INCLUDES_DIR = "../includes"
DEFAULT_CONFD_DIR = "../conf.d"

# Configuration file extensions
CONFIG_EXTENSIONS = [".env", ".json", ".yaml", ".yml"]

# Security-sensitive variables that need validation
SENSITIVE_VARIABLES = ["DOMAIN_NAME", "SSL_CERTIFICATE_PATH", "SSL_KEY_PATH"]

# Environment settings
ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]
ENVIRONMENT_SETTINGS = {
    "development": {
        "CACHE_CONTROL": "no-cache, no-store, must-revalidate",
        "KEEPALIVE_TIMEOUT": "120",
        "LOG_LEVEL": "debug",
        "RATE_LIMIT": "20r/s",
        "ENABLE_WAF": False,
        "WORKER_PROCESSES": "1",
    },
    "staging": {
        "CACHE_CONTROL": "public, max-age=3600",
        "KEEPALIVE_TIMEOUT": "65",
        "LOG_LEVEL": "info",
        "RATE_LIMIT": "30r/s",
        "ENABLE_WAF": True,
        "WORKER_PROCESSES": "auto",
    },
    "production": {
        "CACHE_CONTROL": "public, max-age=86400",
        "KEEPALIVE_TIMEOUT": "65",
        "LOG_LEVEL": "warn",
        "RATE_LIMIT": "10r/s",
        "ENABLE_WAF": True,
        "WORKER_PROCESSES": "auto",
    },
    "dr-recovery": {
        "CACHE_CONTROL": "no-store",
        "KEEPALIVE_TIMEOUT": "30",
        "LOG_LEVEL": "warn",
        "RATE_LIMIT": "5r/s",
        "ENABLE_WAF": True,
        "WORKER_PROCESSES": "auto",
    }
}

# Security settings
SECURE_SSL_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]
INSECURE_SSL_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
DEFAULT_SSL_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
)
REQUIRED_SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy"
]

# Setup logging
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("nginx-config-generator")


def setup_argparse():
    """Configure argument parser for the script."""
    parser = argparse.ArgumentParser(
        description="Generate NGINX configuration files from templates."
    )
    parser.add_argument(
        "--environment", "-e",
        required=True,
        choices=ENVIRONMENTS,
        help="Environment to generate configuration for"
    )
    parser.add_argument(
        "--templates-dir", "-t",
        default=DEFAULT_TEMPLATES_DIR,
        help=f"Directory containing templates (default: {DEFAULT_TEMPLATES_DIR})"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for generated configs (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--config-dir", "-c",
        default=DEFAULT_CONFIG_DIR,
        help=f"Directory containing environment configs (default: {DEFAULT_CONFIG_DIR})"
    )
    parser.add_argument(
        "--includes-dir", "-i",
        default=DEFAULT_INCLUDES_DIR,
        help=f"Directory containing include files (default: {DEFAULT_INCLUDES_DIR})"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force overwrite of existing files"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without writing files"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate generated config files"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create backups of existing config files before overwriting"
    )
    return parser.parse_args()


def load_environment_config(env_name: str, config_dir: str) -> Dict[str, Any]:
    """
    Load environment configuration from files.

    Args:
        env_name: Environment name (development, staging, etc.)
        config_dir: Directory containing configuration files

    Returns:
        Dictionary of configuration values
    """
    config = {}
    found_config = False

    # Apply environment defaults first
    if env_name in ENVIRONMENT_SETTINGS:
        config.update(ENVIRONMENT_SETTINGS[env_name])
        found_config = True

    # Look for environment config files with different extensions
    for ext in CONFIG_EXTENSIONS:
        config_file = os.path.join(config_dir, f"{env_name}{ext}")
        if not os.path.exists(config_file):
            continue

        found_config = True
        logger.info(f"Loading configuration from {config_file}")

        try:
            if ext == ".env":
                with open(config_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            config[key.strip()] = value.strip()

            elif ext in [".json"]:
                with open(config_file, "r") as f:
                    config.update(json.load(f))

            elif ext in [".yaml", ".yml"]:
                try:
                    with open(config_file, "r") as f:
                        config.update(yaml.safe_load(f))
                except ImportError:
                    logger.warning("YAML support requires PyYAML; pip install pyyaml")
        except Exception as e:
            logger.error(f"Error loading configuration from {config_file}: {e}")

    if not found_config:
        logger.warning(f"No configuration files found for {env_name} in {config_dir}")

    return config


def create_template_context(env_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a context dictionary for template rendering.

    Args:
        env_name: Environment name (development, staging, etc.)
        config: Configuration dictionary from config files

    Returns:
        Context dictionary for template rendering
    """
    # Base context with defaults
    context = {
        "ENVIRONMENT": env_name,
        "APP_ROOT": config.get("APP_ROOT", "/var/www/cloud-platform"),
        "STATIC_PATH": config.get("STATIC_PATH", "/var/www/cloud-platform/static"),
        "API_UPSTREAM": config.get("API_UPSTREAM", "backend_api"),
        "API_VERSION": config.get("API_VERSION", "1.0"),
        "APP_VERSION": config.get("APP_VERSION", "1.0.0"),
        "DOMAIN_NAME": config.get("DOMAIN_NAME", f"cloud-platform-{env_name}.example.com"),
        "API_TIMEOUT": config.get("API_TIMEOUT", "60"),
        "API_CONNECT_TIMEOUT": config.get("API_CONNECT_TIMEOUT", "10"),
        "RATE_LIMIT": config.get("RATE_LIMIT", "10r/s"),
        "RATE_LIMIT_BURST": config.get("RATE_LIMIT_BURST", "20"),
        "RATE_LIMIT_MODE": config.get("RATE_LIMIT_MODE", "nodelay"),
        "AUTH_RATE_LIMIT": config.get("AUTH_RATE_LIMIT", "5r/s"),
        "AUTH_RATE_LIMIT_BURST": config.get("AUTH_RATE_LIMIT_BURST", "10"),
        "ICS_TIMEOUT": config.get("ICS_TIMEOUT", "300"),
        "STATIC_MAX_AGE": config.get("STATIC_MAX_AGE", "2592000"),
        "CACHE_CONTROL": config.get("CACHE_CONTROL", "public, max-age=86400"),
        "SSL_CERTIFICATE_PATH": config.get("SSL_CERTIFICATE_PATH", "/etc/ssl/certs/cloud-platform.crt"),
        "SSL_KEY_PATH": config.get("SSL_KEY_PATH", "/etc/ssl/private/cloud-platform.key"),
        "WORKER_CONNECTIONS": config.get("WORKER_CONNECTIONS", "1024"),
        "WORKER_PROCESSES": config.get("WORKER_PROCESSES", "auto"),
        "SSL_CIPHERS": config.get("SSL_CIPHERS", DEFAULT_SSL_CIPHERS),
        "KEEPALIVE_TIMEOUT": config.get("KEEPALIVE_TIMEOUT", "65"),
        "KEEPALIVE_REQUESTS": config.get("KEEPALIVE_REQUESTS", "1000"),
        "CLIENT_BODY_BUFFER_SIZE": config.get("CLIENT_BODY_BUFFER_SIZE", "16k"),
    }

    # Add ICS restricted IPs
    ics_ips = config.get("ICS_RESTRICTED_IPS", "10.100.0.0/16,192.168.10.0/24")
    if isinstance(ics_ips, str):
        context["ICS_RESTRICTED_IPS"] = [ip.strip() for ip in ics_ips.split(",")]
    elif isinstance(ics_ips, list):
        context["ICS_RESTRICTED_IPS"] = ics_ips
    else:
        context["ICS_RESTRICTED_IPS"] = []

    # Environment-specific settings
    if env_name == "production":
        context["INTERNAL_HEALTH_CHECK"] = config.get("INTERNAL_HEALTH_CHECK", True)
        context["CACHE_CONTROL"] = config.get("CACHE_CONTROL", "public, max-age=86400")
        context["ENABLE_WAF"] = config.get("ENABLE_WAF", True)
    elif env_name == "staging":
        context["INTERNAL_HEALTH_CHECK"] = config.get("INTERNAL_HEALTH_CHECK", True)
        context["CACHE_CONTROL"] = config.get("CACHE_CONTROL", "public, max-age=3600")
        context["ENABLE_WAF"] = config.get("ENABLE_WAF", True)
    elif env_name == "dr-recovery":
        context["INTERNAL_HEALTH_CHECK"] = config.get("INTERNAL_HEALTH_CHECK", True)
        context["CACHE_CONTROL"] = config.get("CACHE_CONTROL", "no-store")
        context["ENABLE_WAF"] = config.get("ENABLE_WAF", True)
        # DR-specific settings
        context["DR_MODE"] = config.get("DR_MODE", True)
        context["REDUCED_FEATURES"] = config.get("REDUCED_FEATURES", True)
        context["EMERGENCY_ACCESS"] = config.get("EMERGENCY_ACCESS", True)
        context["STATUS_PAGE_ENABLED"] = config.get("STATUS_PAGE_ENABLED", True)
    else:  # development
        context["INTERNAL_HEALTH_CHECK"] = config.get("INTERNAL_HEALTH_CHECK", False)
        context["CACHE_CONTROL"] = config.get("CACHE_CONTROL", "no-cache, no-store, must-revalidate")
        context["ENABLE_WAF"] = config.get("ENABLE_WAF", False)
        # Development-specific settings
        context["DEBUG_HEADERS"] = config.get("DEBUG_HEADERS", True)
        context["AUTO_RELOAD"] = config.get("AUTO_RELOAD", True)

    return context


def validate_context(context: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate the template context for security issues.

    Args:
        context: Template context dictionary

    Returns:
        Tuple of (is_valid, [error_messages])
    """
    errors = []

    # Check for required variables
    for key in SENSITIVE_VARIABLES:
        if key not in context or not context[key]:
            errors.append(f"Missing or empty required variable: {key}")

    # Path traversal checks
    for key in ["SSL_CERTIFICATE_PATH", "SSL_KEY_PATH"]:
        if key in context and "../" in context[key]:
            errors.append(f"Potential path traversal in {key}: {context[key]}")

    # Check for valid IPs
    if "ICS_RESTRICTED_IPS" in context:
        for ip in context["ICS_RESTRICTED_IPS"]:
            if not is_valid_ip_or_cidr(ip):
                errors.append(f"Invalid IP or CIDR format: {ip}")

    return len(errors) == 0, errors


def is_valid_ip_or_cidr(ip_str: str) -> bool:
    """
    Check if a string is a valid IP address or CIDR notation.

    Args:
        ip_str: IP address or CIDR notation string

    Returns:
        True if valid, False otherwise
    """
    # Simple validation for IPv4 and CIDR notation
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$"
    return bool(re.match(ipv4_pattern, ip_str))


def render_template(template_path: str, context: Dict[str, Any]) -> str:
    """
    Render a template file with the provided context.

    Args:
        template_path: Path to the template file
        context: Dictionary of context variables

    Returns:
        Rendered template content
    """
    with open(template_path, 'r') as f:
        template_content = f.read()

    # Replace simple variables
    for key, value in context.items():
        if isinstance(value, (str, int, float, bool)):
            template_content = template_content.replace(f"{{{{{key}}}}}", str(value))

    # Handle conditional blocks
    for key, value in context.items():
        if isinstance(value, bool):
            if value:
                # Remove the conditional tags for true conditions
                template_content = re.sub(
                    r'\{\{#' + key + r'\}\}(.*?)\{\{/' + key + r'\}\}',
                    r'\1',
                    template_content,
                    flags=re.DOTALL
                )
                # Remove any inverse conditions
                template_content = re.sub(
                    r'\{\{^' + key + r'\}\}(.*?)\{\{/' + key + r'\}\}',
                    '',
                    template_content,
                    flags=re.DOTALL
                )
            else:
                # Remove the entire block for false conditions
                template_content = re.sub(
                    r'\{\{#' + key + r'\}\}(.*?)\{\{/' + key + r'\}\}',
                    '',
                    template_content,
                    flags=re.DOTALL
                )
                # Keep inverse conditions
                template_content = re.sub(
                    r'\{\{^' + key + r'\}\}(.*?)\{\{/' + key + r'\}\}',
                    r'\1',
                    template_content,
                    flags=re.DOTALL
                )

    # Handle lists
    for key, value in context.items():
        if isinstance(value, list):
            list_pattern = r'\{\{#' + key + r'\}\}(.*?)\{\{\.}}'
            list_match = re.search(list_pattern, template_content, re.DOTALL)
            if list_match:
                item_template = list_match.group(1)
                rendered_items = []
                for item in value:
                    rendered_items.append(item_template.replace("{{.}}", str(item)))

                # Replace the entire list block with rendered items
                template_content = re.sub(
                    r'\{\{#' + key + r'\}\}.*?\{\{/' + key + r'\}\}',
                    ''.join(rendered_items),
                    template_content,
                    flags=re.DOTALL
                )

    # Clean up any remaining template tags
    template_content = re.sub(r'\{\{[^}]+\}\}', '', template_content)

    return template_content


def calculate_file_hash(file_path: str) -> str:
    """
    Calculate SHA-256 hash of file contents.

    Args:
        file_path: Path to the file

    Returns:
        Hex digest of SHA-256 hash
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def create_backup(file_path: str) -> Optional[str]:
    """
    Create a backup of a file with timestamp.

    Args:
        file_path: Path to the file to backup

    Returns:
        Path to the backup file or None on failure
    """
    if not os.path.exists(file_path):
        return None

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{file_path}.{timestamp}.bak"

    try:
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created backup: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create backup of {file_path}: {e}")
        return None


def process_templates(templates_dir: str, output_dir: str, context: Dict[str, Any],
                     force: bool = False, dry_run: bool = False, backup: bool = False) -> bool:
    """
    Process all templates in the templates directory.

    Args:
        templates_dir: Directory containing templates
        output_dir: Directory to write rendered templates
        context: Template context dictionary
        force: Whether to overwrite existing files
        dry_run: Perform operations without writing files
        backup: Create backups of existing files

    Returns:
        Success status (True/False)
    """
    templates_dir = os.path.abspath(templates_dir)
    output_dir = os.path.abspath(output_dir)

    if not os.path.isdir(templates_dir):
        logger.error(f"Templates directory {templates_dir} not found")
        return False

    if not dry_run and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
        except OSError as e:
            logger.error(f"Failed to create output directory {output_dir}: {e}")
            return False

    processed_count = 0
    skipped_count = 0
    error_count = 0

    # Process all template files
    for template_file in os.listdir(templates_dir):
        if template_file.endswith('.template'):
            template_path = os.path.join(templates_dir, template_file)
            output_file = template_file.replace('.template', '')
            output_path = os.path.join(output_dir, output_file)

            if os.path.exists(output_path) and not force and not dry_run:
                logger.info(f"Skipping {output_file} (already exists, use --force to overwrite)")
                skipped_count += 1
                continue

            logger.info(f"Processing template: {template_file}")
            try:
                rendered_content = render_template(template_path, context)

                if dry_run:
                    logger.info(f"Would write to: {output_path}")
                    processed_count += 1
                else:
                    # Backup existing file if requested
                    if backup and os.path.exists(output_path):
                        create_backup(output_path)

                    # Create parent directories if they don't exist
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)

                    with open(output_path, 'w') as f:
                        f.write(rendered_content)
                    logger.info(f"Generated: {output_path}")
                    processed_count += 1
            except Exception as e:
                logger.error(f"Error processing template {template_file}: {e}")
                error_count += 1

    # Log summary
    logger.info(f"Templates processed: {processed_count}, skipped: {skipped_count}, errors: {error_count}")

    return error_count == 0


def setup_includes(includes_dir: str, output_dir: str, dry_run: bool = False) -> bool:
    """
    Ensure all required include files are available.

    Args:
        includes_dir: Directory containing include files
        output_dir: Base directory for output
        dry_run: Perform operations without writing files

    Returns:
        Success status (True/False)
    """
    includes_dir = os.path.abspath(includes_dir)
    output_dir = os.path.abspath(output_dir)

    if not os.path.isdir(includes_dir):
        logger.error(f"Includes directory {includes_dir} not found")
        return False

    # Directories to create
    create_dirs = [
        os.path.join(output_dir, "..", "includes"),
        os.path.join(output_dir, "..", "conf.d")
    ]

    for directory in create_dirs:
        if not dry_run and not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
                logger.info(f"Created directory: {directory}")
            except OSError as e:
                logger.error(f"Failed to create directory {directory}: {e}")
                return False

    return True


def validate_nginx_config(output_dir: str) -> bool:
    """
    Validate the generated NGINX configuration.

    Args:
        output_dir: Directory containing the generated configs

    Returns:
        True if validation passes, False otherwise
    """
    logger.info("Validating NGINX configuration...")

    try:
        # Check if nginx is installed and in PATH
        import subprocess
        result = subprocess.run(
            ["nginx", "-t", "-c", "/dev/null", "-g", f"include {output_dir}/*.conf;"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            logger.info("NGINX configuration validation successful")
            return True
        else:
            logger.error(f"NGINX configuration validation failed: {result.stderr}")
            return False
    except FileNotFoundError:
        logger.warning("NGINX binary not found in PATH, skipping validation")
        return True
    except Exception as e:
        logger.error(f"Error validating NGINX configuration: {e}")
        return False


def verify_environment_templates(env_name: str, templates_dir: str) -> bool:
    """
    Verify that all required templates for the specified environment exist.

    Args:
        env_name: Environment name to verify
        templates_dir: Directory containing templates

    Returns:
        True if all required templates exist, False otherwise
    """
    templates_dir = os.path.abspath(templates_dir)
    if not os.path.isdir(templates_dir):
        logger.error(f"Templates directory {templates_dir} not found")
        return False

    # Required templates for all environments
    required_templates = [
        "server.conf.template",
        "ssl-params.conf.template",
        "upstream.conf.template"
    ]

    # Environment-specific templates
    if env_name == "dr-recovery":
        required_templates.extend([
            "dr-status.conf.template",
            "reduced-features.conf.template"
        ])

    missing_templates = []
    for template in required_templates:
        template_path = os.path.join(templates_dir, template)
        if not os.path.exists(template_path):
            missing_templates.append(template)

    if missing_templates:
        logger.warning(f"Missing required templates for {env_name} environment: {', '.join(missing_templates)}")
        return False

    return True


def main():
    """Main entry point for the script."""
    args = setup_argparse()

    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Resolve paths relative to the script
    templates_dir = os.path.join(script_dir, args.templates_dir)
    output_dir = os.path.join(script_dir, args.output_dir)
    config_dir = os.path.join(script_dir, args.config_dir)
    includes_dir = os.path.join(script_dir, args.includes_dir)

    logger.info(f"Generating NGINX configuration for {args.environment} environment")

    # Verify environment templates
    if not verify_environment_templates(args.environment, templates_dir):
        if not args.force:
            logger.error("Missing required templates. Use --force to continue anyway")
            return 1
        logger.warning("Continuing despite missing templates due to --force flag")

    # Load configuration
    config = load_environment_config(args.environment, config_dir)
    context = create_template_context(args.environment, config)

    # Add timestamps and version info
    context["GENERATED_TIMESTAMP"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    context["GENERATOR_SCRIPT"] = os.path.basename(__file__)

    # Validate template context
    valid, errors = validate_context(context)
    if not valid:
        for error in errors:
            logger.error(f"Context validation error: {error}")
        if not args.force:
            logger.error("Context validation failed, use --force to continue anyway")
            return 1
        logger.warning("Continuing despite validation errors due to --force flag")

    if args.verbose:
        logger.debug("Template context:")
        for key, value in sorted(context.items()):
            logger.debug(f"  {key}: {value}")

    # Process templates
    if not process_templates(templates_dir, output_dir, context,
                            args.force, args.dry_run, args.backup):
        logger.error("Error processing templates")
        return 1

    # Ensure includes are set up
    if not setup_includes(includes_dir, output_dir, args.dry_run):
        logger.error("Error setting up include files")
        return 1

    # Validate the generated configuration if requested
    if args.validate and not args.dry_run:
        if not validate_nginx_config(output_dir):
            logger.error("NGINX configuration validation failed")
            return 1

    logger.info("NGINX configuration generation complete")
    if not args.dry_run:
        logger.info(f"Files generated in: {output_dir}")
    else:
        logger.info("Dry run completed, no files were written")

    return 0


if __name__ == "__main__":
    sys.exit(main())
