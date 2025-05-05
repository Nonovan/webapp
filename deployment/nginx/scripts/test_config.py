#!/usr/bin/env python3
"""
Test NGINX configuration for Cloud Infrastructure Platform.

This script performs comprehensive validation of NGINX configuration files,
checking for common security issues, proper environment configuration,
and ensuring that best practices are followed.
"""

import os
import sys
import re
import subprocess
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
import datetime
import json

# Directory structure
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
NGINX_ROOT = Path("/etc/nginx")

# Common directories to check
SITES_AVAILABLE = NGINX_ROOT / "sites-available"
SITES_ENABLED = NGINX_ROOT / "sites-enabled"
CONF_DIR = NGINX_ROOT / "conf.d"
INCLUDES_DIR = NGINX_ROOT / "includes"

# Security headers that should be present
REQUIRED_SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy"
]

# Valid environments
VALID_ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]

# Configure logging
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("nginx-config-tester")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Test NGINX configuration for Cloud Infrastructure Platform"
    )
    parser.add_argument(
        "--config", "-c",
        default="/etc/nginx/nginx.conf",
        help="Path to main NGINX configuration file"
    )
    parser.add_argument(
        "--environment", "-e",
        choices=VALID_ENVIRONMENTS,
        help="Specific environment to check"
    )
    parser.add_argument(
        "--detailed", "-d",
        action="store_true",
        help="Show detailed information"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--output", "-o",
        help="Write JSON output to file"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimize output"
    )
    parser.add_argument(
        "--strict", "-s",
        action="store_true",
        help="Fail on warnings"
    )

    return parser.parse_args()


def check_nginx_installed() -> bool:
    """Check if NGINX is installed on the system."""
    try:
        subprocess.run(["nginx", "-v"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        return False


def test_basic_syntax(config_path: Path) -> bool:
    """
    Test basic NGINX configuration syntax.

    Args:
        config_path: Path to the NGINX config file

    Returns:
        True if syntax is valid, False otherwise
    """
    logger.info("Checking basic NGINX configuration syntax...")

    try:
        result = subprocess.run(
            ["nginx", "-t", "-c", str(config_path)],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            logger.info("✅ NGINX configuration syntax is valid")
            return True
        else:
            logger.error(f"❌ NGINX configuration syntax is invalid:\n{result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error testing NGINX configuration: {e}")
        return False


def find_config_files() -> List[Path]:
    """
    Find all NGINX configuration files.

    Returns:
        List of path objects for all config files
    """
    config_files = []

    dirs_to_check = [
        NGINX_ROOT,
        NGINX_ROOT / "conf.d",
        NGINX_ROOT / "sites-available",
        NGINX_ROOT / "sites-enabled",
        NGINX_ROOT / "includes"
    ]

    for directory in dirs_to_check:
        if directory.exists():
            for file_path in directory.glob("**/*.conf"):
                if file_path.is_file():
                    config_files.append(file_path)

    return config_files


def check_ssl_protocols(config_files: List[Path]) -> Tuple[bool, Set[str]]:
    """
    Check for secure SSL protocol settings.

    Args:
        config_files: List of configuration files to check

    Returns:
        Tuple of (is_secure, insecure_protocols)
    """
    insecure_protocols = set()
    ssl_protocols_found = False

    for file_path in config_files:
        try:
            content = file_path.read_text()
            if "ssl_protocols" in content:
                ssl_protocols_found = True
                for protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]:
                    if re.search(rf"ssl_protocols\s+.*{protocol}", content):
                        insecure_protocols.add(protocol)
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    if not ssl_protocols_found:
        logger.warning("⚠️ WARNING: SSL protocol configuration not found")
        return False, insecure_protocols

    if insecure_protocols:
        protocols_str = ", ".join(insecure_protocols)
        logger.warning(f"⚠️ WARNING: Insecure SSL protocols found: {protocols_str}")
        return False, insecure_protocols

    logger.info("✅ SSL protocol configuration is secure")
    return True, insecure_protocols


def check_security_headers(config_files: List[Path]) -> Tuple[bool, List[str]]:
    """
    Check for important security headers.

    Args:
        config_files: List of configuration files to check

    Returns:
        Tuple of (all_headers_present, missing_headers)
    """
    found_headers = set()

    for file_path in config_files:
        try:
            content = file_path.read_text()
            for header in REQUIRED_SECURITY_HEADERS:
                if header in content:
                    found_headers.add(header)
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    missing_headers = [h for h in REQUIRED_SECURITY_HEADERS if h not in found_headers]

    if not missing_headers:
        logger.info("✅ Essential security headers are configured")
        return True, []
    else:
        logger.warning(f"⚠️ WARNING: Some security headers are missing: {', '.join(missing_headers)}")
        return False, missing_headers


def check_server_tokens(config_files: List[Path]) -> bool:
    """
    Check if server_tokens is disabled.

    Args:
        config_files: List of configuration files to check

    Returns:
        True if server_tokens is disabled, False otherwise
    """
    for file_path in config_files:
        try:
            content = file_path.read_text()
            if re.search(r"server_tokens\s+off", content):
                logger.info("✅ server_tokens is disabled")
                return True
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    logger.warning("⚠️ WARNING: server_tokens should be disabled")
    return False


def check_rate_limiting(config_files: List[Path]) -> bool:
    """
    Check if rate limiting is configured.

    Args:
        config_files: List of configuration files to check

    Returns:
        True if rate limiting is found, False otherwise
    """
    for file_path in config_files:
        try:
            content = file_path.read_text()
            if "limit_req_zone" in content:
                logger.info("✅ Rate limiting is configured")
                return True
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    logger.warning("⚠️ WARNING: Rate limiting configuration not found")
    return False


def check_dh_parameters(config_files: List[Path]) -> Tuple[bool, Optional[str]]:
    """
    Check for DH parameters configuration.

    Args:
        config_files: List of configuration files to check

    Returns:
        Tuple of (dh_params_found, dh_param_file)
    """
    for file_path in config_files:
        try:
            content = file_path.read_text()
            match = re.search(r'ssl_dhparam\s+([^;]+);', content)
            if match:
                dh_param_file = match.group(1).strip()
                logger.info("✅ Custom DH parameters are configured")

                # Check if the file exists
                dh_path = Path(dh_param_file)
                if not dh_path.is_absolute():
                    # Try relative to NGINX root
                    dh_path = NGINX_ROOT / dh_param_file

                if not dh_path.exists():
                    logger.warning(f"⚠️ WARNING: DH parameters file {dh_param_file} not found")

                return True, dh_param_file
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    logger.warning("⚠️ WARNING: Custom DH parameters not configured")
    return False, None


def check_client_certificate_validation(config_files: List[Path]) -> bool:
    """
    Check if client certificate validation is configured.

    Args:
        config_files: List of configuration files to check

    Returns:
        True if client certificate validation is found, False otherwise
    """
    for file_path in config_files:
        try:
            content = file_path.read_text()
            if "ssl_verify_client" in content:
                logger.info("✅ Client certificate validation is configured")
                return True
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    return False


def check_modsecurity_waf(config_files: List[Path]) -> bool:
    """
    Check if ModSecurity WAF is enabled.

    Args:
        config_files: List of configuration files to check

    Returns:
        True if ModSecurity is enabled, False otherwise
    """
    for file_path in config_files:
        try:
            content = file_path.read_text()
            if re.search(r"modsecurity\s+on", content):
                logger.info("✅ ModSecurity WAF is enabled")
                return True
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    logger.warning("⚠️ WARNING: ModSecurity WAF is not enabled")
    return False


def check_https_redirect(config_files: List[Path]) -> bool:
    """
    Check if HTTP to HTTPS redirect is configured.

    Args:
        config_files: List of configuration files to check

    Returns:
        True if HTTP to HTTPS redirect is found, False otherwise
    """
    for file_path in config_files:
        try:
            content = file_path.read_text()
            if "return 301 https://" in content:
                logger.info("✅ HTTP to HTTPS redirect is configured")
                return True
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    logger.warning("⚠️ WARNING: HTTP to HTTPS redirect not found")
    return False


def check_custom_log_format(config_files: List[Path]) -> bool:
    """
    Check if custom log format is configured.

    Args:
        config_files: List of configuration files to check

    Returns:
        True if custom log format is found, False otherwise
    """
    for file_path in config_files:
        try:
            content = file_path.read_text()
            if "log_format" in content:
                logger.info("✅ Custom log format is configured")
                return True
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    logger.warning("⚠️ WARNING: Custom log format not configured")
    return False


def check_environment_configs() -> Dict[str, bool]:
    """
    Check for environment-specific configurations.

    Returns:
        Dictionary with environment names as keys and existence as values
    """
    logger.info("Checking environment configurations...")
    result = {}

    if SITES_AVAILABLE.exists():
        for env in ["production", "staging", "development", "dr-recovery"]:
            # Map environment names to file names
            if env == "production":
                file_name = "cloud-platform.conf"
            else:
                file_name = f"{env}.conf"

            config_path = SITES_AVAILABLE / file_name
            result[env] = config_path.exists()

            if result[env]:
                logger.info(f"✅ {env.capitalize()} configuration exists")
            else:
                logger.warning(f"⚠️ WARNING: {env.capitalize()} configuration not found")

    return result


def generate_report(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive report with all findings.

    Args:
        results: Dictionary with all test results

    Returns:
        Report dictionary with additional metadata
    """
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "nginx_version": get_nginx_version(),
        "results": results,
        "summary": {
            "issues_count": sum(1 for key, value in results.items()
                               if isinstance(value, bool) and value is False),
            "passed_count": sum(1 for key, value in results.items()
                               if isinstance(value, bool) and value is True)
        }
    }

    # Add overall status
    report["status"] = "pass" if report["summary"]["issues_count"] == 0 else "warn"

    return report


def get_nginx_version() -> str:
    """Get the NGINX version string."""
    try:
        result = subprocess.run(
            ["nginx", "-v"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.stderr:  # nginx -v outputs to stderr
            match = re.search(r"nginx/(\d+\.\d+\.\d+)", result.stderr)
            if match:
                return match.group(1)
        return "unknown"
    except Exception:
        return "unknown"


def main() -> int:
    """
    Main entry point for the script.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    args = parse_arguments()

    # Configure logging level
    if args.quiet:
        logger.setLevel(logging.WARNING)

    # Check if NGINX is installed
    if not check_nginx_installed():
        logger.error("❌ ERROR: NGINX is not installed")
        return 1

    logger.info(f"Testing NGINX configuration: {args.config}")
    config_path = Path(args.config)

    # Test basic syntax
    if not test_basic_syntax(config_path):
        return 1

    # Find all configuration files
    config_files = find_config_files()
    if not config_files:
        logger.warning("No configuration files found")

    # Initialize results dictionary
    results = {}

    # Check for common security issues
    logger.info("Checking for common security issues...")

    # SSL protocol checks
    ssl_protocols_secure, insecure_protocols = check_ssl_protocols(config_files)
    results["ssl_protocols_secure"] = ssl_protocols_secure
    results["insecure_protocols"] = list(insecure_protocols)

    # Server tokens check
    results["server_tokens_disabled"] = check_server_tokens(config_files)

    # Security headers check
    headers_secure, missing_headers = check_security_headers(config_files)
    results["security_headers_complete"] = headers_secure
    results["missing_security_headers"] = missing_headers

    # Rate limiting check
    results["rate_limiting_configured"] = check_rate_limiting(config_files)

    # DH parameters check
    dh_params_found, dh_params_file = check_dh_parameters(config_files)
    results["dh_parameters_configured"] = dh_params_found
    results["dh_parameters_file"] = dh_params_file

    # Client certificate validation check
    results["client_cert_validation"] = check_client_certificate_validation(config_files)

    # ModSecurity WAF check
    results["modsecurity_enabled"] = check_modsecurity_waf(config_files)

    # Additional advanced checks
    logger.info("Performing advanced checks...")

    # HTTP to HTTPS redirect check
    results["https_redirect_configured"] = check_https_redirect(config_files)

    # Custom log format check
    results["custom_log_format"] = check_custom_log_format(config_files)

    # Environment configuration checks
    results["environment_configs"] = check_environment_configs()

    # Generate final report
    report = generate_report(results)

    # Determine exit code
    exit_code = 0
    if report["status"] == "warn" and args.strict:
        exit_code = 1

    # Output report
    if args.json:
        if args.output:
            try:
                output_path = Path(args.output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'w') as f:
                    json.dump(report, f, indent=2)
                logger.info(f"Report saved to {output_path}")
            except Exception as e:
                logger.error(f"Failed to save report: {e}")
                exit_code = 1
        else:
            print(json.dumps(report, indent=2))
    else:
        # Final summary
        logger.info("Configuration test complete.")

        if report["summary"]["issues_count"] == 0:
            logger.info("✅ NGINX configuration is valid and ready to use")
        else:
            logger.warning(f"⚠️ Found {report['summary']['issues_count']} potential issues")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
