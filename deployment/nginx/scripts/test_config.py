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


def validate_nginx_installation() -> bool:
    """
    Check if NGINX is installed and configured properly.

    Returns:
        bool: True if NGINX is installed and configured properly, False otherwise
    """
    logger.info("Checking NGINX installation...")

    # Check if NGINX is installed
    if not check_nginx_installed():
        logger.error("❌ NGINX is not installed")
        return False

    # Check if configuration files exist
    nginx_conf = NGINX_ROOT / "nginx.conf"
    if not nginx_conf.exists():
        logger.error(f"❌ Main NGINX configuration file not found: {nginx_conf}")
        return False

    # Check if required directories exist
    required_dirs = [SITES_AVAILABLE, SITES_ENABLED, CONF_DIR, INCLUDES_DIR]
    missing_dirs = []

    for directory in required_dirs:
        if not directory.exists():
            missing_dirs.append(directory)

    if missing_dirs:
        for directory in missing_dirs:
            logger.warning(f"⚠️ WARNING: Required directory not found: {directory}")

        if len(missing_dirs) == len(required_dirs):
            logger.error("❌ NGINX directory structure not configured properly")
            return False

    # Check basic syntax
    config_valid = test_basic_syntax(nginx_conf)
    if not config_valid:
        return False

    logger.info("✅ NGINX is installed and configured properly")
    return True


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
        List of Path objects to configuration files
    """
    config_files = []

    # Find all .conf files in NGINX directories
    for directory in [NGINX_ROOT, SITES_AVAILABLE, SITES_ENABLED, CONF_DIR, INCLUDES_DIR]:
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
    Check for rate limiting configuration.

    Args:
        config_files: List of configuration files to check

    Returns:
        True if rate limiting is configured, False otherwise
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
            if re.search(r"return\s+301\s+https://", content):
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
            if re.search(r"log_format\s+\w+", content):
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
        for env in VALID_ENVIRONMENTS:
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


def check_security_configs(config_files: List[Path]) -> Dict[str, bool]:
    """
    Check for comprehensive security configurations.

    Args:
        config_files: List of configuration files to check

    Returns:
        Dictionary with detailed security checks results
    """
    logger.info("Checking security configurations...")
    results = {}

    # Check for security headers
    headers_secure, missing_headers = check_security_headers(config_files)
    results["security_headers"] = headers_secure
    results["missing_headers"] = missing_headers

    # Check for server tokens
    results["server_tokens_disabled"] = check_server_tokens(config_files)

    # Check for SSL/TLS protocols
    ssl_secure, insecure_protocols = check_ssl_protocols(config_files)
    results["ssl_protocols_secure"] = ssl_secure
    results["insecure_protocols"] = list(insecure_protocols)

    # Check for DH parameters
    dh_params_found, dh_params_file = check_dh_parameters(config_files)
    results["dh_parameters_configured"] = dh_params_found
    if dh_params_file:
        results["dh_parameters_file"] = str(dh_params_file)

    # Check for rate limiting
    results["rate_limiting_configured"] = check_rate_limiting(config_files)

    # Check for HTTP to HTTPS redirect
    results["https_redirect_configured"] = check_https_redirect(config_files)

    # Check for ModSecurity WAF
    results["modsecurity_enabled"] = check_modsecurity_waf(config_files)

    # Check for client certificate validation
    results["client_cert_validation"] = check_client_certificate_validation(config_files)

    logger.info("Security configuration check complete")
    return results


def check_ssl_certificates(config_files: List[Path]) -> Dict[str, Any]:
    """
    Check SSL certificate configurations and expiry.

    Args:
        config_files: List of configuration files to check

    Returns:
        Dictionary with certificate details
    """
    logger.info("Checking SSL certificates...")
    results = {
        "certificates_found": False,
        "certificates": []
    }

    ssl_paths = set()

    # Find all SSL certificate paths in configuration files
    for file_path in config_files:
        try:
            content = file_path.read_text()
            for match in re.finditer(r'ssl_certificate\s+([^;]+);', content):
                cert_path = match.group(1).strip()
                ssl_paths.add(cert_path)
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")

    if not ssl_paths:
        logger.warning("⚠️ WARNING: No SSL certificates found in configuration")
        return results

    results["certificates_found"] = True

    for cert_path in ssl_paths:
        cert_info = {
            "path": cert_path,
            "exists": False
        }

        # Convert to Path and handle relative paths
        cert_file = Path(cert_path)
        if not cert_file.is_absolute():
            cert_file = NGINX_ROOT / cert_path

        if not cert_file.exists():
            logger.error(f"❌ Certificate file not found: {cert_path}")
            results["certificates"].append(cert_info)
            continue

        cert_info["exists"] = True

        # Check certificate expiry
        try:
            result = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", str(cert_file)],
                capture_output=True,
                text=True,
                check=True
            )

            expiry_date = result.stdout.split('=')[1].strip()
            cert_info["expiry_date"] = expiry_date

            # Convert to datetime and calculate days remaining
            expiry_datetime = datetime.datetime.strptime(expiry_date, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_datetime.date() - datetime.datetime.now().date()).days
            cert_info["days_left"] = days_left

            if days_left < 30:
                cert_info["expiring_soon"] = True
                if days_left < 7:
                    logger.error(f"❌ Certificate {cert_path} will expire in {days_left} days")
                    cert_info["critical"] = True
                else:
                    logger.warning(f"⚠️ Certificate {cert_path} will expire in {days_left} days")
            else:
                logger.info(f"✅ Certificate {cert_path} valid for {days_left} days")

        except subprocess.CalledProcessError as e:
            logger.error(f"Error checking certificate {cert_path}: {e}")
            cert_info["error"] = str(e)

        results["certificates"].append(cert_info)

    return results


def generate_report(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive report from all test results.

    Args:
        results: Dictionary containing test results

    Returns:
        Formatted report dictionary
    """
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "nginx_version": get_nginx_version(),
        "summary": {
            "status": "pass",
            "issues_count": 0
        },
        "details": results
    }

    # Count issues
    issues_count = 0
    warnings = []
    errors = []

    # Check SSL protocols
    if results.get("ssl_protocols_secure") is False:
        issues_count += 1
        warnings.append("Insecure SSL protocols found")

    # Check security headers
    if results.get("security_headers_complete") is False:
        issues_count += 1
        warnings.append("Missing security headers")

    # Check server tokens
    if results.get("server_tokens_disabled") is False:
        issues_count += 1
        warnings.append("Server tokens not disabled")

    # Check rate limiting
    if results.get("rate_limiting_configured") is False:
        issues_count += 1
        warnings.append("Rate limiting not configured")

    # Check DH parameters
    if results.get("dh_parameters_configured") is False:
        issues_count += 1
        warnings.append("Custom DH parameters not configured")

    # Check HTTPS redirect
    if results.get("https_redirect_configured") is False:
        issues_count += 1
        warnings.append("HTTP to HTTPS redirect not configured")

    # Check ModSecurity WAF
    if results.get("modsecurity_enabled") is False:
        issues_count += 1
        warnings.append("ModSecurity WAF not enabled")

    # Check SSL certificates
    if "certificates" in results:
        for cert in results["certificates"]:
            if cert.get("exists") is False:
                issues_count += 1
                errors.append(f"Certificate not found: {cert['path']}")
            elif cert.get("critical"):
                issues_count += 1
                errors.append(f"Certificate expiring soon: {cert['path']}")

    # Update summary
    report["summary"]["issues_count"] = issues_count
    if issues_count > 0:
        if errors:
            report["summary"]["status"] = "fail"
        else:
            report["summary"]["status"] = "warn"

    report["summary"]["warnings"] = warnings
    report["summary"]["errors"] = errors

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
        # NGINX outputs version to stderr
        version_output = result.stderr
        match = re.search(r'nginx/(\d+\.\d+\.\d+)', version_output)
        if match:
            return match.group(1)
    except Exception:
        pass

    return "unknown"


def main() -> int:
    """
    Main function for the script.

    Returns:
        Exit code: 0 for success, 1 for error
    """
    args = parse_arguments()

    if args.quiet:
        logger.setLevel(logging.WARNING)

    # Check if NGINX is installed and configured
    if not validate_nginx_installation():
        return 1

    # Get all configuration files
    config_files = find_config_files()
    if not config_files:
        logger.error("No NGINX configuration files found")
        return 1

    # Initialize results
    results = {}
    exit_code = 0

    # Test basic syntax
    results["basic_syntax_valid"] = test_basic_syntax(Path(args.config))
    if not results["basic_syntax_valid"]:
        exit_code = 1

    # Check SSL protocols
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

    # SSL certificate checks
    results["certificates"] = check_ssl_certificates(config_files)

    # Generate final report
    report = generate_report(results)

    # Determine exit code
    exit_code = 0
    if report["summary"]["status"] == "warn" and args.strict:
        exit_code = 1
    elif report["summary"]["status"] == "fail":
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
            if report["summary"]["warnings"]:
                logger.warning("Warnings:")
                for warning in report["summary"]["warnings"]:
                    logger.warning(f"  - {warning}")
            if report["summary"]["errors"]:
                logger.error("Errors:")
                for error in report["summary"]["errors"]:
                    logger.error(f"  - {error}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
