#!/usr/bin/env python3
"""
NGINX Configuration Reload Utility for Cloud Infrastructure Platform.

This module provides functions for safely reloading NGINX configuration with
pre-reload validation and post-reload verification. It implements backup
creation, configuration change detection, graceful reload, and health checking.
"""

import os
import sys
import subprocess
import logging
import argparse
import datetime
import time
import re
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

# Set up logging
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("nginx-reload")

# Define constants
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
NGINX_ROOT = Path("/etc/nginx")
NGINX_CONF = NGINX_ROOT / "nginx.conf"
BACKUP_DIR = Path("/var/backups/nginx-configs")
LOG_FILE = Path("/var/log/cloud-platform/nginx-reload.log")
DEFAULT_TIMEOUT = 30


def setup_file_logging(log_file: Path, dry_run: bool = False):
    """
    Set up file logging in addition to console logging.

    Args:
        log_file: Path to the log file
        dry_run: If True, don't create log file
    """
    if dry_run:
        return

    try:
        # Create directory if it doesn't exist
        log_file.parent.mkdir(parents=True, exist_ok=True)

        # Add file handler
        file_handler = logging.FileHandler(str(log_file))
        file_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not set up file logging: {e}")


def check_nginx_installed() -> bool:
    """
    Check if NGINX is installed on the system.

    Returns:
        True if NGINX is installed, False otherwise
    """
    try:
        subprocess.run(["nginx", "-v"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        return False


def check_nginx_running() -> bool:
    """
    Check if NGINX service is currently running.

    Returns:
        True if NGINX is running, False otherwise
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", "nginx"],
            check=False
        )
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Error checking if NGINX is running: {e}")
        return False


def backup_config(nginx_root: Path, backup_dir: Path, dry_run: bool = False) -> Optional[Path]:
    """
    Create a backup of the NGINX configuration.

    Args:
        nginx_root: Path to NGINX installation directory
        backup_dir: Directory to store backups
        dry_run: If True, don't actually create backups

    Returns:
        Path to the backup file or None if dry run or error
    """
    if dry_run:
        logger.info("[DRY RUN] Would back up NGINX configuration")
        return None

    if not nginx_root.exists():
        logger.warning(f"NGINX root directory {nginx_root} not found, no backup needed")
        return None

    # Create backup directory if it doesn't exist
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create backup directory: {e}")
        return None

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = backup_dir / f"nginx-config-{timestamp}.tar.gz"

    try:
        logger.info(f"Creating backup of NGINX configuration to {backup_file}")
        subprocess.run(
            ["tar", "-czf", str(backup_file), "-C", str(nginx_root), "."],
            check=True,
            stderr=subprocess.PIPE
        )
        logger.info("Backup created successfully")
        return backup_file
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create backup: {e.stderr.decode() if e.stderr else str(e)}")
        return None
    except Exception as e:
        logger.error(f"Failed to create backup: {str(e)}")
        return None


def check_config_changes(nginx_root: Path) -> bool:
    """
    Check if any NGINX configuration file has been modified since last reload.

    Args:
        nginx_root: Path to NGINX installation directory

    Returns:
        True if changes detected or couldn't determine, False if no changes
    """
    try:
        # Get the last reload time from systemd
        result = subprocess.run(
            ["systemctl", "show", "nginx"],
            capture_output=True,
            text=True,
            check=True
        )

        # Extract timestamp from systemd information
        match = re.search(r"ExecMainStartTimestamp=(.+)$", result.stdout, re.MULTILINE)
        if not match:
            logger.warning("Could not determine last reload time, proceeding with reload")
            return True

        last_reload_time = match.group(1)

        # Convert to unix timestamp
        try:
            last_reload_unix = int(datetime.datetime.strptime(
                last_reload_time,
                "%a %Y-%m-%d %H:%M:%S %Z"
            ).timestamp())
        except ValueError:
            logger.warning("Error parsing last reload time, proceeding with reload")
            return True

        # Check if any configuration file has been modified since last reload
        any_changes = False
        conf_files = list(nginx_root.glob("**/*.conf"))

        for file_path in conf_files:
            mod_time = int(file_path.stat().st_mtime)
            if mod_time > last_reload_unix:
                logger.info(f"Configuration file changed since last reload: {file_path}")
                any_changes = True

        if any_changes:
            return True
        else:
            logger.info("No configuration changes detected since last reload")
            return False

    except Exception as e:
        logger.warning(f"Error checking for configuration changes: {e}")
        # Proceed with reload if we couldn't determine
        return True


def test_config(dry_run: bool = False) -> bool:
    """
    Test the NGINX configuration for syntax errors.

    Args:
        dry_run: If True, don't actually test configuration

    Returns:
        True if configuration test passed or dry run, False otherwise
    """
    if dry_run:
        logger.info("[DRY RUN] Would test NGINX configuration")
        return True

    logger.info("Testing NGINX configuration")
    try:
        result = subprocess.run(
            ["nginx", "-t"],
            capture_output=True,
            text=True,
            check=False
        )

        # Output the result regardless of success/failure
        if result.stdout:
            logger.info(result.stdout)
        if result.stderr:
            if result.returncode == 0:
                logger.info(result.stderr)
            else:
                logger.error(result.stderr)

        if result.returncode == 0:
            logger.info("NGINX configuration test passed")
            return True
        else:
            logger.error("NGINX configuration test failed")
            return False
    except Exception as e:
        logger.error(f"Error testing NGINX configuration: {e}")
        return False


def reload_nginx(graceful: bool = True, dry_run: bool = False) -> bool:
    """
    Reload or restart the NGINX service.

    Args:
        graceful: If True, reload gracefully (keeping connections)
        dry_run: If True, don't actually reload NGINX

    Returns:
        True if NGINX was reloaded successfully or in dry run, False otherwise
    """
    if dry_run:
        if graceful:
            logger.info("[DRY RUN] Would reload NGINX configuration")
        else:
            logger.info("[DRY RUN] Would restart NGINX")
        return True

    is_running = check_nginx_running()

    if is_running and graceful:
        logger.info("Reloading NGINX configuration...")
        try:
            subprocess.run(["systemctl", "reload", "nginx"], check=True)
            logger.info("NGINX reloaded successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to reload NGINX: {e}")
            return False

    elif is_running and not graceful:
        logger.info("Restarting NGINX...")
        try:
            subprocess.run(["systemctl", "restart", "nginx"], check=True)
            logger.info("NGINX restarted successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restart NGINX: {e}")
            return False

    else:
        logger.warning("NGINX is not running, starting it...")
        try:
            subprocess.run(["systemctl", "start", "nginx"], check=True)
            logger.info("NGINX started successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start NGINX: {e}")
            return False


def restart_nginx(dry_run: bool = False) -> bool:
    """
    Restart the NGINX service (wrapper for reload_nginx with graceful=False).

    Args:
        dry_run: If True, don't actually restart NGINX

    Returns:
        True if NGINX was restarted successfully or in dry run, False otherwise
    """
    return reload_nginx(graceful=False, dry_run=dry_run)


def verify_nginx_responding(timeout: int = DEFAULT_TIMEOUT, dry_run: bool = False) -> bool:
    """
    Verify NGINX is responding after reload.

    Args:
        timeout: Time in seconds to wait for NGINX to respond
        dry_run: If True, don't perform verification

    Returns:
        True if NGINX is responding or in dry run, False otherwise
    """
    if dry_run:
        logger.info("[DRY RUN] Would verify NGINX is responding")
        return True

    logger.info("Verifying NGINX is responding...")

    # Try to connect to NGINX using curl for $timeout seconds
    end_time = time.time() + timeout
    success = False

    while time.time() < end_time:
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "2", "http://localhost/"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if result.returncode == 0:
                success = True
                break
        except Exception:
            pass
        time.sleep(1)

    if success:
        logger.info("NGINX is responding")
        return True
    else:
        logger.error(f"NGINX is not responding after {timeout} seconds")
        return False


def check_ssl_certs(nginx_root: Path, dry_run: bool = False) -> bool:
    """
    Check for potential SSL certificate issues.

    Args:
        nginx_root: Path to NGINX installation directory
        dry_run: If True, don't actually check certificates

    Returns:
        True if no issues or in dry run, False if issues found
    """
    if dry_run:
        logger.info("[DRY RUN] Would check SSL certificates")
        return True

    logger.info("Checking SSL certificates...")

    # Find SSL certificate paths in configurations
    try:
        result = subprocess.run(
            f"grep -r 'ssl_certificate' --include='*.conf' {nginx_root} | "
            "awk '{print $2}' | tr -d ';' | sort | uniq",
            shell=True,
            check=False,
            capture_output=True,
            text=True
        )

        ssl_paths = [path.strip() for path in result.stdout.splitlines() if path.strip()]

        if not ssl_paths:
            logger.warning("No SSL certificates found in configuration")
            return True

        has_errors = False

        for cert_path in ssl_paths:
            if not os.path.isfile(cert_path):
                logger.error(f"Certificate file not found: {cert_path}")
                has_errors = True
                continue

            # Check expiry date
            try:
                result = subprocess.run(
                    ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
                    check=True,
                    capture_output=True,
                    text=True
                )

                expiry_date = result.stdout.split('=')[1].strip()
                expiry_epoch = int(datetime.datetime.strptime(expiry_date, "%b %d %H:%M:%S %Y %Z").timestamp())
                current_epoch = int(time.time())
                days_left = (expiry_epoch - current_epoch) // 86400

                if days_left < 30:
                    if days_left < 7:
                        logger.error(f"Certificate {cert_path} will expire in {days_left} days")
                        has_errors = True
                    else:
                        logger.warning(f"Certificate {cert_path} will expire in {days_left} days")
                else:
                    logger.info(f"Certificate {cert_path} valid for {days_left} days")

            except Exception as e:
                logger.error(f"Error reading certificate {cert_path}: {e}")
                has_errors = True

        if has_errors:
            logger.warning("There are SSL certificate issues that should be addressed")
            return False

        return True

    except Exception as e:
        logger.error(f"Error checking SSL certificates: {e}")
        return False


def check_nginx_status(dry_run: bool = False) -> None:
    """
    Check and display NGINX status details.

    Args:
        dry_run: If True, don't actually check status
    """
    if dry_run:
        logger.info("[DRY RUN] Would check NGINX status")
        return

    logger.info("Checking NGINX status...")

    # Get current connections
    try:
        result = subprocess.run(
            ["ss", "-ant"],
            capture_output=True,
            text=True,
            check=True
        )
        connections = len([line for line in result.stdout.splitlines() if "ESTAB" in line])
        logger.info(f"Current established connections: {connections}")
    except Exception as e:
        logger.warning(f"Could not determine connection count: {e}")

    # Check if NGINX is running with the expected user
    try:
        result = subprocess.run(
            ["ps", "-eo", "user,comm"],
            capture_output=True,
            text=True,
            check=True
        )

        nginx_users = [
            line.split()[0] for line in result.stdout.splitlines()
            if "nginx" in line and "grep" not in line
        ]

        if nginx_users:
            logger.info(f"NGINX running as user: {nginx_users[0]}")
        else:
            logger.warning("Could not determine NGINX user")
    except Exception as e:
        logger.warning(f"Could not determine NGINX user: {e}")

    # Show NGINX version
    try:
        result = subprocess.run(
            ["nginx", "-v"],
            capture_output=True,
            text=True,
            check=True
        )
        nginx_version = result.stderr.strip() if result.stderr else "unknown"
        logger.info(f"NGINX version: {nginx_version}")
    except Exception as e:
        logger.warning(f"Could not determine NGINX version: {e}")

    # Check for pending restart
    try:
        daemon_reload_check = subprocess.run(
            ["systemctl", "show", "-p", "NeedDaemonReload", "nginx"],
            capture_output=True,
            text=True,
            check=True
        )

        if "NeedDaemonReload=yes" in daemon_reload_check.stdout:
            logger.warning("NGINX needs daemon reload")
    except Exception as e:
        logger.debug(f"Could not check daemon reload status: {e}")


def main() -> int:
    """
    Main function for the NGINX reload utility.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Parse arguments
    parser = argparse.ArgumentParser(description='NGINX Configuration Reload Utility')
    parser.add_argument('--graceful', action='store_true', default=True,
                        help='Reload gracefully, keeping connections (default)')
    parser.add_argument('--restart', action='store_false', dest='graceful',
                        help='Restart NGINX instead of reloading (closes connections)')
    parser.add_argument('--force', action='store_true', default=False,
                        help='Force reload even if config test fails (dangerous)')
    parser.add_argument('--skip-test', action='store_true', default=False,
                        help='Skip configuration test and reload directly')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'Wait N seconds for NGINX to reload (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--reload-only', action='store_true', default=False,
                        help="Only reload, don't check for changed files")
    parser.add_argument('--dry-run', action='store_true', default=False,
                        help="Show what would be done without doing it")
    args = parser.parse_args()

    # Setup logging to file if not in dry run mode
    setup_file_logging(LOG_FILE, args.dry_run)

    logger.info("Starting NGINX configuration reload...")

    # Check if NGINX is installed
    if not check_nginx_installed():
        logger.error("NGINX is not installed")
        return 1

    # Create backup of current configuration
    backup_config(NGINX_ROOT, BACKUP_DIR, args.dry_run)

    # Check if we need to reload (if not in reload-only mode)
    if not args.reload_only:
        if not check_config_changes(NGINX_ROOT):
            logger.info("No changes detected since last reload, exiting")
            return 0

    # Check for SSL certificate issues
    check_ssl_certs(NGINX_ROOT, args.dry_run)

    # Test configuration
    if not args.skip_test:
        if not test_config(args.dry_run) and not args.force:
            logger.error("Configuration test failed. Not reloading NGINX.")
            logger.error("Use --force to reload anyway (dangerous).")
            return 1
    else:
        logger.warning("Skipping configuration test (--skip-test)")

    # Reload or restart NGINX
    if not reload_nginx(args.graceful, args.dry_run):
        logger.error("Failed to reload/restart NGINX")
        return 1

    # Verify NGINX is responding
    if not verify_nginx_responding(args.timeout, args.dry_run):
        logger.error("NGINX may not be fully operational after reload.")
        logger.error("Check the error logs for more details: /var/log/nginx/error.log")
        return 1

    # Show NGINX status
    check_nginx_status(args.dry_run)

    logger.info("NGINX reload/restart completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
