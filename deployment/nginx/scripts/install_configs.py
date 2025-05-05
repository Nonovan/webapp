#!/usr/bin/env python3
"""
Install NGINX configurations for Cloud Infrastructure Platform.

This script installs environment-specific NGINX configuration files, creating
necessary directories, managing symlinks, and safely reloading the NGINX service.
It provides a more robust alternative to the bash implementation with better error
handling and validation.
"""

import os
import sys
import shutil
import subprocess
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Union, Tuple

# Default paths
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
NGINX_ROOT = Path("/etc/nginx")
DEFAULT_SOURCE_DIR = SCRIPT_DIR.parent
DEFAULT_BACKUP_DIR = Path("/var/backups/nginx-configs")
DEFAULT_ENVIRONMENT = "production"
VALID_ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]

# Setup logging
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("nginx-config-installer")


def setup_argparse() -> argparse.Namespace:
    """Configure and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Install NGINX configurations for Cloud Infrastructure Platform"
    )
    parser.add_argument(
        "--environment", "-e",
        choices=VALID_ENVIRONMENTS,
        default=DEFAULT_ENVIRONMENT,
        help=f"Environment to install (default: {DEFAULT_ENVIRONMENT})"
    )
    parser.add_argument(
        "--source-dir", "-s",
        type=Path,
        default=DEFAULT_SOURCE_DIR,
        help=f"Source directory for NGINX configs (default: {DEFAULT_SOURCE_DIR})"
    )
    parser.add_argument(
        "--nginx-root", "-n",
        type=Path,
        default=NGINX_ROOT,
        help=f"NGINX installation directory (default: {NGINX_ROOT})"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force overwrite of existing files"
    )
    parser.add_argument(
        "--dry-run", "-d",
        action="store_true",
        help="Don't actually install anything, just show what would be done"
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="Don't restart NGINX after installation"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--backup-dir", "-b",
        type=Path,
        default=DEFAULT_BACKUP_DIR,
        help=f"Directory for configuration backups (default: {DEFAULT_BACKUP_DIR})"
    )
    return parser.parse_args()


def check_nginx_installed() -> bool:
    """Check if NGINX is installed."""
    try:
        subprocess.run(["nginx", "-v"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        return False


def backup_config(nginx_root: Path, backup_dir: Path, dry_run: bool = False) -> Optional[Path]:
    """
    Create a backup of the existing NGINX configuration.

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

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = backup_dir / f"nginx-backup-{timestamp}.tar.gz"

    try:
        # Create backup directory if it doesn't exist
        backup_dir.mkdir(parents=True, exist_ok=True)

        # Use tar to create the backup
        logger.info(f"Backing up existing NGINX configuration to {backup_file}")
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


def ensure_directory(directory: Path, dry_run: bool = False) -> bool:
    """
    Create directory if it doesn't exist.

    Args:
        directory: Path to the directory
        dry_run: If True, don't actually create directory

    Returns:
        True if directory exists or was created successfully
    """
    if directory.exists():
        return True

    if dry_run:
        logger.info(f"[DRY RUN] Would create directory: {directory}")
        return True

    try:
        directory.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {directory}")
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {directory}: {e}")
        return False


def copy_file(src: Path, dst: Path, force: bool = False, dry_run: bool = False) -> bool:
    """
    Copy a file, backing up any existing destination.

    Args:
        src: Source file path
        dst: Destination file path
        force: If True, overwrite existing files
        dry_run: If True, don't actually copy files

    Returns:
        True if copy was successful or not needed
    """
    if not src.exists():
        logger.warning(f"Source file not found: {src}")
        return False

    if dst.exists():
        if not force:
            logger.warning(f"File exists, skipping: {dst}")
            return True

        # Backup before overwriting
        if not dry_run:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup = Path(f"{dst}.{timestamp}.bak")
            logger.info(f"Backing up {dst} to {backup}")
            try:
                shutil.copy2(dst, backup)
            except Exception as e:
                logger.error(f"Failed to backup file {dst}: {e}")
                return False
        else:
            logger.info(f"[DRY RUN] Would backup existing file: {dst}")

    # Parent directory might not exist
    ensure_directory(dst.parent, dry_run)

    if dry_run:
        logger.info(f"[DRY RUN] Would copy {src} to {dst}")
    else:
        try:
            shutil.copy2(src, dst)
            logger.info(f"Copied {src} to {dst}")
        except Exception as e:
            logger.error(f"Failed to copy file {src} to {dst}: {e}")
            return False

    return True


def create_symlink(src: Path, dst: Path, force: bool = False, dry_run: bool = False) -> bool:
    """
    Create a symbolic link, handling existing files/links.

    Args:
        src: Source file path
        dst: Destination symlink path
        force: If True, overwrite existing symlinks
        dry_run: If True, don't actually create symlinks

    Returns:
        True if symlink was successful or not needed
    """
    if dst.exists() or dst.is_symlink():
        if not force:
            logger.warning(f"File/symlink exists, skipping symlink creation: {dst}")
            return True

        # Backup and remove existing file/symlink
        if not dry_run:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup = Path(f"{dst}.{timestamp}.bak")
            logger.info(f"Backing up and removing existing file/symlink: {dst}")
            try:
                if dst.is_symlink() or dst.exists():
                    shutil.move(dst, backup)
            except Exception as e:
                logger.error(f"Failed to backup file/symlink {dst}: {e}")
                return False
        else:
            logger.info(f"[DRY RUN] Would backup and remove existing file/symlink: {dst}")

    # Parent directory might not exist
    ensure_directory(dst.parent, dry_run)

    if dry_run:
        logger.info(f"[DRY RUN] Would create symlink: {dst} -> {src}")
    else:
        try:
            # Use relative paths for symlinks when possible
            try:
                src_rel = os.path.relpath(src, dst.parent)
                os.symlink(src_rel, dst)
                logger.info(f"Created symlink: {dst} -> {src_rel}")
            except ValueError:
                # Fall back to absolute paths if relative path couldn't be determined
                os.symlink(src, dst)
                logger.info(f"Created symlink: {dst} -> {src}")
        except Exception as e:
            logger.error(f"Failed to create symlink from {src} to {dst}: {e}")
            return False

    return True


def generate_config(environment: str, source_dir: Path, force: bool = False, dry_run: bool = False) -> bool:
    """
    Run the config generation script if available.

    Args:
        environment: Target environment
        source_dir: Base directory containing NGINX config
        force: If True, overwrite existing files
        dry_run: If True, don't actually run the script

    Returns:
        True if generation was successful or not needed
    """
    templates_dir = source_dir / "templates"
    output_dir = source_dir / "sites-available"
    script_path = source_dir / "scripts" / "generate-config.py"

    if not script_path.exists():
        logger.warning(f"Configuration generator script not found: {script_path}")
        return True  # Continue with installation even if generator is not available

    logger.info(f"Generating NGINX configuration for {environment} environment")

    cmd = [
        sys.executable,
        str(script_path),
        "--environment",
        environment
    ]

    if force:
        cmd.append("--force")

    if dry_run:
        cmd.append("--dry-run")
        logger.info(f"[DRY RUN] Would run: {' '.join(str(c) for c in cmd)}")
        return True

    try:
        subprocess.run(cmd, check=True)
        logger.info("Configuration generated successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Configuration generation failed: {e}")
        return False


def install_config_files(environment: str, source_dir: Path, nginx_root: Path,
                         force: bool = False, dry_run: bool = False) -> bool:
    """
    Install NGINX configuration files for the specified environment.

    Args:
        environment: Target environment
        source_dir: Base directory containing NGINX config
        nginx_root: NGINX installation directory
        force: If True, overwrite existing files
        dry_run: If True, don't actually install files

    Returns:
        True if installation was successful
    """
    # Create necessary directories
    dirs_to_create = [
        nginx_root / "sites-available",
        nginx_root / "sites-enabled",
        nginx_root / "conf.d",
        nginx_root / "includes"
    ]

    for directory in dirs_to_create:
        if not ensure_directory(directory, dry_run):
            return False

    success = True

    # Install main site configuration based on environment
    if environment == "production":
        site_config = source_dir / "sites-available" / "cloud-platform.conf"
        if site_config.exists():
            success &= copy_file(
                site_config,
                nginx_root / "sites-available" / "cloud-platform.conf",
                force,
                dry_run
            )
            success &= create_symlink(
                nginx_root / "sites-available" / "cloud-platform.conf",
                nginx_root / "sites-enabled" / "cloud-platform.conf",
                force,
                dry_run
            )
        else:
            logger.warning(f"Production configuration not found: {site_config}")

    elif environment == "staging":
        staging_config = source_dir / "sites-available" / "staging.conf"
        if staging_config.exists():
            success &= copy_file(
                staging_config,
                nginx_root / "sites-available" / "staging.conf",
                force,
                dry_run
            )
            success &= create_symlink(
                nginx_root / "sites-available" / "staging.conf",
                nginx_root / "sites-enabled" / "staging.conf",
                force,
                dry_run
            )
        else:
            logger.warning(f"Staging configuration not found: {staging_config}")

    elif environment == "development":
        dev_config = source_dir / "sites-available" / "development.conf"
        if dev_config.exists():
            success &= copy_file(
                dev_config,
                nginx_root / "sites-available" / "development.conf",
                force,
                dry_run
            )
            success &= create_symlink(
                nginx_root / "sites-available" / "development.conf",
                nginx_root / "sites-enabled" / "development.conf",
                force,
                dry_run
            )
        else:
            logger.warning(f"Development configuration not found: {dev_config}")

    elif environment == "dr-recovery":
        dr_config = source_dir / "sites-available" / "dr-recovery.conf"
        if dr_config.exists():
            success &= copy_file(
                dr_config,
                nginx_root / "sites-available" / "dr-recovery.conf",
                force,
                dry_run
            )
            success &= create_symlink(
                nginx_root / "sites-available" / "dr-recovery.conf",
                nginx_root / "sites-enabled" / "dr-recovery.conf",
                force,
                dry_run
            )
        else:
            logger.warning(f"DR recovery configuration not found: {dr_config}")

    # Install conf.d files
    logger.info(f"Installing configuration module files to {nginx_root}/conf.d/")
    confd_dir = source_dir / "conf.d"
    if confd_dir.exists():
        for conf_file in confd_dir.glob("*.conf"):
            success &= copy_file(
                conf_file,
                nginx_root / "conf.d" / conf_file.name,
                force,
                dry_run
            )

    # Install includes files
    logger.info(f"Installing include files to {nginx_root}/includes/")
    includes_dir = source_dir / "includes"
    if includes_dir.exists():
        for include_file in includes_dir.glob("*.conf"):
            success &= copy_file(
                include_file,
                nginx_root / "includes" / include_file.name,
                force,
                dry_run
            )

    # Create security header symlinks if not already done
    security_headers_src = PROJECT_ROOT / "security" / "security-headers.conf"
    ssl_params_src = PROJECT_ROOT / "security" / "ssl-params.conf"

    if security_headers_src.exists():
        success &= create_symlink(
            security_headers_src,
            nginx_root / "conf.d" / "security-headers.conf",
            force,
            dry_run
        )
    else:
        logger.warning(f"Security headers file not found: {security_headers_src}")

    if ssl_params_src.exists():
        success &= create_symlink(
            ssl_params_src,
            nginx_root / "conf.d" / "ssl-params.conf",
            force,
            dry_run
        )
    else:
        logger.warning(f"SSL parameters file not found: {ssl_params_src}")

    return success


def test_config(nginx_root: Path, dry_run: bool = False) -> bool:
    """
    Test the NGINX configuration for errors.

    Args:
        nginx_root: NGINX installation directory
        dry_run: If True, don't actually test the configuration

    Returns:
        True if configuration test passed
    """
    if dry_run:
        logger.info("[DRY RUN] Would test NGINX configuration")
        return True

    logger.info("Testing NGINX configuration")
    try:
        subprocess.run(["nginx", "-t"], check=True, capture_output=True)
        logger.info("NGINX configuration test passed")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"NGINX configuration test failed: {e.stderr.decode() if e.stderr else str(e)}")
        return False


def reload_nginx(restart_nginx: bool = True, dry_run: bool = False) -> bool:
    """
    Reload or restart the NGINX service.

    Args:
        restart_nginx: If True, restart/reload NGINX
        dry_run: If True, don't actually reload NGINX

    Returns:
        True if NGINX was reloaded successfully or not needed
    """
    if not restart_nginx:
        logger.warning("NGINX reload skipped (--no-restart option)")
        return True

    if dry_run:
        logger.info("[DRY RUN] Would reload NGINX")
        return True

    logger.info("Reloading NGINX")

    try:
        # Check if NGINX is running
        nginx_running = subprocess.run(
            ["systemctl", "is-active", "--quiet", "nginx"],
            check=False
        ).returncode == 0

        if nginx_running:
            # Reload NGINX instead of restarting
            subprocess.run(["systemctl", "reload", "nginx"], check=True)
            logger.info("NGINX reloaded successfully")
        else:
            # NGINX is not running, start it
            logger.warning("NGINX is not running, starting it")
            subprocess.run(["systemctl", "start", "nginx"], check=True)
            logger.info("NGINX started successfully")

        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to reload NGINX: {e}")
        return False


def main() -> int:
    """
    Main entry point for the script.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    args = setup_argparse()

    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Validate NGINX installation
    if not check_nginx_installed():
        logger.error("NGINX is not installed")
        return 1

    # Check source directory
    if not args.source_dir.exists():
        logger.error(f"Source directory not found: {args.source_dir}")
        return 1

    if args.dry_run:
        logger.info("DRY RUN: No changes will be made")

    logger.info(f"Installing NGINX configurations for {args.environment} environment")

    # Create backup directory for non-dry runs
    if not args.dry_run:
        ensure_directory(args.backup_dir, False)

    # Backup existing configuration
    backup_config(args.nginx_root, args.backup_dir, args.dry_run)

    # Generate configuration if possible
    if not generate_config(args.environment, args.source_dir, args.force, args.dry_run):
        logger.error("Configuration generation failed")
        return 1

    # Install configuration files
    if not install_config_files(args.environment, args.source_dir, args.nginx_root, args.force, args.dry_run):
        logger.error("Installation failed: Could not install configuration files")
        return 1

    # Test configuration
    if not test_config(args.nginx_root, args.dry_run):
        logger.error("Installation failed: NGINX configuration test failed")
        return 1

    # Reload NGINX
    if not reload_nginx(not args.no_restart, args.dry_run):
        logger.error("Installation failed: Could not reload NGINX")
        return 1

    if not args.dry_run:
        logger.info(f"NGINX configuration installed successfully for {args.environment} environment")
    else:
        logger.info("DRY RUN completed. No changes were made.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
