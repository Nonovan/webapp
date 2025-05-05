#!/usr/bin/env python3
"""
Create Diffie-Hellman parameters for improved SSL security in NGINX.

This script generates secure DH parameters for NGINX SSL/TLS configuration,
updates the ssl-params.conf file to use these parameters, and ensures the
ssl.conf includes the parameters. It strengthens SSL/TLS connections by using
custom Diffie-Hellman parameters instead of the default ones.
"""

import os
import sys
import subprocess
import argparse
import logging
import shutil
import re
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Union

# Configure logging
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("nginx-dhparams")

# Constants
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
NGINX_ROOT = Path("/etc/nginx")
DEFAULT_DH_BITS = 2048
DEFAULT_DH_FILE = NGINX_ROOT / "dhparams.pem"
SSL_PARAMS_CONF = NGINX_ROOT / "conf.d" / "ssl-params.conf"


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Create Diffie-Hellman parameters for improved SSL security"
    )
    parser.add_argument(
        "--bits",
        type=int,
        default=DEFAULT_DH_BITS,
        choices=[2048, 4096],
        help=f"Key size in bits (default: {DEFAULT_DH_BITS})"
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_DH_FILE,
        help=f"Output file path (default: {DEFAULT_DH_FILE})"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force recreation even if file exists"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()


def check_existing_params(dh_file: Path, dh_bits: int) -> Tuple[bool, Optional[int]]:
    """
    Check if DH parameters already exist and estimate their strength.

    Args:
        dh_file: Path to the DH parameters file
        dh_bits: Requested DH parameter size in bits

    Returns:
        Tuple containing (parameters_adequate, estimated_bits)
    """
    if not dh_file.exists():
        logger.info("No existing DH parameters found")
        return False, None

    try:
        # Check file size to estimate bit length
        file_size = dh_file.stat().st_size
        estimated_bits = 0

        if file_size > 600:
            estimated_bits = 4096
        elif file_size > 300:
            estimated_bits = 2048
        else:
            estimated_bits = 1024

        logger.info(f"Existing parameters file: {dh_file}")
        logger.info(f"File size: {file_size} bytes (approximately {estimated_bits} bits)")

        # Display file info
        result = subprocess.run(
            ["openssl", "dhparam", "-in", str(dh_file), "-text", "-noout"],
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout:
            logger.info(f"Parameter info: {result.stdout.splitlines()[0]}")

        # Check if requested bits are larger than current bits
        if dh_bits > estimated_bits:
            logger.warning(
                f"Current parameters appear to be weaker than requested "
                f"({estimated_bits} vs {dh_bits})"
            )
            return False, estimated_bits

        return True, estimated_bits
    except Exception as e:
        logger.error(f"Error checking existing parameters: {e}")
        return False, None


def generate_dhparams(dh_file: Path, dh_bits: int, dry_run: bool = False) -> bool:
    """
    Generate new Diffie-Hellman parameters.

    Args:
        dh_file: Path to save the generated parameters
        dh_bits: Size of the parameters in bits
        dry_run: If True, only show what would be done

    Returns:
        True if generation was successful or would be in dry run mode
    """
    logger.info(f"Generating {dh_bits}-bit Diffie-Hellman parameters...")
    logger.info("This may take a while, especially for 4096-bit keys.")

    # Display estimated time
    if dh_bits == 4096:
        logger.info("Estimated time: 25-45 minutes depending on system resources.")
    else:
        logger.info("Estimated time: 1-3 minutes depending on system resources.")

    if dry_run:
        logger.info(f"[DRY RUN] Would generate {dh_bits}-bit DH parameters at {dh_file}")
        return True

    # Create directory if it doesn't exist
    dh_file.parent.mkdir(parents=True, exist_ok=True)

    # Generate parameters
    start_time = datetime.now()
    logger.info(f"Starting generation at {start_time.strftime('%H:%M:%S')}")

    try:
        subprocess.run(
            ["openssl", "dhparam", "-out", str(dh_file), str(dh_bits)],
            check=True
        )

        # Set proper permissions
        os.chmod(dh_file, 0o644)

        end_time = datetime.now()
        logger.info(f"DH parameters generated successfully at {dh_file}")
        logger.info(f"Completed at {end_time.strftime('%H:%M:%S')}")
        logger.info(f"Generation took: {end_time - start_time}")

        # Display file info
        result = subprocess.run(
            ["openssl", "dhparam", "-in", str(dh_file), "-text", "-noout"],
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout:
            logger.info(f"Parameter info: {result.stdout.splitlines()[0]}")

        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate DH parameters: {e}")
        return False
    except Exception as e:
        logger.error(f"Error during DH parameter generation: {e}")
        return False


def update_ssl_params(ssl_params_conf: Path, dh_file: Path, dry_run: bool = False) -> bool:
    """
    Update ssl-params.conf to use the generated DH parameters.

    Args:
        ssl_params_conf: Path to the ssl-params.conf file
        dh_file: Path to the DH parameters file
        dry_run: If True, only show what would be done

    Returns:
        True if update was successful or would be in dry run mode
    """
    logger.info("Updating SSL parameters configuration...")

    ssl_params_src = PROJECT_ROOT / "deployment" / "security" / "ssl-params.conf"

    # Convert dh_file to string for use in content
    dh_file_str = str(dh_file)

    if dry_run:
        logger.info(f"[DRY RUN] Would update SSL parameters configuration at {ssl_params_conf}")
        return True

    try:
        # Check if ssl-params.conf already exists
        if ssl_params_conf.exists():
            logger.info(f"Updating existing SSL parameters at {ssl_params_conf}")

            with open(ssl_params_conf, 'r') as f:
                content = f.read()

            # Update the dhparam path if it exists in the file
            if re.search(r'ssl_dhparam\s+[^;]+;', content):
                content = re.sub(
                    r'ssl_dhparam\s+[^;]+;',
                    f'ssl_dhparam {dh_file_str};',
                    content
                )
                with open(ssl_params_conf, 'w') as f:
                    f.write(content)
            else:
                # Add dhparam directive if it doesn't exist
                with open(ssl_params_conf, 'a') as f:
                    f.write(f"\n# DH parameters\nssl_dhparam {dh_file_str};\n")
        else:
            # Check if we have a template to copy from
            if ssl_params_src.exists():
                logger.info(f"Using SSL parameters template from {ssl_params_src}")

                # Create parent directory if needed
                ssl_params_conf.parent.mkdir(parents=True, exist_ok=True)

                # Copy the template
                shutil.copy2(ssl_params_src, ssl_params_conf)

                # Update the dhparam path
                with open(ssl_params_conf, 'r') as f:
                    content = f.read()

                if re.search(r'ssl_dhparam\s+[^;]+;', content):
                    content = re.sub(
                        r'ssl_dhparam\s+[^;]+;',
                        f'ssl_dhparam {dh_file_str};',
                        content
                    )
                else:
                    content += f"\n# DH parameters\nssl_dhparam {dh_file_str};\n"

                with open(ssl_params_conf, 'w') as f:
                    f.write(content)
            else:
                # Create a basic ssl-params.conf if no template exists
                logger.info("Creating basic SSL parameters configuration")

                # Create parent directory if needed
                ssl_params_conf.parent.mkdir(parents=True, exist_ok=True)

                with open(ssl_params_conf, 'w') as f:
                    f.write(f"""# SSL Parameters Configuration for Cloud Infrastructure Platform
# Generated on {datetime.now().strftime('%Y-%m-%d')}

# SSL protocols and ciphers
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

# DH parameters
ssl_dhparam {dh_file_str};

# SSL session settings
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
""")

        logger.info("SSL parameters configuration updated successfully")
        return True
    except Exception as e:
        logger.error(f"Error updating SSL parameters: {e}")
        return False


def update_ssl_conf(nginx_root: Path, dry_run: bool = False) -> bool:
    """
    Update ssl.conf to include ssl-params.conf if needed.

    Args:
        nginx_root: Path to NGINX root directory
        dry_run: If True, only show what would be done

    Returns:
        True if update was successful or would be in dry run mode
    """
    ssl_conf = nginx_root / "conf.d" / "ssl.conf"

    if not ssl_conf.exists():
        logger.info(f"SSL configuration file {ssl_conf} not found, skipping update")
        return True

    logger.info("Checking if SSL configuration includes SSL parameters...")

    if dry_run:
        logger.info(f"[DRY RUN] Would update SSL configuration at {ssl_conf} if needed")
        return True

    try:
        with open(ssl_conf, 'r') as f:
            content = f.read()

        # Check if include directive already exists
        if not re.search(r'include\s+.*ssl-params.conf', content):
            logger.info(f"Adding SSL parameters include to {ssl_conf}")

            # Add include before the first ssl_certificate line
            pattern = r'(\s*ssl_certificate\s+)'
            replacement = r'include conf.d/ssl-params.conf;\n\n\1'
            new_content = re.sub(pattern, replacement, content, count=1)

            with open(ssl_conf, 'w') as f:
                f.write(new_content)

            logger.info("SSL configuration updated to include SSL parameters")
        else:
            logger.info("SSL configuration already includes SSL parameters")

        return True
    except Exception as e:
        logger.error(f"Error updating SSL configuration: {e}")
        return False


def test_nginx_config(dry_run: bool = False) -> bool:
    """
    Test the NGINX configuration.

    Args:
        dry_run: If True, only show what would be done

    Returns:
        True if test was successful or would be in dry run mode
    """
    logger.info("Testing NGINX configuration...")

    if dry_run:
        logger.info("[DRY RUN] Would test NGINX configuration")
        return True

    try:
        subprocess.run(
            ["nginx", "-t"],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("NGINX configuration test passed")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"NGINX configuration test failed: {e.stderr}")
        return False


def reload_nginx(dry_run: bool = False) -> bool:
    """
    Reload NGINX to apply the new configuration.

    Args:
        dry_run: If True, only show what would be done

    Returns:
        True if reload was successful or would be in dry run mode
    """
    logger.info("Reloading NGINX...")

    if dry_run:
        logger.info("[DRY RUN] Would reload NGINX")
        return True

    try:
        subprocess.run(
            ["systemctl", "reload", "nginx"],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("NGINX reloaded successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to reload NGINX: {e.stderr}")
        return False


def validate_requirements() -> bool:
    """
    Validate that all required components are installed.

    Returns:
        True if all requirements are met
    """
    # Check if running as root
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        return False

    # Check if NGINX is installed
    try:
        subprocess.run(
            ["nginx", "-v"],
            check=True,
            capture_output=True
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error("NGINX is not installed")
        return False

    # Check if OpenSSL is installed
    try:
        subprocess.run(
            ["openssl", "version"],
            check=True,
            capture_output=True
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error("OpenSSL is not installed")
        return False

    return True


def main() -> int:
    """
    Main entry point for the script.

    Returns:
        0 on success, non-zero on error
    """
    args = parse_arguments()

    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Get parameters
    dh_file = args.file
    dh_bits = args.bits
    force = args.force
    dry_run = args.dry_run

    logger.info("Starting Diffie-Hellman parameters setup")

    # Validate requirements
    if not validate_requirements() and not dry_run:
        return 1

    # Check existing parameters if they exist
    need_generation = True
    if dh_file.exists() and not force:
        adequate, estimated_bits = check_existing_params(dh_file, dh_bits)
        if adequate:
            logger.info(f"Existing DH parameters are adequate ({estimated_bits} bits)")
            need_generation = False

    # Generate parameters if needed
    if need_generation:
        if not generate_dhparams(dh_file, dh_bits, dry_run):
            logger.error("Failed to generate DH parameters")
            return 1

    # Update ssl-params.conf to use the new parameters
    if not update_ssl_params(SSL_PARAMS_CONF, dh_file, dry_run):
        logger.error("Failed to update SSL parameters configuration")
        return 1

    # Update ssl.conf to include ssl-params.conf
    if not update_ssl_conf(NGINX_ROOT, dry_run):
        logger.error("Failed to update SSL configuration")
        return 1

    # Test NGINX configuration
    if not test_nginx_config(dry_run):
        logger.error("NGINX configuration test failed")
        return 1

    # Reload NGINX
    if not reload_nginx(dry_run):
        logger.error("Failed to reload NGINX")
        return 1

    logger.info("Diffie-Hellman parameters setup completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
