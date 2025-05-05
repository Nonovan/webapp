#!/usr/bin/env python3
"""
SSL Certificate Setup Script for NGINX in Cloud Infrastructure Platform.

This script automates SSL/TLS certificate installation and configuration,
supporting Let's Encrypt, self-signed certificates, and importing existing
certificates. It implements security best practices, including proper DH parameter
generation, secure cipher configuration, and security headers.
"""

import os
import sys
import subprocess
import argparse
import logging
import shutil
import datetime
import tempfile
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, Union

# Set up logging
logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Base directories
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
NGINX_ROOT = Path("/etc/nginx")
DEFAULT_CERT_DIR = Path("/etc/ssl/cloud-platform")

# Default values
DEFAULT_ENVIRONMENT = "production"
DEFAULT_CERT_TYPE = "letsencrypt"
DEFAULT_KEY_SIZE = 4096
DEFAULT_DHPARAM_SIZE = 2048
VALID_ENVIRONMENTS = ["development", "staging", "production", "dr-recovery"]
VALID_CERT_TYPES = ["letsencrypt", "self-signed", "import"]


def ensure_directory(directory_path: Path, dry_run: bool = False) -> bool:
    """
    Ensure that the specified directory exists.

    Args:
        directory_path: The directory path to create
        dry_run: If True, don't actually create, just log what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    if directory_path.exists():
        return True

    if dry_run:
        logger.info(f"[DRY RUN] Would create directory: {directory_path}")
        return True

    try:
        directory_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {directory_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {directory_path}: {e}")
        return False


def check_certbot_installed() -> bool:
    """Check if certbot is installed."""
    try:
        subprocess.run(["which", "certbot"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False


def check_openssl_installed() -> bool:
    """Check if openssl is installed."""
    try:
        subprocess.run(["which", "openssl"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False


def check_nginx_installed() -> bool:
    """Check if NGINX is installed."""
    try:
        subprocess.run(["which", "nginx"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False


def create_self_signed_cert(
    domain: str,
    cert_dir: Path,
    environment: str,
    key_size: int,
    dry_run: bool = False
) -> bool:
    """
    Generate a self-signed SSL certificate.

    Args:
        domain: Domain name for certificate
        cert_dir: Directory to store certificates
        environment: Environment (production, staging, etc.)
        key_size: RSA key size in bits
        dry_run: If True, don't actually generate, just log what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Generating self-signed certificate for {domain}")

    if dry_run:
        logger.info(f"[DRY RUN] Would generate self-signed certificate in {cert_dir}")
        return True

    # Create certificate directory
    if not ensure_directory(cert_dir, dry_run):
        return False

    # Set secure permissions
    os.chmod(cert_dir, 0o700)

    # Generate private key
    privkey_path = cert_dir / "privkey.pem"
    try:
        logger.info("Generating private key...")
        subprocess.run([
            "openssl", "genrsa",
            "-out", str(privkey_path),
            str(key_size)
        ], check=True)
        os.chmod(privkey_path, 0o600)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate private key: {e}")
        return False

    # Create CSR configuration file
    openssl_cnf = cert_dir / "openssl.cnf"
    with open(openssl_cnf, 'w') as f:
        f.write(f"""[req]
default_bits = {key_size}
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = {domain}
O = Cloud Infrastructure Platform
OU = {environment}
C = US
ST = California
L = San Francisco

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = {domain}
DNS.2 = www.{domain}
""")

    # Create CSR
    csr_path = cert_dir / "request.csr"
    try:
        logger.info("Creating certificate signing request...")
        subprocess.run([
            "openssl", "req", "-new",
            "-key", str(privkey_path),
            "-out", str(csr_path),
            "-config", str(openssl_cnf)
        ], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create CSR: {e}")
        return False

    # Create self-signed certificate
    cert_path = cert_dir / "cert.pem"
    try:
        logger.info("Self-signing certificate...")
        subprocess.run([
            "openssl", "x509", "-req",
            "-in", str(csr_path),
            "-signkey", str(privkey_path),
            "-out", str(cert_path),
            "-days", "365",
            "-sha256",
            "-extensions", "req_ext",
            "-extfile", str(openssl_cnf)
        ], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create self-signed certificate: {e}")
        return False

    # Create chain and fullchain files (for compatibility with Let's Encrypt paths)
    try:
        shutil.copy(cert_path, cert_dir / "chain.pem")
        shutil.copy(cert_path, cert_dir / "fullchain.pem")
    except Exception as e:
        logger.error(f"Failed to create chain files: {e}")
        return False

    logger.info(f"✓ Self-signed certificate generated successfully in {cert_dir}")

    # Display certificate information
    try:
        result = subprocess.run([
            "openssl", "x509", "-in", str(cert_path), "-text", "-noout"
        ], check=True, stdout=subprocess.PIPE, text=True)
        logger.info("Certificate information:\n" + "\n".join(result.stdout.splitlines()[:10]))
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to display certificate information: {e}")

    return True


def create_letsencrypt_cert(
    domain: str,
    cert_dir: Path,
    email: str,
    environment: str,
    force: bool = False,
    dry_run: bool = False
) -> bool:
    """
    Request a Let's Encrypt certificate using certbot.

    Args:
        domain: Domain name for certificate
        cert_dir: Directory to store certificates
        email: Email for Let's Encrypt registration
        environment: Environment (production, staging, etc.)
        force: Force certificate renewal
        dry_run: If True, don't actually request, just log what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Requesting Let's Encrypt certificate for {domain}")

    # Check if certbot is installed
    if not check_certbot_installed():
        logger.error("certbot is not installed. Please install it first.")
        logger.error("On Ubuntu/Debian: apt-get install certbot python3-certbot-nginx")
        logger.error("On CentOS/RHEL: yum install certbot python3-certbot-nginx")
        return False

    if dry_run:
        logger.info(f"[DRY RUN] Would request Let's Encrypt certificate for {domain}")
        return True

    # Create webroot directory if it doesn't exist
    webroot = Path("/var/www/html")
    acme_dir = webroot / ".well-known" / "acme-challenge"
    ensure_directory(acme_dir, dry_run)

    if not dry_run:
        os.chmod(acme_dir, 0o755)

    # Create certificate directory
    ensure_directory(cert_dir, dry_run)

    # Build certbot command
    certbot_cmd = [
        "certbot", "certonly", "--webroot",
        "-w", str(webroot),
        "-d", domain, "-d", f"www.{domain}",
        "--email", email,
        "--agree-tos",
        "--non-interactive"
    ]

    # Add options
    if force:
        certbot_cmd.append("--force-renewal")

    # Add staging flag for non-production environments
    if environment != "production":
        certbot_cmd.append("--staging")

    # Run certbot
    logger.info(f"Running certbot: {' '.join(certbot_cmd)}")
    try:
        subprocess.run(certbot_cmd, check=True)
        logger.info("✓ Let's Encrypt certificate obtained successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to obtain Let's Encrypt certificate: {e}")
        return False

    # Copy certificates to our directory
    letsencrypt_dir = Path(f"/etc/letsencrypt/live/{domain}")
    if letsencrypt_dir.exists():
        logger.info(f"Copying certificates to {cert_dir}")
        try:
            shutil.copy(letsencrypt_dir / "privkey.pem", cert_dir / "privkey.pem")
            shutil.copy(letsencrypt_dir / "cert.pem", cert_dir / "cert.pem")
            shutil.copy(letsencrypt_dir / "chain.pem", cert_dir / "chain.pem")
            shutil.copy(letsencrypt_dir / "fullchain.pem", cert_dir / "fullchain.pem")

            # Set proper permissions
            os.chmod(cert_dir / "privkey.pem", 0o600)

            return True
        except Exception as e:
            logger.error(f"Failed to copy certificates: {e}")
            return False
    else:
        logger.error(f"Let's Encrypt directory not found at {letsencrypt_dir}")
        return False


def import_certificates(
    domain: str,
    cert_dir: Path,
    source_privkey: str,
    source_fullchain: str,
    dry_run: bool = False
) -> bool:
    """
    Import existing certificates.

    Args:
        domain: Domain name for the certificate
        cert_dir: Directory to store certificates
        source_privkey: Path to the source private key file
        source_fullchain: Path to the source fullchain certificate file
        dry_run: If True, don't actually import, just log what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Importing existing certificates for {domain}")

    # Check source files
    privkey_path = Path(source_privkey)
    fullchain_path = Path(source_fullchain)

    if not privkey_path.exists():
        logger.error(f"Private key file not found: {source_privkey}")
        return False

    if not fullchain_path.exists():
        logger.error(f"Full chain certificate file not found: {source_fullchain}")
        return False

    if dry_run:
        logger.info(f"[DRY RUN] Would import certificates from {source_privkey} and {source_fullchain} to {cert_dir}")
        return True

    # Create certificate directory
    if not ensure_directory(cert_dir, dry_run):
        return False

    os.chmod(cert_dir, 0o700)

    # Copy certificate files
    try:
        shutil.copy(privkey_path, cert_dir / "privkey.pem")
        shutil.copy(fullchain_path, cert_dir / "fullchain.pem")

        # Set proper permissions
        os.chmod(cert_dir / "privkey.pem", 0o600)
        os.chmod(cert_dir / "fullchain.pem", 0o644)

        logger.info(f"✓ Certificates imported successfully to {cert_dir}")
        return True
    except Exception as e:
        logger.error(f"Failed to import certificates: {e}")
        return False


def generate_dhparams(
    nginx_root: Path,
    dhparam_size: int,
    force: bool = False,
    create_dhparams: bool = True,
    dry_run: bool = False
) -> bool:
    """
    Generate Diffie-Hellman parameters for improved SSL security.

    Args:
        nginx_root: NGINX root directory
        dhparam_size: DH parameter size in bits (2048 or 4096)
        force: Force regeneration even if file exists
        create_dhparams: Whether to create DH parameters
        dry_run: If True, don't actually generate, just log what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    if not create_dhparams:
        logger.info("Skipping DH parameters generation (--no-dhparams specified)")
        return True

    dhparam_file = nginx_root / "dhparams.pem"

    # Check if DH params already exist and we're not forcing recreation
    if dhparam_file.exists() and not force:
        logger.info(f"DH parameters already exist at {dhparam_file}. Use --force to regenerate.")
        return True

    logger.info(f"Generating {dhparam_size}-bit Diffie-Hellman parameters...")
    logger.info("This may take a while, especially for larger key sizes.")

    if dry_run:
        logger.info(f"[DRY RUN] Would generate {dhparam_size}-bit DH parameters at {dhparam_file}")
        return True

    try:
        subprocess.run([
            "openssl", "dhparam",
            "-out", str(dhparam_file),
            str(dhparam_size)
        ], check=True)
        os.chmod(dhparam_file, 0o644)
        logger.info(f"✓ DH parameters generated successfully at {dhparam_file}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate DH parameters: {e}")
        return False


def configure_ssl(
    domain: str,
    cert_dir: Path,
    nginx_root: Path,
    use_security_headers: bool = True,
    force: bool = False,
    dry_run: bool = False
) -> bool:
    """
    Create or update SSL configuration for NGINX.

    Args:
        domain: Domain name for certificate
        cert_dir: Directory where certificates are stored
        nginx_root: NGINX root directory
        use_security_headers: Whether to configure security headers
        force: Force overwrite of existing configuration
        dry_run: If True, don't actually configure, just log what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    logger.info("Configuring NGINX for SSL")

    # Create conf.d directory if it doesn't exist
    conf_d_dir = nginx_root / "conf.d"
    if not ensure_directory(conf_d_dir, dry_run):
        return False

    if dry_run:
        logger.info("[DRY RUN] Would create/update SSL configuration files")
        return True

    # Create SSL parameters file
    ssl_params_conf = conf_d_dir / "ssl-params.conf"
    if not ssl_params_conf.exists() or force:
        logger.info("Creating SSL parameters configuration")
        with open(ssl_params_conf, 'w') as f:
            f.write(f"""# SSL Parameters Configuration for Cloud Infrastructure Platform
# Generated on {datetime.datetime.now().strftime('%Y-%m-%d')}

# SSL protocols and ciphers
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

# DH parameters
ssl_dhparam {nginx_root}/dhparams.pem;

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

    # Create main SSL configuration file
    ssl_conf = conf_d_dir / "ssl.conf"
    if not ssl_conf.exists() or force:
        logger.info("Creating main SSL configuration")
        with open(ssl_conf, 'w') as f:
            f.write(f"""# SSL Configuration for Cloud Infrastructure Platform
# This file configures SSL/TLS settings for NGINX servers

# Include the SSL parameters file
include {nginx_root}/conf.d/ssl-params.conf;

# SSL certificate paths
ssl_certificate {cert_dir}/fullchain.pem;
ssl_certificate_key {cert_dir}/privkey.pem;

# Diffie-Hellman parameters for improved security
ssl_dhparam {nginx_root}/dhparams.pem;

# OCSP Stapling setup
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

# SSL session settings
ssl_session_timeout 24h;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
""")
    else:
        logger.info("Updating certificate paths in SSL configuration")
        with open(ssl_conf, 'r') as f:
            content = f.read()

        content = re.sub(r'ssl_certificate .*', f'ssl_certificate {cert_dir}/fullchain.pem;', content)
        content = re.sub(r'ssl_certificate_key .*', f'ssl_certificate_key {cert_dir}/privkey.pem;', content)

        with open(ssl_conf, 'w') as f:
            f.write(content)

    # Ensure security headers are set up if requested
    if use_security_headers:
        security_headers_conf = conf_d_dir / "security-headers.conf"
        security_headers_src = PROJECT_ROOT / "deployment" / "security" / "security-headers.conf"

        if security_headers_src.exists():
            logger.info(f"Using security headers from {security_headers_src}")
            shutil.copy(security_headers_src, security_headers_conf)
        elif not security_headers_conf.exists():
            logger.info("Creating security headers configuration")
            with open(security_headers_conf, 'w') as f:
                f.write(f"""# Security Headers Configuration for Cloud Infrastructure Platform
# Generated on {datetime.datetime.now().strftime('%Y-%m-%d')}

# Content Security Policy (CSP)
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none';" always;

# HTTP Strict Transport Security (HSTS)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Prevent clickjacking attacks
add_header X-Frame-Options "DENY" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# Configure Cross-site scripting (XSS) Protection
add_header X-XSS-Protection "1; mode=block" always;

# Set referrer policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Set permissions policy
add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), accelerometer=(), gyroscope=()" always;

# Hide NGINX version
server_tokens off;
""")

    logger.info("✓ SSL configuration completed")
    return True


def verify_certificate(cert_dir: Path) -> bool:
    """
    Verify certificate and display information.

    Args:
        cert_dir: Directory where certificates are stored

    Returns:
        bool: True if verification is successful, False otherwise
    """
    fullchain_path = cert_dir / "fullchain.pem"
    if not fullchain_path.exists():
        logger.error(f"Certificate not found at {fullchain_path}")
        return False

    logger.info("Verifying certificate:")

    # Display basic information
    try:
        subprocess.run([
            "openssl", "x509", "-in", str(fullchain_path),
            "-noout", "-subject", "-issuer", "-dates"
        ], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to display certificate information: {e}")
        return False

    # Calculate and display days until expiry
    try:
        result = subprocess.run([
            "openssl", "x509", "-in", str(fullchain_path),
            "-noout", "-enddate"
        ], check=True, stdout=subprocess.PIPE, text=True)

        expiry_date = result.stdout.strip().split('=')[1]
        expiry_epoch = int(subprocess.run([
            "date", "-d", expiry_date, "+%s"
        ], check=True, stdout=subprocess.PIPE, text=True).stdout.strip())

        current_epoch = int(subprocess.run([
            "date", "+%s"
        ], check=True, stdout=subprocess.PIPE, text=True).stdout.strip())

        days_left = (expiry_epoch - current_epoch) // 86400

        logger.info(f"Certificate will expire in {days_left} days")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to calculate expiry days: {e}")
        return False

    # Verify the certificate chain for non-self-signed certificates
    self_signed = False
    try:
        result = subprocess.run([
            "openssl", "x509", "-in", str(fullchain_path),
            "-noout", "-issuer", "-subject"
        ], check=True, stdout=subprocess.PIPE, text=True)

        issuer = ""
        subject = ""
        for line in result.stdout.splitlines():
            if line.startswith("issuer="):
                issuer = line
            elif line.startswith("subject="):
                subject = line

        self_signed = issuer == subject
    except subprocess.CalledProcessError:
        pass

    if not self_signed:
        logger.info("Verifying certificate chain...")
        try:
            subprocess.run([
                "openssl", "verify", "-CAfile", "/etc/ssl/certs/ca-certificates.crt",
                str(fullchain_path)
            ], check=True)
            logger.info("✓ Certificate chain verification successful")
        except subprocess.CalledProcessError as e:
            logger.error(f"Certificate chain verification failed: {e}")
            return False

    return True


def reload_nginx(nginx_reload: bool = True, dry_run: bool = False) -> bool:
    """
    Test and reload NGINX if the configuration is valid.

    Args:
        nginx_reload: Whether to reload NGINX
        dry_run: If True, don't actually reload, just log what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    if not nginx_reload:
        logger.info("Skipping NGINX reload (--no-reload specified)")
        return True

    logger.info("Testing NGINX configuration...")

    if dry_run:
        logger.info("[DRY RUN] Would test and reload NGINX")
        return True

    # Test the NGINX configuration
    try:
        subprocess.run(["nginx", "-t"], check=True, stderr=subprocess.PIPE, text=True)
        logger.info("✓ NGINX configuration test passed")
    except subprocess.CalledProcessError as e:
        logger.error(f"NGINX configuration test failed. Not reloading.")
        logger.error(e.stderr)
        return False

    # Reload NGINX
    logger.info("Reloading NGINX...")
    try:
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
        logger.info("✓ NGINX reloaded successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to reload NGINX: {e}")
        return False


def setup_server_block(
    domain: str,
    nginx_root: Path,
    force: bool = False,
    dry_run: bool = False
) -> bool:
    """
    Set up NGINX server block for the domain.

    Args:
        domain: Domain name
        nginx_root: NGINX root directory
        force: Force overwrite of existing configuration
        dry_run: If True, don't actually set up, just log what would be done

    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Setting up NGINX server block for {domain}")

    server_block_file = nginx_root / "sites-available" / f"{domain}.conf"

    if server_block_file.exists() and not force:
        logger.info(f"Server block already exists at {server_block_file}. Use --force to override.")
        return True

    if dry_run:
        logger.info(f"[DRY RUN] Would create server block at {server_block_file}")
        return True

    # Create sites-available and sites-enabled directories if they don't exist
    sites_available = nginx_root / "sites-available"
    sites_enabled = nginx_root / "sites-enabled"

    ensure_directory(sites_available, dry_run)
    ensure_directory(sites_enabled, dry_run)

    # Create server block configuration
    with open(server_block_file, 'w') as f:
        f.write(f"""# Server configuration for {domain}
# Generated by setup_ssl.py on {datetime.datetime.now().strftime('%Y-%m-%d')}

# HTTP server - redirect to HTTPS
server {{
    listen 80;
    listen [::]:80;
    server_name {domain} www.{domain};

    # Redirect all HTTP requests to HTTPS
    location / {{
        return 301 https://$host$request_uri;
    }}

    # Allow Let's Encrypt validation
    location /.well-known/acme-challenge/ {{
        root /var/www/html;
    }}
}}

# HTTPS server
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain} www.{domain};

    # Root directory
    root /var/www/html;
    index index.html index.htm;

    # Include SSL configuration
    include conf.d/ssl.conf;

    # Include security headers
    include conf.d/security-headers.conf;

    # Other server configuration goes here
    location / {{
        try_files $uri $uri/ =404;
    }}

    # Custom error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;

    # Additional locations and settings can be added here
}}
""")

    # Create symlink in sites-enabled
    enabled_link = nginx_root / "sites-enabled" / f"{domain}.conf"
    if not enabled_link.is_symlink():
        try:
            os.symlink(server_block_file, enabled_link)
        except Exception as e:
            logger.error(f"Failed to create symlink: {e}")
            return False

    # Ensure main nginx.conf includes sites-enabled
    nginx_conf = nginx_root / "nginx.conf"
    if nginx_conf.exists():
        with open(nginx_conf, 'r') as f:
            content = f.read()

        if "sites-enabled" not in content:
            logger.info("Adding include directive for sites-enabled to nginx.conf")
            content = re.sub(
                r'(http\s*{)',
                r'\1\n    include /etc/nginx/sites-enabled/*.conf;',
                content
            )

            with open(nginx_conf, 'w') as f:
                f.write(content)

    logger.info(f"✓ Server block created at {server_block_file}")
    return True


def backup_certificates(cert_dir: Path, backup_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Create a backup of existing certificates.

    Args:
        cert_dir: Directory containing certificates
        backup_dir: Directory to store backups, defaults to cert_dir.parent / "certs-backup"

    Returns:
        Path to the backup file, or None if backup failed
    """
    if not cert_dir.exists():
        logger.debug(f"No certificates to backup at {cert_dir}")
        return None

    if backup_dir is None:
        backup_dir = cert_dir.parent / "certs-backup"

    ensure_directory(backup_dir)

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = backup_dir / f"certs-{timestamp}.tar.gz"

    try:
        subprocess.run([
            "tar", "-czf", str(backup_file), "-C", str(cert_dir.parent), cert_dir.name
        ], check=True)

        logger.info(f"Existing certificates backed up to {backup_file}")
        return backup_file
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to backup certificates: {e}")
        return None


def handle_existing_certificates(
    cert_dir: Path,
    force: bool = False,
    dry_run: bool = False
) -> bool:
    """
    Handle existing certificates - backup or prompt user.

    Args:
        cert_dir: Directory containing certificates
        force: Force overwrite without prompting
        dry_run: If True, don't actually modify anything

    Returns:
        bool: True to proceed, False to abort
    """
    if cert_dir.exists():
        if not force:
            logger.warning(f"Certificate directory already exists at {cert_dir}. Use --force to overwrite.")
            logger.info("To use existing certificates, continue with configuration steps.")

            if not dry_run:
                response = input("Continue with configuration? [Y/n] ")
                if response.lower() not in ('', 'y', 'yes'):
                    logger.info("Operation cancelled by user")
                    return False
        else:
            logger.info("Certificate directory exists. Force flag detected, will overwrite certificates.")
            if not dry_run:
                backup_dir = cert_dir.parent / f"{cert_dir.name}.bak"
                ensure_directory(backup_dir)

                for item in cert_dir.glob('*'):
                    try:
                        if item.is_file():
                            shutil.copy2(item, backup_dir / item.name)
                    except Exception as e:
                        logger.warning(f"Failed to backup {item}: {e}")

                logger.info(f"Existing certificates backed up to {backup_dir}")
            else:
                logger.info("[DRY RUN] Would backup existing certificates")
    else:
        if not dry_run:
            ensure_directory(cert_dir)
            os.chmod(cert_dir, 0o700)
        else:
            logger.info(f"[DRY RUN] Would create certificate directory: {cert_dir}")

    return True


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SSL Certificate Setup Script for NGINX in Cloud Infrastructure Platform"
    )

    parser.add_argument(
        "--domain", "-d",
        required=True,
        help="Domain name for certificate"
    )
    parser.add_argument(
        "--environment", "-e",
        choices=VALID_ENVIRONMENTS,
        default=DEFAULT_ENVIRONMENT,
        help=f"Environment (default: {DEFAULT_ENVIRONMENT})"
    )
    parser.add_argument(
        "--email", "-m",
        help="Email address for Let's Encrypt registration"
    )
    parser.add_argument(
        "--cert-type", "-t",
        choices=VALID_CERT_TYPES,
        default=DEFAULT_CERT_TYPE,
        help=f"Certificate type (default: {DEFAULT_CERT_TYPE})"
    )
    parser.add_argument(
        "--key-size", "-k",
        type=int,
        choices=[2048, 4096],
        default=DEFAULT_KEY_SIZE,
        help=f"RSA key size in bits (default: {DEFAULT_KEY_SIZE})"
    )
    parser.add_argument(
        "--cert-dir", "-c",
        type=Path,
        help="Certificate directory (default: /etc/ssl/cloud-platform)"
    )
    parser.add_argument(
        "--dhparam-size",
        type=int,
        choices=[2048, 4096],
        default=DEFAULT_DHPARAM_SIZE,
        help=f"DH parameter size (default: {DEFAULT_DHPARAM_SIZE})"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force overwrite of existing certificates"
    )
    parser.add_argument(
        "--no-security-headers",
        action="store_true",
        help="Don't configure security headers"
    )
    parser.add_argument(
        "--no-dhparams",
        action="store_true",
        help="Don't generate Diffie-Hellman parameters"
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Don't reload NGINX after installation"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without executing them"
    )
    parser.add_argument(
        "--source-privkey",
        help="Source private key file for import"
    )
    parser.add_argument(
        "--source-fullchain",
        help="Source fullchain certificate file for import"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.cert_type == "letsencrypt" and not args.email:
        parser.error("Email address is required for Let's Encrypt certificates (use --email)")

    if args.cert_type == "import" and (not args.source_privkey or not args.source_fullchain):
        parser.error("Source private key and fullchain files are required for import (use --source-privkey and --source-fullchain)")

    # Set default certificate directory if not specified
    if not args.cert_dir:
        args.cert_dir = DEFAULT_CERT_DIR

    return args


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Initialize
    logger.info(f"Starting SSL certificate setup for {args.domain} (Environment: {args.environment})")

    # Check requirements
    if not check_openssl_installed():
        logger.error("OpenSSL is not installed. Please install it first.")
        return 1

    if not check_nginx_installed():
        logger.error("NGINX is not installed. Please install it first.")
        return 1

    if os.geteuid() != 0 and not args.dry_run:
        logger.error("This script must be run as root")
        return 1

    # Handle existing certificates
    if not handle_existing_certificates(args.cert_dir, args.force, args.dry_run):
        return 1

    # Process based on certificate type
    cert_success = False
    if args.cert_type == "self-signed":
        cert_success = create_self_signed_cert(
            args.domain,
            args.cert_dir,
            args.environment,
            args.key_size,
            args.dry_run
        )
    elif args.cert_type == "letsencrypt":
        cert_success = create_letsencrypt_cert(
            args.domain,
            args.cert_dir,
            args.email,
            args.environment,
            args.force,
            args.dry_run
        )
    elif args.cert_type == "import":
        cert_success = import_certificates(
            args.domain,
            args.cert_dir,
            args.source_privkey,
            args.source_fullchain,
            args.dry_run
        )
    else:
        logger.error(f"Invalid certificate type: {args.cert_type}")
        logger.error("Valid types are: letsencrypt, self-signed, import")
        return 1

    if not cert_success:
        logger.error("Certificate setup failed")
        return 1

    # Generate DH parameters
    if not generate_dhparams(
        NGINX_ROOT,
        args.dhparam_size,
        args.force,
        not args.no_dhparams,
        args.dry_run
    ):
        logger.warning("DH parameters generation failed")

    # Configure SSL
    if not configure_ssl(
        args.domain,
        args.cert_dir,
        NGINX_ROOT,
        not args.no_security_headers,
        args.force,
        args.dry_run
    ):
        logger.error("SSL configuration failed")
        return 1

    # Set up server block
    if not setup_server_block(
        args.domain,
        NGINX_ROOT,
        args.force,
        args.dry_run
    ):
        logger.error("Server block setup failed")
        return 1

    # Verify certificate
    if not args.dry_run:
        if not verify_certificate(args.cert_dir):
            logger.warning("Certificate verification failed")

    # Reload NGINX
    if not reload_nginx(not args.no_reload, args.dry_run):
        logger.warning("NGINX reload failed")

    if args.dry_run:
        logger.info("Dry run completed. No changes were made.")
    else:
        logger.info(f"✓ SSL certificate setup completed successfully for {args.domain}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
