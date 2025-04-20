#!/usr/bin/env python3
"""
Security audit tool for Cloud Infrastructure Platform.

This script performs a comprehensive security audit of the system, checking for
vulnerabilities, misconfigurations, and security updates. It generates a detailed
HTML report and can optionally email the findings to security personnel.

Usage: python security_audit.py [--email <recipient>] [--updates-only] [--verbose]
"""

import argparse
import enum
import grp
import json
import logging
import os
import pwd
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
LOG_FILE = Path("/var/log/cloud-platform/security_audit.log")
REPORT_FILE = Path("/var/www/reports/security-audit-")  # Will add date
EMAIL_RECIPIENT = "security@example.com"

# Ensure directories exist
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(LOG_FILE)),
    ],
)

logger = logging.getLogger("security_audit")


class Severity(enum.Enum):
    """Enumeration of severity levels for security issues."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Security audit tool for Cloud Infrastructure Platform"
    )
    parser.add_argument(
        "--email",
        help="Email address to send the report to"
    )
    parser.add_argument(
        "--updates-only",
        action="store_true",
        help="Only check for security updates"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()


class SecurityAuditor:
    """Main security audit class that performs checks and generates reports."""

    def __init__(self) -> None:
        """Initialize the security auditor.
        
        Sets up the core structures for tracking security issues and configures
        the report file location with a timestamped filename.
        """
        self.issues: List[Dict[str, str]] = []
        self.timestamp: datetime = datetime.now()
        
        # Create a unique report filename with timestamp
        try:
            timestamp_str = self.timestamp.strftime('%Y%m%d-%H%M%S')
            self.report_file = REPORT_FILE.with_name(f"{REPORT_FILE.stem}-{timestamp_str}.html")
        except (AttributeError, ValueError) as e:
            logger.error("Error creating report filename: %s", e)
            # Fallback to a basic filename if there's an error
            self.report_file = Path(f"/tmp/security-audit-{timestamp_str}.html")

    def add_issue(self, severity: Severity, title: str, description: str, recommendation: str) -> None:
        """Add a security issue to the report.
        
        Args:
            severity: Severity level of the issue (critical, high, medium, low, info)
            title: Short descriptive title of the issue
            description: Detailed description of the issue
            recommendation: Recommended steps to address the issue
            
        Returns:
            None: The issue is added to the internal issues list
        """
        # Validate severity
        if isinstance(severity, Severity):
            severity_value = severity.value
        elif isinstance(severity, str) and severity in [item.value for item in Severity]:
            severity_value = severity
        else:
            logger.warning("Invalid severity level '%s' for issue '%s', defaulting to 'info'", 
                          severity, title)
            severity_value = Severity.INFO.value
        
        # Add issue to list
        self.issues.append({
            "severity": severity_value,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat()  # Add timestamp for when issue was found
        })
        
        # Log using proper string formatting
        logger.info("%s: %s", severity_value, title)

    def check_security_updates(self):
        """
        Check for available security updates.
        
        Scans the system for security updates using the appropriate package manager
        (apt-get or yum) and reports issues based on the findings.
        
        Returns:
            int: Number of security updates found, or -1 if check failed.
        """
        logger.info("Checking for security updates...")
        
        # For Debian/Ubuntu
        if os.path.exists("/usr/bin/apt-get"):
            try:
                # Update package lists
                logger.debug("Updating apt package lists")
                subprocess.run(
                    ["apt-get", "update", "-qq"], 
                    check=True, 
                    capture_output=True
                )
                
                # Check for security updates
                logger.debug("Checking for available security updates")
                result = subprocess.run(
                    ["apt-get", "--just-print", "upgrade"], 
                    check=True, 
                    capture_output=True, 
                    text=True
                )
                
                # Find security updates
                update_details = re.findall(r"^Inst.*security", result.stdout, re.MULTILINE)
                security_updates = len(update_details)
                
                logger.info("Found %d security updates via apt", security_updates)
                
                if security_updates > 0:
                    # Check for critical packages that need updates
                    critical_packages = ["openssl", "openssh", "linux-", "nginx", "postgresql", "apache2"]
                    critical_updates = 0
                    
                    for package in update_details:
                        if any(critical in package.lower() for critical in critical_packages):
                            critical_updates += 1
                            logger.warning("Critical package needs update: %s", package)
                    
                    if critical_updates > 0:
                        self.add_issue(
                            Severity.CRITICAL, 
                            "Critical security updates available",
                            f"There are {critical_updates} CRITICAL security updates available including core system packages.",
                            "Run 'apt upgrade' to install security updates IMMEDIATELY."
                        )
                    else:
                        self.add_issue(
                            Severity.HIGH, 
                            "Security updates available",
                            f"There are {security_updates} security updates available for installation.",
                            "Run 'apt upgrade' to install security updates."
                        )
                else:
                    self.add_issue(
                        Severity.INFO,
                        "System up to date",
                        "No security updates are currently available.",
                        "Continue regular patch management."
                    )
                return security_updates
            
            except subprocess.CalledProcessError as e:
                logger.error("Error checking for security updates: %s", e)
                self.add_issue(
                    Severity.MEDIUM,
                    "Could not check for security updates",
                    f"Error while checking for security updates: {e}",
                    "Verify that the package manager is working correctly."
                )
                return -1
            except Exception as e:
                logger.error("Unexpected error during security updates check: %s", e)
                self.add_issue(
                    Severity.HIGH,
                    "Failed to check for security updates",
                    f"Unexpected error occurred while checking for security updates: {e}",
                    "Investigate system logs and verify system health."
                )
                return -1
        
        # For CentOS/RHEL/Fedora
        elif os.path.exists("/usr/bin/yum"):
            try:
                # Check security updates
                logger.info("Using yum to check for security updates")
                result = subprocess.run(
                    ["yum", "check-update", "--security"], 
                    check=False,  # yum returns 100 when updates are available
                    capture_output=True, 
                    text=True
                )
                
                # Parse output to count updates
                lines = result.stdout.strip().split('\n')
                security_updates = sum(1 for line in lines if re.match(r"^[a-zA-Z0-9]", line))
                
                logger.info("Found %d security updates via yum", security_updates)
                
                if security_updates > 0:
                    # Check for critical packages
                    critical_packages = ["openssl", "openssh", "kernel", "nginx", "postgresql", "httpd"]
                    
                    critical_updates = 0
                    for line in lines:
                        if any(critical in line.lower() for critical in critical_packages):
                            critical_updates += 1
                            logger.warning("Critical package needs update: %s", line.strip())
                    
                    if critical_updates > 0:
                        self.add_issue(
                            Severity.CRITICAL, 
                            "Critical security updates available",
                            f"There are {critical_updates} CRITICAL security updates available including core system packages.",
                            "Run 'yum update --security' to install security updates IMMEDIATELY."
                        )
                    else:
                        self.add_issue(
                            Severity.HIGH, 
                            "Security updates available",
                            f"There are {security_updates} security updates available for installation.",
                            "Run 'yum update --security' to install security updates."
                        )
                else:
                    self.add_issue(
                        Severity.INFO,
                        "System up to date",
                        "No security updates are currently available.",
                        "Continue regular patch management."
                    )
                return security_updates
                
            except subprocess.SubprocessError as e:
                logger.error("Error checking for security updates: %s", e)
                self.add_issue(
                    Severity.MEDIUM,
                    "Could not check for security updates",
                    f"Error while checking for security updates: {e}",
                    "Verify that the package manager is working correctly."
                )
                return -1
            except Exception as e:
                logger.error("Unexpected error during security updates check: %s", e)
                self.add_issue(
                    Severity.HIGH,
                    "Failed to check for security updates",
                    f"Unexpected error occurred while checking for security updates: {e}",
                    "Investigate system logs and verify system health."
                )
                return -1
        else:
            self.add_issue(
                Severity.MEDIUM,
                "Unknown package manager",
                "Could not detect a recognized package manager (apt-get or yum).",
                "Manually check for security updates or install a supported package manager."
            )
            return -1

    def check_ssl(self):
        """
        Check SSL certificate expiration and configuration.
        
        Verifies:
        - Certificate expiration dates
        - SSL/TLS protocol versions
        - Cipher configuration
        - Certificate validity
        """
        logger.info("Checking SSL/TLS configuration...")
        
        try:
            # Get domains to check from configuration or detect from environment
            domains_to_check = self._get_domains_to_check()
            
            if not domains_to_check:
                logger.warning("No domains found to check for SSL/TLS configuration")
                self.add_issue(
                    Severity.LOW,
                    "No SSL domains configured",
                    "No domains were found to check for SSL/TLS configuration.",
                    "Configure domains in the application settings or verify domain detection."
                )
                return
            
            for domain in domains_to_check:
                logger.debug("Checking SSL for domain: %s", domain)
                self._check_certificate_expiration(domain)
                self._check_ssl_protocol_versions(domain)
                self._check_ssl_cipher_strength(domain)
        
        except Exception as e:
            logger.error("Error checking SSL certificates: %s", e)
            self.add_issue(
                Severity.MEDIUM,
                "Unable to check SSL certificates",
                "An error occurred while checking SSL certificates: {}".format(str(e)),
                "Verify SSL certificates manually or check server connectivity."
            )
    
    def _get_domains_to_check(self):
        """Get list of domains to check from configuration or environment."""
        domains = []
        
        # Try to get domains from configuration
        try:
            # Check common configuration locations
            if os.path.exists("/etc/nginx/sites-enabled/"):
                for file in os.listdir("/etc/nginx/sites-enabled/"):
                    with open(os.path.join("/etc/nginx/sites-enabled/", file)) as f:
                        content = f.read()
                        server_names = re.findall(r"server_name\s+(.*?);", content)
                        for server_name in server_names:
                            domains.extend(server_name.split())
            
            # If we have a specific configuration we know about
            if os.path.exists("/etc/cloud-platform/config.ini"):
                with open("/etc/cloud-platform/config.ini") as f:
                    for line in f:
                        if "domain" in line.lower() and "=" in line:
                            domain = line.split("=")[1].strip()
                            if domain and domain not in domains:
                                domains.append(domain)
        except Exception as e:
            logger.debug("Error getting domains from configuration: %s", e)
        
        # Add default domain if no domains were found
        if not domains:
            domains = ["cloud-platform.example.com"]
            logger.debug("Using default domain: %s", domains[0])
        
        # Remove duplicates and non-qualified domains
        return [d for d in set(domains) if "." in d]
    
    def _check_certificate_expiration(self, domain):
        """Check SSL certificate expiration for a domain."""
        try:
            # Create a secure context for connection
            context = ssl.create_default_context()
            conn = None
            
            try:
                # Connect to the domain
                conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
                conn.settimeout(3.0)  # Set a reasonable timeout
                conn.connect((domain, 443))
                
                # Get certificate details
                cert = conn.getpeercert()
                
                if not cert:
                    self.add_issue(
                        Severity.HIGH,
                        "Invalid SSL Certificate",
                        f"The SSL certificate for {domain} could not be validated.",
                        "Verify the certificate installation and ensure it's properly configured."
                    )
                    return
                
                # Extract expiration date
                expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.now()).days
                
                # Check and report expiration status
                if days_left < 0:
                    self.add_issue(
                        Severity.CRITICAL,
                        "SSL Certificate Expired",
                        f"SSL certificate for {domain} has expired {abs(days_left)} days ago.",
                        "Renew the SSL certificate immediately."
                    )
                elif days_left < 7:
                    self.add_issue(
                        Severity.CRITICAL,
                        "SSL Certificate Expiring Very Soon",
                        f"SSL certificate for {domain} will expire in {days_left} days.",
                        "Renew the SSL certificate immediately."
                    )
                elif days_left < 30:
                    self.add_issue(
                        Severity.HIGH,
                        "SSL Certificate Expiring Soon",
                        f"SSL certificate for {domain} will expire in {days_left} days.",
                        "Plan to renew the SSL certificate within the next week."
                    )
                else:
                    logger.debug("Certificate for %s valid for %s days", domain, days_left)
                
                # Check certificate issuer and trust
                self._check_certificate_trust(domain, cert)
                
            finally:
                if conn:
                    conn.close()
        
        except socket.gaierror:
            logger.debug("Could not resolve domain: %s", domain)
        except socket.timeout:
            logger.debug("Connection to %s timed out", domain)
            self.add_issue(
                Severity.LOW,
                "SSL Connection Timeout",
                f"Connection to {domain}:443 timed out during SSL check.",
                "Verify server connectivity and SSL configuration."
            )
        except ssl.SSLError as e:
            logger.debug("SSL error for %s: %s", domain, e)
            self.add_issue(
                Severity.HIGH,
                "SSL Connection Error",
                f"SSL error occurred when connecting to {domain}: {str(e)}",
                "Verify SSL configuration and certificate installation."
            )
        except Exception as e:
            logger.debug("Error checking certificate expiration for %s: %s", domain, e)
    
    def _check_certificate_trust(self, domain, cert):
        """Check if the certificate is trusted and properly issued."""
        try:
            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])
            
            # Check if self-signed (issuer == subject)
            if issuer == subject:
                self.add_issue(
                    Severity.MEDIUM,
                    "Self-Signed Certificate",
                    f"SSL certificate for {domain} is self-signed.",
                    "Consider using a certificate from a trusted Certificate Authority for production."
                )
            
            # Check common name
            if 'commonName' in subject:
                common_name = subject['commonName']
                if domain != common_name and not domain.endswith('.' + common_name):
                    # Check for wildcard certificates
                    if not (common_name.startswith('*.') and domain.endswith(common_name[1:])):
                        self.add_issue(
                            Severity.HIGH,
                            "Certificate Name Mismatch",
                            f"SSL certificate for {domain} has CN={common_name} which doesn't match.",
                            "Obtain a certificate with the correct domain name."
                        )
        
        except Exception as e:
            logger.debug("Error checking certificate trust for %s: %s", domain, e)
    
    def _check_ssl_protocol_versions(self, domain):
        """Check SSL/TLS protocol versions supported by the server."""
        insecure_protocols = []
        secure_protocols = []
        
        try:
            # Check for OpenSSL binary for best results
            if not os.path.exists("/usr/bin/openssl") and not os.path.exists("/usr/local/bin/openssl"):
                return
            
            # Check each protocol version
            for protocol in ["ssl2", "ssl3", "tls1", "tls1_1", "tls1_2", "tls1_3"]:
                try:
                    # Use subprocess to invoke openssl for more accurate protocol testing
                    cmd = ["openssl", "s_client", f"-{protocol}", "-connect", f"{domain}:443"]
                    result = subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                        check=False
                    )
                    
                    # Check if connection was successful
                    if "CONNECTED" in result.stdout.decode() or "CONNECTED" in result.stderr.decode():
                        if protocol in ["ssl2", "ssl3", "tls1", "tls1_1"]:
                            insecure_protocols.append(protocol)
                        else:
                            secure_protocols.append(protocol)
                
                except subprocess.SubprocessError:
                    continue
            
            # Report findings
            if insecure_protocols:
                self.add_issue(
                    Severity.HIGH,
                    "Insecure SSL/TLS Protocols Enabled",
                    f"Server {domain} supports insecure protocols: {', '.join(insecure_protocols)}",
                    "Disable these protocols in your web server configuration."
                )
            
            if not secure_protocols:
                self.add_issue(
                    Severity.HIGH,
                    "No Secure SSL/TLS Protocols Enabled",
                    f"Server {domain} does not support secure protocols (TLS 1.2, TLS 1.3)",
                    "Enable TLS 1.2 and TLS 1.3 in your web server configuration."
                )
        
        except Exception as e:
            logger.debug("Error checking SSL/TLS protocols for %s: %s", domain, e)
    
    def _check_ssl_cipher_strength(self, domain):
        """Check cipher suite strength and configuration."""
        try:
            # Use openssl to check cipher configuration
            if not os.path.exists("/usr/bin/openssl") and not os.path.exists("/usr/local/bin/openssl"):
                return
                
            # Get cipher information
            cmd = ["openssl", "s_client", "-connect", f"{domain}:443", "-cipher", "ALL:eNULL"]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                input=b"",
                timeout=5,
                check=False
            )
            
            output = result.stdout.decode()
            
            # Check for weak ciphers
            if "RC4" in output or "DES" in output or "NULL" in output:
                self.add_issue(
                    Severity.HIGH,
                    "Weak SSL/TLS Ciphers Enabled",
                    f"Server {domain} supports weak cipher suites (RC4, DES, or NULL).",
                    "Disable weak ciphers in your web server configuration."
                )
            
            # Check for secure renegotiation
            if "secure renegotiation IS NOT supported" in output:
                self.add_issue(
                    Severity.MEDIUM,
                    "Insecure Renegotiation",
                    f"Server {domain} does not support secure renegotiation.",
                    "Enable secure renegotiation in your web server configuration."
                )
                
        except Exception as e:
            logger.debug("Error checking SSL/TLS cipher strength for %s: %s", domain, e)

    def check_users(self):
        """
        Check user security configuration.
        
        Examines user accounts for security issues including:
        - Accounts without passwords
        - Accounts with expired passwords
        - Accounts with non-expiring passwords
        - Multiple root accounts (UID 0)
        - Weak password hashing algorithms
        - Users with login shells that shouldn't have them
        """
        logger.info("Checking user security configuration...")
        
        try:
            # Get all users from passwd file
            users = []
            root_users = []
            system_users_with_shell = []
            
            # Check /etc/passwd file
            try:
                with open("/etc/passwd", "r") as passwd_file:
                    for line in passwd_file:
                        parts = line.strip().split(":")
                        if len(parts) >= 7:
                            username = parts[0]
                            uid = int(parts[2])
                            shell = parts[6]
                            
                            # Check for multiple root accounts
                            if uid == 0 and username != "root":
                                root_users.append(username)
                            
                            # Check for system users with login shells
                            if uid < 1000 and uid != 0 and shell not in ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"]:
                                system_users_with_shell.append(username)
                            
                            # Add regular users to our list for further checking
                            if uid >= 1000 and "/bin/" in shell:
                                users.append(username)
            except (IOError, PermissionError) as e:
                logger.error("Could not read /etc/passwd: %s", e)
                self.add_issue(
                    Severity.MEDIUM,
                    "Cannot Check User Accounts",
                    "Could not read /etc/passwd file to check user accounts.",
                    "Verify permissions on /etc/passwd or run the security audit with appropriate privileges."
                )
                return
            
            # Report multiple root accounts (critical security issue)
            if root_users:
                self.add_issue(
                    Severity.CRITICAL,
                    "Multiple Root Accounts",
                    f"Found additional accounts with UID 0 (root privileges): {', '.join(root_users)}",
                    "Investigate these accounts and remove root privileges if unauthorized."
                )
            
            # Report system users with login shells
            if system_users_with_shell:
                self.add_issue(
                    Severity.MEDIUM,
                    "System Users With Login Shells",
                    f"System users with login shells: {', '.join(system_users_with_shell)}",
                    "Configure these accounts to use /sbin/nologin or /bin/false if interactive login is not required."
                )
            
            # Check user password status for regular users
            for username in users:
                self._check_user_password_status(username)
            
            # Check password policies in /etc/login.defs
            self._check_password_policies()
            
        except Exception as e:
            logger.error("Error checking user accounts: %s", e)
            self.add_issue(
                Severity.LOW,
                "User Account Check Incomplete",
                f"An error occurred while checking user accounts: {str(e)}",
                "Some user security checks could not be completed."
            )
    
    def _check_user_password_status(self, username):
        """Check password status for a specific user."""
        try:
            # Check password status with timeout to avoid hanging
            result = subprocess.run(
                ["passwd", "-S", username],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=5
            )
            
            if result.returncode != 0:
                logger.debug("Could not check password status for user %s: %s", username, result.stderr)
                return
            
            # Check for accounts with no password
            if "NP" in result.stdout or "Empty" in result.stdout:
                self.add_issue(
                    Severity.CRITICAL,
                    "User Account Without Password",
                    f"User account {username} has no password set.",
                    f"Set a strong password for user {username} or lock the account."
                )
                return
            
            # Locked accounts are secure
            if "L" in result.stdout:
                logger.debug("User account %s is locked (good security practice).", username)
                return
            
            # Check password expiration for accounts with passwords
            if "P" in result.stdout and "Password set" in result.stdout:
                try:
                    expiry_result = subprocess.run(
                        ["chage", "-l", username],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                        timeout=5
                    )
                    
                    if expiry_result.returncode != 0:
                        logger.debug("Could not check password expiry for user %s: %s", username, expiry_result.stderr)
                        return
                    
                    # Check if password has expired
                    if "Password expires" in expiry_result.stdout:
                        if "never" in expiry_result.stdout.lower():
                            self.add_issue(
                                Severity.MEDIUM,
                                "Password Never Expires",
                                f"Password for user {username} is set to never expire.",
                                f"Configure password expiration for user {username} with 'sudo chage -M 90 {username}'."
                            )
                        
                        # Check for expired passwords
                        if "Password expired" in expiry_result.stdout and "Password expired" not in expiry_result.stdout.lower():
                            self.add_issue(
                                Severity.HIGH,
                                "Expired Password",
                                f"Password for user {username} has expired but account is still active.",
                                f"Update the password for {username} or lock the account if unused."
                            )
                
                except subprocess.TimeoutExpired:
                    logger.warning("Timeout while checking password expiry for user %s", username)
                except subprocess.SubprocessError as e:
                    logger.debug("Error checking password expiry for user %s: %s", username, e)
        
        except subprocess.TimeoutExpired:
            logger.warning("Timeout while checking password status for user %s", username)
        except subprocess.SubprocessError as e:
            logger.debug("Error checking password status for user %s: %s", username, e)
        except Exception as e:
            logger.debug("Unexpected error checking user %s: %s", username, e)
    
    def _check_password_policies(self):
        """Check system-wide password policies."""
        try:
            if not os.path.exists("/etc/login.defs"):
                return
            
            with open("/etc/login.defs", "r") as f:
                login_defs = f.read()
            
            # Check password expiration policy
            pass_max_days_match = re.search(r"^PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE)
            if pass_max_days_match:
                max_days = int(pass_max_days_match.group(1))
                if max_days > 90:
                    self.add_issue(
                        Severity.LOW,
                        "Weak Password Expiration Policy",
                        f"Maximum password age is set to {max_days} days (recommended: ≤90 days).",
                        "Update PASS_MAX_DAYS to 90 or less in /etc/login.defs."
                    )
            else:
                self.add_issue(
                    Severity.LOW,
                    "No Password Expiration Policy",
                    "No PASS_MAX_DAYS setting found in /etc/login.defs.",
                    "Configure password expiration by setting PASS_MAX_DAYS to 90 or less in /etc/login.defs."
                )
            
            # Check minimum password age
            pass_min_days_match = re.search(r"^PASS_MIN_DAYS\s+(\d+)", login_defs, re.MULTILINE)
            if pass_min_days_match:
                min_days = int(pass_min_days_match.group(1))
                if min_days < 1:
                    self.add_issue(
                        Severity.LOW,
                        "Weak Minimum Password Age",
                        "Minimum password age is set to 0 days, allowing immediate password reuse.",
                        "Set PASS_MIN_DAYS to at least 1 in /etc/login.defs."
                    )
            
            # Check password warning period
            pass_warn_match = re.search(r"^PASS_WARN_AGE\s+(\d+)", login_defs, re.MULTILINE)
            if not pass_warn_match or int(pass_warn_match.group(1)) < 7:
                self.add_issue(
                    Severity.INFO,
                    "Short Password Warning Period",
                    "Password expiration warning period is less than 7 days.",
                    "Set PASS_WARN_AGE to at least 7 in /etc/login.defs."
                )
                    
        except Exception as e:
            logger.debug("Error checking password policies: %s", e)

    def check_files(self):
        """
        Check file permissions and ownership of sensitive system files.
        
        Verifies that critical system files have appropriate permissions and ownership
        to prevent unauthorized access or modification. Checks include:
        - Files not world-readable or world-writable when they shouldn't be
        - Proper ownership (typically root)
        - Proper directory permissions
        - SUID/SGID binaries
        """
        logger.info("Checking file permissions...")
        
        # Define files and their expected permissions/ownership
        sensitive_files = [
            # File path, expected owner, expected group, max permissions, is_directory
            ("/etc/shadow", "root", "shadow", 0o640, False),
            ("/etc/passwd", "root", "root", 0o644, False),
            ("/etc/ssh/sshd_config", "root", "root", 0o600, False),
            ("/etc/cloud-platform/security/", "root", "root", 0o750, True),
            ("/etc/nginx/nginx.conf", "root", "root", 0o644, False),
            ("/etc/nginx/conf.d/", "root", "root", 0o755, True),
            ("/var/log/cloud-platform/", None, None, 0o750, True),  # Only check max permissions
            ("/etc/ssl/private/", "root", "root", 0o700, True)
        ]
        
        for file_info in sensitive_files:
            file_path, expected_owner, expected_group, max_perms, is_directory = file_info
            
            try:
                # Skip if file doesn't exist
                if not os.path.exists(file_path):
                    logger.debug("File not found: %s", file_path)
                    continue
                    
                stat_info = os.stat(file_path)
                mode = stat_info.st_mode
                actual_mode = mode & 0o777  # Get only permission bits
                
                # Get owner and group names
                try:
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
                    group = grp.getgrgid(stat_info.st_gid).gr_name
                except (KeyError, ImportError):
                    owner = str(stat_info.st_uid)
                    group = str(stat_info.st_gid)
                
                # Check ownership if expected values provided
                if expected_owner and owner != expected_owner:
                    self.add_issue(
                        Severity.HIGH,
                        "Incorrect File Ownership",
                        f"File {file_path} is owned by {owner} (expected: {expected_owner}).",
                        f"Fix ownership with: chown {expected_owner} {file_path}"
                    )
                
                if expected_group and group != expected_group:
                    self.add_issue(
                        Severity.MEDIUM,
                        "Incorrect File Group",
                        f"File {file_path} group is {group} (expected: {expected_group}).",
                        f"Fix group with: chgrp {expected_group} {file_path}"
                    )
                
                # Check if permissions are too permissive
                if actual_mode > max_perms:
                    # Determine if world-readable, world-writable or world-executable
                    world_perms = actual_mode & 0o007
                    
                    severity = Severity.HIGH if world_perms & 0o002 else Severity.MEDIUM
                    
                    if is_directory:
                        recommendation = f"Fix directory permissions with: chmod {oct(max_perms)[2:]} {file_path}"
                    else:
                        recommendation = f"Fix file permissions with: chmod {oct(max_perms)[2:]} {file_path}"
                    
                    self.add_issue(
                        severity,
                        "Insecure File Permissions",
                        f"{'Directory' if is_directory else 'File'} {file_path} has excessive permissions: {oct(actual_mode)[2:]} (should be <= {oct(max_perms)[2:]}).",
                        recommendation
                    )
                    
            except (IOError, PermissionError) as e:
                logger.debug("Error checking permissions for %s: %s", file_path, e)
                self.add_issue(
                    Severity.LOW,
                    "Cannot Check File Permissions",
                    f"Could not check permissions for {file_path}: {str(e)}",
                    "Verify file permissions manually or run the security audit with higher privileges."
                )
            except Exception as e:
                logger.error("Unexpected error checking %s: %s", file_path, e)
        
        # Check for SUID/SGID files
        self._check_suid_sgid_files()
        
        # Check for world-writable files in system directories
        self._check_world_writable_files()
    
    def _check_suid_sgid_files(self):
        """Check for SUID/SGID binaries."""
        try:
            # Find SUID files - with reasonable timeout and error handling
            suid_command = "find /usr /bin /sbin /opt -type f -perm -4000 2>/dev/null"
            sgid_command = "find /usr /bin /sbin /opt -type f -perm -2000 2>/dev/null"
            
            try:
                suid_result = subprocess.run(
                    suid_command, 
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False
                )
                suid_files = suid_result.stdout.strip().split('\n') if suid_result.stdout else []
                
                sgid_result = subprocess.run(
                    sgid_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False
                )
                sgid_files = sgid_result.stdout.strip().split('\n') if sgid_result.stdout else []
                
                # Common/expected SUID binaries
                expected_suid = {
                    '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/chfn',
                    '/usr/bin/chsh', '/usr/bin/gpasswd', '/usr/bin/newgrp',
                    '/bin/su', '/bin/ping', '/bin/ping6', '/usr/bin/pkexec'
                }
                
                # Find unexpected SUID files
                unexpected_suid = [f for f in suid_files if f and f not in expected_suid]
                
                if len(unexpected_suid) > 10:
                    self.add_issue(
                        Severity.HIGH,
                        "Excessive SUID Binaries",
                        f"Found {len(unexpected_suid)} unexpected SUID binaries.",
                        "Review and remove SUID bit from unnecessary binaries using chmod u-s."
                    )
                elif unexpected_suid:
                    self.add_issue(
                        Severity.MEDIUM,
                        "Unexpected SUID Binaries",
                        f"Found {len(unexpected_suid)} unexpected SUID binaries: {', '.join(unexpected_suid[:5])}{'...' if len(unexpected_suid) > 5 else ''}",
                        "Verify these are required and remove SUID bit if unnecessary using chmod u-s."
                    )
                    
                if len(sgid_files) > 5:
                    self.add_issue(
                        Severity.MEDIUM,
                        "Multiple SGID Binaries",
                        f"Found {len(sgid_files)} SGID binaries.",
                        "Review and remove SGID bit from unnecessary binaries using chmod g-s."
                    )
                    
            except subprocess.TimeoutExpired:
                logger.warning("Timeout while searching for SUID/SGID files")
                self.add_issue(
                    Severity.LOW,
                    "SUID/SGID Check Timeout",
                    "Search for SUID/SGID binaries timed out.",
                    "Manually check for SUID/SGID binaries or increase search timeout."
                )
            except subprocess.SubprocessError as e:
                logger.error("Error searching for SUID/SGID files: %s", e)
                
        except Exception as e:
            logger.error("Error checking SUID/SGID files: %s", e)
    
    def _check_world_writable_files(self):
        """Check for world-writable files in system directories."""
        try:
            # Find world-writable files - with reasonable timeout and error handling
            command = "find /etc /var /usr -type f -perm -002 -not -path '/var/tmp/*' -not -path '/tmp/*' 2>/dev/null | head -n 20"
            
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    world_writable_files = result.stdout.strip().split('\n')
                    num_files = len(world_writable_files)
                    
                    self.add_issue(
                        Severity.HIGH,
                        "World-Writable System Files",
                        f"Found {num_files}+ world-writable files in system directories: {', '.join(world_writable_files[:5])}{'...' if num_files > 5 else ''}",
                        "Remove write permissions for 'others' with: chmod o-w [file]"
                    )
                    
            except subprocess.TimeoutExpired:
                logger.warning("Timeout while searching for world-writable files")
                self.add_issue(
                    Severity.LOW,
                    "World-Writable Files Check Timeout",
                    "Search for world-writable files timed out.",
                    "Manually check for world-writable files or optimize the search."
                )
            except subprocess.SubprocessError as e:
                logger.error("Error searching for world-writable files: %s", e)
                
        except Exception as e:
            logger.error("Error checking world-writable files: %s", e)

    def check_security_config(self):
        """
        Check security configuration.
        
        This function checks for various security configurations including:
        - Open network ports that might pose security risks
        - Kernel security parameters
        - Important security services
        - Security-related configuration files
        """
        logger.info("Checking security configuration...")
        
        # Check for open ports
        self._check_open_ports()
        
        # Check kernel security parameters
        self._check_kernel_parameters()
        
        # Check security-related files
        self._check_security_files()
    
    def _check_open_ports(self):
        """Check for potentially risky open network ports."""
        try:
            # Standard allowed ports for common services
            allowed_ports = [
                22,    # SSH
                80,    # HTTP
                443,   # HTTPS
                5432,  # PostgreSQL
                3306,  # MySQL
                27017, # MongoDB
                6379,  # Redis
                # Add other legitimate ports your application uses
            ]
            
            # Choose the right command based on availability
            if os.path.exists("/usr/bin/ss"):
                cmd = ["ss", "-tuln"]
                port_column_index = 4  # Column index for ss output
                port_delimiter = ":"   # Format: 127.0.0.1:80
            elif os.path.exists("/usr/bin/netstat"):
                cmd = ["netstat", "-tuln"]
                port_column_index = 3  # Column index for netstat output
                port_delimiter = ":"   # Format: 127.0.0.1:80
            else:
                self.add_issue(
                    Severity.LOW,
                    "Cannot Check Open Ports",
                    "Neither ss nor netstat commands are available.",
                    "Install net-tools or iproute2 packages to enable network diagnostics."
                )
                return
            
            # Run the command with a timeout to prevent hanging
            try:
                result = subprocess.run(
                    cmd, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10  # 10 second timeout
                )
            except subprocess.TimeoutExpired:
                self.add_issue(
                    Severity.LOW,
                    "Port Scan Timeout",
                    "The port scan operation timed out.",
                    "Check system load or network configuration."
                )
                return
            except subprocess.SubprocessError as e:
                self.add_issue(
                    Severity.LOW,
                    "Port Scan Failed",
                    f"Failed to scan open ports: {e}",
                    "Verify the system has proper permissions to run network diagnostic commands."
                )
                return
            
            # Parse the output to find ports
            open_ports = []
            
            for line in result.stdout.split('\n'):
                # Skip header lines
                if not line or line.startswith('Netid') or line.startswith('Proto'):
                    continue
                    
                parts = line.split()
                if len(parts) >= port_column_index + 1:
                    address_part = parts[port_column_index]
                    
                    # Extract port number
                    if port_delimiter in address_part:
                        try:
                            # Get the last part after splitting by delimiter (handles IPv6 addresses too)
                            port_str = address_part.split(port_delimiter)[-1]
                            # Handle IPv6 address with port format [::]:80
                            if ']' in port_str:
                                port_str = port_str.split(']')[-1]
                                
                            port = int(port_str)
                            if port not in allowed_ports and port < 32768:  # Exclude ephemeral ports
                                open_ports.append(port)
                        except (ValueError, IndexError):
                            continue
            
            # Report findings
            if open_ports:
                # Group ports for better readability
                open_ports.sort()
                
                # Check for particularly concerning ports
                high_risk_ports = [23, 21, 25, 139, 445, 3389]  # telnet, ftp, smtp, smb, rdp
                high_risk_found = [p for p in open_ports if p in high_risk_ports]
                
                if high_risk_found:
                    self.add_issue(
                        Severity.HIGH,
                        "High-Risk Open Ports",
                        f"The following high-risk ports are open: {', '.join(map(str, high_risk_found))}",
                        "Close these ports immediately or restrict access using a firewall."
                    )
                    
                    # Remove high-risk ports from the general list
                    open_ports = [p for p in open_ports if p not in high_risk_ports]
                    
                if open_ports:
                    self.add_issue(
                        Severity.MEDIUM,
                        "Potentially Unnecessary Open Ports",
                        f"The following ports are open but may not be required: {', '.join(map(str, open_ports))}",
                        "Review these ports and close any that are not needed using the firewall."
                    )
                    
        except Exception as e:
            logger.error("Error checking open ports: %s", e)
            self.add_issue(
                Severity.LOW,
                "Failed to Check Open Ports",
                f"An error occurred while checking open ports: {str(e)}",
                "Manually verify open ports using 'ss -tuln' or 'netstat -tuln'."
            )
    
    def _check_kernel_parameters(self):
        """Check kernel security parameters."""
        try:
            # Important kernel security parameters to check
            kernel_params = {
                "kernel.randomize_va_space": {"expected": "2", "severity": Severity.MEDIUM},
                "net.ipv4.tcp_syncookies": {"expected": "1", "severity": Severity.MEDIUM},
                "net.ipv4.conf.all.accept_redirects": {"expected": "0", "severity": Severity.LOW},
                "net.ipv4.conf.all.send_redirects": {"expected": "0", "severity": Severity.LOW},
                "net.ipv4.conf.all.rp_filter": {"expected": "1", "severity": Severity.MEDIUM}
            }
            
            if not os.path.exists("/sbin/sysctl") and not os.path.exists("/usr/sbin/sysctl"):
                self.add_issue(
                    Severity.LOW,
                    "Cannot Check Kernel Parameters",
                    "The sysctl command is not available.",
                    "Install the procps package to enable kernel parameter checks."
                )
                return
                
            for param, config in kernel_params.items():
                expected = config["expected"]
                severity = config["severity"]
                
                try:
                    result = subprocess.run(
                        ["sysctl", "-n", param],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        actual = result.stdout.strip()
                        if actual != expected:
                            self.add_issue(
                                severity,
                                "Insecure Kernel Parameter",
                                f"Kernel parameter {param} is set to {actual} (expected {expected}).",
                                f"Set the parameter correctly with: sysctl -w {param}={expected}"
                            )
                except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                    # Skip this parameter if we can't check it
                    continue
                    
        except Exception as e:
            logger.error(f"Error checking kernel parameters: {e}")
            self.add_issue(
                Severity.LOW,
                "Kernel Parameter Check Failed",
                f"An error occurred while checking kernel security parameters: {str(e)}",
                "Manually verify kernel parameters using 'sysctl -a | grep security'"
            )
    
    def _check_security_files(self):
        """Check security-related configuration files."""
        try:
            # Important security configuration files to check
            security_files = [
                {
                    "path": "/etc/sysctl.conf", 
                    "check": lambda content: "kernel.randomize_va_space = 2" in content,
                    "severity": Severity.LOW,
                    "message": "Address space layout randomization (ASLR) not configured in sysctl.conf",
                    "recommendation": "Add 'kernel.randomize_va_space = 2' to /etc/sysctl.conf"
                },
                {
                    "path": "/etc/login.defs", 
                    "check": lambda content: re.search(r"PASS_MAX_DAYS\s+[0-9]{1,2}", content) is not None,
                    "severity": Severity.LOW,
                    "message": "Password expiration policy not properly configured",
                    "recommendation": "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs"
                }
            ]
            
            for file_config in security_files:
                file_path = file_config["path"]
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                        if not file_config["check"](content):
                            self.add_issue(
                                file_config["severity"],
                                file_config["message"],
                                f"Security configuration issue in {file_path}",
                                file_config["recommendation"]
                            )
                    except (IOError, PermissionError) as e:
                        logger.warning(f"Could not read security file {file_path}: {e}")
                        
        except Exception as e:
            logger.error(f"Error checking security configuration files: {e}")
            self.add_issue(
                Severity.LOW,
                "Security File Check Failed",
                f"An error occurred while checking security configuration files: {str(e)}",
                "Manually verify security configuration files"
            )

    def check_firewall(self):
        """
        Check firewall status and configuration.
        
        Verifies that a firewall is installed, running, and properly configured
        with appropriate rules.
        """
        logger.info("Checking firewall configuration...")
        
        try:
            firewall_checked = False
            
            # Check UFW (Ubuntu/Debian)
            if os.path.exists("/usr/sbin/ufw"):
                firewall_checked = True
                logger.debug("Found UFW firewall")
                
                # Check if UFW is active
                result = subprocess.run(
                    ["ufw", "status"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                
                if "inactive" in result.stdout.lower() or "not enabled" in result.stdout.lower():
                    self.add_issue(
                        Severity.HIGH,
                        "UFW Firewall Disabled",
                        "The UFW firewall is installed but not active.",
                        "Enable the firewall with 'sudo ufw enable' after configuring appropriate rules."
                    )
                else:
                    # Check if UFW has any rules defined
                    if "deny (incoming)" not in result.stdout.lower() and "allow" not in result.stdout.lower():
                        self.add_issue(
                            Severity.MEDIUM,
                            "UFW Firewall Has No Rules",
                            "The UFW firewall is active but may not have any rules configured.",
                            "Configure appropriate firewall rules using 'sudo ufw allow' and 'sudo ufw deny' commands."
                        )
                    else:
                        logger.debug("UFW is active with rules defined")
            
            # Check firewalld (CentOS/RHEL)
            if os.path.exists("/usr/bin/firewall-cmd"):
                firewall_checked = True
                logger.debug("Found firewalld")
                
                # Check if firewalld is running
                state_result = subprocess.run(
                    ["firewall-cmd", "--state"], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                
                if "running" not in state_result.stdout.lower():
                    self.add_issue(
                        Severity.HIGH,
                        "Firewalld Disabled",
                        "The firewalld service is not running.",
                        "Enable the firewall with 'sudo systemctl start firewalld' and 'sudo systemctl enable firewalld'."
                    )
                else:
                    # Check if firewalld has basic configuration
                    list_result = subprocess.run(
                        ["firewall-cmd", "--list-all"], 
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False
                    )
                    
                    if "services:" in list_result.stdout and "ssh" not in list_result.stdout:
                        self.add_issue(
                            Severity.MEDIUM,
                            "Firewalld May Block SSH",
                            "SSH service does not appear to be allowed in firewalld.",
                            "Ensure SSH access is permitted with 'sudo firewall-cmd --permanent --add-service=ssh'."
                        )
            
            # Check iptables directly if no other firewall detected
            if not firewall_checked and os.path.exists("/sbin/iptables"):
                logger.debug("Checking iptables rules")
                
                result = subprocess.run(
                    ["iptables", "-L"], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                
                if "Chain INPUT (policy ACCEPT)" in result.stdout and "DROP" not in result.stdout:
                    self.add_issue(
                        Severity.HIGH,
                        "No Firewall Rules Detected",
                        "No firewall rules appear to be configured with iptables.",
                        "Configure a firewall using UFW, firewalld, or direct iptables rules."
                    )
            
            # If no firewall found at all
            if not firewall_checked and not os.path.exists("/sbin/iptables"):
                self.add_issue(
                    Severity.CRITICAL,
                    "No Firewall Installed",
                    "No firewall software appears to be installed on the system.",
                    "Install and configure a firewall like UFW (apt install ufw) or firewalld."
                )
                
        except subprocess.SubprocessError as e:
            logger.error(f"Error checking firewall status: {e}")
            self.add_issue(
                Severity.MEDIUM,
                "Unable to Check Firewall Status",
                f"An error occurred while checking the firewall status: {str(e)}",
                "Verify firewall configuration manually and ensure the security audit has appropriate permissions."
            )
        except Exception as e:
            logger.error(f"Unexpected error checking firewall status: {e}")
            self.add_issue(
                Severity.MEDIUM,
                "Unable to Check Firewall Status",
                f"An unexpected error occurred while checking the firewall status: {str(e)}",
                "Verify firewall configuration manually."
            )

    def check_services(self):
        """
        Check service security configurations.
        
        Verifies security-related services are properly installed, configured and running,
        including file integrity monitoring, intrusion detection, and audit services.
        """
        logger.info("Checking security services...")
        
        try:
            # Check File Integrity Monitoring
            self._check_file_integrity_monitoring()
            
            # Check auditd (Linux Audit Framework)
            self._check_audit_service()
            
            # Check SSH configuration
            self._check_ssh_configuration()
            
        except Exception as e:
            logger.error(f"Unexpected error during service security checks: {e}")
            self.add_issue(
                Severity.MEDIUM,
                "Service Security Check Failed",
                f"An unexpected error occurred during service security checks: {str(e)}",
                "Review service configurations manually to ensure security services are properly configured."
            )

    def _check_file_integrity_monitoring(self):
        """Check file integrity monitoring tools."""
        logger.debug("Checking file integrity monitoring...")
        
        fim_installed = False
        
        # Check AIDE
        if os.path.exists("/usr/bin/aide"):
            fim_installed = True
            logger.debug("AIDE is installed")
            
            # Check if AIDE database is initialized
            aide_db = "/var/lib/aide/aide.db"
            if not os.path.exists(aide_db):
                aide_db_new = "/var/lib/aide/aide.db.new"
                if not os.path.exists(aide_db_new):
                    self.add_issue(
                        Severity.HIGH,
                        "File Integrity Monitoring Not Initialized",
                        "AIDE is installed but the database is not initialized.",
                        "Initialize AIDE with 'sudo aide --init' and copy the database with 'sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db'."
                    )
                else:
                    self.add_issue(
                        Severity.MEDIUM,
                        "File Integrity Monitoring Database Not Activated",
                        "AIDE is installed and database is initialized but not activated.",
                        "Copy the database with 'sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db'."
                    )
            
            # Check if AIDE runs regularly
            cron_paths = [
                "/etc/cron.daily/aide", 
                "/etc/cron.weekly/aide",
                "/etc/cron.d/aide",
                "/etc/systemd/system/aide.timer",
                "/lib/systemd/system/aide.timer"
            ]
            aide_configured = False
            
            for cron_path in cron_paths:
                if os.path.exists(cron_path):
                    aide_configured = True
                    logger.debug(f"AIDE scheduled check found at {cron_path}")
                    break
            
            if not aide_configured:
                self.add_issue(
                    Severity.MEDIUM,
                    "File Integrity Checks Not Scheduled",
                    "AIDE is installed but not scheduled to run regularly.",
                    "Configure a cron job to run AIDE checks regularly, e.g., 'echo '0 3 * * * root /usr/bin/aide --check' > /etc/cron.d/aide'."
                )
        
        # Check for Tripwire (another popular FIM)
        elif os.path.exists("/usr/sbin/tripwire"):
            fim_installed = True
            logger.debug("Tripwire is installed")
            
            # Check if Tripwire database is initialized
            if not os.path.exists("/var/lib/tripwire/") or len(os.listdir("/var/lib/tripwire/")) == 0:
                self.add_issue(
                    Severity.HIGH,
                    "Tripwire Not Initialized",
                    "Tripwire is installed but the database is not initialized.",
                    "Initialize Tripwire with 'sudo tripwire --init'."
                )
            
            # Check if Tripwire runs regularly
            tripwire_cron = False
            for cron_dir in ["/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.d/"]:
                if os.path.exists(cron_dir) and any("tripwire" in f for f in os.listdir(cron_dir)):
                    tripwire_cron = True
                    break
            
            if not tripwire_cron:
                self.add_issue(
                    Severity.MEDIUM,
                    "Tripwire Checks Not Scheduled",
                    "Tripwire is installed but not scheduled to run regularly.",
                    "Configure a cron job to run Tripwire checks regularly."
                )
        
        # No file integrity monitoring detected
        if not fim_installed:
            self.add_issue(
                Severity.HIGH,
                "File Integrity Monitoring Not Installed",
                "No file integrity monitoring system detected (AIDE or Tripwire).",
                "Install and configure AIDE or Tripwire for file integrity monitoring. For example: 'sudo apt install aide' or 'sudo yum install aide'."
            )

    def _check_audit_service(self):
        """Check Linux Audit service configuration."""
        logger.debug("Checking audit service...")
        
        if os.path.exists("/sbin/auditd") or os.path.exists("/usr/sbin/auditd"):
            # Check if auditd is running
            try:
                status = subprocess.run(
                    ["systemctl", "status", "auditd"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                
                if "active (running)" not in status.stdout:
                    self.add_issue(
                        Severity.MEDIUM,
                        "Audit Service Not Running",
                        "The Linux Audit service (auditd) is installed but not running.",
                        "Start and enable the audit service with 'sudo systemctl start auditd && sudo systemctl enable auditd'."
                    )
                    
                # Check basic audit rules
                rules = subprocess.run(
                    ["auditctl", "-l"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
                
                if not rules.stdout or rules.stdout.strip() == "No rules":
                    self.add_issue(
                        Severity.LOW,
                        "No Audit Rules Configured",
                        "The Linux Audit service is running but has no rules configured.",
                        "Configure audit rules in /etc/audit/rules.d/ or with 'sudo auditctl'."
                    )
            except subprocess.SubprocessError:
                self.add_issue(
                    Severity.LOW,
                    "Could Not Check Audit Service",
                    "Could not determine the status of the Linux Audit service.",
                    "Verify audit service configuration manually with 'systemctl status auditd'."
                )
        else:
            self.add_issue(
                Severity.LOW,
                "Audit Service Not Installed",
                "The Linux Audit service (auditd) is not installed.",
                "Consider installing auditd for enhanced security monitoring: 'sudo apt install auditd' or 'sudo yum install audit'."
            )

    def _check_ssh_configuration(self):
        """Check SSH server configuration for security best practices."""
        logger.debug("Checking SSH configuration...")
        
        ssh_config_file = "/etc/ssh/sshd_config"
        if not os.path.exists(ssh_config_file):
            logger.debug("SSH server configuration not found")
            return
        
        try:
            with open(ssh_config_file, "r") as f:
                config_content = f.read()
            
            # Check for root login permitted
            if re.search(r"^PermitRootLogin\s+yes", config_content, re.MULTILINE):
                self.add_issue(
                    Severity.HIGH,
                    "SSH Root Login Enabled",
                    "SSH configuration allows root to log in directly.",
                    "Disable root login by setting 'PermitRootLogin no' in /etc/ssh/sshd_config and restart the SSH service."
                )
                
            # Check for password authentication
            if not re.search(r"^PasswordAuthentication\s+no", config_content, re.MULTILINE):
                self.add_issue(
                    Severity.MEDIUM,
                    "SSH Password Authentication Enabled",
                    "SSH configuration allows password-based authentication, which is less secure than key-based authentication.",
                    "Consider using key-based authentication only by setting 'PasswordAuthentication no' in /etc/ssh/sshd_config."
                )
                
            # Check SSH protocol version
            if re.search(r"^Protocol\s+1", config_content, re.MULTILINE):
                self.add_issue(
                    Severity.CRITICAL,
                    "Obsolete SSH Protocol Version",
                    "SSH configuration uses obsolete and insecure Protocol version 1.",
                    "Use only Protocol version 2 by setting 'Protocol 2' in /etc/ssh/sshd_config."
                )
        except Exception as e:
            logger.error(f"Error checking SSH configuration: {e}")
            self.add_issue(
                Severity.LOW,
                "Could Not Check SSH Configuration",
                f"An error occurred while checking SSH configuration: {str(e)}",
                "Verify SSH configuration manually."
            )

    def generate_report(self):
        """Generate HTML security report."""
        logger.info(f"Generating security report: {self.report_file}")
        
        # Count issues by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for issue in self.issues:
            severity = issue["severity"]
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Create HTML report
        with open(self.report_file, "w") as f:
            f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; color: #333; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .summary {{ display: flex; justify-content: space-between; margin-bottom: 20px; }}
        .summary-box {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }}
        .summary-critical {{ background-color: #ffeeee; }}
        .summary-high {{ background-color: #fff6ee; }}
        .summary-medium {{ background-color: #ffffee; }}
        .summary-low {{ background-color: #eeffee; }}
        .summary-info {{ background-color: #eeeeff; }}
        .summary-count {{ font-size: 24px; font-weight: bold; }}
        .dashboard {{ display: flex; flex-wrap: wrap; margin-bottom: 20px; }}
        .dashboard-item {{ flex: 1; min-width: 200px; margin: 10px; padding: 15px; border: 1px solid #ddd; }}
        .section {{ margin-bottom: 30px; }}
        .issue {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
        .critical {{ border-color: #ff0000; background-color: #ffeeee; }}
        .high {{ border-color: #ff6600; background-color: #fff6ee; }}
        .medium {{ border-color: #ffcc00; background-color: #ffffee; }}
        .low {{ border-color: #00cc00; background-color: #eeffee; }}
        .info {{ border-color: #0066cc; background-color: #eeeeff; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ text-align: left; padding: 8px; border: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>Cloud Infrastructure Platform Security Audit Report</h1>
    <p>Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Server: {socket.gethostname()}</p>

    <div id="summary" class="section">
        <h2>Executive Summary</h2>
        <div class="dashboard">
            <div class="dashboard-item summary-critical">
                <h3>Critical</h3>
                <p class="summary-count" id="critical-count">{severity_counts["critical"]}</p>
            </div>
            <div class="dashboard-item summary-high">
                <h3>High</h3>
                <p class="summary-count" id="high-count">{severity_counts["high"]}</p>
            </div>
            <div class="dashboard-item summary-medium">
                <h3>Medium</h3>
                <p class="summary-count" id="medium-count">{severity_counts["medium"]}</p>
            </div>
            <div class="dashboard-item summary-low">
                <h3>Low</h3>
                <p class="summary-count" id="low-count">{severity_counts["low"]}</p>
            </div>
            <div class="dashboard-item summary-info">
                <h3>Info</h3>
                <p class="summary-count" id="info-count">{severity_counts["info"]}</p>
            </div>
        </div>
    </div>

    <div id="findings" class="section">
        <h2>Detailed Findings</h2>
""")

            # Write issues by severity
            for severity in ["critical", "high", "medium", "low", "info"]:
                severity_issues = [issue for issue in self.issues if issue["severity"] == severity]
                if severity_issues:
                    f.write(f"        <h3>{severity.capitalize()} Severity Issues</h3>\n")
                    
                    for issue in severity_issues:
                        f.write(f"""        <div class="issue {issue["severity"]}">
            <h3>{issue["title"]}</h3>
            <p><strong>Severity:</strong> {issue["severity"]}</p>
            <p><strong>Description:</strong> {issue["description"]}</p>
            <p><strong>Recommendation:</strong> {issue["recommendation"]}</p>
        </div>
""")
            
            f.write("""    </div>
    
    <div class="section">
        <h2>System Information</h2>
        <table>
            <tr>
                <th>Information</th>
                <th>Value</th>
            </tr>""")
            
            # Add system information
            system_info = {
                "Hostname": socket.gethostname(),
                "Kernel Version": os.uname().release,
                "OS Version": self._get_os_version(),
                "Audit Date": self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "Total Issues": len(self.issues)
            }
            
            for key, value in system_info.items():
                f.write(f"""
            <tr>
                <td>{key}</td>
                <td>{value}</td>
            </tr>""")
            
            f.write("""
        </table>
    </div>

    <div id="recommendations" class="section">
        <h2>Prioritized Recommendations</h2>
        <ol>""")
            
            # Add recommendations for critical and high issues
            for severity in ["critical", "high"]:
                for issue in [i for i in self.issues if i["severity"] == severity]:
                    f.write(f"""
            <li><strong>{issue["title"]}</strong>: {issue["recommendation"]}</li>""")
            
            f.write("""
        </ol>
    </div>

    <div id="footer" class="section">
        <p>For more information on security best practices, refer to the Cloud Infrastructure Platform Security Guide.</p>
    </div>
</body>
</html>""")
        
        # Set appropriate permissions for report file
        os.chmod(self.report_file, 0o640)
        
        return self.report_file

    def _get_os_version(self):
        """Get OS version information."""
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    os_release = dict(line.strip().split("=", 1) for line in f if "=" in line)
                return os_release.get("PRETTY_NAME", "Unknown").strip('"')
            elif os.path.exists("/etc/redhat-release"):
                with open("/etc/redhat-release") as f:
                    return f.read().strip()
            else:
                return "Unknown"
        except Exception as e:
            logger.error(f"Error getting OS version: {e}")
            return "Unknown"

    def get_overall_status(self):
        """Get overall security status based on issues found."""
        if any(issue["severity"] == "critical" for issue in self.issues):
            return "CRITICAL"
        elif any(issue["severity"] == "high" for issue in self.issues):
            return "HIGH"
        elif any(issue["severity"] == "medium" for issue in self.issues):
            return "MEDIUM"
        elif any(issue["severity"] == "low" for issue in self.issues):
            return "LOW"
        else:
            return "CLEAN"


def main() -> int:
    """Main entry point for security audit script."""
    args = parse_arguments()

    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("Starting security audit...")

    # Initialize security auditor
    auditor = SecurityAuditor()
    
    # Add initialization message
    auditor.add_issue(
        Severity.INFO,
        "Security Audit Initialized",
        "The security audit system is functioning properly.",
        "Continue with regular security audits and monitoring."
    )

    # Set email recipient if provided
    email_recipient = args.email if args.email else EMAIL_RECIPIENT
    
    try:
        # Perform only security updates check if specified
        if args.updates_only:
            logger.info("Running in updates-only mode")
            security_updates = auditor.check_security_updates()
            logger.info("Security updates check complete")
            
            # Generate report even if no updates found for consistency
            report_file = auditor.generate_report()
            logger.info(f"Report saved to: {report_file}")
            
            # Send email notification if configured and issues were found
            if security_updates > 0 and email_recipient and os.path.exists("/usr/bin/mail"):
                try:
                    subject = "Security Updates Available"
                    if any(issue["severity"] == "critical" for issue in auditor.issues):
                        subject = "CRITICAL: " + subject
                    
                    body = f"""Security updates are available for {socket.gethostname()}.

Server: {socket.gethostname()}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

The full report is available at: {report_file}
"""
                    # Send email
                    subprocess.run(
                        ["mail", "-s", subject, email_recipient],
                        input=body.encode(),
                        check=True
                    )
                    logger.info(f"Email notification sent to {email_recipient}")
                except Exception as e:
                    logger.error(f"Failed to send email notification: {e}")
            
        else:
            # Perform full security audit
            logger.info("Running full security audit")
            auditor.check_security_updates()
            auditor.check_ssl()
            auditor.check_users()
            auditor.check_files()
            auditor.check_security_config()
            auditor.check_firewall()
            auditor.check_services()
            
            # Generate report
            report_file = auditor.generate_report()
            logger.info(f"Security audit complete. Report saved to: {report_file}")
            
            # Send email notification for full audit if configured
            if email_recipient and os.path.exists("/usr/bin/mail"):
                try:
                    status = auditor.get_overall_status()
                    subject = f"Security Audit Report - {socket.gethostname()}"
                    
                    # Emphasize critical status in subject line
                    if status == "CRITICAL":
                        subject = f"CRITICAL: {subject}"
                    elif status == "HIGH":
                        subject = f"HIGH RISK: {subject}"
                    
                    # Count issues by severity
                    severity_counts = {severity: sum(1 for issue in auditor.issues if issue["severity"] == severity)
                                    for severity in ["critical", "high", "medium", "low", "info"]}
                    
                    # Create email body
                    body = f"""Cloud Infrastructure Platform Security Audit Report is ready.

Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Server: {socket.gethostname()}
Overall Status: {status}

Issue Summary:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Info: {severity_counts['info']}

The full report is available at: {report_file}
"""
                    # Send email
                    subprocess.run(
                        ["mail", "-s", subject, email_recipient],
                        input=body.encode(),
                        check=True
                    )
                    logger.info(f"Email notification sent to {email_recipient}")
                except Exception as e:
                    logger.error(f"Failed to send email notification: {e}")
    
    except KeyboardInterrupt:
        logger.warning("Security audit interrupted by user")
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        logger.error(f"Unhandled exception in security audit: {e}")
        return 1
        
    # Return non-zero exit code if critical or high severity issues found
    critical_high_issues = [issue for issue in auditor.issues 
                          if issue["severity"] in ("critical", "high")]
    return 1 if critical_high_issues else 0


if __name__ == "__main__":
    sys.exit(main())
