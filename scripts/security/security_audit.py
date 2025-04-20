#!/usr/bin/env python3
# Security audit tool for Cloud Infrastructure Platform
# Checks for security vulnerabilities and misconfigurations
# Usage: python security_audit.py [--email <recipient>]

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
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Security audit tool")
    parser.add_argument(
        "--email", 
        help="Email address to send the report to"
    )
    parser.add_argument(
        "--updates-only",
        action="store_true",
        help="Only run security updates check"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Increase output verbosity"
    )
    return parser.parse_args()

class SecurityAuditor:
    """Main security audit class that performs checks and generates reports."""

    def __init__(self):
        """Initialize the security auditor."""
        self.issues = []
        self.timestamp = datetime.now()
        self.report_file = REPORT_FILE.with_name(f"{REPORT_FILE.name}{self.timestamp.strftime('%Y%m%d-%H%M%S')}.html")
        
    def add_issue(self, severity: Severity, title: str, description: str, recommendation: str):
        """Add a security issue to the report."""
        self.issues.append({
            "severity": severity.value if isinstance(severity, Severity) else severity,
            "title": title,
            "description": description,
            "recommendation": recommendation
        })
        logger.info(f"{severity}: {title}")

    def check_security_updates(self):
        """Check for available security updates."""
        logger.info("Checking for security updates...")
        
        # For Debian/Ubuntu
        if os.path.exists("/usr/bin/apt-get"):
            try:
                # Update package lists
                subprocess.run(["apt-get", "update", "-qq"], check=True, capture_output=True)
                
                # Check for security updates
                result = subprocess.run(
                    ["apt-get", "--just-print", "upgrade"], 
                    check=True, 
                    capture_output=True, 
                    text=True
                )
                
                # Count security updates
                security_updates = len(re.findall(r"^Inst.*security", result.stdout, re.MULTILINE))
                
                if security_updates > 0:
                    # Check for critical packages
                    update_details = re.findall(r"^Inst.*security", result.stdout, re.MULTILINE)
                    critical_packages = ["openssl", "openssh", "linux-", "nginx", "postgresql", "apache2"]
                    
                    critical_updates = 0
                    for package in update_details:
                        if any(critical in package.lower() for critical in critical_packages):
                            critical_updates += 1
                    
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
                logger.error(f"Error checking for security updates: {e}")
                self.add_issue(
                    Severity.MEDIUM,
                    "Could not check for security updates",
                    f"Error while checking for security updates: {e}",
                    "Verify that the package manager is working correctly."
                )
                return -1
        
        # For CentOS/RHEL/Fedora
        elif os.path.exists("/usr/bin/yum"):
            try:
                # Check security updates
                result = subprocess.run(
                    ["yum", "check-update", "--security"], 
                    check=False,  # yum returns 100 when updates are available
                    capture_output=True, 
                    text=True
                )
                
                # Parse output to count updates
                lines = result.stdout.strip().split('\n')
                security_updates = sum(1 for line in lines if re.match(r"^[a-zA-Z0-9]", line))
                
                if security_updates > 0:
                    # Check for critical packages
                    critical_packages = ["openssl", "openssh", "kernel", "nginx", "postgresql", "httpd"]
                    
                    critical_updates = 0
                    for line in lines:
                        if any(critical in line.lower() for critical in critical_packages):
                            critical_updates += 1
                    
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
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Error checking for security updates: {e}")
                self.add_issue(
                    Severity.MEDIUM,
                    "Could not check for security updates",
                    f"Error while checking for security updates: {e}",
                    "Verify that the package manager is working correctly."
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
        """Check SSL certificate expiration and configuration."""
        logger.info("Checking SSL/TLS configuration...")
        # SSL check implementation
        try:
            # List of domains to check
            domains = ["cloud-platform.example.com"]
            
            for domain in domains:
                try:
                    # Get certificate info
                    cert_data = ssl.get_server_certificate((domain, 443))
                    x509 = ssl.PEM_cert_to_DER_cert(cert_data)
                    
                    # Check expiration
                    cert = ssl._ssl._test_decode_cert(x509)
                    expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.now()).days
                    
                    if days_left < 7:
                        self.add_issue(
                            Severity.CRITICAL,
                            "SSL Certificate Expiring Soon",
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
                except:
                    # Skip if we can't connect to the domain
                    continue
                    
        except Exception as e:
            logger.error(f"Error checking SSL certificates: {e}")
            self.add_issue(
                Severity.MEDIUM,
                "Unable to check SSL certificates",
                "An error occurred while checking SSL certificates.",
                "Verify SSL certificates manually."
            )

    def check_users(self):
        """Check user security configuration."""
        logger.info("Checking user security configuration...")
        # User security check implementation
        try:
            # Get all regular user accounts
            users = []
            with open("/etc/passwd", "r") as passwd_file:
                for line in passwd_file:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = int(parts[2])
                        shell = parts[6]
                        
                        # Check only standard users
                        if uid >= 1000 and "/bin/" in shell:
                            users.append(username)
            
            # Check user password status
            for username in users:
                try:
                    result = subprocess.run(
                        ["passwd", "-S", username],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    
                    if "NP" in result.stdout or "Empty" in result.stdout:
                        self.add_issue(
                            Severity.CRITICAL,
                            "User Account Without Password",
                            f"User account {username} has no password set.",
                            f"Set a strong password for user {username}."
                        )
                    elif "L" in result.stdout:
                        # Locked account - this is good
                        pass
                    elif "P" in result.stdout and "Password set" in result.stdout:
                        # Account has password, check expiry
                        expiry_result = subprocess.run(
                            ["chage", "-l", username],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        
                        if "Password expires" in expiry_result.stdout and "never" in expiry_result.stdout.lower():
                            self.add_issue(
                                Severity.LOW,
                                "Password Never Expires",
                                f"Password for user {username} is set to never expire.",
                                f"Configure password expiration for user {username}."
                            )
                except:
                    continue
                        
        except Exception as e:
            logger.error(f"Error checking user accounts: {e}")

    def check_files(self):
        """Check file permissions."""
        logger.info("Checking file permissions...")
        # File permission check implementation
        sensitive_files = [
            "/etc/shadow",
            "/etc/ssh/sshd_config",
            "/etc/cloud-platform/security/",
            "/etc/nginx/nginx.conf",
            "/etc/nginx/conf.d/",
        ]
        
        for file_path in sensitive_files:
            try:
                if os.path.exists(file_path):
                    stat_info = os.stat(file_path)
                    mode = stat_info.st_mode
                    if stat_info.st_uid == 0:  # Owned by root
                        if mode & 0o077:  # Group or others have any permissions
                            self.add_issue(
                                Severity.HIGH,
                                "Insecure File Permissions",
                                f"File {file_path} has insecure permissions: {oct(mode & 0o777)}",
                                f"Fix permissions with: chmod go-rwx {file_path}"
                            )
            except Exception as e:
                logger.error(f"Error checking file permissions for {file_path}: {e}")

    def check_security_config(self):
        """Check security configuration."""
        logger.info("Checking security configuration...")
        # Security config check implementation
        try:
            # Get list of listening TCP ports using netstat or ss
            if os.path.exists("/usr/bin/netstat"):
                result = subprocess.run(
                    ["netstat", "-tuln"], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            else:
                result = subprocess.run(
                    ["ss", "-tuln"], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                
            # Allowed ports (SSH, HTTP, HTTPS, PostgreSQL)
            allowed_ports = [22, 80, 443, 5432]
            open_ports = []
            
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part:
                            try:
                                port = int(part.split(':')[-1])
                                if port not in allowed_ports and port < 65000:
                                    open_ports.append(port)
                            except ValueError:
                                continue
            
            if open_ports:
                self.add_issue(
                    Severity.MEDIUM,
                    "Unnecessary Open Ports",
                    f"The following ports are open but may not be required: {', '.join(map(str, open_ports))}",
                    "Close unnecessary ports in the firewall configuration."
                )
                    
        except Exception as e:
            logger.error(f"Error checking open ports: {e}")

    def check_firewall(self):
        """Check firewall configuration."""
        logger.info("Checking firewall configuration...")
        # Firewall check implementation
        try:
            # Try ufw first (Ubuntu/Debian)
            if os.path.exists("/usr/sbin/ufw"):
                result = subprocess.run(
                    ["ufw", "status"], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                
                if "Status: active" not in result.stdout:
                    self.add_issue(
                        Severity.HIGH,
                        "Firewall Disabled",
                        "The UFW firewall is not active.",
                        "Enable the firewall with 'sudo ufw enable'."
                    )
            
            # Try firewalld (CentOS/RHEL)
            elif os.path.exists("/usr/bin/firewall-cmd"):
                result = subprocess.run(
                    ["firewall-cmd", "--state"], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                
                if "running" not in result.stdout:
                    self.add_issue(
                        Severity.HIGH,
                        "Firewall Disabled",
                        "The firewalld service is not running.",
                        "Enable the firewall with 'sudo systemctl start firewalld'."
                    )
                    
        except Exception as e:
            logger.error(f"Error checking firewall status: {e}")
            self.add_issue(
                Severity.MEDIUM,
                "Unable to check firewall status",
                "An error occurred while checking the firewall status.",
                "Verify firewall configuration manually."
            )

    def check_services(self):
        """Check service security."""
        logger.info("Checking service security...")
        # Service security check implementation
        try:
            # Check if AIDE is installed and configured
            if os.path.exists("/usr/bin/aide"):
                aide_db = "/var/lib/aide/aide.db"
                if not os.path.exists(aide_db):
                    self.add_issue(
                        Severity.HIGH,
                        "File Integrity Monitoring Not Initialized",
                        "AIDE is installed but the database is not initialized.",
                        "Initialize AIDE with 'sudo aide --init' and copy the database."
                    )
                    
                # Check if AIDE runs regularly
                cron_files = ["/etc/cron.daily/aide", "/etc/cron.d/aide"]
                aide_configured = False
                
                for cron_file in cron_files:
                    if os.path.exists(cron_file):
                        aide_configured = True
                        break
                
                if not aide_configured:
                    self.add_issue(
                        Severity.MEDIUM,
                        "File Integrity Checks Not Scheduled",
                        "AIDE is installed but not scheduled to run regularly.",
                        "Configure a cron job to run AIDE checks regularly."
                    )
            else:
                self.add_issue(
                    Severity.MEDIUM,
                    "File Integrity Monitoring Not Installed",
                    "No file integrity monitoring system detected.",
                    "Install and configure AIDE for file integrity monitoring."
                )
                    
        except Exception as e:
            logger.error(f"Error checking file integrity monitoring: {e}")

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


def main():
    """Main entry point for security audit script."""
    args = parse_arguments()
    
    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    logger.info("Starting security audit...")
    
    # Initialize security auditor
    auditor = SecurityAuditor()
    
    # Set email recipient if provided
    email_recipient = args.email if args.email else EMAIL_RECIPIENT
    
    # Perform only security updates check if specified
    if args.updates_only:
        security_updates = auditor.check_security_updates()
        logger.info("Security updates check complete")
        
        # Generate report if issues were found
        if security_updates > 0:
            report_file = auditor.generate_report()
            
            # Send email notification if configured
            if email_recipient and os.path.exists("/usr/bin/mail"):
                subject = "Security Updates Available"
                if any(issue["severity"] == "critical" for issue in auditor.issues):
                    subject = "CRITICAL: " + subject
                
                try:
                    # Create email body
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
            
            # Return non-zero exit code if critical or high severity issues found
            return 0 if not any(issue["severity"] in ("critical", "high") for issue in auditor.issues) else 1
        return 0
    
    # Perform full security audit
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
    
    # Send email notification for full audit
    if email_recipient and os.path.exists("/usr/bin/mail"):
        status = auditor.get_overall_status()
        subject = f"Security Audit Report - {socket.gethostname()}"
        
        # Emphasize critical status in subject line
        if status == "CRITICAL":
            subject = f"CRITICAL: {subject}"
        elif status == "HIGH":
            subject = f"HIGH RISK: {subject}"
        
        try:
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
    
    # Return non-zero exit code if critical or high severity issues found
    critical_high_issues = [issue for issue in auditor.issues 
                            if issue["severity"] in ("critical", "high")]
    if critical_high_issues:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
