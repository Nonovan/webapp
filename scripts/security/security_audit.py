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


class SecurityAuditor:
    """Main security audit class that performs checks and generates reports."""

    def __init__(self):
        self.issues = []
        self.timestamp = datetime.now()
        self.report_file = Path(f"{REPORT_FILE}{self.timestamp.strftime('%Y-%m-%d_%H-%M-%S')}.html")

    def add_issue(self, severity: Severity, title: str, description: str, recommendation: str):
        """Add a security issue to the report.
        
        Args:
            severity: Issue severity level
            title: Short issue title
            description: Detailed description of the issue
            recommendation: Recommended remediation steps
        """
        self.issues.append({
            "severity": severity.value,
            "title": title,
            "description": description,
            "recommendation": recommendation,
        })
        logger.info(f"Found {severity.value} issue: {title}")

    def check_security_updates(self):
        """Check for available security updates in the system."""
        logger.info("Checking for security updates")
        try:
            # First check if apt is available (Debian/Ubuntu)
            if os.path.exists("/usr/bin/apt"):
                result = subprocess.run(
                    ["apt", "-s", "upgrade"], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                
                if result.returncode == 0:
                    security_updates = len([l for l in result.stdout.split("\n") if "security" in l and "Inst" in l])
                    
                    if security_updates > 10:
                        self.add_issue(
                            Severity.CRITICAL,
                            "Critical security updates required",
                            f"There are {security_updates} security updates available.",
                            "Run 'sudo apt update && sudo apt upgrade' to install security updates.",
                        )
                    elif security_updates > 0:
                        self.add_issue(
                            Severity.HIGH,
                            "Security updates available",
                            f"There are {security_updates} security updates available.",
                            "Run 'sudo apt update && sudo apt upgrade' to install security updates.",
                        )
            else:
                # Check with yum if apt is not available
                result = subprocess.run(
                    ["yum", "check-update", "--security"], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if result.returncode == 100:  # 100 means updates available
                    security_updates = len([l for l in result.stdout.split("\n") if l and not l.startswith(("Loaded plugins", "Last metadata", " "))])
                    
                    if security_updates > 10:
                        self.add_issue(
                            Severity.CRITICAL,
                            "Critical security updates required",
                            f"There are {security_updates} security updates available.",
                            "Run 'sudo yum update --security' to install security updates.",
                        )
                    elif security_updates > 0:
                        self.add_issue(
                            Severity.HIGH,
                            "Security updates available",
                            f"There are {security_updates} security updates available.",
                            "Run 'sudo yum update --security' to install security updates.",
                        )
        except Exception as e:
            logger.error(f"Error checking security updates: {e}")
            self.add_issue(
                Severity.MEDIUM,
                "Unable to check security updates",
                "An error occurred while checking for security updates.",
                "Verify that the package manager is working correctly and try again."
            )

    def check_ssl_certificates(self):
        """Check SSL certificate expiration and configuration."""
        logger.info("Checking SSL certificates")
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

    def check_file_permissions(self):
        """Check file permissions for sensitive files."""
        logger.info("Checking file permissions")
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

    def check_firewall_status(self):
        """Check if firewall is enabled and properly configured."""
        logger.info("Checking firewall status")
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

    def check_open_ports(self):
        """Check for unnecessary open ports."""
        logger.info("Checking for open ports")
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

    def check_file_integrity(self):
        """Check if file integrity monitoring is configured and running."""
        logger.info("Checking file integrity monitoring")
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

    def check_user_accounts(self):
        """Check for user accounts with weak security configurations."""
        logger.info("Checking user accounts")
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

    def run_all_checks(self):
        """Run all security checks."""
        logger.info("Starting security audit")
        
        self.check_security_updates()
        self.check_ssl_certificates()
        self.check_file_permissions()
        self.check_firewall_status()
        self.check_open_ports()
        self.check_file_integrity()
        self.check_user_accounts()
        
        logger.info(f"Security audit complete: found {len(self.issues)} issues")

    def generate_report(self):
        """Generate HTML report with all found issues."""
        logger.info(f"Generating report to {self.report_file}")
        
        # Count issues by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for issue in self.issues:
            severity_counts[issue["severity"]] += 1
        
        with open(self.report_file, "w") as f:
            f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {self.timestamp.strftime("%Y-%m-%d")}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
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
    <h1>Cloud Infrastructure Platform - Security Audit Report</h1>
    <p>Generated on {self.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for {socket.gethostname()}</p>
    
    <div class="section">
        <h2>Summary</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            <tr>
                <td>Critical</td>
                <td id="critical-count">{severity_counts["critical"]}</td>
            </tr>
            <tr>
                <td>High</td>
                <td id="high-count">{severity_counts["high"]}</td>
            </tr>
            <tr>
                <td>Medium</td>
                <td id="medium-count">{severity_counts["medium"]}</td>
            </tr>
            <tr>
                <td>Low</td>
                <td id="low-count">{severity_counts["low"]}</td>
            </tr>
            <tr>
                <td>Info</td>
                <td id="info-count">{severity_counts["info"]}</td>
            </tr>
        </table>
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
            </tr>
""")

            # Add system info
            try:
                # Get OS info
                with open("/etc/os-release", "r") as os_file:
                    os_info = {}
                    for line in os_file:
                        if "=" in line:
                            key, value = line.strip().split("=", 1)
                            os_info[key] = value.strip('"')
                
                f.write(f'            <tr><td>OS</td><td>{os_info.get("PRETTY_NAME", "Unknown")}</td></tr>\n')
                f.write(f'            <tr><td>Kernel</td><td>{os.uname().release}</td></tr>\n')
                f.write(f'            <tr><td>Hostname</td><td>{socket.gethostname()}</td></tr>\n')
            except:
                pass

            f.write("""        </table>
    </div>
</body>
</html>
""")
        
        logger.info(f"Report generated: {self.report_file}")
        return self.report_file

    def email_report(self, recipient: str):
        """Email the generated report to a specified recipient.
        
        Args:
            recipient: Email address to send the report to
        """
        logger.info(f"Emailing report to {recipient}")
        
        try:
            if not os.path.exists("/usr/bin/mail"):
                logger.error("Mail command not found")
                return False
                
            subject = f"Security Audit Report - {severity_label()}"
            
            subprocess.run(
                ["mail", "-s", subject, "-a", str(self.report_file), recipient],
                input=f"Security audit completed on {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
                      f"Please see the attached report for details.\n",
                text=True,
                check=True
            )
            
            logger.info(f"Report emailed successfully to {recipient}")
            return True
        except Exception as e:
            logger.error(f"Failed to email report: {e}")
            return False
            
    def severity_label(self):
        """Return a severity label based on the most severe issues found."""
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
    """Main entry point for the security audit tool."""
    parser = argparse.ArgumentParser(description="Cloud Infrastructure Platform Security Audit Tool")
    parser.add_argument("--email", help="Email address to send the report to")
    args = parser.parse_args()
    
    recipient = args.email or EMAIL_RECIPIENT
    
    auditor = SecurityAuditor()
    auditor.run_all_checks()
    report_file = auditor.generate_report()
    
    if recipient:
        auditor.email_report(recipient)
    
    print(f"Security audit complete. Report saved to: {report_file}")
    
    # Return non-zero exit code if critical or high severity issues found
    critical_high_issues = [issue for issue in auditor.issues 
                            if issue["severity"] in ("critical", "high")]
    if critical_high_issues:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
