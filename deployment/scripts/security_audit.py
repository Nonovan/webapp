#!/usr/bin/env python3
"""
Security audit script for Cloud Infrastructure Platform.
Checks for security vulnerabilities and misconfigurations.
"""

import os
import sys
import re
import json
import argparse
import logging
import socket
import subprocess
import datetime
import ssl
import pwd
import grp
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
LOG_FILE = Path("/var/log/cloud-platform/security_audit.log")
REPORT_FILE = Path("/var/www/reports/security-audit-")  # Will add date
EMAIL_RECIPIENT = "security@example.com"

# Ensure directories exist
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security_audit")

# Define severity levels
class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityIssue:
    """Class to represent a security issue."""
    
    def __init__(self, severity: str, title: str, description: str, recommendation: str):
        self.severity = severity
        self.title = title
        self.description = description
        self.recommendation = recommendation


class SecurityAudit:
    """Main security audit class."""
    
    def __init__(self, report_file: Optional[Path] = None, email: Optional[str] = None):
        """Initialize the security audit."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d")
        self.report_file = report_file or REPORT_FILE.with_name(f"{REPORT_FILE.name}{timestamp}.html")
        self.email_recipient = email or EMAIL_RECIPIENT
        self.issues: List[SecurityIssue] = []
        self.hostname = socket.gethostname()
        self.os_info = self._get_os_info()
    
    def _get_os_info(self) -> str:
        """Get OS version information."""
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=')[1].strip().strip('"')
            return "Unknown OS"
        except Exception as e:
            logger.error(f"Error getting OS information: {e}")
            return "Unknown OS"
    
    def add_issue(self, severity: str, title: str, description: str, recommendation: str) -> None:
        """Add a security issue."""
        #!/usr/bin/env python3
"""
Security audit script for Cloud Infrastructure Platform.
Checks for security vulnerabilities and misconfigurations.
"""

import os
import sys
import re
import json
import argparse
import logging
import socket
import subprocess
import datetime
import ssl
import pwd
import grp
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
LOG_FILE = Path("/var/log/cloud-platform/security_audit.log")
REPORT_FILE = Path("/var/www/reports/security-audit-")  # Will add date
EMAIL_RECIPIENT = "security@example.com"

# Ensure directories exist
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security_audit")

# Define severity levels
class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityIssue:
    """Class to represent a security issue."""
    
    def __init__(self, severity: str, title: str, description: str, recommendation: str):
        self.severity = severity
        self.title = title
        self.description = description
        self.recommendation = recommendation


class SecurityAudit:
    """Main security audit class."""
    
    def __init__(self, report_file: Optional[Path] = None, email: Optional[str] = None):
        """Initialize the security audit."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d")
        self.report_file = report_file or REPORT_FILE.with_name(f"{REPORT_FILE.name}{timestamp}.html")
        self.email_recipient = email or EMAIL_RECIPIENT
        self.issues: List[SecurityIssue] = []
        self.hostname = socket.gethostname()
        self.os_info = self._get_os_info()
    
    def _get_os_info(self) -> str:
        """Get OS version information."""
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=')[1].strip().strip('"')
            return "Unknown OS"
        except Exception as e:
            logger.error(f"Error getting OS information: {e}")
            return "Unknown OS"
    
    def add_issue(self, severity: str, title: str, description: str, recommendation: str) -> None:
        """Add a security issue."""
