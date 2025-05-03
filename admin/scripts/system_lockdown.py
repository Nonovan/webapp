#!/usr/bin/env python3
"""
System Security Lockdown Script for Cloud Infrastructure Platform.

This script applies security hardening configurations based on defined levels or policies.
It's a Python implementation of system_lockdown.sh with enhanced cross-platform support
and improved security controls.

Usage:
  python system_lockdown.py [--environment <env>] [--security-level <level>]
                          [--component <name>] [--apply-policy <policy>]
                          [--verify] [--policy-file <file>] [--force]

Examples:
  # Apply high security level lockdown in production
  python system_lockdown.py --environment production --security-level high

  # Apply specific policy to the authentication component
  python system_lockdown.py --component authentication --apply-policy strict-mfa

  # Verify current configuration against a baseline policy file
  python system_lockdown.py --verify --policy-file security-baseline.json
"""

import argparse
import datetime
import json
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any, Callable

# Add project root to path to allow imports from core packages
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from core.utils.logging_utils import logger as get_logger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

# Default settings
DEFAULT_ENVIRONMENT = "production"
DEFAULT_SECURITY_LEVEL = "high"
LOG_DIR = Path("/var/log/cloud-platform/admin")
BACKUP_DIR = Path("/var/backups/cloud-platform/lockdown")
HARDENING_PROFILES_DIR = PROJECT_ROOT / "admin/security/incident_response_kit/recovery/resources/hardening_profiles"
BASELINE_DIR = PROJECT_ROOT / "admin/security/assessment_tools/config_files/security_baselines"
DEPLOYMENT_SECURITY_CONFIG = PROJECT_ROOT / "deployment/security/config"
DEPLOYMENT_SECURITY_SCRIPTS = PROJECT_ROOT / "deployment/security/scripts"

# Setup logging
if not LOG_DIR.exists():
    os.makedirs(LOG_DIR, exist_ok=True)
if not BACKUP_DIR.exists():
    os.makedirs(BACKUP_DIR, exist_ok=True)

timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
LOG_FILE = LOG_DIR / f"system_lockdown_{timestamp}.log"

if LOGGER_AVAILABLE:
    logger = get_logger(__name__, log_file=LOG_FILE)
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)


class Severity(Enum):
    """Severity levels for validation results."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    """Data class for validation results."""
    category: str
    control_id: str
    status: Severity
    description: str
    details: Optional[Dict[str, Any]] = None
    actual_output: Optional[str] = None


class SystemLockdown:
    """Main class for system security lockdown operations."""

    def __init__(self):
        """Initialize the System Lockdown controller."""
        self.environment = DEFAULT_ENVIRONMENT
        self.security_level = DEFAULT_SECURITY_LEVEL
        self.component = ""
        self.apply_policy = ""
        self.verify_mode = False
        self.policy_file = ""
        self.force_mode = False
        self.policy_source = ""
        self.is_linux = platform.system() == "Linux"
        self.is_macos = platform.system() == "Darwin"
        self.is_windows = platform.system() == "Windows"
        self.results = []

    def parse_args(self) -> bool:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description="System Security Lockdown Script",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent("""
            Examples:
              # Apply high security level lockdown in production
              python system_lockdown.py --environment production --security-level high

              # Apply specific policy to the authentication component
              python system_lockdown.py --component authentication --apply-policy strict-mfa

              # Verify current configuration against a baseline policy file
              python system_lockdown.py --verify --policy-file security-baseline.json
            """)
        )
        parser.add_argument("--environment", help=f"Target environment (default: {DEFAULT_ENVIRONMENT})")
        parser.add_argument("--security-level", help="Apply a predefined security level (e.g., baseline, medium, high, critical)")
        parser.add_argument("--component", help="Target a specific system component (e.g., ssh, kernel, authentication, network, filesystem)")
        parser.add_argument("--apply-policy", help="Apply a specific named policy (requires --component)")
        parser.add_argument("--verify", action="store_true", help="Verify current configuration against the specified level or policy file")
        parser.add_argument("--policy-file", help="Path to a custom policy file (JSON format) for applying or verifying")
        parser.add_argument("--force", action="store_true", help="Apply changes without confirmation prompts")

        args = parser.parse_args()

        if args.environment:
            self.environment = args.environment

        if args.security_level:
            self.security_level = args.security_level

        if args.component:
            self.component = args.component

        if args.apply_policy:
            self.apply_policy = args.apply_policy

        if args.verify:
            self.verify_mode = True

        if args.policy_file:
            self.policy_file = args.policy_file

        if args.force:
            self.force_mode = True

        # Determine policy source and validate inputs
        if self.policy_file:
            policy_path = Path(self.policy_file)
            if not policy_path.exists() or not policy_path.is_file():
                logger.error(f"Policy file not found: {self.policy_file}")
                return False

            try:
                with open(policy_path, 'r') as f:
                    json.load(f)  # Validate JSON format
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON format in policy file: {self.policy_file}")
                return False

            self.policy_source = f"Policy File: {self.policy_file}"
            # Reset other options if policy file is specified
            self.security_level = ""
            self.component = ""
            self.apply_policy = ""

        elif self.component and self.apply_policy:
            self.policy_source = f"Component: {self.component}, Policy: {self.apply_policy}"
            self.security_level = ""  # Component/policy overrides level

        elif self.security_level:
            if self.security_level not in ["baseline", "medium", "high", "critical"]:
                logger.error(f"Unsupported security level: {self.security_level}. Choose from baseline, medium, high, critical.")
                return False
            self.policy_source = f"Security Level: {self.security_level}"

        else:
            logger.error("No security level, component/policy, or policy file specified.")
            return False

        logger.info(f"Starting System Lockdown Script...")
        logger.info(f"Environment: {self.environment}")
        if self.verify_mode:
            logger.info("Mode: Verification")
        else:
            logger.info("Mode: Application")

        if self.force_mode:
            logger.warning("Force mode enabled - changes will be applied without confirmation")

        return True

    def backup_config_file(self, file_path: str) -> bool:
        """
        Create a backup of configuration file or directory.

        Args:
            file_path: Path to configuration file or directory

        Returns:
            bool: True if backup was successful, False otherwise
        """
        if not file_path or not os.path.exists(file_path):
            logger.warning(f"Cannot back up '{file_path}': Path does not exist or is empty.")
            return False

        backup_path = BACKUP_DIR / f"{os.path.basename(file_path)}.{timestamp}.bak"
        logger.info(f"Backing up '{file_path}' to '{backup_path}'...")

        try:
            if os.path.isdir(file_path):
                shutil.copytree(file_path, backup_path)
            else:
                shutil.copy2(file_path, backup_path)

            # Set secure permissions for backup
            try:
                os.chmod(backup_path, 0o600)
            except OSError as e:
                logger.warning(f"Failed to set secure permissions on backup '{backup_path}': {e}")

            logger.info("Backup created successfully.")
            return True

        except (shutil.Error, OSError) as e:
            logger.error(f"Failed to create backup for '{file_path}': {e}")
            return False

    def apply_setting(self, file_path: str, setting_regex: str, new_setting: str) -> bool:
        """
        Apply a configuration setting if it doesn't already exist or match.

        Args:
            file_path: Path to configuration file
            setting_regex: Regex pattern to match the setting
            new_setting: New setting line to apply

        Returns:
            bool: True if operation was successful, False otherwise
        """
        if not os.path.isfile(file_path):
            logger.warning(f"Configuration file '{file_path}' not found. Cannot apply setting: {new_setting}")
            return False

        try:
            with open(file_path, 'r') as f:
                content = f.read()

            # Check if setting exists and matches
            pattern = re.compile(f"^\\s*{setting_regex}\\s*$", re.MULTILINE)
            match = pattern.search(content)

            if match:
                current_setting = match.group(0).strip()
                if current_setting == new_setting:
                    logger.info(f"Setting '{new_setting}' already correctly configured in '{file_path}'.")
                    return True
                else:
                    logger.info(f"Updating setting in '{file_path}': '{current_setting}' -> '{new_setting}'")
                    # Backup before modifying
                    if not self.backup_config_file(file_path):
                        return False

                    # Use regex to replace the line
                    new_content = pattern.sub(new_setting, content)
                    with open(file_path, 'w') as f:
                        f.write(new_content)

                    return True
            else:
                # Setting doesn't exist, append it
                logger.info(f"Adding setting to '{file_path}': '{new_setting}'")
                # Backup before modifying
                if not self.backup_config_file(file_path):
                    return False

                with open(file_path, 'a') as f:
                    # Ensure there's a newline before appending
                    if not content.endswith("\n"):
                        f.write("\n")
                    f.write(f"{new_setting}\n")

                return True

        except (IOError, OSError) as e:
            logger.error(f"Error applying setting to '{file_path}': {e}")
            return False

    def execute_command(self, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """
        Execute a system command with timeout and return the results.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        logger.debug(f"Executing command: {command}")
        try:
            if isinstance(command, str):
                shell = True
                # Split into list if it's a simple command
                if ' ' not in command and os.path.exists(command) and os.access(command, os.X_OK):
                    command = [command]
                    shell = False
                elif self.is_windows:
                    # Windows requires shell=True for many commands
                    shell = True

            process = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )

            logger.debug(f"Command finished. RC: {process.returncode}, STDOUT: {process.stdout[:100]}..., STDERR: {process.stderr[:100]}...")
            return process.returncode, process.stdout.strip(), process.stderr.strip()

        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out after {timeout}s: {command}")
            return -1, "", "Command timed out"
        except FileNotFoundError:
            logger.error(f"Command not found: {command}")
            return -2, "", "Command not found"
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return -1, "", str(e)

    def confirm_action(self, message: str) -> bool:
        """
        Prompt the user for confirmation before proceeding.

        Args:
            message: Message to display in the confirmation prompt

        Returns:
            bool: True if confirmed, False otherwise
        """
        if self.force_mode:
            return True

        response = input(f"{message} [y/N]: ")
        if response.lower() in ('y', 'yes'):
            return True

        logger.info("Operation cancelled by user.")
        return False

    def apply_kernel_hardening(self) -> bool:
        """
        Apply kernel hardening parameters.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_linux:
            logger.warning("Kernel hardening is only supported on Linux systems. Skipping.")
            return False

        logger.info("Applying kernel hardening parameters...")
        sysctl_conf = "/etc/sysctl.conf"
        sysctl_d = "/etc/sysctl.d/99-hardening.conf"

        # Create/backup the dedicated file
        if not os.path.isfile(sysctl_d):
            try:
                with open(sysctl_d, 'w') as f:
                    f.write("# Security hardening parameters\n")
            except (IOError, OSError) as e:
                logger.error(f"Failed to create {sysctl_d}: {e}")
                return False

        if not self.backup_config_file(sysctl_d):
            return False

        # Common kernel hardening settings
        kernel_settings = {
            # Network Security
            "net.ipv4.tcp_syncookies": "1",
            "net.ipv4.ip_forward": "0",  # Disable IP forwarding unless router
            "net.ipv4.conf.all.accept_source_route": "0",
            "net.ipv4.conf.default.accept_source_route": "0",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.default.accept_redirects": "0",
            "net.ipv4.conf.all.secure_redirects": "0",
            "net.ipv4.conf.default.secure_redirects": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.default.send_redirects": "0",
            "net.ipv4.conf.all.rp_filter": "1",  # Strict Reverse Path Filtering
            "net.ipv4.conf.default.rp_filter": "1",
            "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            "net.ipv4.icmp_ignore_bogus_error_responses": "1",

            # IPv6 Security
            "net.ipv6.conf.all.accept_ra": "0",
            "net.ipv6.conf.default.accept_ra": "0",
            "net.ipv6.conf.all.accept_redirects": "0",
            "net.ipv6.conf.default.accept_redirects": "0",

            # Memory Security
            "kernel.randomize_va_space": "2",  # ASLR

            # Filesystem Security
            "fs.protected_hardlinks": "1",
            "fs.protected_symlinks": "1",
        }

        # Apply all settings
        success = True
        for setting, value in kernel_settings.items():
            setting_line = f"{setting} = {value}"
            if not self.apply_setting(sysctl_d, setting, setting_line):
                success = False

        # Apply changes
        logger.info("Applying sysctl changes...")
        rc, stdout, stderr = self.execute_command(f"sysctl -p {sysctl_d}")
        if rc != 0:
            logger.warning(f"Failed to apply some sysctl settings from {sysctl_d}: {stderr}")
            success = False

        # Also apply system-wide if needed
        rc, stdout, stderr = self.execute_command("sysctl --system")
        if rc != 0:
            logger.warning(f"Failed to apply system-wide sysctl settings: {stderr}")
            success = False

        logger.info("Kernel hardening parameters applied.")
        return success

    def apply_ssh_hardening(self) -> bool:
        """
        Apply SSH hardening settings.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_linux and not self.is_macos:
            logger.warning("SSH hardening is only supported on Unix-like systems. Skipping.")
            return False

        logger.info("Applying SSH hardening...")
        sshd_config = "/etc/ssh/sshd_config"
        ssh_hardening_conf = f"{DEPLOYMENT_SECURITY_CONFIG}/ssh-hardening.conf"

        if not os.path.isfile(sshd_config):
            logger.warning(f"SSHD config file '{sshd_config}' not found. Skipping SSH hardening.")
            return False

        if not self.backup_config_file(sshd_config):
            return False

        # Apply settings based on hardening checklist/policy
        ssh_settings = {
            "Protocol": "Protocol 2",
            "PermitRootLogin": "PermitRootLogin no",
            "PasswordAuthentication": "PasswordAuthentication no",
            "ChallengeResponseAuthentication": "ChallengeResponseAuthentication no",
            "UsePAM": "UsePAM yes",  # Ensure PAM is used for auth methods like MFA
            "X11Forwarding": "X11Forwarding no",
            "AllowAgentForwarding": "AllowAgentForwarding no",
            "AllowTcpForwarding": "AllowTcpForwarding no",
            "MaxAuthTries": "MaxAuthTries 3",
            "MaxSessions": "MaxSessions 5",
            "LoginGraceTime": "LoginGraceTime 30s",
            "ClientAliveInterval": "ClientAliveInterval 300",
            "ClientAliveCountMax": "ClientAliveCountMax 0",  # Disconnect idle clients
            "PermitEmptyPasswords": "PermitEmptyPasswords no",
            "IgnoreRhosts": "IgnoreRhosts yes",
            "HostbasedAuthentication": "HostbasedAuthentication no"
        }

        # Apply all settings
        success = True
        for setting, value in ssh_settings.items():
            if not self.apply_setting(sshd_config, setting, value):
                success = False

        # Apply strong crypto if defined in ssh-hardening.conf or policy
        if os.path.isfile(ssh_hardening_conf):
            logger.info(f"Applying crypto settings from {ssh_hardening_conf}")

            try:
                with open(ssh_hardening_conf, 'r') as f:
                    content = f.read()

                # Extract crypto settings
                kex_match = re.search(r"^\s*KexAlgorithms\s+(.+)$", content, re.MULTILINE)
                ciphers_match = re.search(r"^\s*Ciphers\s+(.+)$", content, re.MULTILINE)
                macs_match = re.search(r"^\s*MACs\s+(.+)$", content, re.MULTILINE)

                if kex_match:
                    kex = kex_match.group(1).strip()
                    self.apply_setting(sshd_config, "KexAlgorithms", f"KexAlgorithms {kex}")

                if ciphers_match:
                    ciphers = ciphers_match.group(1).strip()
                    self.apply_setting(sshd_config, "Ciphers", f"Ciphers {ciphers}")

                if macs_match:
                    macs = macs_match.group(1).strip()
                    self.apply_setting(sshd_config, "MACs", f"MACs {macs}")

            except (IOError, OSError) as e:
                logger.warning(f"Error reading SSH hardening config: {e}")
        else:
            logger.warning(f"SSH hardening config '{ssh_hardening_conf}' not found. Using basic settings.")

        # Validate config and reload
        logger.info("Validating SSHD configuration...")
        rc, stdout, stderr = self.execute_command(f"sshd -t -f {sshd_config}")
        if rc != 0:
            logger.error(f"SSHD configuration validation failed. Check '{sshd_config}'. Manual intervention required.")
            logger.error(stderr)
            success = False
        else:
            logger.info("SSHD configuration is valid. Reloading service...")
            if self.is_linux:
                rc, stdout, stderr = self.execute_command("systemctl reload sshd")
                if rc != 0:
                    logger.error(f"Failed to reload sshd service: {stderr}")
                    success = False
                else:
                    logger.info("SSHD service reloaded.")
            elif self.is_macos:
                rc, stdout, stderr = self.execute_command("launchctl unload /System/Library/LaunchDaemons/ssh.plist && launchctl load /System/Library/LaunchDaemons/ssh.plist")
                if rc != 0:
                    logger.error(f"Failed to reload sshd service: {stderr}")
                    success = False
                else:
                    logger.info("SSHD service reloaded.")

        logger.info("SSH hardening applied.")
        return success

    def apply_filesystem_hardening(self) -> bool:
        """
        Apply filesystem security settings.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_linux:
            logger.warning("Filesystem hardening is only supported on Linux systems. Skipping.")
            return False

        logger.info("Applying filesystem security settings...")
        fstab = "/etc/fstab"

        if not os.path.isfile(fstab):
            logger.warning(f"File '{fstab}' not found. Skipping filesystem hardening.")
            return False

        if not self.backup_config_file(fstab):
            return False

        # Read current fstab content
        try:
            with open(fstab, 'r') as f:
                content = f.read()
        except (IOError, OSError) as e:
            logger.error(f"Error reading {fstab}: {e}")
            return False

        modified = False

        # Harden /tmp
        logger.info("Hardening /tmp mount point...")
        if re.search(r'\s/tmp\s', content):
            # Check if options already exist, add if not
            for option in ["nosuid", "nodev", "noexec"]:
                if not re.search(rf'\s/tmp\s.*\s{option}\s', content):
                    content = re.sub(r'(\s/tmp\s[^#\n]*?)(\s*defaults\b)', f'\\1,{option}\\2', content)
                    if "defaults" not in content:
                        content = re.sub(r'(\s/tmp\s[^#\n]*?)(\s+\w+\s+\w+\s*$)', f'\\1 defaults,{option}\\2', content)
                    modified = True

            if modified:
                with open(fstab, 'w') as f:
                    f.write(content)

                logger.info("Applied nosuid,nodev,noexec to /tmp in fstab. Remounting...")
                rc, stdout, stderr = self.execute_command("mount -o remount /tmp")
                if rc != 0:
                    logger.warning(f"Failed to remount /tmp: {stderr}. Reboot may be required.")
        else:
            logger.warning("/tmp mount point not found in fstab. Skipping fstab hardening for /tmp.")

        # Ensure correct permissions for /tmp itself
        try:
            os.chmod("/tmp", 0o1777)
            shutil.chown("/tmp", "root", "root")
        except (OSError, PermissionError) as e:
            logger.warning(f"Failed to set permissions on /tmp: {e}")

        # Harden /dev/shm (shared memory)
        logger.info("Hardening /dev/shm mount point...")
        modified = False
        if re.search(r'\s/dev/shm\s', content):
            # Check if options already exist, add if not
            for option in ["nosuid", "nodev", "noexec"]:
                if not re.search(rf'\s/dev/shm\s.*\s{option}\s', content):
                    content = re.sub(r'(\s/dev/shm\s[^#\n]*?)(\s*defaults\b)', f'\\1,{option}\\2', content)
                    if "defaults" not in content:
                        content = re.sub(r'(\s/dev/shm\s[^#\n]*?)(\s+\w+\s+\w+\s*$)', f'\\1 defaults,{option}\\2', content)
                    modified = True

            if modified:
                with open(fstab, 'w') as f:
                    f.write(content)

                logger.info("Applied nosuid,nodev,noexec to /dev/shm in fstab. Remounting...")
                rc, stdout, stderr = self.execute_command("mount -o remount /dev/shm")
                if rc != 0:
                    logger.warning(f"Failed to remount /dev/shm: {stderr}. Reboot may be required.")
        else:
            logger.warning("/dev/shm mount point not found in fstab. Skipping fstab hardening for /dev/shm.")

        # Set secure umask (system-wide)
        logger.info("Setting secure umask (027)...")
        profile_path = "/etc/profile"
        if os.path.isfile(profile_path):
            self.apply_setting(profile_path, "umask", "umask 027")

        # Also set in login.defs for useradd defaults
        login_defs = "/etc/login.defs"
        if os.path.isfile(login_defs):
            self.backup_config_file(login_defs)

            try:
                with open(login_defs, 'r') as f:
                    login_content = f.read()

                # Replace UMASK setting
                login_content = re.sub(r'^\s*UMASK\s+\d+', 'UMASK\t\t027', login_content, flags=re.MULTILINE)

                with open(login_defs, 'w') as f:
                    f.write(login_content)

            except (IOError, OSError) as e:
                logger.warning(f"Error updating {login_defs}: {e}")

        # Secure critical file permissions
        logger.info("Setting secure permissions for critical files...")
        critical_files = {
            "/etc/passwd": {"mode": 0o644, "owner": "root", "group": "root"},
            "/etc/group": {"mode": 0o644, "owner": "root", "group": "root"},
            "/etc/hosts": {"mode": 0o644, "owner": "root", "group": "root"},
            "/etc/shadow": {"mode": 0o600, "owner": "root", "group": "root"},
            "/etc/gshadow": {"mode": 0o600, "owner": "root", "group": "root"},
            "/etc/rsyslog.conf": {"mode": 0o640, "owner": "root", "group": "root"}
        }

        for file_path, settings in critical_files.items():
            if os.path.isfile(file_path):
                try:
                    os.chmod(file_path, settings["mode"])
                    shutil.chown(file_path, settings["owner"], settings["group"])
                except (OSError, PermissionError) as e:
                    logger.warning(f"Failed to set permissions on {file_path}: {e}")

        logger.info("Filesystem hardening applied.")
        return True

    def apply_network_hardening(self) -> bool:
        """
        Apply network security settings.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_linux:
            logger.warning("Network hardening is only supported on Linux systems. Skipping.")
            return False

        logger.info("Applying network security settings...")

        # Apply firewall rules
        iptables_script = DEPLOYMENT_SECURITY_SCRIPTS / "iptables_rules.sh"
        if iptables_script.exists() and os.access(iptables_script, os.X_OK):
            logger.info(f"Applying firewall rules from {iptables_script}...")

            # Backup current rules first
            try:
                if shutil.which("iptables-save"):
                    backup_file = BACKUP_DIR / f"iptables-rules-{timestamp}.bak"
                    rc, stdout, stderr = self.execute_command(f"iptables-save > {backup_file}")
                    if rc != 0:
                        logger.warning(f"Failed to backup iptables rules: {stderr}")
            except Exception as e:
                logger.warning(f"Failed to backup iptables rules: {e}")

            # Apply firewall rules
            rc, stdout, stderr = self.execute_command(str(iptables_script))
            if rc != 0:
                logger.error(f"Failed to apply firewall rules from {iptables_script}: {stderr}")
                return False

            logger.info("Firewall rules applied.")
        else:
            logger.warning(f"Firewall script '{iptables_script}' not found or not executable. Skipping firewall rules application.")

        # Note: Other network hardening is handled by the kernel hardening function
        logger.info("Network hardening applied (partially covered by kernel hardening and service disabling).")
        return True

    def apply_authentication_hardening(self) -> bool:
        """
        Apply authentication security settings.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_linux:
            logger.warning("Authentication hardening is only supported on Linux systems. Skipping.")
            return False

        logger.info("Applying authentication hardening...")

        # Configure password policies in /etc/login.defs
        login_defs = "/etc/login.defs"
        if os.path.isfile(login_defs):
            logger.info(f"Configuring password policies in {login_defs}...")

            if not self.backup_config_file(login_defs):
                return False

            try:
                with open(login_defs, 'r') as f:
                    login_content = f.read()

                # Update password policies
                login_content = re.sub(r'^\s*PASS_MAX_DAYS\s+\d+', 'PASS_MAX_DAYS\t90', login_content, flags=re.MULTILINE)
                login_content = re.sub(r'^\s*PASS_MIN_DAYS\s+\d+', 'PASS_MIN_DAYS\t1', login_content, flags=re.MULTILINE)
                login_content = re.sub(r'^\s*PASS_WARN_AGE\s+\d+', 'PASS_WARN_AGE\t14', login_content, flags=re.MULTILINE)
                login_content = re.sub(r'^\s*ENCRYPT_METHOD\s+.*', 'ENCRYPT_METHOD\tSHA512', login_content, flags=re.MULTILINE)

                with open(login_defs, 'w') as f:
                    f.write(login_content)

            except (IOError, OSError) as e:
                logger.warning(f"Error updating {login_defs}: {e}")
                return False
        else:
            logger.warning(f"{login_defs} not found. Skipping password policy configuration.")

        # Configure password quality via PAM
        pwquality_conf = "/etc/security/pwquality.conf"
        if os.path.isfile(pwquality_conf):
            logger.info(f"Configuring password quality in {pwquality_conf}...")

            if not self.backup_config_file(pwquality_conf):
                return False

            # Apply password quality settings
            settings = {
                "minlen": "minlen = 14",
                "dcredit": "dcredit = -1",  # At least 1 digit
                "ucredit": "ucredit = -1",  # At least 1 uppercase
                "lcredit": "lcredit = -1",  # At least 1 lowercase
                "ocredit": "ocredit = -1",  # At least 1 special char
                "difok": "difok = 5",       # Min 5 chars different from old pwd
                "retry": "retry = 3"
            }

            for setting, value in settings.items():
                self.apply_setting(pwquality_conf, setting, value)

        else:
            logger.warning(f"{pwquality_conf} not found. Skipping password quality configuration.")

        # Configure account lockout via PAM
        logger.info("Configuring account lockout policy...")
        pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]  # Adjust for specific distro

        for pam_file in pam_files:
            if os.path.isfile(pam_file):
                if not self.backup_config_file(pam_file):
                    continue

                try:
                    with open(pam_file, 'r') as f:
                        pam_content = f.read()

                    # Add faillock lines if they don't exist
                    if "pam_faillock.so preauth" not in pam_content:
                        pam_content = re.sub(
                            r'^(auth\s+sufficient\s+pam_unix.so.*?)$',
                            'auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=900\n\\1',
                            pam_content,
                            flags=re.MULTILINE
                        )

                    if "pam_faillock.so authfail" not in pam_content:
                        # Remove old entry if exists
                        pam_content = re.sub(
                            r'^auth\s+\[default=die\]\s+pam_faillock.so.*$',
                            '',
                            pam_content,
                            flags=re.MULTILINE
                        )

                        pam_content = re.sub(
                            r'^(auth\s+sufficient\s+pam_unix.so.*?)$',
                            '\\1\nauth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900',
                            pam_content,
                            flags=re.MULTILINE
                        )

                    if "pam_faillock.so authsucc" not in pam_content:
                        pam_content = re.sub(
                            r'^(account\s+required\s+pam_unix.so.*?)$',
                            'account     required      pam_faillock.so\n\\1',
                            pam_content,
                            flags=re.MULTILINE
                        )

                    with open(pam_file, 'w') as f:
                        f.write(pam_content)

                    logger.info(f"Applied faillock settings to {pam_file} (deny=5, unlock_time=900).")

                except (IOError, OSError) as e:
                    logger.warning(f"Error updating {pam_file}: {e}")
            else:
                logger.warning(f"PAM file {pam_file} not found. Skipping faillock configuration for this file.")

        # TODO: Add MFA configuration steps if required by policy
        logger.info("Authentication hardening applied.")
        return True

    def disable_non_essential_services(self) -> bool:
        """
        Disable non-essential services based on policy.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_linux:
            logger.warning("Service hardening is only supported on Linux systems. Skipping.")
            return False

        logger.info("Disabling non-essential services based on policy...")

        # Define services based on security level or policy file
        services_to_disable = []

        # High/Critical disables more services
        if self.security_level in ["high", "critical"]:
            services_to_disable = [
                "telnet.socket", "telnet",
                "rsh.socket", "rlogin.socket", "rexec.socket",  # Insecure remote access
                "tftp.socket", "tftp",                          # Trivial FTP
                "avahi-daemon.socket", "avahi-daemon",          # Zeroconf networking
                "cups.socket", "cups",                          # Printing service
                "nfs-server", "rpcbind",                        # NFS server
                "smb", "nmb",                                   # Samba
                "vsftpd"                                        # FTP server
            ]
        elif self.security_level == "medium":
            services_to_disable = [
                "telnet.socket", "telnet",
                "rsh.socket", "rlogin.socket", "rexec.socket",
                "tftp.socket", "tftp",
                "avahi-daemon.socket", "avahi-daemon"
            ]
        else:  # Baseline
            services_to_disable = [
                "telnet.socket", "telnet",
                "rsh.socket", "rlogin.socket", "rexec.socket"
            ]

        # TODO: Allow overriding services_to_disable from policy file

        if not services_to_disable:
            logger.info("No services marked for disabling at this level/policy.")
            return True

        logger.info(f"Attempting to disable: {', '.join(services_to_disable)}")

        success = True
        for service in services_to_disable:
            # Check if service exists and is active or enabled
            rc, stdout, stderr = self.execute_command(f"systemctl list-unit-files --type=service,socket | grep -q \"^{service}\"")

            if rc == 0:  # Service exists
                logger.info(f"Processing service: {service}")

                if not self.force_mode:
                    logger.warning(f"Skipping disable of {service} (requires --force or policy confirmation)")
                    continue

                # Stop the service
                logger.info(f"Stopping service: {service}")
                rc, stdout, stderr = self.execute_command(f"systemctl stop {service}")
                if rc != 0:
                    logger.warning(f"Failed to stop {service}: {stderr} (may not be running)")

                # Disable the service
                logger.info(f"Disabling service: {service}")
                rc, stdout, stderr = self.execute_command(f"systemctl disable {service}")
                if rc != 0:
                    logger.warning(f"Failed to disable {service}: {stderr}")
                    success = False
                else:
                    logger.info(f"Service {service} disabled successfully.")
            else:
                logger.info(f"Service {service} not found or already inactive/disabled.")

        logger.info("Non-essential service disabling process complete.")
        return success

    def verify_configuration(self, policy_source: str) -> bool:
        """
        Verify current settings against expected state based on policy source.

        Args:
            policy_source: Source of policy being verified

        Returns:
            bool: True if compliant, False if non-compliant
        """
        if not self.is_linux:
            logger.warning("Verification is only supported on Linux systems. Skipping.")
            return False

        compliant = True
        logger.info(f"Verifying system configuration against policy: {policy_source}")

        # TODO: Implement parsing of policy_source (level, component/policy, or file)
        # This verifies a subset of 'high' level settings

        # Verify Kernel Parameters
        logger.info("Verifying kernel parameters...")
        kernel_params = {
            "net.ipv4.tcp_syncookies": "1",
            "net.ipv4.ip_forward": "0",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.all.rp_filter": "1",
            "kernel.randomize_va_space": "2"
        }

        for param, expected in kernel_params.items():
            rc, stdout, stderr = self.execute_command(f"sysctl -n {param}")
            if rc != 0 or stdout.strip() != expected:
                logger.warning(f"Verification FAILED: {param} is not {expected} (found: {stdout.strip()})")
                compliant = False

        # Verify SSH Config
        logger.info("Verifying SSH configuration...")
        sshd_config = "/etc/ssh/sshd_config"
        if os.path.isfile(sshd_config):
            ssh_checks = [
                {"regex": r"^\s*Protocol\s+2\s*$", "message": "SSH Protocol is not 2"},
                {"regex": r"^\s*PermitRootLogin\s+no\s*$", "message": "SSH PermitRootLogin is not no"},
                {"regex": r"^\s*PasswordAuthentication\s+no\s*$", "message": "SSH PasswordAuthentication is not no"},
                {"regex": r"^\s*X11Forwarding\s+no\s*$", "message": "SSH X11Forwarding is not no"},
                {"regex": r"^\s*MaxAuthTries\s+3\s*$", "message": "SSH MaxAuthTries is not 3"}
            ]

            try:
                with open(sshd_config, 'r') as f:
                    content = f.read()

                for check in ssh_checks:
                    if not re.search(check["regex"], content, re.MULTILINE):
                        logger.warning(f"Verification FAILED: {check['message']}")
                        compliant = False

            except (IOError, OSError) as e:
                logger.warning(f"Error reading {sshd_config}: {e}")
                compliant = False
        else:
            logger.warning(f"Verification SKIPPED: SSH config file {sshd_config} not found.")

        # Verify Filesystem Mounts
        logger.info("Verifying filesystem mount options...")
        mount_checks = [
            {"mount": "/tmp", "option": "noexec", "message": "/tmp is not mounted with noexec"},
            {"mount": "/tmp", "option": "nosuid", "message": "/tmp is not mounted with nosuid"},
            {"mount": "/tmp", "option": "nodev", "message": "/tmp is not mounted with nodev"},
            {"mount": "/dev/shm", "option": "noexec", "message": "/dev/shm is not mounted with noexec"},
            {"mount": "/dev/shm", "option": "nosuid", "message": "/dev/shm is not mounted with nosuid"},
            {"mount": "/dev/shm", "option": "nodev", "message": "/dev/shm is not mounted with nodev"}
        ]

        for check in mount_checks:
            rc, stdout, stderr = self.execute_command(f"findmnt -n -o OPTIONS {check['mount']} | grep -q '{check['option']}'")
            if rc != 0:
                logger.warning(f"Verification FAILED: {check['message']}")
                compliant = False

        # Verify Disabled Services
        logger.info("Verifying disabled services...")
        services_to_check = ["telnet.socket", "avahi-daemon.socket"]  # Example list

        for service in services_to_check:
            rc, stdout, stderr = self.execute_command(f"systemctl is-enabled {service}")
            if rc == 0 and stdout.strip() != "disabled":
                logger.warning(f"Verification FAILED: Service {service} is enabled")
                compliant = False

        # Verify Authentication Settings (Password Policy)
        logger.info("Verifying password policies...")
        login_defs = "/etc/login.defs"
        if os.path.isfile(login_defs):
            login_checks = [
                {"regex": r"^\s*PASS_MAX_DAYS\s+90\s*$", "message": "PASS_MAX_DAYS is not 90"},
                {"regex": r"^\s*PASS_MIN_DAYS\s+1\s*$", "message": "PASS_MIN_DAYS is not 1"},
                {"regex": r"^\s*ENCRYPT_METHOD\s+SHA512\s*$", "message": "ENCRYPT_METHOD is not SHA512"}
            ]

            try:
                with open(login_defs, 'r') as f:
                    content = f.read()

                for check in login_checks:
                    if not re.search(check["regex"], content, re.MULTILINE):
                        logger.warning(f"Verification FAILED: {check['message']}")
                        compliant = False

            except (IOError, OSError) as e:
                logger.warning(f"Error reading {login_defs}: {e}")
                compliant = False
        else:
            logger.warning(f"Verification SKIPPED: {login_defs} not found.")

        # TODO: Add verification for pwquality, faillock/tally2, firewall rules etc.

        if compliant:
            logger.info("Verification PASSED: All checked items are compliant.")
            return True
        else:
            logger.error("Verification FAILED: One or more items are non-compliant. Check warnings above.")
            return False

    def add_validation_result(self, category: str, control_id: str, control_data: dict,
                            status: Severity, details: dict, actual_output: Optional[str] = None) -> None:
        """
        Add validation result to results list.

        Args:
            category: Control category
            control_id: Control ID
            control_data: Control data
            status: Result status
            details: Result details
            actual_output: Actual output from validation
        """
        description = control_data.get("description", f"Control {control_id}")
        result = ValidationResult(
            category=category,
            control_id=control_id,
            status=status,
            description=description,
            details=details,
            actual_output=actual_output
        )
        self.results.append(result)

    def run(self) -> int:
        """
        Run the system lockdown script based on provided arguments.

        Returns:
            int: Exit code (0 for success, non-zero for failure)
        """
        # Parse and validate arguments
        if not self.parse_args():
            return 1

        # Execute in verification or application mode
        if self.verify_mode:
            logger.info("--- Starting Configuration Verification ---")
            if self.verify_configuration(self.policy_source):
                return 0
            else:
                return 2
        else:
            # Application mode
            logger.info("--- Starting Security Lockdown Application ---")

            # Ask for confirmation unless forced
            if not self.confirm_action(f"Apply security lockdown settings based on '{self.policy_source}' to environment '{self.environment}'?"):
                return 0  # User cancelled

            # Apply settings based on policy source
            if self.policy_file:
                logger.error("Custom policy files are not yet implemented. Use security level or component-specific options.")
                return 1

            elif self.component and self.apply_policy:
                logger.info(f"Applying policy '{self.apply_policy}' to component '{self.component}'...")

                # Apply component-specific hardening
                if self.component == "kernel":
                    if not self.apply_kernel_hardening():
                        return 1
                elif self.component == "ssh":
                    if not self.apply_ssh_hardening():
                        return 1
                elif self.component == "filesystem":
                    if not self.apply_filesystem_hardening():
                        return 1
                elif self.component == "network":
                    if not self.apply_network_hardening():
                        return 1
                elif self.component == "authentication":
                    if not self.apply_authentication_hardening():
                        return 1
                elif self.component == "services":
                    if not self.disable_non_essential_services():
                        return 1
                else:
                    logger.error(f"Unsupported component: {self.component}")
                    return 1

                logger.warning("Component-specific policy application is basic; full policy parsing not implemented.")

            elif self.security_level:
                logger.info(f"Applying settings for security level: {self.security_level}")

                # Apply functions based on level - order can matter
                # Baseline applies minimal set
                if self.security_level in ["baseline", "medium", "high", "critical"]:
                    if not self.apply_kernel_hardening():
                        logger.error("Kernel hardening failed")

                    if not self.apply_ssh_hardening():
                        logger.error("SSH hardening failed")

                    if not self.apply_filesystem_hardening():
                        logger.error("Filesystem hardening failed")

                    if not self.apply_authentication_hardening():
                        logger.error("Authentication hardening failed")

                    if not self.apply_network_hardening():
                        logger.error("Network hardening failed")

                # Medium doesn't add anything specific yet
                # if self.security_level in ["medium", "high", "critical"]:
                #     pass

                # High/Critical disables more services
                if self.security_level in ["high", "critical"]:
                    if not self.disable_non_essential_services():
                        logger.error("Service disabling failed")

            logger.info("--- Security Lockdown Application Completed ---")
            logger.info(f"Review logs for details: {LOG_FILE}")
            logger.info("It is recommended to reboot the system or restart relevant services for all changes to take effect.")
            logger.info(f"Run 'python {os.path.basename(__file__)} --verify --security-level {self.security_level}' (or relevant policy) to confirm the applied settings.")

            return 0


def main() -> int:
    """
    Main entry point for the script.

    Returns:
        int: Exit code
    """
    try:
        lockdown = SystemLockdown()
        return lockdown.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 130
    except Exception as e:
        logger.error(f"Unhandled error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
