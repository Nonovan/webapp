"""
Service Restoration Tool

This script automates the restoration of services after a security incident,
using predefined templates and configurations. It ensures services are brought
back online securely and consistently, following the recovery phase of the
NIST SP 800-61 framework.

Key Features:
- Template-driven restoration for various service types.
- Dependency validation before restoration.
- Configuration restoration from verified sources or template definitions.
- Phased restoration with validation at each step.
- Integration with security audit logging and notification systems.
- Dry-run capability for planning and testing.
- Basic rollback guidance and attempts on failure.
"""

import argparse
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Set

# Determine project root and add to sys.path if necessary
try:
    # Assumes this script is in admin/security/incident_response_kit/recovery
    RECOVERY_DIR = Path(__file__).resolve().parent
    IR_KIT_DIR = RECOVERY_DIR.parent
    ADMIN_DIR = IR_KIT_DIR.parent
    PROJECT_ROOT = ADMIN_DIR.parent
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    # Import constants and config from the IR Kit package
    from admin.security.incident_response_kit import (
        response_config, tool_paths, CONFIG_AVAILABLE, MODULE_PATH,
        DEFAULT_EVIDENCE_DIR, DEFAULT_LOG_DIR, DEFAULT_TEMP_DIR,
        IncidentResponseError
    )

    # Import core security utilities if available
    try:
        from core.security.cs_audit import log_security_event
        from core.security.cs_file_integrity import calculate_file_hash, verify_file_integrity
        AUDIT_AVAILABLE = True
    except ImportError:
        AUDIT_AVAILABLE = False
        log_security_event = None # Define as None if not available
        calculate_file_hash = None
        verify_file_integrity = None

    # Import notification system if available
    try:
        # Prefer the central notification service if available
        try:
            from services.notification.manager import NotificationManager
            notification_manager = NotificationManager()

            def notify_stakeholders(subject, message, level, recipients=None, incident_id=None):
                notification_manager.send(
                    subject=subject,
                    body=message,
                    level=level,
                    recipients=recipients,
                    tags={'incident_id': incident_id}
                )
            NOTIFICATION_AVAILABLE = True
        except ImportError:
            # Fall back to IR Kit notification system
            from admin.security.incident_response_kit.coordination.notification_system import notify_stakeholders
            NOTIFICATION_AVAILABLE = True
    except ImportError:
        NOTIFICATION_AVAILABLE = False
        notify_stakeholders = None

except ImportError as e:
    print(f"Error importing project modules: {e}", file=sys.stderr)
    print("Ensure the script is run from within the project structure or PYTHONPATH is set correctly.", file=sys.stderr)
    # Define fallback constants if import fails
    response_config = {}
    tool_paths = {}
    CONFIG_AVAILABLE = False
    MODULE_PATH = Path(__file__).resolve().parents[2] # Guess IR Kit path
    DEFAULT_EVIDENCE_DIR = Path("/secure/evidence")
    DEFAULT_LOG_DIR = Path("/var/log/ir-kit")
    DEFAULT_TEMP_DIR = Path("/tmp/ir-kit")
    AUDIT_AVAILABLE = False
    NOTIFICATION_AVAILABLE = False
    log_security_event = None
    calculate_file_hash = None
    verify_file_integrity = None
    notify_stakeholders = None
    class IncidentResponseError(Exception): pass

# --- Configuration ---
TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
DEFAULT_TIMESTAMP_FORMAT_ISO = "%Y-%m-%dT%H:%M:%SZ"
LOG_FILE_NAME = f"service_restoration_{datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)}.log"
LOG_FILE_PATH = Path(DEFAULT_LOG_DIR) / LOG_FILE_NAME
DEFAULT_RESTORE_TIMEOUT = 3600 # 1 hour default timeout for restoration steps
BACKUP_SUFFIX = ".pre-restore-bak"
VERIFICATION_SCRIPTS_DIR = RECOVERY_DIR / "resources" / "verification_scripts"
FILE_PERMISSIONS = 0o600 # Secure permissions for sensitive files
DIR_PERMISSIONS = 0o700 # Owner rwx only for directories
REQUIRED_TEMPLATE_FIELDS = {"metadata", "template_name", "version"}
CONFIG_RETRY_COUNT = 3  # Number of retries for configuration operations
SERVICE_RETRY_COUNT = 2  # Number of retries for service operations

# Configure logging
LOG_LEVEL = response_config.get("logging", {}).get("level", "INFO").upper()
try:
    LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True) # Ensure log directory exists
    # Set secure permissions on the log directory if newly created
    if not os.path.exists(LOG_FILE_PATH.parent):
         os.chmod(LOG_FILE_PATH.parent, DIR_PERMISSIONS)
except OSError as e:
    print(f"Error creating or accessing log directory {LOG_FILE_PATH.parent}: {e}", file=sys.stderr)
    # Fallback to stderr if log file cannot be created
    logging.basicConfig(
        level=LOG_LEVEL,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )
else:
    logging.basicConfig(
        level=LOG_LEVEL,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE_PATH),
            logging.StreamHandler(sys.stdout) # Also log to console
        ]
    )
    # Secure the log file itself
    try:
        os.chmod(LOG_FILE_PATH, FILE_PERMISSIONS)
    except OSError as e:
        print(f"Warning: Could not set permissions on log file {LOG_FILE_PATH}: {e}", file=sys.stderr)


logger = logging.getLogger(__name__)

# Global list to track created/modified files for potential rollback
MODIFIED_FILES_TRACKER = []
CREATED_DIRS_TRACKER = []
METRICS = {
    "backups_created": 0,
    "config_files_modified": 0,
    "verification_checks_run": 0,
    "commands_executed": 0,
    "directories_created": 0,
    "validation_failed": 0,
    "start_time": time.time(),
}

# --- Helper Functions ---

def _interpolate_params(template_str: str, params: Dict[str, str]) -> str:
    """
    Interpolates parameters like ${VAR} in a string template.

    Args:
        template_str: The string template that may contain ${param} placeholders
        params: Dictionary of parameters to interpolate

    Returns:
        Interpolated string with parameters replaced
    """
    if not template_str or not isinstance(template_str, str):
        return template_str

    interpolated_str = template_str
    for key, value in params.items():
        placeholder = f"${{{key}}}"
        # Sanitization to prevent command injection via params
        if isinstance(value, str):
            safe_value = shlex.quote(value)
        else:
            safe_value = str(value)
        interpolated_str = interpolated_str.replace(placeholder, safe_value)
    return interpolated_str

def run_command(command: str, timeout: int = DEFAULT_RESTORE_TIMEOUT,
                cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
                params: Optional[Dict[str, str]] = None, dry_run: bool = False,
                shell: bool = False) -> Tuple[int, str, str]:
    """
    Runs a shell command safely, interpolates parameters, and returns status, stdout, stderr.

    Args:
        command: The command string to execute (can contain ${param} placeholders)
        timeout: Timeout in seconds
        cwd: Working directory for the command
        env: Environment variables for the command
        params: Dictionary of parameters to interpolate into the command
        dry_run: If True, log the command instead of running it
        shell: Whether to use shell=True in subprocess.Popen (use with caution)

    Returns:
        Tuple (return_code, stdout, stderr)
    """
    METRICS["commands_executed"] += 1
    final_command = _interpolate_params(command, params or {})
    logger.info(f"Executing command: {final_command}" + (" (Dry Run)" if dry_run else ""))
    if dry_run:
        return 0, f"Dry run mode, command not executed: {final_command}", ""

    try:
        if shell:
            # We'll use shell=True with extreme caution when absolutely needed
            # This is higher risk but sometimes necessary for complex commands
            logger.debug("Using shell=True for command execution")
            process = subprocess.Popen(
                final_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                cwd=cwd,
                env=env or os.environ.copy()
            )
        else:
            # Preferred approach: shell=False for security
            cmd_parts = shlex.split(final_command)
            process = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=env or os.environ.copy()
            )

        stdout, stderr = process.communicate(timeout=timeout)
        logger.debug(f"Command finished with code {process.returncode}")
        if stdout:
            logger.debug(f"Stdout:\n{stdout.strip()}")
        if stderr:
            logger.debug(f"Stderr:\n{stderr.strip()}")
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds: {final_command}")
        if 'process' in locals() and process.poll() is None:
            process.kill()
            try:
                stdout, stderr = process.communicate(timeout=5)  # Give it 5 seconds to clean up
            except subprocess.TimeoutExpired:
                # If still hanging, force termination
                process.kill()
                stdout, stderr = process.communicate()
        return -1, "", "Command timed out"
    except FileNotFoundError:
        cmd_name = shlex.split(final_command)[0] if not shell else "Command interpreter"
        logger.error(f"Command not found: {cmd_name}")
        return -2, "", f"Command not found: {cmd_name}"
    except Exception as e:
        logger.exception(f"Error executing command '{final_command}': {e}")
        return -3, "", str(e)

def validate_template(template_data: Dict[str, Any]) -> bool:
    """
    Validates a restoration template more thoroughly.

    Args:
        template_data: The template data dictionary

    Returns:
        True if valid, False otherwise. Logs specific validation errors.
    """
    # Check required sections
    if not "metadata" in template_data:
        logger.error("Template missing required 'metadata' section")
        return False

    metadata = template_data.get("metadata", {})
    for field in ["template_name", "version"]:
        if field not in metadata:
            logger.error(f"Template metadata missing required '{field}' field")
            return False

    # Verify section structure
    if "configuration" in template_data:
        config = template_data["configuration"]
        if not isinstance(config, dict):
            logger.error("Template 'configuration' section must be a dictionary")
            return False

    if "restoration" in template_data:
        restoration = template_data["restoration"]
        if not isinstance(restoration, dict):
            logger.error("Template 'restoration' section must be a dictionary")
            return False

        commands = restoration.get("commands", [])
        if not isinstance(commands, list):
            logger.error("Template 'restoration.commands' must be a list")
            return False

        # Check each command has required fields
        for i, cmd in enumerate(commands):
            if not isinstance(cmd, dict):
                logger.error(f"Template restoration command {i} must be a dictionary")
                return False
            if "command" not in cmd:
                logger.error(f"Template restoration command {i} missing required 'command' field")
                return False

    if "validation" in template_data:
        validation = template_data["validation"]
        if not isinstance(validation, dict):
            logger.error("Template 'validation' section must be a dictionary")
            return False

    return True

def load_template(template_path: Path) -> Dict[str, Any]:
    """
    Loads and validates the JSON restoration template.

    Args:
        template_path: Path to the template file

    Returns:
        Template data as dictionary

    Raises:
        FileNotFoundError: If template file doesn't exist
        ValueError: If template has invalid JSON or missing required fields
        IncidentResponseError: For other template loading failures
    """
    if not template_path.exists():
        raise FileNotFoundError(f"Restoration template not found: {template_path}")
    try:
        with open(template_path, 'r') as f:
            template_data = json.load(f)
        logger.info(f"Loaded restoration template: {template_path}")

        # Perform basic validation
        if not validate_template(template_data):
            raise ValueError(f"Template validation failed for {template_path}")

        # Enhanced validation for recommended sections
        missing_sections = []
        recommended_sections = ["metadata", "configuration", "restoration", "validation"]
        for section in recommended_sections:
            if section not in template_data:
                missing_sections.append(section)

        if missing_sections:
            logger.warning(f"Template missing recommended sections: {', '.join(missing_sections)}")

        return template_data
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in template file {template_path}: {e}")
    except Exception as e:
        if isinstance(e, ValueError):
            raise  # Re-raise ValueError
        raise IncidentResponseError(f"Error loading template {template_path}: {e}")

def validate_dependencies(template: Dict[str, Any], params: Dict[str, str], dry_run: bool = False) -> bool:
    """
    Validates required service dependencies using commands from the template.

    Args:
        template: The restoration template
        params: Template parameters for substitution
        dry_run: If True, simulate validation

    Returns:
        True if all dependencies are valid, False otherwise
    """
    dependencies = template.get("dependencies", {})
    required_services = dependencies.get("required_services", [])
    verification_commands = dependencies.get("verification_commands", [])
    optional_services = dependencies.get("optional_services", [])

    if not required_services and not verification_commands:
        logger.info("No dependencies specified in the template.")
        return True

    if required_services:
        logger.info(f"Required services: {', '.join(required_services)}")
    if optional_services:
        logger.info(f"Optional services: {', '.join(optional_services)}")

    all_deps_ok = True
    for command in verification_commands:
        logger.info(f"Running dependency check: {command}")
        METRICS["verification_checks_run"] += 1
        ret_code, stdout, stderr = run_command(command, timeout=60, params=params, dry_run=dry_run) # Shorter timeout for checks
        if ret_code != 0:
            logger.error(f"Dependency check failed: {command}")
            logger.error(f"Stderr: {stderr.strip()}")
            all_deps_ok = False
        else:
            logger.info(f"Dependency check successful: {command}")

    if not all_deps_ok:
        logger.error("One or more required dependencies are not met.")
        return False

    logger.info("All dependencies validated successfully.")
    return True

def find_verification_script(script_name: str) -> Optional[Path]:
    """
    Finds a verification script in the standard locations.

    Args:
        script_name: Name of the script to find

    Returns:
        Path to script if found, None otherwise
    """
    # Check direct path first
    direct_path = Path(script_name)
    if direct_path.exists() and direct_path.is_file():
        return direct_path

    # Check in verification_scripts directory
    script_path = VERIFICATION_SCRIPTS_DIR / script_name
    if script_path.exists() and script_path.is_file():
        return script_path

    # Check with various extensions
    for ext in ["", ".py", ".sh", ".bash"]:
        script_path = VERIFICATION_SCRIPTS_DIR / f"{script_name}{ext}"
        if script_path.exists() and script_path.is_file():
            return script_path

    return None

def run_verification_script(script_name: str, args: str = "", params: Dict[str, str] = None,
                           dry_run: bool = False) -> bool:
    """
    Runs a verification script from the verification_scripts directory.

    Args:
        script_name: Name of the script to run
        args: Arguments to pass to the script
        params: Template parameters for substitution
        dry_run: If True, simulate running the script

    Returns:
        True if script succeeded, False otherwise
    """
    script_path = find_verification_script(script_name)
    if not script_path:
        logger.error(f"Verification script not found: {script_name}")
        return False

    # Determine how to run the script based on extension
    if script_path.suffix == '.py':
        cmd = f"python3 {script_path} {args}"
    elif script_path.suffix in ['.sh', '.bash']:
        cmd = f"bash {script_path} {args}"
    else:
        # Try to make it executable and run directly
        try:
            if not dry_run:
                script_path.chmod(0o700)  # rwx for owner only
            cmd = f"{script_path} {args}"
        except Exception:
            logger.warning(f"Could not make {script_path} executable, trying with bash")
            cmd = f"bash {script_path} {args}"

    METRICS["verification_checks_run"] += 1
    ret_code, stdout, stderr = run_command(cmd, timeout=300, params=params, dry_run=dry_run)

    if ret_code != 0:
        logger.error(f"Verification script {script_name} failed with code {ret_code}")
        logger.error(f"Stderr: {stderr.strip()}")
        METRICS["validation_failed"] += 1
        return False

    logger.info(f"Verification script {script_name} passed")
    if stdout.strip():
        logger.info(f"Script output: {stdout.strip()}")
    return True

def perform_validation(template: Dict[str, Any], params: Dict[str, str], dry_run: bool = False) -> bool:
    """
    Performs post-restoration validation using checks from the template.

    Args:
        template: The restoration template
        params: Template parameters for substitution
        dry_run: If True, simulate validation

    Returns:
        True if all validations pass, False otherwise
    """
    validation_config = template.get("validation", {})
    if not validation_config:
        logger.warning("No validation steps defined in the template.")
        return True # No validation defined is considered success

    logger.info("Performing post-restoration validation...")
    all_validations_ok = True

    # Health Check
    health_check = validation_config.get("health_check")
    if health_check:
        endpoint = health_check.get("endpoint")
        if not endpoint:
            logger.warning("Health check defined but missing 'endpoint'.")
        else:
            interpolated_endpoint = _interpolate_params(endpoint, params)
            expected_status = health_check.get("expected_status", 200)
            timeout = health_check.get("timeout_seconds", 10)
            retries = health_check.get("retries", 3)

            # Use run_command for consistency and parameter interpolation
            health_cmd = f"curl -fsS -o /dev/null -w '%{{http_code}}' --connect-timeout {timeout} {interpolated_endpoint}"
            logger.info(f"Running health check: {health_cmd}")

            METRICS["verification_checks_run"] += 1
            for attempt in range(retries):
                ret_code, stdout, stderr = run_command(health_cmd, timeout=timeout + 5, params=params, dry_run=dry_run)
                if dry_run:
                    status_code = expected_status # Assume success in dry run
                else:
                    try:
                        status_code = int(stdout.strip())
                    except ValueError:
                        status_code = -1

                if ret_code == 0 and status_code == expected_status:
                    logger.info(f"Health check passed (Status: {status_code})")
                    break
                else:
                    logger.warning(f"Health check attempt {attempt + 1}/{retries} failed (Return Code: {ret_code}, HTTP Status: {status_code}, Stderr: {stderr.strip()})")
                    if attempt < retries - 1:
                        time.sleep(5) # Wait before retrying
            else: # Loop completed without break (all retries failed)
                logger.error(f"Health check failed after multiple retries for endpoint: {interpolated_endpoint}")
                METRICS["validation_failed"] += 1
                all_validations_ok = False

    # Functional Tests (using commands)
    functional_tests = validation_config.get("functional_tests", [])
    for test in functional_tests:
        test_name = test.get("name", "Unnamed Test")
        test_command = test.get("command")
        expected_result = test.get("expected_result")
        severity = test.get("severity", "medium")

        if not test_command:
            logger.warning(f"Skipping functional test '{test_name}' due to missing command.")
            continue

        logger.info(f"Running functional test '{test_name}': {test_command}")
        METRICS["verification_checks_run"] += 1
        ret_code, stdout, stderr = run_command(test_command, timeout=300, params=params, dry_run=dry_run) # Longer timeout for tests

        # Check against expected result if specified
        test_passed = ret_code == 0
        if test_passed and expected_result is not None:
            if isinstance(expected_result, str) and expected_result in stdout:
                logger.info(f"Functional test '{test_name}' output contains expected result")
            elif isinstance(expected_result, dict) and "regex" in expected_result:
                import re
                regex = expected_result["regex"]
                if re.search(regex, stdout):
                    logger.info(f"Functional test '{test_name}' output matches regex: {regex}")
                else:
                    logger.error(f"Functional test '{test_name}' output didn't match regex: {regex}")
                    test_passed = False
            elif isinstance(expected_result, int) and ret_code == expected_result:
                logger.info(f"Functional test '{test_name}' expected return code matches: {expected_result}")
            else:
                logger.warning(f"Functional test '{test_name}' has unsupported expected_result format, only checking exit code")

        if test_passed:
            logger.info(f"Functional test '{test_name}' passed.")
        else:
            logger.error(f"Functional test '{test_name}' failed (Severity: {severity}).")
            logger.error(f"Stderr: {stderr.strip()}")
            METRICS["validation_failed"] += 1
            all_validations_ok = False

    # Verification Scripts
    verification_scripts = validation_config.get("verification_scripts", [])
    for script_info in verification_scripts:
        script_name = script_info.get("script_name")
        if not script_name:
            logger.warning("Skipping verification script due to missing script_name")
            continue

        script_args = script_info.get("args", "")
        script_params = params.copy()

        # Add any script-specific params
        if "params" in script_info and isinstance(script_info["params"], dict):
            script_params.update(script_info["params"])

        logger.info(f"Running verification script: {script_name} with args: {script_args}")
        script_passed = run_verification_script(
            script_name=script_name,
            args=script_args,
            params=script_params,
            dry_run=dry_run
        )

        if not script_passed:
            severity = script_info.get("severity", "medium")
            logger.error(f"Verification script '{script_name}' failed (Severity: {severity})")
            if severity in ("critical", "high"):
                all_validations_ok = False

    if all_validations_ok:
        logger.info("All post-restoration validations passed.")
    else:
        logger.error("One or more post-restoration validations failed.")

    return all_validations_ok

def get_user_identity() -> str:
    """Gets the current user identity."""
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", "unknown")

def audit_log(event_type: str, description: str, incident_id: Optional[str] = None,
             success: bool = True, details: Optional[Dict[str, Any]] = None):
    """
    Logs an audit event using core.security.cs_audit if available.

    Args:
        event_type: Type of event (e.g., "service_restoration_start")
        description: Description of the event
        incident_id: Related incident ID
        success: Whether the operation was successful
        details: Additional details to include in the audit log
    """
    if AUDIT_AVAILABLE and log_security_event:
        try:
            log_security_event(
                event_type=event_type,
                description=description,
                severity="info" if success else "warning",
                user_id=get_user_identity(),
                incident_id=incident_id,
                metadata=details or {},
                outcome="success" if success else "failure",
                source_component="service_restoration.py"
            )
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")
    else:
        logger.debug(f"Audit log (skipped - unavailable): {event_type} - {description}")

def send_notification(subject: str, message: str, incident_id: Optional[str] = None,
                     level: str = "info", recipients: Optional[List[str]] = None):
    """
    Sends a notification using the coordination.notification_system or services.notification.

    Args:
        subject: Notification subject
        message: Notification message body
        incident_id: Related incident ID
        level: Notification level (info, success, warning, error, critical)
        recipients: List of recipient email addresses or channels
    """
    if NOTIFICATION_AVAILABLE and notify_stakeholders:
        try:
            # Adapt this call based on the actual signature of notify_stakeholders
            notify_stakeholders(incident_id=incident_id, subject=subject, message=message, level=level, recipients=recipients)
            logger.info(f"Notification sent to {recipients or 'default stakeholders'}.")
        except Exception as e:
            logger.warning(f"Failed to send notification: {e}")
    else:
        logger.debug(f"Notification (skipped - unavailable): {subject} - {message}")

def confirm_action(prompt: str, default: bool = False) -> bool:
    """
    Asks user for confirmation.

    Args:
        prompt: Question to ask the user
        default: Default answer if user just presses Enter

    Returns:
        User's response (True for yes, False for no)
    """
    choices = " [Y/n]" if default else " [y/N]"
    try:
        reply = input(f"{prompt}{choices} ").strip().lower()
        if not reply:
            return default
        return reply == 'y'
    except EOFError: # Handle non-interactive environments
        logger.warning("Non-interactive environment detected, proceeding with default confirmation.")
        return default

def backup_file(file_path: Path, dry_run: bool = False) -> Optional[Path]:
    """
    Creates a backup of a file before modification.

    Args:
        file_path: Path to the file to back up
        dry_run: If True, simulate the backup

    Returns:
        Path to the backup file, or None if backup couldn't be created
    """
    if not file_path.exists() or file_path.is_dir():
        return None

    backup_path = file_path.with_suffix(file_path.suffix + BACKUP_SUFFIX)
    logger.info(f"Backing up '{file_path}' to '{backup_path}'" + (" (Dry Run)" if dry_run else ""))
    if dry_run:
        return backup_path # Return potential backup path even in dry run

    try:
        # Create backup directory if it doesn't exist
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy file and preserve metadata
        shutil.copy2(file_path, backup_path)

        # Set secure permissions on the backup
        os.chmod(backup_path, FILE_PERMISSIONS)

        MODIFIED_FILES_TRACKER.append((file_path, backup_path)) # Track original and backup
        METRICS["backups_created"] += 1

        # Calculate and store hash to verify integrity if available
        if verify_file_integrity:
            try:
                verify_file_integrity(str(backup_path))
            except Exception as e:
                logger.warning(f"Failed to verify backup file integrity: {e}")

        return backup_path
    except Exception as e:
        logger.error(f"Failed to backup file '{file_path}': {e}")
        return None

def restore_file_from_backup(original_path: Path, backup_path: Path, dry_run: bool = False) -> bool:
    """
    Restores a file from its backup.

    Args:
        original_path: Path to the original file to restore
        backup_path: Path to the backup file
        dry_run: If True, simulate the restoration

    Returns:
        True if restoration was successful, False otherwise
    """
    logger.warning(f"Attempting to restore '{original_path}' from '{backup_path}'" + (" (Dry Run)" if dry_run else ""))
    if not backup_path.exists():
        logger.error(f"Backup file '{backup_path}' not found. Cannot restore '{original_path}'.")
        return False
    if dry_run:
        return True

    try:
        # Verify backup file integrity if available
        if verify_file_integrity:
            try:
                if not verify_file_integrity(str(backup_path)):
                    logger.error(f"Backup file integrity check failed for {backup_path}")
                    return False
            except Exception as e:
                logger.warning(f"Failed to verify backup file integrity: {e}")

        # Create parent directory if it doesn't exist
        original_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy backup to original location preserving attributes
        shutil.copy2(backup_path, original_path)

        # Set secure permissions
        os.chmod(original_path, FILE_PERMISSIONS)

        logger.info(f"Successfully restored '{original_path}' from backup.")
        return True
    except Exception as e:
        logger.error(f"Failed to restore '{original_path}' from '{backup_path}': {e}")
        return False

def cleanup_backups(dry_run: bool = False):
    """
    Removes backup files created during the process.

    Args:
        dry_run: If True, simulate the cleanup
    """
    logger.info("Cleaning up backup files..." + (" (Dry Run)" if dry_run else ""))
    for _, backup_path in MODIFIED_FILES_TRACKER:
        if backup_path and backup_path.exists():
            logger.debug(f"Removing backup file: {backup_path}")
            if not dry_run:
                try:
                    backup_path.unlink()
                except OSError as e:
                    logger.warning(f"Failed to remove backup file '{backup_path}': {e}")

def attempt_rollback(dry_run: bool = False):
    """
    Attempts to rollback changes made during the restoration process.

    Args:
        dry_run: If True, simulate the rollback
    """
    logger.warning("Attempting rollback due to failure..." + (" (Dry Run)" if dry_run else ""))
    rollback_success = True

    # Restore modified files from backups
    for original_path, backup_path in reversed(MODIFIED_FILES_TRACKER): # Restore in reverse order
        if backup_path and backup_path.exists():
            if not restore_file_from_backup(original_path, backup_path, dry_run):
                rollback_success = False
        elif original_path.exists() and not dry_run:
             # If backup exists but couldn't be restored, or backup doesn't exist,
             # we might be in an inconsistent state. Log this.
             logger.error(f"Could not restore {original_path}, backup missing or restore failed.")
             rollback_success = False

    # Remove created directories (if empty)
    for dir_path in reversed(CREATED_DIRS_TRACKER):
        logger.info(f"Attempting to remove created directory: {dir_path}" + (" (Dry Run)" if dry_run else ""))
        if dir_path.exists() and dir_path.is_dir():
            if not dry_run:
                try:
                    # Only remove if empty
                    os.rmdir(dir_path)
                    logger.info(f"Removed directory: {dir_path}")
                except OSError as e:
                    logger.warning(f"Could not remove directory '{dir_path}' (may not be empty): {e}")
                    # Don't mark rollback as failed just because dir isn't empty
            else:
                 logger.info(f"Would attempt to remove directory: {dir_path}")

    if rollback_success:
        logger.info("Rollback attempt completed (manual verification recommended).")
    else:
        logger.error("Rollback attempt failed or was incomplete. Manual intervention required.")

def verify_configuration_integrity(config_path: Path, original_hash: Optional[str] = None) -> bool:
    """
    Verifies the integrity of a configuration file after restoration.

    Args:
        config_path: Path to the configuration file
        original_hash: Hash of the original file if available

    Returns:
        True if integrity check passed, False otherwise
    """
    if not config_path.exists():
        logger.error(f"Cannot verify non-existent configuration file: {config_path}")
        return False

    try:
        # If we have access to file integrity verification
        if verify_file_integrity:
            logger.debug(f"Performing integrity verification on {config_path}")
            return verify_file_integrity(str(config_path))
        # If we only have hash calculation
        elif calculate_file_hash and original_hash:
            current_hash = calculate_file_hash(str(config_path))
            if current_hash != original_hash:
                logger.warning(f"Hash mismatch for {config_path}: {current_hash} != {original_hash}")
                return False
            return True
        # Basic verification - just check file exists and is readable
        else:
            with open(config_path, 'r') as f:
                # Just try reading the first line to ensure it's a valid file
                f.readline()
            return True
    except Exception as e:
        logger.error(f"Configuration integrity verification failed for {config_path}: {e}")
        return False

def print_metrics():
    """Prints metrics about the restoration process."""
    duration = time.time() - METRICS["start_time"]
    metrics_str = f"""
Service Restoration Metrics:
==========================
Duration:               {duration:.2f} seconds
Commands executed:      {METRICS["commands_executed"]}
Backups created:        {METRICS["backups_created"]}
Config files modified:  {METRICS["config_files_modified"]}
Directories created:    {METRICS["directories_created"]}
Verification checks:    {METRICS["verification_checks_run"]}
Validation failures:    {METRICS["validation_failed"]}
==========================
"""
    logger.info(metrics_str)
    return metrics_str

def generate_summary_report(incident_id: str, service_type: str, environment: str,
                           success: bool, template_name: str, duration: float,
                           modified_files: List[Path], problems_encountered: List[str]) -> str:
    """
    Generates a summary report of the service restoration.

    Args:
        incident_id: ID of the incident
        service_type: Type of service restored
        environment: Environment where restoration happened
        success: Whether restoration was successful
        template_name: Name of the template used
        duration: Duration of the restoration in seconds
        modified_files: List of files modified during restoration
        problems_encountered: List of problems encountered

    Returns:
        Formatted summary report as string
    """
    status = "SUCCESS" if success else "FAILED"
    modified_files_str = "\n  - ".join([""] + [str(path) for path in modified_files]) if modified_files else "  None"
    problems_str = "\n  - ".join([""] + problems_encountered) if problems_encountered else "  None"

    report = f"""
SERVICE RESTORATION SUMMARY
==========================
Incident ID:    {incident_id}
Service Type:   {service_type}
Environment:    {environment}
Status:         {status}
Template:       {template_name}
Duration:       {duration:.2f} seconds
Timestamp:      {datetime.now(timezone.utc).strftime(DEFAULT_TIMESTAMP_FORMAT_ISO)}

Modified Files:{modified_files_str}

Problems Encountered:{problems_str}

Metrics:
{print_metrics()}
==========================
"""
    return report

def create_secure_directory(path: Path, dry_run: bool = False) -> bool:
    """
    Creates a directory with secure permissions.

    Args:
        path: Path to the directory to create
        dry_run: If True, simulate the creation

    Returns:
        True if directory was created or already exists with correct permissions
    """
    if dry_run:
        logger.info(f"Would create directory: {path} (Dry Run)")
        return True

    try:
        # Create directory if it doesn't exist
        if not path.exists():
            path.mkdir(parents=True)
            os.chmod(path, DIR_PERMISSIONS)
            METRICS["directories_created"] += 1
            CREATED_DIRS_TRACKER.append(path)
            logger.debug(f"Created directory: {path}")
        # Ensure permissions are correct if it does exist
        elif path.is_dir():
            os.chmod(path, DIR_PERMISSIONS)
        else:
            logger.error(f"Path exists but is not a directory: {path}")
            return False
        return True
    except Exception as e:
        logger.error(f"Failed to create secure directory {path}: {e}")
        return False

# --- Main Restoration Logic ---

def restore_service_main(
    incident_id: str,
    service_type: str,
    template_path: Path,
    environment: str,
    config_source: Optional[Path] = None,
    custom_params: Optional[Dict[str, str]] = None,
    validate_steps: bool = False,
    approval_required: bool = False,
    notify_list: Optional[List[str]] = None,
    dry_run: bool = False,
    force: bool = False
) -> bool:
    """
    Orchestrates the service restoration process.

    Args:
        incident_id: Unique identifier for incident tracking
        service_type: Type of service being restored
        template_path: Path to the restoration template
        environment: Target environment (development, staging, production)
        config_source: Path to specific configuration source directory
        custom_params: Custom parameters to use in template substitution
        validate_steps: Whether to validate after each major step
        approval_required: Whether to require user confirmation
        notify_list: Recipients for notifications
        dry_run: If True, simulate actions without making changes
        force: If True, continue despite non-critical issues

    Returns:
        True if restoration was successful, False otherwise
    """
    start_time = time.time()
    global MODIFIED_FILES_TRACKER, CREATED_DIRS_TRACKER
    MODIFIED_FILES_TRACKER = [] # Reset tracker for this run
    CREATED_DIRS_TRACKER = []
    problems_encountered = []

    # Combine default params with custom ones
    all_params = {
        'ENVIRONMENT': environment,
        'SERVICE_TYPE': service_type,
        'INCIDENT_ID': incident_id,
        'TIMESTAMP': datetime.now(timezone.utc).strftime(DEFAULT_TIMESTAMP_FORMAT_ISO)
    }

    if custom_params:
        all_params.update(custom_params)

    logger.info(f"Starting service restoration for '{service_type}' in '{environment}' environment (Incident: {incident_id})")
    audit_log("service_restoration_start", f"Service restoration started for {service_type}", incident_id, details=all_params)

    try:
        # 1. Load Template
        template = load_template(template_path)
        metadata = template.get("metadata", {})
        template_name = metadata.get("template_name", "Unknown")
        template_version = metadata.get("version", "N/A")
        logger.info(f"Using template '{template_name}' version {template_version}")

        # 2. Validate Dependencies
        if not force:
            if not validate_dependencies(template, params=all_params, dry_run=dry_run):
                raise IncidentResponseError("Dependency validation failed.")
        else:
            logger.warning("Skipping dependency validation due to --force flag.")

        # 3. Approval Check (if required)
        if approval_required and not force:
            prompt = f"Proceed with restoring service '{service_type}' in '{environment}' using template '{template_path.name}'?"
            if not confirm_action(prompt, default=False):
                logger.warning("Restoration cancelled by user.")
                audit_log("service_restoration_cancel", f"Restoration cancelled by user for {service_type}", incident_id, success=False)
                return False
            audit_log("service_restoration_approval", f"Restoration approved by user for {service_type}", incident_id)

        # 4. Configuration Restoration
        logger.info("Starting configuration restoration phase...")
        config_restored = True
        config_section = template.get("configuration", {})

        if config_source:
            logger.info(f"Using specific configuration source directory: {config_source}")
            if not config_source.exists():
                raise IncidentResponseError(f"Specified config source does not exist: {config_source}")
            if not config_source.is_dir():
                raise IncidentResponseError(f"Specified config source is not a directory: {config_source}")

            # Handle configuration files from the source directory
            config_mappings = config_section.get("source_mappings", {}) # e.g., {"nginx.conf": "/etc/nginx/nginx.conf"}
            if not config_mappings:
                logger.warning("No source mappings defined in template, but config source provided")

            for src_file, target_path_str in config_mappings.items():
                src_path = config_source / src_file
                # Interpolate parameters in the target path
                target_path = Path(_interpolate_params(target_path_str, all_params))

                if src_path.exists():
                    logger.info(f"Restoring config '{target_path}' from '{src_path}'")
                    # Back up existing file if it exists
                    backup_path = backup_file(target_path, dry_run=dry_run)

                    if not dry_run:
                        try:
                            # Create parent directory with secure permissions
                            create_secure_directory(target_path.parent)

                            # Copy configuration file and set secure permissions
                            shutil.copy2(src_path, target_path)
                            os.chmod(target_path, FILE_PERMISSIONS)
                            METRICS["config_files_modified"] += 1

                            # Optionally verify hash if available
                            if calculate_file_hash:
                                src_hash = calculate_file_hash(str(src_path))
                                target_hash = calculate_file_hash(str(target_path))
                                if src_hash != target_hash:
                                    msg = f"Hash mismatch after copying config: {target_path}"
                                    logger.warning(msg)
                                    problems_encountered.append(msg)
                                    # Continue unless this is a critical file
                                    if config_mappings.get(src_file, {}).get("critical", False) and not force:
                                        raise IncidentResponseError(f"Critical configuration file verification failed: {target_path}")
                        except Exception as e:
                            msg = f"Failed to restore config file '{target_path}': {e}"
                            logger.error(msg)
                            problems_encountered.append(msg)
                            config_restored = False
                            if not force:
                                raise IncidentResponseError(f"Configuration restoration failed for {target_path}")
                else:
                    msg = f"Source config file '{src_path}' not found in config source"
                    logger.warning(msg)
                    problems_encountered.append(msg)
                    # Only fail if the file is marked as required
                    if config_mappings.get(src_file, {}).get("required", True) and not force:
                        raise IncidentResponseError(f"Required configuration file missing: {src_file}")
        else:
            logger.info("Applying configuration defined within the template.")

            # Apply configuration settings from the template itself
            for config_key, config_details in config_section.items():
                # Skip source_mappings as it's handled separately
                if config_key == "source_mappings":
                    continue

                if isinstance(config_details, dict) and "target_file" in config_details:
                    target_path_str = config_details["target_file"]
                    target_path = Path(_interpolate_params(target_path_str, all_params))
                    content = config_details.get("content") # Content might be inline or loaded from elsewhere
                    verification_cmd = config_details.get("verification")

                    # Interpolate parameters in content if it's a string
                    if isinstance(content, str):
                        content = _interpolate_params(content, all_params)

                    if content:
                        logger.info(f"Applying configuration to '{target_path}'")
                        backup_path = backup_file(target_path, dry_run=dry_run)

                        if not dry_run:
                            retry_count = CONFIG_RETRY_COUNT
                            while retry_count > 0:
                                try:
                                    # Create parent directory with secure permissions
                                    create_secure_directory(target_path.parent)

                                    # Write configuration content
                                    with open(target_path, 'w') as f:
                                        f.write(content)
                                    os.chmod(target_path, FILE_PERMISSIONS)
                                    METRICS["config_files_modified"] += 1

                                    # Run verification command if provided
                                    if verification_cmd:
                                        ret_code, _, stderr = run_command(
                                            verification_cmd,
                                            params=all_params,
                                            dry_run=dry_run
                                        )
                                        if ret_code != 0:
                                            msg = f"Configuration verification failed for '{target_path}': {stderr.strip()}"
                                            logger.error(msg)
                                            problems_encountered.append(msg)
                                            # Retry or raise exception
                                            if retry_count > 1 and not force:
                                                retry_count -= 1
                                                logger.info(f"Retrying configuration application ({retry_count} attempts left)")
                                                time.sleep(2)  # Brief delay before retry
                                                continue
                                            else:
                                                config_restored = False
                                                if not force:
                                                    raise IncidentResponseError(f"Configuration verification failed for {target_path}")

                                    # Break out of retry loop on success
                                    break

                                except Exception as e:
                                    msg = f"Failed to apply configuration to '{target_path}': {e}"
                                    logger.error(msg)
                                    problems_encountered.append(msg)

                                    # Retry or raise exception
                                    if retry_count > 1 and not force:
                                        retry_count -= 1
                                        logger.info(f"Retrying configuration application ({retry_count} attempts left)")
                                        time.sleep(2)  # Brief delay before retry
                                    else:
                                        config_restored = False
                                        if not force:
                                            raise IncidentResponseError(f"Configuration application failed for {target_path}")
                                        break

        if not config_restored and not force:
            raise IncidentResponseError("Configuration restoration failed.")

        logger.info("Configuration restoration phase completed.")
        audit_log("service_restoration_config", f"Configuration restoration phase completed for {service_type}", incident_id)

        if validate_steps and config_restored:
            # Perform validation after configuration is applied
            logger.info("Performing intermediate configuration validation...")
            config_validation_ok = perform_validation(
                template.get("config_validation", template.get("validation", {})),
                params=all_params,
                dry_run=dry_run
            )
            if not config_validation_ok and not force:
                raise IncidentResponseError("Configuration validation failed.")


        # 5. Service Restoration
        logger.info("Starting core service restoration phase...")
        service_restored = True
        restoration_section = template.get("restoration", {})
        restoration_commands = restoration_section.get("commands", [])

        if not restoration_commands:
            logger.warning("No restoration commands found in template.")

        # Execute pre-restoration commands if defined
        pre_commands = restoration_section.get("pre_commands", [])
        for cmd_info in pre_commands:
            cmd_str = cmd_info.get("command")
            cmd_desc = cmd_info.get("description", "Pre-restoration step")
            if not cmd_str:
                continue

            logger.info(f"Executing pre-restoration: {cmd_desc}")
            ret_code, stdout, stderr = run_command(cmd_str, params=all_params, dry_run=dry_run)
            if ret_code != 0:
                msg = f"Pre-restoration step failed: {cmd_desc} - {stderr.strip()}"
                logger.warning(msg)
                problems_encountered.append(msg)
                # Pre-commands failing is a warning but not fatal
                logger.warning("Continuing despite pre-restoration step failure.")

        # Execute main restoration commands
        for cmd_index, cmd_info in enumerate(restoration_commands):
            cmd_str = cmd_info.get("command")
            cmd_desc = cmd_info.get("description", f"Restoration step {cmd_index + 1}")
            if not cmd_str:
                continue

            logger.info(f"Executing restoration step: {cmd_desc}")

            # Determine if we need shell=True for complex commands
            shell_required = cmd_info.get("shell_required", False)
            if shell_required:
                logger.warning(f"Using shell=True for command (higher security risk): {cmd_desc}")

            # Execute with retries for reliability
            retry_count = SERVICE_RETRY_COUNT if cmd_info.get("allow_retry", True) else 1
            success = False

            while retry_count > 0 and not success:
                ret_code, stdout, stderr = run_command(
                    cmd_str,
                    params=all_params,
                    dry_run=dry_run,
                    shell=shell_required
                )

                if ret_code == 0:
                    success = True
                    if stdout and cmd_info.get("log_stdout", False):
                        logger.info(f"Command output: {stdout.strip()}")
                else:
                    msg = f"Restoration step failed: {cmd_desc}\nCommand: {cmd_str}\nError: {stderr.strip()}"
                    logger.error(msg)
                    problems_encountered.append(msg)

                    # Only retry if configured and not forced
                    if retry_count > 1 and not cmd_info.get("critical", False):
                        retry_count -= 1
                        wait_time = cmd_info.get("retry_delay", 5)
                        logger.info(f"Retrying command in {wait_time} seconds ({retry_count} attempts left)")
                        time.sleep(wait_time)
                    else:
                        service_restored = False
                        if cmd_info.get("critical", True) and not force:
                            # Critical commands must succeed
                            raise IncidentResponseError(f"Critical restoration step failed: {cmd_desc}")
                        break  # Skip further retries for non-critical commands

        # Execute post-restoration commands if defined
        post_commands = restoration_section.get("post_commands", [])
        for cmd_info in post_commands:
            cmd_str = cmd_info.get("command")
            cmd_desc = cmd_info.get("description", "Post-restoration step")
            if not cmd_str:
                continue

            logger.info(f"Executing post-restoration: {cmd_desc}")
            ret_code, stdout, stderr = run_command(cmd_str, params=all_params, dry_run=dry_run)
            if ret_code != 0:
                msg = f"Post-restoration step failed: {cmd_desc} - {stderr.strip()}"
                logger.warning(msg)
                problems_encountered.append(msg)
                # Post-commands failing is a warning but not fatal
                logger.warning("Continuing despite post-restoration step failure.")

        if not service_restored and not force:
            raise IncidentResponseError("One or more core restoration steps failed.")

        logger.info("Core service restoration phase completed.")
        audit_log("service_restoration_core", f"Core service restoration phase completed for {service_type}", incident_id)

        if validate_steps and service_restored:
            logger.info("Performing intermediate validation after core restoration...")
            service_validation_ok = perform_validation(template, params=all_params, dry_run=dry_run)
            if not service_validation_ok and not force:
                 raise IncidentResponseError("Intermediate validation failed after core restoration.")


        # 6. Final Validation
        logger.info("Starting final validation phase...")
        if not perform_validation(template, params=all_params, dry_run=dry_run):
             raise IncidentResponseError("Final validation failed.")
        logger.info("Final validation phase completed successfully.")
        audit_log("service_restoration_validation", f"Final validation completed for {service_type}", incident_id)


        # 7. Success
        duration = time.time() - start_time
        success_message = f"Service '{service_type}' restored successfully in {duration:.2f} seconds."
        logger.info(success_message)

        # Generate metrics report
        metrics_report = print_metrics()

        # Generate full report
        modified_files = [path for path, _ in MODIFIED_FILES_TRACKER]
        summary_report = generate_summary_report(
            incident_id=incident_id,
            service_type=service_type,
            environment=environment,
            success=True,
            template_name=template_name,
            duration=duration,
            modified_files=modified_files,
            problems_encountered=problems_encountered
        )

        # Log the success and audit
        audit_log("service_restoration_success", success_message, incident_id, details={
            "duration": duration,
            "template": template_name,
            "environment": environment,
            "files_modified": len(modified_files),
            "metrics": METRICS
        })

        # Send notification
        send_notification(
            subject=f"Success: Service Restoration for {service_type} ({environment})",
            message=success_message + f"\nIncident ID: {incident_id}\n\n{summary_report}",
            incident_id=incident_id,
            level="success",
            recipients=notify_list
        )

        # Clean up backups if successful
        cleanup_backups(dry_run=dry_run)
        return True

    except (FileNotFoundError, ValueError, IncidentResponseError) as e:
        error_message = f"Service restoration failed: {e}"
        logger.error(error_message)
        problems_encountered.append(str(e))

        # Generate metrics and summary
        duration = time.time() - start_time
        modified_files = [path for path, _ in MODIFIED_FILES_TRACKER]

        print_metrics()
        summary_report = generate_summary_report(
            incident_id=incident_id,
            service_type=service_type,
            environment=environment,
            success=False,
            template_name=metadata.get("template_name", "Unknown") if 'template' in locals() else "Unknown",
            duration=duration,
            modified_files=modified_files,
            problems_encountered=problems_encountered
        )

        # Log and audit
        audit_log("service_restoration_failure", error_message, incident_id, success=False, details={
            "error": str(e),
            "files_modified": len(modified_files),
            "metrics": METRICS
        })

        # Send notification
        send_notification(
            subject=f"FAILURE: Service Restoration for {service_type} ({environment})",
            message=error_message + f"\nIncident ID: {incident_id}\n\n{summary_report}\n\nCheck logs: {LOG_FILE_PATH}",
            incident_id=incident_id,
            level="error",
            recipients=notify_list
        )

        # Attempt rollback if not forced
        if not force:
            attempt_rollback(dry_run=dry_run)
        else:
            logger.warning("Skipping rollback attempt due to --force flag.")
            logger.info("Rollback Guidance: Manual rollback might be required. Review logs and consult the rollback plan.")

        return False
    except Exception as e:
        error_message = f"An unexpected error occurred during service restoration: {e}"
        logger.exception(error_message) # Log full traceback for unexpected errors
        problems_encountered.append(f"Unexpected error: {str(e)}")
        problems_encountered.append(f"Traceback: {traceback.format_exc()}")

        # Generate metrics and summary
        duration = time.time() - start_time
        modified_files = [path for path, _ in MODIFIED_FILES_TRACKER]

        print_metrics()
        summary_report = generate_summary_report(
            incident_id=incident_id,
            service_type=service_type,
            environment=environment,
            success=False,
            template_name=metadata.get("template_name", "Unknown") if 'template' in locals() else "Unknown",
            duration=duration,
            modified_files=modified_files,
            problems_encountered=problems_encountered
        )

        # Log and audit
        audit_log("service_restoration_exception", error_message, incident_id, success=False, details={
            "error": str(e),
            "traceback": traceback.format_exc(),
            "files_modified": len(modified_files),
            "metrics": METRICS
        })

        # Send notification
        send_notification(
            subject=f"CRITICAL FAILURE: Service Restoration for {service_type} ({environment})",
            message=error_message + f"\nIncident ID: {incident_id}\n\n{summary_report}\n\nCheck logs: {LOG_FILE_PATH}",
            incident_id=incident_id,
            level="critical",
            recipients=notify_list
        )

        # Attempt rollback if not forced
        if not force:
            attempt_rollback(dry_run=dry_run)
        else:
            logger.warning("Skipping rollback attempt due to --force flag.")
            logger.info("Rollback Guidance: Manual rollback likely required. Review logs and consult the rollback plan.")

        return False
    finally:
        # Ensure trackers are cleared even if rollback wasn't attempted
        MODIFIED_FILES_TRACKER.clear()
        CREATED_DIRS_TRACKER.clear()


# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description="Automate service restoration after a security incident.",
        epilog="Example: python service_restoration.py --incident-id IR-2024-001 --service web-app --template resources/restoration_templates/web_application.json --environment production --notify admin@example.com"
    )

    parser.add_argument("--incident-id", required=True, help="Incident ID for tracking and logging.")
    parser.add_argument("--service", required=True, help="Type of service to restore (e.g., web-application, database). Matches template base name.")
    parser.add_argument("--template", required=True, type=Path, help="Path to the JSON restoration template file.")
    parser.add_argument("--environment", required=True, choices=["development", "staging", "production", "dr-recovery"], help="Target environment.")

    parser.add_argument("--config-source", type=Path, help="Path to a directory containing specific configuration files to restore.")
    parser.add_argument("--param", action='append', help="Custom parameters to override template values or use in commands (format: key=value).")
    parser.add_argument("--validate-each-step", action='store_true', help="Perform validation after configuration and core restoration phases.")
    parser.add_argument("--approval-required", action='store_true', help="Require manual confirmation before starting restoration (ignored if --force is used).")
    parser.add_argument("--notify", action='append', help="Email address or channel ID to notify on completion/failure.")
    parser.add_argument("--dry-run", action='store_true', help="Simulate restoration without making changes. Logs actions that would be taken.")
    parser.add_argument("--force", action='store_true', help="Force restoration, bypassing dependency checks, approvals, and stopping on non-critical errors.")
    parser.add_argument("--verify-only", action='store_true', help="Only run validation steps without performing restoration.")
    parser.add_argument("--skip-validation", action='store_true', help="Skip all validation steps, including final validation.")
    parser.add_argument("--output-report", type=Path, help="Save detailed report to specified file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")

    args = parser.parse_args()

    # Adjust log level if verbose
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    if args.dry_run:
        logger.info("--- DRY RUN MODE ENABLED ---")
        logger.warning("No actual changes will be made to the system.")

    # Parse custom parameters
    custom_params = {}
    if args.param:
        for p in args.param:
            if '=' in p:
                key, value = p.split('=', 1)
                custom_params[key.strip()] = value.strip()
                logger.debug(f"Using custom parameter: {key.strip()}={value.strip()}")
            else:
                logger.warning(f"Ignoring invalid parameter format (expected key=value): {p}")

    # Handle verify-only mode
    if args.verify_only:
        logger.info("--- VERIFY ONLY MODE ---")
        try:
            # Load template
            template = load_template(args.template)

            # Set up parameters
            params = {
                'ENVIRONMENT': args.environment,
                'SERVICE_TYPE': args.service,
                'INCIDENT_ID': args.incident_id,
                'TIMESTAMP': datetime.now(timezone.utc).strftime(DEFAULT_TIMESTAMP_FORMAT_ISO)
            }
            if custom_params:
                params.update(custom_params)

            # Run dependency validation first
            logger.info("Validating dependencies...")
            deps_valid = validate_dependencies(template, params=params, dry_run=True)
            if not deps_valid:
                logger.error("Dependency validation failed.")
                sys.exit(1)

            # Run service validation checks
            logger.info("Running service validation checks...")
            validation_ok = perform_validation(template, params=params, dry_run=True)

            if validation_ok:
                logger.info("All validation checks passed.")
                sys.exit(0)
            else:
                logger.error("One or more validation checks failed.")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Error during verification: {e}")
            sys.exit(2)

    # Save report at completion if requested
    def save_report_if_needed(report_text):
        if args.output_report:
            try:
                output_dir = args.output_report.parent
                if not output_dir.exists() and str(output_dir) != '.':
                    output_dir.mkdir(parents=True, exist_ok=True)
                with open(args.output_report, 'w') as f:
                    f.write(report_text)
                logger.info(f"Report saved to {args.output_report}")
            except Exception as e:
                logger.error(f"Failed to save report to {args.output_report}: {e}")

    # Execute main restoration logic
    try:
        success = restore_service_main(
            incident_id=args.incident_id,
            service_type=args.service,
            template_path=args.template,
            environment=args.environment,
            config_source=args.config_source,
            custom_params=custom_params,
            validate_steps=args.validate_each_step and not args.skip_validation,
            approval_required=args.approval_required, # Main function handles force bypass
            notify_list=args.notify,
            dry_run=args.dry_run,
            force=args.force,
            skip_validation=args.skip_validation
        )

        # Generate final report
        modified_files = [path for path, _ in MODIFIED_FILES_TRACKER]
        report = generate_summary_report(
            incident_id=args.incident_id,
            service_type=args.service,
            environment=args.environment,
            success=success,
            template_name=Path(args.template).stem,
            duration=time.time() - METRICS["start_time"],
            modified_files=modified_files,
            problems_encountered=[]
        )

        # Save report if output file specified
        save_report_if_needed(report)

        if success:
            logger.info("Service restoration process completed successfully.")
            sys.exit(0)
        else:
            logger.error("Service restoration process failed.")
            sys.exit(1)
    except Exception as e:
        # Catch any unexpected exceptions from main setup before restore_service_main
        logger.critical(f"Critical error during script execution: {e}", exc_info=True)

        # Try to generate an error report
        try:
            error_report = f"""
SERVICE RESTORATION ERROR REPORT
===============================
Incident ID:    {args.incident_id}
Service Type:   {args.service}
Environment:    {args.environment}
Error:          {str(e)}
Timestamp:      {datetime.now(timezone.utc).strftime(DEFAULT_TIMESTAMP_FORMAT_ISO)}

Stack Trace:
{traceback.format_exc()}
===============================
"""
            save_report_if_needed(error_report)
        except Exception:
            pass  # Don't let the error reporting fail

        sys.exit(2)

def get_template_list() -> List[Dict[str, Any]]:
    """
    Gets a list of available restoration templates.

    Returns:
        List of dictionaries containing template information
    """
    templates_dir = RECOVERY_DIR / "resources" / "restoration_templates"
    if not templates_dir.exists() or not templates_dir.is_dir():
        logger.warning(f"Templates directory not found: {templates_dir}")
        return []

    templates = []
    for file_path in templates_dir.glob("*.json"):
        try:
            with open(file_path, 'r') as f:
                template_data = json.load(f)

            metadata = template_data.get("metadata", {})
            templates.append({
                "name": metadata.get("template_name", file_path.stem),
                "path": file_path,
                "version": metadata.get("version", "Unknown"),
                "applicable_systems": metadata.get("applicable_systems", []),
                "last_updated": metadata.get("last_updated", "Unknown")
            })
        except Exception as e:
            logger.warning(f"Error loading template {file_path}: {e}")

    return templates

if __name__ == "__main__":
    main()
