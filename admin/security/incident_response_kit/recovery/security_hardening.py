"""
Security Hardening Module for Incident Response

This module provides functionality for applying security hardening measures
to systems after a security incident has been contained. It applies security
hardening profiles based on system type and learns from incident findings
to prevent similar issues in the future.
"""

import os
import sys
import json
import logging
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Set, Tuple

# Initialize constants and paths
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
RESOURCES_DIR = SCRIPT_DIR / "resources"
HARDENING_PROFILES_DIR = RESOURCES_DIR / "hardening_profiles"
VERIFICATION_SCRIPTS_DIR = RESOURCES_DIR / "verification_scripts"

# Initialize logging
logger = logging.getLogger(__name__)

# Initialize module path and try to import parent package components
try:
    # Add parent directory to path so we can import from the package
    RECOVERY_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
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
        from admin.security.incident_response_kit.coordination.notification_system import notify_stakeholders
        NOTIFICATION_AVAILABLE = True
    except ImportError:
        NOTIFICATION_AVAILABLE = False
        notify_stakeholders = None

except ImportError as e:
    print(f"Warning: Error importing incident response kit modules: {e}", file=sys.stderr)
    print("Some functionality may be limited.", file=sys.stderr)
    # Set defaults for standalone operation
    AUDIT_AVAILABLE = False
    NOTIFICATION_AVAILABLE = False
    DEFAULT_EVIDENCE_DIR = Path("/secure/evidence")
    DEFAULT_LOG_DIR = Path("/var/log")
    DEFAULT_TEMP_DIR = Path("/tmp/ir-kit")

    # Define minimal necessary classes and functions
    log_security_event = None
    calculate_file_hash = None
    verify_file_integrity = None
    notify_stakeholders = None

    class IncidentResponseError(Exception):
        """Base exception for incident response errors."""
        pass

# Define module-specific exceptions
class SecurityHardeningError(IncidentResponseError):
    """Error during security hardening operations."""
    pass

class ProfileNotFoundError(SecurityHardeningError):
    """Error when a hardening profile cannot be found."""
    pass

class ValidationError(SecurityHardeningError):
    """Error validating security hardening results."""
    pass

# Constants for hardening operations
TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
DEFAULT_BACKUP_SUFFIX = ".pre-hardening-bak"
HARDENING_TIMEOUT = 1800  # 30 minutes default timeout for hardening operations
FILE_PERMISSIONS = 0o600  # Secure permissions for sensitive files
DIR_PERMISSIONS = 0o700  # Owner rwx only for directories
DEFAULT_SEVERITY_THRESHOLD = "medium"  # Default severity threshold for applying hardening
HARDENING_LOG_NAME = f"security_hardening_{datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)}.log"
LOG_FILE_PATH = Path(DEFAULT_LOG_DIR) / HARDENING_LOG_NAME

# Configure logging if not already configured
try:
    LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE_PATH),
            logging.StreamHandler(sys.stdout)  # Also log to console
        ]
    )
    # Secure the log file itself
    try:
        os.chmod(LOG_FILE_PATH, FILE_PERMISSIONS)
    except OSError as e:
        print(f"Warning: Could not set permissions on log file {LOG_FILE_PATH}: {e}", file=sys.stderr)
except OSError as e:
    print(f"Error creating or accessing log directory {LOG_FILE_PATH.parent}: {e}", file=sys.stderr)
    # Fallback to stderr if log file cannot be created
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )

# Global tracking variables
MODIFIED_FILES = []
CREATED_DIRS = []
BACKUP_FILES = []
METRICS = {
    "start_time": time.time(),
    "controls_applied": 0,
    "files_modified": 0,
    "backups_created": 0,
    "verification_failures": 0,
    "skipped_controls": 0
}

def load_hardening_profile(profile_name: str, custom_profile_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load a security hardening profile.

    Args:
        profile_name: Name of the profile to load
        custom_profile_path: Optional path to a custom profile file

    Returns:
        Dictionary containing the hardening profile

    Raises:
        ProfileNotFoundError: If profile cannot be found
        ValueError: If profile has invalid JSON or missing required fields
    """
    try:
        # Try loading from custom path if provided
        if custom_profile_path:
            profile_path = Path(custom_profile_path)
            if not profile_path.exists():
                raise ProfileNotFoundError(f"Custom profile not found: {custom_profile_path}")
        else:
            # Try to load from standard profiles directory
            if not profile_name.lower().endswith('.json'):
                profile_name = f"{profile_name}.json"

            profile_path = HARDENING_PROFILES_DIR / profile_name
            if not profile_path.exists():
                # Try alternate location if available
                alt_path = IR_KIT_DIR / "recovery" / "resources" / "hardening_profiles" / profile_name
                if alt_path.exists():
                    profile_path = alt_path
                else:
                    raise ProfileNotFoundError(f"Hardening profile not found: {profile_name}")

        # Load the profile
        with open(profile_path, 'r') as f:
            profile = json.load(f)

        # Validate profile structure
        required_fields = {"metadata", "controls"}
        if not all(field in profile for field in required_fields):
            missing = required_fields - set(profile.keys())
            raise ValueError(f"Invalid profile format. Missing fields: {missing}")

        logger.info(f"Loaded hardening profile: {profile['metadata'].get('name', profile_name)}")
        return profile

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in profile {profile_name}: {str(e)}")
    except Exception as e:
        if isinstance(e, (ProfileNotFoundError, ValueError)):
            raise
        raise ProfileNotFoundError(f"Failed to load profile {profile_name}: {str(e)}")

def backup_file(file_path: str, suffix: str = DEFAULT_BACKUP_SUFFIX) -> bool:
    """
    Create a backup of a file before modifying it.

    Args:
        file_path: Path to the file to backup
        suffix: Suffix to add to the backup file name

    Returns:
        True if backup was successful, False otherwise
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            logger.warning(f"File does not exist, cannot backup: {file_path}")
            return False

        backup_path = file_path.with_suffix(f"{file_path.suffix}{suffix}")
        shutil.copy2(file_path, backup_path)
        os.chmod(backup_path, FILE_PERMISSIONS)

        BACKUP_FILES.append(str(backup_path))
        METRICS["backups_created"] += 1
        logger.debug(f"Created backup: {backup_path}")
        return True

    except Exception as e:
        logger.error(f"Error backing up file {file_path}: {e}")
        return False

def interpolate_variables(template_str: str, variables: Dict[str, str]) -> str:
    """
    Replace variables in template string with their values.

    Args:
        template_str: Template string with ${variable} placeholders
        variables: Dictionary of variable names and values

    Returns:
        String with variables replaced by their values
    """
    result = template_str
    for key, value in variables.items():
        if isinstance(value, str):
            result = result.replace(f"${{{key}}}", value)
    return result

def execute_command(
    command: Union[str, List[str]],
    variables: Dict[str, str] = None,
    timeout: int = 300,
    capture_output: bool = True,
    check: bool = False
) -> Dict[str, Any]:
    """
    Execute a system command safely.

    Args:
        command: Command to execute (string or list)
        variables: Variables to interpolate in the command
        timeout: Timeout in seconds
        capture_output: Whether to capture command output
        check: Whether to raise an exception on non-zero return code

    Returns:
        Dictionary with command results
    """
    variables = variables or {}
    result = {
        "success": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "command": command
    }

    try:
        # If command is a string, interpolate variables and split
        if isinstance(command, str):
            if variables:
                command = interpolate_variables(command, variables)
            args = command
        else:
            # If command is a list, interpolate variables in each element
            if variables:
                args = [interpolate_variables(arg, variables) for arg in command]
            else:
                args = command

        logger.debug(f"Executing: {args}")

        # Execute the command
        proc = subprocess.run(
            args,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=check,
            shell=isinstance(args, str)
        )

        # Store results
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0
        if capture_output:
            result["stdout"] = proc.stdout
            result["stderr"] = proc.stderr

        if not result["success"]:
            logger.warning(f"Command failed with exit code {proc.returncode}: {args}")
            if capture_output:
                logger.debug(f"STDERR: {proc.stderr}")

        return result

    except subprocess.TimeoutExpired as e:
        result["timed_out"] = True
        result["error"] = str(e)
        logger.error(f"Command timed out after {timeout} seconds: {command}")
        return result

    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Error executing command: {str(e)}")
        return result

def apply_control(
    target: str,
    control_name: str,
    control_config: Dict[str, Any],
    variables: Dict[str, str],
    severity_threshold: str,
    skip_verification: bool = False,
    skip_rules: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Apply a security hardening control to a target system.

    Args:
        target: Target system to harden
        control_name: Name of the control
        control_config: Control configuration
        variables: Variables for command interpolation
        severity_threshold: Minimum severity to apply
        skip_verification: Whether to skip verification steps
        skip_rules: List of rule names to skip

    Returns:
        Dictionary with the control application result
    """
    skip_rules = skip_rules or []

    # If this control is in the skip list, skip it
    if control_name in skip_rules:
        logger.info(f"Skipping control {control_name} (in skip list)")
        METRICS["skipped_controls"] += 1
        return {
            "control": control_name,
            "success": True,
            "skipped": True,
            "reason": "In skip list"
        }

    # Skip controls with severity below threshold
    severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    control_severity = control_config.get("severity", "medium").lower()
    threshold_severity = severity_threshold.lower()

    if severity_levels.get(control_severity, 0) < severity_levels.get(threshold_severity, 0):
        logger.info(f"Skipping control {control_name} (severity {control_severity} below threshold {threshold_severity})")
        METRICS["skipped_controls"] += 1
        return {
            "control": control_name,
            "success": True,
            "skipped": True,
            "reason": f"Severity {control_severity} below threshold {threshold_severity}"
        }

    logger.info(f"Applying control: {control_name} (severity: {control_severity})")

    result = {
        "control": control_name,
        "success": False,
        "skipped": False,
        "verification_passed": None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Apply control based on type
    try:
        # Check if we have a remediation command
        remediation_cmd = control_config.get("remediation_command")
        if remediation_cmd:
            # Update variables with control-specific values
            control_vars = variables.copy()
            control_vars.update({
                "TARGET": target,
                "CONTROL": control_name
            })

            # Add any control-specific variables if they exist
            for key, value in control_config.items():
                if isinstance(value, (str, int, float, bool)) and key not in ("remediation_command", "verification_commands"):
                    control_vars[key] = str(value)

            # Execute the remediation command
            cmd_result = execute_command(remediation_cmd, control_vars)
            result["command_result"] = {
                "exit_code": cmd_result.get("exit_code"),
                "success": cmd_result.get("success", False)
            }

            if not cmd_result.get("success", False):
                result["error"] = f"Remediation command failed: {cmd_result.get('stderr', '')}"
                return result

            METRICS["controls_applied"] += 1
            result["success"] = True

            # Verify if requested
            if not skip_verification and "verification_commands" in control_config:
                verification_results = []
                for verify_cmd in control_config["verification_commands"]:
                    verify_result = execute_command(verify_cmd, control_vars)
                    verification_results.append(verify_result)

                    # If verification failed, mark it but continue with other verifications
                    if not verify_result.get("success", False):
                        logger.warning(f"Verification failed for control {control_name}: {verify_cmd}")
                        METRICS["verification_failures"] += 1

                result["verification_results"] = verification_results
                # Control is verified if all verification commands succeeded
                result["verification_passed"] = all(vr.get("success", False) for vr in verification_results)

        # If we get here without applying anything, mark as not applicable
        elif not remediation_cmd:
            logger.warning(f"No remediation command for control {control_name}")
            result["success"] = True
            result["skipped"] = True
            result["reason"] = "No remediation command"

        return result

    except Exception as e:
        logger.error(f"Error applying control {control_name}: {str(e)}")
        result["error"] = str(e)
        return result

def harden_system(
    target: str,
    profile: Union[str, Dict[str, Any]],
    incident_id: Optional[str] = None,
    component_names: Optional[List[str]] = None,
    severity_threshold: str = DEFAULT_SEVERITY_THRESHOLD,
    custom_params: Optional[Dict[str, str]] = None,
    skip_verification: bool = False,
    skip_rules: Optional[List[str]] = None,
    backup_configs: bool = True,
    custom_profile_path: Optional[str] = None,
    dry_run: bool = False,
    notify: Optional[List[str]] = None,
    evidence_dir: Optional[str] = None,
    log_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Apply security hardening to a system using a security profile.

    This is the main function exposed by the security hardening module. It applies
    a security hardening profile to a system, typically after a security incident.

    Args:
        target: Target system to harden (hostname, IP, or alias)
        profile: Profile name or profile dictionary
        incident_id: Optional incident ID for tracking
        component_names: Optional list of component names to limit hardening scope
        severity_threshold: Minimum severity level to apply (critical, high, medium, low)
        custom_params: Custom parameters to override profile defaults
        skip_verification: Whether to skip verification steps
        skip_rules: List of rule names to skip
        backup_configs: Whether to backup config files before modifying
        custom_profile_path: Path to custom profile file
        dry_run: If True, no changes will be made
        notify: List of email addresses or channels to notify on completion/failure
        evidence_dir: Directory to store evidence and logs
        log_file: Path to log file for hardening operations

    Returns:
        Dictionary with hardening results

    Raises:
        SecurityHardeningError: For hardening failures
        ProfileNotFoundError: If profile cannot be found
        ValueError: If parameters are invalid
    """
    start_time = time.time()
    operation_id = f"harden_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    skip_rules = skip_rules or []
    component_names = component_names or []

    # Set up logging to custom log file if provided
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)

    # Prepare result structure
    result = {
        "success": False,
        "target": target,
        "operation_id": operation_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profile": profile if isinstance(profile, str) else "custom_profile",
        "incident_id": incident_id,
        "dry_run": dry_run,
        "controls_applied": [],
        "controls_failed": [],
        "controls_skipped": [],
        "backup_files": []
    }

    try:
        # Load the hardening profile
        if isinstance(profile, dict):
            hardening_profile = profile
            profile_name = profile.get("metadata", {}).get("name", "custom_profile")
        else:
            try:
                hardening_profile = load_hardening_profile(profile, custom_profile_path)
                profile_name = hardening_profile.get("metadata", {}).get("name", profile)
            except (ProfileNotFoundError, ValueError) as e:
                result["error"] = str(e)
                result["success"] = False
                return result

        logger.info(f"Starting security hardening for {target} using profile {profile_name}")
        if incident_id:
            logger.info(f"Associated with incident: {incident_id}")
        if dry_run:
            logger.info("DRY RUN MODE - No changes will be made")

        # Log hardening operation start to security event log if available
        if AUDIT_AVAILABLE and log_security_event:
            event_data = {
                "target": target,
                "profile": profile_name,
                "operation_id": operation_id,
                "incident_id": incident_id,
                "components": component_names,
                "severity_threshold": severity_threshold,
                "dry_run": dry_run
            }
            log_security_event("security_hardening_start", "info", event_data)

        # Set up variables for command interpolation
        variables = {
            "TARGET": target,
            "PROFILE_NAME": profile_name,
            "TIMESTAMP": datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT),
            "INCIDENT_ID": incident_id or "NONE"
        }

        # Add custom parameters
        if custom_params:
            variables.update(custom_params)

        # Apply each control in the profile
        controls_applied = []
        controls_failed = []
        controls_skipped = []

        # Get controls from profile
        controls = hardening_profile.get("controls", {})

        # Filter by component if specified
        if component_names:
            filtered_controls = {}
            for control_name, control_config in controls.items():
                control_component = control_config.get("component", "").lower()
                if any(comp.lower() == control_component for comp in component_names):
                    filtered_controls[control_name] = control_config

            controls = filtered_controls
            logger.info(f"Filtered to {len(controls)} controls for components: {', '.join(component_names)}")

        if not controls:
            logger.warning(f"No applicable controls found in profile {profile_name}")
            result["warning"] = "No applicable controls found in profile"

        # Process each control
        for control_name, control_config in controls.items():
            if dry_run:
                logger.info(f"Would apply control: {control_name} (DRY RUN)")
                controls_skipped.append({
                    "control": control_name,
                    "skipped": True,
                    "reason": "Dry run mode"
                })
                continue

            control_result = apply_control(
                target=target,
                control_name=control_name,
                control_config=control_config,
                variables=variables,
                severity_threshold=severity_threshold,
                skip_verification=skip_verification,
                skip_rules=skip_rules
            )

            if control_result.get("skipped", False):
                controls_skipped.append(control_result)
            elif control_result.get("success", False):
                controls_applied.append(control_result)
            else:
                controls_failed.append(control_result)

        # Compile overall results
        result["controls_applied"] = controls_applied
        result["controls_failed"] = controls_failed
        result["controls_skipped"] = controls_skipped
        result["backup_files"] = BACKUP_FILES
        result["success"] = len(controls_failed) == 0
        result["metrics"] = {
            "controls_applied": len(controls_applied),
            "controls_failed": len(controls_failed),
            "controls_skipped": len(controls_skipped),
            "verification_failures": METRICS["verification_failures"],
            "backups_created": METRICS["backups_created"],
            "duration_seconds": time.time() - start_time
        }

        # Generate a report file if an evidence directory is specified
        if evidence_dir:
            evidence_path = Path(evidence_dir)
            evidence_path.mkdir(parents=True, exist_ok=True)

            # Generate a report name based on target, profile and timestamp
            report_name = f"hardening_report_{target}_{profile_name}_{operation_id}.json"
            report_path = evidence_path / report_name

            with open(report_path, 'w') as f:
                json.dump(result, f, indent=2, default=str)

            logger.info(f"Hardening report saved to {report_path}")
            result["report_path"] = str(report_path)

        # Log completion status to security event log if available
        if AUDIT_AVAILABLE and log_security_event:
            completion_data = {
                "target": target,
                "profile": profile_name,
                "operation_id": operation_id,
                "success": result["success"],
                "controls_applied": len(controls_applied),
                "controls_failed": len(controls_failed),
                "controls_skipped": len(controls_skipped),
                "duration_seconds": time.time() - start_time
            }
            log_security_event(
                "security_hardening_complete",
                "info" if result["success"] else "warning",
                completion_data
            )

        # Send notifications if requested
        if notify and NOTIFICATION_AVAILABLE and notify_stakeholders:
            notification_subject = f"Security Hardening {result['success'] and 'Completed' or 'Failed'}: {target}"
            notification_body = (
                f"Security hardening operation {operation_id} {result['success'] and 'completed successfully' or 'failed'}.\n\n"
                f"Target: {target}\n"
                f"Profile: {profile_name}\n"
                f"Controls applied: {len(controls_applied)}\n"
                f"Controls failed: {len(controls_failed)}\n"
                f"Controls skipped: {len(controls_skipped)}\n"
                f"Duration: {result['metrics']['duration_seconds']:.2f} seconds\n"
            )

            try:
                notify_stakeholders(
                    recipients=notify,
                    subject=notification_subject,
                    message=notification_body,
                    incident_id=incident_id,
                    priority="normal" if result["success"] else "high"
                )
            except Exception as e:
                logger.error(f"Failed to send notification: {str(e)}")

        # Log final status
        if result["success"]:
            logger.info(f"Security hardening completed successfully for {target}")
        else:
            logger.warning(f"Security hardening completed with failures for {target}")

        return result

    except Exception as e:
        logger.error(f"Error during security hardening: {str(e)}", exc_info=True)
        result["error"] = str(e)
        result["success"] = False

        # Log failure to security event log if available
        if AUDIT_AVAILABLE and log_security_event:
            failure_data = {
                "target": target,
                "operation_id": operation_id,
                "error": str(e)
            }
            log_security_event("security_hardening_failure", "error", failure_data)

        # Send failure notification if requested
        if notify and NOTIFICATION_AVAILABLE and notify_stakeholders:
            notification_subject = f"Security Hardening Failed: {target}"
            notification_body = (
                f"Security hardening operation {operation_id} failed with error:\n\n"
                f"{str(e)}\n\n"
                f"Target: {target}\n"
                f"Profile: {profile if isinstance(profile, str) else 'custom_profile'}\n"
                f"Incident ID: {incident_id or 'N/A'}\n"
            )

            try:
                notify_stakeholders(
                    recipients=notify,
                    subject=notification_subject,
                    message=notification_body,
                    incident_id=incident_id,
                    priority="high"
                )
            except Exception as notify_err:
                logger.error(f"Failed to send notification: {str(notify_err)}")

        return result

def verify_hardening(
    target: str,
    profile: Union[str, Dict[str, Any]],
    component_names: Optional[List[str]] = None,
    custom_profile_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verify security hardening has been applied to a system.

    Args:
        target: Target system to verify
        profile: Profile name or profile dictionary
        component_names: Optional list of component names to verify
        custom_profile_path: Path to custom profile

    Returns:
        Dictionary with verification results
    """
    # Load profile
    if isinstance(profile, dict):
        hardening_profile = profile
        profile_name = profile.get("metadata", {}).get("name", "custom_profile")
    else:
        try:
            hardening_profile = load_hardening_profile(profile, custom_profile_path)
            profile_name = hardening_profile.get("metadata", {}).get("name", profile)
        except (ProfileNotFoundError, ValueError) as e:
            return {
                "success": False,
                "error": str(e),
                "verifications": []
            }

    logger.info(f"Verifying security hardening for {target} using profile {profile_name}")

    # Prepare variables for command interpolation
    variables = {
        "TARGET": target,
        "PROFILE_NAME": profile_name
    }

    # Track verification results
    verifications = []
    verification_passed = 0
    verification_failed = 0

    # Get controls from profile
    controls = hardening_profile.get("controls", {})

    # Filter by component if specified
    if component_names:
        filtered_controls = {}
        for control_name, control_config in controls.items():
            control_component = control_config.get("component", "").lower()
            if any(comp.lower() == control_component for comp in component_names):
                filtered_controls[control_name] = control_config

        controls = filtered_controls

    # Verify each control
    for control_name, control_config in controls.items():
        if "verification_commands" not in control_config:
            logger.debug(f"No verification commands for {control_name}, skipping")
            continue

        verification_results = []
        verification_success = True

        # Run each verification command
        for cmd in control_config["verification_commands"]:
            result = execute_command(cmd, variables)
            verification_results.append(result)

            # Mark verification failed if any command fails
            if not result.get("success", False):
                verification_success = False

        # Add to verification results
        verifications.append({
            "control": control_name,
            "success": verification_success,
            "component": control_config.get("component", ""),
            "severity": control_config.get("severity", "medium"),
            "verification_results": verification_results
        })

        # Update counters
        if verification_success:
            verification_passed += 1
        else:
            verification_failed += 1

    # Compile results
    result = {
        "success": verification_failed == 0 and verification_passed > 0,
        "target": target,
        "profile": profile_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verification_passed": verification_passed,
        "verification_failed": verification_failed,
        "verifications": verifications
    }

    logger.info(f"Verification completed: {verification_passed} passed, {verification_failed} failed")
    return result

def get_available_profiles() -> List[Dict[str, Any]]:
    """
    Get a list of available hardening profiles.

    Returns:
        List of dictionaries with profile information
    """
    profiles = []

    # Check standard directory
    if HARDENING_PROFILES_DIR.exists():
        for file_path in HARDENING_PROFILES_DIR.glob("*.json"):
            try:
                with open(file_path, 'r') as f:
                    profile = json.load(f)

                # Extract basic information
                profiles.append({
                    "filename": file_path.name,
                    "path": str(file_path),
                    "name": profile.get("metadata", {}).get("name", file_path.stem),
                    "version": profile.get("metadata", {}).get("version", "unknown"),
                    "applicable_systems": profile.get("metadata", {}).get("applicable_systems", []),
                    "control_count": len(profile.get("controls", {}))
                })
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Error reading profile {file_path}: {str(e)}")

    return profiles

def generate_hardening_recommendations(
    incident_id: str,
    incident_type: str,
    systems_involved: List[str],
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate security hardening recommendations based on incident data.

    Args:
        incident_id: ID of the incident
        incident_type: Type of security incident
        systems_involved: List of systems involved in the incident
        output_file: Optional path to save recommendations

    Returns:
        Dictionary with hardening recommendations
    """
    logger.info(f"Generating hardening recommendations for incident {incident_id}")

    # Map incident types to profile suggestions
    incident_to_profile_map = {
        "malware": ["application", "container"],
        "ransomware": ["application", "database", "container"],
        "ddos": ["network", "web_server"],
        "data_breach": ["database", "application"],
        "web_attack": ["web_server", "application"],
        "phishing": ["application"],
        "account_compromise": ["application"],
        "unauthorized_access": ["application", "network"]
    }

    # Get profiles based on incident type
    recommended_profiles = incident_to_profile_map.get(incident_type.lower(), ["application"])

    # Get available profiles
    available_profiles = get_available_profiles()

    # Match recommended profiles to available ones
    recommendations = []
    for system in systems_involved:
        system_recommendations = []

        for profile_name in recommended_profiles:
            # Find matching profiles
            matches = [p for p in available_profiles if profile_name in p["filename"].lower()]

            if matches:
                for match in matches:
                    system_recommendations.append({
                        "profile_name": match["name"],
                        "filename": match["filename"],
                        "reason": f"Recommended based on {incident_type} incident type",
                        "priority": "high" if profile_name == recommended_profiles[0] else "medium"
                    })

        recommendations.append({
            "system": system,
            "profiles": system_recommendations
        })

    result = {
        "incident_id": incident_id,
        "incident_type": incident_type,
        "systems_involved": systems_involved,
        "recommendations": recommendations,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "generated_by": "security_hardening.py"
    }

    # Save to file if requested
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            logger.info(f"Hardening recommendations saved to {output_file}")
        except IOError as e:
            logger.error(f"Error saving recommendations to {output_file}: {str(e)}")

    return result

def main():
    """Command line interface for security hardening."""
    import argparse

    parser = argparse.ArgumentParser(description="Security Hardening Tool")
    parser.add_argument("--target", required=True, help="Target system to harden")
    parser.add_argument("--profile", required=True, help="Profile name or path to profile file")
    parser.add_argument("--incident-id", help="Incident ID for tracking")
    parser.add_argument("--components", nargs="+", help="Component names to limit hardening scope")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                       default="medium", help="Minimum severity level to apply")
    parser.add_argument("--param", action="append", help="Custom parameters in KEY=VALUE format")
    parser.add_argument("--skip-verification", action="store_true", help="Skip verification steps")
    parser.add_argument("--skip-rules", nargs="+", help="Rules to skip")
    parser.add_argument("--no-backup", action="store_true", help="Don't backup config files")
    parser.add_argument("--dry-run", action="store_true", help="No changes will be made")
    parser.add_argument("--notify", nargs="+", help="Email addresses or channels to notify")
    parser.add_argument("--evidence-dir", help="Directory to store evidence and logs")
    parser.add_argument("--log-file", help="Path to log file for operations")
    parser.add_argument("--verify-only", action="store_true", help="Only verify, don't apply hardening")
    parser.add_argument("--list-profiles", action="store_true", help="List available profiles")

    args = parser.parse_args()

    # Handle listing profiles
    if args.list_profiles:
        profiles = get_available_profiles()
        print(f"Available security hardening profiles ({len(profiles)}):")
        for i, profile in enumerate(profiles, 1):
            print(f"{i}. {profile['name']} (v{profile['version']})")
            print(f"   File: {profile['filename']}")
            print(f"   Controls: {profile['control_count']}")
            print(f"   Systems: {', '.join(profile['applicable_systems'])}")
            print()
        sys.exit(0)

    # Parse custom parameters
    custom_params = {}
    if args.param:
        for param in args.param:
            if "=" in param:
                key, value = param.split("=", 1)
                custom_params[key.strip()] = value.strip()

    # Determine if profile is a file path
    custom_profile_path = None
    if os.path.isfile(args.profile):
        custom_profile_path = args.profile
        profile = os.path.basename(args.profile)
    else:
        profile = args.profile

    try:
        if args.verify_only:
            # Verify only mode
            result = verify_hardening(
                target=args.target,
                profile=profile,
                component_names=args.components,
                custom_profile_path=custom_profile_path
            )

            # Print verification results
            print(f"\nVerification Results for {args.target} using profile {profile}:")
            print(f"Status: {'SUCCESS' if result['success'] else 'FAILED'}")
            print(f"Passed: {result['verification_passed']}")
            print(f"Failed: {result['verification_failed']}")

            # Print failures
            if result['verification_failed'] > 0:
                print("\nFailed Verifications:")
                for i, verification in enumerate([v for v in result['verifications'] if not v['success']], 1):
                    print(f"{i}. Control: {verification['control']}")
                    print(f"   Severity: {verification['severity']}")
                    if verification.get('component'):
                        print(f"   Component: {verification['component']}")
                    print()

            sys.exit(0 if result['success'] else 1)
        else:
            # Apply hardening
            result = harden_system(
                target=args.target,
                profile=profile,
                incident_id=args.incident_id,
                component_names=args.components,
                severity_threshold=args.severity,
                custom_params=custom_params,
                skip_verification=args.skip_verification,
                skip_rules=args.skip_rules,
                backup_configs=not args.no_backup,
                custom_profile_path=custom_profile_path,
                dry_run=args.dry_run,
                notify=args.notify,
                evidence_dir=args.evidence_dir,
                log_file=args.log_file
            )

            # Print summary
            print(f"\nSecurity Hardening Summary for {args.target}:")
            print(f"Status: {'SUCCESS' if result['success'] else 'FAILED'}")
            print(f"Controls Applied: {len(result['controls_applied'])}")
            print(f"Controls Failed: {len(result['controls_failed'])}")
            print(f"Controls Skipped: {len(result['controls_skipped'])}")

            # Print failures if any
            if result['controls_failed']:
                print("\nFailed Controls:")
                for i, control in enumerate(result['controls_failed'], 1):
                    print(f"{i}. {control['control']}: {control.get('error', 'Unknown error')}")

            # Show report location if available
            if 'report_path' in result:
                print(f"\nDetailed report: {result['report_path']}")

            # Set exit code based on success
            sys.exit(0 if result['success'] else 1)

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

# Module exports
__all__ = [
    # Main functions
    'harden_system',
    'verify_hardening',
    'get_available_profiles',
    'generate_hardening_recommendations',

    # Helper functions
    'load_hardening_profile',

    # Exceptions
    'SecurityHardeningError',
    'ProfileNotFoundError',
    'ValidationError',

    # Constants
    'HARDENING_PROFILES_DIR',
    'VERIFICATION_SCRIPTS_DIR',
    'DEFAULT_SEVERITY_THRESHOLD'
]

if __name__ == "__main__":
    main()
