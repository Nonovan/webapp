#!/usr/bin/env python3
# filepath: scripts/security/audit/checkers/common/check_helper.py
"""
Helper functions for implementing security checks.

This module provides higher-level functions and decorators that simplify
the implementation of security checks, including baseline application,
evidence collection, compliance mapping, remediation generation, and
error handling patterns.
"""

import os
import re
import sys
import time
import json
import logging
import platform
import traceback
import functools
import contextlib
import resource
from pathlib import Path
from typing import Any, Dict, List, Callable, Optional, Union, Set, Tuple, TypeVar, Generic, cast

# Import common utilities
try:
    from .check_utils import (
        load_baseline,
        secure_execute,
        get_environment,
        get_os_info,
        get_compliance_requirements,
        sanitize_string
    )
    from .check_result import CheckResult, CheckResultSet, Severity
except ImportError:
    # Allow standalone operation for testing
    import sys
    sys.stderr.write("Warning: Running check_helper in standalone mode\n")

    # Mock imports if modules are not available
    class Severity:
        CRITICAL = 5
        HIGH = 4
        MEDIUM = 3
        LOW = 2
        INFO = 1

    class CheckResult:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class CheckResultSet:
        def __init__(self):
            self.results = []

        def add_result(self, result):
            self.results.append(result)

        def add_results(self, results):
            self.results.extend(results)

    def load_baseline(*args, **kwargs):
        return {}

    def secure_execute(*args, **kwargs):
        return None

    def get_environment():
        return "development"

    def get_os_info():
        return {"system": platform.system()}

    def get_compliance_requirements(*args, **kwargs):
        return {}

    def sanitize_string(s):
        return s

# Configure logging
logger = logging.getLogger("security.audit.checker")

# Type variables for generics
T = TypeVar('T')
R = TypeVar('R')

# Constants
MAX_EVIDENCE_SIZE = 1024 * 1024  # 1MB max evidence size
DEFAULT_TIMEOUT = 30  # Default timeout in seconds
DEFAULT_MEMORY_LIMIT = 512 * 1024 * 1024  # 512MB memory limit


def run_check(
    check_func: Callable[..., List[CheckResult]],
    environment: Optional[str] = None,
    baseline_name: Optional[str] = None,
    **kwargs
) -> List[CheckResult]:
    """
    Run a security check with proper error handling and baseline application.

    Args:
        check_func: The check function to run
        environment: Optional environment name (development, staging, production)
        baseline_name: Optional baseline name to load and apply
        **kwargs: Additional arguments to pass to the check function

    Returns:
        List of CheckResult objects
    """
    start_time = time.time()
    env = environment or get_environment()

    try:
        # Set resource limits for the check
        set_resource_limits()

        # Load baseline if specified
        baseline = None
        if baseline_name:
            try:
                logger.debug(f"Loading baseline '{baseline_name}' for environment '{env}'")
                baseline = load_baseline(baseline_name, env)
                kwargs['baseline'] = baseline
            except Exception as e:
                logger.warning(f"Failed to load baseline '{baseline_name}': {e}")
                # Continue without baseline

        # Run the check function
        results = check_func(**kwargs)

        # Apply baseline to results if specified
        if baseline:
            results = apply_baseline(results, baseline)

        # Add execution time to results context
        for result in results:
            result.add_context("execution_time", time.time() - start_time)
            result.add_context("environment", env)

        return results

    except Exception as e:
        logger.error(f"Error running check {check_func.__name__}: {e}", exc_info=True)
        # Return error as a check result
        return [CheckResult(
            severity=Severity.HIGH,
            title=f"Check Execution Failed: {check_func.__name__}",
            description=f"The security check failed to execute properly: {str(e)}",
            remediation="Review the check implementation and address any errors.",
            evidence={"error": str(e), "traceback": traceback.format_exc()}
        )]


def apply_baseline(
    results: List[CheckResult],
    baseline: Dict[str, Any]
) -> List[CheckResult]:
    """
    Apply baseline configuration to check results.

    This function filters or modifies results based on the provided baseline,
    which may include exemptions, severity adjustments, or additional context.

    Args:
        results: List of check results
        baseline: Baseline configuration dictionary

    Returns:
        Modified list of check results
    """
    if not baseline or not results:
        return results

    filtered_results = []
    exemptions = baseline.get("exemptions", {})

    for result in results:
        # Check if this finding is exempted
        exempted = False

        # Check exemptions by check ID if it exists
        if result.check_id and result.check_id in exemptions:
            # Check if exemption is valid (has proper expiration)
            exemption = exemptions[result.check_id]
            reason = exemption.get("reason", "No reason provided")
            expiration = exemption.get("expiration")

            if expiration:
                # Check if exemption is expired
                try:
                    from datetime import datetime
                    expiry_date = datetime.fromisoformat(expiration)
                    if expiry_date > datetime.now():
                        exempted = True
                        logger.info(f"Finding {result.check_id} exempted: {reason} until {expiration}")
                        result.add_context("exemption", {"reason": reason, "expiration": expiration})
                except (ValueError, ImportError) as e:
                    logger.warning(f"Invalid exemption expiration date for {result.check_id}: {e}")
            else:
                # Permanent exemption (not recommended)
                exempted = True
                logger.info(f"Finding {result.check_id} permanently exempted: {reason}")
                result.add_context("exemption", {"reason": reason, "permanent": True})

        # Apply severity adjustments if configured
        severity_adjustments = baseline.get("severity_adjustments", {})
        if result.check_id in severity_adjustments:
            new_severity = severity_adjustments[result.check_id]
            original_severity = result.severity

            try:
                if isinstance(new_severity, str):
                    result.severity = Severity[new_severity.upper()]
                elif isinstance(new_severity, int):
                    result.severity = Severity(new_severity)

                logger.info(f"Adjusted severity for {result.check_id} from {original_severity} to {result.severity}")
                result.add_context("severity_adjusted", {"original": original_severity.name})
            except (KeyError, ValueError) as e:
                logger.warning(f"Invalid severity adjustment for {result.check_id}: {e}")

        # Add additional context from baseline if available
        additional_context = baseline.get("context", {})
        if result.check_id in additional_context:
            for key, value in additional_context[result.check_id].items():
                result.add_context(f"baseline_{key}", value)

        # Include result unless exempted
        if not exempted:
            filtered_results.append(result)

    return filtered_results


def normalize_path(path: Union[str, Path]) -> Path:
    """
    Normalize a path for security checks, expanding variables and user directory.

    Args:
        path: Path string or Path object

    Returns:
        Normalized Path object
    """
    if isinstance(path, str):
        # Expand environment variables and user directory
        path = os.path.expandvars(os.path.expanduser(path))

    return Path(path).resolve()


def validate_check_config(
    config: Dict[str, Any],
    required_fields: List[str] = None,
    optional_fields: Dict[str, Any] = None
) -> Tuple[bool, List[str]]:
    """
    Validate a check configuration against required and optional fields.

    Args:
        config: Configuration dictionary to validate
        required_fields: List of required field names
        optional_fields: Dictionary of optional field names and default values

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []
    required_fields = required_fields or []
    optional_fields = optional_fields or {}

    # Check required fields
    for field in required_fields:
        if field not in config:
            errors.append(f"Missing required field: {field}")

    # Set defaults for optional fields if not present
    for field, default in optional_fields.items():
        if field not in config:
            config[field] = default

    return len(errors) == 0, errors


def collect_evidence(
    evidence_func: Callable[..., Dict[str, Any]],
    *args,
    **kwargs
) -> Dict[str, Any]:
    """
    Safely collect evidence for security check findings.

    Args:
        evidence_func: Function that collects evidence
        *args: Arguments to pass to evidence function
        **kwargs: Keyword arguments to pass to evidence function

    Returns:
        Dictionary containing evidence
    """
    try:
        # Collect evidence with timeout
        with with_timeout(DEFAULT_TIMEOUT):
            evidence = evidence_func(*args, **kwargs)

        # Truncate large evidence to prevent memory issues
        if isinstance(evidence, dict):
            for key, value in evidence.items():
                if isinstance(value, str) and len(value) > MAX_EVIDENCE_SIZE:
                    evidence[key] = value[:MAX_EVIDENCE_SIZE] + "... [truncated]"

        return evidence
    except Exception as e:
        logger.warning(f"Error collecting evidence: {e}")
        return {"error": f"Failed to collect evidence: {str(e)}"}


def map_to_compliance(
    finding_type: str,
    compliance_framework: Optional[str] = None
) -> List[str]:
    """
    Map a finding type to relevant compliance requirements.

    Args:
        finding_type: Type of finding (e.g., "weak_password", "world_writable")
        compliance_framework: Optional specific framework to map to

    Returns:
        List of compliance reference IDs
    """
    try:
        # Get all applicable frameworks or the specific one requested
        frameworks = [compliance_framework] if compliance_framework else [
            "CIS", "NIST", "PCI_DSS", "HIPAA", "SOC2"
        ]

        compliance_refs = []

        for framework in frameworks:
            # Load compliance mappings
            mappings = get_compliance_requirements(framework)

            # Find matching references
            for control_id, control_info in mappings.items():
                if isinstance(control_info, dict) and "findings" in control_info:
                    findings = control_info["findings"]
                    if finding_type in findings or any(re.match(pattern, finding_type) for pattern in findings if isinstance(pattern, str)):
                        compliance_refs.append(f"{framework} {control_id}")

        return compliance_refs
    except Exception as e:
        logger.warning(f"Error mapping compliance: {e}")
        return []


def generate_remediation(
    finding_type: str,
    context: Dict[str, Any] = None
) -> str:
    """
    Generate standardized remediation guidance for a finding type.

    Args:
        finding_type: Type of finding
        context: Additional context for customizing remediation

    Returns:
        Remediation guidance string
    """
    context = context or {}

    # Common remediation templates
    remediation_templates = {
        "world_writable_file": "Remove world-writable permissions with: chmod o-w {path}",
        "world_readable_sensitive": "Remove world-readable permissions with: chmod o-r {path}",
        "incorrect_owner": "Change file owner with: chown {owner} {path}",
        "incorrect_group": "Change file group with: chgrp {group} {path}",
        "weak_permissions": "Set secure permissions with: chmod {mode} {path}",
        "suid_set": "Remove SUID bit with: chmod u-s {path}",
        "sgid_set": "Remove SGID bit with: chmod g-s {path}",
        "service_running": "Disable and stop the service with: systemctl disable --now {service}",
        "service_not_running": "Enable and start the service with: systemctl enable --now {service}",
        "open_port": "Close unnecessary port {port} in the firewall configuration",
        "missing_patch": "Install security patch with: {package_manager} update {package}",
        "weak_cipher": "Update TLS configuration to disable weak ciphers and protocols"
    }

    # Get remediation template
    template = remediation_templates.get(finding_type, "Review system configuration and apply appropriate security controls.")

    # Format with context
    try:
        return template.format(**context)
    except KeyError:
        return template


def merge_results(
    result_sets: List[List[CheckResult]]
) -> List[CheckResult]:
    """
    Merge multiple lists of check results into a single list.

    Args:
        result_sets: List of result lists to merge

    Returns:
        Combined list of unique results
    """
    merged = []
    seen_titles = set()

    for result_list in result_sets:
        for result in result_list:
            # Create a unique key for the result
            key = f"{result.title}_{result.severity.name}"
            if key not in seen_titles:
                seen_titles.add(key)
                merged.append(result)

    return merged


def filter_results(
    results: List[CheckResult],
    min_severity: Severity = Severity.LOW,
    title_pattern: Optional[str] = None,
    compliance: Optional[List[str]] = None,
    context_key: Optional[str] = None,
    context_value: Optional[Any] = None
) -> List[CheckResult]:
    """
    Filter results based on various criteria.

    Args:
        results: List of check results to filter
        min_severity: Minimum severity level
        title_pattern: Optional regex pattern to match titles
        compliance: Optional list of compliance framework prefixes
        context_key: Optional context key to check for
        context_value: Optional context value to match (if key is provided)

    Returns:
        Filtered list of results
    """
    filtered = []

    for result in results:
        # Check severity
        if result.severity < min_severity:
            continue

        # Check title pattern
        if title_pattern and not re.search(title_pattern, result.title):
            continue

        # Check compliance
        if compliance:
            if not hasattr(result, 'compliance') or not result.compliance:
                continue

            if not any(c.startswith(prefix) for prefix in compliance for c in result.compliance):
                continue

        # Check context
        if context_key:
            if not hasattr(result, 'context') or not result.context:
                continue

            if context_key not in result.context:
                continue

            if context_value is not None and result.context[context_key] != context_value:
                continue

        filtered.append(result)

    return filtered


def set_resource_limits(
    cpu_time: int = 60,           # 60 seconds of CPU time
    memory: int = DEFAULT_MEMORY_LIMIT,  # 512MB memory limit
    open_files: int = 1024        # 1024 open files
) -> None:
    """
    Set resource limits for security checks to prevent resource exhaustion.

    Args:
        cpu_time: Maximum CPU time in seconds
        memory: Maximum memory in bytes
        open_files: Maximum number of open files
    """
    try:
        # Set CPU time limit
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_time, cpu_time))

        # Set memory limit
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))

        # Set open files limit
        resource.setrlimit(resource.RLIMIT_NOFILE, (open_files, open_files))
    except (resource.error, ValueError, AttributeError) as e:
        logger.warning(f"Failed to set resource limits: {e}")


@contextlib.contextmanager
def with_timeout(seconds: int = DEFAULT_TIMEOUT):
    """
    Context manager that applies a timeout to the enclosed block.

    Args:
        seconds: Timeout in seconds

    Raises:
        TimeoutError: If the operation times out
    """
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")

    # Set the timeout handler
    import signal
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)

    try:
        yield
    finally:
        # Reset the alarm and restore the old handler
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def handle_check_error(
    error: Exception,
    check_name: str = "unknown"
) -> CheckResult:
    """
    Handle errors in security checks and convert to a check result.

    Args:
        error: The exception that occurred
        check_name: Name of the check that failed

    Returns:
        CheckResult representing the error
    """
    logger.error(f"Error in check {check_name}: {str(error)}", exc_info=True)

    error_type = type(error).__name__
    tb = traceback.format_exc()

    # Create a check result for the error
    return CheckResult(
        severity=Severity.MEDIUM,
        title=f"Check Error: {check_name}",
        description=f"An error occurred during security check execution: {error_type}: {str(error)}",
        remediation="Review the check implementation and correct any issues.",
        evidence={
            "error_type": error_type,
            "error_message": str(error),
            "traceback": tb
        }
    )


def safe_check(
    check_func: Callable[..., List[CheckResult]]
) -> Callable[..., List[CheckResult]]:
    """
    Decorator to make a security check function safe with error handling.

    Args:
        check_func: Check function to decorate

    Returns:
        Wrapped check function with error handling
    """
    @functools.wraps(check_func)
    def wrapper(*args, **kwargs) -> List[CheckResult]:
        try:
            # Set resource limits
            set_resource_limits()

            # Run the check with timeout
            with with_timeout():
                return check_func(*args, **kwargs)
        except Exception as e:
            # Handle the error
            return [handle_check_error(e, check_func.__name__)]

    return wrapper


if __name__ == "__main__":
    # Example usage when module is run directly
    @safe_check
    def example_check() -> List[CheckResult]:
        results = []

        # Simulate a check that collects evidence
        evidence = collect_evidence(lambda: {
            "system_info": get_os_info(),
            "environment": get_environment()
        })

        # Create a check result
        result = CheckResult(
            severity=Severity.MEDIUM,
            title="Example Security Check",
            description="This is an example security check result.",
            remediation="Apply the recommended security control.",
            evidence=evidence
        )

        # Map to compliance frameworks
        compliance = map_to_compliance("weak_configuration")
        for ref in compliance:
            result.add_compliance_references([ref])

        results.append(result)
        return results

    # Run the example check
    print("Running example security check...")
    results = run_check(example_check)

    # Show results
    for result in results:
        print(f"[{result.severity.name}] {result.title}")
        print(f"  Description: {result.description}")
        print(f"  Remediation: {result.remediation}")
