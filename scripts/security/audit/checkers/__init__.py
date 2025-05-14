#!/usr/bin/env python3
"""
Security audit checkers for the Cloud Infrastructure Platform.

This package contains modular security check implementations for verifying security
controls across various domains including file permissions, network security,
system configurations, and common utilities.

Each checker follows a consistent pattern for severity classification, evidence collection,
compliance mapping, and remediation guidance to ensure standardized findings.
"""

import logging
from typing import Dict, List, Any, Optional

# Configure package-level logger
logger = logging.getLogger("security.audit.checkers")

# Import key components for easier access at the package level
try:
    # Import core components from common module
    from scripts.security.audit.checkers.common import (
        # Core classes
        CheckResult,
        CheckResultSet,
        Severity,
        ComplianceFramework,

        # Constants
        DEFAULT_RESULT_FORMAT,
        SEVERITY_COLOR_MAP,
        DEFAULT_BASELINE_DIR,
        DEFAULT_CONFIG_DIR,
        DEFAULT_TIMEOUT,

        # Severity levels for convenient access
        CRITICAL, HIGH, MEDIUM, LOW, INFO,

        # Common helper functions
        create_check_result,
        run_check,
        validate_check_config,
        handle_check_error,
        safe_check,

        # Utility version info
        __version__ as common_version
    )

    # Import specialized checker groups
    from scripts.security.audit.checkers.file_permissions import (
        critical_file_check,
        ownership_check,
        world_writable_check
    )

    from scripts.security.audit.checkers.network import (
        firewall_check,
        open_port_check,
        tls_check
    )

    from scripts.security.audit.checkers.system import (
        auth_check,
        password_policy_check,
        service_check
    )

    CHECKERS_AVAILABLE = True
    logger.debug("Security audit checkers initialized successfully")

except ImportError as e:
    CHECKERS_AVAILABLE = False
    logger.warning(f"Could not initialize all security audit checkers: {e}")


# Package version
__version__ = "1.0.0"


def get_available_checkers() -> Dict[str, List[str]]:
    """
    Get a list of available security checkers organized by domain.

    Returns:
        Dictionary mapping domains to lists of available checker module names
    """
    if not CHECKERS_AVAILABLE:
        return {"error": ["Security audit checkers not fully available"]}

    return {
        "file_permissions": [
            "critical_file_check",
            "ownership_check",
            "world_writable_check"
        ],
        "network": [
            "firewall_check",
            "open_port_check",
            "tls_check"
        ],
        "system": [
            "auth_check",
            "password_policy_check",
            "service_check"
        ]
    }


def run_security_checks(
    domains: Optional[List[str]] = None,
    severity_threshold: str = "LOW",
    baseline: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> CheckResultSet:
    """
    Run security checks across specified domains.

    Args:
        domains: List of domains to check (file_permissions, network, system)
                 or None to check all domains
        severity_threshold: Minimum severity level to include in results
        baseline: Optional baseline configuration to use for checks
        config: Optional configuration parameters for checkers

    Returns:
        CheckResultSet containing all check results
    """
    if not CHECKERS_AVAILABLE:
        logger.error("Cannot run security checks: checkers not fully available")
        raise ImportError("Security audit checkers not fully available")

    results = CheckResultSet()
    all_domains = ["file_permissions", "network", "system"]
    domains_to_check = domains if domains is not None else all_domains

    # Validate domains
    for domain in domains_to_check:
        if domain not in all_domains:
            logger.warning(f"Unknown checker domain: {domain}, skipping")
            continue

        logger.info(f"Running security checks for domain: {domain}")

        try:
            if domain == "file_permissions":
                # Run file permission checks
                checker = critical_file_check.CriticalFileChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

                checker = ownership_check.OwnershipChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

                checker = world_writable_check.WorldWritableChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

            elif domain == "network":
                # Run network checks
                checker = firewall_check.FirewallChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

                checker = open_port_check.OpenPortChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

                checker = tls_check.TLSChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

            elif domain == "system":
                # Run system checks
                checker = auth_check.AuthenticationChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

                checker = password_policy_check.PasswordPolicyChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

                checker = service_check.ServiceChecker(baseline=baseline, config=config)
                results.add_results(checker.check())

        except Exception as e:
            logger.error(f"Error running {domain} security checks: {e}", exc_info=True)
            # Add error as a result
            results.add_results([
                create_check_result(
                    severity=HIGH,
                    title=f"{domain.capitalize()} Security Check Failed",
                    description=f"An error occurred while running security checks in the {domain} domain: {str(e)}",
                    remediation="Check logs for detailed error information and address any underlying issues."
                )
            ])

    # Apply severity threshold filter if specified
    if severity_threshold:
        try:
            threshold_level = Severity[severity_threshold.upper()]
            results.filter_by_severity(threshold_level)
        except (KeyError, AttributeError):
            logger.warning(f"Invalid severity threshold '{severity_threshold}', using all results")

    return results


# Export key elements at package level
__all__ = [
    # Core classes
    'CheckResult',
    'CheckResultSet',
    'Severity',
    'ComplianceFramework',

    # Constants
    'DEFAULT_RESULT_FORMAT',
    'SEVERITY_COLOR_MAP',
    'DEFAULT_BASELINE_DIR',
    'DEFAULT_CONFIG_DIR',
    'DEFAULT_TIMEOUT',

    # Severity level constants
    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO',

    # Utility functions
    'create_check_result',
    'run_check',
    'validate_check_config',
    'handle_check_error',
    'safe_check',

    # Entry point functions
    'run_security_checks',
    'get_available_checkers',

    # Checker module imports
    'critical_file_check',
    'ownership_check',
    'world_writable_check',
    'firewall_check',
    'open_port_check',
    'tls_check',
    'auth_check',
    'password_policy_check',
    'service_check',

    # Version information
    '__version__'
]
