#!/usr/bin/env python3
"""
Dependency security scanner for Cloud Infrastructure Platform.

This script analyzes project dependencies for known security vulnerabilities
and license compliance issues. It also verifies package integrity and checks
for potential supply chain attacks.
"""

import os
import sys
import json
import subprocess
import re
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional, Set, Union

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
REPORT_DIR = PROJECT_ROOT / "security-reports"
REPORT_FILE = REPORT_DIR / f"dependency-check-{datetime.now().strftime('%Y%m%d')}.json"
REQUIREMENTS_FILES = [
    PROJECT_ROOT / "requirements.txt",
    PROJECT_ROOT / "requirements-dev.txt"
]
ALLOWED_LICENSES = [
    "MIT",
    "BSD",
    "Apache-2.0",
    "Apache 2.0",
    "LGPL",
    "Python-2.0",
    "ISC"
]
VULNERABILITY_THRESHOLD = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 5,
    "LOW": 10
}

# Critical dependencies that require verification
CRITICAL_DEPS = {
    "cryptography",
    "requests",
    "urllib3",
    "flask",
    "sqlalchemy",
    "werkzeug",
    "jwt",
    "pyjwt"
}

# File paths for dependency integrity tracking
DEPS_HASH_FILE = PROJECT_ROOT / "deployment/security/dependency_hashes.json"


def log(message: str, level: str = "INFO") -> None:
    """Print a timestamped log message with level.

    Args:
        message: The message to log
        level: The log level (INFO, WARNING, ERROR)
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] {message}")


def run_safety_check() -> List[Dict[str, Any]]:
    """Run safety check on Python dependencies.

    Returns:
        List of found vulnerabilities
    """
    log("Running safety check for Python dependencies")

    try:
        # Ensure the safety tool is installed
        subprocess.check_call([sys.executable, "-m", "pip", "install", "safety"],
                              stdout=subprocess.PIPE)

        # Run safety check for each requirements file
        results = []
        for req_file in REQUIREMENTS_FILES:
            if not req_file.exists():
                continue

            log(f"Checking {req_file}")
            output = subprocess.check_output(
                [sys.executable, "-m", "safety", "check",
                 "-r", str(req_file), "--json"],
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            try:
                data = json.loads(output)
                results.extend(data.get("vulnerabilities", []))
            except json.JSONDecodeError:
                log(f"Error parsing safety output: {output}", "WARNING")
                continue

        return results
    except subprocess.CalledProcessError as e:
        log(f"Safety check command failed: {e}", "ERROR")
        if e.output:
            try:
                data = json.loads(e.output)
                return data.get("vulnerabilities", [])
            except json.JSONDecodeError:
                pass
        return []
    except Exception as e:
        log(f"Error running safety check: {e}", "ERROR")
        return []


def check_licenses() -> List[Dict[str, str]]:
    """Check licenses of Python dependencies.

    Returns:
        List of license compliance issues
    """
    log("Checking licenses for Python dependencies")

    try:
        # Ensure pip-licenses is installed
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pip-licenses"],
                              stdout=subprocess.PIPE)

        # Get license information as JSON
        output = subprocess.check_output(
            [sys.executable, "-m", "pip_licenses", "--format=json"],
            universal_newlines=True
        )

        licenses = json.loads(output)
        violations = []

        for pkg in licenses:
            license_name = pkg.get("License", "Unknown")
            pkg_name = pkg.get("Name", "Unknown")

            if license_name == "UNKNOWN":
                violations.append({
                    "package": pkg_name,
                    "license": "Unknown",
                    "issue": "Unknown license"
                })
            elif not any(allowed in license_name for allowed in ALLOWED_LICENSES):
                violations.append({
                    "package": pkg_name,
                    "license": license_name,
                    "issue": "Non-compliant license"
                })

        return violations
    except Exception as e:
        log(f"Error checking licenses: {e}", "ERROR")
        return []


def check_outdated_dependencies() -> List[Dict[str, str]]:
    """Check for outdated dependencies.

    Returns:
        List of outdated dependencies
    """
    log("Checking for outdated dependencies")

    try:
        output = subprocess.check_output(
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            universal_newlines=True
        )

        outdated = json.loads(output)
        return outdated
    except Exception as e:
        log(f"Error checking outdated dependencies: {e}", "ERROR")
        return []


def calculate_package_hash(package_name: str) -> Dict[str, str]:
    """Calculate file hashes for an installed package.

    Args:
        package_name: Name of the installed package

    Returns:
        Dictionary of file paths and their hashes
    """
    try:
        # Get package files
        import pkg_resources
        dist = pkg_resources.get_distribution(package_name)

        hashes = {}
        base_path = Path(dist.location)

        # Find package directory
        package_path = None
        for path in base_path.glob(f"**/{dist.key}*"):
            if path.is_dir() and (path / "__init__.py").exists():
                package_path = path
                break

        if not package_path:
            return {}

        # Calculate hashes for all Python files
        for py_file in package_path.glob("**/*.py"):
            if py_file.is_file():
                try:
                    rel_path = py_file.relative_to(base_path)
                    with open(py_file, "rb") as f:
                        content = f.read()
                        file_hash = hashlib.sha256(content).hexdigest()
                        hashes[str(rel_path)] = file_hash
                except (IOError, OSError):
                    pass

        return hashes

    except Exception as e:
        log(f"Error calculating package hash for {package_name}: {e}", "WARNING")
        return {}


def verify_dependency_integrity() -> Tuple[bool, List[Dict[str, Any]]]:
    """Verify integrity of installed critical dependencies.

    Returns:
        Tuple of (success_status, list_of_modified_packages)
    """
    log("Verifying integrity of critical dependencies")

    # Get baseline hashes if they exist
    baseline_hashes = {}
    if DEPS_HASH_FILE.exists():
        try:
            with open(DEPS_HASH_FILE, 'r') as f:
                baseline_hashes = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            log(f"Error loading dependency baseline: {e}", "ERROR")

    modified_packages = []
    success = True

    # Check critical dependencies
    for package_name in CRITICAL_DEPS:
        try:
            import pkg_resources
            pkg = pkg_resources.get_distribution(package_name)

            # Calculate current hashes
            current_hashes = calculate_package_hash(package_name)

            # If no baseline exists for this package, add it to the baseline
            if package_name not in baseline_hashes:
                baseline_hashes[package_name] = {
                    "version": pkg.version,
                    "files": current_hashes
                }
                continue

            baseline = baseline_hashes[package_name]

            # If version changed, we expect files to change too
            if baseline["version"] != pkg.version:
                log(f"Package {package_name} version changed: {baseline['version']} → {pkg.version}")
                baseline_hashes[package_name]["version"] = pkg.version
                baseline_hashes[package_name]["files"] = current_hashes
                continue

            # Check for file modifications without version change (suspicious)
            baseline_files = baseline["files"]

            # Find changed files
            changed_files = []
            for file_path, current_hash in current_hashes.items():
                if file_path in baseline_files and baseline_files[file_path] != current_hash:
                    changed_files.append(file_path)

            # If files changed but version didn't, this is suspicious
            if changed_files:
                success = False
                modified_packages.append({
                    "package": package_name,
                    "version": pkg.version,
                    "changed_files": changed_files
                })
                log(f"WARNING: {package_name} has {len(changed_files)} modified files but same version", "WARNING")

        except Exception as e:
            log(f"Error verifying {package_name}: {e}", "WARNING")

    # Update baseline with current hashes
    try:
        DEPS_HASH_FILE.parent.mkdir(exist_ok=True)
        with open(DEPS_HASH_FILE, 'w') as f:
            json.dump(baseline_hashes, f, indent=2)
    except (IOError, OSError) as e:
        log(f"Error updating dependency baseline: {e}", "ERROR")

    return success, modified_packages


def generate_report(
    vulnerabilities: List[Dict[str, Any]],
    license_issues: List[Dict[str, str]],
    outdated: List[Dict[str, str]],
    integrity_issues: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generate a comprehensive report.

    Args:
        vulnerabilities: List of found vulnerabilities
        license_issues: List of license compliance issues
        outdated: List of outdated dependencies
        integrity_issues: List of integrity violations

    Returns:
        Report data as dictionary
    """
    REPORT_DIR.mkdir(exist_ok=True)
    integrity_issues = integrity_issues or []

    # Count vulnerabilities by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "UNKNOWN").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Prepare report data
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "vulnerabilities": {
                "total": len(vulnerabilities),
                "by_severity": severity_counts,
                "threshold_exceeded": any(
                    count > VULNERABILITY_THRESHOLD.get(sev, 0)
                    for sev, count in severity_counts.items()
                )
            },
            "license_issues": {
                "total": len(license_issues)
            },
            "outdated_dependencies": {
                "total": len(outdated)
            },
            "integrity_issues": {
                "total": len(integrity_issues)
            }
        },
        "vulnerabilities": vulnerabilities,
        "license_issues": license_issues,
        "outdated_dependencies": outdated,
        "integrity_issues": integrity_issues
    }

    # Write report to file
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    return report


# Alias for the generate_report function to match API exposed in __init__.py
generate_dependency_report = generate_report


def main() -> int:
    """Main function to run all dependency checks.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    log("Starting dependency security check")

    # Run vulnerability checks
    vulnerabilities = run_safety_check()
    log(f"Found {len(vulnerabilities)} potential security vulnerabilities")

    # Check licenses
    license_issues = check_licenses()
    log(f"Found {len(license_issues)} license compliance issues")

    # Check outdated dependencies
    outdated = check_outdated_dependencies()
    log(f"Found {len(outdated)} outdated dependencies")

    # Verify dependency integrity
    integrity_ok, integrity_issues = verify_dependency_integrity()
    if not integrity_ok:
        log(f"Found {len(integrity_issues)} dependency integrity issues", "WARNING")

    # Generate report
    report = generate_dependency_report(vulnerabilities, license_issues, outdated, integrity_issues)
    log(f"Report generated: {REPORT_FILE}")

    # Determine exit code based on thresholds
    exit_code = 0

    # Check vulnerability thresholds
    for severity, count in report["summary"]["vulnerabilities"]["by_severity"].items():
        threshold = VULNERABILITY_THRESHOLD.get(severity, 0)
        if count > threshold:
            log(f"FAIL: {severity} vulnerabilities ({count}) exceed threshold ({threshold})", "ERROR")
            exit_code = 1

    # Check for integrity issues
    if not integrity_ok and os.environ.get("CI_SKIP_INTEGRITY_CHECK") != "true":
        log("FAIL: Dependency integrity check failed", "ERROR")
        exit_code = 1

    if exit_code == 0:
        log("All dependency checks passed")
    else:
        log("Dependency checks failed", "ERROR")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
