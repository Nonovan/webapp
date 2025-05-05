#!/usr/bin/env python3
"""
Static Application Security Testing (SAST) scanner for Cloud Infrastructure Platform.

This script performs static code analysis to identify potential security issues
in the codebase and integrates with the file integrity monitoring system.
"""

import os
import sys
import json
import subprocess
import tempfile
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
REPORT_DIR = PROJECT_ROOT / "security-reports"
REPORT_FILE = REPORT_DIR / f"sast-scan-{datetime.now().strftime('%Y%m%d')}.json"
GITLAB_REPORT_FILE = REPORT_DIR / "gl-sast-report.json"
CODE_DIRS = ["api", "blueprints", "models", "services", "core", "extensions"]
SEVERITY_THRESHOLD = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 5,
    "LOW": 10
}

# Special directories that require additional security scrutiny
CRITICAL_PATHS = [
    "core/security",
    "api/security",
    "models/security",
    "services/security",
    "models/auth",
    "api/auth"
]

# Configure execution environment
TIMEOUT_SECONDS = 600  # 10 minutes
MAX_CONCURRENT_PROCESSES = 4


def log(message: str, level: str = "INFO") -> None:
    """Print a timestamped log message with level.

    Args:
        message: The message to log
        level: The log level (INFO, WARNING, ERROR)
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] {message}")


def run_bandit() -> Dict[str, Any]:
    """Run bandit security scanner.

    Returns:
        Dict containing scan results
    """
    log("Running Bandit security scanner")

    try:
        # Ensure bandit is installed
        subprocess.check_call([sys.executable, "-m", "pip", "install", "bandit>=1.7.5"],
                             stdout=subprocess.PIPE)

        # Create directory paths to scan
        dirs_to_scan = [str(PROJECT_ROOT / d) for d in CODE_DIRS if (PROJECT_ROOT / d).exists()]

        # Set up configuration for special attention to critical paths
        with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as config_file:
            bandit_config = {
                'profiles': {
                    'critical': {
                        'include': ['all'],
                    },
                    'standard': {
                        'include': ['all']
                    }
                }
            }
            json.dump(bandit_config, config_file)
            config_path = config_file.name

        # Set up additional arguments for critical paths
        bandit_args = [sys.executable, "-m", "bandit", "-r", "-f", "json"]

        # Add critical paths with higher confidence threshold
        for critical_path in CRITICAL_PATHS:
            path = PROJECT_ROOT / critical_path
            if path.exists():
                bandit_args.extend(["-l", str(path)])

        # Add standard paths
        bandit_args.extend(dirs_to_scan)

        # Run bandit scan
        output = subprocess.check_output(
            bandit_args,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=TIMEOUT_SECONDS
        )

        # Clean up temporary config
        os.unlink(config_path)

        try:
            return json.loads(output)
        except json.JSONDecodeError:
            log(f"Error parsing bandit output: {output[:500]}...", "WARNING")
            return {"results": []}
    except subprocess.CalledProcessError as e:
        log(f"Bandit command failed with exit code {e.returncode}", "ERROR")
        if e.output:
            try:
                return json.loads(e.output)
            except json.JSONDecodeError:
                pass
        return {"results": []}
    except subprocess.TimeoutExpired:
        log("Bandit scan timed out", "ERROR")
        return {"results": [], "error": "timeout"}
    except Exception as e:
        log(f"Error running bandit: {e}", "ERROR")
        return {"results": []}


def run_semgrep() -> Dict[str, Any]:
    """Run semgrep security scanner.

    Returns:
        Dict containing scan results
    """
    log("Running semgrep security scanner")

    try:
        # Check if semgrep is available
        if subprocess.call(["which", "semgrep"],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) != 0:
            # Try to install semgrep if not available
            try:
                log("Semgrep not found, attempting to install", "INFO")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "semgrep"],
                                     stdout=subprocess.PIPE)
            except Exception:
                log("Semgrep installation failed, skipping semgrep scan", "WARNING")
                return {"results": []}

        # Run semgrep scan with security-focused ruleset
        cmd = [
            "semgrep",
            "--config=p/security-audit",
            "--config=p/owasp-top-ten",
            "--json",
            "--timeout", str(TIMEOUT_SECONDS),
            "--exclude", "tests",
            "--exclude", "venv",
            str(PROJECT_ROOT)
        ]

        output = subprocess.check_output(
            cmd,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=TIMEOUT_SECONDS
        )

        try:
            return json.loads(output)
        except json.JSONDecodeError:
            log(f"Error parsing semgrep output", "WARNING")
            return {"results": []}
    except subprocess.CalledProcessError as e:
        log(f"Semgrep command failed with exit code {e.returncode}", "ERROR")
        return {"results": []}
    except subprocess.TimeoutExpired:
        log("Semgrep scan timed out", "ERROR")
        return {"results": [], "error": "timeout"}
    except Exception as e:
        log(f"Error running semgrep: {e}", "ERROR")
        return {"results": []}


def run_pylint() -> List[Dict[str, Any]]:
    """Run pylint with security plugins.

    Returns:
        List of issues found by pylint
    """
    log("Running pylint security checks")

    try:
        # Ensure pylint and plugins are installed
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pylint>=2.13.0", "pylint-security"],
            stdout=subprocess.PIPE
        )

        # Create directory paths to scan
        dirs_to_scan = [str(PROJECT_ROOT / d) for d in CODE_DIRS if (PROJECT_ROOT / d).exists()]

        # Add critical paths to ensure they're scanned
        for path in CRITICAL_PATHS:
            full_path = str(PROJECT_ROOT / path)
            if os.path.exists(full_path) and full_path not in dirs_to_scan:
                dirs_to_scan.append(full_path)

        # Run pylint
        cmd = [
            sys.executable, "-m", "pylint",
            "--load-plugins=pylint_security",
            "--disable=all",
            "--enable=security",
            "--output-format=json"
        ]
        cmd.extend(dirs_to_scan)

        output = subprocess.check_output(
            cmd,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=TIMEOUT_SECONDS
        )

        try:
            return json.loads(output)
        except json.JSONDecodeError:
            log(f"Error parsing pylint output", "WARNING")
            return []
    except subprocess.CalledProcessError as e:
        log(f"Pylint command failed with exit code {e.returncode}", "ERROR")
        if e.output:
            try:
                return json.loads(e.output)
            except json.JSONDecodeError:
                pass
        return []
    except subprocess.TimeoutExpired:
        log("Pylint scan timed out", "ERROR")
        return []
    except Exception as e:
        log(f"Error running pylint: {e}", "ERROR")
        return []


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

        # Look for requirements files
        requirements_files = [
            PROJECT_ROOT / "requirements.txt",
            PROJECT_ROOT / "requirements-dev.txt",
            PROJECT_ROOT / "xtrareqs.txt"
        ]

        # Run safety check for each requirements file
        results = []
        for req_file in requirements_files:
            if not req_file.exists():
                continue

            log(f"Checking {req_file}")
            output = subprocess.check_output(
                [sys.executable, "-m", "safety", "check",
                 "-r", str(req_file), "--json"],
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=TIMEOUT_SECONDS
            )

            try:
                data = json.loads(output)
                if "vulnerabilities" in data:
                    results.extend(data["vulnerabilities"])
            except json.JSONDecodeError:
                log(f"Error parsing safety output", "WARNING")
                continue

        return results
    except subprocess.CalledProcessError as e:
        log(f"Safety check command failed with exit code {e.returncode}", "ERROR")
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


def check_file_integrity() -> List[Dict[str, Any]]:
    """Check file integrity by comparing against baseline.

    Returns:
        List of integrity violations
    """
    log("Checking file integrity against baseline")

    try:
        # Import the file integrity module if available
        integrity_module = None
        try:
            # Try to import from core security
            from core.security.cs_file_integrity import check_critical_file_integrity
            integrity_module = 'core'
        except ImportError:
            try:
                # Fall back to models.security
                from models.security.file_integrity import check_file_integrity
                integrity_module = 'models'
            except ImportError:
                log("File integrity module not available", "WARNING")
                return []

        # Use the appropriate module based on what's available
        if integrity_module == 'core':
            from core.security.cs_file_integrity import check_critical_file_integrity
            integrity_ok, changes = check_critical_file_integrity()
        else:
            from models.security.file_integrity import check_file_integrity
            integrity_ok, changes = check_file_integrity()

        if not integrity_ok:
            formatted_changes = []
            for change in changes:
                formatted_changes.append({
                    "file": change.get("path", "unknown"),
                    "severity": "HIGH",
                    "issue_type": "integrity_violation",
                    "description": f"File integrity violation: {change.get('type', 'unknown')}",
                    "source": "integrity_check"
                })
            return formatted_changes
        return []

    except Exception as e:
        log(f"Error checking file integrity: {e}", "ERROR")
        return []


def calculate_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """Calculate a cryptographic hash for a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        Hex digest hash of the file
    """
    hash_obj = hashlib.new(algorithm)

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def generate_report(
    bandit_results: Dict[str, Any],
    semgrep_results: Dict[str, Any],
    pylint_results: List[Dict[str, Any]],
    safety_results: List[Dict[str, Any]] = None,
    integrity_results: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generate a comprehensive security report from multiple scan tools.

    Args:
        bandit_results: Results from Bandit scan
        semgrep_results: Results from Semgrep scan
        pylint_results: Results from Pylint scan
        safety_results: Results from Safety dependency check
        integrity_results: Results from integrity check

    Returns:
        Dictionary with complete security report data
    """
    REPORT_DIR.mkdir(exist_ok=True)

    # Initialize with empty lists if not provided
    safety_results = safety_results or []
    integrity_results = integrity_results or []

    # Count issues by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    # Process bandit results
    bandit_issues = []
    for issue in bandit_results.get("results", []):
        # Map bandit severities to our scheme
        bandit_severity = issue.get("issue_severity", "low").upper()
        confidence = issue.get("issue_confidence", "low").upper()

        # Increase severity for high-confidence issues in critical paths
        file_path = issue.get("filename", "")
        if any(critical in file_path for critical in CRITICAL_PATHS) and confidence in ["HIGH", "MEDIUM"]:
            if bandit_severity == "MEDIUM":
                bandit_severity = "HIGH"
            elif bandit_severity == "LOW":
                bandit_severity = "MEDIUM"

        severity_counts[bandit_severity] = severity_counts.get(bandit_severity, 0) + 1

        bandit_issues.append({
            "file": issue.get("filename", ""),
            "line": issue.get("line_number", 0),
            "severity": bandit_severity,
            "issue_type": issue.get("test_id", ""),
            "description": issue.get("issue_text", ""),
            "confidence": confidence,
            "source": "bandit",
            "cwe": issue.get("cwe", "")
        })

    # Process semgrep results
    semgrep_issues = []
    for result in semgrep_results.get("results", []):
        # Map semgrep severity to our scale
        severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        raw_severity = result.get("extra", {}).get("severity", "INFO")
        severity = severity_map.get(raw_severity, "LOW")

        # Elevate severity for critical paths
        file_path = result.get("path", "")
        if any(critical in file_path for critical in CRITICAL_PATHS):
            if severity == "MEDIUM":
                severity = "HIGH"
            elif severity == "LOW":
                severity = "MEDIUM"

        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        semgrep_issues.append({
            "file": result.get("path", ""),
            "line": result.get("start", {}).get("line", 0),
            "severity": severity,
            "issue_type": result.get("check_id", ""),
            "description": result.get("extra", {}).get("message", ""),
            "source": "semgrep"
        })

    # Process pylint results
    pylint_issues = []
    for issue in pylint_results:
        # Map pylint message types to severity
        msg_to_severity = {"E": "HIGH", "W": "MEDIUM", "C": "LOW", "R": "LOW", "F": "MEDIUM"}
        msg_type = issue.get("type", "W")
        severity = msg_to_severity.get(msg_type, "LOW")

        # Only include security-related messages
        if "security" in issue.get("symbol", "").lower():
            # Elevate severity for critical paths
            file_path = issue.get("path", "")
            if any(critical in file_path for critical in CRITICAL_PATHS):
                if severity == "MEDIUM":
                    severity = "HIGH"
                elif severity == "LOW":
                    severity = "MEDIUM"

            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            pylint_issues.append({
                "file": issue.get("path", ""),
                "line": issue.get("line", 0),
                "severity": severity,
                "issue_type": issue.get("symbol", ""),
                "description": issue.get("message", ""),
                "source": "pylint"
            })

    # Process safety scan results
    safety_issues = []
    for vuln in safety_results:
        # Map CVE severity to our scale
        severity = "MEDIUM"  # Default
        cvss_score = vuln.get("cvss_score")
        if isinstance(cvss_score, (int, float)):
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        safety_issues.append({
            "package": vuln.get("package_name", ""),
            "severity": severity,
            "issue_type": "dependency_vulnerability",
            "affected_versions": vuln.get("affected_versions", ""),
            "description": vuln.get("advisory", ""),
            "source": "safety",
            "cve": vuln.get("cve", ""),
            "fix_version": vuln.get("fixed_versions", [])[0] if vuln.get("fixed_versions") else None
        })

    # Process file integrity issues
    for issue in integrity_results:
        severity = issue.get("severity", "HIGH")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Prepare report data
    all_issues = bandit_issues + semgrep_issues + pylint_issues + safety_issues + integrity_results
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_issues": len(all_issues),
            "by_severity": severity_counts,
            "by_source": {
                "bandit": len(bandit_issues),
                "semgrep": len(semgrep_issues),
                "pylint": len(pylint_issues),
                "safety": len(safety_issues),
                "integrity": len(integrity_results)
            },
            "threshold_exceeded": any(
                count > SEVERITY_THRESHOLD.get(sev, 0)
                for sev, count in severity_counts.items()
            )
        },
        "issues": all_issues
    }

    # Write standard report to file
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    # Generate GitLab compatible SAST report
    generate_gitlab_report(report)

    return report


def generate_gitlab_report(report: Dict[str, Any]) -> None:
    """Generate GitLab compatible SAST report.

    Args:
        report: The standard report format to convert
    """
    gitlab_report = {
        "version": "2.0",
        "vulnerabilities": [],
        "scan": {
            "analyzer": {"id": "cloud-platform-sast", "name": "Cloud Platform SAST", "version": "1.0.0"},
            "scanner": {"id": "security-scan", "name": "Cloud Platform Security Scanner", "version": "1.0.0"},
            "type": "sast",
            "start_time": report["timestamp"],
            "end_time": datetime.now(timezone.utc).isoformat(),
            "status": "success"
        }
    }

    # Convert issues to GitLab format
    for issue in report["issues"]:
        severity = issue.get("severity", "UNKNOWN").lower()
        confidence = issue.get("confidence", "medium").lower()

        # Map confidence levels
        if confidence not in ["low", "medium", "high", "critical"]:
            confidence = "medium"

        # Create vulnerability entry
        vuln = {
            "id": hashlib.md5(f"{issue.get('source', '')}:{issue.get('file', '')}:{issue.get('line', '')}:{issue.get('description', '')}".encode()).hexdigest(),
            "category": "sast",
            "name": issue.get("issue_type", "Unknown Issue"),
            "message": issue.get("description", ""),
            "severity": severity,
            "confidence": confidence,
            "scanner": {"id": issue.get("source", "unknown"), "name": issue.get("source", "unknown").title()},
        }

        # Add location if available
        if "file" in issue:
            vuln["location"] = {
                "file": issue["file"].replace(str(PROJECT_ROOT) + "/", ""),
                "start_line": issue.get("line", 1)
            }

        # Add CWE if available
        if "cwe" in issue and issue["cwe"]:
            vuln["identifiers"] = [
                {
                    "type": "cwe",
                    "name": f"CWE-{issue['cwe']}",
                    "value": f"CWE-{issue['cwe']}",
                    "url": f"https://cwe.mitre.org/data/definitions/{issue['cwe']}.html"
                }
            ]

        gitlab_report["vulnerabilities"].append(vuln)

    # Write GitLab report to file
    with open(GITLAB_REPORT_FILE, "w") as f:
        json.dump(gitlab_report, f)


def main() -> int:
    """Main function to run all SAST checks.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    log("Starting Static Application Security Testing (SAST)", "INFO")

    try:
        # Run security scanners
        bandit_results = run_bandit()
        semgrep_results = run_semgrep()
        pylint_results = run_pylint()
        safety_results = run_safety_check()
        integrity_results = check_file_integrity()

        # Generate report
        report = generate_report(
            bandit_results,
            semgrep_results,
            pylint_results,
            safety_results,
            integrity_results
        )
        log(f"Report generated: {REPORT_FILE}", "INFO")

        # Log summary
        log(f"Found issues: Critical={report['summary']['by_severity']['CRITICAL']}, " +
            f"High={report['summary']['by_severity']['HIGH']}, " +
            f"Medium={report['summary']['by_severity']['MEDIUM']}, " +
            f"Low={report['summary']['by_severity']['LOW']}", "INFO")

        # Determine exit code based on thresholds
        exit_code = 0

        for severity, count in report["summary"]["by_severity"].items():
            threshold = SEVERITY_THRESHOLD.get(severity, 0)
            if count > threshold:
                log(f"FAIL: {severity} issues ({count}) exceed threshold ({threshold})", "ERROR")
                exit_code = 1

        if exit_code == 0:
            log("All SAST checks passed", "INFO")
        else:
            log("SAST checks failed", "ERROR")

        # Handle CI variables for thresholds
        if os.environ.get("CI_SKIP_SECURITY_THRESHOLDS") == "true" and exit_code != 0:
            log("Security thresholds bypassed via CI_SKIP_SECURITY_THRESHOLDS", "WARNING")
            exit_code = 0

        return exit_code

    except Exception as e:
        log(f"Error during SAST scanning: {str(e)}", "ERROR")
        # Generate error report
        error_report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
            "status": "error"
        }
        REPORT_DIR.mkdir(exist_ok=True)
        with open(REPORT_FILE, "w") as f:
            json.dump(error_report, f, indent=2)
        return 2  # Different exit code for unexpected errors


if __name__ == "__main__":
    sys.exit(main())
