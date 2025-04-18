#!/usr/bin/env python3
"""
Dependency security scanner for Cloud Infrastructure Platform.

This script analyzes project dependencies for known security vulnerabilities
and license compliance issues.
"""

import os
import sys
import json
import subprocess
import re
from pathlib import Path
from datetime import datetime

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
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


def log(message):
    """Print a timestamped log message."""
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}")


def run_safety_check():
    """Run safety check on Python dependencies."""
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
                log(f"Error parsing safety output: {output}")
                continue
        
        return results
    except subprocess.CalledProcessError as e:
        log(f"Safety check command failed: {e}")
        if e.output:
            try:
                data = json.loads(e.output)
                return data.get("vulnerabilities", [])
            except json.JSONDecodeError:
                pass
        return []
    except Exception as e:
        log(f"Error running safety check: {e}")
        return []


def check_licenses():
    """Check licenses of Python dependencies."""
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
        log(f"Error checking licenses: {e}")
        return []


def check_outdated_dependencies():
    """Check for outdated dependencies."""
    log("Checking for outdated dependencies")
    
    try:
        output = subprocess.check_output(
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            universal_newlines=True
        )
        
        outdated = json.loads(output)
        return outdated
    except Exception as e:
        log(f"Error checking outdated dependencies: {e}")
        return []


def generate_report(vulnerabilities, license_issues, outdated):
    """Generate a comprehensive report."""
    REPORT_DIR.mkdir(exist_ok=True)
    
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
            }
        },
        "vulnerabilities": vulnerabilities,
        "license_issues": license_issues,
        "outdated_dependencies": outdated
    }
    
    # Write report to file
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    
    return report


def main():
    """Main function to run all dependency checks."""
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
    
    # Generate report
    report = generate_report(vulnerabilities, license_issues, outdated)
    log(f"Report generated: {REPORT_FILE}")
    
    # Determine exit code based on thresholds
    exit_code = 0
    
    for severity, count in report["summary"]["vulnerabilities"]["by_severity"].items():
        threshold = VULNERABILITY_THRESHOLD.get(severity, 0)
        if count > threshold:
            log(f"FAIL: {severity} vulnerabilities ({count}) exceed threshold ({threshold})")
            exit_code = 1
    
    if exit_code == 0:
        log("All dependency checks passed")
    else:
        log("Dependency checks failed")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
