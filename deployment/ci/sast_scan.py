#!/usr/bin/env python3
"""
Static Application Security Testing (SAST) scanner for Cloud Infrastructure Platform.

This script performs static code analysis to identify potential security issues
in the codebase.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
REPORT_DIR = PROJECT_ROOT / "security-reports"
REPORT_FILE = REPORT_DIR / f"sast-scan-{datetime.now().strftime('%Y%m%d')}.json"
CODE_DIRS = ["api", "blueprints", "models", "services", "core", "extensions"]
SEVERITY_THRESHOLD = {
    "HIGH": 0,
    "MEDIUM": 5,
    "LOW": 10
}


def log(message):
    """Print a timestamped log message."""
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}")


def run_bandit():
    """Run bandit security scanner."""
    log("Running Bandit security scanner")
    
    try:
        # Ensure bandit is installed
        subprocess.check_call([sys.executable, "-m", "pip", "install", "bandit"], 
                             stdout=subprocess.PIPE)
        
        # Create directory paths to scan
        dirs_to_scan = [str(PROJECT_ROOT / d) for d in CODE_DIRS if (PROJECT_ROOT / d).exists()]
        
        # Run bandit scan
        output = subprocess.check_output(
            [sys.executable, "-m", "bandit", "-r"] + dirs_to_scan + ["-f", "json"],
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            log(f"Error parsing bandit output: {output}")
            return {"results": []}
    except subprocess.CalledProcessError as e:
        log(f"Bandit command failed with exit code {e.returncode}")
        if e.output:
            try:
                return json.loads(e.output)
            except json.JSONDecodeError:
                pass
        return {"results": []}
    except Exception as e:
        log(f"Error running bandit: {e}")
        return {"results": []}


def run_semgrep():
    """Run semgrep security scanner."""
    log("Running semgrep security scanner")
    
    try:
        # Check if semgrep is available
        if subprocess.call(["which", "semgrep"], 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE) != 0:
            log("Semgrep not installed, skipping")
            return {"results": []}
        
        # Run semgrep scan
        output = subprocess.check_output(
            ["semgrep", "--config=p/security-audit", "--json", str(PROJECT_ROOT)],
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            log(f"Error parsing semgrep output")
            return {"results": []}
    except subprocess.CalledProcessError as e:
        log(f"Semgrep command failed with exit code {e.returncode}")
        return {"results": []}
    except Exception as e:
        log(f"Error running semgrep: {e}")
        return {"results": []}


def run_pylint():
    """Run pylint with security plugins."""
    log("Running pylint security checks")
    
    try:
        # Ensure pylint and plugins are installed
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pylint", "pylint-security"],
            stdout=subprocess.PIPE
        )
        
        # Create directory paths to scan
        dirs_to_scan = [str(PROJECT_ROOT / d) for d in CODE_DIRS if (PROJECT_ROOT / d).exists()]
        
        # Run pylint
        output = subprocess.check_output(
            [sys.executable, "-m", "pylint"] + dirs_to_scan + 
            ["--load-plugins=pylint_security", "--disable=all", "--enable=security", "--output-format=json"],
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            log(f"Error parsing pylint output")
            return []
    except subprocess.CalledProcessError as e:
        log(f"Pylint command failed with exit code {e.returncode}")
        if e.output:
            try:
                return json.loads(e.output)
            except json.JSONDecodeError:
                pass
        return []
    except Exception as e:
        log(f"Error running pylint: {e}")
        return []


def generate_report(bandit_results, semgrep_results, pylint_results):
    """Generate a comprehensive report."""
    REPORT_DIR.mkdir(exist_ok=True)
    
    # Count issues by severity
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    # Process bandit results
    bandit_issues = []
    for issue in bandit_results.get("results", []):
        severity = issue.get("issue_severity", "LOW").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        bandit_issues.append({
            "file": issue.get("filename", ""),
            "line": issue.get("line_number", 0),
            "severity": severity,
            "issue_type": issue.get("issue_text", ""),
            "description": issue.get("issue_text", ""),
            "confidence": issue.get("issue_confidence", ""),
            "source": "bandit"
        })
    
    # Process semgrep results
    semgrep_issues = []
    for result in semgrep_results.get("results", []):
        # Map semgrep severity to our scale
        severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        severity = severity_map.get(result.get("extra", {}).get("severity", "INFO"), "LOW")
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
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            pylint_issues.append({
                "file": issue.get("path", ""),
                "line": issue.get("line", 0),
                "severity": severity,
                "issue_type": issue.get("symbol", ""),
                "description": issue.get("message", ""),
                "source": "pylint"
            })
    
    # Prepare report data
    all_issues = bandit_issues + semgrep_issues + pylint_issues
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_issues": len(all_issues),
            "by_severity": severity_counts,
            "by_source": {
                "bandit": len(bandit_issues),
                "semgrep": len(semgrep_issues),
                "pylint": len(pylint_issues)
            },
            "threshold_exceeded": any(
                count > SEVERITY_THRESHOLD.get(sev, 0) 
                for sev, count in severity_counts.items()
            )
        },
        "issues": all_issues
    }
    
    # Write report to file
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    
    return report


def main():
    """Main function to run all SAST checks."""
    log("Starting Static Application Security Testing (SAST)")
    
    # Run security scanners
    bandit_results = run_bandit()
    semgrep_results = run_semgrep()
    pylint_results = run_pylint()
    
    # Generate report
    report = generate_report(bandit_results, semgrep_results, pylint_results)
    log(f"Report generated: {REPORT_FILE}")
    
    # Log summary
    log(f"Found issues: High={report['summary']['by_severity']['HIGH']}, " +
        f"Medium={report['summary']['by_severity']['MEDIUM']}, " +
        f"Low={report['summary']['by_severity']['LOW']}")
    
    # Determine exit code based on thresholds
    exit_code = 0
    
    for severity, count in report["summary"]["by_severity"].items():
        threshold = SEVERITY_THRESHOLD.get(severity, 0)
        if count > threshold:
            log(f"FAIL: {severity} issues ({count}) exceed threshold ({threshold})")
            exit_code = 1
    
    if exit_code == 0:
        log("All SAST checks passed")
    else:
        log("SAST checks failed")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
