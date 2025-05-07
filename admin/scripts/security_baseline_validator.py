#!/usr/bin/env python3
"""
Security Baseline Validator for Cloud Infrastructure Platform.

This script validates system configurations against predefined security baselines
to ensure compliance with security standards. It checks various configuration
settings, permissions, and system states based on JSON baseline files.

Usage:
    python security_baseline_validator.py --target <hostname_or_ip> \
                                          --baseline <baseline_file.json> \
                                          [--output <report_file>] \
                                          [--format <json|html|text>] \
                                          [--verbose]

Requires:
    - Access to target systems (SSH recommended for remote targets).
    - Baseline JSON files defining security controls and validation methods.
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_BASELINE_DIR = PROJECT_ROOT / "admin" / "security" / "assessment_tools" / "config_files" / "security_baselines"
LOG_DIR = Path("/var/log/cloud-platform/admin")
LOG_FILE = LOG_DIR / "security_baseline_validator.log"
DEFAULT_REPORT_DIR = LOG_DIR / "reports"

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout) # Also print to console
    ]
)
logger = logging.getLogger(__name__)


__all__ = [
    # Core functions


    # Helper functions


    # Classes


    # Constants


    # Main entry point
    "main"
]


class Severity(Enum):
    """Severity levels for validation results."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASSED = "passed"

class BaselineValidator:
    """Validates system configuration against a security baseline."""

    def __init__(self, target: str, baseline_paths: List[str], ssh_user: Optional[str] = None):
        """
        Initialize the validator.

        Args:
            target: The hostname or IP address of the target system. 'localhost' for local checks.
            baseline_paths: List of paths to the baseline JSON files.
            ssh_user: Optional SSH user for remote connections.
        """
        self.target = target
        self.baseline_paths = baseline_paths
        self.ssh_user = ssh_user
        self.results: List[Dict[str, Any]] = []
        self.baselines: Dict[str, Any] = {}
        self.is_remote = target.lower() != 'localhost'

        if self.is_remote and not self.ssh_user:
            # Attempt to use current user if not specified
            try:
                import getpass
                self.ssh_user = getpass.getuser()
                logger.info(f"Using current user '{self.ssh_user}' for SSH connection to {self.target}")
            except ImportError:
                logger.error("Cannot determine current user for SSH. Please specify --ssh-user.")
                sys.exit(1)
            except Exception as e:
                 logger.error(f"Error getting current user: {e}. Please specify --ssh-user.")
                 sys.exit(1)


    def load_baselines(self) -> bool:
        """Load and merge baseline files."""
        merged_baseline: Dict[str, Any] = {"metadata": {}, "controls": {}}
        loaded_files = []

        for path_str in self.baseline_paths:
            path = Path(path_str)
            if not path.is_file():
                logger.error(f"Baseline file not found: {path}")
                return False
            try:
                with open(path, 'r') as f:
                    baseline_data = json.load(f)
                logger.info(f"Successfully loaded baseline file: {path.name}")
                loaded_files.append(path.name)

                # Merge metadata (simple update, last file wins for conflicts)
                if "metadata" in baseline_data:
                    merged_baseline["metadata"].update(baseline_data["metadata"])

                # Merge controls (deep merge by category and control ID)
                if "controls" in baseline_data:
                    for category, controls in baseline_data["controls"].items():
                        if category not in merged_baseline["controls"]:
                            merged_baseline["controls"][category] = {}
                        for control_id, control_data in controls.items():
                            if control_id in merged_baseline["controls"][category]:
                                logger.warning(f"Duplicate control ID '{control_id}' in category '{category}' found in {path.name}. Overwriting.")
                            merged_baseline["controls"][category][control_id] = control_data

            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from baseline file {path}: {e}")
                return False
            except IOError as e:
                logger.error(f"Error reading baseline file {path}: {e}")
                return False

        # Store the final merged baseline
        self.baselines = merged_baseline
        if "metadata" in self.baselines:
             self.baselines["metadata"]["loaded_files"] = loaded_files # Track which files contributed

        if not self.baselines.get("controls"):
             logger.error("No controls found in the loaded baseline files.")
             return False

        logger.info(f"Baselines loaded successfully from: {', '.join(loaded_files)}")
        return True

    def _execute_command(self, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """
        Execute a command locally or remotely via SSH.

        Args:
            command: The command string to execute.
            timeout: Command execution timeout in seconds.

        Returns:
            Tuple containing (return_code, stdout, stderr).
        """
        try:
            if self.is_remote:
                ssh_command = ["ssh", f"{self.ssh_user}@{self.target}", command]
                logger.debug(f"Executing remote command: {' '.join(ssh_command)}")
                process = subprocess.run(
                    ssh_command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False  # Don't raise exception on non-zero exit code
                )
            else:
                logger.debug(f"Executing local command: {command}")
                process = subprocess.run(
                    command,
                    shell=True, # Use shell for local commands for simplicity with pipes etc.
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
             logger.error(f"SSH command not found. Ensure SSH client is installed and in PATH.")
             # Return a distinct error code or raise an exception
             return -2, "", "SSH command not found"
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return -1, "", str(e)

    def _parse_output(self, output: str, control_data: Dict[str, Any]) -> bool:
        """
        Parse command output based on expected value or pattern in the control data.

        Args:
            output: The stdout from the command execution.
            control_data: The dictionary containing control details from the baseline.

        Returns:
            True if the output matches the expected state, False otherwise.
        """
        expected_value = control_data.get("expected_value")
        expected_pattern = control_data.get("expected_pattern")
        match_type = control_data.get("match_type", "exact") # exact, contains, regex, not_contains

        if expected_value is not None:
            if match_type == "exact":
                return output == str(expected_value)
            elif match_type == "contains":
                return str(expected_value) in output
            elif match_type == "not_contains":
                return str(expected_value) not in output
            else:
                 logger.warning(f"Unsupported match_type '{match_type}' for expected_value. Defaulting to 'exact'.")
                 return output == str(expected_value)
        elif expected_pattern is not None:
            try:
                # Assume match_type 'regex' if pattern is used
                if re.search(expected_pattern, output):
                    return True
                else:
                    return False
            except re.error as e:
                logger.error(f"Invalid regex pattern '{expected_pattern}': {e}")
                return False # Treat invalid regex as a validation failure
        else:
            # If neither value nor pattern is defined, assume success if command runs (rc=0)
            # This logic is handled in validate_control based on return code
            logger.debug("No expected_value or expected_pattern defined. Validation relies on command exit code.")
            return True # Placeholder, actual check happens in validate_control

    def add_result(self, category: str, control_id: str, control_data: Dict[str, Any], status: Severity, details: str, actual_output: Optional[str] = None):
        """Add a validation result."""
        result = {
            "category": category,
            "control_id": control_id,
            "description": control_data.get("description", "N/A"),
            "severity": control_data.get("severity", Severity.INFO.value),
            "status": status.value,
            "details": details,
            "rationale": control_data.get("rationale", ""),
            "remediation": control_data.get("remediation", ""),
            "actual_output": actual_output if actual_output is not None else ""
        }
        self.results.append(result)

    def validate_control(self, category: str, control_id: str, control_data: Dict[str, Any]):
        """
        Validate a single security control.

        Args:
            category: The category of the control.
            control_id: The unique identifier for the control.
            control_data: Dictionary containing control details (validation command, expected value/pattern, etc.).
        """
        validation_command = control_data.get("validation")
        if not validation_command:
            logger.debug(f"Skipping control '{control_id}' in category '{category}': No validation command defined.")
            # Optionally add an INFO result indicating skipped control
            # self.add_result(category, control_id, control_data, Severity.INFO, "Skipped: No validation command.")
            return

        logger.info(f"Validating [{category}/{control_id}]: {control_data.get('description', '')}")

        rc, stdout, stderr = self._execute_command(validation_command)

        status = Severity.PASSED
        details = "Control validation passed."
        actual_output = stdout # Default to stdout

        if rc != 0:
            # Command failed to execute or returned non-zero (often indicates failure)
            status = Severity[control_data.get("severity", Severity.MEDIUM.value).upper()] # Use control's severity for failure
            details = f"Validation command failed with exit code {rc}."
            if stderr:
                details += f" Stderr: {stderr}"
            actual_output = f"RC={rc}, STDOUT={stdout}, STDERR={stderr}" # Capture all output on error
            logger.warning(f"Validation failed for [{category}/{control_id}]: Command returned {rc}. Stderr: {stderr}")

        elif control_data.get("expected_value") is not None or control_data.get("expected_pattern") is not None:
            # Command succeeded, now check output if expectations are defined
            if not self._parse_output(stdout, control_data):
                status = Severity[control_data.get("severity", Severity.MEDIUM.value).upper()]
                details = "Validation command output did not match expected state."
                expected = control_data.get('expected_value') or control_data.get('expected_pattern')
                match_type = control_data.get('match_type', 'exact' if control_data.get('expected_value') else 'regex')
                details += f" Expected ({match_type}): '{expected}'. Actual: '{stdout[:200]}{'...' if len(stdout)>200 else ''}'"
                actual_output = stdout
                logger.warning(f"Validation failed for [{category}/{control_id}]: Output mismatch. Expected ({match_type}): '{expected}', Got: '{stdout[:100]}...'")
            else:
                 logger.info(f"Validation passed for [{category}/{control_id}]")
        else:
             # Command succeeded (rc=0) and no specific output check needed
             logger.info(f"Validation passed for [{category}/{control_id}] (based on exit code 0)")


        self.add_result(category, control_id, control_data, status, details, actual_output)


    def run_validation(self):
        """Run validation for all controls in the loaded baselines."""
        if not self.baselines or not self.baselines.get("controls"):
            logger.error("Cannot run validation: Baselines not loaded or no controls found.")
            return

        logger.info(f"Starting baseline validation for target: {self.target}")
        total_controls = sum(len(controls) for controls in self.baselines["controls"].values())
        logger.info(f"Total controls to validate: {total_controls}")
        validated_count = 0

        for category, controls in self.baselines["controls"].items():
            logger.info(f"--- Validating Category: {category} ---")
            for control_id, control_data in controls.items():
                 validated_count += 1
                 logger.debug(f"Progress: {validated_count}/{total_controls}")
                 self.validate_control(category, control_id, control_data)

        logger.info(f"--- Validation Complete for target: {self.target} ---")


    def generate_report(self, output_format: str = "text", output_file: Optional[Path] = None):
        """
        Generate a report of the validation results.

        Args:
            output_format: The desired format ('text', 'json', 'html').
            output_file: Optional path to save the report file.
        """
        report_content = ""
        summary = self._generate_summary()

        if output_format == "json":
            report_data = {
                "metadata": self.baselines.get("metadata", {}),
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "summary": summary,
                "results": self.results
            }
            report_content = json.dumps(report_data, indent=2)
        elif output_format == "html":
            report_content = self._generate_html_report(summary)
        else: # Default to text
            report_content = self._generate_text_report(summary)

        if output_file:
            try:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write(report_content)
                logger.info(f"Report saved to: {output_file}")
            except IOError as e:
                logger.error(f"Failed to write report to {output_file}: {e}")
        else:
            # Print text report to stdout if no file specified
            if output_format == "text":
                print("\n" + report_content)


    def _generate_summary(self) -> Dict[str, int]:
        """Generate a summary count of results by status."""
        summary = {status.value: 0 for status in Severity}
        for result in self.results:
            status_val = result.get("status", Severity.INFO.value)
            if status_val in summary:
                summary[status_val] += 1
            else:
                 # Handle potential unexpected status values gracefully
                 summary[status_val] = 1
        return summary

    def _generate_text_report(self, summary: Dict[str, int]) -> str:
        """Generate a plain text report."""
        lines = []
        lines.append("=" * 60)
        lines.append(f"Security Baseline Validation Report")
        lines.append("=" * 60)
        lines.append(f"Target: {self.target}")
        lines.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        baselines_used = ", ".join(self.baselines.get("metadata", {}).get("loaded_files", ["N/A"]))
        lines.append(f"Baselines Used: {baselines_used}")
        lines.append("-" * 60)
        lines.append("Summary:")
        for status, count in summary.items():
            if count > 0:
                lines.append(f"  {status.upper()}: {count}")
        lines.append("-" * 60)
        lines.append("Detailed Results:")

        # Sort results by severity (critical first) then category/id
        severity_order = {s.value: i for i, s in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.PASSED])}
        sorted_results = sorted(self.results, key=lambda r: (severity_order.get(r.get('status'), 99), r.get('category'), r.get('control_id')))


        for result in sorted_results:
            lines.append(f"\n[{result['status'].upper()}] {result['category']}/{result['control_id']}")
            lines.append(f"  Description: {result['description']}")
            lines.append(f"  Severity: {result['severity']}")
            lines.append(f"  Details: {result['details']}")
            if result['status'] != Severity.PASSED.value and result.get('remediation'):
                lines.append(f"  Remediation: {result['remediation']}")
            if result.get('rationale'):
                 lines.append(f"  Rationale: {result['rationale']}")
            # Optionally include actual output for failures in text report
            # if result['status'] != Severity.PASSED.value and result.get('actual_output'):
            #     lines.append(f"  Actual Output: {result['actual_output']}")

        lines.append("\n" + "=" * 60)
        lines.append("End of Report")
        lines.append("=" * 60)
        return "\n".join(lines)

    def _generate_html_report(self, summary: Dict[str, int]) -> str:
        """Generate an HTML report."""
        # Basic HTML structure - can be enhanced significantly
        html_start = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Baseline Validation Report - {self.target}</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .summary-box {{ display: inline-block; border: 1px solid #ccc; padding: 10px 15px; margin: 5px; border-radius: 5px; }}
        .status-passed {{ background-color: #e6ffe6; border-left: 5px solid #00cc00; }}
        .status-critical {{ background-color: #ffeeee; border-left: 5px solid #ff0000; }}
        .status-high {{ background-color: #fff6ee; border-left: 5px solid #ff6600; }}
        .status-medium {{ background-color: #ffffee; border-left: 5px solid #ffcc00; }}
        .status-low {{ background-color: #f0fff0; border-left: 5px solid #99cc99; }}
        .status-info {{ background-color: #eeeeff; border-left: 5px solid #6666cc; }}
        .details {{ white-space: pre-wrap; font-family: monospace; background-color: #f8f8f8; padding: 5px; margin-top: 5px; border: 1px dashed #ccc; }}
    </style>
</head>
<body>
    <h1>Security Baseline Validation Report</h1>
    <p><strong>Target:</strong> {self.target}</p>
    <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Baselines Used:</strong> {", ".join(self.baselines.get("metadata", {}).get("loaded_files", ["N/A"]))}</p>

    <h2>Summary</h2>
    <div>
"""
        for status, count in summary.items():
            if count > 0:
                 html_start += f'        <div class="summary-box status-{status}">{status.upper()}: {count}</div>\n'
        html_start += """
    </div>

    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr>
                <th>Status</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Control ID</th>
                <th>Description</th>
                <th>Details</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
"""
        html_end = """
        </tbody>
    </table>
</body>
</html>
"""
        rows = []
        severity_order = {s.value: i for i, s in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.PASSED])}
        sorted_results = sorted(self.results, key=lambda r: (severity_order.get(r.get('status'), 99), r.get('category'), r.get('control_id')))

        for result in sorted_results:
            status_class = f"status-{result['status']}"
            details_html = result['details']
            # Optionally add actual output to details for failures
            if result['status'] != Severity.PASSED.value and result.get('actual_output'):
                 details_html += f"<div class='details'>Actual Output:\n{result['actual_output']}</div>"

            rows.append(f"""
            <tr class="{status_class}">
                <td>{result['status'].upper()}</td>
                <td>{result['severity']}</td>
                <td>{result['category']}</td>
                <td>{result['control_id']}</td>
                <td>{result['description']}</td>
                <td>{details_html}</td>
                <td>{result.get('remediation', '')}</td>
            </tr>""")

        return html_start + "\n".join(rows) + html_end


def main():
    """Main function to parse arguments and run the validator."""
    parser = argparse.ArgumentParser(description="Security Baseline Validator.")
    parser.add_argument(
        "--target",
        required=True,
        help="Target hostname or IP address ('localhost' for local machine)."
    )
    parser.add_argument(
        "--baseline",
        required=True,
        action='append', # Allow multiple baseline files
        help="Path to the security baseline JSON file(s). Can be specified multiple times."
    )
    parser.add_argument(
        "--ssh-user",
        help="SSH username for connecting to remote targets (defaults to current user)."
    )
    parser.add_argument(
        "--output",
        help="Path to save the validation report file."
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output report format (default: text)."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)."
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        # Update handler levels if necessary
        for handler in logging.getLogger().handlers:
             handler.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    # Resolve baseline paths relative to default dir if not absolute
    resolved_baseline_paths = []
    for b_path in args.baseline:
        path = Path(b_path)
        if not path.is_absolute():
            resolved_path = DEFAULT_BASELINE_DIR / path
            if resolved_path.exists():
                 resolved_baseline_paths.append(str(resolved_path))
                 logger.debug(f"Resolved relative baseline path '{b_path}' to '{resolved_path}'")
            elif path.exists(): # Check if relative path exists from current dir
                 resolved_baseline_paths.append(str(path.resolve()))
                 logger.debug(f"Using baseline path relative to current directory: '{path.resolve()}'")
            else:
                 logger.error(f"Baseline file '{b_path}' not found in default directory or current path.")
                 sys.exit(1)
        elif path.exists():
            resolved_baseline_paths.append(str(path))
        else:
             logger.error(f"Absolute baseline file path not found: '{path}'")
             sys.exit(1)


    validator = BaselineValidator(args.target, resolved_baseline_paths, args.ssh_user)

    if not validator.load_baselines():
        sys.exit(1)

    validator.run_validation()

    output_file_path = None
    if args.output:
        output_file_path = Path(args.output)
        if output_file_path.is_dir():
             # If user provided a directory, create a default filename
             timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
             filename = f"baseline-report-{args.target}-{timestamp}.{args.format}"
             output_file_path = output_file_path / filename
             logger.info(f"Output path is a directory, saving report to: {output_file_path}")
        # Ensure parent dir exists if a file path is given
        elif not output_file_path.parent.exists():
             output_file_path.parent.mkdir(parents=True, exist_ok=True)

    elif args.format != "text":
         # Default report file if format is not text and no output specified
         timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
         filename = f"baseline-report-{args.target}-{timestamp}.{args.format}"
         output_file_path = DEFAULT_REPORT_DIR / filename
         logger.info(f"No output file specified, saving {args.format} report to default location: {output_file_path}")


    validator.generate_report(args.format, output_file_path)

    # Determine exit code based on findings
    critical_or_high = any(r['status'] in [Severity.CRITICAL.value, Severity.HIGH.value] for r in validator.results)
    if critical_or_high:
        logger.error("Validation finished with CRITICAL or HIGH severity findings.")
        sys.exit(2) # Exit code 2 for critical/high issues
    elif any(r['status'] == Severity.MEDIUM.value for r in validator.results):
         logger.warning("Validation finished with MEDIUM severity findings.")
         sys.exit(1) # Exit code 1 for medium issues
    else:
        logger.info("Validation finished successfully with no critical, high, or medium findings.")
        sys.exit(0) # Exit code 0 for success (only low/info/passed)

if __name__ == "__main__":
    main()
