#!/usr/bin/env python3
# filepath: scripts/security/audit/checkers/common/check_result.py
"""
Standardized result class for security checks.

This module provides classes for representing security check results in a consistent
manner, including severity classification, evidence attachment, compliance mapping,
and remediation guidance.
"""

import json
import logging
import datetime
from enum import IntEnum
from typing import Dict, List, Any, Optional, Set, Union, Iterable

# Configure logging
logger = logging.getLogger("security.audit.checker")

# Define constants
DEFAULT_RESULT_FORMAT = "json"
SEVERITY_COLOR_MAP = {
    "CRITICAL": "#cc0000",  # Red
    "HIGH": "#ff6600",      # Orange
    "MEDIUM": "#ffcc00",    # Yellow
    "LOW": "#ffff99",       # Light yellow
    "INFO": "#99ccff"       # Light blue
}


class Severity(IntEnum):
    """Enumeration of severity levels for security findings."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    def __str__(self) -> str:
        """Return the string representation of the severity level."""
        return self.name


def format_severity(severity: Union[Severity, str, int]) -> str:
    """
    Format severity into a standardized string representation.

    Args:
        severity: Severity level as Severity enum, string or integer

    Returns:
        Formatted severity string
    """
    if isinstance(severity, Severity):
        return severity.name
    elif isinstance(severity, int):
        try:
            return Severity(severity).name
        except ValueError:
            return f"UNKNOWN({severity})"
    elif isinstance(severity, str) and severity.upper() in [s.name for s in Severity]:
        return severity.upper()
    return str(severity)


def format_evidence(evidence: Any) -> str:
    """
    Format evidence into a readable string representation.

    Args:
        evidence: Evidence data in any format

    Returns:
        Formatted evidence string
    """
    if evidence is None:
        return "No evidence collected"

    if isinstance(evidence, dict):
        return "\n".join(f"- {k}: {v}" for k, v in evidence.items())
    elif isinstance(evidence, list):
        return "\n".join(f"- {item}" for item in evidence)
    else:
        return str(evidence)


class CheckResult:
    """
    Standard result class for security check findings.

    This class represents a security finding with severity, description,
    remediation steps, and optional additional information.
    """

    def __init__(
        self,
        severity: Union[Severity, str, int],
        title: str,
        description: str,
        remediation: str,
        evidence: Optional[Any] = None,
        compliance: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime.datetime] = None,
        check_id: Optional[str] = None,
    ):
        """
        Initialize a check result.

        Args:
            severity: Severity level of the finding
            title: Short title describing the finding
            description: Detailed description of the issue
            remediation: Action steps to resolve the issue
            evidence: Supporting evidence (optional)
            compliance: Related compliance requirements (optional)
            context: Additional context for the finding (optional)
            timestamp: Time the check was performed (optional)
            check_id: Unique identifier for the check (optional)
        """
        # Convert severity to Enum if provided as string or integer
        if isinstance(severity, str):
            try:
                self.severity = Severity[severity.upper()]
            except KeyError:
                logger.warning(f"Unknown severity level: {severity}, using MEDIUM")
                self.severity = Severity.MEDIUM
        elif isinstance(severity, int):
            try:
                self.severity = Severity(severity)
            except ValueError:
                logger.warning(f"Invalid severity value: {severity}, using MEDIUM")
                self.severity = Severity.MEDIUM
        else:
            self.severity = severity

        self.title = title
        self.description = description
        self.remediation = remediation
        self.evidence = evidence if evidence is not None else {}
        self.compliance = set(compliance) if compliance else set()
        self.context = context if context is not None else {}
        self.timestamp = timestamp or datetime.datetime.now()
        self.check_id = check_id

    def add_compliance_references(self, references: List[str]) -> None:
        """
        Add compliance reference IDs to the result.

        Args:
            references: List of compliance reference IDs (e.g., ["CIS 1.1.2", "NIST AC-3"])
        """
        if not self.compliance:
            self.compliance = set()
        self.compliance.update(references)

    def add_evidence(self, key: str, value: Any) -> None:
        """
        Add a piece of evidence to the result.

        Args:
            key: Evidence identifier
            value: Evidence value
        """
        if not isinstance(self.evidence, dict):
            # Convert existing evidence to dictionary if it's not already
            self.evidence = {"previous_evidence": self.evidence}
        self.evidence[key] = value

    def add_context(self, key: str, value: Any) -> None:
        """
        Add contextual information to the result.

        Args:
            key: Context identifier
            value: Context value
        """
        self.context[key] = value

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the result to a dictionary representation.

        Returns:
            Dictionary representation of the result
        """
        return {
            "severity": self.severity.name,
            "severity_level": int(self.severity),
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "compliance": list(self.compliance),
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "check_id": self.check_id
        }

    def to_json(self) -> str:
        """
        Convert the result to a JSON string.

        Returns:
            JSON string representation of the result
        """
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_markdown(self) -> str:
        """
        Convert the result to a Markdown string.

        Returns:
            Markdown formatted representation of the result
        """
        lines = [
            f"## {self.title}",
            f"**Severity**: {self.severity.name}",
            "",
            f"### Description",
            self.description,
            "",
            f"### Remediation",
            self.remediation,
            ""
        ]

        if self.evidence:
            lines.extend([
                "### Evidence",
                format_evidence(self.evidence),
                ""
            ])

        if self.compliance:
            lines.extend([
                "### Compliance",
                ", ".join(sorted(self.compliance)),
                ""
            ])

        if self.context:
            lines.extend([
                "### Context",
                "\n".join(f"- **{k}**: {v}" for k, v in self.context.items()),
                ""
            ])

        return "\n".join(lines)

    def to_html(self) -> str:
        """
        Convert the result to an HTML string.

        Returns:
            HTML formatted representation of the result
        """
        severity_color = SEVERITY_COLOR_MAP.get(self.severity.name, "#cccccc")

        html = f"""
        <div class="check-result severity-{self.severity.name.lower()}">
            <h3 class="result-title">{self.title}</h3>
            <div class="result-severity" style="background-color: {severity_color}">
                {self.severity.name}
            </div>
            <div class="result-description">
                <h4>Description</h4>
                <p>{self.description}</p>
            </div>
            <div class="result-remediation">
                <h4>Remediation</h4>
                <p>{self.remediation}</p>
            </div>
        """

        if self.evidence:
            html += """
            <div class="result-evidence">
                <h4>Evidence</h4>
                <pre>"""
            if isinstance(self.evidence, dict):
                for k, v in self.evidence.items():
                    html += f"<div><strong>{k}:</strong> {v}</div>"
            else:
                html += str(self.evidence)
            html += "</pre></div>"

        if self.compliance:
            html += """
            <div class="result-compliance">
                <h4>Compliance</h4>
                <p>"""
            html += ", ".join(sorted(self.compliance))
            html += "</p></div>"

        html += "</div>"
        return html

    def __str__(self) -> str:
        """Return string representation of the result."""
        return f"[{self.severity.name}] {self.title}: {self.description}"

    def __repr__(self) -> str:
        """Return detailed representation of the result."""
        return f"CheckResult({self.severity.name}, '{self.title}', compliance={list(self.compliance) if self.compliance else []})"


class CheckResultSet:
    """
    A collection of check results with aggregation capabilities.

    This class represents a set of security check results with methods for filtering,
    aggregating, and generating reports.
    """

    def __init__(self, results: Optional[List[CheckResult]] = None):
        """
        Initialize a check result set.

        Args:
            results: Initial list of check results (optional)
        """
        self.results = results or []
        self.timestamp = datetime.datetime.now()
        self.metadata = {}

    def add_result(self, result: CheckResult) -> None:
        """
        Add a single result to the set.

        Args:
            result: CheckResult to add
        """
        self.results.append(result)

    def add_results(self, results: Iterable[CheckResult]) -> None:
        """
        Add multiple results to the set.

        Args:
            results: Iterable of CheckResults to add
        """
        self.results.extend(results)

    def filter_by_severity(self, severity: Union[Severity, str, List[Severity], List[str]]) -> "CheckResultSet":
        """
        Filter results by severity level.

        Args:
            severity: Severity level(s) to include

        Returns:
            New CheckResultSet containing only matching results
        """
        # Convert single severity to list
        if not isinstance(severity, list):
            severities = [severity]
        else:
            severities = severity

        # Convert string severities to Severity enum
        severity_enums = []
        for s in severities:
            if isinstance(s, str):
                try:
                    severity_enums.append(Severity[s.upper()])
                except KeyError:
                    logger.warning(f"Unknown severity: {s}")
            else:
                severity_enums.append(s)

        filtered_results = [r for r in self.results if r.severity in severity_enums]
        return CheckResultSet(filtered_results)

    def filter_by_compliance(self, standard: str) -> "CheckResultSet":
        """
        Filter results by compliance standard.

        Args:
            standard: Compliance standard prefix to filter by

        Returns:
            New CheckResultSet containing only matching results
        """
        standard = standard.upper()
        filtered_results = [
            r for r in self.results
            if any(c.upper().startswith(standard) for c in r.compliance)
        ]
        return CheckResultSet(filtered_results)

    def filter_by_context(self, key: str, value: Any = None) -> "CheckResultSet":
        """
        Filter results by context key and optional value.

        Args:
            key: Context key to filter by
            value: Optional value to match (if None, just checks for key presence)

        Returns:
            New CheckResultSet containing only matching results
        """
        if value is None:
            filtered_results = [r for r in self.results if key in r.context]
        else:
            filtered_results = [r for r in self.results if r.context.get(key) == value]
        return CheckResultSet(filtered_results)

    def get_severity_counts(self) -> Dict[str, int]:
        """
        Get counts of results by severity.

        Returns:
            Dictionary mapping severity names to counts
        """
        counts = {s.name: 0 for s in Severity}
        for result in self.results:
            counts[result.severity.name] += 1
        return counts

    def get_compliance_coverage(self) -> Dict[str, int]:
        """
        Get counts of compliance standards referenced.

        Returns:
            Dictionary mapping compliance standards to counts
        """
        standards = {}
        for result in self.results:
            for compliance in result.compliance:
                # Extract the standard (e.g., "CIS" from "CIS 1.1.2")
                parts = compliance.split()
                if parts:
                    standard = parts[0]
                    standards[standard] = standards.get(standard, 0) + 1
        return standards

    def has_critical_findings(self) -> bool:
        """
        Check if the result set contains any critical findings.

        Returns:
            True if there are critical findings, False otherwise
        """
        return any(r.severity == Severity.CRITICAL for r in self.results)

    def has_high_findings(self) -> bool:
        """
        Check if the result set contains any high severity findings.

        Returns:
            True if there are high severity findings, False otherwise
        """
        return any(r.severity == Severity.HIGH for r in self.results)

    def highest_severity(self) -> Optional[Severity]:
        """
        Get the highest severity level in the result set.

        Returns:
            Highest severity level or None if there are no results
        """
        if not self.results:
            return None
        return max(r.severity for r in self.results)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the result set to a dictionary representation.

        Returns:
            Dictionary representation of the result set
        """
        return {
            "results": [r.to_dict() for r in self.results],
            "timestamp": self.timestamp.isoformat(),
            "count": len(self.results),
            "severity_summary": self.get_severity_counts(),
            "highest_severity": self.highest_severity().name if self.highest_severity() else None,
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """
        Convert the result set to a JSON string.

        Returns:
            JSON string representation of the result set
        """
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_markdown(self) -> str:
        """
        Convert the result set to a Markdown string.

        Returns:
            Markdown formatted representation of the result set
        """
        if not self.results:
            return "# Security Check Results\n\nNo findings."

        lines = [
            "# Security Check Results",
            "",
            "## Summary",
            "",
            f"- **Date**: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Total Findings**: {len(self.results)}",
            ""
        ]

        # Add severity summary
        severity_counts = self.get_severity_counts()
        lines.append("### Severity Distribution")
        lines.append("")
        for severity in sorted(Severity, reverse=True):
            count = severity_counts.get(severity.name, 0)
            if count > 0:
                lines.append(f"- **{severity.name}**: {count}")
        lines.append("")

        # Add findings by severity
        lines.append("## Findings")
        lines.append("")

        # Group by severity
        for severity in sorted(Severity, reverse=True):
            severity_results = [r for r in self.results if r.severity == severity]
            if severity_results:
                lines.append(f"### {severity.name} Severity Findings")
                lines.append("")

                for result in severity_results:
                    lines.append(f"#### {result.title}")
                    lines.append("")
                    lines.append(result.description)
                    lines.append("")
                    lines.append("**Remediation:**")
                    lines.append(result.remediation)
                    lines.append("")

                    if result.compliance:
                        lines.append("**Compliance:** " + ", ".join(sorted(result.compliance)))
                        lines.append("")

                    if result.evidence:
                        lines.append("**Evidence:**")
                        lines.append("```")
                        lines.append(format_evidence(result.evidence))
                        lines.append("```")
                        lines.append("")

        return "\n".join(lines)

    def generate_report(self, title: str = "Security Check Report",
                       format: str = DEFAULT_RESULT_FORMAT) -> str:
        """
        Generate a formatted report of the results.

        Args:
            title: Report title
            format: Report format (json, markdown, html)

        Returns:
            Formatted report string
        """
        self.metadata["title"] = title

        if format.lower() == "json":
            return self.to_json()
        elif format.lower() == "markdown":
            return self.to_markdown()
        elif format.lower() == "html":
            return self.to_html(title)
        else:
            logger.warning(f"Unsupported format: {format}, falling back to JSON")
            return self.to_json()

    def to_html(self, title: str = "Security Check Report") -> str:
        """
        Convert the result set to an HTML string.

        Args:
            title: Report title

        Returns:
            HTML formatted representation of the result set
        """
        if not self.results:
            return f"<h1>{title}</h1><p>No findings.</p>"

        severity_counts = self.get_severity_counts()
        highest_severity = self.highest_severity()

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; color: #333; }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3, h4 {{ margin-top: 20px; margin-bottom: 10px; }}
                .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .severity-critical {{ border-left: 5px solid #cc0000; padding-left: 15px; margin-bottom: 20px; }}
                .severity-high {{ border-left: 5px solid #ff6600; padding-left: 15px; margin-bottom: 20px; }}
                .severity-medium {{ border-left: 5px solid #ffcc00; padding-left: 15px; margin-bottom: 20px; }}
                .severity-low {{ border-left: 5px solid #ffff99; padding-left: 15px; margin-bottom: 20px; }}
                .severity-info {{ border-left: 5px solid #99ccff; padding-left: 15px; margin-bottom: 20px; }}
                .result-severity {{ display: inline-block; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
                .evidence-box {{ background: #f9f9f9; padding: 10px; border: 1px solid #ddd; margin-top: 10px; font-family: monospace; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>{title}</h1>

                <div class="summary">
                    <h2>Summary</h2>
                    <p><strong>Date:</strong> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Total Findings:</strong> {len(self.results)}</p>

                    <h3>Severity Distribution</h3>
                    <ul>
        """

        # Add severity summary
        for severity in sorted(Severity, reverse=True):
            count = severity_counts.get(severity.name, 0)
            if count > 0:
                color = SEVERITY_COLOR_MAP.get(severity.name, "#cccccc")
                html += f"""<li><span class="result-severity" style="background-color: {color}">{severity.name}</span>: {count}</li>"""

        html += """
                    </ul>
                </div>

                <h2>Findings</h2>
        """

        # Group by severity
        for severity in sorted(Severity, reverse=True):
            severity_results = [r for r in self.results if r.severity == severity]
            if severity_results:
                html += f"""<h3>{severity.name} Severity Findings</h3>"""

                for result in severity_results:
                    html += f"""
                    <div class="severity-{severity.name.lower()}">
                        <h4>{result.title}</h4>
                        <p>{result.description}</p>
                        <p><strong>Remediation:</strong> {result.remediation}</p>
                    """

                    if result.compliance:
                        html += f"""<p><strong>Compliance:</strong> {', '.join(sorted(result.compliance))}</p>"""

                    if result.evidence:
                        html += """<p><strong>Evidence:</strong></p>
                        <div class="evidence-box">"""
                        if isinstance(result.evidence, dict):
                            for k, v in result.evidence.items():
                                html += f"<div><strong>{k}:</strong> {v}</div>"
                        else:
                            html += str(result.evidence)
                        html += "</div>"

                    html += "</div>"

        html += """
            </div>
        </body>
        </html>
        """

        return html

    def compare_with_baseline(self, baseline: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Compare results with a baseline to identify new, resolved, and unchanged findings.

        Args:
            baseline: Dictionary representation of previous results

        Returns:
            Dictionary with new, resolved, and unchanged findings
        """
        baseline_findings = {
            f"{item.get('title')}_{item.get('severity')}": item
            for item in baseline.get("results", [])
        }

        current_findings = {
            f"{r.title}_{r.severity.name}": r.to_dict()
            for r in self.results
        }

        new_findings = []
        for key, finding in current_findings.items():
            if key not in baseline_findings:
                finding["comparison"] = "new"
                new_findings.append(finding)

        resolved_findings = []
        for key, finding in baseline_findings.items():
            if key not in current_findings:
                finding["comparison"] = "resolved"
                resolved_findings.append(finding)

        unchanged_findings = []
        for key in set(current_findings.keys()) & set(baseline_findings.keys()):
            finding = current_findings[key].copy()
            finding["comparison"] = "unchanged"
            unchanged_findings.append(finding)

        return {
            "new": new_findings,
            "resolved": resolved_findings,
            "unchanged": unchanged_findings
        }

    def __len__(self) -> int:
        """Return the number of results in the set."""
        return len(self.results)

    def __iter__(self):
        """Allow iteration over results."""
        return iter(self.results)

    def __bool__(self) -> bool:
        """Return True if there are any results in the set."""
        return bool(self.results)


if __name__ == "__main__":
    # Example usage
    result = CheckResult(
        severity=Severity.MEDIUM,
        title="Weak File Permissions",
        description="Configuration file has excessive permissions",
        remediation="Change permissions to 0600",
        evidence={"file": "/etc/app/config.json", "permissions": "0644"},
        compliance=["CIS 5.1.2", "NIST AC-6"]
    )

    print(result)
    print(result.to_json())
