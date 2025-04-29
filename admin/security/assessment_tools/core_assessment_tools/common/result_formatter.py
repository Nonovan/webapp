"""
Result formatting utilities for security assessment tools.

This module provides functionality for formatting assessment results in various
output formats (JSON, CSV, XML, HTML, Markdown) with support for different
output customization options including severity filtering, evidence inclusion,
and compliance control mapping.
"""

import csv
import datetime
import io
import json
import logging
import os
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union, cast

from .assessment_logging import get_assessment_logger
from .data_types import AssessmentResult, Evidence, Finding, FindingSeverity

logger = get_assessment_logger("result_formatter")

# Constants for output formats
FORMAT_JSON = "json"
FORMAT_CSV = "csv"
FORMAT_XML = "xml"
FORMAT_HTML = "html"
FORMAT_MARKDOWN = "markdown"
FORMAT_TEXT = "text"
FORMAT_STANDARD = "standard"  # Default format - typically JSON with some extra structure
FORMAT_SARIF = "sarif"  # Static Analysis Results Interchange Format
FORMAT_JUNIT = "junit"  # JUnit XML format for CI/CD integration

# Valid output formats
VALID_OUTPUT_FORMATS = [
    FORMAT_JSON, FORMAT_CSV, FORMAT_XML, FORMAT_HTML, FORMAT_MARKDOWN,
    FORMAT_TEXT, FORMAT_STANDARD, FORMAT_SARIF, FORMAT_JUNIT
]

# Constants for severity levels mapping to other systems
SEVERITY_MAPPING = {
    # CVSS to internal severity
    "cvss": {
        "0.0": FindingSeverity.INFO,
        "0.1-3.9": FindingSeverity.LOW,
        "4.0-6.9": FindingSeverity.MEDIUM,
        "7.0-8.9": FindingSeverity.HIGH,
        "9.0-10.0": FindingSeverity.CRITICAL
    },
    # PCI DSS severity mapping
    "pci-dss": {
        FindingSeverity.CRITICAL: "High",
        FindingSeverity.HIGH: "High",
        FindingSeverity.MEDIUM: "Medium",
        FindingSeverity.LOW: "Low",
        FindingSeverity.INFO: "Informational"
    },
    # NIST severity mapping
    "nist": {
        FindingSeverity.CRITICAL: "Very High",
        FindingSeverity.HIGH: "High",
        FindingSeverity.MEDIUM: "Moderate",
        FindingSeverity.LOW: "Low",
        FindingSeverity.INFO: "Informational"
    }
}


class ResultFormatter:
    """
    Formats assessment results into various output formats.

    This class provides methods to convert assessment results into different
    output formats and write them to files or return them as strings.
    """

    def __init__(self) -> None:
        """Initialize the result formatter."""
        self.logger = get_assessment_logger("result_formatter")

    def format(
        self,
        results: AssessmentResult,
        format_type: str = FORMAT_STANDARD,
        include_evidence: bool = False,
        filter_severity: Optional[List[str]] = None,
        compliance_map: Optional[List[str]] = None,
    ) -> str:
        """
        Format assessment results into the specified format.

        Args:
            results: AssessmentResult object to format
            format_type: Output format type (json, csv, xml, html, markdown, etc.)
            include_evidence: Whether to include evidence details
            filter_severity: List of severity levels to include
            compliance_map: List of compliance frameworks to map findings to

        Returns:
            Formatted results as string
        """
        self.logger.info(f"Formatting results in {format_type} format")

        # Apply severity filter if requested
        findings = self._filter_findings_by_severity(results.findings, filter_severity)

        # Map findings to compliance frameworks if requested
        if compliance_map:
            findings = self._map_findings_to_compliance(findings, compliance_map)

        # Format results based on requested format
        try:
            format_type = format_type.lower()

            if format_type == FORMAT_JSON:
                return self._format_json(results, findings, include_evidence)
            elif format_type == FORMAT_CSV:
                return self._format_csv(results, findings, include_evidence)
            elif format_type == FORMAT_XML:
                return self._format_xml(results, findings, include_evidence)
            elif format_type == FORMAT_HTML:
                return self._format_html(results, findings, include_evidence)
            elif format_type == FORMAT_MARKDOWN:
                return self._format_markdown(results, findings, include_evidence)
            elif format_type == FORMAT_TEXT:
                return self._format_text(results, findings, include_evidence)
            elif format_type == FORMAT_SARIF:
                return self._format_sarif(results, findings, include_evidence)
            elif format_type == FORMAT_JUNIT:
                return self._format_junit(results, findings, include_evidence)
            elif format_type == FORMAT_STANDARD:
                # Standard format is our enhanced JSON format
                return self._format_standard(results, findings, include_evidence)
            else:
                self.logger.warning(f"Unsupported format: {format_type}, using standard format")
                return self._format_standard(results, findings, include_evidence)
        except Exception as e:
            self.logger.error(f"Error formatting results: {str(e)}", exc_info=True)
            error_result = {
                "error": f"Failed to format results: {str(e)}",
                "assessment_id": results.assessment_id,
                "timestamp": datetime.datetime.now().isoformat()
            }
            return json.dumps(error_result, indent=2)

    def write_to_file(self, content: str, output_path: Union[str, Path]) -> bool:
        """
        Write formatted results to a file.

        Args:
            content: Formatted content to write
            output_path: Path to write the file to

        Returns:
            True if successful, False otherwise
        """
        try:
            output_path = Path(output_path)

            # Create directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)

            self.logger.info(f"Results written to {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error writing results to {output_path}: {str(e)}", exc_info=True)
            return False

    def generate_summary(self, results: AssessmentResult) -> Dict[str, Any]:
        """
        Generate a summary of assessment results.

        Args:
            results: AssessmentResult to summarize

        Returns:
            Dictionary with summary information
        """
        # Count findings by severity
        severity_counts = {severity.value: 0 for severity in FindingSeverity}
        for finding in results.findings:
            severity_counts[finding.severity.value] += 1

        # Calculate risk statistics
        total_findings = len(results.findings)
        risk_score = self._calculate_risk_score(results)

        # Generate summary
        summary = {
            "assessment_id": results.assessment_id,
            "name": results.name,
            "target": results.target.to_dict() if not isinstance(results.target, list) else [t.to_dict() for t in results.target],
            "timestamp": datetime.datetime.now().isoformat(),
            "start_time": results.start_time.isoformat(),
            "end_time": results.end_time.isoformat() if results.end_time else datetime.datetime.now().isoformat(),
            "duration_seconds": (results.end_time - results.start_time).total_seconds() if results.end_time else None,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "status": results.status
        }

        # Add risk level
        if results.summary and "risk_level" in results.summary:
            summary["risk_level"] = results.summary["risk_level"].value

        return summary

    def _filter_findings_by_severity(
        self,
        findings: List[Finding],
        severity_levels: Optional[List[str]]
    ) -> List[Finding]:
        """
        Filter findings by severity levels.

        Args:
            findings: List of findings to filter
            severity_levels: List of severity levels to include

        Returns:
            Filtered list of findings
        """
        if not severity_levels:
            return findings

        # Convert string severity levels to FindingSeverity enums
        valid_levels = []
        for level in severity_levels:
            try:
                valid_levels.append(FindingSeverity(level.lower()))
            except ValueError:
                self.logger.warning(f"Invalid severity level: {level}")

        # Filter findings
        filtered = [finding for finding in findings if finding.severity in valid_levels]
        self.logger.debug(f"Filtered {len(findings)} findings to {len(filtered)} based on severity")

        return filtered

    def _map_findings_to_compliance(
        self,
        findings: List[Finding],
        frameworks: List[str]
    ) -> List[Finding]:
        """
        Map findings to compliance frameworks.

        Args:
            findings: List of findings to map
            frameworks: List of compliance frameworks

        Returns:
            List of findings with compliance mappings
        """
        # Create deep copies of findings to avoid modifying originals
        import copy
        mapped_findings = copy.deepcopy(findings)

        # Apply mappings
        for finding in mapped_findings:
            if not finding.compliance:
                finding.compliance = {}

            for framework in frameworks:
                if framework not in finding.compliance:
                    # Apply any default mappings based on finding category or CWE
                    compliance_controls = self._get_compliance_controls(finding, framework)
                    if compliance_controls:
                        finding.compliance[framework] = compliance_controls

        return mapped_findings

    def _get_compliance_controls(self, finding: Finding, framework: str) -> List[str]:
        """
        Get compliance controls for a finding based on framework.

        Args:
            finding: Finding to map
            framework: Compliance framework

        Returns:
            List of compliance controls
        """
        # This would typically look up mappings in a database or configuration
        # For now, we'll return placeholder mappings based on finding category
        controls = []

        if framework.lower() == "pci-dss":
            if finding.category == "authentication":
                controls = ["PCI-DSS 8.2"]
            elif finding.category == "access_control":
                controls = ["PCI-DSS 7.1", "PCI-DSS 7.2"]
            elif finding.category == "encryption":
                controls = ["PCI-DSS 3.4", "PCI-DSS 4.1"]

        elif framework.lower() == "nist":
            if finding.category == "authentication":
                controls = ["NIST SP 800-53 IA-2", "NIST SP 800-53 IA-5"]
            elif finding.category == "access_control":
                controls = ["NIST SP 800-53 AC-3", "NIST SP 800-53 AC-6"]
            elif finding.category == "encryption":
                controls = ["NIST SP 800-53 SC-8", "NIST SP 800-53 SC-13"]

        # Add placeholder if empty
        if not controls:
            self.logger.debug(f"No compliance controls found for {finding.title} in {framework}")
            # Use finding ID to create deterministic but unique control ID
            control_id = f"{framework.upper()}-REVIEW-{abs(hash(finding.finding_id)) % 1000:03d}"
            controls = [f"{control_id} (Manual Review Required)"]

        return controls

    def _calculate_risk_score(self, results: AssessmentResult) -> float:
        """
        Calculate a risk score based on findings.

        Args:
            results: Assessment results

        Returns:
            Risk score from 0-100
        """
        # Simple calculation based on severity counts
        severity_weights = {
            FindingSeverity.CRITICAL: 10.0,
            FindingSeverity.HIGH: 5.0,
            FindingSeverity.MEDIUM: 2.0,
            FindingSeverity.LOW: 0.5,
            FindingSeverity.INFO: 0.0
        }

        total_score = 0.0
        for finding in results.findings:
            total_score += severity_weights.get(finding.severity, 0.0)

        # Cap at 100
        return min(100.0, total_score)

    def _format_standard(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results in standard format (enhanced JSON).

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            Formatted results string
        """
        # Convert to dictionary with enhanced metadata
        data_dict = results.to_dict()

        # Replace findings with filtered findings
        data_dict["findings"] = [f.to_dict() for f in findings]

        # Remove evidence if not requested
        if not include_evidence:
            for finding in data_dict["findings"]:
                if "evidence" in finding:
                    del finding["evidence"]

        # Add additional metadata
        data_dict["metadata"] = {
            "format_version": "1.0",
            "formatted_at": datetime.datetime.now().isoformat(),
            "total_findings": len(findings),
            "filtered_count": len(results.findings) - len(findings) if len(findings) != len(results.findings) else 0,
            "formatter": "AssessmentResultFormatter"
        }

        # Convert to JSON
        return json.dumps(data_dict, indent=2, default=str)

    def _format_json(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results as JSON.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            JSON-formatted results
        """
        # Convert results to dictionary with filtered findings
        data_dict = results.to_dict()
        data_dict["findings"] = [f.to_dict() for f in findings]

        # Remove evidence if not requested
        if not include_evidence:
            for finding in data_dict["findings"]:
                if "evidence" in finding:
                    del finding["evidence"]

        # Convert to JSON
        return json.dumps(data_dict, indent=2, default=str)

    def _format_csv(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results as CSV.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            CSV-formatted results
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header row
        header = [
            "ID", "Title", "Severity", "Category", "Description",
            "Remediation", "Status", "CVSS", "Created Date"
        ]

        # Add evidence columns if requested
        if include_evidence:
            header.extend(["Evidence Count", "Evidence Types"])

        writer.writerow(header)

        # Write finding rows
        for finding in findings:
            row = [
                finding.finding_id,
                finding.title,
                finding.severity.value,
                finding.category,
                finding.description,
                finding.remediation,
                finding.status.value if finding.status else "new",
                finding.cvss.base_score if finding.cvss else "",
                finding.created_date.isoformat() if finding.created_date else ""
            ]

            # Add evidence data if requested
            if include_evidence and finding.evidence:
                row.extend([
                    len(finding.evidence),
                    ", ".join(set(e.evidence_type for e in finding.evidence))
                ])
            elif include_evidence:
                row.extend(["0", ""])

            writer.writerow(row)

        return output.getvalue()

    def _format_xml(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results as XML.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            XML-formatted results
        """
        try:
            import xml.etree.ElementTree as ET
            from xml.dom import minidom
        except ImportError:
            self.logger.error("XML libraries not available")
            return f"<error>XML formatting libraries not available</error>"

        # Create root element
        root = ET.Element("assessmentResults")
        ET.SubElement(root, "assessmentId").text = results.assessment_id
        ET.SubElement(root, "name").text = results.name

        # Add target details
        if isinstance(results.target, list):
            targets_elem = ET.SubElement(root, "targets")
            for target in results.target:
                target_elem = ET.SubElement(targets_elem, "target")
                ET.SubElement(target_elem, "targetId").text = target.target_id
                ET.SubElement(target_elem, "name").text = target.name
                ET.SubElement(target_elem, "type").text = target.target_type
        else:
            target_elem = ET.SubElement(root, "target")
            ET.SubElement(target_elem, "targetId").text = results.target.target_id
            ET.SubElement(target_elem, "name").text = results.target.name
            ET.SubElement(target_elem, "type").text = results.target.target_type

        # Add metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "startTime").text = results.start_time.isoformat()
        if results.end_time:
            ET.SubElement(metadata, "endTime").text = results.end_time.isoformat()
        ET.SubElement(metadata, "status").text = results.status

        # Add summary
        summary = ET.SubElement(root, "summary")
        ET.SubElement(summary, "totalFindings").text = str(len(findings))

        # Add severity counts
        severity_counts = ET.SubElement(summary, "severityCounts")
        severity_count = {s.value: 0 for s in FindingSeverity}
        for finding in findings:
            severity_count[finding.severity.value] += 1

        for severity, count in severity_count.items():
            severity_elem = ET.SubElement(severity_counts, "count")
            ET.SubElement(severity_elem, "severity").text = severity
            ET.SubElement(severity_elem, "value").text = str(count)

        # Add findings
        findings_elem = ET.SubElement(root, "findings")
        for finding in findings:
            finding_elem = ET.SubElement(findings_elem, "finding")
            ET.SubElement(finding_elem, "id").text = finding.finding_id
            ET.SubElement(finding_elem, "title").text = finding.title
            ET.SubElement(finding_elem, "severity").text = finding.severity.value
            ET.SubElement(finding_elem, "category").text = finding.category

            description = ET.SubElement(finding_elem, "description")
            description.text = finding.description

            if finding.remediation:
                remediation = ET.SubElement(finding_elem, "remediation")
                remediation.text = finding.remediation

            ET.SubElement(finding_elem, "status").text = finding.status.value if finding.status else "new"

            # Add evidence if requested
            if include_evidence and finding.evidence:
                evidence_list = ET.SubElement(finding_elem, "evidence")
                for evidence in finding.evidence:
                    evidence_elem = ET.SubElement(evidence_list, "item")
                    ET.SubElement(evidence_elem, "id").text = evidence.evidence_id
                    ET.SubElement(evidence_elem, "type").text = evidence.evidence_type
                    ET.SubElement(evidence_elem, "description").text = evidence.description

        # Format the XML with proper indentation
        xml_str = ET.tostring(root, encoding="unicode")
        pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")

        return pretty_xml

    def _format_html(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results as HTML.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            HTML-formatted results
        """
        html = []

        # Start HTML document
        html.append("<!DOCTYPE html>")
        html.append("<html lang=\"en\">")
        html.append("<head>")
        html.append("  <meta charset=\"UTF-8\">")
        html.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
        html.append(f"  <title>Security Assessment Results - {results.assessment_id}</title>")
        html.append("  <style>")
        html.append("    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }")
        html.append("    h1, h2, h3 { color: #0066cc; }")
        html.append("    .container { max-width: 1200px; margin: 0 auto; }")
        html.append("    .header { margin-bottom: 30px; }")
        html.append("    .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }")
        html.append("    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }")
        html.append("    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }")
        html.append("    th { background-color: #f2f2f2; }")
        html.append("    tr:hover { background-color: #f5f5f5; }")
        html.append("    .severity-critical { color: #721c24; background-color: #f8d7da; }")
        html.append("    .severity-high { color: #856404; background-color: #fff3cd; }")
        html.append("    .severity-medium { color: #0c5460; background-color: #d1ecf1; }")
        html.append("    .severity-low { color: #155724; background-color: #d4edda; }")
        html.append("    .severity-info { color: #383d41; background-color: #e2e3e5; }")
        html.append("    .finding { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }")
        html.append("    .finding-header { display: flex; justify-content: space-between; align-items: center; }")
        html.append("    .evidence { margin-top: 15px; padding: 10px; background-color: #f8f9fa; border-radius: 4px; }")
        html.append("    footer { margin-top: 50px; border-top: 1px solid #ddd; padding-top: 10px; color: #777; }")
        html.append("  </style>")
        html.append("</head>")
        html.append("<body>")
        html.append("  <div class=\"container\">")

        # Header
        html.append("    <div class=\"header\">")
        html.append(f"      <h1>Security Assessment Results</h1>")
        html.append(f"      <p>Assessment ID: {results.assessment_id}</p>")
        html.append(f"      <p>Assessment Name: {results.name}</p>")
        html.append(f"      <p>Date: {results.end_time.strftime('%Y-%m-%d %H:%M:%S') if results.end_time else datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append("    </div>")

        # Summary
        html.append("    <div class=\"summary\">")
        html.append("      <h2>Summary</h2>")

        # Target Information
        html.append("      <h3>Target Information</h3>")
        if isinstance(results.target, list):
            html.append("      <table>")
            html.append("        <tr><th>Target ID</th><th>Name</th><th>Type</th></tr>")
            for target in results.target:
                html.append(f"        <tr><td>{target.target_id}</td><td>{target.name}</td><td>{target.target_type}</td></tr>")
            html.append("      </table>")
        else:
            html.append("      <table>")
            html.append("        <tr><th>Target ID</th><th>Name</th><th>Type</th></tr>")
            html.append(f"        <tr><td>{results.target.target_id}</td><td>{results.target.name}</td><td>{results.target.target_type}</td></tr>")
            html.append("      </table>")

        # Findings Count
        html.append("      <h3>Findings Breakdown</h3>")
        html.append("      <table>")
        html.append("        <tr><th>Severity</th><th>Count</th></tr>")

        severity_count = {s.value: 0 for s in FindingSeverity}
        for finding in findings:
            severity_count[finding.severity.value] += 1

        for severity in ["critical", "high", "medium", "low", "info"]:
            html.append(f"        <tr class=\"severity-{severity}\"><td>{severity.capitalize()}</td><td>{severity_count[severity]}</td></tr>")

        html.append(f"        <tr><td><strong>Total</strong></td><td><strong>{len(findings)}</strong></td></tr>")
        html.append("      </table>")
        html.append("    </div>")

        # Findings
        html.append("    <h2>Findings</h2>")
        if not findings:
            html.append("    <p>No findings to report.</p>")
        else:
            for finding in findings:
                html.append(f"    <div class=\"finding\">")
                html.append(f"      <div class=\"finding-header\">")
                html.append(f"        <h3>{finding.title}</h3>")
                html.append(f"        <span class=\"severity-{finding.severity.value}\">{finding.severity.value.upper()}</span>")
                html.append("      </div>")
                html.append(f"      <p><strong>ID:</strong> {finding.finding_id}</p>")
                html.append(f"      <p><strong>Category:</strong> {finding.category}</p>")
                html.append(f"      <p><strong>Status:</strong> {finding.status.value if finding.status else 'New'}</p>")

                # Description with word wrap for better readability
                html.append("      <h4>Description</h4>")
                html.append(f"      <p>{finding.description}</p>")

                # Remediation if available
                if finding.remediation:
                    html.append("      <h4>Remediation</h4>")
                    html.append(f"      <p>{finding.remediation}</p>")

                # Evidence if requested
                if include_evidence and finding.evidence:
                    html.append("      <h4>Evidence</h4>")
                    html.append("      <div class=\"evidence\">")
                    for evidence in finding.evidence:
                        html.append(f"        <p><strong>{evidence.title}</strong> ({evidence.evidence_type})</p>")
                        html.append(f"        <p>{evidence.description}</p>")
                    html.append("      </div>")

                # Compliance mappings if available
                if finding.compliance:
                    html.append("      <h4>Compliance</h4>")
                    html.append("      <table>")
                    html.append("        <tr><th>Framework</th><th>Controls</th></tr>")
                    for framework, controls in finding.compliance.items():
                        html.append(f"        <tr><td>{framework}</td><td>{', '.join(controls)}</td></tr>")
                    html.append("      </table>")

                html.append("    </div>")

        # Footer
        html.append("    <footer>")
        html.append(f"      <p>Generated by Security Assessment Tools on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append("    </footer>")
        html.append("  </div>")
        html.append("</body>")
        html.append("</html>")

        return "\n".join(html)

    def _format_markdown(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results as Markdown.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            Markdown-formatted results
        """
        md = []

        # Header
        md.append(f"# Security Assessment Results")
        md.append(f"**Assessment ID:** {results.assessment_id}  ")
        md.append(f"**Assessment Name:** {results.name}  ")
        md.append(f"**Date:** {results.end_time.strftime('%Y-%m-%d %H:%M:%S') if results.end_time else datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        md.append("")

        # Summary
        md.append("## Summary")

        # Target Information
        md.append("### Target Information")
        if isinstance(results.target, list):
            md.append("| Target ID | Name | Type |")
            md.append("| --------- | ---- | ---- |")
            for target in results.target:
                md.append(f"| {target.target_id} | {target.name} | {target.target_type} |")
        else:
            md.append("| Target ID | Name | Type |")
            md.append("| --------- | ---- | ---- |")
            md.append(f"| {results.target.target_id} | {results.target.name} | {results.target.target_type} |")

        md.append("")

        # Findings Count
        md.append("### Findings Breakdown")
        md.append("| Severity | Count |")
        md.append("| -------- | ----- |")

        severity_count = {s.value: 0 for s in FindingSeverity}
        for finding in findings:
            severity_count[finding.severity.value] += 1

        for severity in ["critical", "high", "medium", "low", "info"]:
            md.append(f"| {severity.capitalize()} | {severity_count[severity]} |")

        md.append(f"| **Total** | **{len(findings)}** |")
        md.append("")

        # Findings
        md.append("## Findings")
        if not findings:
            md.append("No findings to report.")
        else:
            for i, finding in enumerate(findings):
                md.append(f"### {i+1}. {finding.title}")
                md.append(f"**Severity:** {finding.severity.value.upper()}  ")
                md.append(f"**ID:** {finding.finding_id}  ")
                md.append(f"**Category:** {finding.category}  ")
                md.append(f"**Status:** {finding.status.value if finding.status else 'New'}  ")

                if finding.cvss:
                    md.append(f"**CVSS:** {finding.cvss.base_score}  ")

                md.append("")
                md.append("#### Description")
                md.append(finding.description)
                md.append("")

                if finding.remediation:
                    md.append("#### Remediation")
                    md.append(finding.remediation)
                    md.append("")

                if include_evidence and finding.evidence:
                    md.append("#### Evidence")
                    for evidence in finding.evidence:
                        md.append(f"**{evidence.title}** ({evidence.evidence_type})  ")
                        md.append(evidence.description)
                        md.append("")

                if finding.compliance:
                    md.append("#### Compliance")
                    md.append("| Framework | Controls |")
                    md.append("| --------- | -------- |")
                    for framework, controls in finding.compliance.items():
                        md.append(f"| {framework} | {', '.join(controls)} |")
                    md.append("")

                md.append("---")

        # Footer
        md.append("")
        md.append(f"*Generated by Security Assessment Tools on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(md)

    def _format_text(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results as plain text.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            Text-formatted results
        """
        text = []

        # Header with horizontal line
        text.append("=" * 80)
        text.append("SECURITY ASSESSMENT RESULTS")
        text.append("=" * 80)
        text.append(f"Assessment ID: {results.assessment_id}")
        text.append(f"Assessment Name: {results.name}")
        text.append(f"Date: {results.end_time.strftime('%Y-%m-%d %H:%M:%S') if results.end_time else datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        text.append("")

        # Summary
        text.append("SUMMARY")
        text.append("-" * 80)

        # Target Information
        text.append("Target Information:")
        if isinstance(results.target, list):
            for target in results.target:
                text.append(f"  - ID: {target.target_id}, Name: {target.name}, Type: {target.target_type}")
        else:
            text.append(f"  - ID: {results.target.target_id}, Name: {results.target.name}, Type: {results.target.target_type}")

        text.append("")

        # Findings Count
        text.append("Findings Breakdown:")

        severity_count = {s.value: 0 for s in FindingSeverity}
        for finding in findings:
            severity_count[finding.severity.value] += 1

        for severity in ["critical", "high", "medium", "low", "info"]:
            text.append(f"  - {severity.capitalize()}: {severity_count[severity]}")

        text.append(f"  - Total: {len(findings)}")
        text.append("")

        # Findings
        text.append("FINDINGS")
        text.append("-" * 80)
        if not findings:
            text.append("No findings to report.")
        else:
            for i, finding in enumerate(findings):
                text.append(f"Finding {i+1}: {finding.title}")
                text.append(f"Severity: {finding.severity.value.upper()}")
                text.append(f"ID: {finding.finding_id}")
                text.append(f"Category: {finding.category}")
                text.append(f"Status: {finding.status.value if finding.status else 'New'}")

                if finding.cvss:
                    text.append(f"CVSS: {finding.cvss.base_score}")

                text.append("")
                text.append("Description:")
                text.append(textwrap.fill(finding.description, width=80, initial_indent='  ', subsequent_indent='  '))
                text.append("")

                if finding.remediation:
                    text.append("Remediation:")
                    text.append(textwrap.fill(finding.remediation, width=80, initial_indent='  ', subsequent_indent='  '))
                    text.append("")

                if include_evidence and finding.evidence:
                    text.append("Evidence:")
                    for evidence in finding.evidence:
                        text.append(f"  - {evidence.title} ({evidence.evidence_type})")
                        text.append(textwrap.fill(evidence.description, width=80, initial_indent='    ', subsequent_indent='    '))
                        text.append("")

                if finding.compliance:
                    text.append("Compliance:")
                    for framework, controls in finding.compliance.items():
                        text.append(f"  - {framework}: {', '.join(controls)}")
                    text.append("")

                text.append("-" * 80)

        # Footer
        text.append("")
        text.append(f"Generated by Security Assessment Tools on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        return "\n".join(text)

    def _format_sarif(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results in SARIF (Static Analysis Results Interchange Format).

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            SARIF-formatted results
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Security Assessment Tools",
                            "informationUri": "https://example.com/security-assessment-tools",
                            "version": "1.0.0",
                            "rules": []
                        }
                    },
                    "results": [],
                    "properties": {
                        "assessmentId": results.assessment_id,
                        "assessmentName": results.name,
                    },
                }
            ]
        }

        # Create rules and results
        rules = {}
        results_list = []

        for finding in findings:
            # Create rule ID from finding category and severity
            rule_id = f"{finding.category}_{finding.severity.value}"
            rule_id = rule_id.replace(" ", "_").replace("-", "_").lower()

            # Add rule if not already defined
            if rule_id not in rules:
                rule = {
                    "id": rule_id,
                    "name": finding.category,
                    "shortDescription": {
                        "text": f"{finding.category.capitalize()} ({finding.severity.value.upper()})"
                    },
                    "fullDescription": {
                        "text": f"Issues related to {finding.category}"
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity)
                    },
                    "properties": {
                        "tags": [finding.category, finding.severity.value],
                        "precision": "high"
                    }
                }

                rules[rule_id] = rule

            # Create result
            result = {
                "ruleId": rule_id,
                "message": {
                    "text": finding.title
                },
                "level": self._severity_to_sarif_level(finding.severity),
                "properties": {
                    "findingId": finding.finding_id,
                    "description": finding.description,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "status": finding.status.value if finding.status else "new",
                }
            }

            # Add remediation if available
            if finding.remediation:
                result["properties"]["remediation"] = finding.remediation

            # Add compliance mappings if available
            if finding.compliance:
                result["properties"]["compliance"] = finding.compliance

            # Add evidence if requested
            if include_evidence and finding.evidence:
                result["properties"]["evidence"] = []
                for evidence in finding.evidence:
                    result["properties"]["evidence"].append({
                        "evidenceId": evidence.evidence_id,
                        "title": evidence.title,
                        "description": evidence.description,
                        "evidenceType": evidence.evidence_type
                    })

            results_list.append(result)

        # Add rules and results to SARIF
        sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
        sarif["runs"][0]["results"] = results_list

        return json.dumps(sarif, indent=2)

    def _format_junit(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results in JUnit XML format for CI/CD integration.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            JUnit XML-formatted results
        """
        try:
            import xml.etree.ElementTree as ET
            from xml.dom import minidom
        except ImportError:
            self.logger.error("XML libraries not available")
            return f"<error>XML formatting libraries not available</error>"

        # Create testsuite element
        testsuite = ET.Element("testsuite")
        testsuite.set("name", f"SecurityAssessment-{results.assessment_id}")
        testsuite.set("tests", str(len(findings)))

        # Count failures
        failures = len([f for f in findings if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]])
        testsuite.set("failures", str(failures))

        # Count errors
        errors = len([f for f in findings if f.severity == FindingSeverity.MEDIUM])
        testsuite.set("errors", str(errors))

        # Set timestamp
        testsuite.set("timestamp", results.end_time.isoformat() if results.end_time else datetime.datetime.now().isoformat())

        # Create properties
        properties = ET.SubElement(testsuite, "properties")

        ET.SubElement(properties, "property", name="assessmentId", value=results.assessment_id)
        ET.SubElement(properties, "property", name="assessmentName", value=results.name)

        # Add target properties
        if isinstance(results.target, list):
            for i, target in enumerate(results.target):
                ET.SubElement(properties, "property", name=f"target.{i}.id", value=target.target_id)
                ET.SubElement(properties, "property", name=f"target.{i}.name", value=target.name)
                ET.SubElement(properties, "property", name=f"target.{i}.type", value=target.target_type)
        else:
            ET.SubElement(properties, "property", name="target.id", value=results.target.target_id)
            ET.SubElement(properties, "property", name="target.name", value=results.target.name)
            ET.SubElement(properties, "property", name="target.type", value=results.target.target_type)

        # Create testcase for each finding
        for finding in findings:
            testcase = ET.SubElement(testsuite, "testcase")
            testcase.set("name", finding.title)
            testcase.set("classname", finding.category)

            # Add failure element for critical/high findings
            if finding.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                failure = ET.SubElement(testcase, "failure")
                failure.set("message", f"{finding.severity.value.upper()}: {finding.title}")
                failure.set("type", finding.severity.value)
                failure.text = finding.description

            # Add error element for medium findings
            elif finding.severity == FindingSeverity.MEDIUM:
                error = ET.SubElement(testcase, "error")
                error.set("message", f"{finding.severity.value.upper()}: {finding.title}")
                error.set("type", finding.severity.value)
                error.text = finding.description

            # Add system-out with details for all findings
            system_out = ET.SubElement(testcase, "system-out")
            details = [f"ID: {finding.finding_id}", f"Category: {finding.category}", f"Severity: {finding.severity.value.upper()}"]

            if finding.remediation:
                details.append(f"Remediation: {finding.remediation}")

            if finding.compliance:
                compliance_details = []
                for framework, controls in finding.compliance.items():
                    compliance_details.append(f"{framework}: {', '.join(controls)}")
                details.append("Compliance: " + "; ".join(compliance_details))

            if include_evidence and finding.evidence:
                evidence_details = []
                for evidence in finding.evidence:
                    evidence_details.append(f"{evidence.title} ({evidence.evidence_type}): {evidence.description}")
                details.append("Evidence: " + "; ".join(evidence_details))

            system_out.text = "\n".join(details)

        # Format the XML with proper indentation
        xml_str = ET.tostring(testsuite, encoding="unicode")
        pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")

        return pretty_xml

    def _severity_to_sarif_level(self, severity: FindingSeverity) -> str:
        """
        Convert FindingSeverity to SARIF level.

        Args:
            severity: FindingSeverity enum value

        Returns:
            SARIF level string
        """
        mapping = {
            FindingSeverity.CRITICAL: "error",
            FindingSeverity.HIGH: "error",
            FindingSeverity.MEDIUM: "warning",
            FindingSeverity.LOW: "note",
            FindingSeverity.INFO: "note"
        }
        return mapping.get(severity, "warning")


def format_json_output(
    data: Dict[str, Any],
    indent: int = 2,
    sort_keys: bool = False
) -> str:
    """
    Format data as JSON.

    Args:
        data: Data to format
        indent: JSON indentation level
        sort_keys: Whether to sort keys

    Returns:
        JSON-formatted string
    """
    return json.dumps(data, indent=indent, sort_keys=sort_keys, default=str)


def format_csv_output(
    data: List[Dict[str, Any]],
    field_names: Optional[List[str]] = None,
    delimiter: str = ','
) -> str:
    """
    Format data as CSV.

    Args:
        data: List of dictionaries to format
        field_names: List of field names to include (defaults to all keys in first dict)
        delimiter: CSV delimiter character

    Returns:
        CSV-formatted string
    """
    if not data:
        return ""

    output = io.StringIO()

    # If field_names not specified, use keys from first item
    if not field_names:
        field_names = list(data[0].keys())

    writer = csv.DictWriter(
        output,
        fieldnames=field_names,
        delimiter=delimiter,
        extrasaction='ignore'
    )

    writer.writeheader()
    writer.writerows(data)

    return output.getvalue()


def format_xml_output(
    data: Dict[str, Any],
    root_element: str = "assessment_result",
    pretty_print: bool = True
) -> str:
    """
    Format data as XML.

    Args:
        data: Data to format
        root_element: Name for the XML root element
        pretty_print: Whether to format with indentation

    Returns:
        XML-formatted string
    """
    try:
        import xml.etree.ElementTree as ET
        from xml.dom import minidom
    except ImportError:
        logger.error("XML libraries not available")
        return f"<error>XML formatting libraries not available</error>"

    def _convert_dict_to_xml(parent: ET.Element, data_dict: Dict[str, Any]) -> None:
        """Convert a dictionary to XML elements."""
        for key, value in data_dict.items():
            # Create valid XML element name (remove spaces, non-alphanumeric chars)
            key = ''.join(c for c in key if c.isalnum() or c in '_-')
            key = key.lower()

            if key == '':
                key = 'item'

            # Handle different types
            if isinstance(value, dict):
                element = ET.SubElement(parent, key)
                _convert_dict_to_xml(element, value)
            elif isinstance(value, list):
                list_element = ET.SubElement(parent, key + '_list')
                for item in value:
                    if isinstance(item, dict):
                        item_element = ET.SubElement(list_element, key)
                        _convert_dict_to_xml(item_element, item)
                    else:
                        item_element = ET.SubElement(list_element, 'item')
                        item_element.text = str(item)
            else:
                element = ET.SubElement(parent, key)
                element.text = str(value)

    # Create root element and populate
    root = ET.Element(root_element)
    _convert_dict_to_xml(root, data)

    # Convert to string
    xml_str = ET.tostring(root, encoding='unicode')

    # Pretty print if requested
    if pretty_print:
        xml_str = minidom.parseString(xml_str).toprettyxml(indent="  ")

    return xml_str


def format_html_output(
    data: Dict[str, Any],
    title: str = "Assessment Report",
    include_css: bool = True
) -> str:
    """
    Format data as HTML.

    Args:
        data: Data to format
        title: HTML document title
        include_css: Whether to include basic CSS styling

    Returns:
        HTML-formatted string
    """
    html = ["<!DOCTYPE html>", "<html>", "<head>"]
    html.append(f"  <title>{title}</title>")

    if include_css:
        html.append("  <style>")
        html.append("    body { font-family: Arial, sans-serif; margin: 20px; }")
        html.append("    h1 { color: #0066cc; }")
        html.append("    table { border-collapse: collapse; width: 100%; }")
        html.append("    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }")
        html.append("    tr:nth-child(even) { background-color: #f2f2f2; }")
        html.append("    .section { margin-bottom: 30px; }")
        html.append("  </style>")

    html.append("</head>")
    html.append("<body>")

    # Convert data to HTML
    html.append(f"  <h1>{title}</h1>")

    def _render_dict(d: Dict[str, Any], level: int = 0) -> None:
        """Render a dictionary as HTML."""
        html.append("  <table>")

        for key, value in d.items():
            html.append("    <tr>")
            html.append(f"      <th>{key}</th>")

            # Handle different value types
            if isinstance(value, dict):
                html.append("      <td>")
                _render_dict(value, level + 1)
                html.append("      </td>")
            elif isinstance(value, list):
                if value and isinstance(value[0], dict):
                    # List of dictionaries
                    html.append("      <td>")
                    _render_list_of_dicts(value, level + 1)
                    html.append("      </td>")
                else:
                    # Simple list
                    html.append(f"      <td>{', '.join(str(item) for item in value)}</td>")
            else:
                html.append(f"      <td>{value}</td>")

            html.append("    </tr>")

        html.append("  </table>")

    def _render_list_of_dicts(items: List[Dict[str, Any]], level: int = 0) -> None:
        """Render a list of dictionaries as HTML tables."""
        for i, item in enumerate(items):
            if i > 0:
                html.append("  <hr>")
            _render_dict(item, level + 1)

    # Render the data
    _render_dict(data)

    html.append("</body>")
    html.append("</html>")

    return "\n".join(html)


def format_markdown_output(
    data: Dict[str, Any],
    title: str = "Assessment Report"
) -> str:
    """
    Format data as Markdown.

    Args:
        data: Data to format
        title: Markdown document title

    Returns:
        Markdown-formatted string
    """
    md = [f"# {title}", ""]

    def _render_dict(d: Dict[str, Any], level: int = 0) -> None:
        """Render a dictionary as Markdown."""
        for key, value in d.items():
            # Handle different value types
            if isinstance(value, dict):
                md.append(f"{'#' * (level + 2)} {key}")
                md.append("")
                _render_dict(value, level + 1)
            elif isinstance(value, list):
                md.append(f"{'#' * (level + 2)} {key}")
                md.append("")
                if value and isinstance(value[0], dict):
                    # List of dictionaries
                    _render_list_of_dicts(value, level + 1)
                else:
                    # Simple list
                    for item in value:
                        md.append(f"- {item}")
                    md.append("")
            else:
                md.append(f"**{key}:** {value}  ")

        md.append("")

    def _render_list_of_dicts(items: List[Dict[str, Any]], level: int = 0) -> None:
        """Render a list of dictionaries as Markdown."""
        for i, item in enumerate(items):
            md.append(f"### Item {i+1}")
            _render_dict(item, level + 1)
            md.append("---")
            md.append("")

    # Render the data
    _render_dict(data)

    return "\n".join(md)


def generate_summary(
    findings: List[Dict[str, Any]],
    include_details: bool = False
) -> Dict[str, Any]:
    """
    Generate a summary of findings.

    Args:
        findings: List of finding dictionaries to summarize
        include_details: Whether to include detailed finding information

    Returns:
        Summary dictionary
    """
    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Count findings by category
    categories = {}
    for finding in findings:
        category = finding.get("category", "uncategorized")
        categories[category] = categories.get(category, 0) + 1

    # Build summary
    summary = {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "categories": categories,
        "timestamp": datetime.datetime.now().isoformat()
    }

    # Add top findings if requested
    if include_details:
        # Sort by severity (critical, high, medium, low, info)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "").lower(), 5)
        )

        # Include top findings
        summary["top_findings"] = sorted_findings[:5] if len(sorted_findings) > 5 else sorted_findings

    return summary


def export_findings(
    findings: List[Dict[str, Any]],
    output_format: str = "json",
    output_file: Optional[str] = None
) -> Union[str, bool]:
    """
    Export findings in the specified format.

    Args:
        findings: List of finding dictionaries to export
        output_format: Format to export in
        output_file: Optional output file path

    Returns:
        Formatted string or True if written to file
    """
    formatter = ResultFormatter()

    # Create a minimal AssessmentResult for formatting
    from datetime import datetime
    result = AssessmentResult(
        assessment_id="export",
        name="Exported Findings",
        target={},  # Minimal target
        findings=[],  # Will be replaced by the formatter
        start_time=datetime.now(),
        end_time=datetime.now()
    )

    # Format the findings
    formatted_content = formatter.format(
        results=result,
        format_type=output_format,
        include_evidence=True,
        filter_severity=None
    )

    if output_file:
        return formatter.write_to_file(formatted_content, output_file)
    else:
        return formatted_content
