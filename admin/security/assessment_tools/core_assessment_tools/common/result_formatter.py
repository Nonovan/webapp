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
FORMAT_PDF = "pdf"  # PDF format
FORMAT_YAML = "yaml"  # Add to the format constants

# Valid output formats
VALID_OUTPUT_FORMATS = [
    FORMAT_JSON, FORMAT_CSV, FORMAT_XML, FORMAT_HTML, FORMAT_MARKDOWN,
    FORMAT_TEXT, FORMAT_STANDARD, FORMAT_SARIF, FORMAT_JUNIT, FORMAT_PDF, FORMAT_YAML
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
    ) -> Union[str, bytes]:
        """
        Format assessment results into the specified format.

        Args:
            results: AssessmentResult object to format
            format_type: Output format type (json, csv, xml, html, markdown, etc.)
            include_evidence: Whether to include evidence details
            filter_severity: List of severity levels to include
            compliance_map: List of compliance frameworks to map findings to

        Returns:
            Formatted results as string or bytes
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
            elif format_type == FORMAT_PDF:
                return self._format_pdf(results, findings, include_evidence)
            elif format_type == FORMAT_YAML:
                return self._format_yaml(results, findings, include_evidence)
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

    def _format_pdf(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> bytes:
        """
        Format results as PDF.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            PDF-formatted results as bytes
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from io import BytesIO
        except ImportError:
            self.logger.error("PDF generation libraries not available. Install reportlab package.")
            return b"Error: PDF generation libraries not available"

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Add report title
        title_style = styles["Title"]
        elements.append(Paragraph(f"Security Assessment Results - {results.assessment_id}", title_style))
        elements.append(Spacer(1, 12))

        # Add assessment details
        elements.append(Paragraph(f"Assessment Name: {results.name}", styles["Normal"]))
        elements.append(Paragraph(f"Date: {results.end_time.strftime('%Y-%m-%d %H:%M:%S') if results.end_time else datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        elements.append(Spacer(1, 12))

        # Add target information
        elements.append(Paragraph("Target Information", styles["Heading2"]))

        if isinstance(results.target, list):
            target_data = [["Target ID", "Name", "Type"]]
            for target in results.target:
                target_data.append([target.target_id, target.name, target.target_type])
        else:
            target_data = [["Target ID", "Name", "Type"],
                        [results.target.target_id, results.target.name, results.target.target_type]]

        target_table = Table(target_data)
        target_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(target_table)
        elements.append(Spacer(1, 12))

        # Add findings summary
        elements.append(Paragraph("Findings Summary", styles["Heading2"]))

        # Calculate severity counts
        severity_count = {s.value: 0 for s in FindingSeverity}
        for finding in findings:
            severity_count[finding.severity.value] += 1

        summary_data = [["Severity", "Count"]]
        for severity in ["critical", "high", "medium", "low", "info"]:
            summary_data.append([severity.capitalize(), str(severity_count[severity])])
        summary_data.append(["Total", str(len(findings))])

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            # Color rows by severity
            ('BACKGROUND', (0, 1), (-1, 1), colors.pink),  # critical
            ('BACKGROUND', (0, 2), (-1, 2), colors.orange),  # high
            ('BACKGROUND', (0, 3), (-1, 3), colors.lightblue),  # medium
            ('BACKGROUND', (0, 4), (-1, 4), colors.lightgreen),  # low
            ('BACKGROUND', (0, 5), (-1, 5), colors.white),  # info
            ('BACKGROUND', (0, 6), (-1, 6), colors.grey),  # total
            ('FONTNAME', (0, 6), (-1, 6), 'Helvetica-Bold')
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        # Add detailed findings
        elements.append(Paragraph("Detailed Findings", styles["Heading2"]))

        for i, finding in enumerate(findings):
            elements.append(Paragraph(f"{i+1}. {finding.title}", styles["Heading3"]))

            # Create finding details table
            details_data = [
                ["ID", finding.finding_id],
                ["Severity", finding.severity.value.upper()],
                ["Category", finding.category],
                ["Status", finding.status.value if finding.status else "New"]
            ]

            if finding.cvss:
                details_data.append(["CVSS", str(finding.cvss.base_score)])

            details_table = Table(details_data, colWidths=[100, 400])
            details_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
            ]))
            elements.append(details_table)
            elements.append(Spacer(1, 10))

            # Description
            elements.append(Paragraph("Description", styles["Heading4"]))
            elements.append(Paragraph(finding.description, styles["Normal"]))

            # Remediation if available
            if finding.remediation:
                elements.append(Paragraph("Remediation", styles["Heading4"]))
                elements.append(Paragraph(finding.remediation, styles["Normal"]))

            # Evidence if requested
            if include_evidence and finding.evidence:
                elements.append(Paragraph("Evidence", styles["Heading4"]))
                for evidence in finding.evidence:
                    elements.append(Paragraph(f"<b>{evidence.title}</b> ({evidence.evidence_type})", styles["Normal"]))
                    elements.append(Paragraph(evidence.description, styles["Normal"]))

            # Compliance mappings if available
            if finding.compliance:
                elements.append(Paragraph("Compliance", styles["Heading4"]))
                compliance_data = [["Framework", "Controls"]]
                for framework, controls in finding.compliance.items():
                    compliance_data.append([framework, ", ".join(controls)])

                compliance_table = Table(compliance_data)
                compliance_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold')
                ]))
                elements.append(compliance_table)

            elements.append(Spacer(1, 20))

        # Footer
        elements.append(Paragraph(f"Generated by Security Assessment Tools on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))

        # Build PDF
        doc.build(elements)

        return buffer.getvalue()

    def _format_yaml(
        self,
        results: AssessmentResult,
        findings: List[Finding],
        include_evidence: bool
    ) -> str:
        """
        Format results as YAML.

        Args:
            results: Assessment results to format
            findings: Filtered findings
            include_evidence: Whether to include evidence

        Returns:
            YAML-formatted results
        """
        try:
            import yaml
        except ImportError:
            self.logger.error("YAML libraries not available")
            return "Error: YAML libraries not available. Install PyYAML package."

        # Convert results to dictionary with filtered findings
        data_dict = results.to_dict()
        data_dict["findings"] = [f.to_dict() for f in findings]

        # Remove evidence if not requested
        if not include_evidence:
            for finding in data_dict["findings"]:
                if "evidence" in finding:
                    del finding["evidence"]

        # Convert to YAML
        return yaml.dump(data_dict, default_flow_style=False, sort_keys=False)

    def format_from_template(
        self,
        results: AssessmentResult,
        template_path: str,
        output_format: str = FORMAT_HTML
    ) -> str:
        """
        Format results using a custom template.

        Args:
            results: Assessment results to format
            template_path: Path to the template file
            output_format: Output format type

        Returns:
            Formatted results using the template
        """
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
            import os
        except ImportError:
            self.logger.error("Jinja2 template library not available")
            return "Error: Template library not available. Install jinja2 package."

        try:
            # Set up the template environment
            template_dir = os.path.dirname(template_path)
            template_file = os.path.basename(template_path)

            env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )

            template = env.get_template(template_file)

            # Prepare data for the template
            severity_counts = {s.value: 0 for s in FindingSeverity}
            for finding in results.findings:
                severity_counts[finding.severity.value] += 1

            template_data = {
                "assessment": {
                    "id": results.assessment_id,
                    "name": results.name,
                    "start_time": results.start_time,
                    "end_time": results.end_time if results.end_time else datetime.datetime.now(),
                    "status": results.status
                },
                "target": results.target.to_dict() if not isinstance(results.target, list)
                        else [t.to_dict() for t in results.target],
                "findings": [f.to_dict() for f in results.findings],
                "summary": {
                    "total_findings": len(results.findings),
                    "severity_counts": severity_counts,
                    "risk_score": self._calculate_risk_score(results)
                },
                "timestamp": datetime.datetime.now()
            }

            # Render the template
            return template.render(**template_data)

        except Exception as e:
            self.logger.error(f"Error formatting results with template: {str(e)}", exc_info=True)
            return f"Error formatting results with template: {str(e)}"

    def generate_executive_summary(
        self,
        results: AssessmentResult,
        format_type: str = FORMAT_MARKDOWN,
        risk_threshold: str = "medium"
    ) -> str:
        """
        Generate an executive summary from assessment results.

        Args:
            results: Assessment results to summarize
            format_type: Output format type (markdown, html, pdf, etc.)
            risk_threshold: Only include findings at or above this severity

        Returns:
            Executive summary in the specified format
        """
        # Filter findings by threshold
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4
        }
        threshold_value = severity_order.get(risk_threshold.lower(), 2)  # Default to medium

        filtered_findings = [
            f for f in results.findings
            if severity_order.get(f.severity.value, 4) <= threshold_value
        ]

        # Calculate severity counts
        severity_counts = {s.value: 0 for s in FindingSeverity}
        for finding in filtered_findings:
            severity_counts[finding.severity.value] += 1

        # Calculate risk score
        risk_score = self._calculate_risk_score(results)

        # Determine overall risk level
        if risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Generate summary content based on format
        if format_type == FORMAT_MARKDOWN:
            summary = [
                f"# Executive Summary - {results.assessment_id}",
                "",
                f"**Assessment:** {results.name}",
                f"**Date:** {results.end_time.strftime('%Y-%m-%d') if results.end_time else datetime.datetime.now().strftime('%Y-%m-%d')}",
                f"**Overall Risk Level:** {risk_level} (Score: {risk_score:.1f}/100)",
                "",
                "## Key Findings",
                ""
            ]

            if not filtered_findings:
                summary.append("No significant security issues were identified.")
            else:
                summary.append("| Severity | Count |")
                summary.append("|----------|-------|")
                for severity in ["critical", "high", "medium", "low"]:
                    if severity_counts[severity] > 0:
                        summary.append(f"| {severity.capitalize()} | {severity_counts[severity]} |")

                summary.append("")
                summary.append("### Top Issues")

                # Sort by severity and limit to top 5
                sorted_findings = sorted(filtered_findings, key=lambda f: severity_order.get(f.severity.value, 4))
                for i, finding in enumerate(sorted_findings[:5]):
                    summary.append(f"**{i+1}. {finding.title}** ({finding.severity.value.upper()})")
                    summary.append(f"   - {finding.description.split('.')[0]}.")  # First sentence only

                if len(filtered_findings) > 5:
                    summary.append(f"\n*Plus {len(filtered_findings) - 5} additional findings...*")

            summary.append("\n## Recommendations")
            summary.append("\n1. Address all Critical and High severity findings as soon as possible")
            summary.append("2. Develop a remediation plan for Medium severity findings")
            summary.append("3. Schedule a follow-up assessment to verify remediation effectiveness")

            return "\n".join(summary)

        elif format_type == FORMAT_HTML:
            # Similar HTML implementation...
            pass

        else:
            # For other formats, format a simplified results with filtered findings
            simplified_result = AssessmentResult(
                assessment_id=results.assessment_id,
                name=f"Executive Summary - {results.name}",
                target=results.target,
                findings=filtered_findings,
                start_time=results.start_time,
                end_time=results.end_time,
                status=results.status
            )

            return self.format(
                results=simplified_result,
                format_type=format_type,
                include_evidence=False
            )

    def generate_diff_report(
        self,
        old_results: AssessmentResult,
        new_results: AssessmentResult,
        format_type: str = FORMAT_MARKDOWN
    ) -> str:
        """
        Generate a diff report comparing two assessment results.

        Args:
            old_results: Previous assessment results
            new_results: Current assessment results
            format_type: Output format type

        Returns:
            Formatted diff report
        """
        # Find common and different findings
        old_findings_dict = {f.finding_id: f for f in old_results.findings}
        new_findings_dict = {f.finding_id: f for f in new_results.findings}

        # Categorize findings
        new_findings = []
        fixed_findings = []
        changed_findings = []
        unchanged_findings = []

        for find_id, finding in new_findings_dict.items():
            if find_id not in old_findings_dict:
                new_findings.append(finding)
            else:
                old = old_findings_dict[find_id]
                if old.status != finding.status or old.severity != finding.severity:
                    changed_findings.append((old, finding))
                else:
                    unchanged_findings.append(finding)

        for find_id, finding in old_findings_dict.items():
            if find_id not in new_findings_dict:
                fixed_findings.append(finding)

        # Generate the diff report based on the format
        if format_type == FORMAT_MARKDOWN:
            report = [
                f"# Assessment Comparison Report",
                f"**Previous Assessment:** {old_results.assessment_id} ({old_results.end_time.strftime('%Y-%m-%d') if old_results.end_time else 'Unknown'})",
                f"**Current Assessment:** {new_results.assessment_id} ({new_results.end_time.strftime('%Y-%m-%d') if new_results.end_time else datetime.datetime.now().strftime('%Y-%m-%d')})",
                "",
                "## Summary of Changes",
                "",
                f"* **New Findings:** {len(new_findings)}",
                f"* **Fixed Findings:** {len(fixed_findings)}",
                f"* **Changed Findings:** {len(changed_findings)}",
                f"* **Unchanged Findings:** {len(unchanged_findings)}",
                "",
            ]

            if new_findings:
                report.append("## New Findings")
                report.append("")
                for finding in new_findings:
                    report.append(f"### {finding.title} ({finding.severity.value.upper()})")
                    report.append(f"**ID:** {finding.finding_id}  ")
                    report.append(f"**Category:** {finding.category}  ")
                    report.append("")
                    report.append(finding.description)
                    report.append("")

            if fixed_findings:
                report.append("## Fixed Findings")
                report.append("")
                for finding in fixed_findings:
                    report.append(f"* **{finding.title}** ({finding.severity.value.upper()}) - ID: {finding.finding_id}")
                report.append("")

            if changed_findings:
                report.append("## Changed Findings")
                report.append("")
                for old, new in changed_findings:
                    report.append(f"### {new.title}")
                    report.append(f"**ID:** {new.finding_id}  ")

                    if old.severity != new.severity:
                        report.append(f"**Severity:** {old.severity.value.upper()} → {new.severity.value.upper()}  ")
                    else:
                        report.append(f"**Severity:** {new.severity.value.upper()}  ")

                    if old.status != new.status:
                        report.append(f"**Status:** {old.status.value if old.status else 'New'} → {new.status.value if new.status else 'New'}  ")

                    report.append("")

            return "\n".join(report)
        else:
            # Handle other formats...
            pass

    def _format_csv_output(self, data: List[Dict[str, Any]]) -> str:
        """
        Format a list of dictionaries as CSV.

        Args:
            data: List of dictionaries to format as CSV.

        Returns:
            CSV-formatted string.
        """
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()

    def _format_xml_output(self, data: Dict[str, Any]) -> str:
        """
        Format a dictionary as XML.

        Args:
            data: Dictionary to format as XML.

        Returns:
            XML-formatted string.
        """
        try:
            import xml.etree.ElementTree as ET

            def dict_to_xml(tag: str, d: Dict[str, Any]) -> ET.Element:
                elem = ET.Element(tag)
                for key, val in d.items():
                    child = ET.SubElement(elem, key)
                    child.text = str(val)
                return elem

            root = dict_to_xml("root", data)
            return ET.tostring(root, encoding="unicode")
        except Exception as e:
            self.logger.error(f"Error formatting XML: {str(e)}", exc_info=True)
            return f"Error formatting XML: {str(e)}"

    def convert_format(
        self,
        content: str,
        input_format: str,
        output_format: str
    ) -> str:
        """
        Convert content from one format to another.

        Args:
            content: Content to convert
            input_format: Current format of content
            output_format: Desired output format

        Returns:
            Converted content
        """
        # For JSON to other formats, parse and then format
        if input_format == FORMAT_JSON:
            try:
                data = json.loads(content)

                # Convert to AssessmentResult if needed
                if "assessment_id" in data and "findings" in data:
                    from .data_types import AssessmentResult

                    # Create an AssessmentResult instance
                    result = AssessmentResult(
                        assessment_id=data["assessment_id"],
                        name=data.get("name", "Converted Assessment"),
                        target=data.get("target", {}),
                        findings=data.get("findings", []),
                        status=data.get("status", "completed")
                    )

                    # Format using the desired output format
                    return self.format(result, format_type=output_format)
                else:
                    # Generic conversion based on format
                    if output_format == FORMAT_CSV:
                        if isinstance(data, list):
                            return self._format_csv_output(data)
                        else:
                            return self._format_csv_output([data])
                    elif output_format == FORMAT_XML:
                        return self._format_xml_output(data)
                    elif output_format == FORMAT_HTML:
                        return self._format_html(None, [], False, data)
                    elif output_format == FORMAT_MARKDOWN:
                        return self._format_markdown(None, [], False, data)
                    elif output_format == FORMAT_TEXT:
                        return str(data)
                    else:
                        raise ValueError(f"Unsupported output format: {output_format}")

            except Exception as e:
                self.logger.error(f"Error converting format: {str(e)}", exc_info=True)
                return f"Error converting format: {str(e)}"
        else:
            self.logger.error(f"Conversion from {input_format} to {output_format} not supported")
            return f"Conversion from {input_format} to {output_format} not supported"


def generate_summary(
    results: AssessmentResult,
    format_type: str = FORMAT_MARKDOWN,
    severity_threshold: str = "low",
    max_findings: int = 10
) -> str:
    """
    Generate a summary of assessment findings.

    This standalone function creates a concise summary of assessment results
    without requiring direct instantiation of ResultFormatter. It's useful
    for quick reporting and dashboard displays.

    Args:
        results: Assessment results to summarize
        format_type: Output format type (markdown, html, text, etc.)
        severity_threshold: Minimum severity level to include in summary
        max_findings: Maximum number of findings to include in summary details

    Returns:
        Formatted summary in the requested format
    """
    # Use ResultFormatter to keep format consistency with other outputs
    formatter = ResultFormatter()

    # Map severity threshold to internal levels
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }
    threshold_value = severity_order.get(severity_threshold.lower(), 3)  # Default to low

    # Filter findings by threshold
    filtered_findings = [
        f for f in results.findings
        if severity_order.get(f.severity.value, 4) <= threshold_value
    ]

    # Count findings by severity
    severity_counts = {s.value: 0 for s in FindingSeverity}
    for finding in filtered_findings:
        severity_counts[finding.severity.value] += 1

    # Sort findings by severity for top findings section
    sorted_findings = sorted(
        filtered_findings,
        key=lambda f: (severity_order.get(f.severity.value, 4), f.finding_id)
    )

    # Calculate total risk score
    risk_score = formatter._calculate_risk_score(results)

    # Determine overall risk level
    if risk_score >= 75:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 25:
        risk_level = "Medium"
    elif risk_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Negligible"

    # Generate output based on requested format
    if format_type == FORMAT_MARKDOWN:
        output = [
            f"# Assessment Summary - {results.name}",
            "",
            f"**Assessment ID:** {results.assessment_id}",
            f"**Date:** {results.end_time.strftime('%Y-%m-%d') if results.end_time else datetime.datetime.now().strftime('%Y-%m-%d')}",
            f"**Risk Level:** {risk_level}",
            "",
            "## Findings Overview",
            "",
            "| Severity | Count |",
            "|----------|-------|"
        ]

        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity_counts[severity] > 0:
                output.append(f"| {severity.capitalize()} | {severity_counts[severity]} |")

        output.append("")
        output.append(f"**Total Findings:** {len(filtered_findings)}")
        output.append("")

        # Add top findings section if any exist
        if sorted_findings:
            output.append("## Top Findings")
            output.append("")

            for i, finding in enumerate(sorted_findings[:max_findings]):
                if i >= max_findings:
                    break
                output.append(f"**{i+1}. {finding.title}** ({finding.severity.value.upper()})")
                # Add first sentence of description for context
                first_sentence = finding.description.split('.')[0] + '.'
                output.append(f"   - {first_sentence}")
                output.append("")

            if len(sorted_findings) > max_findings:
                output.append(f"*Plus {len(sorted_findings) - max_findings} additional findings...*")

        return "\n".join(output)

    elif format_type == FORMAT_HTML:
        # Basic HTML summary implementation
        output = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            f"<title>Assessment Summary - {results.name}</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; }",
            "h1, h2 { color: #333; }",
            "table { border-collapse: collapse; width: 100%; margin: 20px 0; }",
            "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "th { background-color: #f2f2f2; }",
            ".critical { color: #721c24; background-color: #f8d7da; }",
            ".high { color: #856404; background-color: #fff3cd; }",
            ".medium { color: #0c5460; background-color: #d1ecf1; }",
            ".low { color: #155724; background-color: #d4edda; }",
            ".info { color: #383d41; background-color: #e2e3e5; }",
            "</style>",
            "</head>",
            "<body>",
            f"<h1>Assessment Summary - {results.name}</h1>",
            f"<p><strong>Assessment ID:</strong> {results.assessment_id}</p>",
            f"<p><strong>Date:</strong> {results.end_time.strftime('%Y-%m-%d') if results.end_time else datetime.datetime.now().strftime('%Y-%m-%d')}</p>",
            f"<p><strong>Risk Level:</strong> {risk_level}</p>",
            "<h2>Findings Overview</h2>",
            "<table>",
            "<tr><th>Severity</th><th>Count</th></tr>"
        ]

        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity_counts[severity] > 0:
                output.append(f"<tr class='{severity}'><td>{severity.capitalize()}</td><td>{severity_counts[severity]}</td></tr>")

        output.append("</table>")
        output.append(f"<p><strong>Total Findings:</strong> {len(filtered_findings)}</p>")

        # Add top findings section if any exist
        if sorted_findings:
            output.append("<h2>Top Findings</h2>")
            output.append("<ol>")

            for i, finding in enumerate(sorted_findings[:max_findings]):
                if i >= max_findings:
                    break
                severity_class = finding.severity.value.lower()
                output.append(f"<li><strong class='{severity_class}'>{finding.title} ({finding.severity.value.upper()})</strong><br>")
                # Add first sentence of description for context
                first_sentence = finding.description.split('.')[0] + '.'
                output.append(f"<p>{first_sentence}</p></li>")

            output.append("</ol>")

            if len(sorted_findings) > max_findings:
                output.append(f"<p><em>Plus {len(sorted_findings) - max_findings} additional findings...</em></p>")

        output.append("</body>")
        output.append("</html>")

        return "\n".join(output)

    elif format_type == FORMAT_JSON:
        # Create structured summary data
        summary_data = {
            "assessment_id": results.assessment_id,
            "name": results.name,
            "date": (results.end_time if results.end_time else datetime.datetime.now()).isoformat(),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "findings": {
                "total": len(filtered_findings),
                "severity_counts": severity_counts,
                "top_findings": [
                    {
                        "id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "category": f.category,
                        "status": f.status.value if f.status else "new"
                    }
                    for f in sorted_findings[:max_findings]
                ]
            }
        }

        return json.dumps(summary_data, indent=2)

    elif format_type == FORMAT_TEXT:
        # Simple text summary
        width = 80
        separator = "=" * width

        output = [
            separator,
            f"ASSESSMENT SUMMARY - {results.name}".center(width),
            separator,
            f"Assessment ID: {results.assessment_id}",
            f"Date: {results.end_time.strftime('%Y-%m-%d') if results.end_time else datetime.datetime.now().strftime('%Y-%m-%d')}",
            f"Risk Level: {risk_level}",
            "",
            "FINDINGS OVERVIEW".center(width),
            "-" * width
        ]

        # Format severity counts as a simple table
        output.append(f"{'Severity':<15} {'Count':<10}")
        output.append("-" * 25)
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity_counts[severity] > 0:
                output.append(f"{severity.capitalize():<15} {severity_counts[severity]:<10}")

        output.append("")
        output.append(f"Total Findings: {len(filtered_findings)}")
        output.append("")

        # Add top findings section if any exist
        if sorted_findings:
            output.append("TOP FINDINGS".center(width))
            output.append("-" * width)

            for i, finding in enumerate(sorted_findings[:max_findings]):
                if i >= max_findings:
                    break
                output.append(f"{i+1}. {finding.title} ({finding.severity.value.upper()})")
                # Add first sentence of description for context
                first_sentence = finding.description.split('.')[0] + '.'
                wrapped_text = textwrap.fill(first_sentence, width=width-3)
                # Indent the wrapped text
                wrapped_lines = wrapped_text.split('\n')
                output.append(f"   {wrapped_lines[0]}")
                for line in wrapped_lines[1:]:
                    output.append(f"   {line}")
                output.append("")

            if len(sorted_findings) > max_findings:
                output.append(f"Plus {len(sorted_findings) - max_findings} additional findings...")

        return "\n".join(output)

    else:
        # Use default formatter for other formats
        formatter = ResultFormatter()
        filtered_result = AssessmentResult(
            assessment_id=results.assessment_id,
            name=f"Summary - {results.name}",
            target=results.target,
            findings=sorted_findings[:max_findings],
            start_time=results.start_time,
            end_time=results.end_time,
            status="completed",
            summary={
                "severity_counts": severity_counts,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "total_findings": len(filtered_findings)
            }
        )

        return formatter.format(filtered_result, format_type=format_type)


def export_findings(
    results: AssessmentResult,
    output_file: str,
    format_type: str = FORMAT_JSON,
    filter_severity: Optional[List[str]] = None,
    findings_only: bool = False,
    include_evidence: bool = False,
    compliance_map: Optional[List[str]] = None
) -> bool:
    """
    Export assessment findings to a file in specified format.

    This standalone function exports assessment findings to a file without requiring
    direct instantiation of ResultFormatter. It provides a simplified interface
    for the most common use case of exporting findings.

    Args:
        results: Assessment results to export
        output_file: Path to output file
        format_type: Output format (json, csv, xml, html, markdown, etc.)
        filter_severity: Optional list of severity levels to include
        findings_only: If True, export only findings without assessment metadata
        include_evidence: Whether to include evidence details
        compliance_map: Optional list of compliance frameworks to map findings to

    Returns:
        True if export was successful, False otherwise
    """
    try:
        # Validate output format
        if format_type.lower() not in VALID_OUTPUT_FORMATS:
            logger.warning(f"Unsupported format '{format_type}', using '{FORMAT_STANDARD}'")
            format_type = FORMAT_STANDARD

        formatter = ResultFormatter()

        # Apply severity filter if specified
        if filter_severity is not None:
            filtered_findings = formatter._filter_findings_by_severity(results.findings, filter_severity)
        else:
            filtered_findings = results.findings

        # Apply compliance mapping if requested
        if compliance_map is not None:
            filtered_findings = formatter._map_findings_to_compliance(filtered_findings, compliance_map)

        # Create output path directory if it doesn't exist
        output_path = Path(output_file)
        if not output_path.parent.exists():
            output_path.parent.mkdir(parents=True, exist_ok=True)

        if findings_only:
            # Export only the findings without the full assessment context
            if format_type.lower() == FORMAT_JSON:
                # For JSON, export findings as array of dictionaries
                findings_data = [finding.to_dict() for finding in filtered_findings]
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(findings_data, f, indent=2, default=str)
                return True

            elif format_type.lower() == FORMAT_CSV:
                # For CSV, convert findings to flat structure
                if not filtered_findings:
                    logger.warning("No findings to export")
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write("No findings to export")
                    return True

                # Extract common fields from findings
                finding_dicts = []
                for finding in filtered_findings:
                    finding_dict = {
                        "id": finding.finding_id,
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity.value,
                        "category": finding.category,
                        "status": finding.status.value if finding.status else "new"
                    }

                    if finding.remediation:
                        finding_dict["remediation"] = finding.remediation

                    if include_evidence and finding.evidence:
                        # Simplify evidence to comma-separated list of titles
                        finding_dict["evidence"] = ", ".join(e.title for e in finding.evidence)

                    finding_dicts.append(finding_dict)

                with open(output_file, "w", encoding="utf-8", newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=finding_dicts[0].keys())
                    writer.writeheader()
                    writer.writerows(finding_dicts)
                return True

            else:
                # For other formats, create a minimal assessment result
                minimal_result = AssessmentResult(
                    assessment_id="findings-export",
                    name="Exported Findings",
                    target={},  # Empty target as we're just exporting findings
                    findings=filtered_findings,
                    start_time=datetime.datetime.now(),
                    end_time=datetime.datetime.now(),
                    status="completed"
                )

                # Use the formatter to format and write the minimal result
                formatted_content = formatter.format(
                    results=minimal_result,
                    format_type=format_type,
                    include_evidence=include_evidence
                )

                return formatter.write_to_file(formatted_content, output_file)

        else:
            # Format and export the full assessment result
            formatted_content = formatter.format(
                results=results,
                format_type=format_type,
                include_evidence=include_evidence,
                filter_severity=filter_severity,
                compliance_map=compliance_map
            )

            return formatter.write_to_file(formatted_content, output_file)

    except Exception as e:
        logger.error(f"Error exporting findings: {e}", exc_info=True)
        return False
