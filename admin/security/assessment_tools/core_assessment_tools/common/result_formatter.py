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
