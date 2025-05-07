#!/usr/bin/env python3
"""
Compliance Report Generator

This script generates compliance reports for various regulatory frameworks
by leveraging the compliance validation functionality of the platform.
It provides options for different report formats, targeting specific compliance
frameworks, and customizing the output based on environment and categories.

Usage:
    python admin/scripts/compliance_report_generator.py [options]

Examples:
    # Generate a PCI-DSS compliance report in HTML format
    python admin/scripts/compliance_report_generator.py --standard pci-dss --format html

    # Generate a specific category report for GDPR with a custom output path
    python admin/scripts/compliance_report_generator.py --standard gdpr --categories data-protection --output gdpr-report.pdf
"""

import argparse
import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Union, Any

# Adjust path to import application components
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from flask import Flask
    from models.security.system.compliance_check import ComplianceValidator, ComplianceStatus
    from core.factory import create_app
    from core.security.cs_audit import log_security_event
except ImportError as e:
    print(f"Error importing application modules: {e}", file=sys.stderr)
    print("Please ensure the script is run within the project environment or PYTHONPATH is set correctly.", file=sys.stderr)
    sys.exit(1)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
DEFAULT_OUTPUT_DIR = os.path.join(project_root, "reports", "compliance")
SUPPORTED_FRAMEWORKS = ["pci-dss", "hipaa", "gdpr", "iso27001", "soc2", "fedramp", "nist-csf"]
SUPPORTED_FORMATS = ["json", "html", "text", "pdf"]
REGULATORY_AUTHORITIES = {
    "pci-dss": "Payment Card Industry Security Standards Council",
    "hipaa": "U.S. Department of Health & Human Services",
    "gdpr": "European Data Protection Board",
    "iso27001": "International Organization for Standardization",
    "soc2": "American Institute of CPAs",
    "fedramp": "U.S. General Services Administration",
    "nist-csf": "National Institute of Standards and Technology"
}

__all__ = [
    # Core functions
    "generate_compliance_report",
    "validate_compliance",
    "get_compliance_status",
    "export_compliance_evidence",
    "check_regulatory_requirements",

    # Helper functions
    "parse_arguments",
    "generate_report_filename",
    "ensure_output_directory",
    "load_compliance_mapping",
    "generate_pdf_from_html",
    "enhance_report_with_remediation",
    "append_evidence_to_report",
    "log_compliance_report_generation",

    # Constants
    "DEFAULT_OUTPUT_DIR",
    "SUPPORTED_FRAMEWORKS",
    "SUPPORTED_FORMATS",
    "REGULATORY_AUTHORITIES",

    # Main entry point
    "main"
]


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Generate compliance reports for various standards")

    parser.add_argument(
        "--standard",
        required=True,
        choices=SUPPORTED_FRAMEWORKS,
        help="Compliance standard to validate against"
    )

    parser.add_argument(
        "--environment",
        default=None,
        help="Target environment (e.g., production, staging, development)"
    )

    parser.add_argument(
        "--categories",
        nargs='+',
        default=[],
        help="Specific compliance categories to validate (e.g., access-control, encryption)"
    )

    parser.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default="html",
        help="Output format for the compliance report (default: html)"
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Output file path for the report"
    )

    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Include detailed information in the report"
    )

    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Generate summary report without detailed findings"
    )

    parser.add_argument(
        "--include-evidence",
        action="store_true",
        help="Include evidence data in the report (if available)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--evidence-dir",
        default=None,
        help="Directory containing compliance evidence files"
    )

    parser.add_argument(
        "--remediation-plan",
        action="store_true",
        help="Include remediation plan for failed compliance checks"
    )

    parser.add_argument(
        "--compliance-map",
        default=None,
        help="JSON file mapping controls to specific compliance requirements"
    )

    parser.add_argument(
        "--env",
        default="production",
        help="Application environment to load configuration (default: production)"
    )

    return parser.parse_args()


def generate_report_filename(args: argparse.Namespace) -> str:
    """Generate a default report filename based on arguments."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    env_suffix = f"_{args.environment}" if args.environment else ""
    extension = "pdf" if args.format == "pdf" else args.format

    return f"{args.standard}{env_suffix}_compliance_report_{timestamp}.{extension}"


def ensure_output_directory(output_path: str) -> None:
    """Ensure the output directory exists."""
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)


def load_compliance_mapping(mapping_file: str) -> Dict:
    """Load compliance mapping from a JSON file."""
    try:
        with open(mapping_file, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load compliance mapping file: {e}")
        return {}


def generate_pdf_from_html(html_content: str, output_path: str) -> bool:
    """Generate a PDF file from HTML content."""
    try:
        import weasyprint
    except ImportError:
        logger.error("WeasyPrint is required for PDF generation. Install with: pip install weasyprint")
        return False

    try:
        # Create a temporary HTML file
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(html_content.encode('utf-8'))

        # Generate PDF from HTML
        html = weasyprint.HTML(filename=temp_path)
        html.write_pdf(output_path)

        # Clean up temporary file
        os.unlink(temp_path)

        return True
    except Exception as e:
        logger.error(f"Failed to generate PDF: {e}")
        return False


def enhance_report_with_remediation(report: Dict[str, Any], mapping_file: Optional[str]) -> Dict[str, Any]:
    """Enhance the report with remediation information."""
    # Load remediation guidance if a mapping file is provided
    remediation_guidance = {}
    if mapping_file and os.path.exists(mapping_file):
        try:
            with open(mapping_file, 'r') as f:
                remediation_data = json.load(f)
                remediation_guidance = remediation_data.get('remediation_guidance', {})
        except (IOError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load remediation guidance: {e}")

    # Add remediation guidance to each failed check
    if isinstance(report, dict) and 'compliance_report' in report:
        results = report['compliance_report'].get('results', [])
        for result in results:
            if result.get('status') == ComplianceStatus.FAILED.value:
                control_id = result.get('check', {}).get('control', {}).get('control_id', '')

                # Try to find remediation guidance
                if control_id in remediation_guidance:
                    result['remediation'] = remediation_guidance[control_id]
                else:
                    # Generate generic remediation guidance
                    result['remediation'] = {
                        "steps": ["Review control requirements", "Implement missing controls", "Validate implementation"],
                        "priority": "medium",
                        "estimated_effort": "medium"
                    }

    return report


def append_evidence_to_report(report: Union[str, Dict], evidence_dir: str, format_type: str) -> Union[str, Dict]:
    """Append evidence data to the report."""
    if not evidence_dir or not os.path.exists(evidence_dir):
        logger.warning(f"Evidence directory not found: {evidence_dir}")
        return report

    # Load evidence files
    evidence_data = []
    for filename in os.listdir(evidence_dir):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(evidence_dir, filename), 'r') as f:
                    evidence_item = json.load(f)
                    evidence_data.append(evidence_item)
            except (IOError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to load evidence file {filename}: {e}")

    if not evidence_data:
        logger.warning("No valid evidence files found")
        return report

    # Append evidence based on format type
    if format_type == 'json':
        if isinstance(report, dict) and 'compliance_report' in report:
            report['compliance_report']['evidence'] = evidence_data
        return report

    elif format_type == 'html':
        evidence_html = """
        <div class="section evidence">
            <h2>Compliance Evidence</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Date</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
        """

        for item in evidence_data:
            date = item.get('date', 'Unknown')
            evidence_html += f"""
                <tr>
                    <td>{item.get('id', 'N/A')}</td>
                    <td>{item.get('type', 'N/A')}</td>
                    <td>{date}</td>
                    <td>{item.get('description', 'No description')}</td>
                </tr>
            """

        evidence_html += """
                </tbody>
            </table>
        </div>
        """

        # Insert evidence section before the closing </body> tag
        return report.replace('</body>', f"{evidence_html}\n</body>")

    elif format_type == 'text':
        evidence_text = "\n\nEVIDENCE SUMMARY\n==================\n\n"
        for item in evidence_data:
            evidence_text += f"ID: {item.get('id', 'N/A')}\n"
            evidence_text += f"Type: {item.get('type', 'N/A')}\n"
            evidence_text += f"Date: {item.get('date', 'Unknown')}\n"
            evidence_text += f"Description: {item.get('description', 'No description')}\n\n"

        return report + evidence_text

    else:
        # For other formats (like PDF), return original
        logger.warning(f"Evidence appendage not implemented for format: {format_type}")
        return report


def log_compliance_report_generation(app: Flask, standard: str, environment: Optional[str],
                                    categories: List[str], format_type: str, results: Dict[str, Any]) -> None:
    """Log the compliance report generation in the security audit log."""
    summary = results.get('compliance_report', {}).get('summary', {})
    total_checks = summary.get('total_checks', 0)
    passed = summary.get('passed', 0)
    failed = summary.get('failed', 0)
    overall_status = summary.get('overall_status', 'UNKNOWN')

    event_details = {
        "standard": standard,
        "environment": environment or "default",
        "categories": categories if categories else ["all"],
        "format": format_type,
        "total_checks": total_checks,
        "passed_checks": passed,
        "failed_checks": failed,
        "overall_status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    with app.app_context():
        log_security_event(
            event_type="compliance_report_generated",
            severity="info" if overall_status == ComplianceStatus.PASSED.value else "warning",
            description=f"Generated {standard.upper()} compliance report ({format_type})",
            details=event_details,
            category="compliance"
        )


def generate_compliance_report(app: Flask, args: argparse.Namespace) -> Optional[str]:
    """
    Generate compliance report based on provided arguments.

    Args:
        app: Flask application instance
        args: Command line arguments

    Returns:
        Path to the generated report file if successful, None otherwise
    """
    # Determine output path
    if args.output:
        output_path = args.output
    else:
        os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
        output_path = os.path.join(DEFAULT_OUTPUT_DIR, generate_report_filename(args))

    # Ensure output directory exists
    ensure_output_directory(output_path)

    # Create validator
    with app.app_context():
        validator = ComplianceValidator(
            framework=args.standard,
            categories=args.categories if args.categories else None,
            environment=args.environment
        )

        try:
            # Run validation
            validation_results = validator.validate()

            # Generate the report
            format_type = 'html' if args.format == 'pdf' else args.format

            # Handle summary-only mode
            if args.summary_only and format_type == 'json':
                # Extract only the summary from the results
                full_report = validator.generate_report(format=format_type)
                if isinstance(full_report, dict) and 'compliance_report' in full_report:
                    summary_only_report = {
                        'compliance_report': {
                            'metadata': full_report['compliance_report']['metadata'],
                            'summary': full_report['compliance_report']['summary']
                        }
                    }
                    report_content = summary_only_report
                else:
                    report_content = full_report
            else:
                report_content = validator.generate_report(format=format_type)

            # Add remediation information if requested
            if args.remediation_plan and format_type == 'json':
                report_content = enhance_report_with_remediation(report_content, args.compliance_map)

            # Add evidence data if requested
            if args.include_evidence and args.evidence_dir:
                report_content = append_evidence_to_report(report_content, args.evidence_dir, format_type)

            # Save report to output path
            if format_type == 'pdf':
                # For PDF, we need to convert HTML to PDF
                if isinstance(report_content, str):
                    success = generate_pdf_from_html(report_content, output_path)
                    if not success:
                        logger.error("Failed to generate PDF report")
                        return None
                else:
                    logger.error("HTML content expected for PDF generation")
                    return None
            else:
                # For other formats, write directly to file
                with open(output_path, 'w', encoding='utf-8') as f:
                    if format_type == 'json' and isinstance(report_content, dict):
                        json.dump(report_content, f, indent=4)
                    elif isinstance(report_content, str):
                        f.write(report_content)
                    else:
                        json.dump(report_content, f, indent=4)

            # Set secure permissions
            os.chmod(output_path, 0o640)

            # Log the report generation
            if isinstance(report_content, dict):
                log_compliance_report_generation(
                    app, args.standard, args.environment,
                    args.categories, args.format, report_content
                )

            logger.info(f"Compliance report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}", exc_info=True)
            return None


def validate_compliance(framework: str, categories: Optional[List[str]] = None,
                        environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Validate compliance against specified framework without generating a report.

    Args:
        framework: The compliance framework to validate against
        categories: Optional list of specific categories to validate
        environment: Optional environment to validate against

    Returns:
        Validation results as a dictionary
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unsupported framework: {framework}. Supported frameworks: {', '.join(SUPPORTED_FRAMEWORKS)}")

    # Create a Flask application for context
    app = create_app(env=environment or "production")

    with app.app_context():
        validator = ComplianceValidator(
            framework=framework,
            categories=categories,
            environment=environment
        )

        # Run validation
        validation_results = validator.validate()

        # Calculate summary statistics
        total_checks = len(validator.results)
        passed = sum(1 for r in validator.results if r.get('status') == ComplianceStatus.PASSED.value)
        failed = sum(1 for r in validator.results if r.get('status') == ComplianceStatus.FAILED.value)
        errors = sum(1 for r in validator.results if r.get('status') == ComplianceStatus.ERROR.value)
        skipped = sum(1 for r in validator.results if r.get('status') == ComplianceStatus.SKIPPED.value)

        # Determine overall status
        overall_status = ComplianceStatus.PASSED.value if failed == 0 else ComplianceStatus.FAILED.value

        # Return the results
        return {
            "metadata": {
                "framework": framework,
                "categories": categories or [],
                "environment": environment or "production",
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "summary": {
                "total_checks": total_checks,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "skipped": skipped,
                "compliance_percentage": round((passed / total_checks * 100), 1) if total_checks > 0 else 0,
                "overall_status": overall_status
            },
            "results": validator.results
        }


def get_compliance_status(framework: str, environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Get the current compliance status for a specific framework.

    Args:
        framework: The compliance framework to check
        environment: Optional environment to check

    Returns:
        Dictionary with compliance status information
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unsupported framework: {framework}. Supported frameworks: {', '.join(SUPPORTED_FRAMEWORKS)}")

    # Get validation results for high-level summary
    validation_results = validate_compliance(framework, environment=environment)
    summary = validation_results["summary"]

    # Get additional metadata
    authority = REGULATORY_AUTHORITIES.get(framework, "Unknown Regulatory Authority")
    current_date = datetime.now()

    # Create a status summary (simplified for the status call)
    return {
        "standard": framework,
        "environment": environment or "production",
        "authority": authority,
        "last_assessment": current_date.strftime("%Y-%m-%d"),
        "status": "Compliant" if summary["overall_status"] == ComplianceStatus.PASSED.value else "Non-Compliant",
        "compliance_percentage": summary["compliance_percentage"],
        "total_controls": summary["total_checks"],
        "passed_controls": summary["passed"],
        "failed_controls": summary["failed"],
        "timestamp": current_date.isoformat()
    }


def export_compliance_evidence(framework: str, control_id: Optional[str] = None,
                              output_dir: Optional[str] = None, format_type: str = "json") -> str:
    """
    Export compliance evidence for a specific framework or control.

    Args:
        framework: The compliance framework
        control_id: Optional specific control ID to export evidence for
        output_dir: Directory to save evidence files
        format_type: Output format (json, csv, pdf)

    Returns:
        Path to the evidence file or directory
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unsupported framework: {framework}. Supported frameworks: {', '.join(SUPPORTED_FRAMEWORKS)}")

    if format_type not in ["json", "csv", "pdf"]:
        raise ValueError(f"Unsupported format: {format_type}. Supported formats: json, csv, pdf")

    # Determine output directory
    if not output_dir:
        output_dir = os.path.join(DEFAULT_OUTPUT_DIR, "evidence", framework)

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if control_id:
        filename = f"{framework}_{control_id}_{timestamp}.{format_type}"
    else:
        filename = f"{framework}_evidence_{timestamp}.{format_type}"

    output_path = os.path.join(output_dir, filename)

    # Generate sample evidence (in a real implementation, this would fetch actual evidence)
    evidence_data = {
        "metadata": {
            "framework": framework,
            "control_id": control_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "exported_by": os.environ.get("USER", "unknown")
        },
        "evidence_items": []
    }

    if control_id:
        # Add evidence specific to this control
        evidence_data["evidence_items"].append({
            "id": f"evidence-{control_id}-001",
            "type": "documentation",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "description": f"Documentation for control {control_id}",
            "location": f"/evidence/{framework}/{control_id}/documentation.pdf"
        })
    else:
        # Add general evidence for the framework
        evidence_data["evidence_items"].append({
            "id": f"evidence-{framework}-001",
            "type": "certification",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "description": f"{framework.upper()} Certification Document",
            "location": f"/evidence/{framework}/certification.pdf"
        })

    # Write the evidence file
    with open(output_path, 'w', encoding='utf-8') as f:
        if format_type == "json":
            json.dump(evidence_data, f, indent=4)
        elif format_type == "csv":
            # Simple CSV format
            f.write("id,type,date,description,location\n")
            for item in evidence_data["evidence_items"]:
                f.write(f"{item['id']},{item['type']},{item['date']},{item['description']},{item['location']}\n")
        else:  # pdf
            # For PDF, we create a simple HTML that will be converted
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Compliance Evidence - {framework}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Compliance Evidence: {framework.upper()}</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Control ID:</strong> {control_id or 'All Controls'}</p>

    <h2>Evidence Items</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Date</th>
            <th>Description</th>
            <th>Location</th>
        </tr>
"""

            for item in evidence_data["evidence_items"]:
                html_content += f"""
        <tr>
            <td>{item['id']}</td>
            <td>{item['type']}</td>
            <td>{item['date']}</td>
            <td>{item['description']}</td>
            <td>{item['location']}</td>
        </tr>"""

            html_content += """
    </table>
</body>
</html>"""

            # Convert HTML to PDF
            generate_pdf_from_html(html_content, output_path)

    logger.info(f"Exported evidence to {output_path}")
    return output_path


def check_regulatory_requirements(framework: str, region: Optional[str] = None) -> Dict[str, Any]:
    """
    Check regulatory requirements for a specific framework and region.

    Args:
        framework: The compliance framework to check
        region: Optional region for region-specific requirements

    Returns:
        Dictionary with regulatory requirement information
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unsupported framework: {framework}. Supported frameworks: {', '.join(SUPPORTED_FRAMEWORKS)}")

    # Create response structure
    requirements = {
        "framework": framework,
        "region": region or "global",
        "authority": REGULATORY_AUTHORITIES.get(framework, "Unknown"),
        "last_updated": datetime.now().strftime("%Y-%m-%d"),
        "requirements": []
    }

    # Add framework-specific requirements
    if framework == "gdpr" and region in ["EU", "EEA", None]:
        requirements["requirements"].extend([
            {"id": "gdpr-art-5", "name": "Principles relating to processing", "type": "mandatory"},
            {"id": "gdpr-art-6", "name": "Lawfulness of processing", "type": "mandatory"},
            {"id": "gdpr-art-12", "name": "Transparent information", "type": "mandatory"},
            {"id": "gdpr-art-25", "name": "Data protection by design and default", "type": "mandatory"}
        ])
    elif framework == "hipaa":
        requirements["requirements"].extend([
            {"id": "hipaa-privacy", "name": "Privacy Rule", "type": "mandatory"},
            {"id": "hipaa-security", "name": "Security Rule", "type": "mandatory"},
            {"id": "hipaa-breach", "name": "Breach Notification Rule", "type": "mandatory"}
        ])
    elif framework == "pci-dss":
        requirements["requirements"].extend([
            {"id": "pci-req-1", "name": "Install and maintain a firewall configuration", "type": "mandatory"},
            {"id": "pci-req-3", "name": "Protect stored cardholder data", "type": "mandatory"},
            {"id": "pci-req-7", "name": "Restrict access to cardholder data", "type": "mandatory"}
        ])
    else:
        # Generic requirements for other frameworks
        requirements["requirements"].extend([
            {"id": f"{framework}-001", "name": "Security Policy", "type": "mandatory"},
            {"id": f"{framework}-002", "name": "Risk Management", "type": "mandatory"},
            {"id": f"{framework}-003", "name": "Access Controls", "type": "mandatory"}
        ])

    return requirements


def main():
    """Main entry point for the script."""
    args = parse_arguments()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.debug(f"Generating {args.standard} compliance report in {args.format} format")

    try:
        # Create Flask app instance for database access
        app = create_app(env=args.env)
    except Exception as e:
        logger.error(f"Failed to create Flask app: {e}")
        return 1

    # Generate the report
    report_path = generate_compliance_report(app, args)

    if report_path:
        print(f"Compliance report generated successfully: {report_path}")
        return 0
    else:
        print("Failed to generate compliance report")
        return 1


if __name__ == "__main__":
    sys.exit(main())
