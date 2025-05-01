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
    from models.security.compliance_check import ComplianceValidator, ComplianceStatus
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
