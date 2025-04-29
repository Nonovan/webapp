"""
Forensic Report Building Utilities.

This module provides functions to generate structured reports based on forensic
findings, evidence logs, timelines, and other analysis results. It supports
various output formats and aims for consistency and clarity in reporting.

Integrates with forensic logging and potentially uses standardized templates.
"""

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union

# Attempt to import forensic-specific logging and constants
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    FORENSIC_LOGGING_AVAILABLE = True
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger for report building.")
    FORENSIC_LOGGING_AVAILABLE = False
    # Fallback logging function
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

try:
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_TIMESTAMP_FORMAT, DEFAULT_TIMEZONE
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    logging.warning("Forensic constants not found. Using default values.")
    CONSTANTS_AVAILABLE = False
    FALLBACK_TIMESTAMP_FORMAT = "iso8601"  # Use a new variable for the fallback value
    FALLBACK_TIMEZONE = "UTC"  # Use a new variable for the fallback value

# Attempt to import templating engine (optional)
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False
    logging.info("Jinja2 not found. HTML report generation will be basic.")

# Attempt to import PDF generation library (optional)
try:
    # Example using WeasyPrint, other libraries like reportlab could be used
    from weasyprint import HTML as WeasyHTML
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logging.info("WeasyPrint not found. PDF report generation via HTML is disabled.")


logger = logging.getLogger(__name__)

# Supported report formats
FORMAT_TEXT = "text"
FORMAT_JSON = "json"
FORMAT_HTML = "html"
FORMAT_PDF = "pdf"
SUPPORTED_FORMATS = [FORMAT_TEXT, FORMAT_JSON, FORMAT_HTML, FORMAT_PDF]

# Default template locations (adjust as needed based on project structure)
DEFAULT_TEMPLATE_DIRS = [
    os.path.join(os.path.dirname(__file__), '../templates/reports'), # forensics/templates/reports
    os.path.join(os.path.dirname(__file__), '../../../../admin/templates/reports'), # admin/templates/reports
]

# --- Helper Functions ---

def _get_current_timestamp() -> str:
    """Returns the current timestamp in the standard format."""
    now = datetime.now(timezone.utc)
    if DEFAULT_TIMESTAMP_FORMAT.lower() == "iso8601":
        return now.isoformat()
    else:
        # Fallback or handle other formats if needed
        return now.strftime("%Y-%m-%d %H:%M:%S %Z")

def _prepare_report_metadata(
    case_id: Optional[str],
    report_title: str,
    analyst_name: Optional[str],
    report_format: str
) -> Dict[str, Any]:
    """Creates a standard metadata dictionary for the report."""
    return {
        "report_title": report_title,
        "case_id": case_id or "N/A",
        "analyst_name": analyst_name or "Unknown",
        "generation_timestamp": _get_current_timestamp(),
        "report_format": report_format,
        "timezone": DEFAULT_TIMEZONE,
    }

def _find_template(template_name: str, template_dirs: List[str]) -> Optional[str]:
    """Searches for a template file in the specified directories."""
    for directory in template_dirs:
        full_path = os.path.abspath(os.path.join(directory, template_name))
        if os.path.isfile(full_path):
            logger.debug(f"Found template '{template_name}' at '{full_path}'")
            return os.path.dirname(full_path) # Return the directory containing the template
    logger.warning(f"Template '{template_name}' not found in directories: {template_dirs}")
    return None

# --- Report Generation Functions ---

def _generate_text_report(
    report_data: Dict[str, Any],
    metadata: Dict[str, Any]
) -> str:
    """Generates a simple plain text report."""
    lines = []
    lines.append("=" * 80)
    lines.append(f"FORENSIC REPORT: {metadata.get('report_title', 'Untitled')}")
    lines.append("=" * 80)
    lines.append(f"Case ID: {metadata.get('case_id', 'N/A')}")
    lines.append(f"Analyst: {metadata.get('analyst_name', 'Unknown')}")
    lines.append(f"Generated: {metadata.get('generation_timestamp', 'N/A')} ({metadata.get('timezone', 'UTC')})")
    lines.append("-" * 80)

    # Add sections from report_data
    for section_title, section_content in report_data.items():
        lines.append(f"\n## {section_title.replace('_', ' ').upper()} ##\n")
        if isinstance(section_content, list):
            for item in section_content:
                if isinstance(item, dict):
                    for key, value in item.items():
                        lines.append(f"  {key.replace('_', ' ').capitalize()}: {value}")
                    lines.append("") # Add space between list items
                else:
                    lines.append(f"  - {item}")
        elif isinstance(section_content, dict):
            for key, value in section_content.items():
                lines.append(f"  {key.replace('_', ' ').capitalize()}: {value}")
        else:
            lines.append(str(section_content))

    lines.append("\n" + "=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)

    return "\n".join(lines)

def _generate_json_report(
    report_data: Dict[str, Any],
    metadata: Dict[str, Any]
) -> str:
    """Generates a JSON formatted report."""
    full_report = {
        "metadata": metadata,
        "report_content": report_data
    }
    try:
        return json.dumps(full_report, indent=2, default=str) # Use default=str for non-serializable types like datetime
    except TypeError as e:
        logger.error(f"Error serializing report data to JSON: {e}")
        log_forensic_operation(
            "generate_report", False,
            {"format": FORMAT_JSON, "error": f"JSON serialization error: {e}"},
            level=logging.ERROR
        )
        # Fallback: try to serialize with problematic types converted to strings
        try:
            return json.dumps(full_report, indent=2, default=lambda o: f"<non-serializable: {type(o).__name__}>")
        except Exception as fallback_e:
             logger.error(f"Fallback JSON serialization failed: {fallback_e}")
             raise ValueError(f"Could not serialize report data to JSON: {fallback_e}") from fallback_e


def _generate_html_report(
    report_data: Dict[str, Any],
    metadata: Dict[str, Any],
    template_name: str = "forensic_report_template.html",
    template_dirs: Optional[List[str]] = None
) -> str:
    """Generates an HTML report using Jinja2 templates if available."""
    if not JINJA_AVAILABLE:
        logger.warning("Jinja2 not available. Generating basic HTML report.")
        # Basic HTML fallback
        html_lines = ["<html><head><title>{metadata.get('report_title', 'Forensic Report')}</title></head><body>"]
        html_lines.append(f"<h1>{metadata.get('report_title', 'Forensic Report')}</h1>")
        html_lines.append(f"<p><strong>Case ID:</strong> {metadata.get('case_id', 'N/A')}<br>")
        html_lines.append(f"<strong>Analyst:</strong> {metadata.get('analyst_name', 'Unknown')}<br>")
        html_lines.append(f"<strong>Generated:</strong> {metadata.get('generation_timestamp', 'N/A')} ({metadata.get('timezone', 'UTC')})</p>")
        html_lines.append("<hr>")

        for section_title, section_content in report_data.items():
            html_lines.append(f"<h2>{section_title.replace('_', ' ').upper()}</h2>")
            if isinstance(section_content, list):
                html_lines.append("<ul>")
                for item in section_content:
                     html_lines.append(f"<li>{json.dumps(item, default=str) if isinstance(item, dict) else str(item)}</li>")
                html_lines.append("</ul>")
            elif isinstance(section_content, dict):
                 html_lines.append("<pre><code>" + json.dumps(section_content, indent=2, default=str) + "</code></pre>")
            else:
                 html_lines.append(f"<p>{str(section_content)}</p>")

        html_lines.append("</body></html>")
        return "\n".join(html_lines)

    # Use Jinja2
    search_dirs = template_dirs or DEFAULT_TEMPLATE_DIRS
    template_dir = _find_template(template_name, search_dirs)

    if not template_dir:
         logger.error(f"HTML template '{template_name}' not found. Cannot generate HTML report.")
         raise FileNotFoundError(f"HTML template '{template_name}' not found in {search_dirs}")

    try:
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template(template_name)
        context = {
            "metadata": metadata,
            "data": report_data,
            # Add any other variables the template might need
            "title": metadata.get('report_title', 'Forensic Report')
        }
        return template.render(context)
    except Exception as e:
        logger.error(f"Error rendering HTML template '{template_name}': {e}", exc_info=True)
        log_forensic_operation(
            "generate_report", False,
            {"format": FORMAT_HTML, "template": template_name, "error": f"Template rendering error: {e}"},
            level=logging.ERROR
        )
        raise RuntimeError(f"Failed to render HTML template: {e}") from e


def _generate_pdf_report(
    report_data: Dict[str, Any],
    metadata: Dict[str, Any],
    output_path: str,
    template_name: str = "forensic_report_template.html",
    template_dirs: Optional[List[str]] = None
) -> None:
    """Generates a PDF report by rendering an HTML template first."""
    if not PDF_AVAILABLE:
        logger.error("PDF generation library (e.g., WeasyPrint) not installed. Cannot generate PDF report.")
        raise ImportError("PDF generation library not available.")

    # 1. Generate HTML content
    try:
        html_content = _generate_html_report(report_data, metadata, template_name, template_dirs)
    except Exception as e:
        logger.error(f"Failed to generate HTML for PDF conversion: {e}")
        # Logging done within _generate_html_report
        raise

    # 2. Convert HTML to PDF
    try:
        # Base URL might be needed for relative paths (CSS, images) in the HTML
        base_url = os.path.dirname(os.path.abspath(output_path)) # Use output dir as base
        pdf_bytes = WeasyHTML(string=html_content, base_url=base_url).write_pdf()

        # 3. Write PDF to file
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
        logger.info(f"Successfully generated PDF report: {output_path}")

    except Exception as e:
        logger.error(f"Error converting HTML to PDF: {e}", exc_info=True)
        log_forensic_operation(
            "generate_report", False,
            {"format": FORMAT_PDF, "output_path": output_path, "error": f"PDF conversion error: {e}"},
            level=logging.ERROR
        )
        raise RuntimeError(f"Failed to generate PDF report: {e}") from e


# --- Main Function ---

def generate_forensic_report(
    report_data: Dict[str, Any],
    output_path: str,
    report_format: str,
    case_id: Optional[str] = None,
    analyst_name: Optional[str] = None,
    report_title: str = "Forensic Analysis Report",
    template_name: Optional[str] = None, # e.g., "detailed_findings.html"
    template_dirs: Optional[List[str]] = None,
    overwrite: bool = False
) -> bool:
    """
    Generates a forensic report in the specified format.

    Args:
        report_data: Dictionary containing the structured data for the report sections.
                     Example: {"summary": "...", "timeline": [...], "findings": [...]}
        output_path: The full path where the report file should be saved.
        report_format: The desired output format (e.g., "text", "json", "html", "pdf").
        case_id: Optional identifier for the forensic case.
        analyst_name: Optional name of the analyst generating the report.
        report_title: The title for the report.
        template_name: Optional specific template file name for HTML/PDF formats.
                       Defaults based on format if not provided.
        template_dirs: Optional list of directories to search for templates.
                       Defaults to standard locations.
        overwrite: If True, overwrite the output file if it exists. Defaults to False.

    Returns:
        True if the report was generated successfully, False otherwise.
    """
    report_format = report_format.lower()
    if report_format not in SUPPORTED_FORMATS:
        logger.error(f"Unsupported report format: {report_format}. Supported formats: {SUPPORTED_FORMATS}")
        return False

    if not overwrite and os.path.exists(output_path):
        logger.error(f"Output file already exists: {output_path}. Use overwrite=True to replace.")
        return False

    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    try:
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create output directory '{output_dir}': {e}")
        log_forensic_operation(
            "generate_report", False,
            {"format": report_format, "output_path": output_path, "error": f"Cannot create output directory: {e}"},
            level=logging.ERROR
        )
        return False

    operation_details = {
        "output_path": output_path,
        "format": report_format,
        "case_id": case_id,
        "report_title": report_title,
        "analyst": analyst_name,
    }
    log_forensic_operation("generate_report_start", True, operation_details)

    metadata = _prepare_report_metadata(case_id, report_title, analyst_name, report_format)

    try:
        content = None
        if report_format == FORMAT_TEXT:
            content = _generate_text_report(report_data, metadata)
        elif report_format == FORMAT_JSON:
            content = _generate_json_report(report_data, metadata)
        elif report_format == FORMAT_HTML:
            html_template = template_name or "forensic_report_template.html"
            content = _generate_html_report(report_data, metadata, html_template, template_dirs)
            operation_details["template"] = html_template
        elif report_format == FORMAT_PDF:
            if not PDF_AVAILABLE:
                 logger.error("Cannot generate PDF report: WeasyPrint library not found.")
                 log_forensic_operation("generate_report", False, {**operation_details, "error": "PDF library missing"}, level=logging.ERROR)
                 return False
            pdf_template = template_name or "forensic_report_template.html"
            _generate_pdf_report(report_data, metadata, output_path, pdf_template, template_dirs)
            operation_details["template"] = pdf_template
            # PDF is written directly in its function, so we return early
            log_forensic_operation("generate_report", True, operation_details)
            return True
        else:
            # This case should be caught by the initial format check, but included for safety
             logger.error(f"Internal error: Reached unsupported format '{report_format}' in generation logic.")
             return False


        # Write content to file (for TEXT, JSON, HTML)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Successfully generated {report_format.upper()} report: {output_path}")
        log_forensic_operation("generate_report", True, operation_details)
        return True

    except (FileNotFoundError, ImportError, RuntimeError, ValueError, OSError, Exception) as e:
        logger.error(f"Failed to generate {report_format.upper()} report: {e}", exc_info=True)
        # Specific errors logged within helper functions or here
        if not FORENSIC_LOGGING_AVAILABLE or "generate_report" not in str(e): # Avoid duplicate logs if logged in helpers
             log_forensic_operation(
                 "generate_report", False,
                 {**operation_details, "error": str(e)},
                 level=logging.ERROR
             )
        # Clean up potentially partially written file
        if os.path.exists(output_path) and report_format != FORMAT_PDF: # PDF handles its own writing/errors
            try:
                os.remove(output_path)
            except OSError:
                logger.warning(f"Could not remove partially written report file: {output_path}")
        return False


# --- Example Usage ---

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create dummy template directory and file for testing
    TEST_TEMPLATE_DIR = "temp_report_templates"
    TEST_HTML_TEMPLATE = "forensic_report_template.html"
    if JINJA_AVAILABLE:
        os.makedirs(TEST_TEMPLATE_DIR, exist_ok=True)
        template_content = """
<!DOCTYPE html>
<html>
<head><title>{{ title }}</title></head>
<body>
    <h1>{{ metadata.report_title }}</h1>
    <p>Case: {{ metadata.case_id }} | Analyst: {{ metadata.analyst_name }}</p>
    <hr>
    {% for section, content in data.items() %}
    <h2>{{ section|replace('_', ' ')|upper }}</h2>
    {% if content is iterable and content is not string and content is not mapping %}
        <ul>{% for item in content %}<li>{{ item }}</li>{% endfor %}</ul>
    {% elif content is mapping %}
        <pre>{{ content|tojson(indent=2) }}</pre>
    {% else %}
        <p>{{ content }}</p>
    {% endif %}
    {% endfor %}
</body>
</html>
"""
        with open(os.path.join(TEST_TEMPLATE_DIR, TEST_HTML_TEMPLATE), "w") as f:
            f.write(template_content)
        logger.info(f"Created dummy HTML template at {os.path.join(TEST_TEMPLATE_DIR, TEST_HTML_TEMPLATE)}")


    # Example report data
    sample_data = {
        "case_summary": "Investigation into unauthorized access on server WEB01.",
        "key_findings": [
            {"timestamp": "2023-10-27T10:15:00Z", "finding": "Suspicious login from IP 198.51.100.10", "severity": "High"},
            {"timestamp": "2023-10-27T10:22:00Z", "finding": "Malware detected: Trojan.GenericKD.123", "severity": "Critical"},
            {"timestamp": "2023-10-27T11:05:00Z", "finding": "Data exfiltration attempt via port 8080", "severity": "High"},
        ],
        "evidence_collected": [
            "Memory dump from WEB01",
            "Disk image of /var/log partition",
            "Network traffic capture (2023-10-27 10:00-11:00 UTC)",
        ],
        "analysis_steps": "Performed memory analysis using Volatility. Scanned disk image with ClamAV. Analyzed network traffic in Wireshark.",
        "recommendations": [
            "Isolate server WEB01 immediately.",
            "Block IP address 198.51.100.10 at the firewall.",
            "Perform full malware scan on all related systems.",
            "Review access logs for further compromise.",
        ]
    }

    output_dir = "temp_reports"
    os.makedirs(output_dir, exist_ok=True)
    case = "CASE-2023-001"
    analyst = "Jane Doe"

    # Generate reports in different formats
    formats_to_test = [FORMAT_TEXT, FORMAT_JSON, FORMAT_HTML]
    if PDF_AVAILABLE and JINJA_AVAILABLE:
        formats_to_test.append(FORMAT_PDF)
    else:
        logger.warning("Skipping PDF report test as dependencies are missing.")


    for fmt in formats_to_test:
        output_file = os.path.join(output_dir, f"forensic_report_{case}.{fmt}")
        print(f"\n--- Generating {fmt.upper()} Report ---")
        success = generate_forensic_report(
            report_data=sample_data,
            output_path=output_file,
            report_format=fmt,
            case_id=case,
            analyst_name=analyst,
            report_title=f"Forensic Report for {case}",
            template_dirs=[TEST_TEMPLATE_DIR] + DEFAULT_TEMPLATE_DIRS, # Prioritize test template
            overwrite=True
        )
        if success:
            print(f"Successfully generated: {output_file}")
            # Optional: print content for text/json
            # if fmt in [FORMAT_TEXT, FORMAT_JSON]:
            #     with open(output_file, 'r') as f_read:
            #         print(f_read.read()[:500] + "...") # Print first 500 chars
        else:
            print(f"Failed to generate {fmt.upper()} report.")

    # Clean up dummy template
    if JINJA_AVAILABLE:
        try:
            shutil.rmtree(TEST_TEMPLATE_DIR)
            logger.info("Removed dummy template directory.")
        except OSError as e:
            logger.warning(f"Could not remove dummy template directory '{TEST_TEMPLATE_DIR}': {e}")

    print("\nReport generation tests complete.")
    # Manual cleanup of temp_reports directory might be needed
