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

def prepare_report_metadata(
    case_id: Optional[str] = None,
    report_title: str = "Forensic Analysis Report",
    analyst_name: Optional[str] = None,
    report_format: str = "pdf"
) -> Dict[str, Any]:
    """
    Creates standardized metadata for a forensic report.

    Args:
        case_id: Optional case identifier
        report_title: Title of the report
        analyst_name: Name of the forensic analyst
        report_format: Format of the report (pdf, html, text, json)

    Returns:
        Dictionary containing structured metadata for the report
    """
    timestamp = _get_current_timestamp()

    metadata = {
        "report_title": report_title,
        "case_id": case_id or "N/A",
        "analyst_name": analyst_name or "Unknown",
        "generation_timestamp": timestamp,
        "report_format": report_format,
        "timezone": DEFAULT_TIMEZONE if CONSTANTS_AVAILABLE else FALLBACK_TIMEZONE,
        "report_id": f"FR-{datetime.now().strftime('%Y%m%d')}-{os.urandom(3).hex().upper()}",
        "report_version": "1.0",
        "confidentiality": "Confidential - Investigation Material"
    }

    log_forensic_operation(
        "prepare_report_metadata",
        True,
        {"case_id": case_id, "report_title": report_title, "format": report_format}
    )

    return metadata

def create_timeline_chart(
    events: List[Dict[str, Any]],
    output_path: Optional[str] = None,
    chart_type: str = "html",
    title: str = "Event Timeline",
    include_details: bool = True,
    highlight_events: Optional[List[str]] = None
) -> Union[str, bool]:
    """
    Creates a visual timeline chart from event data.

    This function generates a timeline visualization from a list of events.
    It can output HTML interactive charts, static image files, or JSON
    data for integration with other visualization tools.

    Args:
        events: List of event dictionaries with at minimum 'timestamp' and 'description' keys.
              Each event should contain at least:
                - timestamp: ISO format timestamp or datetime object
                - description: Text description of the event
              Optional fields that will be used if present:
                - category: Event category for grouping/coloring
                - severity: For visual indication of importance
                - source: Source of the event data
                - confidence: Confidence level in event data
        output_path: Optional path to save the generated timeline chart
        chart_type: Type of chart to generate: 'html', 'image', 'json'
        title: Title for the timeline
        include_details: Whether to include full event details or simplified view
        highlight_events: List of event IDs or descriptions to highlight

    Returns:
        If output_path is provided, returns True on success and False on failure.
        If output_path is None, returns the generated chart content as a string.
    """
    if not events or not isinstance(events, list):
        logger.error("No events provided or invalid format")
        return False if output_path else ""

    # Normalize timestamps and sort events chronologically
    normalized_events = []
    for event in events:
        if not isinstance(event, dict) or 'timestamp' not in event or 'description' not in event:
            logger.warning(f"Skipping invalid event: {event}")
            continue

        event_copy = event.copy()

        # Convert timestamp to datetime if it's a string
        if isinstance(event_copy['timestamp'], str):
            try:
                if ADVANCED_TIMESTAMP_AVAILABLE:
                    event_copy['timestamp'] = parse_timestamp(event_copy['timestamp'])
                else:
                    # Simple fallback parsing
                    event_copy['timestamp'] = datetime.fromisoformat(
                        event_copy['timestamp'].replace('Z', '+00:00')
                    )
            except (ValueError, AttributeError):
                logger.warning(f"Invalid timestamp format in event: {event}")
                continue

        normalized_events.append(event_copy)

    # Sort events by timestamp
    normalized_events.sort(key=lambda e: e['timestamp'])

    operation_details = {
        "event_count": len(normalized_events),
        "chart_type": chart_type,
        "output_path": output_path,
        "title": title
    }

    try:
        if chart_type.lower() == 'html':
            # Generate an HTML timeline using a template
            if not JINJA_AVAILABLE:
                logger.warning("Jinja2 not available, falling back to basic HTML timeline")
                # Generate basic HTML timeline
                html_content = _generate_basic_html_timeline(normalized_events, title, include_details, highlight_events)
            else:
                # Use Jinja2 template for more sophisticated visualization
                html_content = _generate_jinja_html_timeline(normalized_events, title, include_details, highlight_events)

            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                log_forensic_operation("create_timeline_chart", True, operation_details)
                return True
            else:
                return html_content

        elif chart_type.lower() == 'image':
            # This would require additional libraries like matplotlib or plotly
            # Simplified implementation creates a text-based timeline
            logger.warning("Image-based timeline requires additional dependencies, falling back to text")
            text_timeline = _generate_text_timeline(normalized_events, title)

            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(text_timeline)
                log_forensic_operation("create_timeline_chart", True,
                                      {**operation_details, "note": "Fallback to text timeline"})
                return True
            else:
                return text_timeline

        elif chart_type.lower() == 'json':
            # Prepare events for JSON serialization
            serializable_events = []
            for event in normalized_events:
                event_copy = event.copy()
                # Convert datetime objects to ISO format strings
                if isinstance(event_copy.get('timestamp'), datetime):
                    event_copy['timestamp'] = event_copy['timestamp'].isoformat()
                serializable_events.append(event_copy)

            json_data = json.dumps({
                'title': title,
                'events': serializable_events,
                'generated_at': datetime.now(timezone.utc).isoformat()
            }, indent=2)

            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_data)
                log_forensic_operation("create_timeline_chart", True, operation_details)
                return True
            else:
                return json_data

        else:
            logger.error(f"Unsupported chart type: {chart_type}")
            log_forensic_operation("create_timeline_chart", False,
                                 {**operation_details, "error": f"Unsupported chart type: {chart_type}"})
            return False if output_path else ""

    except Exception as e:
        logger.error(f"Failed to create timeline chart: {e}", exc_info=True)
        log_forensic_operation("create_timeline_chart", False,
                             {**operation_details, "error": str(e)})
        return False if output_path else ""

def create_evidence_summary(
    evidence_items: List[Dict[str, Any]],
    case_id: Optional[str] = None,
    include_chain_of_custody: bool = True,
    format_type: str = "html"
) -> Dict[str, Any]:
    """
    Creates a structured summary of evidence collected in an investigation.

    This function compiles evidence details into a standardized format suitable
    for inclusion in forensic reports. It can optionally include chain of custody
    information and sort/categorize evidence by type.

    Args:
        evidence_items: List of evidence item dictionaries
        case_id: Optional case identifier to pull additional evidence if available
        include_chain_of_custody: Whether to include chain of custody information
        format_type: Output format type (html, text, json)

    Returns:
        Dictionary containing structured evidence summary information
    """
    if not evidence_items and not case_id:
        logger.warning("No evidence items provided and no case ID specified")
        return {"evidence_count": 0, "evidence_items": [], "summary": "No evidence provided"}

    # If case_id is provided and evidence tracking is available, get evidence from the system
    if case_id and EVIDENCE_TRACKING_AVAILABLE:
        try:
            case_evidence = list_evidence_by_case(case_id)
            if case_evidence:
                # Merge provided items with those from the evidence system
                evidence_items = evidence_items or []

                # Create a set of existing evidence IDs to avoid duplicates
                existing_ids = {item.get('evidence_id') for item in evidence_items if 'evidence_id' in item}

                # Add case evidence items that aren't already included
                for item in case_evidence:
                    if item.get('evidence_id') not in existing_ids:
                        evidence_items.append(item)

        except Exception as e:
            logger.warning(f"Failed to retrieve case evidence: {e}")

    # Process evidence items
    processed_items = []
    evidence_by_type = {}
    total_size = 0
    acquisition_dates = []

    for item in evidence_items:
        if not isinstance(item, dict):
            continue

        # Create a clean copy with standardized fields
        processed_item = {
            "evidence_id": item.get("evidence_id", "Unknown"),
            "description": item.get("description", "No description provided"),
            "type": item.get("type", item.get("evidence_type", "Unspecified")),
            "acquisition_date": item.get("acquisition_date", item.get("collected_at", "Unknown")),
            "collected_by": item.get("collected_by", item.get("analyst", "Unknown")),
            "hash": item.get("hash", item.get("sha256", item.get("md5", "Not hashed"))),
            "location": item.get("location", item.get("path", item.get("storage_location", "Unknown"))),
        }

        # Add optional fields if present
        if "size" in item:
            processed_item["size"] = item["size"]
            try:
                size_val = int(item["size"])
                total_size += size_val
            except (ValueError, TypeError):
                pass

        # Track acquisition date if available
        if isinstance(processed_item["acquisition_date"], datetime):
            acquisition_dates.append(processed_item["acquisition_date"])
        elif isinstance(processed_item["acquisition_date"], str):
            try:
                date_obj = datetime.fromisoformat(processed_item["acquisition_date"].replace('Z', '+00:00'))
                acquisition_dates.append(date_obj)
            except (ValueError, AttributeError):
                pass

        # Group by evidence type
        ev_type = processed_item["type"]
        if ev_type not in evidence_by_type:
            evidence_by_type[ev_type] = []
        evidence_by_type[ev_type].append(processed_item)

        processed_items.append(processed_item)

    # Get chain of custody if requested and available
    chain_of_custody = {}
    if include_chain_of_custody and EVIDENCE_TRACKING_AVAILABLE and case_id:
        for item in processed_items:
            ev_id = item.get("evidence_id")
            if ev_id and ev_id != "Unknown":
                try:
                    custody_chain = get_chain_of_custody(case_id, ev_id)
                    if custody_chain:
                        chain_of_custody[ev_id] = custody_chain
                except Exception as e:
                    logger.warning(f"Failed to get chain of custody for {ev_id}: {e}")

    # Create the summary
    summary = {
        "evidence_count": len(processed_items),
        "evidence_types": list(evidence_by_type.keys()),
        "evidence_by_type": evidence_by_type,
        "evidence_items": processed_items,
        "total_size_bytes": total_size,
        "formatted_total_size": _format_file_size(total_size),
        "earliest_acquisition": min(acquisition_dates).isoformat() if acquisition_dates else "Unknown",
        "latest_acquisition": max(acquisition_dates).isoformat() if acquisition_dates else "Unknown"
    }

    if include_chain_of_custody:
        summary["chain_of_custody"] = chain_of_custody

    # Format the summary based on the requested output type
    if format_type.lower() == "html":
        summary["formatted_html"] = _format_evidence_summary_html(summary)
    elif format_type.lower() == "text":
        summary["formatted_text"] = _format_evidence_summary_text(summary)

    log_forensic_operation(
        "create_evidence_summary",
        True,
        {
            "case_id": case_id,
            "evidence_count": len(processed_items),
            "include_chain_of_custody": include_chain_of_custody,
            "format_type": format_type
        }
    )

    return summary

# Helper functions for the main functions above

def _generate_basic_html_timeline(
    events: List[Dict[str, Any]],
    title: str,
    include_details: bool,
    highlight_events: Optional[List[str]]
) -> str:
    """Generates a basic HTML timeline without requiring Jinja2."""
    html = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        f"<title>{title}</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 20px; }",
        ".timeline { position: relative; max-width: 1200px; margin: 0 auto; }",
        ".timeline::after { content: ''; position: absolute; width: 6px; background-color: #999; top: 0; bottom: 0; left: 50%; margin-left: -3px; }",
        ".event { padding: 10px 40px; position: relative; background-color: inherit; width: 45%; }",
        ".event::after { content: ''; position: absolute; width: 20px; height: 20px; right: -10px; top: 15px; border-radius: 50%; z-index: 1; background: #fff; border: 4px solid #888; }",
        ".event-left { left: 0; }",
        ".event-right { left: 55%; }",
        ".event-left::after { right: -12px; }",
        ".event-right::after { left: -12px; }",
        ".event-content { padding: 20px; background-color: white; border-radius: 6px; box-shadow: 0 0 5px rgba(0,0,0,0.3); }",
        ".highlight { border-left: 5px solid red; }",
        ".category-security { border-left: 5px solid #ff9800; }",
        ".category-user { border-left: 5px solid #2196F3; }",
        ".category-system { border-left: 5px solid #4CAF50; }",
        ".category-network { border-left: 5px solid #9C27B0; }",
        ".severity-high { background-color: #ffebee; }",
        ".severity-medium { background-color: #fff8e1; }",
        ".severity-low { background-color: #f1f8e9; }",
        "</style>",
        "</head>",
        "<body>",
        f"<h1>{title}</h1>",
        "<div class='timeline'>"
    ]

    # Add events to the timeline
    for i, event in enumerate(events):
        timestamp = event["timestamp"]
        description = event["description"]
        timestamp_str = timestamp if isinstance(timestamp, str) else timestamp.strftime("%Y-%m-%d %H:%M:%S")

        # Determine event position (alternating)
        position = "event-left" if i % 2 == 0 else "event-right"

        # Determine if this event should be highlighted
        is_highlighted = False
        if highlight_events:
            if any(highlight in description for highlight in highlight_events):
                is_highlighted = True

        # Determine category class
        category_class = ""
        if "category" in event:
            category_class = f"category-{event['category'].lower()}"

        # Determine severity class
        severity_class = ""
        if "severity" in event:
            severity = event["severity"].lower()
            if severity in ["high", "critical"]:
                severity_class = "severity-high"
            elif severity in ["medium"]:
                severity_class = "severity-medium"
            elif severity in ["low"]:
                severity_class = "severity-low"

        # Create class attribute
        classes = ["event", position]
        if is_highlighted:
            classes.append("highlight")
        if category_class:
            classes.append(category_class)
        if severity_class:
            classes.append(severity_class)
        class_attr = ' '.join(classes)

        # Start event div
        html.append(f'<div class="{class_attr}">')
        html.append('<div class="event-content">')

        # Add event content
        html.append(f'<h3>{timestamp_str}</h3>')
        html.append(f'<p>{description}</p>')

        # Add details if requested
        if include_details:
            for key, value in event.items():
                if key not in ["timestamp", "description"]:
                    # Format the value
                    if isinstance(value, datetime):
                        value_str = value.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        value_str = str(value)
                    html.append(f'<p><strong>{key}:</strong> {value_str}</p>')

        # Close divs
        html.append('</div>')  # event-content
        html.append('</div>')  # event

    # Close HTML
    html.append("</div>")  # timeline
    html.append("</body>")
    html.append("</html>")

    return '\n'.join(html)

def _generate_jinja_html_timeline(
    events: List[Dict[str, Any]],
    title: str,
    include_details: bool,
    highlight_events: Optional[List[str]]
) -> str:
    """Generates a more sophisticated HTML timeline using Jinja2."""
    # Create Environment and load template
    # Since we don't have the actual template, we'll create a basic one
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ title }}</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .timeline { position: relative; max-width: 1200px; margin: 0 auto; }
            .timeline::after { content: ''; position: absolute; width: 6px; background-color: #999; top: 0; bottom: 0; left: 50%; margin-left: -3px; }
            .event { padding: 10px 40px; position: relative; background-color: inherit; width: 45%; }
            .event::after { content: ''; position: absolute; width: 20px; height: 20px; right: -10px; top: 15px; border-radius: 50%; z-index: 1; background: #fff; border: 4px solid #888; }
            .event-left { left: 0; }
            .event-right { left: 55%; }
            .event-left::after { right: -12px; }
            .event-right::after { left: -12px; }
            .event-content { padding: 20px; background-color: white; border-radius: 6px; box-shadow: 0 0 5px rgba(0,0,0,0.3); }
            .highlight { border-left: 5px solid red; }
            .category-security { border-left: 5px solid #ff9800; }
            .category-user { border-left: 5px solid #2196F3; }
            .category-system { border-left: 5px solid #4CAF50; }
            .category-network { border-left: 5px solid #9C27B0; }
            .severity-high { background-color: #ffebee; }
            .severity-medium { background-color: #fff8e1; }
            .severity-low { background-color: #f1f8e9; }
            .metadata { margin-bottom: 20px; padding: 10px; background-color: #f5f5f5; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>{{ title }}</h1>

        <div class="metadata">
            <p><strong>Total Events:</strong> {{ events|length }}</p>
            <p><strong>Time Range:</strong> {{ time_range }}</p>
            <p><strong>Generated:</strong> {{ generation_time }}</p>
        </div>

        <div class="timeline">
            {% for event in events %}
                <div class="event {% if loop.index0 % 2 == 0 %}event-left{% else %}event-right{% endif %}
                            {% if event.category %}category-{{ event.category|lower }}{% endif %}
                            {% if event.severity %}severity-{{ event.severity|lower }}{% endif %}
                            {% if event.description in highlight_events %}highlight{% endif %}">
                    <div class="event-content">
                        <h3>{{ event.timestamp_str }}</h3>
                        <p>{{ event.description }}</p>

                        {% if include_details %}
                            {% for key, value in event.items() %}
                                {% if key not in ['timestamp', 'description', 'timestamp_str'] %}
                                    <p><strong>{{ key }}:</strong> {{ value }}</p>
                                {% endif %}
                            {% endfor %}
                        {% endif %}
                    </div>
                </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """

    env = Environment(autoescape=select_autoescape(['html', 'xml']))
    template = env.from_string(template_str)

    # Process events to include formatted timestamps
    for event in events:
        if isinstance(event["timestamp"], datetime):
            event["timestamp_str"] = event["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        else:
            event["timestamp_str"] = str(event["timestamp"])

    # Determine time range
    if events:
        start_time = events[0]["timestamp_str"]
        end_time = events[-1]["timestamp_str"]
        time_range = f"{start_time} to {end_time}"
    else:
        time_range = "No events"

    # Prepare highlight list
    highlight_list = highlight_events or []

    # Render the template
    return template.render(
        title=title,
        events=events,
        include_details=include_details,
        highlight_events=highlight_list,
        time_range=time_range,
        generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

def _generate_text_timeline(events: List[Dict[str, Any]], title: str) -> str:
    """Generates a simple text-based timeline."""
    text_lines = [
        title,
        "=" * len(title),
        ""
    ]

    for event in events:
        timestamp = event["timestamp"]
        timestamp_str = timestamp if isinstance(timestamp, str) else timestamp.strftime("%Y-%m-%d %H:%M:%S")
        text_lines.append(f"{timestamp_str} - {event['description']}")

    return "\n".join(text_lines)

def _format_file_size(size_bytes: int) -> str:
    """Converts bytes to a human-readable size format."""
    if size_bytes == 0:
        return "0 B"

    size_names = ("B", "KB", "MB", "GB", "TB", "PB")
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024
        i += 1
    return f"{size_bytes:.2f} {size_names[i]}"

def _format_evidence_summary_html(summary: Dict[str, Any]) -> str:
    """Creates an HTML representation of the evidence summary."""
    html = [
        "<div class='evidence-summary'>",
        f"<h2>Evidence Summary ({summary['evidence_count']} items)</h2>",
        f"<p>Total Size: {summary['formatted_total_size']}</p>",
        f"<p>Evidence Types: {', '.join(summary['evidence_types'])}</p>",
        "<h3>Evidence by Type</h3>"
    ]

    for ev_type, items in summary['evidence_by_type'].items():
        html.append(f"<h4>{ev_type} ({len(items)} items)</h4>")
        html.append("<table class='evidence-table'>")
        html.append("<tr><th>ID</th><th>Description</th><th>Acquisition Date</th><th>Collected By</th><th>Hash</th></tr>")

        for item in items:
            html.append("<tr>")
            html.append(f"<td>{item['evidence_id']}</td>")
            html.append(f"<td>{item['description']}</td>")
            html.append(f"<td>{item['acquisition_date']}</td>")
            html.append(f"<td>{item['collected_by']}</td>")
            html.append(f"<td>{item['hash']}</td>")
            html.append("</tr>")

        html.append("</table>")

    # Add chain of custody if available
    if 'chain_of_custody' in summary and summary['chain_of_custody']:
        html.append("<h3>Chain of Custody</h3>")
        for ev_id, custody_chain in summary['chain_of_custody'].items():
            html.append(f"<h4>Evidence ID: {ev_id}</h4>")
            html.append("<table class='custody-table'>")
            html.append("<tr><th>Date/Time</th><th>Action</th><th>Person</th><th>Details</th></tr>")

            for entry in custody_chain:
                html.append("<tr>")
                html.append(f"<td>{entry.get('timestamp', 'Unknown')}</td>")
                html.append(f"<td>{entry.get('action', 'Unknown')}</td>")
                html.append(f"<td>{entry.get('person', entry.get('analyst', 'Unknown'))}</td>")
                html.append(f"<td>{entry.get('details', '')}</td>")
                html.append("</tr>")

            html.append("</table>")

    html.append("</div>")
    return "\n".join(html)

def _format_evidence_summary_text(summary: Dict[str, Any]) -> str:
    """Creates a text representation of the evidence summary."""
    text_lines = [
        f"EVIDENCE SUMMARY ({summary['evidence_count']} items)",
        "=" * 50,
        f"Total Size: {summary['formatted_total_size']}",
        f"Evidence Types: {', '.join(summary['evidence_types'])}",
        "",
        "EVIDENCE BY TYPE:",
        "=" * 50
    ]

    for ev_type, items in summary['evidence_by_type'].items():
        text_lines.append(f"\n{ev_type.upper()} ({len(items)} items):")
        text_lines.append("-" * 50)

        for item in items:
            text_lines.append(f"ID: {item['evidence_id']}")
            text_lines.append(f"Description: {item['description']}")
            text_lines.append(f"Acquisition Date: {item['acquisition_date']}")
            text_lines.append(f"Collected By: {item['collected_by']}")
            text_lines.append(f"Hash: {item['hash']}")
            text_lines.append(f"Location: {item['location']}")
            text_lines.append("")

    # Add chain of custody if available
    if 'chain_of_custody' in summary and summary['chain_of_custody']:
        text_lines.append("\nCHAIN OF CUSTODY:")
        text_lines.append("=" * 50)

        for ev_id, custody_chain in summary['chain_of_custody'].items():
            text_lines.append(f"\nEvidence ID: {ev_id}")
            text_lines.append("-" * 50)

            for entry in custody_chain:
                text_lines.append(f"Date/Time: {entry.get('timestamp', 'Unknown')}")
                text_lines.append(f"Action: {entry.get('action', 'Unknown')}")
                text_lines.append(f"Person: {entry.get('person', entry.get('analyst', 'Unknown'))}")
                text_lines.append(f"Details: {entry.get('details', '')}")
                text_lines.append("")

    return "\n".join(text_lines)


def generate_html_report(
    report_data: Dict[str, Any],
    output_path: str,
    template_name: str = "forensic_report_template.html",
    template_dirs: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Generate an HTML report and save it to the specified path.

    Args:
        report_data: Dictionary containing the report content
        output_path: Path where to save the generated HTML report
        template_name: Name of the HTML template file to use
        template_dirs: List of directories to search for the template
        metadata: Optional metadata to include in the report

    Returns:
        True if the report was successfully generated, False otherwise
    """
    operation_details = {
        "format": "html",
        "output_path": output_path,
        "template": template_name
    }

    try:
        if metadata is None:
            metadata = _prepare_report_metadata(
                case_id=report_data.get("case_id"),
                report_title=report_data.get("report_title", "Forensic Analysis Report"),
                analyst_name=report_data.get("analyst_name"),
                report_format="html"
            )

        html_content = _generate_html_report(report_data, metadata, template_name, template_dirs)

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Successfully generated HTML report: {output_path}")
        log_forensic_operation("generate_html_report", True, operation_details)
        return True

    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}", exc_info=True)
        log_forensic_operation(
            "generate_html_report", False,
            {**operation_details, "error": str(e)},
            level=logging.ERROR
        )
        return False


def generate_pdf_report(
    report_data: Dict[str, Any],
    output_path: str,
    template_name: str = "forensic_report_template.html",
    template_dirs: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Generate a PDF report and save it to the specified path.

    This function converts HTML to PDF using WeasyPrint if available.

    Args:
        report_data: Dictionary containing the report content
        output_path: Path where to save the generated PDF report
        template_name: Name of the HTML template file to use (for PDF conversion)
        template_dirs: List of directories to search for the template
        metadata: Optional metadata to include in the report

    Returns:
        True if the report was successfully generated, False otherwise
    """
    operation_details = {
        "format": "pdf",
        "output_path": output_path,
        "template": template_name
    }

    if not PDF_AVAILABLE:
        logger.error("Cannot generate PDF report: WeasyPrint library not found.")
        log_forensic_operation(
            "generate_pdf_report", False,
            {**operation_details, "error": "PDF library missing"},
            level=logging.ERROR
        )
        return False

    try:
        if metadata is None:
            metadata = _prepare_report_metadata(
                case_id=report_data.get("case_id"),
                report_title=report_data.get("report_title", "Forensic Analysis Report"),
                analyst_name=report_data.get("analyst_name"),
                report_format="pdf"
            )

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Generate HTML first
        html_content = _generate_html_report(report_data, metadata, template_name, template_dirs)

        # Convert HTML to PDF
        _generate_pdf_report(report_data, metadata, output_path, template_name, template_dirs)

        logger.info(f"Successfully generated PDF report: {output_path}")
        log_forensic_operation("generate_pdf_report", True, operation_details)
        return True

    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}", exc_info=True)
        log_forensic_operation(
            "generate_pdf_report", False,
            {**operation_details, "error": str(e)},
            level=logging.ERROR
        )
        return False


def generate_json_report(
    report_data: Dict[str, Any],
    output_path: str,
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Generate a JSON report and save it to the specified path.

    Args:
        report_data: Dictionary containing the report content
        output_path: Path where to save the generated JSON report
        metadata: Optional metadata to include in the report

    Returns:
        True if the report was successfully generated, False otherwise
    """
    operation_details = {
        "format": "json",
        "output_path": output_path
    }

    try:
        if metadata is None:
            metadata = _prepare_report_metadata(
                case_id=report_data.get("case_id"),
                report_title=report_data.get("report_title", "Forensic Analysis Report"),
                analyst_name=report_data.get("analyst_name"),
                report_format="json"
            )

        # Get JSON content
        json_content = _generate_json_report(report_data, metadata)

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_content)

        logger.info(f"Successfully generated JSON report: {output_path}")
        log_forensic_operation("generate_json_report", True, operation_details)
        return True

    except Exception as e:
        logger.error(f"Failed to generate JSON report: {e}", exc_info=True)
        log_forensic_operation(
            "generate_json_report", False,
            {**operation_details, "error": str(e)},
            level=logging.ERROR
        )
        return False


def generate_text_report(
    report_data: Dict[str, Any],
    output_path: str,
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Generate a plain text report and save it to the specified path.

    Args:
        report_data: Dictionary containing the report content
        output_path: Path where to save the generated text report
        metadata: Optional metadata to include in the report

    Returns:
        True if the report was successfully generated, False otherwise
    """
    operation_details = {
        "format": "text",
        "output_path": output_path
    }

    try:
        if metadata is None:
            metadata = _prepare_report_metadata(
                case_id=report_data.get("case_id"),
                report_title=report_data.get("report_title", "Forensic Analysis Report"),
                analyst_name=report_data.get("analyst_name"),
                report_format="text"
            )

        # Get text content
        text_content = _generate_text_report(report_data, metadata)

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text_content)

        logger.info(f"Successfully generated text report: {output_path}")
        log_forensic_operation("generate_text_report", True, operation_details)
        return True

    except Exception as e:
        logger.error(f"Failed to generate text report: {e}", exc_info=True)
        log_forensic_operation(
            "generate_text_report", False,
            {**operation_details, "error": str(e)},
            level=logging.ERROR
        )
        return False


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
