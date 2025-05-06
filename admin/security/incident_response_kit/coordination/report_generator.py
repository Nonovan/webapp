"""
Incident Response Kit - Report Generator

This module provides functionality for generating standardized incident reports,
status reports, and timeline reports for security incidents. It integrates with
other components of the incident response toolkit to provide unified reporting
capabilities.
"""

import os
import sys
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Set

# Configure logging
logger = logging.getLogger(__name__)

# Determine module paths
try:
    MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
    COORDINATION_DIR = MODULE_DIR
    IR_KIT_DIR = COORDINATION_DIR.parent

    # Add parent directory to path if running as script
    if __name__ == "__main__" and str(IR_KIT_DIR) not in sys.path:
        sys.path.insert(0, str(IR_KIT_DIR.parent))

    # Import from parent package
    try:
        from admin.security.incident_response_kit import (
            IncidentStatus, IncidentPhase, IncidentSeverity, IncidentType,
            response_config, tool_paths, CONFIG_AVAILABLE, MODULE_PATH,
            sanitize_incident_id
        )
        from admin.security.incident_response_kit.coordination.status_tracker import (
            get_incident_status, initialize_incident_status, update_incident_status
        )
        from admin.security.incident_response_kit.templates import (
            get_template, render_template, DEFAULT_INCIDENT_TEMPLATE,
            get_template_variables
        )
        PARENT_IMPORTS_AVAILABLE = True
    except ImportError as e:
        logger.warning(f"Failed to import parent package components: {e}")
        PARENT_IMPORTS_AVAILABLE = False

        # Define fallback classes/constants if imports fail
        class IncidentStatus:
            OPEN = "open"
            INVESTIGATING = "investigating"
            CONTAINED = "contained"
            ERADICATED = "eradicated"
            RECOVERING = "recovering"
            RESOLVED = "resolved"
            CLOSED = "closed"
            MERGED = "merged"

        class IncidentPhase:
            IDENTIFICATION = "identification"
            CONTAINMENT = "containment"
            ERADICATION = "eradication"
            RECOVERY = "recovery"
            LESSONS_LEARNED = "lessons_learned"

        class IncidentSeverity:
            CRITICAL = "critical"
            HIGH = "high"
            MEDIUM = "medium"
            LOW = "low"

        DEFAULT_INCIDENT_TEMPLATE = "incident_report.md"
        response_config = {}
        tool_paths = {}
        CONFIG_AVAILABLE = False
        MODULE_PATH = Path(__file__).resolve().parent.parent

        def sanitize_incident_id(incident_id: str) -> str:
            return re.sub(r'[^a-zA-Z0-9_\-]', '_', incident_id)

        def get_incident_status(incident_id: str) -> Optional[Dict[str, Any]]:
            return None

        def get_template(template_name: str, template_dir: Optional[Path] = None) -> Optional[str]:
            return None

        def render_template(template_content: str, variables: Dict[str, Any]) -> str:
            return template_content

        def get_template_variables() -> Dict[str, List[str]]:
            return {}

    # Try to import core security audit logging if available
    try:
        from core.security.cs_audit import log_security_event
        AUDIT_AVAILABLE = True
    except ImportError:
        AUDIT_AVAILABLE = False
        logger.debug("Security audit logging not available")

        def log_security_event(*args, **kwargs):
            """Placeholder for audit logging when not available."""
            pass

except Exception as e:
    logger.error(f"Error during module initialization: {e}")
    # Define basic fallbacks for critical components
    PARENT_IMPORTS_AVAILABLE = False
    AUDIT_AVAILABLE = False

# Define constants
DEFAULT_TEMPLATE_DIR = IR_KIT_DIR / "templates" if 'IR_KIT_DIR' in locals() else Path("./templates")
DEFAULT_REPORT_DIR = Path("/secure/incident_reports")
REPORT_FORMATS = ["text", "markdown", "json", "html", "pdf"]

# Ensure report directory exists
try:
    DEFAULT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
except Exception as e:
    logger.warning(f"Could not create report directory: {e}")


def generate_report(
    incident_id: str,
    report_type: str = "status",
    output_format: str = "markdown",
    output_file: Optional[Union[str, Path]] = None,
    template_name: Optional[str] = None,
    variables: Optional[Dict[str, Any]] = None,
    include_all: bool = False
) -> Optional[Union[str, Dict[str, Any]]]:
    """
    Generate a report for an incident.

    Args:
        incident_id: The ID of the incident
        report_type: Type of report to generate (status, full, timeline, etc.)
        output_format: Format of the output report (markdown, text, json, html, pdf)
        output_file: Optional path to save the report
        template_name: Optional template name to use (default depends on report_type)
        variables: Optional additional variables for the template
        include_all: Whether to include all details (history, notes, etc.)

    Returns:
        Generated report content or dictionary, or None on failure
    """
    try:
        # Sanitize and validate inputs
        incident_id = sanitize_incident_id(incident_id)

        if output_format not in REPORT_FORMATS:
            logger.error(f"Unsupported report format: {output_format}")
            return None

        # Handle different report types
        if report_type == "status":
            return generate_status_report(
                incident_id=incident_id,
                output_format=output_format,
                output_file=output_file,
                include_all=include_all
            )
        elif report_type == "full":
            return generate_full_report(
                incident_id=incident_id,
                output_format=output_format,
                output_file=output_file,
                template_name=template_name,
                variables=variables
            )
        elif report_type == "timeline":
            return generate_timeline_report(
                incident_id=incident_id,
                output_format=output_format,
                output_file=output_file,
                template_name=template_name,
                variables=variables
            )
        else:
            logger.error(f"Unsupported report type: {report_type}")
            return None

    except Exception as e:
        logger.error(f"Error generating report: {e}", exc_info=True)
        return None


def generate_status_report(
    incident_id: str,
    output_format: str = "text",
    output_file: Optional[Union[str, Path]] = None,
    include_all: bool = False
) -> Optional[Union[str, Dict[str, Any]]]:
    """
    Generate a status report for an incident. This report provides a concise
    summary of the current incident status.

    Args:
        incident_id: The ID of the incident
        output_format: Format of the output report (text, json, markdown, html, pdf)
        output_file: Optional path to save the report
        include_all: Whether to include all history and notes

    Returns:
        Generated report content or dictionary, or None on failure
    """
    try:
        # Get incident data from status tracker
        data = get_incident_status(incident_id)
        if not data:
            logger.error(f"No data found for incident {incident_id}")
            return None

        # Format varies based on output type
        if output_format == "json":
            # For JSON, return the data structure directly
            result = {
                "incident_report": {
                    "id": incident_id,
                    "type": data.get("incident_type", "Unknown"),
                    "severity": data.get("severity", "Unknown"),
                    "status": data.get("status", "Unknown"),
                    "phase": data.get("current_phase", "Unknown"),
                    "lead_responder": data.get("lead_responder", "Unassigned"),
                    "created_at": data.get("created_at", "Unknown"),
                    "updated_at": data.get("updated_at", "Unknown"),
                    "description": data.get("description", "No description available")
                }
            }

            # Add metrics if available
            if "metrics" in data:
                result["incident_report"]["metrics"] = data["metrics"]

            # Add history if requested
            if include_all and "history" in data:
                result["incident_report"]["history"] = data["history"]

            # Add notes if requested
            if include_all and "notes" in data:
                result["incident_report"]["notes"] = data["notes"]

            # Write to file if requested
            if output_file:
                output_file = Path(output_file)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
                logger.info(f"JSON report saved to {output_file}")

            return result

        elif output_format in ["text", "markdown"]:
            # Generate text/markdown format
            report_lines = [
                f"INCIDENT STATUS REPORT: {incident_id}",
                f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "-" * 50,
                f"Type:         {data.get('incident_type', 'N/A')}",
                f"Severity:     {data.get('severity', 'N/A')}",
                f"Status:       {data.get('status', 'N/A')}",
                f"Phase:        {data.get('current_phase', 'N/A')}",
                f"Lead:         {data.get('lead_responder', 'N/A')}",
                f"Created:      {data.get('created_at', 'N/A')}",
                f"Last Updated: {data.get('updated_at', 'N/A')}",
                f"Description:  {data.get('description', 'N/A')}",
            ]

            # Add metrics if available
            if "metrics" in data:
                report_lines.append("\n--- Metrics ---")
                metrics = data["metrics"]
                for key, value in metrics.items():
                    report_lines.append(f"  {key}: {value}")

            # Add history section if requested
            if include_all and "history" in data:
                report_lines.append("\n--- History ---")
                history = data.get('history', [])

                # Sort by timestamp (newest first)
                history_to_show = sorted(
                    history,
                    key=lambda x: x.get('timestamp', ''),
                    reverse=True
                )

                if not history_to_show:
                    report_lines.append("  No history available")
                else:
                    for entry in history_to_show:
                        # Format details for cleaner display
                        details = entry.get('details', {})
                        details_formatted = []

                        for key, value in details.items():
                            if key == 'phase_change' and isinstance(value, dict):
                                details_formatted.append(f"phase changed from '{value.get('old')}' to '{value.get('new')}'")
                            elif key == 'status_change' and isinstance(value, dict):
                                details_formatted.append(f"status changed from '{value.get('old')}' to '{value.get('new')}'")
                            elif key == 'severity_change' and isinstance(value, dict):
                                details_formatted.append(f"severity changed from '{value.get('old')}' to '{value.get('new')}'")
                            elif key == 'note_added':
                                details_formatted.append(f"note added")
                            elif key == 'escalated' and value:
                                details_formatted.append("incident escalated")
                            else:
                                details_formatted.append(f"{key}: {value}")

                        details_str = ", ".join(details_formatted) if details_formatted else ""
                        report_lines.append(f"  [{entry.get('timestamp')}] {entry.get('action')} by {entry.get('user')}: {details_str}")

            # Add notes section if requested
            if include_all and "notes" in data:
                report_lines.append("\n--- Notes ---")
                notes = data.get('notes', [])

                # Sort by timestamp (newest first)
                notes_to_show = sorted(
                    notes,
                    key=lambda x: x.get('timestamp', ''),
                    reverse=True
                )

                if not notes_to_show:
                    report_lines.append("  No notes available")
                else:
                    for entry in notes_to_show:
                        report_lines.append(f"  [{entry.get('timestamp')}] by {entry.get('user')}:")
                        note_text = entry.get('note', '')

                        # Format multi-line notes with proper indentation
                        if '\n' in note_text:
                            note_lines = note_text.split('\n')
                            report_lines.append(f"    {note_lines[0]}")
                            for line in note_lines[1:]:
                                report_lines.append(f"    {line}")
                        else:
                            report_lines.append(f"    {note_text}")

            result = "\n".join(report_lines)

            # Write to file if requested
            if output_file:
                output_file = Path(output_file)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write(result)
                logger.info(f"Status report saved to {output_file}")

            return result

        elif output_format in ["html", "pdf"]:
            # For now, we'll generate a simple HTML document for both HTML and PDF
            # In a real implementation, you'd use a proper PDF library for PDF output

            html_result = f"""<!DOCTYPE html>
<html>
<head>
    <title>Incident Status Report: {incident_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin-bottom: 20px; }}
        .label {{ font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Incident Status Report: {incident_id}</h1>
    <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

    <div class="section">
        <p><span class="label">Type:</span> {data.get('incident_type', 'N/A')}</p>
        <p><span class="label">Severity:</span> {data.get('severity', 'N/A')}</p>
        <p><span class="label">Status:</span> {data.get('status', 'N/A')}</p>
        <p><span class="label">Phase:</span> {data.get('current_phase', 'N/A')}</p>
        <p><span class="label">Lead:</span> {data.get('lead_responder', 'N/A')}</p>
        <p><span class="label">Created:</span> {data.get('created_at', 'N/A')}</p>
        <p><span class="label">Last Updated:</span> {data.get('updated_at', 'N/A')}</p>
        <p><span class="label">Description:</span> {data.get('description', 'N/A')}</p>
    </div>
"""

            # Add metrics if available
            if "metrics" in data:
                html_result += '<div class="section"><h2>Metrics</h2><ul>'
                metrics = data["metrics"]
                for key, value in metrics.items():
                    html_result += f'<li><strong>{key}:</strong> {value}</li>'
                html_result += '</ul></div>'

            # Add history section if requested
            if include_all and "history" in data:
                html_result += '<div class="section"><h2>History</h2>'
                history = data.get('history', [])

                # Sort by timestamp (newest first)
                history_to_show = sorted(
                    history,
                    key=lambda x: x.get('timestamp', ''),
                    reverse=True
                )

                if not history_to_show:
                    html_result += '<p>No history available</p>'
                else:
                    html_result += '<table><tr><th>Timestamp</th><th>Action</th><th>User</th><th>Details</th></tr>'
                    for entry in history_to_show:
                        # Format details for cleaner display
                        details = entry.get('details', {})
                        details_formatted = []

                        for key, value in details.items():
                            if key == 'phase_change' and isinstance(value, dict):
                                details_formatted.append(f"phase changed from '{value.get('old')}' to '{value.get('new')}'")
                            elif key == 'status_change' and isinstance(value, dict):
                                details_formatted.append(f"status changed from '{value.get('old')}' to '{value.get('new')}'")
                            elif key == 'severity_change' and isinstance(value, dict):
                                details_formatted.append(f"severity changed from '{value.get('old')}' to '{value.get('new')}'")
                            elif key == 'note_added':
                                details_formatted.append(f"note added")
                            elif key == 'escalated' and value:
                                details_formatted.append("incident escalated")
                            else:
                                details_formatted.append(f"{key}: {value}")

                        details_str = ", ".join(details_formatted) if details_formatted else ""
                        html_result += f'<tr><td>{entry.get("timestamp")}</td><td>{entry.get("action")}</td><td>{entry.get("user")}</td><td>{details_str}</td></tr>'
                    html_result += '</table>'
                html_result += '</div>'

            # Add notes section if requested
            if include_all and "notes" in data:
                html_result += '<div class="section"><h2>Notes</h2>'
                notes = data.get('notes', [])

                # Sort by timestamp (newest first)
                notes_to_show = sorted(
                    notes,
                    key=lambda x: x.get('timestamp', ''),
                    reverse=True
                )

                if not notes_to_show:
                    html_result += '<p>No notes available</p>'
                else:
                    for i, entry in enumerate(notes_to_show):
                        note_text = entry.get('note', '').replace('\n', '<br>')
                        html_result += f'<div class="note"><p><strong>[{entry.get("timestamp")}] by {entry.get("user")}:</strong></p>'
                        html_result += f'<p>{note_text}</p></div>'
                        if i < len(notes_to_show) - 1:
                            html_result += '<hr>'
                html_result += '</div>'

            # Close HTML document
            html_result += '</body></html>'

            # Write to file if requested
            if output_file:
                output_file = Path(output_file)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write(html_result)
                logger.info(f"HTML report saved to {output_file}")

            return html_result

        else:
            logger.error(f"Unsupported report format: {output_format}")
            return None

    except Exception as e:
        logger.error(f"Error generating status report: {e}", exc_info=True)
        return None


def generate_full_report(
    incident_id: str,
    output_format: str = "markdown",
    output_file: Optional[Union[str, Path]] = None,
    template_name: Optional[str] = None,
    variables: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """
    Generate a full incident report from templates.

    Args:
        incident_id: The ID of the incident
        output_format: Format of the output report (markdown, html, pdf)
        output_file: Optional path to save the report
        template_name: Optional template name to use
        variables: Optional additional variables for the template

    Returns:
        Generated report content or None on failure
    """
    try:
        # Use default template if none provided
        if not template_name:
            template_name = DEFAULT_INCIDENT_TEMPLATE

        # Get incident data from status tracker
        incident_data = get_incident_status(incident_id)
        if not incident_data:
            logger.error(f"No data found for incident {incident_id}")
            return None

        # Create a dictionary of template variables
        template_variables = variables or {}

        # Add standard variables from incident data
        template_variables.update({
            "INCIDENT_ID": incident_id,
            "INCIDENT_TYPE": incident_data.get("incident_type", "Unknown"),
            "SEVERITY": incident_data.get("severity", "Unknown"),
            "STATUS": incident_data.get("status", "Unknown"),
            "PHASE": incident_data.get("current_phase", "Unknown"),
            "LEAD_RESPONDER": incident_data.get("lead_responder", "Unassigned"),
            "DATE": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "LAST_UPDATED": incident_data.get("updated_at", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
            "REPORT_VERSION": "1.0",
            "CLASSIFICATION": "Internal"
        })

        # Add description if available
        if "description" in incident_data:
            template_variables["EXECUTIVE_SUMMARY"] = incident_data["description"]

        # Add metrics if available
        if "metrics" in incident_data:
            for key, value in incident_data["metrics"].items():
                template_variables[f"METRIC_{key.upper()}"] = value

        # Get available template variables to check what we're missing
        available_vars = get_template_variables()

        # For variables not set, use placeholders
        for var_category, var_list in available_vars.items():
            for var in var_list:
                if var not in template_variables:
                    template_variables[var] = f"{{Insert {var.lower().replace('_', ' ')} here}}"

        # Get the template content
        template_content = get_template(template_name)
        if not template_content:
            logger.error(f"Template not found: {template_name}")
            return None

        # Render the template with variables
        rendered_content = render_template(template_content, template_variables)

        # For now, we only support markdown output for full reports
        # In a real implementation, you'd support conversion to other formats
        if output_format != "markdown":
            logger.warning(f"Output format {output_format} not fully supported for full reports. Using markdown.")

        # Write to file if requested
        if output_file:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(rendered_content)
            logger.info(f"Full report saved to {output_file}")

        return rendered_content

    except Exception as e:
        logger.error(f"Error generating full report: {e}", exc_info=True)
        return None


def generate_timeline_report(
    incident_id: str,
    output_format: str = "markdown",
    output_file: Optional[Union[str, Path]] = None,
    template_name: Optional[str] = None,
    variables: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """
    Generate a timeline report for an incident.

    Args:
        incident_id: The ID of the incident
        output_format: Format of the output report (markdown, html, pdf)
        output_file: Optional path to save the report
        template_name: Optional template name to use
        variables: Optional additional variables for the template

    Returns:
        Generated report content or None on failure
    """
    try:
        # Use default template if none provided
        if not template_name:
            template_name = "incident_timeline.md"

        # Get incident data from status tracker
        incident_data = get_incident_status(incident_id)
        if not incident_data:
            logger.error(f"No data found for incident {incident_id}")
            return None

        # Create a dictionary of template variables
        template_variables = variables or {}

        # Add standard variables from incident data
        template_variables.update({
            "INCIDENT_ID": incident_id,
            "INCIDENT_TYPE": incident_data.get("incident_type", "Unknown"),
            "SEVERITY": incident_data.get("severity", "Unknown"),
            "STATUS": incident_data.get("status", "Unknown"),
            "PHASE": incident_data.get("current_phase", "Unknown"),
            "LEAD_RESPONDER": incident_data.get("lead_responder", "Unassigned"),
            "DATE": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "LAST_UPDATED": incident_data.get("updated_at", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
            "REPORT_VERSION": "1.0"
        })

        # Build timeline events from history
        timeline_events = []
        if "history" in incident_data:
            for entry in incident_data["history"]:
                timestamp = entry.get("timestamp", "")
                action = entry.get("action", "")
                user = entry.get("user", "")
                details = entry.get("details", {})

                # Format details for timeline
                event_details = ""
                if "status_change" in details:
                    old = details["status_change"].get("old", "")
                    new = details["status_change"].get("new", "")
                    event_details = f"Status changed from {old} to {new}"
                elif "phase_change" in details:
                    old = details["phase_change"].get("old", "")
                    new = details["phase_change"].get("new", "")
                    event_details = f"Phase changed from {old} to {new}"
                elif "note_added" in details:
                    event_details = "Note added"
                elif "escalated" in details and details["escalated"]:
                    event_details = "Incident escalated"
                else:
                    # Generic handling for other actions
                    event_details = action

                # Add formatted event to timeline
                timeline_events.append({
                    "timestamp": timestamp,
                    "event": event_details,
                    "user": user
                })

        # Sort events by timestamp
        sorted_events = sorted(timeline_events, key=lambda x: x["timestamp"])

        # Create timeline table in markdown
        timeline_table = "| Date/Time (UTC) | Event | Performed By |\n"
        timeline_table += "|-----------------|-------|-------------|\n"

        for event in sorted_events:
            timeline_table += f"| {event['timestamp']} | {event['event']} | {event['user']} |\n"

        # Add timeline to variables
        template_variables["TIMELINE_EVENTS"] = timeline_table

        # Get the template content
        template_content = get_template(template_name)
        if not template_content:
            # Fallback to simple table if template not found
            logger.warning(f"Template not found: {template_name}, using simple timeline")
            template_content = """# Incident Timeline for {{INCIDENT_ID}}

## Incident Details

- **Type:** {{INCIDENT_TYPE}}
- **Severity:** {{SEVERITY}}
- **Current Status:** {{STATUS}}
- **Current Phase:** {{PHASE}}
- **Lead Responder:** {{LEAD_RESPONDER}}

## Timeline of Events

{{TIMELINE_EVENTS}}

Report generated: {{DATE}}
"""

        # Render the template with variables
        rendered_content = render_template(template_content, template_variables)

        # For now, we only support markdown output for timeline reports
        # In a real implementation, you'd support conversion to other formats
        if output_format != "markdown":
            logger.warning(f"Output format {output_format} not fully supported for timeline reports. Using markdown.")

        # Write to file if requested
        if output_file:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(rendered_content)
            logger.info(f"Timeline report saved to {output_file}")

        return rendered_content

    except Exception as e:
        logger.error(f"Error generating timeline report: {e}", exc_info=True)
        return None


# Command-line interface
def main():
    """Command-line interface for the report generator."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate reports for security incidents")
    parser.add_argument("--incident-id", required=True, help="Incident identifier")
    parser.add_argument("--report-type", choices=["status", "full", "timeline"], default="status",
                      help="Type of report to generate")
    parser.add_argument("--format", choices=REPORT_FORMATS, default="markdown",
                      help="Report output format")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--template", help="Custom template name")
    parser.add_argument("--all", action="store_true", help="Include all details (history, notes, etc.)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Configure logging based on arguments
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    # Generate the report
    report = generate_report(
        incident_id=args.incident_id,
        report_type=args.report_type,
        output_format=args.format,
        output_file=args.output if args.output else None,
        template_name=args.template if args.template else None,
        include_all=args.all
    )

    # Output report to console if no output file specified
    if report and not args.output:
        print(report)

    # Exit with status code based on success
    sys.exit(0 if report else 1)


# Module exports
__all__ = [
    'generate_report',
    'generate_status_report',
    'generate_full_report',
    'generate_timeline_report',
    'REPORT_FORMATS'
]

# Run as script
if __name__ == "__main__":
    main()
