"""
Audit Data Export Module

This module provides functions for exporting audit logs in various formats
(JSON, CSV, PDF) for reporting, compliance documentation, and archival purposes.
All exports implement proper data sanitization and formatting consistent with
security best practices.
"""

import logging
import json
import csv
import os
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union
from io import StringIO, BytesIO

from flask import Response, current_app
from sqlalchemy import desc
from sqlalchemy.exc import SQLAlchemyError

from models.security.audit_log import AuditLog
from models.auth.user import User
from .filters import build_audit_query
from core.security.cs_audit import log_security_event

# Initialize logger
logger = logging.getLogger(__name__)

def export_audit_data(
    format_type: str,
    start_date: datetime,
    end_date: datetime,
    filters: Dict[str, Any] = None
) -> Union[Dict[str, Any], str, bytes, Response]:
    """
    Export audit logs in various formats.

    Args:
        format_type: Format to export ('json', 'csv', 'pdf')
        start_date: Start date for logs to export
        end_date: End date for logs to export
        filters: Additional filters to apply to the query

    Returns:
        Exported data in requested format (dict for JSON, Response for others)
    """
    try:
        # Build query with filters
        query_filters = {
            'start_date': start_date.isoformat() if start_date else None,
            'end_date': end_date.isoformat() if end_date else None
        }

        # Add additional filters if provided
        if filters:
            query_filters.update(filters)

        query = build_audit_query(query_filters)

        # Order by timestamp (newest first)
        query = query.order_by(desc(AuditLog.created_at))

        # Execute query and get results
        logs = query.all()

        # Count of exported logs
        log_count = len(logs)
        logger.info(f"Exporting {log_count} audit logs in {format_type} format")

        # Format the logs based on requested format
        if format_type == 'json':
            return _export_json(logs)
        elif format_type == 'csv':
            return _export_csv(logs)
        elif format_type == 'pdf':
            return _export_pdf(logs, start_date, end_date)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    except SQLAlchemyError as e:
        logger.error(f"Database error during audit export: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error exporting audit logs: {str(e)}", exc_info=True)
        raise

def _export_json(logs: List[AuditLog]) -> Dict[str, Any]:
    """
    Export audit logs as JSON.

    Args:
        logs: List of AuditLog objects

    Returns:
        Dict containing the exported logs
    """
    # Format the logs
    formatted_logs = []
    for log in logs:
        # Get username if available
        username = None
        if log.user_id:
            user = User.query.get(log.user_id)
            if user:
                username = user.username

        # Format log entry
        log_entry = {
            'id': log.id,
            'timestamp': log.created_at.isoformat() if log.created_at else None,
            'event_type': log.event_type,
            'category': log.category,
            'description': log.description,
            'user_id': log.user_id,
            'username': username,
            'severity': log.severity,
            'ip_address': log.ip_address,
            'user_agent': log.user_agent
        }

        # Add details if they exist
        if log.details:
            try:
                # If details is stored as a JSON string
                if isinstance(log.details, str):
                    log_entry['details'] = json.loads(log.details)
                else:
                    log_entry['details'] = log.details
            except json.JSONDecodeError:
                log_entry['details'] = log.details

        # Add additional fields
        if hasattr(log, 'object_type') and log.object_type:
            log_entry['object_type'] = log.object_type
        if hasattr(log, 'object_id') and log.object_id:
            log_entry['object_id'] = log.object_id

        formatted_logs.append(log_entry)

    # Create result with metadata
    result = {
        'logs': formatted_logs,
        'count': len(formatted_logs),
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'export_format': 'json'
    }

    return result

def _export_csv(logs: List[AuditLog]) -> Response:
    """
    Export audit logs as CSV.

    Args:
        logs: List of AuditLog objects

    Returns:
        Flask Response with CSV data
    """
    # Create CSV in memory
    output = StringIO()
    csv_writer = csv.writer(output)

    # Define headers
    headers = [
        'id', 'timestamp', 'event_type', 'category', 'description',
        'user_id', 'username', 'severity', 'ip_address', 'user_agent',
        'details', 'object_type', 'object_id'
    ]

    # Write headers
    csv_writer.writerow(headers)

    # Write data rows
    for log in logs:
        # Get username if available
        username = None
        if log.user_id:
            user = User.query.get(log.user_id)
            if user:
                username = user.username

        # Format details for CSV
        details_str = ''
        if log.details:
            if isinstance(log.details, str):
                details_str = log.details
            else:
                details_str = json.dumps(log.details)

        # Create row
        row = [
            log.id,
            log.created_at.isoformat() if log.created_at else '',
            log.event_type,
            log.category,
            log.description,
            log.user_id,
            username,
            log.severity,
            log.ip_address,
            log.user_agent,
            details_str,
            getattr(log, 'object_type', ''),
            getattr(log, 'object_id', '')
        ]

        csv_writer.writerow(row)

    # Create response
    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        }
    )

    return response

def _export_pdf(logs: List[AuditLog], start_date: datetime, end_date: datetime) -> Response:
    """
    Export audit logs as PDF.

    Args:
        logs: List of AuditLog objects
        start_date: Start date for the export period
        end_date: End date for the export period

    Returns:
        Flask Response with PDF data
    """
    try:
        # Try to import PDF generation libraries
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.units import inch
    except ImportError:
        logger.error("ReportLab library not installed. PDF export unavailable.")
        raise RuntimeError("PDF export requires ReportLab library.")

    # Create temporary file for the PDF
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
        pdf_path = tmp_file.name

    # Set up the document
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=landscape(letter),
        rightMargin=0.5*inch,
        leftMargin=0.5*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch
    )

    # Define styles
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']

    # Add custom styles
    small_style = ParagraphStyle(
        'Small',
        parent=normal_style,
        fontSize=8
    )

    # Create content elements
    elements = []

    # Add title
    elements.append(Paragraph("Audit Log Export", title_style))
    elements.append(Spacer(1, 0.2*inch))

    # Add export info
    export_time = datetime.now(timezone.utc)
    elements.append(Paragraph(f"Generated: {export_time.strftime('%Y-%m-%d %H:%M:%S UTC')}", normal_style))
    elements.append(Paragraph(f"Period: {start_date.strftime('%Y-%m-%d %H:%M:%S')} to {end_date.strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Paragraph(f"Total Records: {len(logs)}", normal_style))
    elements.append(Spacer(1, 0.2*inch))

    # Add summary section
    elements.append(Paragraph("Summary", subtitle_style))

    # Count events by severity
    severity_counts = {}
    for log in logs:
        severity = log.severity or 'unknown'
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Create summary table
    summary_data = [['Severity', 'Count']]
    for severity, count in severity_counts.items():
        summary_data.append([severity.title(), count])

    summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 0.2*inch))

    # Add logs table
    elements.append(Paragraph("Audit Logs", subtitle_style))

    # Define table headers and data
    table_data = [['Time', 'Event Type', 'User', 'Severity', 'Description']]

    # Add log entries
    for log in logs:
        # Get username if available
        username = str(log.user_id)
        if log.user_id:
            user = User.query.get(log.user_id)
            if user:
                username = user.username

        # Format timestamp
        timestamp = log.created_at.strftime('%Y-%m-%d %H:%M:%S') if log.created_at else 'N/A'

        # Format description (limit length)
        description = log.description
        if description and len(description) > 100:
            description = description[:97] + '...'

        # Add row
        table_data.append([
            timestamp,
            log.event_type or 'N/A',
            username,
            log.severity or 'N/A',
            description or 'N/A'
        ])

    # Create and style the table
    logs_table = Table(table_data, repeatRows=1)
    logs_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),  # Smaller font for data rows
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        # Alternate row colors for readability
        *[('BACKGROUND', (0, i), (-1, i), colors.lightgrey) for i in range(2, len(table_data), 2)]
    ]))

    elements.append(logs_table)

    # Add footer
    elements.append(Spacer(1, 0.5*inch))
    footer_text = (
        "CONFIDENTIAL: This audit log export contains sensitive security information. "
        "Handle according to your organization's data classification policy."
    )
    elements.append(Paragraph(footer_text, small_style))

    # Build the PDF document
    doc.build(elements)

    # Create response from file
    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()

    # Clean up the temporary file
    os.unlink(pdf_path)

    # Create response
    response = Response(
        pdf_data,
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        }
    )

    return response
