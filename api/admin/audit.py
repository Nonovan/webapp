"""
Administrative audit functions for the Cloud Infrastructure Platform.

This module provides functions for retrieving, analyzing, and exporting audit logs
and security events for administrative purposes. It supports comprehensive filtering,
export in multiple formats, and generation of compliance reports.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple, Union

from flask import current_app, jsonify
from sqlalchemy import desc, func, or_, and_
from sqlalchemy.exc import SQLAlchemyError

from models.security.audit_log import AuditLog
from models.auth.user import User
from core.security.cs_audit import get_recent_security_events
from extensions import db

# Initialize logger
logger = logging.getLogger(__name__)

def get_audit_logs(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user_id: Optional[int] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = 1,
    per_page: int = 50
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Retrieve audit logs with filtering options.

    Args:
        start_date: ISO format start date for filtering
        end_date: ISO format end date for filtering
        user_id: Filter logs by user ID
        event_type: Filter logs by event type
        severity: Filter logs by severity level
        page: Page number for pagination
        per_page: Number of items per page

    Returns:
        Tuple containing:
        - List of audit log dictionaries
        - Total count of matching logs
        - Total number of pages
    """
    try:
        # Parse date strings to datetime objects
        start_dt = None
        end_dt = None

        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Invalid start_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS+TZ).")

        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Invalid end_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS+TZ).")

        # Build query with filters
        query = AuditLog.query

        if start_dt:
            query = query.filter(AuditLog.created_at >= start_dt)

        if end_dt:
            query = query.filter(AuditLog.created_at <= end_dt)

        if user_id:
            query = query.filter(AuditLog.user_id == user_id)

        if event_type:
            query = query.filter(AuditLog.event_type == event_type)

        if severity:
            # Map the severity string to the constant if needed
            severity_map = {
                'info': AuditLog.SEVERITY_INFO,
                'warning': AuditLog.SEVERITY_WARNING,
                'error': AuditLog.SEVERITY_ERROR,
                'critical': AuditLog.SEVERITY_CRITICAL
            }
            db_severity = severity_map.get(severity.lower(), severity)
            query = query.filter(AuditLog.severity == db_severity)

        # Get total count before pagination
        total_count = query.count()

        # Calculate total pages
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

        # Apply pagination and ordering
        query = query.order_by(AuditLog.created_at.desc())
        query = query.offset((page - 1) * per_page).limit(per_page)

        # Execute query
        logs = query.all()

        # Format logs for response
        result = []
        for log in logs:
            log_entry = log.to_dict()

            # Fetch username for display if available
            if log.user_id:
                user = User.query.get(log.user_id)
                if user:
                    log_entry['username'] = user.username

            result.append(log_entry)

        return result, total_count, total_pages

    except SQLAlchemyError as e:
        logger.error(f"Database error in get_audit_logs: {str(e)}")
        raise ValueError("A database error occurred while retrieving audit logs")
    except Exception as e:
        logger.error(f"Unexpected error in get_audit_logs: {str(e)}")
        raise ValueError(f"Failed to retrieve audit logs: {str(e)}")


def get_security_events(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    page: int = 1,
    per_page: int = 50
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Retrieve security events with filtering options.

    Args:
        start_date: ISO format start date for filtering
        end_date: ISO format end date for filtering
        severity: Filter events by severity level
        event_type: Filter events by event type
        page: Page number for pagination
        per_page: Number of items per page

    Returns:
        Tuple containing:
        - List of security event dictionaries
        - Total count of matching events
        - Total number of pages
    """
    try:
        # Parse date strings to datetime objects
        start_dt = None
        end_dt = None

        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Invalid start_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS+TZ).")

        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Invalid end_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS+TZ).")

        # Default to last 24 hours if no dates provided
        if not start_dt and not end_dt:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(hours=24)

        # Build query with filters
        query = AuditLog.query.filter(
            AuditLog.category == AuditLog.EVENT_CATEGORY_SECURITY
        )

        if start_dt:
            query = query.filter(AuditLog.created_at >= start_dt)

        if end_dt:
            query = query.filter(AuditLog.created_at <= end_dt)

        if severity:
            # Map the severity string to the constant if needed
            severity_map = {
                'info': AuditLog.SEVERITY_INFO,
                'warning': AuditLog.SEVERITY_WARNING,
                'error': AuditLog.SEVERITY_ERROR,
                'critical': AuditLog.SEVERITY_CRITICAL
            }
            db_severity = severity_map.get(severity.lower(), severity)
            query = query.filter(AuditLog.severity == db_severity)

        if event_type:
            query = query.filter(AuditLog.event_type == event_type)

        # Get total count before pagination
        total_count = query.count()

        # Calculate total pages
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

        # Apply pagination and ordering
        query = query.order_by(AuditLog.severity.desc(), AuditLog.created_at.desc())
        query = query.offset((page - 1) * per_page).limit(per_page)

        # Execute query
        events = query.all()

        # Format logs for response
        result = []
        for event in events:
            event_entry = event.to_dict()

            # Fetch username for display if available
            if event.user_id:
                user = User.query.get(event.user_id)
                if user:
                    event_entry['username'] = user.username

            result.append(event_entry)

        return result, total_count, total_pages

    except SQLAlchemyError as e:
        logger.error(f"Database error in get_security_events: {str(e)}")
        raise ValueError("A database error occurred while retrieving security events")
    except Exception as e:
        logger.error(f"Unexpected error in get_security_events: {str(e)}")
        raise ValueError(f"Failed to retrieve security events: {str(e)}")


def export_audit_data(
    format_type: str,
    start_date: str,
    end_date: str,
    filters: Dict[str, Any] = None
) -> Union[Dict[str, Any], str]:
    """
    Export audit logs in various formats.

    Args:
        format_type: Export format ('json', 'csv', or 'pdf')
        start_date: ISO format start date
        end_date: ISO format end date
        filters: Additional filters to apply to the query

    Returns:
        Exported data in the specified format:
        - JSON: Dictionary of audit data
        - CSV: CSV string
        - PDF: PDF content
    """
    try:
        # Parse date strings to datetime objects
        start_dt = None
        end_dt = None

        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Invalid start_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS+TZ).")
        else:
            raise ValueError("start_date is required")

        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Invalid end_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS+TZ).")
        else:
            raise ValueError("end_date is required")

        # Check export size limit
        export_limit = current_app.config.get('AUDIT_EXPORT_LIMIT', 50000)

        # Build query with filters
        query = AuditLog.query.filter(
            AuditLog.created_at.between(start_dt, end_dt)
        )

        # Apply additional filters
        if filters:
            if filters.get('user_id'):
                query = query.filter(AuditLog.user_id == filters['user_id'])

            if filters.get('event_type'):
                query = query.filter(AuditLog.event_type == filters['event_type'])

            if filters.get('severity'):
                severity_map = {
                    'info': AuditLog.SEVERITY_INFO,
                    'warning': AuditLog.SEVERITY_WARNING,
                    'error': AuditLog.SEVERITY_ERROR,
                    'critical': AuditLog.SEVERITY_CRITICAL
                }
                db_severity = severity_map.get(filters['severity'].lower(), filters['severity'])
                query = query.filter(AuditLog.severity == db_severity)

            if filters.get('category'):
                query = query.filter(AuditLog.category == filters['category'])

        # Check count against limit
        count = query.count()
        if count > export_limit:
            raise ValueError(f"Export exceeds maximum limit of {export_limit} records. Please refine your filters.")

        # Get all matching logs
        logs = query.order_by(AuditLog.created_at.desc()).all()

        # Format for export
        if format_type == 'json':
            return {
                'metadata': {
                    'export_date': datetime.now(timezone.utc).isoformat(),
                    'start_date': start_dt.isoformat(),
                    'end_date': end_dt.isoformat(),
                    'record_count': len(logs),
                    'filters': filters
                },
                'logs': [log.to_dict() for log in logs]
            }

        elif format_type == 'csv':
            import csv
            import io

            # Prepare CSV data
            output = io.StringIO()
            fieldnames = ['id', 'timestamp', 'event_type', 'severity', 'user_id',
                         'ip_address', 'description', 'category', 'object_type', 'object_id']

            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for log in logs:
                writer.writerow({
                    'id': log.id,
                    'timestamp': log.created_at.isoformat() if log.created_at else '',
                    'event_type': log.event_type,
                    'severity': log.severity,
                    'user_id': log.user_id,
                    'ip_address': log.ip_address,
                    'description': log.description,
                    'category': log.category,
                    'object_type': log.object_type,
                    'object_id': log.object_id
                })

            return output.getvalue()

        elif format_type == 'pdf':
            # For PDF generation, we'll integrate with a PDF generation module
            # This is a simplified example that would need to be replaced with actual PDF generation
            try:
                from api.audit.exporters import generate_pdf_export

                # Use the audit exporters module to generate the PDF
                return generate_pdf_export([log.to_dict() for log in logs], {
                    'title': 'Audit Log Export',
                    'start_date': start_dt.isoformat(),
                    'end_date': end_dt.isoformat(),
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'filters': filters
                })

            except ImportError:
                logger.error("PDF export module not available")
                raise ValueError("PDF export is not available. Please use JSON or CSV format.")

        else:
            raise ValueError(f"Unsupported format: {format_type}. Use 'json', 'csv', or 'pdf'")

    except SQLAlchemyError as e:
        logger.error(f"Database error in export_audit_data: {str(e)}")
        raise ValueError("A database error occurred while exporting audit data")
    except Exception as e:
        logger.error(f"Unexpected error in export_audit_data: {str(e)}")
        raise ValueError(f"Failed to export audit data: {str(e)}")


def generate_compliance_report(
    report_type: str,
    start_date: str,
    end_date: str,
    format_type: str = 'json',
    additional_params: Dict[str, Any] = None
) -> Union[Dict[str, Any], str]:
    """
    Generate a compliance report for the specified time period.

    Args:
        report_type: Type of compliance report ('soc2', 'hipaa', 'gdpr', etc.)
        start_date: ISO format start date
        end_date: ISO format end date
        format_type: Report format ('json', 'csv', or 'pdf')
        additional_params: Additional parameters for report generation

    Returns:
        Compliance report in the specified format:
        - JSON: Dictionary of report data
        - CSV: CSV string
        - PDF: PDF content
    """
    try:
        # Parse date strings to datetime objects
        start_dt = None
        end_dt = None

        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Invalid start_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS+TZ).")
        else:
            raise ValueError("start_date is required")

        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Invalid end_date format. Use ISO format (YYYY-MM-DDTHH:MM:SS+TZ).")
        else:
            raise ValueError("end_date is required")

        # Verify report type is supported
        supported_frameworks = current_app.config.get('COMPLIANCE_FRAMEWORKS', {})
        if report_type not in supported_frameworks:
            raise ValueError(f"Unsupported compliance framework: {report_type}")

        # We'll integrate with the compliance report generation views
        try:
            from api.audit.views.compliance import generate_compliance_report as gen_report

            params = additional_params or {}

            # Add default parameters
            params.update({
                'start_date': start_dt,
                'end_date': end_dt,
                'format_type': format_type
            })

            # Generate the report using the compliance view
            return gen_report(report_type=report_type, **params)

        except ImportError:
            logger.error("Compliance report module not available")

            # Fallback to a simplified report if the compliance module is not available
            return generate_fallback_compliance_report(
                report_type=report_type,
                start_date=start_dt,
                end_date=end_dt,
                format_type=format_type
            )

    except SQLAlchemyError as e:
        logger.error(f"Database error in generate_compliance_report: {str(e)}")
        raise ValueError("A database error occurred while generating compliance report")
    except Exception as e:
        logger.error(f"Unexpected error in generate_compliance_report: {str(e)}")
        raise ValueError(f"Failed to generate compliance report: {str(e)}")


def generate_fallback_compliance_report(
    report_type: str,
    start_date: datetime,
    end_date: datetime,
    format_type: str
) -> Union[Dict[str, Any], str]:
    """
    Generate a simplified compliance report when the full module is not available.

    This is a fallback implementation that provides basic compliance data
    based on audit logs.

    Args:
        report_type: Type of compliance report
        start_date: Start date for the report period
        end_date: End date for the report period
        format_type: Report format ('json', 'csv', or 'pdf')

    Returns:
        Basic compliance report in the specified format
    """
    try:
        # Define relevant event types and categories for the framework
        framework_filters = {
            'soc2': {
                'categories': ['security', 'availability', 'processing_integrity', 'confidentiality', 'privacy'],
                'event_types': [
                    AuditLog.EVENT_LOGIN_SUCCESS,
                    AuditLog.EVENT_LOGIN_FAILED,
                    AuditLog.EVENT_FILE_INTEGRITY,
                    AuditLog.EVENT_CONFIG_CHANGE
                ]
            },
            'hipaa': {
                'categories': ['security', 'access_control', 'data_protection'],
                'event_types': [
                    AuditLog.EVENT_FILE_ACCESS,
                    AuditLog.EVENT_PERMISSION_GRANTED,
                    AuditLog.EVENT_PERMISSION_REVOKED
                ]
            },
            'gdpr': {
                'categories': ['data_protection', 'privacy'],
                'event_types': [
                    AuditLog.EVENT_PERMISSION_GRANTED,
                    AuditLog.EVENT_FILE_ACCESS
                ]
            },
            'pci-dss': {
                'categories': ['security', 'access_control'],
                'event_types': [
                    AuditLog.EVENT_LOGIN_SUCCESS,
                    AuditLog.EVENT_LOGIN_FAILED,
                    AuditLog.EVENT_FILE_INTEGRITY
                ]
            }
        }

        # Use default filters if specific framework not defined
        filters = framework_filters.get(report_type, {
            'categories': ['security'],
            'event_types': []
        })

        # Build query with filters for compliance-relevant logs
        query = AuditLog.query.filter(
            AuditLog.created_at.between(start_date, end_date)
        )

        if filters.get('categories'):
            query = query.filter(AuditLog.category.in_(filters['categories']))

        if filters.get('event_types'):
            query = query.filter(AuditLog.event_type.in_(filters['event_types']))

        # Execute query
        logs = query.order_by(AuditLog.created_at).all()

        # Group logs by event type
        event_counts = {}
        for log in logs:
            event_type = log.event_type
            if event_type not in event_counts:
                event_counts[event_type] = 0
            event_counts[event_type] += 1

        # Group logs by severity
        severity_counts = {
            'critical': 0,
            'error': 0,
            'warning': 0,
            'info': 0
        }

        for log in logs:
            severity = log.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Prepare basic compliance metrics
        compliance_status = "compliant"
        if severity_counts['critical'] > 0:
            compliance_status = "non_compliant"
        elif severity_counts['error'] > 0:
            compliance_status = "partially_compliant"

        # Create report data structure
        report_data = {
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "compliance_status": compliance_status,
            "total_events": len(logs),
            "events_by_type": event_counts,
            "events_by_severity": severity_counts,
            "framework_specific_checks": {},  # Would be populated by a proper compliance module
        }

        # Format for export
        if format_type == 'json':
            return report_data

        elif format_type == 'csv':
            import csv
            import io

            # Prepare CSV data
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header and metadata
            writer.writerow(['Compliance Report', report_type])
            writer.writerow(['Generated At', datetime.now(timezone.utc).isoformat()])
            writer.writerow(['Period', f"{start_date.isoformat()} to {end_date.isoformat()}"])
            writer.writerow(['Compliance Status', compliance_status])
            writer.writerow(['Total Events', len(logs)])
            writer.writerow([])

            # Write event counts by type
            writer.writerow(['Event Type', 'Count'])
            for event_type, count in event_counts.items():
                writer.writerow([event_type, count])
            writer.writerow([])

            # Write severity counts
            writer.writerow(['Severity', 'Count'])
            for severity, count in severity_counts.items():
                writer.writerow([severity, count])

            return output.getvalue()

        elif format_type == 'pdf':
            # For PDF generation, we'll integrate with a PDF generation module
            # This is a simplified example that would need to be replaced with actual PDF generation
            try:
                from api.audit.exporters import generate_pdf_export

                # Use the audit exporters module to generate the PDF
                return generate_pdf_export(logs, {
                    'title': f'{report_type.upper()} Compliance Report',
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'compliance_status': compliance_status,
                    'generated_at': datetime.now(timezone.utc).isoformat()
                })

            except ImportError:
                logger.error("PDF export module not available")
                raise ValueError("PDF export is not available. Please use JSON or CSV format.")

        else:
            raise ValueError(f"Unsupported format: {format_type}. Use 'json', 'csv', or 'pdf'")

    except SQLAlchemyError as e:
        logger.error(f"Database error in generate_fallback_compliance_report: {str(e)}")
        raise ValueError("A database error occurred while generating compliance report")
    except Exception as e:
        logger.error(f"Unexpected error in generate_fallback_compliance_report: {str(e)}")
        raise ValueError(f"Failed to generate compliance report: {str(e)}")
