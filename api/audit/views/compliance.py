"""
Compliance Report Generation and Validation

This module provides functions for generating compliance reports,
checking compliance status, collecting control evidence, and validating
compliance requirements using audit log data.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Union, Tuple
import json

from flask import current_app, Response, send_file
from sqlalchemy import func, distinct, desc, and_, or_
from sqlalchemy.sql.expression import text

from extensions import db, cache
from api.audit.views.reports import _generate_csv_report, _generate_html_report, _generate_pdf_report
from models.auth.user import User
from models.security import AuditLog
from models.security.system import ComplianceCheck, ComplianceStatus, ComplianceValidator
from core.security.cs_audit import log_security_event, get_critical_event_categories
from core.security.cs_utils import format_time_period, parse_time_period

# Initialize logger
logger = logging.getLogger(__name__)

# Constants
DEFAULT_CACHE_TTL = 900  # 15 minutes
COMPLIANCE_FRAMEWORKS = ["pci-dss", "hipaa", "gdpr", "iso27001", "soc2", "fedramp"]
REPORT_FORMATS = ["json", "csv", "pdf", "html"]


def generate_compliance_report(
    report_type: str = "general",
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    format_type: str = "pdf",
    sections: Optional[List[str]] = None
) -> Union[Dict[str, Any], str, bytes, Response]:
    """
    Generate a compliance report for a specific standard.

    Args:
        report_type: The compliance framework (pci-dss, hipaa, gdpr, iso27001, soc2, fedramp)
        start_date: Start date for the reporting period
        end_date: End date for the reporting period
        format_type: Output format (json, csv, pdf, html)
        sections: Specific compliance sections to include

    Returns:
        A report in the specified format
    """
    try:
        # Validate parameters
        if report_type not in COMPLIANCE_FRAMEWORKS:
            raise ValueError(f"Unsupported compliance framework: {report_type}")

        if format_type not in REPORT_FORMATS:
            raise ValueError(f"Unsupported format: {format_type}")

        # Set default dates if not provided
        if not end_date:
            end_date = datetime.now(timezone.utc)
        if not start_date:
            start_date = end_date - timedelta(days=90)  # Default to last 90 days

        # Initialize report structure
        report = {
            "title": f"{report_type.upper()} Compliance Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "description": f"From {start_date.strftime('%Y-%m-%d %H:%M:%S')} to {end_date.strftime('%Y-%m-%d %H:%M:%S')}"
            },
            "summary": {},
            "details": {},
            "recommendations": []
        }

        # Initialize compliance validator
        validator = ComplianceValidator(report_type, start_date, end_date)

        # Run compliance checks
        validation_result = validator.validate()

        # Process validation results
        total_checks = len(validation_result.get('results', []))
        passed = sum(1 for r in validation_result.get('results', [])
                    if r.get('status') == ComplianceStatus.PASSED.value)
        failed = sum(1 for r in validation_result.get('results', [])
                    if r.get('status') == ComplianceStatus.FAILED.value)
        errors = sum(1 for r in validation_result.get('results', [])
                    if r.get('status') == ComplianceStatus.ERROR.value)

        # Calculate overall status
        overall_status = ComplianceStatus.PASSED.value if failed == 0 else ComplianceStatus.FAILED.value

        # Get audit logs related to compliance
        compliance_logs = get_compliance_audit_logs(report_type, start_date, end_date)

        # Get counts by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for log in compliance_logs:
            severity = log.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Collect evidence for each compliance control
        control_evidence = {}
        if sections:
            for section in sections:
                control_evidence[section] = get_control_evidence(report_type, section, start_date, end_date)

        # Add data to report
        report["summary"] = {
            "framework": report_type,
            "total_checks": total_checks,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "overall_status": overall_status,
            "compliance_percentage": round((passed / total_checks * 100), 1) if total_checks > 0 else 0
        }

        report["details"] = {
            "severity_distribution": severity_counts,
            "audit_events": len(compliance_logs),
            "control_results": validation_result.get('results', []),
            "evidence": control_evidence
        }

        # Add recommendations based on findings
        if failed > 0:
            # Find the most critical failures
            critical_failures = [r for r in validation_result.get('results', [])
                               if r.get('status') == ComplianceStatus.FAILED.value and
                               r.get('details', {}).get('severity') == 'critical']

            for failure in critical_failures:
                report["recommendations"].append(
                    f"Critical compliance failure: {failure.get('check', {}).get('name', 'Unknown')}. "
                    f"Immediate remediation required."
                )

            # General recommendation for failures
            report["recommendations"].append(
                f"Address {failed} compliance check failures to achieve full compliance."
            )

        # Log this report generation
        log_security_event(
            event_type="compliance_report_generated",
            description=f"Generated {report_type.upper()} compliance report",
            severity="info",
            details={
                "report_type": report_type,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "format": format_type,
                "overall_status": overall_status,
                "compliance_percentage": report["summary"]["compliance_percentage"]
            },
            category="compliance"
        )

        # Return report in the requested format
        if format_type == "json":
            return report
        elif format_type == "csv":
            return _generate_csv_report(report)
        elif format_type == "pdf":
            return _generate_pdf_report(report)
        elif format_type == "html":
            return _generate_html_report(report)
        else:
            return report

    except Exception as e:
        logger.error(f"Error generating compliance report: {str(e)}", exc_info=True)
        raise


def get_compliance_status(
    framework: str,
    include_details: bool = False
) -> Dict[str, Any]:
    """
    Get the current compliance status for a specific framework.

    Args:
        framework: The compliance framework to check
        include_details: Whether to include detailed control status

    Returns:
        Compliance status summary
    """
    try:
        # Check if data is in cache first
        cache_key = f"compliance_status:{framework}"
        cached_data = cache.get(cache_key) if hasattr(cache, 'get') else None

        if cached_data and not include_details:
            return cached_data

        # Query compliance data
        current_date = datetime.now(timezone.utc)
        start_date = current_date - timedelta(days=30)  # Last 30 days

        # Get compliance checks for this framework
        compliance_checks = db.session.query(ComplianceCheck).filter(
            ComplianceCheck.framework == framework
        ).all()

        # Calculate status metrics
        total = len(compliance_checks) if compliance_checks else 0
        passed = sum(1 for check in compliance_checks if check.status == ComplianceStatus.PASSED.value)
        failed = sum(1 for check in compliance_checks if check.status == ComplianceStatus.FAILED.value)

        # Calculate compliance percentage
        compliance_percentage = (passed / total * 100) if total > 0 else 0

        # Determine overall status
        if compliance_percentage >= 100:
            status = "compliant"
        elif compliance_percentage >= 80:
            status = "partially_compliant"
        else:
            status = "non_compliant"

        # Build response data
        result = {
            "framework": framework,
            "status": status,
            "last_assessment": current_date.isoformat(),
            "compliance_percentage": round(compliance_percentage, 1),
            "summary": {
                "total_controls": total,
                "passed": passed,
                "failed": failed,
                "unknown": total - (passed + failed)
            }
        }

        # Add details if requested
        if include_details:
            result["details"] = {}

            # Group controls by category/section
            control_categories = {}
            for check in compliance_checks:
                category = check.control.category if hasattr(check, 'control') and check.control else "uncategorized"
                if category not in control_categories:
                    control_categories[category] = {
                        "total": 0,
                        "passed": 0,
                        "failed": 0,
                        "controls": []
                    }

                control_categories[category]["total"] += 1
                if check.status == ComplianceStatus.PASSED.value:
                    control_categories[category]["passed"] += 1
                elif check.status == ComplianceStatus.FAILED.value:
                    control_categories[category]["failed"] += 1

                control_categories[category]["controls"].append({
                    "id": check.id,
                    "name": check.name,
                    "status": check.status,
                    "last_checked": check.updated_at.isoformat() if check.updated_at else None
                })

            result["details"]["categories"] = control_categories

        # Cache the result (without details)
        if hasattr(cache, 'set') and not include_details:
            cache_ttl = current_app.config.get('COMPLIANCE_STATUS_CACHE_TTL', DEFAULT_CACHE_TTL)
            cache.set(cache_key, result, timeout=cache_ttl)

        return result

    except Exception as e:
        logger.error(f"Error getting compliance status: {str(e)}", exc_info=True)
        return {
            "framework": framework,
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


def get_control_evidence(
    framework: str,
    control_id: str,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Get evidence for a specific compliance control.

    Args:
        framework: The compliance framework (e.g., pci-dss, hipaa)
        control_id: The specific control ID
        start_date: Start of the evidence collection period
        end_date: End of the evidence collection period

    Returns:
        List of evidence items for the control
    """
    try:
        # Set default dates if not provided
        if not end_date:
            end_date = datetime.now(timezone.utc)
        if not start_date:
            start_date = end_date - timedelta(days=90)  # Default to last 90 days

        # Map framework controls to relevant event types and categories
        control_mappings = {
            "pci-dss": {
                "req_1": ["firewall_change", "network_segmentation"],
                "req_2": ["system_config_change", "vendor_defaults"],
                "req_3": ["data_protection", "encryption_key_management"],
                "req_4": ["encryption_in_transit"],
                "req_5": ["malware_protection"],
                "req_6": ["secure_systems", "patch_management"],
                "req_7": ["access_restriction"],
                "req_8": ["authentication_management"],
                "req_9": ["physical_access"],
                "req_10": [AuditLog.EVENT_API_ACCESS, AuditLog.EVENT_ADMIN_ACTION],
                "req_11": ["security_testing"],
                "req_12": ["security_policy"]
            },
            "hipaa": {
                "164.308": ["admin_safeguards", "risk_assessment"],
                "164.310": ["physical_safeguards"],
                "164.312": ["technical_safeguards", "encryption"],
                "164.316": ["documentation"]
            },
            # Add mappings for other frameworks
        }

        # Get relevant event types for this control
        event_types = []
        if framework in control_mappings and control_id in control_mappings[framework]:
            event_types = control_mappings[framework][control_id]

        # Query for evidence
        evidence_query = db.session.query(AuditLog).filter(
            AuditLog.created_at.between(start_date, end_date)
        )

        # Add framework-specific filtering
        if event_types:
            evidence_query = evidence_query.filter(
                or_(
                    AuditLog.event_type.in_(event_types),
                    AuditLog.category.in_(event_types)
                )
            )

        # Execute query and get results
        evidence_logs = evidence_query.order_by(AuditLog.created_at.desc()).limit(100).all()

        # Format results
        evidence_items = []
        for log in evidence_logs:
            evidence_items.append({
                "id": log.id,
                "timestamp": log.created_at.isoformat() if log.created_at else None,
                "event_type": log.event_type,
                "description": log.description,
                "user_id": log.user_id,
                "severity": log.severity,
                "details": log.details
            })

        # Get compliance check results as additional evidence
        check_results = db.session.query(ComplianceCheck).filter(
            ComplianceCheck.framework == framework,
            ComplianceCheck.control_id == control_id
        ).order_by(ComplianceCheck.updated_at.desc()).limit(10).all()

        for result in check_results:
            evidence_items.append({
                "id": f"check-{result.id}",
                "timestamp": result.updated_at.isoformat() if result.updated_at else None,
                "event_type": "compliance_check",
                "description": f"Compliance check: {result.name}",
                "status": result.status,
                "details": result.result_details
            })

        return evidence_items

    except Exception as e:
        logger.error(f"Error getting control evidence: {str(e)}", exc_info=True)
        return [{
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]


def validate_compliance_requirements(
    framework: str,
    control_ids: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Validate compliance requirements for a specific framework.

    Args:
        framework: The compliance framework to validate against
        control_ids: Optional list of specific control IDs to validate

    Returns:
        Validation results with details of passing and failing controls
    """
    try:
        # Create validator for the specified framework
        validator = ComplianceValidator(framework)

        # Execute validation (either for all controls or specific ones)
        if control_ids:
            validation_results = validator.validate_controls(control_ids)
        else:
            validation_results = validator.validate()

        # Process results
        passed = []
        failed = []
        errors = []

        for result in validation_results.get('results', []):
            status = result.get('status')
            result_data = {
                "check_id": result.get('check', {}).get('id'),
                "name": result.get('check', {}).get('name'),
                "description": result.get('check', {}).get('description'),
                "details": result.get('details')
            }

            if status == ComplianceStatus.PASSED.value:
                passed.append(result_data)
            elif status == ComplianceStatus.FAILED.value:
                failed.append(result_data)
            elif status == ComplianceStatus.ERROR.value:
                errors.append(result_data)

        # Calculate compliance metrics
        total = len(passed) + len(failed) + len(errors)
        compliance_percentage = (len(passed) / total * 100) if total > 0 else 0

        # Create final response
        response = {
            "framework": framework,
            "validation_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_controls": total,
                "passed": len(passed),
                "failed": len(failed),
                "errors": len(errors),
                "compliance_percentage": round(compliance_percentage, 1)
            },
            "results": {
                "passed": passed,
                "failed": failed,
                "errors": errors
            }
        }

        # Log validation event
        log_security_event(
            event_type="compliance_validation_completed",
            description=f"Compliance validation for {framework} completed",
            severity="info" if len(failed) == 0 else "warning",
            details={
                "framework": framework,
                "passed": len(passed),
                "failed": len(failed),
                "errors": len(errors),
                "compliance_percentage": response["summary"]["compliance_percentage"]
            },
            category="compliance"
        )

        return response

    except Exception as e:
        logger.error(f"Error validating compliance requirements: {str(e)}", exc_info=True)
        return {
            "framework": framework,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


# --- Helper Functions ---

def get_compliance_audit_logs(
    framework: str,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Retrieve audit logs relevant to compliance for a specific framework.

    Args:
        framework: The compliance framework (e.g., pci-dss, hipaa)
        start_date: Start of the reporting period
        end_date: End of the reporting period

    Returns:
        List of audit logs relevant to the compliance framework
    """
    try:
        # Set default dates if not provided
        if not end_date:
            end_date = datetime.now(timezone.utc)
        if not start_date:
            start_date = end_date - timedelta(days=90)  # Default to last 90 days

        # Define framework-specific event types and categories
        framework_filters = {
            "pci-dss": {
                "categories": ["security", "access_control", "data_protection"],
                "event_types": [
                    AuditLog.EVENT_FILE_INTEGRITY,
                    AuditLog.EVENT_CONFIG_CHANGE,
                    AuditLog.EVENT_PERMISSION_GRANTED,
                    AuditLog.EVENT_PERMISSION_REVOKED,
                    AuditLog.EVENT_ROLE_ASSIGNED,
                    AuditLog.EVENT_ROLE_REMOVED,
                    "encryption_key_management",
                    "patch_applied"
                ]
            },
            "hipaa": {
                "categories": ["security", "access_control", "data_protection", "audit"],
                "event_types": [
                    AuditLog.EVENT_FILE_INTEGRITY,
                    AuditLog.EVENT_FILE_ACCESS,
                    "phi_access",
                    "encryption_check",
                    "backup_verified"
                ]
            },
            "gdpr": {
                "categories": ["data_protection", "privacy", "consent", "user_rights"],
                "event_types": [
                    "data_access_request",
                    "data_deletion_request",
                    "consent_change",
                    "data_breach_notification"
                ]
            },
            "iso27001": {
                "categories": ["security", "risk_management", "asset_management"],
                "event_types": [
                    AuditLog.EVENT_SECURITY_ALERT,
                    AuditLog.EVENT_CONFIG_CHANGE,
                    "risk_assessment",
                    "control_review"
                ]
            },
            "soc2": {
                "categories": ["security", "availability", "processing_integrity", "confidentiality", "privacy"],
                "event_types": [
                    AuditLog.EVENT_FILE_INTEGRITY,
                    AuditLog.EVENT_SYSTEM_BACKUP,
                    "availability_check",
                    "data_validation"
                ]
            },
            "fedramp": {
                "categories": ["security", "government", "compliance"],
                "event_types": [
                    AuditLog.EVENT_FILE_INTEGRITY,
                    AuditLog.EVENT_CONFIG_CHANGE,
                    "authorization_change",
                    "boundary_control"
                ]
            },
            # Default for "general" framework
            "general": {
                "categories": ["security", "compliance", "audit"],
                "event_types": [
                    AuditLog.EVENT_FILE_INTEGRITY,
                    AuditLog.EVENT_CONFIG_CHANGE,
                    "compliance_check"
                ]
            }
        }

        # Get framework specific filters or use general ones if not found
        filters = framework_filters.get(framework, framework_filters["general"])

        # Build query
        query = db.session.query(AuditLog).filter(
            AuditLog.created_at.between(start_date, end_date)
        )

        # Apply framework-specific filtering
        query = query.filter(
            or_(
                AuditLog.category.in_(filters["categories"]),
                AuditLog.event_type.in_(filters["event_types"])
            )
        )

        # Execute query and get results
        logs = query.order_by(AuditLog.created_at.desc()).all()

        # Format results
        formatted_logs = []
        for log in logs:
            formatted_logs.append({
                "id": log.id,
                "timestamp": log.created_at.isoformat() if log.created_at else None,
                "event_type": log.event_type,
                "category": log.category,
                "description": log.description,
                "user_id": log.user_id,
                "severity": log.severity,
                "details": log.details
            })

        return formatted_logs

    except Exception as e:
        logger.error(f"Error retrieving compliance audit logs: {str(e)}", exc_info=True)
        return []
