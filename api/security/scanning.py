"""
API Endpoints for Security Scanning Operations.

Provides endpoints for initiating, monitoring, and managing security scans
within the Cloud Infrastructure Platform.
"""

import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from flask import request, jsonify, current_app, abort, g
from marshmallow import ValidationError

# Import the central security blueprint from routes.py
from .routes import security_bp

# Core security components
from core.security import require_permission, log_security_event

# Schemas for validation and serialization
from .schemas import (
    scan_schema,
    scans_schema,
    scan_create_schema,
    scan_update_schema,
    scan_filter_schema,
    scan_result_schema,
    scan_findings_schema
)

# Models
# Adjust import path based on actual model location
try:
    # Use package-level imports
    from models.security import SecurityScan, AuditLog, Vulnerability
    from services import ScanningService
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False
    # Define dummy classes if models are not available for drafting
    class SecurityScan:
        @staticmethod
        def find_by_id(scan_id): return None
        @staticmethod
        def create(**kwargs): return SecurityScan(**kwargs)
        @staticmethod
        def get_paginated(**kwargs): return [], 0
        @staticmethod
        def get_scans_by_status(status, **kwargs): return []
        @staticmethod
        def count_by_type_and_status(**kwargs): return {}
        @staticmethod
        def get_recent_failed_scans(**kwargs): return []
        def update(self, **kwargs): pass
        def delete(self): pass # Although delete endpoint is not defined, keep for consistency
        def save(self): pass
        def add_findings(self, findings): pass
        def get_findings(self): return []
        def mark_in_progress(self): pass
        def mark_completed(self, result_summary): pass
        def mark_failed(self, error_message): pass
        def cancel(self): pass
        def __init__(self, **kwargs):
            self.id = kwargs.get('id', 1)
            self.scan_type = kwargs.get('scan_type')
            self.targets = kwargs.get('targets')
            self.status = kwargs.get('status', 'queued')
            self.profile_id = kwargs.get('profile_id')
            self.options = kwargs.get('options', {})
            self.initiated_by_id = kwargs.get('initiated_by_id')
            self.start_time = kwargs.get('start_time')
            self.end_time = kwargs.get('end_time')
            self.findings_summary = kwargs.get('findings_summary', {})
            self.created_at = kwargs.get('created_at')
            self.updated_at = kwargs.get('updated_at')
            self.error_message = kwargs.get('error_message')
            self.findings_count = kwargs.get('findings_count', 0)
            self.critical_count = kwargs.get('critical_count', 0)
            self.high_count = kwargs.get('high_count', 0)
            self.medium_count = kwargs.get('medium_count', 0)
            self.low_count = kwargs.get('low_count', 0)
            self.info_count = kwargs.get('info_count', 0)
            self.next_scheduled = kwargs.get('next_scheduled')
            self.last_duration = kwargs.get('last_duration')

    class AuditLog:
        EVENT_SECURITY_SCAN_INITIATED = "security_scan_initiated"
        EVENT_SECURITY_SCAN_STATUS_CHANGE = "security_scan_status_change"
        EVENT_SECURITY_SCAN_ERROR = "security_scan_error"
        EVENT_SECURITY_SCAN_COMPLETED = "security_scan_completed"
        EVENT_SECURITY_SCAN_FINDING = "security_scan_finding"

    class Vulnerability:
        @staticmethod
        def create_from_finding(**kwargs): return None
        @staticmethod
        def find_similar(finding_data): return None
        @staticmethod
        def bulk_update_from_findings(findings): return 0

    class ScanningService:
        @staticmethod
        def start_scan(scan): return True
        @staticmethod
        def cancel_scan(scan): return True
        @staticmethod
        def get_available_scan_profiles(): return []
        @staticmethod
        def get_scan_health_metrics(): return {}
        @staticmethod
        def estimate_scan_duration(scan_type, targets, profile): return 30

logger = logging.getLogger(__name__)

# --- Helper Functions ---

def _process_targets(targets: List[str], scan_type: str) -> List[Dict[str, Any]]:
    """
    Process and validate scan targets based on scan type.

    Args:
        targets: List of target identifiers
        scan_type: Type of scan to perform

    Returns:
        List of processed target objects
    """
    processed_targets = []

    for target in targets:
        target_info = {
            "id": target,
            "status": "pending"
        }

        # Add extra metadata based on scan type
        if scan_type == "vulnerability":
            # For vulnerability scans, try to determine target type
            if target.startswith("host:"):
                target_info["type"] = "host"
                target_info["id"] = target[5:]
            elif target.startswith("app:"):
                target_info["type"] = "application"
                target_info["id"] = target[4:]
            elif target.startswith("container:"):
                target_info["type"] = "container"
                target_info["id"] = target[10:]
            else:
                # Default to host if no prefix
                target_info["type"] = "host"

        processed_targets.append(target_info)

    return processed_targets

def _create_scan_metrics(scan: SecurityScan) -> Dict[str, Any]:
    """
    Create metrics dictionary from scan data.

    Args:
        scan: SecurityScan object

    Returns:
        Dictionary with metrics data
    """
    metrics = {
        "findings_count": scan.findings_count,
        "severity_counts": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "info": scan.info_count
        },
        "status": scan.status
    }

    # Calculate duration if available
    if scan.start_time and scan.end_time:
        start = scan.start_time
        end = scan.end_time

        if isinstance(start, str):
            start = datetime.fromisoformat(start.replace('Z', '+00:00'))
        if isinstance(end, str):
            end = datetime.fromisoformat(end.replace('Z', '+00:00'))

        duration_seconds = (end - start).total_seconds()
        metrics["duration_seconds"] = duration_seconds
    elif scan.last_duration:
        metrics["duration_seconds"] = scan.last_duration

    return metrics

# --- Security Scan Endpoints ---

@security_bp.route('/scan', methods=['POST'])
@require_permission('security:scan:create')
def initiate_security_scan():
    """
    Initiate a new security scan.
    Requires 'security:scan:create' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        logger.warning("Initiate scan request received with no JSON data.")
        abort(400, description="No input data provided.")

    try:
        data = scan_create_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error initiating scan: %s", err.messages)
        return jsonify(err.messages), 400

    try:
        # Get the current user ID from request context
        user_id = getattr(g, 'user', None).id if hasattr(g, 'user') else None

        # Process scan targets
        processed_targets = _process_targets(data['targets'], data['scan_type'])

        # Estimate scan duration for the response
        estimated_duration = ScanningService.estimate_scan_duration(
            scan_type=data['scan_type'],
            targets=processed_targets,
            profile=data.get('profile', 'standard')
        )

        scan_data = {
            **data,
            'status': 'queued',
            'initiated_by_id': user_id,
            'targets': processed_targets,
            'created_at': datetime.now(timezone.utc)
        }

        new_scan = SecurityScan.create(**scan_data)
        new_scan.save() # Persist to database

        # Schedule the scan in background task queue
        scan_scheduled = ScanningService.start_scan(new_scan)
        if not scan_scheduled:
            logger.error("Failed to schedule scan in task queue for ID %s", new_scan.id)
            # We'll continue anyway since the record is created and can be retried

        # Log the security event
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_INITIATED,
            description=f"Security scan initiated: Type '{data['scan_type']}' on targets {data['targets']}",
            severity="medium",
            user_id=user_id,
            details={"scan_id": new_scan.id, **data}
        )

        logger.info("Security scan initiated: ID %s, Type: %s", new_scan.id, data['scan_type'])

        # Return response with scan details and estimated duration
        response_data = scan_schema.dump(new_scan)
        response_data.update({
            "estimated_duration_minutes": estimated_duration,
            "scheduled_start": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        })

        # Return 202 Accepted as the scan is asynchronous
        return jsonify(response_data), 202

    except Exception as e:
        logger.error("Error initiating security scan: %s", e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
            description=f"Failed to initiate security scan: {e}",
            severity="high",
            details=data
        )
        abort(500, description="Failed to initiate security scan.")

@security_bp.route('/scan', methods=['GET'])
@require_permission('security:scan:read')
def list_security_scans():
    """
    List security scans with filtering and pagination.
    Requires 'security:scan:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        # Validate query parameters
        query_params = scan_filter_schema.load(request.args)
    except ValidationError as err:
        logger.warning("Validation error listing security scans: %s", err.messages)
        return jsonify(err.messages), 400

    try:
        page = query_params.pop('page', 1)
        per_page = query_params.pop('per_page', 20)
        sort_by = query_params.pop('sort_by', 'created_at')
        sort_direction = query_params.pop('sort_direction', 'desc')

        # Pass validated filters to the model/service layer
        scans, total = SecurityScan.get_paginated(
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            sort_direction=sort_direction,
            filters=query_params # Pass remaining validated params as filters
        )

        logger.debug("Retrieved %d security scans (page %d)", len(scans), page)
        return jsonify({
            "scans": scans_schema.dump(scans),
            "total": total,
            "page": page,
            "per_page": per_page
        }), 200

    except Exception as e:
        logger.error("Error listing security scans: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve security scans.")

@security_bp.route('/scan/<int:scan_id>', methods=['GET'])
@require_permission('security:scan:read')
def get_security_scan(scan_id):
    """
    Get details of a specific security scan.
    Requires 'security:scan:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    scan = SecurityScan.find_by_id(scan_id)
    if not scan:
        logger.warning("Security scan with ID %s not found.", scan_id)
        abort(404, description="Security scan not found.")

    logger.debug("Retrieved security scan ID %s", scan_id)
    return jsonify(scan_schema.dump(scan)), 200

@security_bp.route('/scan/<int:scan_id>/findings', methods=['GET'])
@require_permission('security:scan:read')
def get_scan_findings(scan_id):
    """
    Get detailed findings from a security scan.
    Requires 'security:scan:read' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    try:
        scan = SecurityScan.find_by_id(scan_id)
        if not scan:
            logger.warning("Security scan with ID %s not found.", scan_id)
            abort(404, description="Security scan not found.")

        # Get requested page and filtering
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 25, type=int), 100)  # Cap at 100 findings per page
        severity = request.args.getlist('severity')  # Filter by severity
        status = request.args.getlist('status')  # Filter by status
        target = request.args.get('target')  # Filter by target

        # Get findings with pagination and filters
        findings = scan.get_findings(
            page=page,
            per_page=per_page,
            severity=severity,
            status=status,
            target=target
        )

        # For scan types that support vulnerability tracking,
        # include references to associated vulnerability records
        if scan.scan_type == 'vulnerability':
            for finding in findings:
                vuln = Vulnerability.find_similar(finding)
                if vuln:
                    finding['vulnerability_id'] = vuln.id
                    finding['vulnerability_status'] = vuln.status

        return jsonify({
            "scan_id": scan_id,
            "findings": scan_findings_schema.dump(findings),
            "findings_count": scan.findings_count,
            "severity_counts": {
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "info": scan.info_count
            },
            "page": page,
            "per_page": per_page
        }), 200

    except Exception as e:
        logger.error("Error retrieving findings for scan ID %s: %s", scan_id, e, exc_info=True)
        abort(500, description="Failed to retrieve scan findings.")

@security_bp.route('/scan/<int:scan_id>/results', methods=['POST'])
@require_permission('security:scan:update')
def update_scan_results(scan_id):
    """
    Update scan results - used by scanner services to report results.
    Requires 'security:scan:update' permission.

    This endpoint is primarily for internal use by scanning microservices
    to report scan results back to the API.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    # Find the scan
    scan = SecurityScan.find_by_id(scan_id)
    if not scan:
        logger.warning("Attempt to update results for non-existent scan ID %s", scan_id)
        abort(404, description="Security scan not found.")

    # Only accept results for scans that are in progress
    if scan.status not in ['queued', 'in_progress']:
        logger.warning("Attempt to update results for scan ID %s with status %s", scan_id, scan.status)
        abort(400, description=f"Cannot update results for scan in '{scan.status}' state.")

    # Validate incoming results
    json_data = request.get_json()
    if not json_data:
        logger.warning("Update scan results request received with no JSON data.")
        abort(400, description="No input data provided.")

    try:
        data = scan_result_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error updating scan results: %s", err.messages)
        return jsonify(err.messages), 400

    try:
        # Extract findings and status information
        status = data.get('status', 'completed')
        findings = data.get('findings', [])
        result_summary = data.get('summary', {})
        error_message = data.get('error_message')

        # Update the scan record based on status
        if status == 'failed':
            scan.mark_failed(error_message or "Unknown error")

            # Log the error
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Security scan {scan_id} failed: {error_message or 'Unknown error'}",
                severity="medium",
                details={"scan_id": scan_id, "error": error_message}
            )
        elif status == 'completed':
            # First add all findings
            scan.add_findings(findings)

            # Then mark scan as completed with summary
            scan.mark_completed(result_summary)

            # Log completion
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_COMPLETED,
                description=f"Security scan {scan_id} completed with {len(findings)} findings",
                severity="medium",
                details={
                    "scan_id": scan_id,
                    "findings_count": len(findings),
                    "summary": result_summary
                }
            )

            # For vulnerability scans, create/update vulnerability records
            if scan.scan_type == 'vulnerability' and findings:
                try:
                    updated = Vulnerability.bulk_update_from_findings(findings)
                    logger.info("Updated %d vulnerability records from scan %s", updated, scan_id)
                except Exception as vuln_err:
                    logger.error("Error updating vulnerability records: %s", vuln_err, exc_info=True)
        else:
            # For other statuses (like 'in_progress'), just update progress info
            scan.update(**data)

        scan.save()

        # Return confirmation
        return jsonify({
            "scan_id": scan_id,
            "status": "updated",
            "findings_processed": len(findings)
        }), 200

    except Exception as e:
        logger.error("Error updating scan results for ID %s: %s", scan_id, e, exc_info=True)
        abort(500, description="Failed to update scan results.")

@security_bp.route('/scan/<int:scan_id>', methods=['PATCH'])
@require_permission('security:scan:update')
def update_security_scan(scan_id):
    """
    Update an existing security scan (e.g., cancel).
    Requires 'security:scan:update' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available for SecurityScan.")
        return jsonify({"error": "Model layer not available"}), 500

    scan = SecurityScan.find_by_id(scan_id)
    if not scan:
        logger.warning("Attempt to update non-existent security scan ID %s", scan_id)
        abort(404, description="Security scan not found.")

    # Check if scan is in a state that allows update (e.g., cancellation)
    if scan.status not in ['queued', 'in_progress']:
         logger.warning("Attempt to update scan ID %s in non-updatable state: %s", scan_id, scan.status)
         abort(400, description=f"Scan cannot be updated in its current state: {scan.status}")

    json_data = request.get_json()
    if not json_data:
        logger.warning("Update scan request received with no JSON data for ID %s.", scan_id)
        abort(400, description="No input data provided.")

    try:
        # Validate only the fields provided for update (currently only 'status' for cancellation)
        data = scan_update_schema.load(json_data)
    except ValidationError as err:
        logger.warning("Validation error updating scan ID %s: %s", scan_id, err.messages)
        return jsonify(err.messages), 400

    try:
        original_status = scan.status

        # Handle cancellation specially
        if 'status' in data and data['status'] == 'cancelled':
            # Try to cancel the actual scan process through the service
            cancellation_successful = ScanningService.cancel_scan(scan)
            if cancellation_successful:
                # Only update the status if cancellation was successful
                scan.cancel()
                scan.save()
            else:
                # Return error if cancellation failed
                logger.error("Failed to cancel scan ID %s", scan_id)
                abort(500, description="Failed to cancel scan operation.")
        else:
            # Handle other updates
            scan.update(**data)
            scan.save()

        # Log the status change
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_STATUS_CHANGE,
            description=f"Security scan ID {scan_id} status changed from {original_status} to {scan.status}",
            severity="medium",
            details={"scan_id": scan_id, "old_status": original_status, "new_status": scan.status}
        )
        logger.info("Security scan updated: ID %s, Status: %s", scan_id, scan.status)
        return jsonify(scan_schema.dump(scan)), 200

    except Exception as e:
        logger.error("Error updating security scan ID %s: %s", scan_id, e, exc_info=True)
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
            description=f"Failed to update security scan ID {scan_id}: {e}",
            severity="high",
            details={"scan_id": scan_id, "update_data": data}
        )
        abort(500, description="Failed to update security scan.")

@security_bp.route('/scan/profiles', methods=['GET'])
@require_permission('security:scan:read')
def list_scan_profiles():
    """
    List available security scan profiles.
    Requires 'security:scan:read' permission.
    """
    try:
        # Get available profiles from scanning service
        profiles = ScanningService.get_available_scan_profiles()

        # Structure response with profile details
        formatted_profiles = []
        for profile in profiles:
            formatted_profiles.append({
                "id": profile.get("id"),
                "name": profile.get("name"),
                "description": profile.get("description"),
                "scan_types": profile.get("scan_types", []),
                "intensity": profile.get("intensity", "standard"),
                "is_default": profile.get("is_default", False),
            })

        return jsonify({
            "profiles": formatted_profiles
        }), 200

    except Exception as e:
        logger.error("Error listing scan profiles: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve scan profiles.")

@security_bp.route('/scan/metrics', methods=['GET'])
@require_permission('security:scan:read')
def get_scan_metrics():
    """
    Get security scan metrics and statistics.
    Requires 'security:scan:read' permission.
    """
    try:
        # Get recent metrics (last 30 days by default)
        days = request.args.get('days', 30, type=int)
        if days <= 0 or days > 365:
            days = 30

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        # Get health metrics from scanning service
        health_metrics = ScanningService.get_scan_health_metrics()

        # Count scans by status
        status_counts = {
            "total": 0,
            "queued": 0,
            "in_progress": 0,
            "completed": 0,
            "failed": 0,
            "cancelled": 0
        }

        # Get counts by scan type and status
        type_stats = SecurityScan.count_by_type_and_status(since=cutoff_date)

        # Calculate totals
        for scan_type, status_data in type_stats.items():
            for status, count in status_data.items():
                if status in status_counts:
                    status_counts[status] += count
                status_counts["total"] += count

        # Get recent failed scans
        failed_scans = SecurityScan.get_recent_failed_scans(limit=5, since=cutoff_date)

        # Format response
        response = {
            "status_counts": status_counts,
            "by_type": type_stats,
            "health": health_metrics,
            "recent_failures": [
                {
                    "id": scan.id,
                    "scan_type": scan.scan_type,
                    "created_at": scan.created_at,
                    "targets": [t.get("id") for t in scan.targets],
                    "error_message": scan.error_message
                } for scan in failed_scans
            ],
            "time_period": f"Last {days} days"
        }

        return jsonify(response), 200

    except Exception as e:
        logger.error("Error retrieving scan metrics: %s", e, exc_info=True)
        abort(500, description="Failed to retrieve scan metrics.")

@security_bp.route('/scan/convert-to-vulnerabilities', methods=['POST'])
@require_permission('security:vulnerability:create')
def convert_findings_to_vulnerabilities():
    """
    Convert scan findings to vulnerability records.
    Requires 'security:vulnerability:create' permission.
    """
    if not MODELS_AVAILABLE:
        logger.error("Model layer not available.")
        return jsonify({"error": "Model layer not available"}), 500

    json_data = request.get_json()
    if not json_data:
        abort(400, description="No input data provided.")

    scan_id = json_data.get('scan_id')
    finding_ids = json_data.get('finding_ids', [])

    if not scan_id:
        abort(400, description="'scan_id' is required.")

    if not finding_ids:
        abort(400, description="'finding_ids' array is required.")

    try:
        # Find the scan
        scan = SecurityScan.find_by_id(scan_id)
        if not scan:
            abort(404, description="Security scan not found.")

        # Check scan type - only vulnerability scans can be converted
        if scan.scan_type != 'vulnerability':
            abort(400, description="Only vulnerability scans can be converted to vulnerability records.")

        # Get the specified findings
        all_findings = scan.get_findings()
        selected_findings = [f for f in all_findings if f.get('id') in finding_ids]

        if not selected_findings:
            abort(404, description="No matching findings found.")

        # Create vulnerability records from findings
        created_count = 0
        updated_count = 0
        skipped_count = 0
        errors = []

        for finding in selected_findings:
            try:
                # Check if similar vulnerability exists
                existing = Vulnerability.find_similar(finding)

                if existing:
                    # Update existing record
                    # (actual implementation would merge data appropriately)
                    updated_count += 1
                else:
                    # Create new vulnerability record
                    Vulnerability.create_from_finding(**finding)
                    created_count += 1

            except Exception as e:
                errors.append(f"Error processing finding {finding.get('id')}: {str(e)}")
                skipped_count += 1

        # Log the action
        log_security_event(
            event_type=AuditLog.EVENT_SECURITY_SCAN_FINDING,
            description=f"Converted {created_count + updated_count} findings to vulnerability records",
            severity="medium",
            user_id=getattr(g, 'user', None).id if hasattr(g, 'user') else None,
            details={
                "scan_id": scan_id,
                "findings_count": len(finding_ids),
                "created_count": created_count,
                "updated_count": updated_count,
                "skipped_count": skipped_count,
                "errors": errors[:5]  # Include only first 5 errors
            }
        )

        return jsonify({
            "message": f"Processed {len(finding_ids)} findings",
            "created_count": created_count,
            "updated_count": updated_count,
            "skipped_count": skipped_count,
            "errors": errors if errors else None
        }), 200

    except Exception as e:
        logger.error("Error converting findings to vulnerabilities: %s", e, exc_info=True)
        abort(500, description="Failed to convert findings to vulnerabilities.")
