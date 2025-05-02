"""
Security Scan Model for Cloud Infrastructure Platform.

This module provides a data model for tracking and managing security scans
across different infrastructure components. It supports multiple scan types,
target management, findings storage, and integration with the vulnerability
management workflow.

Features:
- Comprehensive scan metadata tracking
- Finding management with severity classification
- Integration with vulnerability record creation
- Scan state management (queued, in_progress, completed, failed)
- Scan metrics collection and reporting
- Target filtering and categorization
- Compliance framework mapping
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple, Set
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func, text
from sqlalchemy.exc import SQLAlchemyError

from models.base import BaseModel
from models.security.audit_log import AuditLog
from extensions import db, cache, metrics
from core.security.cs_audit import log_security_event


class SecurityScan(BaseModel):
    """
    Model for tracking security scan operations and findings.

    Represents a security scan operation performed against one or more targets,
    storing metadata about the scan, its status, and findings discovered.

    Attributes:
        id: Unique identifier for the scan
        scan_type: Type of security scan (vulnerability, compliance, etc.)
        profile: Profile/ruleset used for this scan
        status: Current scan status
        targets: List of scan targets (servers, applications, etc.)
        options: Optional scan parameters and configuration
        initiated_by_id: User ID of scan initiator
        start_time: When scan execution began
        end_time: When scan execution completed
        findings_count: Total number of findings discovered
        critical_count: Number of critical severity findings
        high_count: Number of high severity findings
        medium_count: Number of medium severity findings
        low_count: Number of low severity findings
        info_count: Number of informational findings
        findings_summary: Summary statistics of findings
        error_message: Error details if scan failed
        next_scheduled: When the next scan is scheduled (for recurring scans)
        last_duration: Duration of previous scan in seconds
    """

    __tablename__ = 'security_scans'

    # Status constants
    STATUS_QUEUED = 'queued'
    STATUS_IN_PROGRESS = 'in_progress'
    STATUS_COMPLETED = 'completed'
    STATUS_FAILED = 'failed'
    STATUS_CANCELLED = 'cancelled'

    VALID_STATUSES = [
        STATUS_QUEUED, STATUS_IN_PROGRESS,
        STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED
    ]

    # Scan type constants
    TYPE_VULNERABILITY = 'vulnerability'
    TYPE_COMPLIANCE = 'compliance'
    TYPE_CONFIGURATION = 'configuration'
    TYPE_SECURITY_POSTURE = 'posture'
    TYPE_PENETRATION = 'penetration'
    TYPE_CODE = 'code'
    TYPE_CONTAINER = 'container'
    TYPE_IAM = 'iam'

    VALID_SCAN_TYPES = [
        TYPE_VULNERABILITY, TYPE_COMPLIANCE, TYPE_CONFIGURATION,
        TYPE_SECURITY_POSTURE, TYPE_PENETRATION, TYPE_CODE,
        TYPE_CONTAINER, TYPE_IAM
    ]

    # Redis key prefixes
    FINDINGS_PREFIX = "security:scan:findings:"
    SUMMARY_PREFIX = "security:scan:summary:"

    # Database columns
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False, index=True)
    profile = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), nullable=False, default=STATUS_QUEUED, index=True)
    targets = db.Column(JSONB, nullable=False)
    options = db.Column(JSONB, nullable=True)

    # Ownership/timing fields
    initiated_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    start_time = db.Column(db.DateTime(timezone=True), nullable=True)
    end_time = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Results fields
    findings_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    findings_summary = db.Column(JSONB, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    # Schedule management
    next_scheduled = db.Column(db.DateTime(timezone=True), nullable=True)
    last_duration = db.Column(db.Integer, nullable=True)  # Duration in seconds

    # Relationships
    initiated_by = db.relationship('User', foreign_keys=[initiated_by_id], lazy='joined')

    def __init__(self, **kwargs):
        """Initialize a new security scan."""
        # Set default values
        kwargs.setdefault('status', self.STATUS_QUEUED)
        kwargs.setdefault('findings_count', 0)
        kwargs.setdefault('critical_count', 0)
        kwargs.setdefault('high_count', 0)
        kwargs.setdefault('medium_count', 0)
        kwargs.setdefault('low_count', 0)
        kwargs.setdefault('info_count', 0)

        # Process targets input - ensure it's stored as proper JSON
        if 'targets' in kwargs and not isinstance(kwargs['targets'], dict):
            if isinstance(kwargs['targets'], list):
                processed_targets = []
                for target in kwargs['targets']:
                    if isinstance(target, str):
                        processed_targets.append({"id": target, "type": "host"})
                    elif isinstance(target, dict):
                        processed_targets.append(target)
                kwargs['targets'] = processed_targets

        super().__init__(**kwargs)

    @hybrid_property
    def duration(self) -> Optional[int]:
        """Calculate the scan duration in seconds."""
        if self.start_time and self.end_time:
            return int((self.end_time - self.start_time).total_seconds())
        elif self.start_time and self.status == self.STATUS_IN_PROGRESS:
            # For in-progress scans, calculate current duration
            return int((datetime.now(timezone.utc) - self.start_time).total_seconds())
        return self.last_duration

    @hybrid_property
    def target_count(self) -> int:
        """Get the number of targets in this scan."""
        if isinstance(self.targets, list):
            return len(self.targets)
        return 0

    @hybrid_property
    def is_complete(self) -> bool:
        """Check if the scan has been completed."""
        return self.status == self.STATUS_COMPLETED

    @hybrid_property
    def is_active(self) -> bool:
        """Check if the scan is currently active."""
        return self.status in [self.STATUS_QUEUED, self.STATUS_IN_PROGRESS]

    @hybrid_property
    def has_findings(self) -> bool:
        """Check if the scan has any findings."""
        return self.findings_count > 0

    @hybrid_property
    def has_critical_or_high(self) -> bool:
        """Check if the scan has any critical or high severity findings."""
        return self.critical_count > 0 or self.high_count > 0

    def update(self, **kwargs):
        """Update scan attributes."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        # Automatically update the updated_at timestamp
        self.updated_at = datetime.now(timezone.utc)

    def save(self):
        """Save the scan to the database."""
        try:
            db.session.add(self)
            db.session.commit()

            # Update metrics after successful save
            if self.status == self.STATUS_COMPLETED:
                metrics.info('security_scans_completed_total', 1, {
                    'type': self.scan_type,
                    'profile': self.profile or 'default'
                })
                if self.has_critical_or_high:
                    metrics.info('security_scans_with_high_findings_total', 1, {
                        'type': self.scan_type
                    })

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            error_message = str(e)
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Failed to save security scan: {error_message}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"scan_id": self.id, "error": error_message}
            )
            return False

    def mark_in_progress(self):
        """Mark the scan as in progress and record start time."""
        self.status = self.STATUS_IN_PROGRESS
        self.start_time = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

        # Record scan start in metrics
        metrics.info('security_scans_started_total', 1, {
            'type': self.scan_type,
            'profile': self.profile or 'default'
        })

    def mark_completed(self, result_summary: Optional[Dict[str, Any]] = None):
        """
        Mark the scan as completed and record end time.

        Args:
            result_summary: Optional summary of scan results
        """
        self.status = self.STATUS_COMPLETED
        self.end_time = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

        if result_summary:
            self.findings_summary = result_summary

        # Calculate duration
        if self.start_time:
            self.last_duration = int((self.end_time - self.start_time).total_seconds())

    def mark_failed(self, error_message: str):
        """
        Mark the scan as failed with an error message.

        Args:
            error_message: Description of what went wrong
        """
        self.status = self.STATUS_FAILED
        self.error_message = error_message
        self.end_time = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

        # Calculate duration
        if self.start_time:
            self.last_duration = int((self.end_time - self.start_time).total_seconds())

        # Record failure in metrics
        metrics.info('security_scans_failed_total', 1, {
            'type': self.scan_type,
            'profile': self.profile or 'default'
        })

    def cancel(self):
        """
        Mark the scan as cancelled.
        """
        self.status = self.STATUS_CANCELLED
        self.end_time = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

        # Calculate duration if started
        if self.start_time:
            self.last_duration = int((self.end_time - self.start_time).total_seconds())

        # Record cancellation in metrics
        metrics.info('security_scans_cancelled_total', 1, {
            'type': self.scan_type
        })

    def add_findings(self, findings: List[Dict[str, Any]]) -> bool:
        """
        Add findings from a scan.

        Args:
            findings: List of finding dictionaries

        Returns:
            bool: Success status
        """
        try:
            # Initialize counters
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            info_count = 0

            # Store findings in Redis for faster retrieval and to avoid large DB records
            redis_client = self._get_redis_client()
            if redis_client:
                # Use a Redis transaction
                pipeline = redis_client.pipeline()

                # Store each finding with a unique ID
                for finding in findings:
                    # Ensure finding has an ID
                    if 'id' not in finding:
                        finding['id'] = str(uuid.uuid4())

                    # Count by severity
                    severity = finding.get('severity', '').lower()
                    if severity == 'critical':
                        critical_count += 1
                    elif severity == 'high':
                        high_count += 1
                    elif severity == 'medium':
                        medium_count += 1
                    elif severity == 'low':
                        low_count += 1
                    else:
                        info_count += 1

                    # Store the finding JSON in Redis
                    finding_key = f"{self.FINDINGS_PREFIX}{self.id}:{finding['id']}"
                    pipeline.set(finding_key, json.dumps(finding))
                    # Set appropriate TTL (90 days)
                    pipeline.expire(finding_key, 90 * 24 * 60 * 60)

                # Store finding summaries
                summary_key = f"{self.SUMMARY_PREFIX}{self.id}"
                summary = {
                    'total': len(findings),
                    'critical': critical_count,
                    'high': high_count,
                    'medium': medium_count,
                    'low': low_count,
                    'info': info_count,
                    'by_category': self._summarize_by_category(findings),
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
                pipeline.set(summary_key, json.dumps(summary))
                pipeline.expire(summary_key, 90 * 24 * 60 * 60)

                # Execute transaction
                pipeline.execute()

            # Update scan record with counts
            self.findings_count = len(findings)
            self.critical_count = critical_count
            self.high_count = high_count
            self.medium_count = medium_count
            self.low_count = low_count
            self.info_count = info_count

            return True
        except Exception as e:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Error adding findings to scan {self.id}: {str(e)}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"scan_id": self.id, "error": str(e)}
            )
            return False

    def get_findings(self, page: int = 1, per_page: int = 25,
                    severity: Optional[List[str]] = None,
                    status: Optional[List[str]] = None,
                    target: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get scan findings with pagination and filtering.

        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            severity: Optional list of severities to filter by
            status: Optional list of statuses to filter by
            target: Optional target identifier to filter by

        Returns:
            List[Dict[str, Any]]: List of finding dictionaries
        """
        try:
            redis_client = self._get_redis_client()
            if not redis_client:
                return []

            # Get all findings for this scan
            prefix = f"{self.FINDINGS_PREFIX}{self.id}:"
            all_keys = redis_client.keys(f"{prefix}*")

            if not all_keys:
                return []

            # Get all findings from Redis
            all_findings = []
            for key in all_keys:
                finding_json = redis_client.get(key)
                if finding_json:
                    try:
                        finding = json.loads(finding_json)
                        all_findings.append(finding)
                    except json.JSONDecodeError:
                        continue

            # Apply filters
            filtered_findings = self._filter_findings(all_findings, severity, status, target)

            # Sort by severity (critical first)
            filtered_findings.sort(
                key=lambda x: self._severity_sort_value(x.get('severity', 'info')),
                reverse=True
            )

            # Apply pagination
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated_findings = filtered_findings[start_idx:end_idx]

            return paginated_findings
        except Exception as e:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Error retrieving findings for scan {self.id}: {str(e)}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"scan_id": self.id, "error": str(e)}
            )
            return []

    def get_findings_by_severity(self, severity: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get findings filtered by a specific severity.

        Args:
            severity: Severity level to filter by (critical, high, medium, low, info)
            limit: Maximum number of findings to return

        Returns:
            List[Dict[str, Any]]: List of finding dictionaries
        """
        return self.get_findings(
            page=1,
            per_page=limit,
            severity=[severity]
        )

    def get_critical_findings(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get critical severity findings.

        Args:
            limit: Maximum number of findings to return

        Returns:
            List[Dict[str, Any]]: List of critical findings
        """
        return self.get_findings_by_severity('critical', limit)

    def get_high_findings(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get high severity findings.

        Args:
            limit: Maximum number of findings to return

        Returns:
            List[Dict[str, Any]]: List of high severity findings
        """
        return self.get_findings_by_severity('high', limit)

    def get_target_findings(self, target_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get findings for a specific target.

        Args:
            target_id: Target identifier
            limit: Maximum number of findings to return

        Returns:
            List[Dict[str, Any]]: List of findings for the target
        """
        return self.get_findings(
            page=1,
            per_page=limit,
            target=target_id
        )

    def get_findings_summary(self) -> Dict[str, Any]:
        """
        Get a summary of findings.

        Returns:
            Dict[str, Any]: Summary of findings by severity, category, etc.
        """
        # Try to get from Redis first
        redis_client = self._get_redis_client()
        if redis_client:
            summary_key = f"{self.SUMMARY_PREFIX}{self.id}"
            summary_json = redis_client.get(summary_key)
            if summary_json:
                try:
                    return json.loads(summary_json)
                except json.JSONDecodeError:
                    pass

        # Fallback to database counts
        return {
            'total': self.findings_count,
            'critical': self.critical_count,
            'high': self.high_count,
            'medium': self.medium_count,
            'low': self.low_count,
            'info': self.info_count,
            'by_category': self.findings_summary.get('by_category', {}) if self.findings_summary else {}
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert scan to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of scan
        """
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'profile': self.profile,
            'status': self.status,
            'targets': self.targets,
            'options': self.options,
            'initiated_by_id': self.initiated_by_id,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'findings_count': self.findings_count,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'findings_summary': self.findings_summary,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    # Static methods for queries

    @staticmethod
    def find_by_id(scan_id: int) -> Optional['SecurityScan']:
        """
        Find a scan by ID.

        Args:
            scan_id: Scan identifier

        Returns:
            Optional[SecurityScan]: The scan object or None if not found
        """
        try:
            return SecurityScan.query.get(scan_id)
        except SQLAlchemyError as e:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Error finding scan by ID {scan_id}: {str(e)}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"scan_id": scan_id, "error": str(e)}
            )
            return None

    @staticmethod
    def get_paginated(page: int = 1, per_page: int = 20,
                     sort_by: str = 'created_at',
                     sort_direction: str = 'desc',
                     filters: Optional[Dict[str, Any]] = None) -> Tuple[List['SecurityScan'], int]:
        """
        Get paginated list of security scans.

        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            sort_by: Column to sort by
            sort_direction: Sort direction ('asc' or 'desc')
            filters: Optional filters to apply

        Returns:
            Tuple[List[SecurityScan], int]: List of scans and total count
        """
        try:
            query = SecurityScan.query

            # Apply filters if provided
            if filters:
                if 'scan_type' in filters:
                    query = query.filter(SecurityScan.scan_type == filters['scan_type'])

                if 'status' in filters:
                    if isinstance(filters['status'], list):
                        query = query.filter(SecurityScan.status.in_(filters['status']))
                    else:
                        query = query.filter(SecurityScan.status == filters['status'])

                if 'initiated_by' in filters:
                    query = query.filter(SecurityScan.initiated_by_id == filters['initiated_by'])

                if 'has_findings' in filters and filters['has_findings']:
                    query = query.filter(SecurityScan.findings_count > 0)

                if 'has_critical' in filters and filters['has_critical']:
                    query = query.filter(SecurityScan.critical_count > 0)

                if 'start_date' in filters:
                    query = query.filter(SecurityScan.created_at >= filters['start_date'])

                if 'end_date' in filters:
                    query = query.filter(SecurityScan.created_at <= filters['end_date'])

                if 'target' in filters:
                    # JSON path search for target in targets array (PostgreSQL specific)
                    if db.engine.dialect.name == 'postgresql':
                        target = filters['target']
                        query = query.filter(text(f"targets @> '[{{'id': '{target}'}}]'::jsonb"))
                    else:
                        # Fallback for other databases (less efficient)
                        # This should be improved based on the specific database in use
                        pass

            # Apply sorting
            if sort_direction.lower() == 'asc':
                query = query.order_by(getattr(SecurityScan, sort_by).asc())
            else:
                query = query.order_by(getattr(SecurityScan, sort_by).desc())

            # Get total count
            total = query.count()

            # Apply pagination
            offset = (page - 1) * per_page
            scans = query.offset(offset).limit(per_page).all()

            return scans, total

        except SQLAlchemyError as e:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Error getting paginated scans: {str(e)}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"error": str(e)}
            )
            return [], 0

    @staticmethod
    def get_scans_by_status(status: str, limit: int = 10,
                           scan_type: Optional[str] = None) -> List['SecurityScan']:
        """
        Get scans by status.

        Args:
            status: Scan status to filter by
            limit: Maximum number of scans to return
            scan_type: Optional scan type filter

        Returns:
            List[SecurityScan]: List of matching scans
        """
        try:
            query = SecurityScan.query.filter(SecurityScan.status == status)

            if scan_type:
                query = query.filter(SecurityScan.scan_type == scan_type)

            return query.order_by(SecurityScan.created_at.desc()).limit(limit).all()
        except SQLAlchemyError as e:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Error getting scans by status {status}: {str(e)}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"status": status, "scan_type": scan_type, "error": str(e)}
            )
            return []

    @staticmethod
    def count_by_type_and_status(since: Optional[datetime] = None) -> Dict[str, Dict[str, int]]:
        """
        Get scan counts grouped by type and status.

        Args:
            since: Optional cutoff date for counting

        Returns:
            Dict[str, Dict[str, int]]: Counts by scan type and status
        """
        try:
            result = {}

            # Base query
            query = db.session.query(
                SecurityScan.scan_type,
                SecurityScan.status,
                func.count(SecurityScan.id)
            ).group_by(
                SecurityScan.scan_type,
                SecurityScan.status
            )

            # Apply date filter if provided
            if since:
                query = query.filter(SecurityScan.created_at >= since)

            # Build the result structure
            for scan_type, status, count in query.all():
                if scan_type not in result:
                    result[scan_type] = {}

                result[scan_type][status] = count

            return result
        except SQLAlchemyError as e:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Error counting scans by type and status: {str(e)}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"error": str(e)}
            )
            return {}

    @staticmethod
    def get_recent_failed_scans(limit: int = 10, since: Optional[datetime] = None) -> List['SecurityScan']:
        """
        Get recently failed scans.

        Args:
            limit: Maximum number of scans to return
            since: Optional cutoff date

        Returns:
            List[SecurityScan]: List of failed scans
        """
        try:
            query = SecurityScan.query.filter(SecurityScan.status == SecurityScan.STATUS_FAILED)

            if since:
                query = query.filter(SecurityScan.updated_at >= since)

            return query.order_by(SecurityScan.updated_at.desc()).limit(limit).all()
        except SQLAlchemyError as e:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Error getting recent failed scans: {str(e)}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"error": str(e)}
            )
            return []

    @staticmethod
    def get_scan_health_metrics() -> Dict[str, Any]:
        """
        Get health metrics for scan operations.

        Returns:
            Dict[str, Any]: Scan health metrics
        """
        try:
            # Get current time and time ranges
            now = datetime.now(timezone.utc)
            one_day_ago = now - timedelta(days=1)
            seven_days_ago = now - timedelta(days=7)

            # Get counts of scans in last 24 hours
            day_count = SecurityScan.query.filter(SecurityScan.created_at >= one_day_ago).count()

            # Get success rate in last 7 days
            week_scans = SecurityScan.query.filter(
                SecurityScan.created_at >= seven_days_ago,
                SecurityScan.status.in_([SecurityScan.STATUS_COMPLETED, SecurityScan.STATUS_FAILED])
            ).count()

            week_success = SecurityScan.query.filter(
                SecurityScan.created_at >= seven_days_ago,
                SecurityScan.status == SecurityScan.STATUS_COMPLETED
            ).count()

            success_rate = (week_success / week_scans) * 100 if week_scans > 0 else 0

            # Get average scan duration
            avg_duration_result = db.session.query(
                func.avg(SecurityScan.last_duration)
            ).filter(
                SecurityScan.created_at >= seven_days_ago,
                SecurityScan.last_duration.isnot(None)
            ).scalar()

            avg_duration = int(avg_duration_result) if avg_duration_result else 0

            # Get currently running scans
            active_scans = SecurityScan.query.filter(
                SecurityScan.status == SecurityScan.STATUS_IN_PROGRESS
            ).count()

            # Get scans running for longer than expected
            long_running = SecurityScan.query.filter(
                SecurityScan.status == SecurityScan.STATUS_IN_PROGRESS,
                SecurityScan.start_time < (now - timedelta(hours=2))  # Running for more than 2 hours
            ).count()

            return {
                'daily_scans': day_count,
                'success_rate': round(success_rate, 2),
                'avg_duration_seconds': avg_duration,
                'active_scans': active_scans,
                'long_running_scans': long_running,
                'health_status': 'degraded' if long_running > 0 else 'healthy'
            }

        except SQLAlchemyError as e:
            log_security_event(
                event_type=AuditLog.EVENT_SECURITY_SCAN_ERROR,
                description=f"Error getting scan health metrics: {str(e)}",
                severity=AuditLog.SEVERITY_ERROR,
                details={"error": str(e)}
            )
            return {
                'health_status': 'unknown',
                'error': str(e)
            }

    # Helper methods

    def _filter_findings(self, findings: List[Dict[str, Any]],
                        severity: Optional[List[str]] = None,
                        status: Optional[List[str]] = None,
                        target: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Filter findings based on criteria.

        Args:
            findings: List of all findings
            severity: Optional list of severities to filter by
            status: Optional list of statuses to filter by
            target: Optional target identifier to filter by

        Returns:
            List[Dict[str, Any]]: Filtered findings
        """
        filtered = findings

        # Filter by severity
        if severity and isinstance(severity, list):
            severity_lower = [s.lower() for s in severity]
            filtered = [f for f in filtered if f.get('severity', '').lower() in severity_lower]

        # Filter by status
        if status and isinstance(status, list):
            status_lower = [s.lower() for s in status]
            filtered = [f for f in filtered if f.get('status', '').lower() in status_lower]

        # Filter by target
        if target:
            filtered = [f for f in filtered if
                        (f.get('target_id') == target or
                         f.get('affected_resource') == target or
                         (isinstance(f.get('affected_resources'), list) and
                          target in f.get('affected_resources', [])))]

        return filtered

    def _severity_sort_value(self, severity: str) -> int:
        """Get numeric value for severity for sorting."""
        severity_map = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return severity_map.get(severity.lower(), 0)

    def _summarize_by_category(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Summarize findings by category.

        Args:
            findings: List of findings

        Returns:
            Dict[str, int]: Count of findings by category
        """
        categories = {}

        for finding in findings:
            category = finding.get('category', 'uncategorized').lower()
            if category in categories:
                categories[category] += 1
            else:
                categories[category] = 1

        return categories

    @staticmethod
    def _get_redis_client():
        """Get Redis client from cache extension."""
        try:
            if hasattr(cache, 'cache') and hasattr(cache.cache, '_client'):
                return cache.cache._client
        except Exception:
            pass
        return None
