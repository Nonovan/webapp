"""
Alert suppression model for managing alert filtering and silencing rules.

This module provides the AlertSuppression model for managing rules that
suppress or silence alerts based on specific criteria, preventing alert
storms and reducing noise during maintenance periods.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy import desc, asc, and_, or_, func, text
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app
import re

from extensions import db
from models.base import BaseModel
from core.security import log_security_event
from models.alerts.alert import Alert

class AlertSuppression(BaseModel):
    """
    Model for managing alert suppression rules.

    This model defines rules for suppressing alerts based on criteria
    such as service, resource, alert type, and environment. Suppressions
    can be time-bound (for maintenance windows) or indefinite.

    Attributes:
        id (int): Suppression rule unique identifier
        name (str): Descriptive name for the suppression rule
        description (str): Detailed description of the suppression
        criteria (dict): JSON criteria for matching alerts
        environment (str): Environment where suppression applies
        created_by (str): User who created the suppression
        created_at (datetime): When suppression was created
        start_time (datetime): When suppression begins
        end_time (datetime): When suppression ends (null for indefinite)
        active (bool): Whether the suppression is currently active
        reason (str): Reason for suppression (maintenance, noise reduction, etc.)
        suppression_type (str): Type of suppression (silence, throttle, deduplicate)
    """

    __tablename__ = 'alert_suppressions'

    # Suppression reasons
    REASON_MAINTENANCE = 'maintenance'
    REASON_TESTING = 'testing'
    REASON_KNOWN_ISSUE = 'known_issue'
    REASON_NOISE_REDUCTION = 'noise_reduction'
    REASON_FALSE_POSITIVE = 'false_positive'

    REASONS = [REASON_MAINTENANCE, REASON_TESTING, REASON_KNOWN_ISSUE,
              REASON_NOISE_REDUCTION, REASON_FALSE_POSITIVE]

    # Suppression types
    TYPE_SILENCE = 'silence'  # Don't create alerts at all
    TYPE_THROTTLE = 'throttle'  # Limit number of alerts in time period
    TYPE_DEDUPLICATE = 'deduplicate'  # Create only one alert for duplicates

    TYPES = [TYPE_SILENCE, TYPE_THROTTLE, TYPE_DEDUPLICATE]

    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    criteria = db.Column(MutableDict.as_mutable(db.JSON), nullable=False)
    environment = db.Column(db.String(32), nullable=False, index=True)
    created_by = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    start_time = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    end_time = db.Column(db.DateTime(timezone=True), nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    reason = db.Column(db.String(32), nullable=False)
    suppression_type = db.Column(db.String(32), nullable=False, default=TYPE_SILENCE)

    # Additional throttling/deduplication settings
    throttle_count = db.Column(db.Integer, default=1, nullable=True)
    throttle_period = db.Column(db.Integer, default=3600, nullable=True)  # In seconds

    # Track suppressed alerts
    suppressed_count = db.Column(db.Integer, default=0, nullable=False)
    last_suppressed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, name: str, criteria: Dict[str, Any], environment: str,
                created_by: str, reason: str, suppression_type: str = TYPE_SILENCE,
                description: str = None, start_time: datetime = None,
                end_time: datetime = None, throttle_count: int = None,
                throttle_period: int = None):
        """
        Initialize a new suppression rule.

        Args:
            name: Descriptive name for the rule
            criteria: JSON criteria for matching alerts
            environment: Environment where suppression applies
            created_by: User who created the suppression
            reason: Reason for suppression
            suppression_type: Type of suppression
            description: Detailed description
            start_time: When suppression begins
            end_time: When suppression ends
            throttle_count: Max alerts allowed in period for throttling
            throttle_period: Time period in seconds for throttling
        """
        self.name = name
        self.criteria = criteria
        self.environment = environment
        self.created_by = created_by
        self.reason = reason
        self.suppression_type = suppression_type
        self.description = description
        self.start_time = start_time or datetime.now(timezone.utc)
        self.end_time = end_time

        if suppression_type == self.TYPE_THROTTLE:
            self.throttle_count = throttle_count or 1
            self.throttle_period = throttle_period or 3600

    def is_active(self) -> bool:
        """
        Check if the suppression rule is currently active.

        Returns:
            True if active, False otherwise
        """
        now = datetime.now(timezone.utc)

        # Check if suppression is marked as active
        if not self.active:
            return False

        # Check time bounds
        if now < self.start_time:
            return False

        if self.end_time and now > self.end_time:
            return False

        return True

    def should_suppress(self, alert: Alert) -> bool:
        """
        Check if an alert should be suppressed based on this rule.

        Args:
            alert: Alert to check

        Returns:
            True if alert should be suppressed, False otherwise
        """
        # First check if rule is active
        if not self.is_active():
            return False

        # Check environment match
        if self.environment != 'all' and self.environment != alert.environment:
            return False

        # Check criteria match
        for key, value in self.criteria.items():
            # Handle alert attributes
            if key in ['alert_type', 'resource_id', 'service_name', 'severity']:
                # Handle exact match
                if isinstance(value, str) and getattr(alert, key) != value:
                    return False

                # Handle list of allowed values
                if isinstance(value, list) and getattr(alert, key) not in value:
                    return False

                # Handle regex match
                if isinstance(value, dict) and value.get('regex'):
                    if not re.search(value['regex'], str(getattr(alert, key) or '')):
                        return False

            # Check message content match
            elif key == 'message' and isinstance(value, dict) and value.get('contains'):
                if value['contains'] not in alert.message:
                    return False

            # Check details match if criteria specifies details fields
            elif key == 'details' and isinstance(value, dict):
                for detail_key, detail_value in value.items():
                    # Navigate nested paths with dot notation
                    if '.' in detail_key:
                        parts = detail_key.split('.')
                        curr = alert.details
                        for part in parts[:-1]:
                            if not isinstance(curr, dict) or part not in curr:
                                return False
                            curr = curr[part]

                        last_key = parts[-1]
                        if not isinstance(curr, dict) or last_key not in curr or curr[last_key] != detail_value:
                            return False
                    else:
                        # Simple key lookup
                        if detail_key not in alert.details or alert.details[detail_key] != detail_value:
                            return False

        # For throttling, check if we've exceeded the threshold
        if self.suppression_type == self.TYPE_THROTTLE:
            # Count matching alerts in time period
            cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=self.throttle_period)

            # Build query based on criteria
            query = Alert.query.filter(
                Alert.environment == self.environment,
                Alert.created_at >= cutoff_time
            )

            # Apply criteria filters
            for key, value in self.criteria.items():
                if key in ['alert_type', 'resource_id', 'service_name', 'severity'] and isinstance(value, str):
                    query = query.filter(getattr(Alert, key) == value)

            # Count alerts
            recent_count = query.count()

            # If we've already seen enough alerts, suppress this one
            return recent_count >= self.throttle_count

        # For deduplication, we'll always create the first alert but suppress duplicates
        if self.suppression_type == self.TYPE_DEDUPLICATE:
            # Check if we already have a non-resolved alert matching this criteria
            query = Alert.query.filter(
                Alert.environment == self.environment,
                Alert.status.in_(['active', 'acknowledged'])
            )

            # Apply criteria filters
            for key, value in self.criteria.items():
                if key in ['alert_type', 'resource_id', 'service_name', 'severity'] and isinstance(value, str):
                    query = query.filter(getattr(Alert, key) == value)

            # Check if matching alert exists
            return query.count() > 0

        # For silencing, always suppress if criteria match
        return True

    def mark_alert_suppressed(self) -> None:
        """Update suppression stats when an alert is suppressed."""
        self.suppressed_count += 1
        self.last_suppressed_at = datetime.now(timezone.utc)
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_matching_suppressions(cls, alert: Alert) -> List['AlertSuppression']:
        """
        Find all active suppression rules that match an alert.

        Args:
            alert: Alert to check

        Returns:
            List of matching suppression rules
        """
        try:
            # First filter by environment and active status
            now = datetime.now(timezone.utc)
            candidates = cls.query.filter(
                cls.active == True,
                cls.start_time <= now,
                or_(
                    cls.end_time.is_(None),
                    cls.end_time >= now
                ),
                or_(
                    cls.environment == 'all',
                    cls.environment == alert.environment
                )
            ).all()

            # Then check detailed criteria match
            return [rule for rule in candidates if rule.should_suppress(alert)]

        except SQLAlchemyError as e:
            current_app.logger.error(f"Error finding matching suppressions: {e}")
            return []

    @classmethod
    def should_alert_be_suppressed(cls, alert: Alert) -> Dict[str, Any]:
        """
        Check if an alert should be suppressed by any rule.

        Args:
            alert: Alert to check

        Returns:
            Dict with suppression info, or empty dict if not suppressed
        """
        matching_rules = cls.find_matching_suppressions(alert)

        if not matching_rules:
            return {}

        # Get highest priority rule (silencing takes precedence over throttling over deduplication)
        priority_map = {cls.TYPE_SILENCE: 3, cls.TYPE_THROTTLE: 2, cls.TYPE_DEDUPLICATE: 1}
        rule = max(matching_rules, key=lambda r: priority_map.get(r.suppression_type, 0))

        # Update suppression stats
        rule.mark_alert_suppressed()

        return {
            'suppressed': True,
            'rule_id': rule.id,
            'rule_name': rule.name,
            'suppression_type': rule.suppression_type,
            'reason': rule.reason,
            'created_by': rule.created_by
        }

    @classmethod
    def create_maintenance_suppression(cls, service_name: str, environment: str,
                                     duration_hours: int, created_by: str,
                                     description: str = None) -> Optional['AlertSuppression']:
        """
        Create a time-limited maintenance suppression for a service.

        Args:
            service_name: Service being maintained
            environment: Environment where maintenance occurs
            duration_hours: Duration of maintenance in hours
            created_by: User who initiated maintenance
            description: Optional description of maintenance

        Returns:
            Created suppression rule or None if creation failed
        """
        try:
            start_time = datetime.now(timezone.utc)
            end_time = start_time + timedelta(hours=duration_hours)

            rule = cls(
                name=f"Maintenance - {service_name} - {start_time.strftime('%Y-%m-%d %H:%M')}",
                criteria={'service_name': service_name},
                environment=environment,
                created_by=created_by,
                reason=cls.REASON_MAINTENANCE,
                suppression_type=cls.TYPE_SILENCE,
                description=description or f"Scheduled maintenance for {service_name}",
                start_time=start_time,
                end_time=end_time
            )

            db.session.add(rule)
            db.session.commit()

            # Log security event
            try:
                log_security_event(
                    event_type="alert_suppression_created",
                    description=f"Alert suppression rule created for {service_name}",
                    severity="info",
                    details={
                        'rule_id': rule.id,
                        'service_name': service_name,
                        'environment': environment,
                        'duration_hours': duration_hours,
                        'created_by': created_by,
                        'reason': cls.REASON_MAINTENANCE
                    }
                )
            except Exception as e:
                current_app.logger.warning(f"Could not log security event: {str(e)}")

            return rule

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create maintenance suppression: {e}")
            return None

    @classmethod
    def create_throttle_rule(cls, name: str, criteria: Dict[str, Any],
                          environment: str, created_by: str,
                          max_alerts: int, time_period_minutes: int,
                          description: str = None) -> Optional['AlertSuppression']:
        """
        Create a throttling rule to limit alert frequency.

        Args:
            name: Rule name
            criteria: Alert matching criteria
            environment: Environment where rule applies
            created_by: User who created rule
            max_alerts: Maximum alerts allowed in time period
            time_period_minutes: Time period in minutes
            description: Optional description

        Returns:
            Created suppression rule or None if creation failed
        """
        try:
            rule = cls(
                name=name,
                criteria=criteria,
                environment=environment,
                created_by=created_by,
                reason=cls.REASON_NOISE_REDUCTION,
                suppression_type=cls.TYPE_THROTTLE,
                description=description or f"Throttle rule: max {max_alerts} alerts per {time_period_minutes} minutes",
                throttle_count=max_alerts,
                throttle_period=time_period_minutes * 60  # Convert to seconds
            )

            db.session.add(rule)
            db.session.commit()

            return rule

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create throttle rule: {e}")
            return None

    @classmethod
    def cleanup_expired_suppressions(cls) -> int:
        """
        Deactivate expired suppression rules.

        Returns:
            Number of rules deactivated
        """
        try:
            now = datetime.now(timezone.utc)

            # Find expired but still active rules
            expired = cls.query.filter(
                cls.active == True,
                cls.end_time.isnot(None),
                cls.end_time < now
            ).all()

            # Deactivate expired rules
            for rule in expired:
                rule.active = False
                db.session.add(rule)

            db.session.commit()
            return len(expired)

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error cleaning up expired suppressions: {e}")
            return 0
