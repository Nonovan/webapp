"""
Alert escalation model for managing automated alert escalation workflows.

This module provides the AlertEscalation model for tracking and managing
alert escalation policies, history, and notification workflows to ensure
timely response to critical alerts.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy import desc, asc, and_, or_, func
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db
from models.base import BaseModel
from core.security import log_security_event
from models.alerts.alert import Alert

class AlertEscalation(BaseModel):
    """
    Model for tracking alert escalations.

    This model tracks alert escalations, enforces escalation policies,
    and manages notification of escalation contacts.

    Attributes:
        id (int): Escalation unique identifier
        alert_id (int): Associated alert ID
        previous_severity (str): Previous alert severity
        new_severity (str): New alert severity
        reason (str): Reason for escalation (time-based, manual, policy-based)
        escalated_by (str): User or system that triggered escalation
        escalated_at (datetime): When escalation occurred
        notified_contacts (list): List of contacts notified about escalation
        acknowledged (bool): Whether the escalation was acknowledged
        acknowledged_by (str): User who acknowledged the escalation
        acknowledged_at (datetime): When the escalation was acknowledged
    """

    __tablename__ = 'alert_escalations'

    # Escalation reasons
    REASON_TIME = 'time_threshold'
    REASON_MANUAL = 'manual'
    REASON_POLICY = 'policy_violation'
    REASON_REOCCURRENCE = 'reoccurrence'
    REASON_IMPACT = 'increased_impact'

    REASONS = [REASON_TIME, REASON_MANUAL, REASON_POLICY,
              REASON_REOCCURRENCE, REASON_IMPACT]

    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id', ondelete='CASCADE'), nullable=False, index=True)
    previous_severity = db.Column(db.String(32), nullable=False)
    new_severity = db.Column(db.String(32), nullable=False)
    reason = db.Column(db.String(32), nullable=False, index=True)
    escalated_by = db.Column(db.String(100), nullable=False)
    escalated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    notified_contacts = db.Column(MutableDict.as_mutable(db.JSON), default=list, nullable=False)
    acknowledged = db.Column(db.Boolean, default=False, nullable=False)
    acknowledged_by = db.Column(db.String(100), nullable=True)
    acknowledged_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relationships
    alert = db.relationship('Alert', backref=db.backref('escalations', lazy='dynamic', cascade='all, delete-orphan'))

    def __init__(self, alert_id: int, previous_severity: str, new_severity: str,
                reason: str, escalated_by: str = 'system'):
        """
        Initialize a new escalation record.

        Args:
            alert_id: ID of the associated alert
            previous_severity: Previous alert severity
            new_severity: New alert severity
            reason: Reason for escalation
            escalated_by: User or system that triggered escalation
        """
        self.alert_id = alert_id
        self.previous_severity = previous_severity
        self.new_severity = new_severity
        self.reason = reason
        self.escalated_by = escalated_by
        self.notified_contacts = []
        self.acknowledged = False

    def acknowledge(self, user: str) -> bool:
        """
        Acknowledge the escalation.

        Args:
            user: User acknowledging the escalation

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.acknowledged:
                self.acknowledged = True
                self.acknowledged_by = user
                self.acknowledged_at = datetime.now(timezone.utc)
                db.session.add(self)
                db.session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to acknowledge escalation: {e}")
            return False

    def add_notified_contact(self, contact: str, channel: str) -> bool:
        """
        Add a contact to the list of notified contacts.

        Args:
            contact: Contact identifier (email, username, etc.)
            channel: Notification channel used

        Returns:
            True if successful, False otherwise
        """
        try:
            self.notified_contacts.append({
                'contact': contact,
                'channel': channel,
                'notified_at': datetime.now(timezone.utc).isoformat()
            })
            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to add notified contact: {e}")
            return False

    @classmethod
    def create(cls, alert: Alert, new_severity: str, reason: str,
             escalated_by: str = 'system') -> Optional['AlertEscalation']:
        """
        Create a new escalation record and update the alert.

        Args:
            alert: Alert to escalate
            new_severity: New alert severity
            reason: Reason for escalation
            escalated_by: User or system that triggered escalation

        Returns:
            Created escalation record or None if failed
        """
        try:
            previous_severity = alert.severity

            # Create escalation record
            escalation = cls(
                alert_id=alert.id,
                previous_severity=previous_severity,
                new_severity=new_severity,
                reason=reason,
                escalated_by=escalated_by
            )

            # Update alert severity
            alert.severity = new_severity

            # Update alert details with escalation info
            details = alert.details or {}
            if 'escalation_history' not in details:
                details['escalation_history'] = []

            details['escalation_history'].append({
                'previous_severity': previous_severity,
                'new_severity': new_severity,
                'reason': reason,
                'escalated_by': escalated_by,
                'escalated_at': datetime.now(timezone.utc).isoformat()
            })

            alert.details = details

            # Save changes
            db.session.add(escalation)
            db.session.add(alert)
            db.session.commit()

            # Log security event
            try:
                log_security_event(
                    event_type="alert_escalated",
                    description=f"Alert escalated: ID {alert.id} from {previous_severity} to {new_severity}",
                    severity=new_severity.lower(),
                    details={
                        'alert_id': alert.id,
                        'alert_type': alert.alert_type,
                        'previous_severity': previous_severity,
                        'new_severity': new_severity,
                        'reason': reason,
                        'escalated_by': escalated_by
                    }
                )
            except Exception as e:
                current_app.logger.warning(f"Could not log security event: {str(e)}")

            return escalation

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to create escalation: {e}")
            return None

    @classmethod
    def check_for_escalations(cls) -> int:
        """
        Check for alerts that need to be escalated based on time thresholds.

        Returns:
            Number of alerts escalated
        """
        try:
            # Get escalation thresholds from config
            thresholds = current_app.config.get('ALERT_ESCALATION_THRESHOLDS', {
                'warning': 24,  # 24 hours
                'high': 4,      # 4 hours
                'critical': 1   # 1 hour
            })

            # Define severity upgrade path
            upgrade_path = {
                'info': 'warning',
                'warning': 'high',
                'high': 'critical'
            }

            # Track escalation count
            escalated_count = 0

            # Check each severity level for escalation
            for severity, hours in thresholds.items():
                if severity == 'critical':
                    continue  # Can't escalate critical alerts

                # Calculate threshold time
                threshold_time = datetime.now(timezone.utc) - timedelta(hours=hours)

                # Find alerts to escalate
                alerts_to_escalate = Alert.query.filter(
                    Alert.status == 'active',
                    Alert.severity == severity,
                    Alert.created_at < threshold_time,
                    # Ensure we haven't already escalated recently
                    ~Alert.id.in_(
                        db.session.query(cls.alert_id).filter(
                            cls.escalated_at > threshold_time
                        ).subquery()
                    )
                ).all()

                # Escalate each alert
                for alert in alerts_to_escalate:
                    new_severity = upgrade_path.get(severity, 'high')
                    escalation = cls.create(
                        alert=alert,
                        new_severity=new_severity,
                        reason=cls.REASON_TIME
                    )

                    if escalation:
                        escalated_count += 1

                        # Try to notify about escalation
                        try:
                            from models.alerts.alert_notification import AlertNotification
                            AlertNotification.create_notification(
                                alert=alert,
                                channel='email',
                                recipient='security-team@example.com',  # This would come from config
                                template='escalation',
                                extra_context={
                                    'previous_severity': severity,
                                    'new_severity': new_severity,
                                    'reason': cls.REASON_TIME,
                                    'threshold_hours': hours
                                }
                            )

                            # Record notification
                            escalation.add_notified_contact('security-team@example.com', 'email')
                        except Exception as e:
                            current_app.logger.warning(f"Failed to send escalation notification: {e}")

            return escalated_count

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error checking for escalations: {e}")
            return 0
