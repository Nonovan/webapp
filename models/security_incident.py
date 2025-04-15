from datetime import datetime, timezone
from extensions import db
from models.base import BaseModel

class SecurityIncident(BaseModel):
    """
    A class to represent a security incident.
    
    This model tracks security incidents detected by the application's
    monitoring systems, including breach detection, login anomalies,
    and other security-related events that require attention or response.
    """
    __tablename__ = 'security_incidents'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(36), unique=True, nullable=True)  # For backward compatibility
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=True)  # For backward compatibility (low, medium, high)
    reported_at = db.Column(db.DateTime(timezone=True), nullable=True)  # For backward compatibility
    
    # New fields for breach detection and incident response
    title = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, nullable=False)
    threat_level = db.Column(db.Integer, default=1)  # 1-10 scale
    status = db.Column(db.String(20), default='open')  # open, investigating, resolved, false_positive
    detected_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolved_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    source = db.Column(db.String(50), default='system')  # system, manual, external
    
    # Define relationship but don't import User to avoid circular imports
    resolved_by = db.relationship('User', foreign_keys=[resolved_by_id], backref=db.backref('resolved_incidents', lazy='dynamic'))

    def __init__(self, threat_level=None, details=None, status=None, detected_at=None, 
                title=None, incident_id=None, description=None, severity=None, reported_at=None,
                source=None):
        """
        Initialize a SecurityIncident instance.

        Args:
            threat_level: Numeric assessment of threat severity (1-10)
            details: Detailed information about the incident
            status: Current status of the incident (open, investigating, resolved, false_positive)
            detected_at: Timestamp when the incident was detected
            title: Short title describing the incident
            incident_id: Legacy field - unique identifier for the incident
            description: Legacy field - description of the incident
            severity: Legacy field - severity level (low, medium, high)
            reported_at: Legacy field - timestamp when incident was reported
            source: Source of the incident detection (system, manual, external)
        """
        # Handle new fields
        self.threat_level = threat_level or 1
        self.details = details or ""
        self.status = status or "open"
        self.detected_at = detected_at or datetime.now(timezone.utc)
        self.title = title or "Security incident detected"
        self.source = source or "system"
        
        # Handle legacy fields for backward compatibility
        self.incident_id = incident_id
        self.description = description
        self.severity = severity
        self.reported_at = reported_at

    def __str__(self):
        """
        Return a string representation of the security incident.
        """
        return f"SecurityIncident(ID: {self.id}, Threat Level: {self.threat_level}, Status: {self.status})"

    def is_critical(self):
        """
        Check if the incident is critical based on threat level or severity.

        Returns:
            bool: True if threat level is high (>=7) or severity is "high"
        """
        # Check both new and legacy fields
        threat_critical = self.threat_level >= 7 if self.threat_level else False
        severity_critical = self.severity and self.severity.lower() == "high"
        
        return threat_critical or severity_critical
        
    def resolve(self, user_id, resolution_notes=None):
        """
        Mark the incident as resolved.
        
        Args:
            user_id: ID of the user resolving the incident
            resolution_notes: Notes explaining the resolution
            
        Returns:
            bool: True if successfully resolved
        """
        self.status = "resolved"
        self.resolved_at = datetime.now(timezone.utc)
        self.resolved_by_id = user_id
        
        if resolution_notes:
            self.details += f"\n\nRESOLUTION ({self.resolved_at.strftime('%Y-%m-%d %H:%M:%S')}):\n{resolution_notes}"
            
        db.session.add(self)
        try:
            db.session.commit()
            return True
        except db.exc.SQLAlchemyError:
            db.session.rollback()
            return False
            
    def mark_false_positive(self, user_id, notes=None):
        """
        Mark the incident as a false positive.
        
        Args:
            user_id: ID of the user marking the incident
            notes: Additional notes explaining why it's a false positive
        
        Returns:
            bool: True if successfully updated
        """
        self.status = "false_positive"
        self.resolved_at = datetime.now(timezone.utc)
        self.resolved_by_id = user_id
        
        if notes:
            self.details += f"\n\nFALSE POSITIVE ({self.resolved_at.strftime('%Y-%m-%d %H:%M:%S')}):\n{notes}"
            
        db.session.add(self)
        try:
            db.session.commit()
            return True
        except db.exc.SQLAlchemyError:
            db.session.rollback()
            return False