"""
Administrative reporting functionality for the Cloud Infrastructure Platform.

This module provides classes and functions for generating, processing, and
managing compliance and security reports. It integrates with the underlying
database models and services to provide standardized reporting functionality
that meets regulatory and organizational requirements.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union

from flask import current_app
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.hybrid import hybrid_property

from extensions import db
from models.base import BaseModel

logger = logging.getLogger(__name__)


class ComplianceReport(BaseModel):
    """
    Model for tracking and managing compliance reports.

    Handles the generation, status tracking, and metadata for compliance
    reports across different regulatory frameworks (GDPR, HIPAA, PCI, etc.).
    Integrates with the compliance validation services to generate comprehensive
    reports that can be downloaded in various formats.
    """

    __tablename__ = 'compliance_reports'

    # Primary key
    id = Column(Integer, primary_key=True)

    # Report metadata
    name = Column(String(255), nullable=False, index=True)
    report_type = Column(String(50), nullable=False, index=True)  # gdpr, hipaa, pci, etc.
    description = Column(Text, nullable=True)

    # Time period covered by the report
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)

    # Report generation metadata
    status = Column(String(20), default='pending', nullable=False)  # pending, generating, completed, failed
    format = Column(String(20), default='pdf', nullable=False)  # pdf, json, csv, html

    # Storage info
    file_path = Column(String(255), nullable=True)
    file_size = Column(Integer, nullable=True)

    # Timestamps and user tracking
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    download_count = Column(Integer, default=0, nullable=False)
    last_downloaded_at = Column(DateTime(timezone=True), nullable=True)

    # Additional metadata
    completion_notes = Column(Text, nullable=True)
    metadata = Column(JSONB, nullable=True)

    # If report generation is scheduled for periodic runs
    is_scheduled = Column(Boolean, default=False, nullable=False)
    schedule_frequency = Column(String(50), nullable=True)  # daily, weekly, monthly, quarterly
    next_run_at = Column(DateTime(timezone=True), nullable=True)

    @hybrid_property
    def is_available(self) -> bool:
        """Check if the report is available for download."""
        return self.status == 'completed' and self.file_path is not None

    @hybrid_property
    def duration(self) -> Optional[int]:
        """Calculate the generation duration in seconds if completed."""
        if self.status == 'completed' and self.completed_at and self.created_at:
            return (self.completed_at - self.created_at).total_seconds()
        return None

    def generate(self) -> bool:
        """
        Generate the compliance report based on the report type and parameters.

        Integrates with the compliance validation service to run the appropriate
        checks and compile the results into the specified format.

        Returns:
            bool: True if generation was successful, False otherwise
        """
        try:
            self.status = 'generating'
            db.session.commit()

            # Initialize report generation service based on report type
            # This could use a service factory pattern based on report_type
            from services.compliance_service import generate_compliance_report

            # Generate the report
            result = generate_compliance_report(
                report_id=self.id,
                report_type=self.report_type,
                start_date=self.period_start,
                end_date=self.period_end,
                output_format=self.format
            )

            # Update report status based on result
            if result.get('success', False):
                self.status = 'completed'
                self.file_path = result.get('file_path')
                self.file_size = result.get('file_size')
                self.completed_at = datetime.now(timezone.utc)
                self.completion_notes = result.get('notes')
                self.metadata = result.get('metadata')
                db.session.commit()
                return True
            else:
                self.status = 'failed'
                self.completion_notes = result.get('error', 'Unknown error during report generation')
                db.session.commit()
                return False

        except Exception as e:
            logger.error(f"Error generating compliance report {self.id}: {str(e)}", exc_info=True)
            self.status = 'failed'
            self.completion_notes = f"Error: {str(e)}"
            db.session.commit()
            return False

    def increment_download_count(self) -> None:
        """Update the download counter and timestamp when report is accessed."""
        self.download_count += 1
        self.last_downloaded_at = datetime.now(timezone.utc)
        db.session.commit()

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the report for display.

        Returns:
            Dict[str, Any]: Summary information about the report
        """
        return {
            'id': self.id,
            'name': self.name,
            'report_type': self.report_type,
            'period': {
                'start': self.period_start.isoformat() if self.period_start else None,
                'end': self.period_end.isoformat() if self.period_end else None,
            },
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'download_count': self.download_count,
            'is_available': self.is_available,
            'format': self.format,
            'file_size': self.file_size
        }

    @classmethod
    def get_reports_by_type(cls, report_type: str, limit: int = 10) -> List['ComplianceReport']:
        """
        Get reports of a specific type.

        Args:
            report_type: Type of compliance report to retrieve
            limit: Maximum number of reports to return

        Returns:
            List of compliance report objects
        """
        return cls.query.filter_by(report_type=report_type).order_by(
            cls.created_at.desc()
        ).limit(limit).all()

    @classmethod
    def get_recent_reports(cls, limit: int = 10) -> List['ComplianceReport']:
        """
        Get the most recent reports of any type.

        Args:
            limit: Maximum number of reports to return

        Returns:
            List of compliance report objects
        """
        return cls.query.order_by(cls.created_at.desc()).limit(limit).all()

    def __repr__(self) -> str:
        """String representation of the compliance report."""
        return f"<ComplianceReport id={self.id} type={self.report_type} status={self.status}>"
