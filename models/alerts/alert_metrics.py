"""
Alert metrics model for tracking and analyzing alert statistics.

This module provides the AlertMetrics model for tracking alert statistics
across time periods, environments, and services to enable trending analysis
and reporting on alert patterns.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple
from sqlalchemy import desc, asc, and_, or_, func, extract
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db
from models.base import BaseModel
from models.alerts.alert import Alert

class AlertMetrics(BaseModel):
    """
    Model for tracking aggregated alert metrics.

    This model stores daily aggregated alert statistics for trending
    and reporting purposes, including counts by severity, status,
    and service.

    Attributes:
        id (int): Metrics record unique identifier
        date (datetime): Date of the metrics data (day precision)
        environment (str): Environment for these metrics
        total_alerts (int): Total alerts created on this day
        critical_count (int): Count of critical alerts
        high_count (int): Count of high severity alerts
        warning_count (int): Count of warning alerts
        info_count (int): Count of info alerts
        active_count (int): Count of alerts that remain active
        acknowledged_count (int): Count of acknowledged alerts
        resolved_count (int): Count of resolved alerts
        service_counts (dict): Alert counts by service
        avg_time_to_acknowledge (float): Average time to acknowledge (minutes)
        avg_time_to_resolve (float): Average time to resolve (minutes)
        created_at (datetime): When this metrics record was created
    """

    __tablename__ = 'alert_metrics'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    environment = db.Column(db.String(32), nullable=False, index=True)

    # Alert counts by severity
    total_alerts = db.Column(db.Integer, default=0, nullable=False)
    critical_count = db.Column(db.Integer, default=0, nullable=False)
    high_count = db.Column(db.Integer, default=0, nullable=False)
    warning_count = db.Column(db.Integer, default=0, nullable=False)
    info_count = db.Column(db.Integer, default=0, nullable=False)

    # Alert counts by status
    active_count = db.Column(db.Integer, default=0, nullable=False)
    acknowledged_count = db.Column(db.Integer, default=0, nullable=False)
    resolved_count = db.Column(db.Integer, default=0, nullable=False)

    # Service-specific counts (stored as JSON)
    service_counts = db.Column(db.JSON, default=dict, nullable=False)

    # Performance metrics
    avg_time_to_acknowledge = db.Column(db.Float, nullable=True)  # In minutes
    avg_time_to_resolve = db.Column(db.Float, nullable=True)      # In minutes

    # Metadata
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True),
                          default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc),
                          nullable=False)

    def __init__(self, date: datetime, environment: str):
        """
        Initialize a metrics record.

        Args:
            date: Date for the metrics (will be truncated to day)
            environment: Environment for the metrics
        """
        self.date = date.date()  # Truncate to day
        self.environment = environment
        self.service_counts = {}

    @classmethod
    def get_or_create(cls, date: datetime, environment: str) -> Tuple['AlertMetrics', bool]:
        """
        Get or create a metrics record for a specific date and environment.

        Args:
            date: Date for the metrics
            environment: Environment for the metrics

        Returns:
            Tuple of (metrics record, created flag)
        """
        metrics = cls.query.filter_by(
            date=date.date(),
            environment=environment
        ).first()

        created = False
        if not metrics:
            metrics = cls(date=date, environment=environment)
            db.session.add(metrics)
            db.session.commit()
            created = True

        return metrics, created

    @classmethod
    def calculate_daily_metrics(cls, target_date: Optional[datetime] = None,
                              environment: Optional[str] = None) -> Optional['AlertMetrics']:
        """
        Calculate metrics for a specific day.

        Args:
            target_date: Target date (defaults to yesterday)
            environment: Environment to calculate metrics for (defaults to all)

        Returns:
            Created or updated metrics record, or None if failed
        """
        try:
            # Default to yesterday
            if target_date is None:
                target_date = datetime.now(timezone.utc) - timedelta(days=1)

            # Truncate to day
            target_date = datetime.combine(target_date.date(), datetime.min.time())
            next_day = target_date + timedelta(days=1)

            # Create metrics record
            metrics, created = cls.get_or_create(target_date, environment or 'all')

            # Create base query
            query = Alert.query.filter(
                Alert.created_at >= target_date,
                Alert.created_at < next_day
            )

            # Filter by environment if specified
            if environment:
                query = query.filter_by(environment=environment)

            # Count total alerts
            metrics.total_alerts = query.count()

            # Count by severity
            for severity in ['critical', 'high', 'warning', 'info']:
                count = query.filter_by(severity=severity).count()
                setattr(metrics, f"{severity}_count", count)

            # Count by status
            for status in ['active', 'acknowledged', 'resolved']:
                count = query.filter_by(status=status).count()
                setattr(metrics, f"{status}_count", count)

            # Count by service
            service_counts = {}
            service_results = db.session.query(
                Alert.service_name, func.count(Alert.id)
            ).filter(
                Alert.created_at >= target_date,
                Alert.created_at < next_day
            )

            # Filter by environment if specified
            if environment:
                service_results = service_results.filter_by(environment=environment)

            service_results = service_results.group_by(Alert.service_name).all()

            for service_name, count in service_results:
                if service_name:  # Exclude None values
                    service_counts[service_name] = count

            metrics.service_counts = service_counts

            # Calculate average time to acknowledge
            ack_results = db.session.query(
                func.avg(
                    func.extract('epoch', Alert.acknowledged_at) -
                    func.extract('epoch', Alert.created_at)
                ) / 60  # Convert seconds to minutes
            ).filter(
                Alert.created_at >= target_date,
                Alert.created_at < next_day,
                Alert.acknowledged_at.isnot(None)
            )

            # Filter by environment if specified
            if environment:
                ack_results = ack_results.filter_by(environment=environment)

            avg_time_to_ack = ack_results.scalar()
            metrics.avg_time_to_acknowledge = avg_time_to_ack

            # Calculate average time to resolve
            resolve_results = db.session.query(
                func.avg(
                    func.extract('epoch', Alert.resolved_at) -
                    func.extract('epoch', Alert.created_at)
                ) / 60  # Convert seconds to minutes
            ).filter(
                Alert.created_at >= target_date,
                Alert.created_at < next_day,
                Alert.resolved_at.isnot(None)
            )

            # Filter by environment if specified
            if environment:
                resolve_results = resolve_results.filter_by(environment=environment)

            avg_time_to_resolve = resolve_results.scalar()
            metrics.avg_time_to_resolve = avg_time_to_resolve

            # Save changes
            metrics.updated_at = datetime.now(timezone.utc)
            db.session.add(metrics)
            db.session.commit()

            return metrics

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to calculate daily metrics: {e}")
            return None

    @classmethod
    def get_trend_data(cls, days: int = 30, environment: Optional[str] = None) -> Dict[str, Any]:
        """
        Get trending data for alerts over a period.

        Args:
            days: Number of days to include
            environment: Environment to filter by (defaults to all)

        Returns:
            Dictionary with trend data
        """
        try:
            # Calculate date range
            end_date = datetime.now(timezone.utc).date()
            start_date = end_date - timedelta(days=days)

            # Build query
            query = cls.query.filter(
                cls.date >= start_date,
                cls.date <= end_date
            ).order_by(asc(cls.date))

            # Filter by environment if specified
            if environment and environment != 'all':
                query = query.filter_by(environment=environment)

            metrics = query.all()

            # Initialize result structure
            result = {
                'dates': [],
                'total_alerts': [],
                'by_severity': {
                    'critical': [],
                    'high': [],
                    'warning': [],
                    'info': []
                },
                'by_status': {
                    'active': [],
                    'acknowledged': [],
                    'resolved': []
                },
                'avg_time_to_acknowledge': [],
                'avg_time_to_resolve': [],
                'top_services': {}
            }

            # Fill in missing dates with zeros
            date_metrics = {m.date.isoformat(): m for m in metrics}
            current_date = start_date
            service_counters = {}

            while current_date <= end_date:
                date_iso = current_date.isoformat()
                result['dates'].append(date_iso)

                if date_iso in date_metrics:
                    m = date_metrics[date_iso]
                    result['total_alerts'].append(m.total_alerts)
                    result['by_severity']['critical'].append(m.critical_count)
                    result['by_severity']['high'].append(m.high_count)
                    result['by_severity']['warning'].append(m.warning_count)
                    result['by_severity']['info'].append(m.info_count)
                    result['by_status']['active'].append(m.active_count)
                    result['by_status']['acknowledged'].append(m.acknowledged_count)
                    result['by_status']['resolved'].append(m.resolved_count)
                    result['avg_time_to_acknowledge'].append(m.avg_time_to_acknowledge or 0)
                    result['avg_time_to_resolve'].append(m.avg_time_to_resolve or 0)

                    # Accumulate service counts
                    for service, count in m.service_counts.items():
                        if service not in service_counters:
                            service_counters[service] = 0
                        service_counters[service] += count
                else:
                    # Fill with zeros for missing dates
                    result['total_alerts'].append(0)
                    result['by_severity']['critical'].append(0)
                    result['by_severity']['high'].append(0)
                    result['by_severity']['warning'].append(0)
                    result['by_severity']['info'].append(0)
                    result['by_status']['active'].append(0)
                    result['by_status']['acknowledged'].append(0)
                    result['by_status']['resolved'].append(0)
                    result['avg_time_to_acknowledge'].append(0)
                    result['avg_time_to_resolve'].append(0)

                current_date += timedelta(days=1)

            # Get top 5 services by alert count
            top_services = sorted(service_counters.items(), key=lambda x: x[1], reverse=True)[:5]
            for service, count in top_services:
                result['top_services'][service] = count

            return result

        except SQLAlchemyError as e:
            current_app.logger.error(f"Failed to get trend data: {e}")
            return {
                'dates': [],
                'total_alerts': [],
                'by_severity': {'critical': [], 'high': [], 'warning': [], 'info': []},
                'by_status': {'active': [], 'acknowledged': [], 'resolved': []},
                'avg_time_to_acknowledge': [],
                'avg_time_to_resolve': [],
                'top_services': {},
                'error': str(e)
            }

    @classmethod
    def calculate_missing_daily_metrics(cls, days_back: int = 30) -> int:
        """
        Calculate missing metrics for the past N days.

        Args:
            days_back: Number of days to go back

        Returns:
            Number of days for which metrics were calculated
        """
        try:
            calculated_count = 0
            today = datetime.now(timezone.utc).date()

            # Get environments
            environments = db.session.query(
                Alert.environment
            ).distinct().all()

            environments = [e[0] for e in environments] + ['all']

            # Loop through each day and environment
            for days_ago in range(1, days_back + 1):
                target_date = today - timedelta(days=days_ago)

                for env in environments:
                    # Check if metrics already exist
                    existing = cls.query.filter_by(
                        date=target_date,
                        environment=env
                    ).first()

                    if not existing:
                        if cls.calculate_daily_metrics(
                            target_date=datetime.combine(target_date, datetime.min.time()),
                            environment=env
                        ):
                            calculated_count += 1

            return calculated_count

        except Exception as e:
            current_app.logger.error(f"Error calculating missing metrics: {e}")
            return 0
