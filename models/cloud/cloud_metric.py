"""
Cloud metric model for tracking cloud resource metrics.

This module provides the CloudMetric model which stores time-series metrics data
for cloud resources across different providers. It enables historical data analysis,
trend visualization, and anomaly detection for monitored cloud resources.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Union
from sqlalchemy import func, desc, cast, Numeric
from sqlalchemy.sql import text as sql_text
from sqlalchemy.exc import SQLAlchemyError
from flask import current_app

from extensions import db, metrics, cache
from models.base import BaseModel


class CloudMetric(BaseModel):
    """
    Model representing a cloud resource metric data point.

    This model stores time-series data points for various metrics related to
    cloud resources. Each data point includes timestamp, metric type, numeric value,
    and associated metadata to support comprehensive monitoring and visualization.

    Attributes:
        id: Primary key
        resource_id: ID of the cloud resource
        provider_id: ID of the cloud provider
        metric_name: Name of the metric (cpu_usage, memory_usage, etc.)
        value: Numeric metric value
        unit: Unit of measurement (percent, bytes, etc.)
        timestamp: When the metric was recorded
        dimensions: JSON data with additional dimensions for the metric
        is_anomaly: Whether this data point represents an anomaly
        anomaly_score: Numeric score for anomaly severity if applicable
        collection_method: How the metric was collected (api, agent, synthetic)
        region: Cloud region where the metric was collected
    """
    __tablename__ = 'cloud_metrics'

    # Common metric names
    METRIC_CPU_USAGE = 'cpu_usage'
    METRIC_MEMORY_USAGE = 'memory_usage'
    METRIC_DISK_USAGE = 'disk_usage'
    METRIC_NETWORK_IN = 'network_in'
    METRIC_NETWORK_OUT = 'network_out'
    METRIC_IOPS = 'iops'
    METRIC_LATENCY = 'latency'
    METRIC_ERROR_RATE = 'error_rate'
    METRIC_REQUEST_COUNT = 'request_count'
    METRIC_COST = 'cost'

    # Collection methods
    COLLECTION_API = 'api'
    COLLECTION_AGENT = 'agent'
    COLLECTION_SYNTHETIC = 'synthetic'

    # Valid collection methods
    VALID_COLLECTION_METHODS = [
        COLLECTION_API,
        COLLECTION_AGENT,
        COLLECTION_SYNTHETIC
    ]

    # Table definition
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('cloud_resources.id', ondelete='CASCADE'), nullable=False, index=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('cloud_providers.id', ondelete='CASCADE'), nullable=False, index=True)
    metric_name = db.Column(db.String(64), nullable=False, index=True)
    value = db.Column(db.Numeric(16, 6), nullable=False)
    unit = db.Column(db.String(32), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    dimensions = db.Column(db.JSON, default=dict, nullable=False)
    is_anomaly = db.Column(db.Boolean, default=False, nullable=False, index=True)
    anomaly_score = db.Column(db.Float, nullable=True)
    collection_method = db.Column(db.String(16), default=COLLECTION_API, nullable=False)
    region = db.Column(db.String(32), nullable=True, index=True)

    # Relationships
    provider = db.relationship('CloudProvider', backref=db.backref('metrics', lazy='dynamic'))
    resource = db.relationship('CloudResource', backref=db.backref('metrics', lazy='dynamic'))

    def __init__(self, resource_id: int, provider_id: int, metric_name: str, value: float,
                unit: str, timestamp: Optional[datetime] = None, dimensions: Optional[Dict] = None,
                is_anomaly: bool = False, anomaly_score: Optional[float] = None,
                collection_method: str = COLLECTION_API, region: Optional[str] = None) -> None:
        """
        Initialize a CloudMetric instance.

        Args:
            resource_id: ID of the cloud resource
            provider_id: ID of the cloud provider
            metric_name: Name of the metric (cpu_usage, memory_usage, etc.)
            value: Numeric metric value
            unit: Unit of measurement (percent, bytes, etc.)
            timestamp: When the metric was recorded, defaults to now
            dimensions: Additional dimensions for the metric
            is_anomaly: Whether this data point represents an anomaly
            anomaly_score: Numeric score for anomaly severity if applicable
            collection_method: How the metric was collected
            region: Cloud region where the metric was collected
        """
        self.resource_id = resource_id
        self.provider_id = provider_id
        self.metric_name = metric_name
        self.value = value
        self.unit = unit
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.dimensions = dimensions or {}
        self.is_anomaly = is_anomaly
        self.anomaly_score = anomaly_score

        # Validate collection method
        if collection_method in self.VALID_COLLECTION_METHODS:
            self.collection_method = collection_method
        else:
            self.collection_method = self.COLLECTION_API

        self.region = region

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert metric to dictionary for API responses.

        Returns:
            Dict[str, Any]: Dictionary representation of the metric
        """
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'provider_id': self.provider_id,
            'metric_name': self.metric_name,
            'value': float(self.value) if self.value is not None else None,
            'unit': self.unit,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'dimensions': self.dimensions,
            'is_anomaly': self.is_anomaly,
            'anomaly_score': self.anomaly_score,
            'collection_method': self.collection_method,
            'region': self.region
        }

    @classmethod
    def batch_insert(cls, metrics_data: List[Dict[str, Any]]) -> bool:
        """
        Efficiently insert multiple metrics at once.

        Args:
            metrics_data: List of dictionaries containing metric data

        Returns:
            bool: True if batch insert was successful, False otherwise
        """
        if not metrics_data:
            current_app.logger.warning("Empty metrics data provided for batch insert")
            return False

        try:
            # Validate collection methods in all entries
            for entry in metrics_data:
                if 'collection_method' in entry:
                    if entry['collection_method'] not in cls.VALID_COLLECTION_METHODS:
                        entry['collection_method'] = cls.COLLECTION_API

                # Ensure timestamp is timezone-aware
                if 'timestamp' in entry and entry['timestamp'] and isinstance(entry['timestamp'], datetime):
                    if entry['timestamp'].tzinfo is None:
                        entry['timestamp'] = entry['timestamp'].replace(tzinfo=timezone.utc)

                # Ensure dimensions is not None
                if 'dimensions' not in entry or entry['dimensions'] is None:
                    entry['dimensions'] = {}

            db.session.bulk_insert_mappings(cls, metrics_data)
            db.session.commit()

            # Update prometheus metrics if available
            if hasattr(metrics, 'gauge'):
                metrics.gauge(
                    'cloud_metrics_batch_insert',
                    len(metrics_data),
                    {'status': 'success'}
                )

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to batch insert metrics: {str(e)}")

            # Update prometheus metrics if available
            if hasattr(metrics, 'gauge'):
                metrics.gauge(
                    'cloud_metrics_batch_insert',
                    0,
                    {'status': 'error'}
                )

            return False
        except Exception as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Unexpected error in batch insert: {str(e)}")
            return False

    @classmethod
    def get_metrics_for_resource(cls, resource_id: int, metric_name: Optional[str] = None,
                               start_time: Optional[datetime] = None,
                               end_time: Optional[datetime] = None,
                               limit: int = 1000) -> List['CloudMetric']:
        """
        Get metrics for a specific resource with optional filtering.

        Args:
            resource_id: ID of the resource to get metrics for
            metric_name: Optional filter by metric name
            start_time: Optional start time filter
            end_time: Optional end time filter
            limit: Maximum number of metrics to return

        Returns:
            List[CloudMetric]: List of CloudMetric objects
        """
        try:
            # Validate parameters
            if limit <= 0 or limit > 10000:
                limit = 1000  # Set a reasonable default if out of bounds

            # Ensure proper datetime objects with timezone
            if start_time and start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=timezone.utc)
            if end_time and end_time.tzinfo is None:
                end_time = end_time.replace(tzinfo=timezone.utc)

            query = cls.query.filter_by(resource_id=resource_id)

            if metric_name:
                query = query.filter_by(metric_name=metric_name)

            if start_time:
                query = query.filter(cls.timestamp >= start_time)

            if end_time:
                query = query.filter(cls.timestamp <= end_time)

            result = query.order_by(desc(cls.timestamp)).limit(limit).all()

            # Update lookup metrics if metrics tracking is available
            if hasattr(metrics, 'counter'):
                metrics.counter(
                    'cloud_metrics_retrieved',
                    len(result),
                    {'resource_id': str(resource_id)}
                )

            return result
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error retrieving metrics for resource {resource_id}: {str(e)}")
            return []

    @classmethod
    def get_latest_metric(cls, resource_id: int, metric_name: str) -> Optional['CloudMetric']:
        """
        Get the latest metric value for a resource and metric name.

        Args:
            resource_id: ID of the resource
            metric_name: Name of the metric

        Returns:
            Optional[CloudMetric]: The latest CloudMetric object or None if not found
        """
        # Check cache first
        cache_key = f"latest_metric:{resource_id}:{metric_name}"
        cached_data = None

        if hasattr(cache, 'get'):
            cached_data = cache.get(cache_key)

        if cached_data:
            try:
                # Create metric object from cached data
                metric = cls(**cached_data)
                return metric
            except (TypeError, ValueError):
                # If we can't recreate from cache, ignore and get from DB
                pass

        try:
            metric = cls.query.filter_by(
                resource_id=resource_id,
                metric_name=metric_name
            ).order_by(desc(cls.timestamp)).first()

            # Cache the result for 60 seconds
            if metric and hasattr(cache, 'set'):
                serialized_data = metric.to_dict()
                cache.set(cache_key, serialized_data, timeout=60)

            return metric
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error retrieving latest metric: {str(e)}")
            return None

    @classmethod
    def get_aggregated_metrics(cls, resource_id: int, metric_name: str,
                             interval: str = '1 hour',
                             start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get time-aggregated metrics for visualization.

        Args:
            resource_id: ID of the resource
            metric_name: Name of the metric
            interval: Time interval for aggregation (e.g., '1 hour', '15 minute', '1 day')
            start_time: Optional start time filter
            end_time: Optional end time filter

        Returns:
            List[Dict[str, Any]]: List of dictionaries with aggregated metric data
        """
        # Validate inputs
        if not isinstance(resource_id, int) or resource_id <= 0:
            if hasattr(current_app, 'logger'):
                current_app.logger.warning(f"Invalid resource_id provided: {resource_id}")
            return []

        # Sanitize interval to prevent SQL injection
        allowed_intervals = ['5 minute', '15 minute', '30 minute', '1 hour', '4 hour', '6 hour', '12 hour', '1 day', '7 day']
        if interval not in allowed_intervals:
            interval = '1 hour'  # Safe default

        if start_time is None:
            start_time = datetime.now(timezone.utc) - timedelta(days=1)

        if end_time is None:
            end_time = datetime.now(timezone.utc)

        # Ensure proper datetime objects
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        # Ensure proper date range
        if end_time <= start_time:
            end_time = start_time + timedelta(hours=1)

        # Cache key for frequent dashboard queries
        cache_key = f"agg_metrics:{resource_id}:{metric_name}:{interval}:{start_time.isoformat()}:{end_time.isoformat()}"
        cached_result = None

        if hasattr(cache, 'get'):
            cached_result = cache.get(cache_key)

        if cached_result:
            return cached_result

        try:
            # Check if we have the TimescaleDB time_bucket function
            has_timescaledb = False
            try:
                db.session.execute(sql_text("SELECT time_bucket('1 hour', NOW())"))
                has_timescaledb = True
            except Exception:
                pass

            if has_timescaledb:
                # Use TimescaleDB time_bucket for efficient time-series aggregation
                result = db.session.execute(
                    sql_text("""
                        SELECT
                            time_bucket(:interval, timestamp) AS bucket,
                            AVG(CAST(value AS FLOAT)) AS avg_value,
                            MAX(CAST(value AS FLOAT)) AS max_value,
                            MIN(CAST(value AS FLOAT)) AS min_value,
                            COUNT(*) AS sample_count
                        FROM cloud_metrics
                        WHERE
                            resource_id = :resource_id AND
                            metric_name = :metric_name AND
                            timestamp BETWEEN :start_time AND :end_time
                        GROUP BY bucket
                        ORDER BY bucket ASC
                    """),
                    {
                        'interval': interval,
                        'resource_id': resource_id,
                        'metric_name': metric_name,
                        'start_time': start_time,
                        'end_time': end_time
                    }
                )

                # Process the result into a dictionary format for JSON responses
                aggregated_data = [
                    {
                        'timestamp': row[0].isoformat(),
                        'avg_value': float(row[1]) if row[1] is not None else None,
                        'max_value': float(row[2]) if row[2] is not None else None,
                        'min_value': float(row[3]) if row[3] is not None else None,
                        'sample_count': int(row[4])
                    }
                    for row in result
                ]
            else:
                # Fallback to standard SQL if TimescaleDB is not available
                aggregated_data = cls._fallback_aggregation(
                    resource_id, metric_name, interval, start_time, end_time)

            # Cache result for 5 minutes
            if hasattr(cache, 'set'):
                cache.set(cache_key, aggregated_data, timeout=300)

            return aggregated_data
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error aggregating metrics: {str(e)}")

            # Fallback to a non-TimescaleDB approach if necessary
            try:
                return cls._fallback_aggregation(
                    resource_id, metric_name, interval, start_time, end_time)
            except (ValueError, SQLAlchemyError) as fallback_err:
                if hasattr(current_app, 'logger'):
                    current_app.logger.error(f"Fallback aggregation failed: {fallback_err}")
                return []

    @classmethod
    def _fallback_aggregation(cls, resource_id: int, metric_name: str,
                            interval: str, start_time: datetime,
                            end_time: datetime) -> List[Dict[str, Any]]:
        """
        Fallback method for aggregation when TimescaleDB is not available.

        Args:
            resource_id: ID of the resource
            metric_name: Name of the metric
            interval: Time interval for aggregation
            start_time: Start time filter
            end_time: End time filter

        Returns:
            List[Dict[str, Any]]: List of dictionaries with aggregated metric data
        """
        # Parse interval string to determine grouping (e.g., "1 hour" -> group by hour)
        interval_parts = interval.split()
        if len(interval_parts) != 2:
            raise ValueError(f"Invalid interval format: {interval}")

        unit = interval_parts[1].lower()

        # Map unit to SQLAlchemy func
        if 'minute' in unit:
            date_trunc = func.date_trunc('minute', cls.timestamp)
        elif 'hour' in unit:
            date_trunc = func.date_trunc('hour', cls.timestamp)
        elif 'day' in unit:
            date_trunc = func.date_trunc('day', cls.timestamp)
        else:
            raise ValueError(f"Unsupported interval unit: {unit}")

        # Build query with regular SQLAlchemy
        result = db.session.query(
            date_trunc.label('bucket'),
            func.avg(cast(cls.value, Numeric)).label('avg_value'),
            func.max(cast(cls.value, Numeric)).label('max_value'),
            func.min(cast(cls.value, Numeric)).label('min_value'),
            func.count().label('sample_count')
        ).filter(
            cls.resource_id == resource_id,
            cls.metric_name == metric_name,
            cls.timestamp.between(start_time, end_time)
        ).group_by(
            date_trunc
        ).order_by(
            date_trunc.asc()
        ).all()

        # Format results safely
        return [
            {
                'timestamp': row.bucket.isoformat(),
                'avg_value': float(row.avg_value) if row.avg_value is not None else None,
                'max_value': float(row.max_value) if row.max_value is not None else None,
                'min_value': float(row.min_value) if row.min_value is not None else None,
                'sample_count': int(row.sample_count)
            }
            for row in result
        ]

    @classmethod
    def detect_anomalies(cls, resource_id: int, metric_name: str,
                       threshold_sigma: float = 2.0, window_minutes: int = 60,
                       baseline_days: int = 7) -> List['CloudMetric']:
        """
        Detect anomalies in recent metrics data using statistical methods.

        Args:
            resource_id: ID of the resource to check
            metric_name: Metric name to analyze
            threshold_sigma: Standard deviation threshold for anomaly detection
            window_minutes: Window of time to analyze for anomalies (minutes)
            baseline_days: Days of historical data to use for baseline

        Returns:
            List[CloudMetric]: List of metrics flagged as anomalies
        """
        # Validate inputs
        if threshold_sigma <= 0:
            threshold_sigma = 2.0
        if window_minutes <= 0 or window_minutes > 1440:  # Max 1 day
            window_minutes = 60
        if baseline_days <= 0 or baseline_days > 30:  # Max 30 days
            baseline_days = 7

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=window_minutes)
        baseline_start = end_time - timedelta(days=baseline_days)

        try:
            # Get recent metrics to check for anomalies
            recent_metrics = cls.get_metrics_for_resource(
                resource_id=resource_id,
                metric_name=metric_name,
                start_time=start_time,
                end_time=end_time
            )

            if not recent_metrics:
                return []

            # Calculate baseline statistics
            baseline = db.session.query(
                func.avg(cls.value).label('avg'),
                func.stddev(cls.value).label('stddev')
            ).filter(
                cls.resource_id == resource_id,
                cls.metric_name == metric_name,
                cls.timestamp.between(baseline_start, start_time)
            ).first()

            if not baseline or baseline.avg is None or baseline.stddev is None:
                # Not enough baseline data
                return []

            baseline_avg = float(baseline.avg)
            baseline_stddev = float(baseline.stddev) if baseline.stddev > 0 else 1.0

            anomalies = []
            for metric in recent_metrics:
                # Calculate z-score (standard deviations from mean)
                try:
                    value = float(metric.value)
                    z_score = abs(value - baseline_avg) / baseline_stddev
                except (ValueError, TypeError, ZeroDivisionError):
                    continue

                if z_score > threshold_sigma:
                    # Mark as anomaly
                    metric.is_anomaly = True
                    metric.anomaly_score = float(z_score)
                    anomalies.append(metric)

                    # Update in database
                    db.session.add(metric)

            if anomalies:
                db.session.commit()

                # Create alerts for significant anomalies
                cls._create_anomaly_alerts(anomalies, baseline_avg, threshold_sigma)

            return anomalies
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error detecting anomalies: {str(e)}")
            return []

    @classmethod
    def _create_anomaly_alerts(cls, anomalies: List['CloudMetric'],
                             baseline: float, threshold: float) -> None:
        """
        Create alerts for significant anomalies.

        Args:
            anomalies: List of anomalous metrics
            baseline: Baseline average value
            threshold: Standard deviation threshold used for detection
        """
        # Import here to avoid circular imports
        try:
            from models.cloud_alert import CloudAlert

            for metric in anomalies:
                # Only alert on significant anomalies (high anomaly score)
                if metric.anomaly_score and metric.anomaly_score > threshold * 1.5:
                    # Determine severity based on anomaly score
                    if metric.anomaly_score > threshold * 3:
                        severity = CloudAlert.SEVERITY_ERROR
                    elif metric.anomaly_score > threshold * 2:
                        severity = CloudAlert.SEVERITY_WARNING
                    else:
                        severity = CloudAlert.SEVERITY_INFO

                    # Create the alert
                    CloudAlert.create_from_metric(
                        metric.metric_name,
                        float(metric.value),
                        baseline,
                        metric.resource_id,
                        metric.provider_id,
                        severity=severity
                    )
        except (ImportError, AttributeError, SQLAlchemyError) as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error creating anomaly alerts: {str(e)}")

    @classmethod
    def get_statistics_by_provider(cls, provider_id: int, days: int = 30) -> Dict[str, Any]:
        """
        Get statistical summary of metrics for a provider.

        Args:
            provider_id: ID of the provider
            days: Number of days to include in the statistics

        Returns:
            Dict[str, Any]: Dictionary with metric statistics
        """
        # Validate input
        if days <= 0 or days > 365:
            days = 30

        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        try:
            # Get total metrics count
            metrics_count = db.session.query(func.count(cls.id)).filter(
                cls.provider_id == provider_id,
                cls.timestamp >= start_time
            ).scalar() or 0

            # Get metrics by region
            region_counts = db.session.query(
                cls.region,
                func.count(cls.id).label('count')
            ).filter(
                cls.provider_id == provider_id,
                cls.timestamp >= start_time
            ).group_by(
                cls.region
            ).all()

            # Get anomaly count
            anomaly_count = db.session.query(func.count(cls.id)).filter(
                cls.provider_id == provider_id,
                cls.timestamp >= start_time,
                cls.is_anomaly == True  # Using == for SQLAlchemy
            ).scalar() or 0

            # Format the results
            return {
                'total_metrics': metrics_count,
                'anomaly_count': anomaly_count,
                'anomaly_percentage': (anomaly_count / metrics_count * 100) if metrics_count > 0 else 0,
                'regions': {region: count for region, count in region_counts if region},
                'collection_period_days': days
            }
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error getting provider statistics: {str(e)}")
            return {
                'total_metrics': 0,
                'anomaly_count': 0,
                'anomaly_percentage': 0,
                'regions': {},
                'collection_period_days': days,
                'error': str(e)
            }

    @classmethod
    def get_cost_metrics(cls, resource_id: int, start_time: Optional[datetime] = None,
                       end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Get cost metrics for a specific resource.

        Args:
            resource_id: ID of the resource
            start_time: Optional start time
            end_time: Optional end time

        Returns:
            Dict[str, Any]: Dictionary with cost metrics
        """
        if start_time is None:
            start_time = datetime.now(timezone.utc) - timedelta(days=30)

        if end_time is None:
            end_time = datetime.now(timezone.utc)

        # Ensure proper timezone
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        try:
            # Get total cost for the period
            total_cost = db.session.query(func.sum(cls.value)).filter(
                cls.resource_id == resource_id,
                cls.metric_name == cls.METRIC_COST,
                cls.timestamp.between(start_time, end_time)
            ).scalar() or 0

            # Get daily costs
            daily_costs = db.session.query(
                func.date_trunc('day', cls.timestamp).label('day'),
                func.sum(cls.value).label('cost')
            ).filter(
                cls.resource_id == resource_id,
                cls.metric_name == cls.METRIC_COST,
                cls.timestamp.between(start_time, end_time)
            ).group_by(
                func.date_trunc('day', cls.timestamp)
            ).order_by(
                func.date_trunc('day', cls.timestamp)
            ).all()

            # Format result
            return {
                'total_cost': float(total_cost),
                'daily_costs': [
                    {'date': day.strftime('%Y-%m-%d'), 'cost': float(cost)}
                    for day, cost in daily_costs
                ],
                'start_date': start_time.strftime('%Y-%m-%d'),
                'end_date': end_time.strftime('%Y-%m-%d')
            }
        except SQLAlchemyError as e:
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Error getting cost metrics: {str(e)}")
            return {
                'total_cost': 0,
                'daily_costs': [],
                'start_date': start_time.strftime('%Y-%m-%d'),
                'end_date': end_time.strftime('%Y-%m-%d'),
                'error': str(e)
            }

    @classmethod
    def cleanup_old_metrics(cls, days: int = 90) -> int:
        """
        Delete metrics older than the specified number of days.

        Args:
            days: Age threshold in days

        Returns:
            int: Number of deleted metrics
        """
        # Validate input
        if days <= 0:
            if hasattr(current_app, 'logger'):
                current_app.logger.warning("Invalid days parameter for cleanup_old_metrics, using default")
            days = 90

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        try:
            # Perform bulk delete operation
            deleted = db.session.query(cls).filter(
                cls.timestamp < cutoff_date
            ).delete(synchronize_session=False)

            db.session.commit()

            # Log the cleanup operation
            if hasattr(current_app, 'logger'):
                current_app.logger.info(f"Cleaned up {deleted} metrics older than {days} days")

            # Update prometheus metrics if available
            if hasattr(metrics, 'counter'):
                metrics.counter(
                    'cloud_metrics_cleanup_total',
                    deleted,
                    {'days_threshold': str(days)}
                )

            return deleted
        except SQLAlchemyError as e:
            db.session.rollback()
            if hasattr(current_app, 'logger'):
                current_app.logger.error(f"Failed to clean up old metrics: {str(e)}")
            return 0

    def __repr__(self) -> str:
        """
        String representation of the CloudMetric.

        Returns:
            str: String representation
        """
        return f"<CloudMetric id={self.id} resource_id={self.resource_id} metric={self.metric_name} value={self.value}>"
