"""
Alert correlation module for detecting related alerts.

This module provides functionality to analyze and correlate alerts,
helping operators identify related issues and reduce alert noise by
grouping similar alerts that might have the same root cause.
"""

from typing import List, Dict, Any, Tuple, Optional, Set, Union
from datetime import datetime, timedelta
import logging
from sqlalchemy import and_, or_, desc, func, case
from sqlalchemy.exc import SQLAlchemyError

from flask import current_app, has_request_context, g
from extensions import db, metrics
from models.alerts.alert import Alert
from core.security import log_security_event
from core.utils.validation import sanitize_html

logger = logging.getLogger(__name__)

class AlertCorrelation:
    """
    Alert correlation functionality for identifying related alerts.

    This class provides methods for correlating alerts based on various
    factors like time proximity, resource relationships, service dependencies,
    and common attributes.
    """

    # Constants for correlation metrics
    METRIC_CORRELATION_FOUND = 'alert.correlation.found'
    METRIC_CORRELATION_PROCESSED = 'alert.correlation.processed'
    METRIC_GROUP_CREATED = 'alert.group.created'

    # Event type for audit logging
    EVENT_CORRELATION_FOUND = 'alert.correlation_found'

    # Correlation strength categories
    CORRELATION_STRONG = 'strong'     # Score 80-100
    CORRELATION_MEDIUM = 'medium'     # Score 60-79
    CORRELATION_WEAK = 'weak'         # Score 50-59

    def __init__(self, correlation_window_minutes: int = 30,
                 max_alerts: int = 50, min_correlation_score: int = 50):
        """
        Initialize correlation engine with configuration parameters.

        Args:
            correlation_window_minutes: Time window to look for related alerts in minutes
            max_alerts: Maximum number of alerts to analyze
            min_correlation_score: Minimum score to consider alerts correlated (0-100)
        """
        # Get config from app if available, otherwise use defaults
        if has_request_context() and current_app:
            self.correlation_window_minutes = current_app.config.get(
                'ALERT_CORRELATION_WINDOW_MINUTES', correlation_window_minutes
            )
            self.max_alerts = current_app.config.get('ALERT_MAX_CORRELATIONS', max_alerts)
            self.min_correlation_score = current_app.config.get(
                'ALERT_MIN_CORRELATION_SCORE', min_correlation_score
            )
        else:
            self.correlation_window_minutes = correlation_window_minutes
            self.max_alerts = max_alerts
            self.min_correlation_score = min_correlation_score

    def find_correlated_alerts(self, alert_id: int) -> List[Dict[str, Any]]:
        """
        Find alerts correlated to the given alert.

        Args:
            alert_id: ID of the alert to find correlations for

        Returns:
            List of dictionaries with correlated alert info and correlation scores
        """
        try:
            # Get the source alert
            alert = Alert.query.get(alert_id)
            if not alert:
                logger.warning(f"Alert ID {alert_id} not found for correlation")
                return []

            # Define time window for correlation
            time_threshold = alert.created_at - timedelta(minutes=self.correlation_window_minutes)
            future_threshold = alert.created_at + timedelta(minutes=self.correlation_window_minutes)

            # Find potential candidates within the time window
            candidates = Alert.query.filter(
                Alert.id != alert_id,
                Alert.created_at >= time_threshold,
                Alert.created_at <= future_threshold,
                Alert.environment == alert.environment
            ).order_by(desc(Alert.created_at)).limit(self.max_alerts).all()

            # Calculate correlation scores
            correlated_alerts = []
            for candidate in candidates:
                score = self._calculate_correlation_score(alert, candidate)
                if score >= self.min_correlation_score:
                    correlated_alerts.append({
                        'alert': candidate.to_dict(),
                        'correlation_score': score,
                        'correlation_strength': self._get_correlation_strength(score),
                        'correlation_factors': self._get_correlation_factors(alert, candidate)
                    })

                    # Track metric for each correlation found
                    if metrics:
                        try:
                            metrics.increment(self.METRIC_CORRELATION_FOUND, 1, {
                                'environment': alert.environment,
                                'source_severity': alert.severity,
                                'target_severity': candidate.severity,
                                'correlation_strength': self._get_correlation_strength(score)
                            })
                        except Exception as e:
                            logger.debug(f"Failed to record correlation metrics: {e}")

            # Log high-value correlations (strong correlation with high severity alerts)
            if any(c['correlation_strength'] == self.CORRELATION_STRONG and
                   c['alert'].get('severity') in ['critical', 'high']
                   for c in correlated_alerts):
                try:
                    log_security_event(
                        event_type=self.EVENT_CORRELATION_FOUND,
                        description=f"Strong correlation detected for alert ID {alert_id}",
                        severity="info",
                        details={
                            'alert_id': alert_id,
                            'service_name': alert.service_name,
                            'correlated_count': len(correlated_alerts),
                            'correlation_strengths': [c['correlation_strength'] for c in correlated_alerts]
                        }
                    )
                except Exception as e:
                    logger.debug(f"Failed to log correlation event: {e}")

            # Sort by correlation score descending
            return sorted(correlated_alerts, key=lambda x: x['correlation_score'], reverse=True)

        except SQLAlchemyError as e:
            logger.error(f"Database error during alert correlation: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error during alert correlation: {str(e)}")
            return []
        finally:
            # Track processing metric regardless of outcome
            if metrics:
                try:
                    metrics.increment(self.METRIC_CORRELATION_PROCESSED, 1)
                except Exception:
                    pass

    def _calculate_correlation_score(self, alert1: Alert, alert2: Alert) -> int:
        """
        Calculate correlation score between two alerts.

        Args:
            alert1: First alert
            alert2: Second alert

        Returns:
            Correlation score (0-100)
        """
        score = 0

        # Same service is a strong indicator
        if alert1.service_name == alert2.service_name:
            score += 30

        # Same resource is a very strong indicator
        if alert1.resource_id and alert1.resource_id == alert2.resource_id:
            score += 40

        # Same alert type increases correlation likelihood
        if alert1.alert_type == alert2.alert_type:
            score += 20

        # Same region increases correlation
        if alert1.region and alert1.region == alert2.region:
            score += 10

        # Related services from configuration
        related_services = current_app.config.get('RELATED_SERVICES', {}) if has_request_context() else {}
        if alert1.service_name in related_services.get(alert2.service_name, []):
            score += 15

        # Severity relationship (alerts of similar severity are more likely related)
        severity_map = {'critical': 4, 'high': 3, 'warning': 2, 'info': 1}
        severity1 = severity_map.get(alert1.severity, 0)
        severity2 = severity_map.get(alert2.severity, 0)
        if abs(severity1 - severity2) <= 1:  # Adjacent severity levels
            score += 10

        # Time proximity factor (closer in time = higher score)
        time_diff = abs((alert1.created_at - alert2.created_at).total_seconds())
        time_factor = max(0, 1 - (time_diff / (self.correlation_window_minutes * 60)))
        score += int(time_factor * 20)

        # Common values in details
        if alert1.details and alert2.details:
            common_keys = set(alert1.details.keys()) & set(alert2.details.keys())
            detail_score = 0
            for key in common_keys:
                if alert1.details[key] == alert2.details[key]:
                    detail_score += 5  # Up to 5 points per matching detail field
                    # Extra points for matching hostname or instance ID
                    if key in ['host', 'hostname', 'instance_id', 'node_name']:
                        detail_score += 10
            score += min(detail_score, 25)  # Cap detail matching at 25 points

        # Cap the score at 100
        return min(score, 100)

    def _get_correlation_factors(self, alert1: Alert, alert2: Alert) -> List[str]:
        """
        Get human-readable factors that contribute to correlation.

        Args:
            alert1: First alert
            alert2: Second alert

        Returns:
            List of correlation factor descriptions
        """
        factors = []

        # Check various correlation factors
        if alert1.service_name == alert2.service_name:
            factors.append(f"Same service: {alert1.service_name}")

        if alert1.resource_id and alert1.resource_id == alert2.resource_id:
            factors.append(f"Same resource: {alert1.resource_id}")

        if alert1.alert_type == alert2.alert_type:
            factors.append(f"Same alert type: {alert1.alert_type}")

        if alert1.region and alert1.region == alert2.region:
            factors.append(f"Same region: {alert1.region}")

        if alert1.severity == alert2.severity:
            factors.append(f"Same severity: {alert1.severity}")

        time_diff = abs((alert1.created_at - alert2.created_at).total_seconds())
        if time_diff < 60:  # Within a minute
            factors.append(f"Occurred {int(time_diff)} seconds apart")
        elif time_diff < 3600:  # Within an hour
            factors.append(f"Occurred {int(time_diff/60)} minutes apart")
        else:  # More than an hour
            factors.append(f"Occurred {int(time_diff/3600)} hours apart")

        # Check related services from configuration
        related_services = current_app.config.get('RELATED_SERVICES', {}) if has_request_context() else {}
        if alert1.service_name in related_services.get(alert2.service_name, []):
            factors.append(f"Related services: {alert1.service_name} and {alert2.service_name}")

        # Check for common detailed attributes
        if alert1.details and alert2.details:
            common_keys = set(alert1.details.keys()) & set(alert2.details.keys())
            common_values = [k for k in common_keys if alert1.details[k] == alert2.details[k]]
            if common_values:
                if len(common_values) <= 3:
                    factors.append(f"Shared attributes: {', '.join(common_values)}")
                else:
                    factors.append(f"Shared {len(common_values)} attributes including: {', '.join(common_values[:3])}...")

        return factors

    def _get_correlation_strength(self, score: int) -> str:
        """
        Get correlation strength category based on score.

        Args:
            score: Correlation score (0-100)

        Returns:
            Correlation strength category
        """
        if score >= 80:
            return self.CORRELATION_STRONG
        elif score >= 60:
            return self.CORRELATION_MEDIUM
        else:
            return self.CORRELATION_WEAK

    @staticmethod
    def group_alerts_by_similarity(alerts: List[Alert]) -> List[List[Dict[str, Any]]]:
        """
        Group a list of alerts into clusters based on similarity.

        Args:
            alerts: List of Alert objects to group

        Returns:
            List of alert groups, each group is a list of alert dictionaries
        """
        try:
            if not alerts:
                return []

            correlation_engine = AlertCorrelation()
            processed = set()
            groups = []

            # Sort alerts by severity and time (critical & recent first)
            sorted_alerts = sorted(
                alerts,
                key=lambda a: (
                    -{'critical': 4, 'high': 3, 'warning': 2, 'info': 1}.get(a.severity, 0),
                    -int(a.created_at.timestamp())
                )
            )

            for alert in sorted_alerts:
                if alert.id in processed:
                    continue

                # Start a new group with this alert
                current_group = [alert.to_dict()]
                processed.add(alert.id)

                # Find alerts correlated to this one
                correlated = correlation_engine.find_correlated_alerts(alert.id)
                for item in correlated:
                    related_alert_id = item['alert']['id']
                    if related_alert_id not in processed:
                        current_group.append(item['alert'])
                        processed.add(related_alert_id)

                groups.append(current_group)

                # Track metrics for group creation if available
                if metrics:
                    try:
                        metrics.increment(correlation_engine.METRIC_GROUP_CREATED, 1, {
                            'group_size': len(current_group),
                            'environment': alert.environment,
                            'primary_severity': alert.severity
                        })
                    except Exception:
                        pass

            return groups

        except Exception as e:
            logger.error(f"Error grouping alerts: {str(e)}")
            return [[alert.to_dict() for alert in alerts]]  # Return ungrouped as fallback

    @staticmethod
    def update_alert_with_correlations(alert_id: int) -> bool:
        """
        Update an alert with its correlation information.

        Args:
            alert_id: ID of the alert to update

        Returns:
            Bool indicating success
        """
        try:
            alert = Alert.query.get(alert_id)
            if not alert:
                logger.warning(f"Alert ID {alert_id} not found for correlation update")
                return False

            correlation_engine = AlertCorrelation()
            correlated_alerts = correlation_engine.find_correlated_alerts(alert_id)

            # Extract just the IDs for storage
            correlation_ids = [item['alert']['id'] for item in correlated_alerts]
            correlation_strengths = {
                item['alert']['id']: item['correlation_strength']
                for item in correlated_alerts
            }

            # Update the alert details with correlation info
            details = alert.details or {}
            details['correlated_alerts'] = correlation_ids
            details['correlation_strengths'] = correlation_strengths
            details['correlation_updated_at'] = datetime.now().isoformat()
            details['correlation_count'] = len(correlation_ids)

            return alert.update_details(details)

        except Exception as e:
            logger.error(f"Error updating alert correlations: {str(e)}")
            return False

    @staticmethod
    def find_root_cause_alert(alert_ids: List[int]) -> Optional[Dict[str, Any]]:
        """
        Attempt to identify the root cause alert from a group of correlated alerts.

        Args:
            alert_ids: List of alert IDs that are correlated

        Returns:
            Dictionary with root cause alert information or None if not found
        """
        try:
            if not alert_ids:
                return None

            # Get all alerts in the group
            alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all()
            if not alerts:
                return None

            # Apply heuristics to find root cause:
            # 1. First, check for alerts that occurred earliest
            # 2. Among those, prioritize by severity
            # 3. Among equal severity, prioritize infrastructure over applications

            # First, get the earliest alerts (within 60 second window)
            sorted_by_time = sorted(alerts, key=lambda a: a.created_at)
            earliest_time = sorted_by_time[0].created_at
            earliest_window = earliest_time + timedelta(seconds=60)
            earliest_alerts = [a for a in alerts if a.created_at <= earliest_window]

            # Among earliest, get highest severity
            severity_rank = {'critical': 4, 'high': 3, 'warning': 2, 'info': 1}
            highest_severity = max(earliest_alerts, key=lambda a: severity_rank.get(a.severity, 0))
            candidates = [a for a in earliest_alerts
                         if severity_rank.get(a.severity, 0) == severity_rank.get(highest_severity.severity, 0)]

            # Among equal severity, prioritize infrastructure services over applications
            infra_services = current_app.config.get('INFRASTRUCTURE_SERVICES',
                                                  ['network', 'storage', 'database', 'compute']) \
                             if has_request_context() else []

            for alert in candidates:
                if any(service in alert.service_name.lower() for service in infra_services):
                    # Convert to dict with root cause flag
                    result = alert.to_dict()
                    result['is_root_cause'] = True
                    result['root_cause_confidence'] = 'high'
                    return result

            # If no infrastructure services, just pick the earliest with highest severity
            result = candidates[0].to_dict()
            result['is_root_cause'] = True
            result['root_cause_confidence'] = 'medium'
            return result

        except Exception as e:
            logger.error(f"Error finding root cause alert: {str(e)}")
            return None

    @staticmethod
    def bulk_correlate_alerts(alert_ids: List[int]) -> Dict[str, Any]:
        """
        Perform correlation analysis on multiple alerts and create alert groups.

        Args:
            alert_ids: List of alert IDs to correlate

        Returns:
            Dictionary with correlation results and groups
        """
        try:
            if not alert_ids:
                return {'groups': [], 'stats': {'total_alerts': 0, 'total_groups': 0}}

            # Get all alerts
            alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all()
            if not alerts:
                return {'groups': [], 'stats': {'total_alerts': 0, 'total_groups': 0}}

            # Group by similarity
            groups = AlertCorrelation.group_alerts_by_similarity(alerts)

            # For each group, find potential root cause
            enriched_groups = []
            for group in groups:
                # Skip empty groups
                if not group:
                    continue

                # Get alert IDs in this group
                group_ids = [alert['id'] for alert in group]

                # Find potential root cause
                root_cause = AlertCorrelation.find_root_cause_alert(group_ids)

                # Add to enriched groups
                enriched_groups.append({
                    'alerts': group,
                    'root_cause': root_cause,
                    'count': len(group),
                    'primary_service': group[0].get('service_name'),
                    'highest_severity': max(a.get('severity', 'info') for a in group),
                    'created_at': group[0].get('created_at')
                })

            # Sort groups by highest severity then size
            severity_rank = {'critical': 4, 'high': 3, 'warning': 2, 'info': 1}
            sorted_groups = sorted(
                enriched_groups,
                key=lambda g: (
                    severity_rank.get(g['highest_severity'], 0),
                    g['count']
                ),
                reverse=True
            )

            # Calculate stats
            stats = {
                'total_alerts': len(alerts),
                'total_groups': len(sorted_groups),
                'reduction_percentage': int((1 - len(sorted_groups) / max(len(alerts), 1)) * 100)
                                         if len(alerts) > 0 else 0,
                'largest_group_size': max(g['count'] for g in sorted_groups) if sorted_groups else 0
            }

            return {
                'groups': sorted_groups,
                'stats': stats
            }

        except Exception as e:
            logger.error(f"Error during bulk correlation: {str(e)}")
            return {'groups': [], 'stats': {'total_alerts': 0, 'total_groups': 0}, 'error': str(e)}
