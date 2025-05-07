#!/usr/bin/env python3
"""
User Activity Monitoring for Incident Response

This module provides tools for collecting, analyzing, and visualizing user
activity data during security incident investigations. It integrates with
the application's activity tracking systems to provide comprehensive views
of user actions before, during, and after security incidents.

The module supports timeline creation, behavioral analysis, anomaly detection,
and evidence collection to assist in identifying suspicious activity patterns.
"""

import os
import sys
import json
import logging
import hashlib
import argparse
import csv
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Union, Tuple
from dataclasses import dataclass, field, asdict

# Add parent directories to path to enable imports
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
IR_KIT_DIR = SCRIPT_DIR.parent
ADMIN_DIR = IR_KIT_DIR.parent.parent
PROJECT_ROOT = ADMIN_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Setup logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Try to import from other modules
try:
    # Import from parent toolkit
    from admin.security.incident_response_kit import (
        sanitize_incident_id,
        DEFAULT_EVIDENCE_DIR
    )
    from admin.security.incident_response_kit.collect_evidence import (
        create_evidence_directory
    )
    PARENT_IMPORTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Failed to import from parent modules: {e}")
    PARENT_IMPORTS_AVAILABLE = False

    def sanitize_incident_id(incident_id: str) -> str:
        """Fallback implementation to sanitize incident IDs."""
        return incident_id.replace('/', '-').replace('\\', '-')

    DEFAULT_EVIDENCE_DIR = "/secure/evidence"

    def create_evidence_directory(incident_id: str) -> str:
        """Fallback implementation to create evidence directory."""
        dir_path = os.path.join(DEFAULT_EVIDENCE_DIR, sanitize_incident_id(incident_id))
        os.makedirs(dir_path, exist_ok=True)
        return dir_path

# Try to import application models for direct database access
try:
    from models.auth.user_activity import UserActivity
    from models.auth.user_session import UserSession
    from models.security.login_attempt import LoginAttempt
    from core.security import cs_monitoring
    from extensions import db
    MODELS_AVAILABLE = True
    logger.debug("Application models available for direct database access")
except ImportError:
    MODELS_AVAILABLE = False
    logger.warning("Application models not available, using fallback functionality")

# Constants
class ACTIVITY_TYPES:
    """Activity type constants."""
    LOGIN = 'login'
    LOGOUT = 'logout'
    RESOURCE_ACCESS = 'resource_access'
    CONFIG_CHANGE = 'configuration_change'
    ADMIN_ACTION = 'admin_action'
    SECURITY_EVENT = 'security_event'
    ALL = ['login', 'logout', 'resource_access', 'configuration_change',
           'admin_action', 'security_event']

class DETECTION_SENSITIVITY:
    """Sensitivity levels for anomaly detection."""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'

    @staticmethod
    def get_threshold(sensitivity: str) -> float:
        """Get the numeric threshold for a given sensitivity level."""
        if sensitivity == DETECTION_SENSITIVITY.LOW:
            return 0.9  # High threshold = less sensitive (fewer anomalies detected)
        elif sensitivity == DETECTION_SENSITIVITY.HIGH:
            return 0.6  # Low threshold = more sensitive (more anomalies detected)
        else:  # MEDIUM is default
            return 0.75

class ANALYSIS_FEATURES:
    """Feature types used in behavioral analysis."""
    TIME_PATTERN = 'time_pattern'
    RESOURCE_PATTERN = 'resource_pattern'
    VOLUME_PATTERN = 'volume_pattern'
    LOCATION_PATTERN = 'location_pattern'
    ALL = ['time_pattern', 'resource_pattern', 'volume_pattern', 'location_pattern']

class EVIDENCE_FORMATS:
    """Supported output formats for evidence."""
    JSON = 'json'
    CSV = 'csv'
    EVTX = 'evtx'
    MARKDOWN = 'markdown'
    ALL = ['json', 'csv', 'evtx', 'markdown']

# Exceptions
class UserActivityMonitorError(Exception):
    """Base exception for user activity monitoring errors."""
    pass

class ActivityDataNotFoundError(UserActivityMonitorError):
    """Exception raised when no activity data is found."""
    pass

class EvidenceExportError(UserActivityMonitorError):
    """Exception raised when evidence export fails."""
    pass

class InvalidParameterError(UserActivityMonitorError):
    """Exception raised when an invalid parameter is provided."""
    pass

# Helper functions
def _normalize_time_period(time_period: Union[timedelta, int, float, str]) -> timedelta:
    """
    Convert various time period formats to a timedelta object.

    Args:
        time_period: Time period as timedelta, hours (int/float), or string with suffix (e.g., '24h', '7d')

    Returns:
        timedelta: Normalized time period

    Raises:
        InvalidParameterError: If the time period format is invalid
    """
    if isinstance(time_period, timedelta):
        return time_period
    elif isinstance(time_period, (int, float)):
        return timedelta(hours=time_period)
    elif isinstance(time_period, str):
        try:
            # Parse strings like "24h", "7d"
            if time_period.endswith('h'):
                return timedelta(hours=float(time_period[:-1]))
            elif time_period.endswith('d'):
                return timedelta(days=float(time_period[:-1]))
            elif time_period.endswith('m'):
                return timedelta(minutes=float(time_period[:-1]))
            else:
                # Assume hours if no suffix
                return timedelta(hours=float(time_period))
        except ValueError:
            raise InvalidParameterError(f"Invalid time period format: {time_period}")
    else:
        raise InvalidParameterError(f"Unsupported time period type: {type(time_period)}")

def _get_user_activities(user_id: str,
                        time_period: Union[timedelta, int, float, str] = 24,
                        activity_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Retrieve user activity data from the database.

    Args:
        user_id: User identifier
        time_period: Time period to look back
        activity_types: Types of activities to collect

    Returns:
        List of activity records
    """
    period = _normalize_time_period(time_period)
    start_time = datetime.now(timezone.utc) - period

    if MODELS_AVAILABLE:
        try:
            # Use direct database access if available
            query = UserActivity.query.filter(
                UserActivity.created_at >= start_time
            )

            # Filter by user ID (either numeric or string)
            if user_id.isdigit():
                query = query.filter(UserActivity.user_id == int(user_id))
            else:
                # Join with users table to filter by username
                query = query.join(
                    UserActivity.user
                ).filter(
                    UserActivity.user.has(username=user_id)
                )

            # Filter by activity types if specified
            if activity_types:
                query = query.filter(UserActivity.activity_type.in_(activity_types))

            # Execute query and convert to dictionaries
            activities = [activity.to_dict() for activity in query.all()]
            logger.info(f"Retrieved {len(activities)} activities for user {user_id}")
            return activities
        except Exception as e:
            logger.warning(f"Error querying database directly: {e}. Will try fallback method.")

    # Fallback approach: try to use core security monitoring module
    try:
        if MODELS_AVAILABLE and hasattr(cs_monitoring, 'get_user_activities'):
            activities = cs_monitoring.get_user_activities(
                user_id=user_id,
                start_time=start_time,
                activity_types=activity_types
            )
            return activities
    except Exception as e:
        logger.warning(f"Error using security monitoring module: {e}")

    # If we get here, we need to read from log files directly
    logger.warning("Using log file parsing as fallback method for activity data")
    return _parse_activity_logs_for_user(user_id, start_time)

def _parse_activity_logs_for_user(user_id: str, start_time: datetime) -> List[Dict[str, Any]]:
    """
    Parse system logs to extract user activity data as a fallback method.

    Args:
        user_id: User identifier
        start_time: Start time for activity search

    Returns:
        List of parsed activity records
    """
    activities = []

    # Common log paths to search
    log_paths = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/var/log/cloud-platform/access.log",
        "/var/log/application.log",
        # App-specific logs
        os.path.join(str(PROJECT_ROOT), "logs", "user_activity.log"),
        os.path.join(str(PROJECT_ROOT), "logs", "app.log"),
    ]

    # Add instance-specific logs if they exist
    instance_log_dir = os.path.join(str(PROJECT_ROOT), "instance", "logs")
    if os.path.exists(instance_log_dir):
        for filename in os.listdir(instance_log_dir):
            if filename.endswith('.log'):
                log_paths.append(os.path.join(instance_log_dir, filename))

    for log_path in log_paths:
        if not os.path.exists(log_path):
            continue

        try:
            with open(log_path, 'r', errors='ignore') as f:
                for line in f:
                    # Basic log parsing logic - look for user ID and timestamps
                    if user_id in line:
                        # Try to extract timestamp using common formats
                        timestamp_match = re.search(r'\[(.*?)\]|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
                        if timestamp_match:
                            timestamp_str = timestamp_match.group(0).strip('[]')
                            try:
                                # Try different timestamp formats
                                for fmt in ('%Y-%m-%d %H:%M:%S', '%d/%b/%Y:%H:%M:%S %z'):
                                    try:
                                        log_time = datetime.strptime(timestamp_str, fmt)
                                        break
                                    except ValueError:
                                        continue

                                # Check if log is within time range
                                if log_time >= start_time:
                                    # Infer activity type
                                    activity_type = 'resource_access'  # default
                                    if 'login' in line.lower():
                                        activity_type = 'login'
                                    elif 'logout' in line.lower():
                                        activity_type = 'logout'
                                    elif 'admin' in line.lower():
                                        activity_type = 'admin_action'
                                    elif 'change' in line.lower() or 'update' in line.lower():
                                        activity_type = 'configuration_change'

                                    # Create activity record
                                    activity = {
                                        'user_id': user_id,
                                        'activity_type': activity_type,
                                        'created_at': log_time.isoformat(),
                                        'source_log': log_path,
                                        'raw_log': line.strip(),
                                    }

                                    # Extract additional data if possible
                                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                                    if ip_match:
                                        activity['ip_address'] = ip_match.group(0)

                                    # Add to activities list
                                    activities.append(activity)
                            except Exception as parse_error:
                                logger.debug(f"Error parsing timestamp: {parse_error}")
        except Exception as e:
            logger.warning(f"Error reading log file {log_path}: {e}")

    logger.info(f"Extracted {len(activities)} activities for user {user_id} from logs")
    return activities

def _calculate_activity_hash(activity: Dict[str, Any]) -> str:
    """
    Calculate a unique hash for an activity record to verify integrity.

    Args:
        activity: Activity data dictionary

    Returns:
        str: SHA-256 hash of the activity
    """
    # Extract the key fields in a deterministic order
    key_fields = [
        str(activity.get('id', '')),
        str(activity.get('user_id', '')),
        str(activity.get('activity_type', '')),
        str(activity.get('created_at', '')),
        str(activity.get('resource_type', '')),
        str(activity.get('resource_id', '')),
        str(activity.get('action', '')),
        str(activity.get('status', '')),
        str(activity.get('ip_address', ''))
    ]

    # Calculate hash
    hash_input = '|'.join(key_fields)
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

def _export_to_format(data: Dict[str, Any], format: str, output_path: str) -> str:
    """
    Export data to the specified format.

    Args:
        data: Data to export
        format: Output format (json, csv, markdown)
        output_path: Path to save the output file

    Returns:
        str: Path to the output file

    Raises:
        EvidenceExportError: If export fails
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if format == EVIDENCE_FORMATS.JSON:
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)

        elif format == EVIDENCE_FORMATS.CSV:
            if 'activities' in data and isinstance(data['activities'], list):
                with open(output_path, 'w', newline='') as f:
                    if data['activities']:
                        fieldnames = data['activities'][0].keys()
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        for activity in data['activities']:
                            # Convert non-string values to strings
                            row = {k: str(v) if not isinstance(v, (str, int, float)) else v
                                  for k, v in activity.items()}
                            writer.writerow(row)
            else:
                # Handle non-activity data
                with open(output_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    for key, value in data.items():
                        if isinstance(value, list):
                            writer.writerow([key, f"{len(value)} items"])
                            for i, item in enumerate(value):
                                if isinstance(item, dict):
                                    for k, v in item.items():
                                        writer.writerow([f"{key}[{i}].{k}", v])
                                else:
                                    writer.writerow([f"{key}[{i}]", item])
                        elif isinstance(value, dict):
                            for k, v in value.items():
                                writer.writerow([f"{key}.{k}", v])
                        else:
                            writer.writerow([key, value])

        elif format == EVIDENCE_FORMATS.MARKDOWN:
            with open(output_path, 'w') as f:
                f.write(f"# User Activity Report\n\n")
                f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")

                if 'metadata' in data:
                    f.write("## Metadata\n\n")
                    for key, value in data['metadata'].items():
                        f.write(f"- **{key}**: {value}\n")
                    f.write("\n")

                if 'activities' in data and data['activities']:
                    f.write("## Activities\n\n")

                    # Create table header based on first activity's keys
                    keys = ['timestamp', 'activity_type', 'resource_type', 'resource_id', 'action', 'status']
                    header = "| " + " | ".join(keys) + " |"
                    separator = "| " + " | ".join(["---" for _ in keys]) + " |"
                    f.write(header + "\n")
                    f.write(separator + "\n")

                    # Write rows
                    for activity in data['activities']:
                        row = []
                        for key in keys:
                            value = activity.get('created_at' if key == 'timestamp' else key, '')
                            row.append(str(value))
                        f.write("| " + " | ".join(row) + " |\n")

                    f.write("\n")

                if 'findings' in data and data['findings']:
                    f.write("## Findings\n\n")
                    for finding in data['findings']:
                        f.write(f"### {finding.get('title', 'Unnamed Finding')}\n\n")
                        f.write(f"**Severity**: {finding.get('severity', 'Unknown')}\n\n")
                        f.write(f"{finding.get('description', 'No description')}\n\n")
                        if 'details' in finding and finding['details']:
                            f.write("**Details**:\n\n")
                            for k, v in finding['details'].items():
                                f.write(f"- {k}: {v}\n")
                        f.write("\n---\n\n")

        elif format == EVIDENCE_FORMATS.EVTX:
            # EVTX format requires Windows Event Log API, use JSON as fallback
            logger.warning("EVTX format not supported in this environment, using JSON instead")
            json_path = output_path.replace('.evtx', '.json')
            with open(json_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            output_path = json_path

        else:
            raise ValueError(f"Unsupported format: {format}")

        return output_path

    except Exception as e:
        logger.error(f"Failed to export data: {e}")
        raise EvidenceExportError(f"Failed to export data: {str(e)}")

def _create_chain_of_custody(evidence_path: str, user_id: str, analyst: str) -> str:
    """
    Create a chain of custody document for the evidence.

    Args:
        evidence_path: Path to the evidence file
        user_id: User ID the evidence relates to
        analyst: Name of the analyst collecting the evidence

    Returns:
        str: Path to the chain of custody document
    """
    custody_path = os.path.join(
        os.path.dirname(evidence_path),
        f"{os.path.basename(evidence_path)}.custody.txt"
    )

    try:
        # Calculate file hash for verification
        with open(evidence_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        with open(custody_path, 'w') as f:
            f.write("CHAIN OF CUSTODY DOCUMENTATION\n")
            f.write("==============================\n\n")
            f.write(f"Evidence File: {os.path.basename(evidence_path)}\n")
            f.write(f"Creation Date: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"Subject User ID: {user_id}\n")
            f.write(f"Collecting Analyst: {analyst}\n")
            f.write(f"SHA-256 Hash: {file_hash}\n\n")
            f.write("Custody Events:\n")
            f.write("--------------\n")
            f.write(f"1. {datetime.now(timezone.utc).isoformat()} - Initial collection by {analyst}\n")

        logger.info(f"Created chain of custody document: {custody_path}")
        return custody_path

    except Exception as e:
        logger.error(f"Failed to create chain of custody document: {e}")
        return None

# Class Definitions
@dataclass
class UserActivityCollection:
    """Container for collected user activity data with integrity verification."""
    user_id: str
    collection_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    activities: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    _integrity_hashes: Dict[int, str] = field(default_factory=dict)

    def add_activity(self, activity_data: Dict[str, Any]) -> None:
        """
        Add an activity event to the collection.

        Args:
            activity_data: Activity data to add
        """
        # Calculate integrity hash
        index = len(self.activities)
        self._integrity_hashes[index] = _calculate_activity_hash(activity_data)

        # Add to collection
        self.activities.append(activity_data)

    def filter(self, criteria: Dict[str, Any]) -> 'UserActivityCollection':
        """
        Filter activities based on criteria.

        Args:
            criteria: Dictionary of field:value pairs to filter on

        Returns:
            A new filtered UserActivityCollection
        """
        filtered_collection = UserActivityCollection(user_id=self.user_id)
        filtered_collection.metadata = self.metadata.copy()

        for activity in self.activities:
            matches = True
            for key, value in criteria.items():
                if key not in activity or activity[key] != value:
                    matches = False
                    break

            if matches:
                filtered_collection.add_activity(activity)

        return filtered_collection

    def get_timeline(self) -> 'ActivityTimeline':
        """
        Generate chronological timeline from activities.

        Returns:
            ActivityTimeline object
        """
        timeline = ActivityTimeline(user_id=self.user_id)

        for activity in sorted(self.activities, key=lambda x: x.get('created_at', '')):
            timeline.add_event(activity)

        return timeline

    def export(self, format: str, output_path: str) -> str:
        """
        Export data in specified format.

        Args:
            format: Output format
            output_path: Path to save the output

        Returns:
            Path to the exported file
        """
        data = {
            "metadata": self.metadata,
            "activities": self.activities,
            "collection_info": {
                "collection_time": self.collection_time.isoformat(),
                "activity_count": len(self.activities)
            }
        }

        return _export_to_format(data, format, output_path)

    def verify_integrity(self) -> bool:
        """
        Verify data hasn't been modified.

        Returns:
            bool: True if integrity is intact, False otherwise
        """
        for index, activity in enumerate(self.activities):
            if index not in self._integrity_hashes:
                logger.error(f"No integrity hash found for activity {index}")
                return False

            current_hash = _calculate_activity_hash(activity)
            if current_hash != self._integrity_hashes[index]:
                logger.error(f"Integrity check failed for activity {index}")
                return False

        return True

@dataclass
class UserBehaviorAnalysis:
    """Analysis engine for user behavior patterns."""
    user_id: str
    baseline: Dict[str, Any] = field(default_factory=dict)
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)

    def establish_baseline(self, days: int = 30) -> Dict[str, Any]:
        """
        Create baseline of normal behavior.

        Args:
            days: Number of days to include in baseline

        Returns:
            Baseline data dictionary
        """
        # Get historical activity
        activities = _get_user_activities(self.user_id, days)

        if not activities:
            logger.warning(f"No activities found for user {self.user_id} in the past {days} days")
            return {}

        # Analyze time patterns
        hour_distribution = [0] * 24
        day_distribution = [0] * 7
        for activity in activities:
            try:
                timestamp = activity.get('created_at')
                if not timestamp:
                    continue

                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp

                hour_distribution[dt.hour] += 1
                day_distribution[dt.weekday()] += 1
            except (ValueError, TypeError):
                continue

        # Analyze resource access patterns
        resource_counts = {}
        for activity in activities:
            resource_type = activity.get('resource_type')
            resource_id = activity.get('resource_id')

            if not resource_type:
                continue

            # Create a key combining type and ID if both exist
            resource_key = f"{resource_type}:{resource_id}" if resource_id else resource_type

            if resource_key not in resource_counts:
                resource_counts[resource_key] = 0

            resource_counts[resource_key] += 1

        # Calculate activity volume patterns
        activity_by_type = {}
        for activity in activities:
            activity_type = activity.get('activity_type')
            if not activity_type:
                continue

            if activity_type not in activity_by_type:
                activity_by_type[activity_type] = 0

            activity_by_type[activity_type] += 1

        # Build location patterns
        locations = {}
        for activity in activities:
            location = activity.get('geo_location') or activity.get('ip_address')
            if not location:
                continue

            if location not in locations:
                locations[location] = 0

            locations[location] += 1

        # Create the baseline
        self.baseline = {
            'user_id': self.user_id,
            'baseline_period_days': days,
            'activity_count': len(activities),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'time_patterns': {
                'hour_distribution': hour_distribution,
                'day_distribution': day_distribution,
                'active_hours': [i for i, count in enumerate(hour_distribution) if count > 0],
                'peak_hour': hour_distribution.index(max(hour_distribution)),
                'inactive_hours': [i for i, count in enumerate(hour_distribution) if count == 0]
            },
            'resource_patterns': {
                'resource_counts': resource_counts,
                'top_resources': sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            },
            'volume_patterns': {
                'activity_by_type': activity_by_type,
                'average_daily_activities': len(activities) / days if days > 0 else 0
            },
            'location_patterns': {
                'locations': locations,
                'primary_location': max(locations.items(), key=lambda x: x[1])[0] if locations else None,
                'location_count': len(locations)
            }
        }

        logger.info(f"Established baseline for user {self.user_id} covering {days} days and {len(activities)} activities")
        return self.baseline

    def detect_anomalies(self, activities: List[Dict[str, Any]], sensitivity: str = DETECTION_SENSITIVITY.MEDIUM) -> List[Dict[str, Any]]:
        """
        Detect deviations from baseline.

        Args:
            activities: List of activities to analyze
            sensitivity: Detection sensitivity level

        Returns:
            List of detected anomalies
        """
        if not self.baseline:
            raise ValueError("Baseline not established. Call establish_baseline() first.")

        if not activities:
            logger.warning("No activities provided for anomaly detection")
            return []

        # Get threshold based on sensitivity
        threshold = DETECTION_SENSITIVITY.get_threshold(sensitivity)

        # Reset anomalies
        self.anomalies = []

        # Time pattern anomalies
        baseline_active_hours = set(self.baseline['time_patterns']['active_hours'])
        baseline_inactive_hours = set(self.baseline['time_patterns']['inactive_hours'])

        for activity in activities:
            try:
                # Parse timestamp
                timestamp = activity.get('created_at')
                if not timestamp:
                    continue

                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp

                # Check for activity during typically inactive hours
                if dt.hour in baseline_inactive_hours:
                    self.anomalies.append({
                        'type': 'time_anomaly',
                        'subtype': 'inactive_hour',
                        'severity': 'high',
                        'activity_id': activity.get('id'),
                        'timestamp': timestamp,
                        'description': f"Activity during typically inactive hour ({dt.hour}:00)",
                        'details': {
                            'hour': dt.hour,
                            'baseline_inactive_hours': list(baseline_inactive_hours)
                        }
                    })
            except (ValueError, TypeError) as e:
                logger.debug(f"Error parsing timestamp: {e}")
                continue

        # Resource pattern anomalies
        baseline_resources = set(self.baseline['resource_patterns']['resource_counts'].keys())
        activity_resources = {}

        for activity in activities:
            resource_type = activity.get('resource_type')
            resource_id = activity.get('resource_id')

            if not resource_type:
                continue

            resource_key = f"{resource_type}:{resource_id}" if resource_id else resource_type

            if resource_key not in activity_resources:
                activity_resources[resource_key] = 0

            activity_resources[resource_key] += 1

            # Check for access to new resources
            if resource_key not in baseline_resources:
                self.anomalies.append({
                    'type': 'resource_anomaly',
                    'subtype': 'new_resource',
                    'severity': 'medium',
                    'activity_id': activity.get('id'),
                    'timestamp': activity.get('created_at'),
                    'description': f"Access to previously unused resource: {resource_key}",
                    'details': {
                        'resource_key': resource_key,
                        'resource_type': resource_type,
                        'resource_id': resource_id
                    }
                })

        # Volume anomalies
        baseline_avg_daily = self.baseline['volume_patterns'].get('average_daily_activities', 0)

        # Determine the time span of the activities
        timestamps = [a.get('created_at') for a in activities if a.get('created_at')]
        if len(timestamps) > 1:
            try:
                # Parse to datetime objects if they're strings
                if isinstance(timestamps[0], str):
                    parsed_timestamps = [datetime.fromisoformat(t.replace('Z', '+00:00')) for t in timestamps]
                else:
                    parsed_timestamps = timestamps

                min_time = min(parsed_timestamps)
                max_time = max(parsed_timestamps)
                time_span_days = (max_time - min_time).total_seconds() / (24 * 3600)

                if time_span_days > 0:
                    current_daily_rate = len(activities) / time_span_days

                    # Check for unusually high activity volume
                    if baseline_avg_daily > 0 and current_daily_rate > (baseline_avg_daily * 3):
                        self.anomalies.append({
                            'type': 'volume_anomaly',
                            'subtype': 'high_activity_rate',
                            'severity': 'high',
                            'timestamp': max_time.isoformat() if isinstance(max_time, datetime) else max_time,
                            'description': f"Unusually high activity rate detected: {current_daily_rate:.1f} activities/day vs baseline {baseline_avg_daily:.1f}",
                            'details': {
                                'current_rate': current_daily_rate,
                                'baseline_rate': baseline_avg_daily,
                                'ratio': current_daily_rate / baseline_avg_daily if baseline_avg_daily > 0 else float('inf'),
                                'activity_count': len(activities),
                                'time_span_days': time_span_days
                            }
                        })
            except (ValueError, TypeError) as e:
                logger.debug(f"Error analyzing activity timestamps: {e}")

        # Location anomalies
        baseline_locations = set(self.baseline['location_patterns'].get('locations', {}).keys())
        primary_location = self.baseline['location_patterns'].get('primary_location')

        for activity in activities:
            location = activity.get('geo_location') or activity.get('ip_address')
            if not location:
                continue

            # Check for new locations
            if location not in baseline_locations:
                self.anomalies.append({
                    'type': 'location_anomaly',
                    'subtype': 'new_location',
                    'severity': 'high',
                    'activity_id': activity.get('id'),
                    'timestamp': activity.get('created_at'),
                    'description': f"Activity from new location: {location}",
                    'details': {
                        'location': location,
                        'primary_location': primary_location
                    }
                })

        # Store analysis results
        self.analysis_results = {
            'user_id': self.user_id,
            'analysis_time': datetime.now(timezone.utc).isoformat(),
            'activities_analyzed': len(activities),
            'anomalies_detected': len(self.anomalies),
            'sensitivity': sensitivity,
            'threshold': threshold
        }

        logger.info(f"Detected {len(self.anomalies)} anomalies from {len(activities)} activities")
        return self.anomalies

    def score_risk(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate risk scores for events.

        Args:
            events: List of events to score

        Returns:
            Dictionary with risk scores
        """
        if not events:
            return {"overall_score": 0, "factors": {}, "events_scored": 0}

        # Initialize risk factors
        risk_factors = {
            "time_risk": 0,
            "resource_risk": 0,
            "volume_risk": 0,
            "location_risk": 0
        }

        # Count events by type
        event_types = {}
        for event in events:
            event_type = event.get('type', 'unknown')
            if event_type not in event_types:
                event_types[event_type] = 0
            event_types[event_type] += 1

            # Assign risk scores based on anomaly types and severity
            severity = event.get('severity', 'medium').lower()
            severity_multiplier = {'low': 1, 'medium': 2, 'high': 4, 'critical': 8}.get(severity, 1)

            if event_type == 'time_anomaly':
                risk_factors["time_risk"] += 10 * severity_multiplier
            elif event_type == 'resource_anomaly':
                risk_factors["resource_risk"] += 15 * severity_multiplier
            elif event_type == 'volume_anomaly':
                risk_factors["volume_risk"] += 20 * severity_multiplier
            elif event_type == 'location_anomaly':
                risk_factors["location_risk"] += 25 * severity_multiplier

        # Calculate overall risk score (0-100)
        max_possible_score = 4 * 25 * 8  # 4 factors, max 25 points each, max multiplier 8
        current_score = sum(risk_factors.values())
        normalized_score = min(100, int((current_score / max_possible_score) * 100))

        return {
            "user_id": self.user_id,
            "overall_score": normalized_score,
            "risk_level": "critical" if normalized_score >= 80 else
                         "high" if normalized_score >= 60 else
                         "medium" if normalized_score >= 40 else
                         "low",
            "factors": risk_factors,
            "events_scored": len(events),
            "event_types": event_types
        }

    def generate_report(self, output_path: Optional[str] = None) -> Union[str, Dict[str, Any]]:
        """
        Create analysis report.

        Args:
            output_path: Optional path to save the report

        Returns:
            Report as dictionary or path to saved report file
        """
        # Calculate risk score
        risk_assessment = self.score_risk(self.anomalies)

        # Build report
        report = {
            "user_id": self.user_id,
            "report_time": datetime.now(timezone.utc).isoformat(),
            "baseline_info": {
                "period_days": self.baseline.get('baseline_period_days', 0),
                "activity_count": self.baseline.get('activity_count', 0),
                "generated_at": self.baseline.get('generated_at')
            },
            "analysis_results": self.analysis_results,
            "risk_assessment": risk_assessment,
            "anomalies": self.anomalies
        }

        # Save report if path provided
        if output_path:
            try:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                logger.info(f"Analysis report saved to {output_path}")
                return output_path
            except Exception as e:
                logger.error(f"Failed to save report: {e}")

        return report

    def save(self, filepath: str) -> str:
        """
        Save the behavior analysis data to file.

        Args:
            filepath: Path to save the data

        Returns:
            Path to the saved file
        """
        data = {
            "user_id": self.user_id,
            "baseline": self.baseline,
            "analysis_results": self.analysis_results,
            "saved_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"Behavior analysis data saved to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to save baseline data: {e}")
            raise EvidenceExportError(f"Failed to save baseline data: {str(e)}")

    @classmethod
    def load(cls, filepath: str) -> 'UserBehaviorAnalysis':
        """
        Load behavior analysis from file.

        Args:
            filepath: Path to the saved data file

        Returns:
            UserBehaviorAnalysis object
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            analysis = cls(user_id=data.get('user_id', ''))
            analysis.baseline = data.get('baseline', {})
            analysis.analysis_results = data.get('analysis_results', {})

            logger.info(f"Loaded behavior analysis from {filepath}")
            return analysis
        except Exception as e:
            logger.error(f"Failed to load baseline data: {e}")
            raise ValueError(f"Failed to load baseline data: {str(e)}")

    def has_critical_anomalies(self) -> bool:
        """
        Check if there are any critical anomalies.

        Returns:
            bool: True if critical anomalies exist
        """
        return any(a.get('severity') == 'critical' or a.get('severity') == 'high'
                   for a in self.anomalies)

@dataclass
class ActivityTimeline:
    """Timeline representation of user activities."""
    user_id: str
    events: List[Dict[str, Any]] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

    def add_event(self, event: Dict[str, Any]) -> None:
        """
        Add event to timeline.

        Args:
            event: Event data to add
        """
        self.events.append(event)

        # Keep events sorted by timestamp
        self.events.sort(key=lambda x: x.get('created_at', ''))

    def add_context(self, context_data: Dict[str, Any]) -> None:
        """
        Add contextual information.

        Args:
            context_data: Context data to add
        """
        self.context.update(context_data)

    def filter_by_time(self, start: datetime, end: datetime) -> 'ActivityTimeline':
        """
        Filter timeline to time range.

        Args:
            start: Start time
            end: End time

        Returns:
            Filtered timeline object
        """
        filtered_timeline = ActivityTimeline(user_id=self.user_id)
        filtered_timeline.context = self.context.copy()

        for event in self.events:
            timestamp = event.get('created_at')

            if not timestamp:
                continue

            # Parse timestamp if it's a string
            if isinstance(timestamp, str):
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except ValueError:
                    continue
            else:
                dt = timestamp

            if start <= dt <= end:
                filtered_timeline.add_event(event)

        return filtered_timeline

    def export(self, format: str = 'json', output_path: Optional[str] = None) -> Union[Dict[str, Any], str]:
        """
        Export timeline in specified format.

        Args:
            format: Output format
            output_path: Optional path to save the output

        Returns:
            Dictionary with timeline data or path to saved file
        """
        # Prepare data
        data = {
            "user_id": self.user_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(self.events),
            "context": self.context,
            "events": sorted(self.events, key=lambda x: x.get('created_at', ''))
        }

        # Return data if no output path
        if not output_path:
            return data

        # Export to file
        return _export_to_format(data, format, output_path)

# Core Functions
def collect_user_activity(
    user_id: str,
    time_period: Union[timedelta, int, float, str] = 48,
    activity_types: Optional[List[str]] = None,
    include_metadata: bool = True,
    output_dir: Optional[str] = None
) -> UserActivityCollection:
    """
    Collect and preserve user activity data.

    Args:
        user_id: User identifier
        time_period: Time period to collect (timedelta object or hours)
        activity_types: Types of activities to collect (defaults to all)
        include_metadata: Whether to include context metadata
        output_dir: Directory to save evidence files

    Returns:
        UserActivityCollection object with collected data

    Raises:
        ActivityDataNotFoundError: If no activity data could be found
    """
    logger.info(f"Collecting user activity for {user_id} over the past {time_period} period")

    # Create collection object
    collection = UserActivityCollection(user_id=user_id)

    # Get activities
    activities = _get_user_activities(user_id, time_period, activity_types)

    if not activities:
        logger.warning(f"No activities found for user {user_id}")
        raise ActivityDataNotFoundError(f"No activities found for user {user_id}")

    # Add activities to collection
    for activity in activities:
        collection.add_activity(activity)

    # Add metadata if requested
    if include_metadata:
        # Get user information
        user_info = {}
        if MODELS_AVAILABLE:
            try:
                # Try to get user details from database
                from models.auth.user import User

                if user_id.isdigit():
                    user = User.query.get(int(user_id))
                else:
                    user = User.query.filter_by(username=user_id).first()

                if user:
                    user_info = {
                        'username': user.username,
                        'email': user.email,
                        'is_active': user.is_active,
                        'last_login': user.last_login.isoformat() if hasattr(user, 'last_login') and user.last_login else None
                    }
            except Exception as e:
                logger.warning(f"Could not retrieve user details: {e}")

        # Get session information
        session_info = {}
        if MODELS_AVAILABLE:
            try:
                # Try to get session details from database
                session_data = UserSession.query.filter_by(user_id=int(user_id) if user_id.isdigit() else None).all()
                if session_data:
                    session_info = {
                        'active_sessions': sum(1 for s in session_data if s.is_active and not s.revoked),
                        'last_active': max(s.last_active for s in session_data if s.last_active).isoformat(),
                        'session_count': len(session_data)
                    }
            except Exception as e:
                logger.warning(f"Could not retrieve session details: {e}")

        collection.metadata = {
            'user_info': user_info,
            'session_info': session_info,
            'collection_parameters': {
                'time_period': str(time_period),
                'activity_types': activity_types
            },
            'collection_time': datetime.now(timezone.utc).isoformat(),
            'activity_count': len(activities)
        }

    # Save to output directory if specified
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"user_activity_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        collection.export(EVIDENCE_FORMATS.JSON, output_file)

    logger.info(f"Collected {len(activities)} activities for user {user_id}")
    return collection

def generate_activity_timeline(
    user_id: str,
    time_period: Union[timedelta, int, float, str] = 72,
    include_related_events: bool = False,
    add_context: bool = True,
    output_format: str = 'json'
) -> ActivityTimeline:
    """
    Create chronological timeline of user activities.

    Args:
        user_id: User identifier
        time_period: Time period to analyze
        include_related_events: Include events from related systems
        add_context: Add contextual information to timeline
        output_format: Format for timeline output

    Returns:
        ActivityTimeline object with events

    Raises:
        ActivityDataNotFoundError: If no activity data is found
    """
    logger.info(f"Generating timeline for user {user_id} over {time_period} period")

    # Get activities
    activities = _get_user_activities(user_id, time_period)

    if not activities:
        logger.warning(f"No activities found for user {user_id}")
        raise ActivityDataNotFoundError(f"No activities found for user {user_id}")

    # Create timeline
    timeline = ActivityTimeline(user_id=user_id)

    # Add events to timeline
    for activity in activities:
        timeline.add_event(activity)

    # Add related events if requested
    if include_related_events and MODELS_AVAILABLE:
        try:
            # Try to find events related to the same resources
            related_activities = []

            # Collect unique resources accessed by the user
            resources = set()
            for activity in activities:
                resource_type = activity.get('resource_type')
                resource_id = activity.get('resource_id')
                if resource_type and resource_id:
                    resources.add((resource_type, resource_id))

            # Query for activities from other users on these resources
            for resource_type, resource_id in resources:
                # Skip if either are None
                if not resource_type or not resource_id:
                    continue

                query = UserActivity.query.filter(
                    UserActivity.resource_type == resource_type,
                    UserActivity.resource_id == resource_id
                )

                # Filter by user ID (either numeric or string)
                if user_id.isdigit():
                    query = query.filter(UserActivity.user_id != int(user_id))
                else:
                    # This would require a join with the users table, simplified here
                    pass

                # Add to related activities
                related = query.order_by(UserActivity.created_at.desc()).limit(10).all()
                if related:
                    for rel in related:
                        rel_dict = rel.to_dict()
                        rel_dict['event_type'] = 'related_resource_activity'
                        related_activities.append(rel_dict)

            # Add to timeline
            for activity in related_activities:
                timeline.add_event(activity)

            logger.info(f"Added {len(related_activities)} related events to timeline")

        except Exception as e:
            logger.warning(f"Failed to collect related events: {e}")

    # Add context if requested
    if add_context and MODELS_AVAILABLE:
        context_data = {}

        try:
            # Add user information
            from models.auth.user import User

            if user_id.isdigit():
                user = User.query.get(int(user_id))
            else:
                user = User.query.filter_by(username=user_id).first()

            if user:
                context_data['user'] = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_active': user.is_active,
                    'roles': [r.name for r in user.roles] if hasattr(user, 'roles') else [],
                    'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') and user.created_at else None
                }

            # Add login history
            login_history = LoginAttempt.query.filter_by(
                username=user.username if user else user_id
            ).order_by(
                LoginAttempt.timestamp.desc()
            ).limit(10).all()

            if login_history:
                context_data['login_history'] = [login.to_dict() for login in login_history]

            # Add suspicious activity if available
            if cs_monitoring and hasattr(cs_monitoring, 'detect_suspicious_activity'):
                suspicious = cs_monitoring.detect_suspicious_activity(hours=24)
                if suspicious and not isinstance(suspicious, Exception):
                    context_data['security_context'] = suspicious

            timeline.add_context(context_data)
            logger.info(f"Added context data to timeline")

        except Exception as e:
            logger.warning(f"Failed to add context data: {e}")

    logger.info(f"Generated timeline with {len(timeline.events)} events")
    return timeline

def analyze_user_behavior(
    user_id: str,
    baseline_period: Union[timedelta, int, float, str],
    analysis_window: Union[timedelta, int, float, str],
    detection_sensitivity: str = DETECTION_SENSITIVITY.MEDIUM
) -> UserBehaviorAnalysis:
    """
    Perform behavioral analysis to detect anomalies.

    Args:
        user_id: User identifier
        baseline_period: Period for establishing normal behavior
        analysis_window: Window for analysis
        detection_sensitivity: Sensitivity level

    Returns:
        UserBehaviorAnalysis object with results

    Raises:
        InvalidParameterError: If sensitivity level is invalid
        ActivityDataNotFoundError: If no activity data is found
    """
    # Validate sensitivity
    if detection_sensitivity not in [DETECTION_SENSITIVITY.LOW, DETECTION_SENSITIVITY.MEDIUM, DETECTION_SENSITIVITY.HIGH]:
        raise InvalidParameterError(f"Invalid sensitivity level: {detection_sensitivity}")

    logger.info(f"Analyzing user behavior for {user_id} (sensitivity: {detection_sensitivity})")

    # Convert time periods
    baseline_td = _normalize_time_period(baseline_period)
    analysis_td = _normalize_time_period(analysis_window)

    # Create analyzer
    analyzer = UserBehaviorAnalysis(user_id=user_id)

    # Establish baseline
    logger.info(f"Establishing baseline over {baseline_td.days} days")
    baseline = analyzer.establish_baseline(days=baseline_td.days)

    if not baseline:
        logger.warning(f"Unable to establish baseline for user {user_id}")
        raise ActivityDataNotFoundError(f"No baseline activity data found for user {user_id}")

    # Get activities for analysis window
    activities = _get_user_activities(user_id, analysis_td)

    if not activities:
        logger.warning(f"No recent activities found for user {user_id} in analysis window")
        raise ActivityDataNotFoundError(f"No recent activity data found for user {user_id}")

    # Detect anomalies
    anomalies = analyzer.detect_anomalies(activities, sensitivity=detection_sensitivity)

    logger.info(f"Behavioral analysis complete, detected {len(anomalies)} anomalies")
    return analyzer

def detect_access_anomalies(
    user_id: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    baseline_days: int = 30,
    detection_hours: int = 24
) -> List[Dict[str, Any]]:
    """
    Detect unusual resource access patterns.

    Args:
        user_id: User identifier
        resource_type: Optional resource type filter
        resource_id: Optional specific resource filter
        baseline_days: Baseline period in days
        detection_hours: Detection window in hours

    Returns:
        List of anomalous access events
    """
    logger.info(f"Detecting access anomalies for user {user_id}")

    # Get baseline activities
    baseline_activities = _get_user_activities(
        user_id=user_id,
        time_period=timedelta(days=baseline_days)
    )

    if not baseline_activities:
        logger.warning(f"No baseline activities found for user {user_id}")
        return []

    # Extract baseline resource access patterns
    baseline_resources = {}
    for activity in baseline_activities:
        act_resource_type = activity.get('resource_type')
        act_resource_id = activity.get('resource_id')

        if not act_resource_type:
            continue

        # Skip if we're filtering by type and it doesn't match
        if resource_type and act_resource_type != resource_type:
            continue

        # Skip if we're filtering by ID and it doesn't match
        if resource_id and act_resource_id and act_resource_id != resource_id:
            continue

        # Create a key combining type and ID if both exist
        resource_key = f"{act_resource_type}:{act_resource_id}" if act_resource_id else act_resource_type

        if resource_key not in baseline_resources:
            baseline_resources[resource_key] = 0

        baseline_resources[resource_key] += 1

    # Get recent activities
    recent_activities = _get_user_activities(
        user_id=user_id,
        time_period=timedelta(hours=detection_hours)
    )

    if not recent_activities:
        logger.warning(f"No recent activities found for user {user_id}")
        return []

    # Analyze for anomalies
    anomalies = []

    # Check for access to new resources
    for activity in recent_activities:
        act_resource_type = activity.get('resource_type')
        act_resource_id = activity.get('resource_id')

        if not act_resource_type:
            continue

        # Skip if we're filtering by type and it doesn't match
        if resource_type and act_resource_type != resource_type:
            continue

        # Skip if we're filtering by ID and it doesn't match
        if resource_id and act_resource_id and act_resource_id != resource_id:
            continue

        # Create a key combining type and ID if both exist
        resource_key = f"{act_resource_type}:{act_resource_id}" if act_resource_id else act_resource_type

        # Check if this is a new resource
        if resource_key not in baseline_resources:
            anomalies.append({
                'type': 'access_anomaly',
                'subtype': 'new_resource_access',
                'severity': 'medium',
                'activity_id': activity.get('id'),
                'timestamp': activity.get('created_at'),
                'description': f"Access to previously unused resource: {resource_key}",
                'details': {
                    'resource_key': resource_key,
                    'resource_type': act_resource_type,
                    'resource_id': act_resource_id,
                    'action': activity.get('action')
                }
            })

    logger.info(f"Detected {len(anomalies)} access anomalies")
    return anomalies

def detect_authorization_anomalies(
    user_id: str,
    detection_hours: int = 24,
    sensitivity: str = DETECTION_SENSITIVITY.MEDIUM
) -> List[Dict[str, Any]]:
    """
    Identify unusual permission usage patterns.

    Args:
        user_id: User identifier
        detection_hours: Analysis window in hours
        sensitivity: Detection sensitivity level

    Returns:
        List of unusual authorization events
    """
    logger.info(f"Detecting authorization anomalies for user {user_id}")

    # Get recent activities
    recent_activities = _get_user_activities(
        user_id=user_id,
        time_period=timedelta(hours=detection_hours)
    )

    if not recent_activities:
        logger.warning(f"No recent activities found for user {user_id}")
        return []

    # Filter for authorization-related activities
    auth_events = []
    for activity in recent_activities:
        # Look for activities that involve permissions
        resource_type = activity.get('resource_type', '').lower()
        action = activity.get('action', '').lower()
        activity_type = activity.get('activity_type', '').lower()

        # Keywords that indicate permission-related activities
        auth_keywords = ['permission', 'role', 'privilege', 'auth', 'right', 'grant', 'admin']

        is_auth_related = False

        # Check resource type
        if any(keyword in resource_type for keyword in auth_keywords):
            is_auth_related = True

        # Check if it's an admin action or auth change
        if activity_type in ['admin_action', 'auth_change']:
            is_auth_related = True

        # Check if action is related to permissions
        if action in ['grant', 'revoke', 'modify', 'elevate', 'assign']:
            is_auth_related = True

        # Check data field
        data = activity.get('data', {})
        if isinstance(data, dict):
            data_str = json.dumps(data).lower()
            if any(keyword in data_str for keyword in auth_keywords):
                is_auth_related = True

        if is_auth_related:
            auth_events.append(activity)

    # Simple analysis: check for frequency anomalies
    anomalies = []

    # If user performed multiple permission-related activities in a short time
    if len(auth_events) >= 3:
        # Different threshold based on sensitivity
        threshold = 3
        if sensitivity == DETECTION_SENSITIVITY.HIGH:
            threshold = 2
        elif sensitivity == DETECTION_SENSITIVITY.LOW:
            threshold = 5

        if len(auth_events) >= threshold:
            anomalies.append({
                'type': 'authorization_anomaly',
                'subtype': 'high_frequency_permission_changes',
                'severity': 'high',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'description': f"Unusually high frequency of permission-related activities: {len(auth_events)} in {detection_hours} hours",
                'details': {
                    'event_count': len(auth_events),
                    'time_period_hours': detection_hours,
                    'first_event_time': auth_events[0].get('created_at'),
                    'last_event_time': auth_events[-1].get('created_at')
                }
            })

    # Check for unusual actions based on data
    for event in auth_events:
        data = activity.get('data', {})
        if isinstance(data, dict):
            # Look for permission escalation or privileged operations in the data
            if data.get('is_admin_action') or data.get('privileged'):
                anomalies.append({
                    'type': 'authorization_anomaly',
                    'subtype': 'privileged_operation',
                    'severity': 'medium',
                    'activity_id': activity.get('id'),
                    'timestamp': activity.get('created_at'),
                    'description': f"Privileged operation performed: {action} on {resource_type}",
                    'details': {
                        'action': action,
                        'resource_type': resource_type,
                        'resource_id': activity.get('resource_id'),
                        'operation_details': data
                    }
                })

            # Look for permission changes to sensitive resources
            sensitive_resources = ['admin', 'security', 'config', 'user', 'credential', 'key']
            if resource_type and any(res in resource_type for res in sensitive_resources):
                anomalies.append({
                    'type': 'authorization_anomaly',
                    'subtype': 'sensitive_resource_permission_change',
                    'severity': 'high',
                    'activity_id': activity.get('id'),
                    'timestamp': activity.get('created_at'),
                    'description': f"Permission change to sensitive resource: {action} on {resource_type}",
                    'details': {
                        'action': action,
                        'resource_type': resource_type,
                        'resource_id': activity.get('resource_id')
                    }
                })

    logger.info(f"Detected {len(anomalies)} authorization anomalies")
    return anomalies

def extract_login_patterns(user_id: str, days: int = 30) -> Dict[str, Any]:
    """
    Extract authentication patterns for the user.

    Args:
        user_id: User identifier
        days: Analysis period in days

    Returns:
        Dictionary with login pattern information

    Raises:
        ActivityDataNotFoundError: If no activity data is found
    """
    logger.info(f"Extracting login patterns for user {user_id} over {days} days")

    # Get login activities
    activities = _get_user_activities(
        user_id=user_id,
        time_period=timedelta(days=days),
        activity_types=[ACTIVITY_TYPES.LOGIN]
    )

    if not activities:
        logger.warning(f"No login activities found for user {user_id}")
        raise ActivityDataNotFoundError(f"No login activity found for user {user_id}")

    # Build time patterns
    hour_distribution = [0] * 24
    day_distribution = [0] * 7
    locations = {}
    devices = {}

    for activity in activities:
        try:
            # Process timestamp
            timestamp = activity.get('created_at')
            if not timestamp:
                continue

            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = timestamp

            # Update time distributions
            hour_distribution[dt.hour] += 1
            day_distribution[dt.weekday()] += 1

            # Track locations
            location = activity.get('geo_location') or activity.get('ip_address')
            if location:
                locations[location] = locations.get(location, 0) + 1

            # Track devices
            device = activity.get('device_info', {}).get('user_agent') or activity.get('user_agent')
            if device:
                devices[device] = devices.get(device, 0) + 1

        except (ValueError, TypeError) as e:
            logger.debug(f"Error processing timestamp: {e}")
            continue

    # Calculate most active periods
    peak_hour = hour_distribution.index(max(hour_distribution)) if max(hour_distribution) > 0 else None
    peak_day = day_distribution.index(max(day_distribution)) if max(day_distribution) > 0 else None

    # Calculate primary location
    primary_location = max(locations.items(), key=lambda x: x[1])[0] if locations else None

    # Compile results
    login_patterns = {
        'user_id': user_id,
        'analysis_period_days': days,
        'login_count': len(activities),
        'time_patterns': {
            'hour_distribution': hour_distribution,
            'day_distribution': day_distribution,
            'peak_hour': peak_hour,
            'peak_day': peak_day
        },
        'location_patterns': {
            'locations': locations,
            'location_count': len(locations),
            'primary_location': primary_location
        },
        'device_patterns': {
            'devices': devices,
            'device_count': len(devices)
        },
        'generated_at': datetime.now(timezone.utc).isoformat()
    }

    logger.info(f"Extracted login patterns from {len(activities)} login activities")
    return login_patterns

def find_concurrent_sessions(user_id: str, detection_hours: int = 24) -> List[Dict[str, Any]]:
    """
    Identify potentially concurrent user sessions.

    Args:
        user_id: User identifier
        detection_hours: Detection window in hours

    Returns:
        List of concurrent session events
    """
    logger.info(f"Finding concurrent sessions for user {user_id} over {detection_hours} hours")

    # Get login and resource access activities
    activities = _get_user_activities(
        user_id=user_id,
        time_period=timedelta(hours=detection_hours),
        activity_types=[ACTIVITY_TYPES.LOGIN, ACTIVITY_TYPES.RESOURCE_ACCESS]
    )

    if not activities:
        logger.info(f"No activities found for user {user_id}")
        return []

    # Group activities by location/IP
    sessions_by_location = {}
    for activity in activities:
        location = activity.get('geo_location') or activity.get('ip_address')
        if not location:
            continue

        timestamp = activity.get('created_at')
        if not timestamp:
            continue

        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                continue
        else:
            dt = timestamp

        if location not in sessions_by_location:
            sessions_by_location[location] = []

        sessions_by_location[location].append({
            'timestamp': dt,
            'activity_type': activity.get('activity_type'),
            'resource_type': activity.get('resource_type'),
            'resource_id': activity.get('resource_id'),
            'action': activity.get('action'),
            'id': activity.get('id')
        })

    # If less than 2 locations, no concurrent sessions
    if len(sessions_by_location) < 2:
        logger.info(f"User {user_id} has activity from only {len(sessions_by_location)} locations")
        return []

    # Look for concurrent sessions (activities from different locations in close time proximity)
    concurrent_events = []
    locations = list(sessions_by_location.keys())

    # The time window (in minutes) to consider activities concurrent
    concurrency_window = 5

    # For each location, compare with other locations
    for i, loc1 in enumerate(locations):
        for j in range(i + 1, len(locations)):
            loc2 = locations[j]

            # Get activities from both locations
            activities1 = sessions_by_location[loc1]
            activities2 = sessions_by_location[loc2]

            # Sort by timestamp
            activities1.sort(key=lambda x: x['timestamp'])
            activities2.sort(key=lambda x: x['timestamp'])

            # Identify overlapping time periods
            for act1 in activities1:
                for act2 in activities2:
                    # Calculate time difference in minutes
                    time_diff = abs((act1['timestamp'] - act2['timestamp']).total_seconds()) / 60

                    if time_diff <= concurrency_window:
                        # Found potential concurrent activities
                        concurrent_events.append({
                            'type': 'concurrent_session',
                            'severity': 'high',
                            'description': f"Concurrent activity from different locations: {loc1} and {loc2}",
                            'timestamp': act1['timestamp'].isoformat(),
                            'details': {
                                'location1': loc1,
                                'activity1': {
                                    'id': act1.get('id'),
                                    'timestamp': act1['timestamp'].isoformat(),
                                    'activity_type': act1.get('activity_type'),
                                    'resource': f"{act1.get('resource_type')}:{act1.get('resource_id')}"
                                },
                                'location2': loc2,
                                'activity2': {
                                    'id': act2.get('id'),
                                    'timestamp': act2['timestamp'].isoformat(),
                                    'activity_type': act2.get('activity_type'),
                                    'resource': f"{act2.get('resource_type')}:{act2.get('resource_id')}"
                                },
                                'time_difference_minutes': round(time_diff, 2)
                            }
                        })
                        # Only need to find one instance of concurrency between these locations
                        break

    logger.info(f"Found {len(concurrent_events)} potential concurrent session events")
    return concurrent_events

def get_resource_access_summary(user_id: str, days: int = 30) -> Dict[str, Any]:
    """
    Summarize resource access by type.

    Args:
        user_id: User identifier
        days: Analysis period in days

    Returns:
        Dictionary with resource access summary
    """
    logger.info(f"Generating resource access summary for user {user_id} over {days} days")

    # Get resource access activities
    activities = _get_user_activities(
        user_id=user_id,
        time_period=timedelta(days=days),
        activity_types=[ACTIVITY_TYPES.RESOURCE_ACCESS]
    )

    if not activities:
        logger.info(f"No resource access activities found for user {user_id}")
        return {
            'user_id': user_id,
            'period_days': days,
            'access_count': 0,
            'resource_types': {},
            'resources': {},
            'generated_at': datetime.now(timezone.utc).isoformat()
        }

    # Count accesses by resource type
    resource_type_counts = {}
    resource_counts = {}

    for activity in activities:
        resource_type = activity.get('resource_type')
        resource_id = activity.get('resource_id')

        if not resource_type:
            continue

        # Count by resource type
        resource_type_counts[resource_type] = resource_type_counts.get(resource_type, 0) + 1

        # Count by specific resource
        if resource_id:
            resource_key = f"{resource_type}:{resource_id}"
            resource_counts[resource_key] = resource_counts.get(resource_key, 0) + 1

    # Get top accessed resources
    top_resources = sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_types = sorted(resource_type_counts.items(), key=lambda x: x[1], reverse=True)

    # Compile results
    summary = {
        'user_id': user_id,
        'period_days': days,
        'access_count': len(activities),
        'resource_types': {
            'counts': resource_type_counts,
            'top_types': top_types
        },
        'resources': {
            'counts': resource_counts,
            'top_resources': top_resources
        },
        'generated_at': datetime.now(timezone.utc).isoformat()
    }

    logger.info(f"Generated resource access summary with {len(resource_counts)} unique resources")
    return summary

def correlate_activities(
    user_id: str,
    related_indicator: Optional[str] = None,
    time_window: Optional[timedelta] = None,
    related_systems: Optional[List[str]] = None,
    event_types: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Correlates user activities with other events.

    Args:
        user_id: User identifier
        related_indicator: Optional specific indicator (IP, system, etc.)
        time_window: Optional time window for correlation
        related_systems: Optional list of systems to check
        event_types: Optional types of events to correlate

    Returns:
        List of correlated events
    """
    logger.info(f"Correlating activities for user {user_id}")

    # Default time window if not provided
    if time_window is None:
        time_window = timedelta(hours=1)

    # Get user activities
    user_activities = _get_user_activities(
        user_id=user_id,
        time_period=time_window
    )

    if not user_activities:
        logger.warning(f"No activities found for user {user_id}")
        return []

    # Build correlation lookup
    correlated_events = []

    # Process each activity to find related events
    for activity in user_activities:
        timestamp = activity.get('created_at')
        if not timestamp:
            continue

        # Parse timestamp if it's a string
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                continue
        else:
            dt = timestamp

        # Define correlation window (before and after activity)
        start_time = dt - timedelta(minutes=30)
        end_time = dt + timedelta(minutes=30)

        # Get related events if the database is available
        if MODELS_AVAILABLE:
            try:
                from models.security.audit_log import AuditLog

                # Build query conditions
                query = AuditLog.query.filter(
                    AuditLog.created_at >= start_time,
                    AuditLog.created_at <= end_time
                )

                # Filter by specific indicator (like IP address)
                if related_indicator:
                    query = query.filter(
                        (AuditLog.ip_address == related_indicator) |
                        (AuditLog.details.cast(db.String).contains(related_indicator))
                    )

                # Filter by systems
                if related_systems:
                    query = query.filter(AuditLog.system.in_(related_systems))

                # Filter by event types
                if event_types:
                    query = query.filter(AuditLog.event_type.in_(event_types))

                # Execute query
                related_logs = query.all()

                # Add to correlated events
                for log in related_logs:
                    correlated_events.append({
                        'type': 'correlated_event',
                        'source': 'audit_log',
                        'event_type': log.event_type,
                        'timestamp': log.created_at.isoformat(),
                        'system': log.system,
                        'ip_address': log.ip_address,
                        'severity': log.severity,
                        'details': log.details,
                        'correlation': {
                            'user_activity_id': activity.get('id'),
                            'time_difference_seconds': abs((log.created_at - dt).total_seconds()),
                            'correlation_basis': related_indicator or 'time_window'
                        }
                    })
            except Exception as e:
                logger.warning(f"Failed to query audit logs: {e}")

    # Sort by timestamp
    correlated_events.sort(key=lambda x: x.get('timestamp', ''))

    logger.info(f"Found {len(correlated_events)} correlated events")
    return correlated_events

def export_activity_evidence(
    user_id: str,
    time_period: Union[timedelta, int, float, str],
    format: str = 'json',
    evidence_dir: Optional[str] = None,
    chain_of_custody: bool = True,
    analyst: str = "Security Analyst",
    incident_id: Optional[str] = None
) -> str:
    """
    Exports user activity data in forensic format.

    Args:
        user_id: User identifier
        time_period: Time period to collect
        format: Export format
        evidence_dir: Directory to save evidence
        chain_of_custody: Whether to create a chain of custody document
        analyst: Name of the analyst collecting the evidence
        incident_id: Optional incident ID for evidence organization

    Returns:
        Path to exported evidence file

    Raises:
        ActivityDataNotFoundError: If no activity data is found
        EvidenceExportError: If export fails
    """
    logger.info(f"Exporting activity evidence for user {user_id}")

    # Create the evidence directory
    if incident_id and PARENT_IMPORTS_AVAILABLE:
        if evidence_dir is None:
            evidence_dir = create_evidence_directory(incident_id)
    elif evidence_dir is None:
        # Create a default directory
        evidence_dir = os.path.join(DEFAULT_EVIDENCE_DIR, f"user_{user_id}")
        os.makedirs(evidence_dir, exist_ok=True)
    else:
        os.makedirs(evidence_dir, exist_ok=True)

    # Define evidence file path
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(
        evidence_dir,
        f"user_activity_{user_id}_{timestamp}.{format}"
    )

    # Collect user activity
    collection = collect_user_activity(
        user_id=user_id,
        time_period=time_period,
        include_metadata=True
    )

    # Export to file
    try:
        output_path = collection.export(format, output_file)
        logger.info(f"Exported activity evidence to {output_path}")

        # Create chain of custody if requested
        if chain_of_custody:
            custody_doc = _create_chain_of_custody(
                evidence_path=output_path,
                user_id=user_id,
                analyst=analyst
            )
            if custody_doc:
                logger.info(f"Created chain of custody document: {custody_doc}")

        return output_path
    except Exception as e:
        logger.error(f"Failed to export activity evidence: {e}")
        raise EvidenceExportError(f"Failed to export activity evidence: {str(e)}")

# Command-line interface
def main() -> None:
    """Command line interface for user activity monitoring."""
    parser = argparse.ArgumentParser(description='User Activity Monitoring for Incident Response')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Collect command
    collect_parser = subparsers.add_parser('collect', help='Collect user activity data')
    collect_parser.add_argument('--user-id', required=True, help='User identifier')
    collect_parser.add_argument('--timeframe', default='48h', help='Time period (e.g., 24h, 7d)')
    collect_parser.add_argument('--activity-types', nargs='+', help='Activity types to collect')
    collect_parser.add_argument('--output', required=True, help='Output directory')
    collect_parser.add_argument('--format', default='json', choices=EVIDENCE_FORMATS.ALL, help='Output format')

    # Timeline command
    timeline_parser = subparsers.add_parser('timeline', help='Generate user activity timeline')
    timeline_parser.add_argument('--user-id', required=True, help='User identifier')
    timeline_parser.add_argument('--timeframe', default='72h', help='Time period (e.g., 72h, 14d)')
    timeline_parser.add_argument('--include-related', action='store_true', help='Include related events')
    timeline_parser.add_argument('--add-context', action='store_true', default=True, help='Add contextual information')
    timeline_parser.add_argument('--format', default='json', choices=EVIDENCE_FORMATS.ALL, help='Output format')
    timeline_parser.add_argument('--output', required=True, help='Output file path')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze user behavior for anomalies')
    analyze_parser.add_argument('--user-id', required=True, help='User identifier')
    analyze_parser.add_argument('--baseline', default='30d', help='Baseline period (e.g., 30d)')
    analyze_parser.add_argument('--detection-window', default='48h', help='Detection window (e.g., 48h)')
    analyze_parser.add_argument('--sensitivity', default='medium', choices=['low', 'medium', 'high'], help='Detection sensitivity')
    analyze_parser.add_argument('--output', help='Output file for analysis report')

    # Access anomalies command
    access_parser = subparsers.add_parser('detect-access', help='Detect unusual resource access')
    access_parser.add_argument('--user-id', required=True, help='User identifier')
    access_parser.add_argument('--resource-type', help='Filter by resource type')
    access_parser.add_argument('--resource-id', help='Filter by resource ID')
    access_parser.add_argument('--baseline-days', type=int, default=30, help='Days for baseline')
    access_parser.add_argument('--detection-hours', type=int, default=24, help='Hours for detection window')
    access_parser.add_argument('--output', help='Output file for findings')

    # Authorization anomalies command
    auth_parser = subparsers.add_parser('detect-auth', help='Detect unusual authorization patterns')
    auth_parser.add_argument('--user-id', required=True, help='User identifier')
    auth_parser.add_argument('--detection-hours', type=int, default=24, help='Hours for detection window')
    auth_parser.add_argument('--sensitivity', default='medium', choices=['low', 'medium', 'high'], help='Detection sensitivity')
    auth_parser.add_argument('--output', help='Output file for findings')

    # Login patterns command
    login_parser = subparsers.add_parser('login-patterns', help='Extract login patterns')
    login_parser.add_argument('--user-id', required=True, help='User identifier')
    login_parser.add_argument('--days', type=int, default=30, help='Analysis period in days')
    login_parser.add_argument('--output', help='Output file for pattern data')

    # Resource summary command
    resource_parser = subparsers.add_parser('resource-summary', help='Get resource access summary')
    resource_parser.add_argument('--user-id', required=True, help='User identifier')
    resource_parser.add_argument('--days', type=int, default=30, help='Analysis period in days')
    resource_parser.add_argument('--output', help='Output file for summary')

    # Parse arguments
    args = parser.parse_args()

    # Set log level based on command
    logger.setLevel(logging.INFO)

    try:
        if args.command == 'collect':
            # Collect user activity data
            collection = collect_user_activity(
                user_id=args.user_id,
                time_period=args.timeframe,
                activity_types=args.activity_types,
                output_dir=args.output
            )

            # Export to file
            output_file = os.path.join(
                args.output,
                f"user_activity_{args.user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.format}"
            )
            output_path = collection.export(args.format, output_file)
            print(f"Exported {len(collection.activities)} activities to {output_path}")

        elif args.command == 'timeline':
            # Generate timeline
            timeline = generate_activity_timeline(
                user_id=args.user_id,
                time_period=args.timeframe,
                include_related_events=args.include_related,
                add_context=args.add_context,
                output_format=args.format
            )

            # Export to file
            output_path = timeline.export(args.format, args.output)
            print(f"Exported timeline with {len(timeline.events)} events to {args.output}")

        elif args.command == 'analyze':
            # Analyze user behavior
            analyzer = analyze_user_behavior(
                user_id=args.user_id,
                baseline_period=args.baseline,
                analysis_window=args.detection_window,
                detection_sensitivity=args.sensitivity
            )

            # Generate report
            if args.output:
                report_path = analyzer.generate_report(args.output)
                print(f"Analysis report with {len(analyzer.anomalies)} anomalies saved to {report_path}")
            else:
                # Print summary to console
                print(f"Analysis complete. Found {len(analyzer.anomalies)} anomalies.")
                for anomaly in analyzer.anomalies:
                    print(f" - [{anomaly.get('severity', 'medium').upper()}] {anomaly.get('description')}")

        elif args.command == 'detect-access':
            # Detect access anomalies
            anomalies = detect_access_anomalies(
                user_id=args.user_id,
                resource_type=args.resource_type,
                resource_id=args.resource_id,
                baseline_days=args.baseline_days,
                detection_hours=args.detection_hours
            )

            # Output results
            if args.output:
                os.makedirs(os.path.dirname(args.output), exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(anomalies, f, indent=2, default=str)
                print(f"Found {len(anomalies)} access anomalies. Results saved to {args.output}")
            else:
                # Print to console
                print(f"Found {len(anomalies)} access anomalies.")
                for anomaly in anomalies:
                    print(f" - [{anomaly.get('severity', 'medium').upper()}] {anomaly.get('description')}")

        elif args.command == 'detect-auth':
            # Detect authorization anomalies
            anomalies = detect_authorization_anomalies(
                user_id=args.user_id,
                detection_hours=args.detection_hours,
                sensitivity=args.sensitivity
            )

            # Output results
            if args.output:
                os.makedirs(os.path.dirname(args.output), exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(anomalies, f, indent=2, default=str)
                print(f"Found {len(anomalies)} authorization anomalies. Results saved to {args.output}")
            else:
                # Print to console
                print(f"Found {len(anomalies)} authorization anomalies.")
                for anomaly in anomalies:
                    print(f" - [{anomaly.get('severity', 'medium').upper()}] {anomaly.get('description')}")

        elif args.command == 'login-patterns':
            # Extract login patterns
            patterns = extract_login_patterns(
                user_id=args.user_id,
                days=args.days
            )

            # Output results
            if args.output:
                os.makedirs(os.path.dirname(args.output), exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(patterns, f, indent=2, default=str)
                print(f"Login patterns extracted. Results saved to {args.output}")
            else:
                # Print summary to console
                print(f"Login patterns for user {args.user_id} over {args.days} days:")
                print(f" - Total logins: {patterns.get('login_count', 0)}")
                print(f" - Peak hour: {patterns.get('time_patterns', {}).get('peak_hour')}")
                print(f" - Primary location: {patterns.get('location_patterns', {}).get('primary_location')}")
                print(f" - Unique locations: {patterns.get('location_patterns', {}).get('location_count', 0)}")
                print(f" - Unique devices: {patterns.get('device_patterns', {}).get('device_count', 0)}")

        elif args.command == 'resource-summary':
            # Get resource access summary
            summary = get_resource_access_summary(
                user_id=args.user_id,
                days=args.days
            )

            # Output results
            if args.output:
                os.makedirs(os.path.dirname(args.output), exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(summary, f, indent=2, default=str)
                print(f"Resource summary generated. Results saved to {args.output}")
            else:
                # Print summary to console
                print(f"Resource access summary for user {args.user_id} over {args.days} days:")
                print(f" - Total accesses: {summary.get('access_count', 0)}")

                # Show top resource types
                print(" - Top resource types:")
                for rt, count in summary.get('resource_types', {}).get('top_types', [])[:5]:
                    print(f"   - {rt}: {count} accesses")

                # Show top resources
                print(" - Top accessed resources:")
                for res, count in summary.get('resources', {}).get('top_resources', [])[:5]:
                    print(f"   - {res}: {count} accesses")

        else:
            parser.print_help()

    except ActivityDataNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except InvalidParameterError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except EvidenceExportError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

# Ensure functions and classes are exposed properly
__all__ = [
    # Classes
    'UserActivityCollection',
    'UserBehaviorAnalysis',
    'ActivityTimeline',

    # Constants
    'ACTIVITY_TYPES',
    'DETECTION_SENSITIVITY',
    'ANALYSIS_FEATURES',
    'EVIDENCE_FORMATS',

    # Core functions
    'collect_user_activity',
    'generate_activity_timeline',
    'analyze_user_behavior',
    'detect_access_anomalies',
    'detect_authorization_anomalies',

    # Helper functions
    'extract_login_patterns',
    'find_concurrent_sessions',
    'get_resource_access_summary',
    'correlate_activities',
    'export_activity_evidence'
]

# Execute main function when run as a script
if __name__ == "__main__":
    import re  # Import here for regex pattern matching
    main()
