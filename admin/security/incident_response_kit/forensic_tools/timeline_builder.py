#!/usr/bin/env python3
"""
Timeline Builder Module for Incident Response Toolkit

This module provides capabilities for creating, analyzing, and visualizing chronological
timelines of security incidents. It combines data from multiple sources, normalizes
timestamps across different formats, and produces structured timeline representations.

The timeline builder is a critical component for incident documentation and analysis,
enabling responders to establish accurate chronology of events and identify patterns
or anomalies in the sequence of activities during a security incident.
"""

import os
import sys
import json
import csv
import logging
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple, Set
import re

# Setup module logging
logger = logging.getLogger(__name__)

# Constants
DEFAULT_OUTPUT_FORMAT = "json"  # Default output format
SUPPORTED_FORMATS = ["json", "csv", "html", "markdown"]
DATETIME_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO 8601 with microseconds
    "%Y-%m-%dT%H:%M:%SZ",      # ISO 8601
    "%Y-%m-%d %H:%M:%S.%f",    # ISO-like with microseconds
    "%Y-%m-%d %H:%M:%S",       # ISO-like without timezone
    "%d/%b/%Y:%H:%M:%S %z",    # Common Log Format
    "%a %b %d %H:%M:%S %Y",    # Unix-style
    "%m/%d/%y %H:%M:%S",       # MDY format
    "%d-%b-%Y %H:%M:%S"        # DMY format
]

# Attempt to import core security or forensics utilities if available
CORE_SECURITY_AVAILABLE = False
FORENSIC_UTILS_AVAILABLE = False
ADVANCED_TIMESTAMP_AVAILABLE = False

try:
    from core.security.cs_file_integrity import calculate_file_hash
    from core.security.cs_utils import normalize_timestamp
    CORE_SECURITY_AVAILABLE = True
    logger.debug("Core security utilities available")
except ImportError as e:
    logger.debug(f"Core security utilities not available: {e}")

try:
    from admin.security.forensics.timeline_builder import (
        create_timeline as forensic_create_timeline,
        add_event as forensic_add_event,
        merge_timelines as forensic_merge_timelines,
        normalize_timestamp as forensic_normalize_timestamp,
        extract_timeline_from_logs as forensic_extract_from_logs
    )
    FORENSIC_UTILS_AVAILABLE = True
    logger.debug("Forensic timeline utilities available")
except ImportError as e:
    logger.debug(f"Forensic timeline utilities not available: {e}")

try:
    from admin.security.forensics.utils.timestamp_utils import (
        normalize_timestamp,
        parse_timestamp,
        validate_timestamp
    )
    ADVANCED_TIMESTAMP_AVAILABLE = True
    logger.debug("Advanced timestamp utilities available")
except ImportError as e:
    logger.debug(f"Advanced timestamp utilities not available: {e}")

# Determine module base path
MODULE_PATH = Path(os.path.dirname(os.path.abspath(__file__)))
IR_KIT_PATH = MODULE_PATH.parent

# Try to import from parent package with relative imports
try:
    from .. import log_forensic_operation, IncidentResponseError, sanitize_incident_id
except ImportError:
    # Define fallback logging function
    def log_forensic_operation(operation: str, success: bool, details: Dict[str, Any] = None) -> None:
        """Log a forensic operation when the primary logging system is unavailable."""
        if success:
            logger.info(f"Forensic operation '{operation}' completed successfully: {details}")
        else:
            logger.warning(f"Forensic operation '{operation}' failed: {details}")


class TimelineBuilderError(Exception):
    """Exception raised for errors in the timeline builder module."""
    pass


class Event:
    """Represents a single timeline event with consistent attributes."""

    def __init__(
        self,
        timestamp: Union[str, datetime],
        description: str,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        severity: Optional[str] = None,
        evidence_reference: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize a timeline event.

        Args:
            timestamp: Event timestamp (string or datetime)
            description: Description of the event
            source: Source of the event (log file, system, etc.)
            event_type: Type of event (e.g., "detection", "response", etc.)
            actor: Person or system that performed the action
            severity: Event severity (e.g., "high", "medium", "low")
            evidence_reference: Reference to related evidence
            **kwargs: Additional event attributes
        """
        self.timestamp = self._normalize_timestamp(timestamp)
        self.description = description
        self.source = source
        self.event_type = event_type
        self.actor = actor
        self.severity = severity
        self.evidence_reference = evidence_reference

        # Store additional attributes
        self.attributes = kwargs

        # Generate a unique ID if not provided
        if 'id' not in self.attributes:
            self.attributes['id'] = self._generate_id()

    def _normalize_timestamp(self, timestamp: Union[str, datetime]) -> datetime:
        """
        Normalize the timestamp to a datetime object.

        Args:
            timestamp: Timestamp as string or datetime

        Returns:
            Normalized datetime object with timezone info

        Raises:
            ValueError: If timestamp format is not recognized
        """
        if isinstance(timestamp, datetime):
            # Ensure timezone info is present
            if timestamp.tzinfo is None:
                return timestamp.replace(tzinfo=timezone.utc)
            return timestamp

        # Use available normalization functions
        if ADVANCED_TIMESTAMP_AVAILABLE:
            dt = parse_timestamp(timestamp)
            if dt:
                return dt
        elif FORENSIC_UTILS_AVAILABLE:
            dt = forensic_normalize_timestamp(timestamp)
            if dt:
                return dt
        elif CORE_SECURITY_AVAILABLE:
            dt = normalize_timestamp(timestamp)
            if dt:
                return dt

        # Fallback to manual parsing
        for fmt in DATETIME_FORMATS:
            try:
                dt = datetime.strptime(timestamp, fmt)
                # Add UTC timezone if missing
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue

        # Last resort for Unix timestamp
        try:
            return datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
        except (ValueError, TypeError, OverflowError):
            raise ValueError(f"Cannot parse timestamp: {timestamp}")

    def _generate_id(self) -> str:
        """Generate a unique ID for this event."""
        # Use timestamp and part of description to create a semi-unique ID
        timestamp_str = self.timestamp.strftime("%Y%m%d%H%M%S")
        desc_part = re.sub(r'[^a-zA-Z0-9]', '', self.description[:20])
        return f"evt-{timestamp_str}-{desc_part}"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary.

        Returns:
            Dictionary representation of the event
        """
        event_dict = {
            'timestamp': self.timestamp.isoformat(),
            'description': self.description,
        }

        # Add optional fields if present
        if self.source:
            event_dict['source'] = self.source
        if self.event_type:
            event_dict['event_type'] = self.event_type
        if self.actor:
            event_dict['actor'] = self.actor
        if self.severity:
            event_dict['severity'] = self.severity
        if self.evidence_reference:
            event_dict['evidence_reference'] = self.evidence_reference

        # Add all additional attributes
        event_dict.update(self.attributes)

        return event_dict


class Timeline:
    """Class representing a chronological timeline of incident events."""

    def __init__(
        self,
        name: str = "Incident Timeline",
        incident_id: Optional[str] = None,
        description: Optional[str] = None
    ):
        """
        Initialize a new timeline.

        Args:
            name: Name of the timeline
            incident_id: ID of the incident this timeline is for
            description: Description of the timeline
        """
        self.name = name
        self.incident_id = incident_id
        self.description = description or f"Timeline for incident {incident_id}" if incident_id else "Incident timeline"
        self.events: List[Event] = []
        self.sources: Set[str] = set()
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at
        self.metadata: Dict[str, Any] = {
            "created": self.created_at.isoformat(),
            "modified": self.updated_at.isoformat(),
            "source_files": [],
            "event_count": 0,
            "time_range": {
                "start": None,
                "end": None
            }
        }

    def add_event(
        self,
        event: Union[Event, Dict[str, Any], List[Union[Event, Dict[str, Any]]]],
        source: Optional[str] = None
    ) -> int:
        """
        Add one or more events to the timeline.

        Args:
            event: Event instance, event dictionary, or list of events
            source: Source of the event(s) if not specified in the event

        Returns:
            Number of events added
        """
        # Handle multiple events
        if isinstance(event, list):
            count = 0
            for e in event:
                if self._add_single_event(e, source):
                    count += 1
            return count

        # Handle single event
        if self._add_single_event(event, source):
            return 1
        return 0

    def _add_single_event(self, event: Union[Event, Dict[str, Any]], source: Optional[str] = None) -> bool:
        """
        Add a single event to the timeline.

        Args:
            event: Event instance or event dictionary
            source: Source of the event if not specified in the event

        Returns:
            True if event was added, False otherwise
        """
        try:
            # Convert dict to Event if needed
            if isinstance(event, dict):
                # Extract known fields from dict
                evt_source = event.get('source') or source
                evt = Event(
                    timestamp=event.get('timestamp'),
                    description=event.get('description'),
                    source=evt_source,
                    event_type=event.get('event_type'),
                    actor=event.get('actor'),
                    severity=event.get('severity'),
                    evidence_reference=event.get('evidence_reference'),
                    # Add all remaining fields as additional attributes
                    **{k: v for k, v in event.items() if k not in [
                        'timestamp', 'description', 'source', 'event_type',
                        'actor', 'severity', 'evidence_reference'
                    ]}
                )
            elif isinstance(event, Event):
                evt = event
                # Update source if provided
                if source and not evt.source:
                    evt.source = source
            else:
                logger.warning(f"Invalid event type: {type(event)}")
                return False

            # Add source to sources set
            if evt.source:
                self.sources.add(evt.source)

            # Add event to list
            self.events.append(evt)

            # Update metadata
            self._update_metadata()

            return True
        except Exception as e:
            logger.warning(f"Failed to add event: {e}")
            return False

    def _update_metadata(self):
        """Update timeline metadata after adding events."""
        self.updated_at = datetime.now(timezone.utc)
        self.metadata["modified"] = self.updated_at.isoformat()
        self.metadata["event_count"] = len(self.events)

        # Sort events by timestamp
        self.sort_events()

        # Update time range
        if self.events:
            self.metadata["time_range"]["start"] = self.events[0].timestamp.isoformat()
            self.metadata["time_range"]["end"] = self.events[-1].timestamp.isoformat()

    def sort_events(self):
        """Sort timeline events chronologically by timestamp."""
        self.events.sort(key=lambda e: e.timestamp)

    def merge(self, other_timeline: 'Timeline') -> int:
        """
        Merge another timeline into this one.

        Args:
            other_timeline: Another Timeline object

        Returns:
            Number of events added

        Raises:
            TypeError: If other_timeline is not a Timeline object
        """
        if not isinstance(other_timeline, Timeline):
            raise TypeError("Can only merge with another Timeline object")

        # Get current event count
        current_count = len(self.events)

        # Merge events
        for event in other_timeline.events:
            self.add_event(event)

        # Merge source files
        for source in other_timeline.metadata.get('source_files', []):
            if source not in self.metadata['source_files']:
                self.metadata['source_files'].append(source)

        # Return number of events added
        return len(self.events) - current_count

    def export(self, output_path: str, format_type: str = DEFAULT_OUTPUT_FORMAT) -> bool:
        """
        Export the timeline to a file in the specified format.

        Args:
            output_path: Path to save the exported timeline
            format_type: Export format (json, csv, html, markdown)

        Returns:
            True if export was successful, False otherwise
        """
        format_type = format_type.lower()

        if format_type not in SUPPORTED_FORMATS:
            logger.error(f"Unsupported export format: {format_type}")
            return False

        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

            if format_type == 'json':
                return self._export_json(output_path)
            elif format_type == 'csv':
                return self._export_csv(output_path)
            elif format_type == 'html':
                return self._export_html(output_path)
            elif format_type == 'markdown':
                return self._export_markdown(output_path)

        except Exception as e:
            logger.error(f"Failed to export timeline: {e}")
            return False

        return False

    def _export_json(self, output_path: str) -> bool:
        """Export timeline to JSON format."""
        try:
            # Convert events to dict
            events_dict = [event.to_dict() for event in self.events]

            # Create export data
            export_data = {
                "metadata": {
                    "name": self.name,
                    "description": self.description,
                    "incident_id": self.incident_id,
                    "created": self.created_at.isoformat(),
                    "modified": self.updated_at.isoformat(),
                    "event_count": len(self.events),
                    "sources": list(self.sources),
                    "source_files": self.metadata.get("source_files", []),
                    "time_range": self.metadata["time_range"]
                },
                "events": events_dict
            }

            # Write to file with pretty formatting
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=_json_serializer)

            log_forensic_operation("export_timeline", True, {
                "format": "json",
                "output_path": output_path,
                "event_count": len(self.events),
                "incident_id": self.incident_id
            })

            return True

        except Exception as e:
            logger.error(f"Error exporting timeline to JSON: {e}")
            log_forensic_operation("export_timeline", False, {
                "format": "json",
                "output_path": output_path,
                "error": str(e)
            })
            return False

    def _export_csv(self, output_path: str) -> bool:
        """Export timeline to CSV format."""
        try:
            # Prepare events for CSV export
            events_dict = [event.to_dict() for event in self.events]

            # Determine all unique field names
            all_fields = set()
            for event in events_dict:
                all_fields.update(event.keys())

            # Prioritize standard fields
            fieldnames = []
            standard_fields = ['timestamp', 'description', 'source', 'event_type', 'actor', 'severity', 'evidence_reference']
            for field in standard_fields:
                if field in all_fields:
                    fieldnames.append(field)
                    all_fields.remove(field)

            # Add remaining fields
            fieldnames.extend(sorted(all_fields))

            # Write CSV file
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(events_dict)

            log_forensic_operation("export_timeline", True, {
                "format": "csv",
                "output_path": output_path,
                "event_count": len(self.events),
                "incident_id": self.incident_id
            })

            return True

        except Exception as e:
            logger.error(f"Error exporting timeline to CSV: {e}")
            log_forensic_operation("export_timeline", False, {
                "format": "csv",
                "output_path": output_path,
                "error": str(e)
            })
            return False

    def _export_html(self, output_path: str) -> bool:
        """Export timeline to HTML format."""
        try:
            # Get events as dictionaries
            events_dict = [event.to_dict() for event in self.events]

            # Create HTML template
            html = self._generate_html_timeline(events_dict)

            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)

            log_forensic_operation("export_timeline", True, {
                "format": "html",
                "output_path": output_path,
                "event_count": len(self.events),
                "incident_id": self.incident_id
            })

            return True

        except Exception as e:
            logger.error(f"Error exporting timeline to HTML: {e}")
            log_forensic_operation("export_timeline", False, {
                "format": "html",
                "output_path": output_path,
                "error": str(e)
            })
            return False

    def _export_markdown(self, output_path: str) -> bool:
        """Export timeline to markdown format."""
        try:
            # Generate markdown table headers
            md_lines = [
                f"# {self.name}",
                "",
                f"**Incident ID:** {self.incident_id or 'N/A'}",
                f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                f"**Event Count:** {len(self.events)}",
                "",
                "## Event Timeline",
                "",
                "| Timestamp | Event Type | Description | Source | Actor | Evidence |",
                "|-----------|------------|-------------|--------|-------|----------|",
            ]

            # Add each event as a row
            for event in self.events:
                # Format timestamp
                ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

                # Create markdown table row
                row = f"| {ts} | {event.event_type or ''} | {event.description} | {event.source or ''} | {event.actor or ''} | {event.evidence_reference or ''} |"
                md_lines.append(row)

            # Add metadata section
            md_lines.extend([
                "",
                "## Timeline Metadata",
                "",
                f"* **Name:** {self.name}",
                f"* **Description:** {self.description}",
                f"* **Created:** {self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                f"* **Last Updated:** {self.updated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                f"* **Time Range:** {self.metadata['time_range']['start']} to {self.metadata['time_range']['end']}",
                "",
                "### Sources",
                ""
            ])

            # Add sources
            for source in self.sources:
                md_lines.append(f"* {source}")

            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(md_lines))

            log_forensic_operation("export_timeline", True, {
                "format": "markdown",
                "output_path": output_path,
                "event_count": len(self.events),
                "incident_id": self.incident_id
            })

            return True

        except Exception as e:
            logger.error(f"Error exporting timeline to markdown: {e}")
            log_forensic_operation("export_timeline", False, {
                "format": "markdown",
                "output_path": output_path,
                "error": str(e)
            })
            return False

    def _generate_html_timeline(self, events: List[Dict[str, Any]]) -> str:
        """Generate HTML timeline."""
        # Create basic HTML template with CSS for timeline visualization
        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            f"<title>{self.name}</title>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }",
            ".container { max-width: 1200px; margin: 0 auto; }",
            ".metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }",
            ".timeline { position: relative; max-width: 1200px; margin: 20px auto; }",
            ".timeline::after { content: ''; position: absolute; width: 6px; background-color: #999; top: 0; bottom: 0; left: 50%; margin-left: -3px; }",
            ".event { padding: 10px 40px; position: relative; background-color: inherit; width: 45%; }",
            ".event::after { content: ''; position: absolute; width: 20px; height: 20px; right: -10px; background-color: white; border: 4px solid #999; border-radius: 50%; z-index: 1; top: 15px; }",
            ".event-left { left: 0; }",
            ".event-right { left: 55%; }",
            ".event-left::after { right: -12px; }",
            ".event-right::after { left: -12px; }",
            ".event-content { padding: 20px; background-color: white; position: relative; border-radius: 6px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }",
            ".timestamp { font-weight: bold; color: #666; }",
            ".description { margin: 10px 0; }",
            ".event-high { border-left: 5px solid #dc3545; }",
            ".event-medium { border-left: 5px solid #fd7e14; }",
            ".event-low { border-left: 5px solid #28a745; }",
            ".details { font-size: 0.9em; color: #666; margin-top: 10px; }",
            ".source { font-style: italic; font-size: 0.8em; color: #666; }",
            ".actor { font-weight: bold; }",
            ".evidence { font-family: monospace; font-size: 0.9em; }",
            "@media screen and (max-width: 600px) {",
            "  .timeline::after { left: 31px; }",
            "  .event { width: 100%; padding-left: 70px; padding-right: 25px; }",
            "  .event::after { left: 15px; }",
            "  .event-left::after { left: 15px; }",
            "  .event-right::after { left: 15px; }",
            "  .event-right { left: 0; }",
            "}",
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            f"<h1>{self.name}</h1>",
            f"<p>{self.description}</p>",
            "<div class='metadata'>",
            f"<p><strong>Incident ID:</strong> {self.incident_id or 'N/A'}</p>",
            f"<p><strong>Event Count:</strong> {len(events)}</p>",
            f"<p><strong>Time Range:</strong> {self.metadata['time_range']['start']} to {self.metadata['time_range']['end']}</p>",
            f"<p><strong>Generated:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>",
            "</div>",
            "<div class='timeline'>"
        ]

        # Add each event to the timeline
        for i, event in enumerate(events):
            position = "event-left" if i % 2 == 0 else "event-right"

            # Determine severity class
            severity_class = ""
            severity = event.get("severity", "").lower()
            if severity == "high":
                severity_class = " event-high"
            elif severity == "medium":
                severity_class = " event-medium"
            elif severity == "low":
                severity_class = " event-low"

            # Format timestamp
            timestamp = event.get("timestamp", "")
            if timestamp and timestamp.endswith("Z"):
                timestamp = timestamp[:-1]  # Remove 'Z' suffix

            try:
                ts = datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                ts = timestamp

            html.extend([
                f"<div class='event {position}{severity_class}'>",
                "<div class='event-content'>",
                f"<div class='timestamp'>{ts}</div>",
                f"<div class='description'>{event.get('description', '')}</div>",
                "<div class='details'>"
            ])

            # Add event details
            if event.get("event_type"):
                html.append(f"<p><strong>Type:</strong> {event.get('event_type')}</p>")
            if event.get("actor"):
                html.append(f"<p><strong>Actor:</strong> <span class='actor'>{event.get('actor')}</span></p>")
            if event.get("source"):
                html.append(f"<p><strong>Source:</strong> <span class='source'>{event.get('source')}</span></p>")
            if event.get("evidence_reference"):
                html.append(f"<p><strong>Evidence:</strong> <span class='evidence'>{event.get('evidence_reference')}</span></p>")
            if event.get("severity"):
                html.append(f"<p><strong>Severity:</strong> {event.get('severity')}</p>")

            # Add any additional attributes
            for key, value in event.items():
                if key not in ["timestamp", "description", "source", "event_type", "actor", "severity", "evidence_reference"]:
                    html.append(f"<p><strong>{key}:</strong> {value}</p>")

            html.extend([
                "</div>",
                "</div>",
                "</div>"
            ])

        # Close HTML
        html.extend([
            "</div>",
            "</div>",
            "</body>",
            "</html>"
        ])

        return "\n".join(html)


def _json_serializer(obj):
    """
    Handle serialization of special objects to JSON.

    Args:
        obj: The object to serialize

    Returns:
        JSON-serializable representation of the object

    Raises:
        TypeError: If the object cannot be serialized
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


def analyze_timeline(
    timeline: Union[Timeline, str],
    output_path: Optional[str] = None,
    analysis_types: Optional[List[str]] = None,
    incident_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyze a timeline to identify patterns, anomalies, and key events.

    This function performs various types of analysis on timeline data including:
    - Anomaly detection (time gaps, unusual activity bursts)
    - Pattern recognition (repeated event sequences)
    - Key event identification (high severity, privileged actions)
    - Timeline segmentation (identifying distinct phases)

    Args:
        timeline: Timeline object or path to timeline file
        output_path: Optional path to save analysis results
        analysis_types: List of analysis types to perform (default: all available)
        incident_id: Optional incident ID for result tracking

    Returns:
        Dict with analysis results including identified patterns and anomalies

    Example:
        >>> result = analyze_timeline(
        ...     timeline="/secure/evidence/incident-2023-001/timeline.json",
        ...     output_path="/secure/evidence/incident-2023-001/timeline-analysis.json",
        ...     analysis_types=["anomalies", "patterns"]
        ... )
        >>> print(f"Found {result['anomaly_count']} anomalies in timeline")
    """
    # Default analysis types if none provided
    all_analysis_types = ["anomalies", "patterns", "key_events", "phases"]
    if analysis_types is None:
        analysis_types = all_analysis_types
    else:
        # Validate provided analysis types
        for analysis_type in analysis_types:
            if analysis_type not in all_analysis_types:
                logger.warning(f"Unsupported analysis type: {analysis_type}")

    # Initialize result structure
    result = {
        "success": False,
        "incident_id": incident_id,
        "output_path": output_path,
        "status": "initialized",
        "errors": [],
        "anomalies": [],
        "patterns": [],
        "key_events": [],
        "phases": [],
        "analysis_types": analysis_types,
        "statistics": {}
    }

    try:
        # Load timeline if it's a file path
        if isinstance(timeline, str):
            loaded_timeline = _load_timeline_file(timeline)
            if not loaded_timeline:
                result["errors"].append(f"Failed to load timeline from {timeline}")
                result["status"] = "failed_to_load"
                return result
            timeline = loaded_timeline

        # Set incident ID from timeline if not provided
        if not incident_id and timeline.incident_id:
            result["incident_id"] = timeline.incident_id

        # Ensure timeline has events
        if not timeline.events:
            result["errors"].append("Timeline contains no events to analyze")
            result["status"] = "no_events"
            return result

        # Make sure events are sorted
        timeline.sort_events()

        # Track operation details for logging
        operation_details = {
            "timeline_name": timeline.name,
            "incident_id": result["incident_id"],
            "event_count": len(timeline.events),
            "analysis_types": analysis_types
        }

        # Perform selected analyses
        if "anomalies" in analysis_types:
            anomaly_result = identify_timeline_anomalies(timeline)
            if anomaly_result["success"]:
                result["anomalies"] = anomaly_result["anomalies"]
                result["statistics"].update(anomaly_result.get("time_statistics", {}))
            else:
                result["errors"].extend(anomaly_result.get("errors", []))

        if "patterns" in analysis_types:
            patterns = _identify_event_patterns(timeline)
            result["patterns"] = patterns
            result["statistics"]["pattern_count"] = len(patterns)

        if "key_events" in analysis_types:
            key_events = _identify_key_events(timeline)
            result["key_events"] = key_events
            result["statistics"]["key_event_count"] = len(key_events)

        if "phases" in analysis_types:
            phases = _identify_timeline_phases(timeline)
            result["phases"] = phases
            result["statistics"]["phase_count"] = len(phases)

        # Update counts for result summary
        result["anomaly_count"] = len(result["anomalies"])
        result["pattern_count"] = len(result["patterns"])
        result["key_event_count"] = len(result["key_events"])
        result["phase_count"] = len(result["phases"])
        result["event_count"] = len(timeline.events)

        # Add basic timeline statistics
        if timeline.events:
            result["statistics"]["time_range"] = {
                "start": timeline.events[0].timestamp.isoformat(),
                "end": timeline.events[-1].timestamp.isoformat()
            }

            # Calculate total timeline duration in seconds
            start_time = timeline.events[0].timestamp
            end_time = timeline.events[-1].timestamp
            duration = (end_time - start_time).total_seconds()
            result["statistics"]["duration_seconds"] = duration

            # Count events by source
            source_counts = {}
            for event in timeline.events:
                source = event.source or "unknown"
                source_counts[source] = source_counts.get(source, 0) + 1
            result["statistics"]["sources"] = source_counts

            # Count events by type if available
            if any(event.event_type for event in timeline.events):
                type_counts = {}
                for event in timeline.events:
                    event_type = event.event_type or "unknown"
                    type_counts[event_type] = type_counts.get(event_type, 0) + 1
                result["statistics"]["event_types"] = type_counts

            # Count events by severity if available
            if any(event.severity for event in timeline.events):
                severity_counts = {}
                for event in timeline.events:
                    severity = event.severity or "unknown"
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                result["statistics"]["severities"] = severity_counts

        # Export result if output path provided
        if output_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, default=_json_serializer)
                result["status"] = "exported"
            except Exception as e:
                result["errors"].append(f"Failed to export analysis results: {str(e)}")
        else:
            result["status"] = "analyzed"

        # Set success flag based on errors
        result["success"] = len(result["errors"]) == 0

        # Log operation
        log_forensic_operation(
            "analyze_timeline",
            result["success"],
            {
                **operation_details,
                "anomaly_count": result["anomaly_count"],
                "pattern_count": result["pattern_count"],
                "key_event_count": result["key_event_count"],
                "phase_count": result["phase_count"],
                "output_path": output_path
            }
        )

        return result

    except Exception as e:
        logger.error(f"Failed to analyze timeline: {e}", exc_info=True)
        result["errors"].append(f"Error analyzing timeline: {str(e)}")
        result["status"] = "failed"

        # Log operation
        log_forensic_operation(
            "analyze_timeline",
            False,
            {
                "timeline": getattr(timeline, "name", str(timeline)),
                "analysis_types": analysis_types,
                "output_path": output_path,
                "error": str(e)
            }
        )

        return result


def _identify_event_patterns(timeline: Timeline) -> List[Dict[str, Any]]:
    """
    Identify recurring patterns in the event sequence.

    Args:
        timeline: Timeline to analyze

    Returns:
        List of identified event patterns
    """
    patterns = []

    # Skip if fewer than 3 events (minimum needed for a pattern)
    if len(timeline.events) < 3:
        return patterns

    try:
        # Look for repeated sequences of event types
        event_types = []
        for event in timeline.events:
            event_type = event.event_type or "unknown"
            event_types.append(event_type)

        # Look for patterns of length 2-5 events
        for pattern_length in range(2, min(6, len(event_types) // 2)):
            pattern_candidates = {}

            # Find all potential patterns
            for i in range(len(event_types) - pattern_length + 1):
                pattern = tuple(event_types[i:i+pattern_length])

                if pattern not in pattern_candidates:
                    pattern_candidates[pattern] = []
                pattern_candidates[pattern].append(i)

            # Keep patterns that appear multiple times
            for pattern, positions in pattern_candidates.items():
                if len(positions) >= 2:
                    # Get the actual events for each occurrence
                    occurrences = []
                    for pos in positions:
                        events_in_pattern = timeline.events[pos:pos+pattern_length]
                        occurrence = {
                            "start_index": pos,
                            "events": [e.to_dict() for e in events_in_pattern],
                            "start_time": events_in_pattern[0].timestamp.isoformat(),
                            "end_time": events_in_pattern[-1].timestamp.isoformat()
                        }
                        occurrences.append(occurrence)

                    # Add to results
                    patterns.append({
                        "pattern_id": f"pattern-{len(patterns)+1}",
                        "pattern_length": pattern_length,
                        "event_types": list(pattern),
                        "occurrence_count": len(positions),
                        "occurrences": occurrences,
                        "confidence": "high" if len(positions) > 2 else "medium"
                    })

    except Exception as e:
        logger.warning(f"Error identifying event patterns: {e}")

    return patterns


def _identify_key_events(timeline: Timeline) -> List[Dict[str, Any]]:
    """
    Identify key events in the timeline based on severity and event type.

    Args:
        timeline: Timeline to analyze

    Returns:
        List of key events with their significance
    """
    key_events = []

    # Skip if no events
    if not timeline.events:
        return key_events

    try:
        # High-impact events are those with high severity or specific event types
        high_impact_types = [
            "privilege_escalation", "data_exfiltration", "malware_execution",
            "authentication_bypass", "lateral_movement", "defense_evasion"
        ]

        # First and last events are always key events
        if timeline.events:
            first_event = timeline.events[0]
            key_events.append({
                "event_id": getattr(first_event, "id", f"event-{0}"),
                "index": 0,
                "event": first_event.to_dict(),
                "significance": "first_event",
                "description": "First event in timeline"
            })

            last_event = timeline.events[-1]
            key_events.append({
                "event_id": getattr(last_event, "id", f"event-{len(timeline.events)-1}"),
                "index": len(timeline.events) - 1,
                "event": last_event.to_dict(),
                "significance": "last_event",
                "description": "Last event in timeline"
            })

        # Identify other key events
        for i, event in enumerate(timeline.events):
            # Skip first and last which we've already added
            if i == 0 or i == len(timeline.events) - 1:
                continue

            # Check if this is a high-severity event
            if event.severity and event.severity.lower() in ("critical", "high"):
                key_events.append({
                    "event_id": getattr(event, "id", f"event-{i}"),
                    "index": i,
                    "event": event.to_dict(),
                    "significance": "high_severity",
                    "description": f"High severity event ({event.severity})"
                })

            # Check if this is a high-impact event type
            if event.event_type and any(impact_type in event.event_type.lower()
                                       for impact_type in high_impact_types):
                key_events.append({
                    "event_id": getattr(event, "id", f"event-{i}"),
                    "index": i,
                    "event": event.to_dict(),
                    "significance": "high_impact_type",
                    "description": f"High-impact event type: {event.event_type}"
                })

            # Check for events with evidence references
            if event.evidence_reference:
                key_events.append({
                    "event_id": getattr(event, "id", f"event-{i}"),
                    "index": i,
                    "event": event.to_dict(),
                    "significance": "has_evidence",
                    "description": "Event with evidence reference"
                })

    except Exception as e:
        logger.warning(f"Error identifying key events: {e}")

    return key_events


def _identify_timeline_phases(timeline: Timeline) -> List[Dict[str, Any]]:
    """
    Split the timeline into logical phases or segments.

    Args:
        timeline: Timeline to analyze

    Returns:
        List of identified phases with their events
    """
    phases = []

    # Skip if no events
    if not timeline.events:
        return phases

    try:
        # Simple phase detection based on time gaps
        if len(timeline.events) >= 2:
            # Calculate time differences between consecutive events
            time_diffs = []
            for i in range(len(timeline.events) - 1):
                try:
                    current = timeline.events[i].timestamp
                    next_event = timeline.events[i + 1].timestamp
                    diff_seconds = (next_event - current).total_seconds()
                    time_diffs.append(diff_seconds)
                except Exception:
                    time_diffs.append(None)

            # Remove None values
            valid_diffs = [d for d in time_diffs if d is not None]

            if not valid_diffs:
                # Can't detect phases without valid time differences
                return phases

            # Calculate statistics for time differences
            mean_diff = sum(valid_diffs) / len(valid_diffs)
            std_dev = (sum((x - mean_diff) ** 2 for x in valid_diffs) / len(valid_diffs)) ** 0.5

            # Define a significant gap as mean + 2*std_dev
            significant_gap = mean_diff + (2 * std_dev)

            # Identify phase boundaries based on significant gaps
            phase_boundaries = [0]  # Start with the first event

            for i, diff in enumerate(time_diffs):
                if diff is not None and diff > significant_gap:
                    phase_boundaries.append(i + 1)  # Add the index after the gap

            phase_boundaries.append(len(timeline.events))  # Add the end boundary

            # Create phases from the boundaries
            for i in range(len(phase_boundaries) - 1):
                start_idx = phase_boundaries[i]
                end_idx = phase_boundaries[i + 1]

                if end_idx - start_idx > 0:
                    phase_events = timeline.events[start_idx:end_idx]
                    start_time = phase_events[0].timestamp
                    end_time = phase_events[-1].timestamp

                    # Try to determine phase type based on events
                    phase_type = _determine_phase_type(phase_events)

                    # Create phase record
                    phases.append({
                        "phase_id": f"phase-{i+1}",
                        "start_index": start_idx,
                        "end_index": end_idx - 1,
                        "event_count": len(phase_events),
                        "time_range": {
                            "start": start_time.isoformat(),
                            "end": end_time.isoformat()
                        },
                        "duration_seconds": (end_time - start_time).total_seconds(),
                        "phase_type": phase_type,
                        "events": [e.to_dict() for e in phase_events]
                    })

    except Exception as e:
        logger.warning(f"Error identifying timeline phases: {e}")

    return phases


def _determine_phase_type(events: List[Event]) -> str:
    """
    Try to determine the phase type based on the events.

    Args:
        events: List of events in the phase

    Returns:
        Phase type identifier
    """
    # Check for predominant event types
    type_counts = {}
    for event in events:
        if event.event_type:
            event_type = event.event_type.lower()
            type_counts[event_type] = type_counts.get(event_type, 0) + 1

    if not type_counts:
        return "unknown"

    # Get the most common event type
    most_common_type, count = max(type_counts.items(), key=lambda x: x[1])

    # Map common event types to phase types
    phase_type_mapping = {
        "reconnaissance": "recon",
        "scanning": "recon",
        "discovery": "recon",
        "initial_access": "initial_access",
        "execution": "execution",
        "privilege_escalation": "privilege_escalation",
        "defense_evasion": "defense_evasion",
        "credential_access": "credential_access",
        "lateral_movement": "lateral_movement",
        "persistence": "persistence",
        "collection": "collection",
        "exfiltration": "exfiltration",
        "impact": "impact",
        "containment": "containment",
        "eradication": "eradication",
        "recovery": "recovery"
    }

    # Check if the event type maps to a phase type
    for key, value in phase_type_mapping.items():
        if key in most_common_type:
            return value

    return "activity"


def build_timeline(
    incident_id: str,
    sources: Optional[Union[str, List[str]]] = None,
    events: Optional[List[Dict[str, Any]]] = None,
    output_path: Optional[str] = None,
    output_format: str = DEFAULT_OUTPUT_FORMAT,
    name: Optional[str] = None,
    description: Optional[str] = None
) -> Union[Timeline, Dict[str, Any]]:
    """
    Build a timeline from various sources of events.

    This is the main function exposed by the timeline_builder module. It creates a timeline
    from sources like log files, alerts, system events, or user-provided event data.

    Args:
        incident_id: ID of the incident for the timeline
        sources: Source files or source IDs to collect events from
        events: Pre-formatted event dictionaries to include
        output_path: Path to save the timeline output file
        output_format: Format to export the timeline in (json, csv, html, markdown)
        name: Custom name for the timeline
        description: Description of the timeline

    Returns:
        Timeline object or dict with status and summary

    Example:
        >>> timeline = build_timeline(
        ...     incident_id="INC-2023-001",
        ...     sources=["/var/log/auth.log", "/var/log/apache2/access.log"],
        ...     output_path="/secure/evidence/INC-2023-001/timeline.json"
        ... )
    """
    # Create a result dict to track the build process
    result = {
        "incident_id": incident_id,
        "success": False,
        "errors": [],
        "event_count": 0,
        "status": "initialized",
        "output_path": output_path,
        "output_format": output_format
    }

    try:
        # Initialize logging
        operation_details = {
            "incident_id": incident_id,
            "output_format": output_format
        }
        if output_path:
            operation_details["output_path"] = output_path

        sanitized_id = sanitize_incident_id(incident_id)
        timeline_name = name or f"Timeline for Incident {incident_id}"
        timeline_description = description or f"Security incident timeline for {incident_id}"

        # Create timeline
        timeline = Timeline(name=timeline_name, incident_id=sanitized_id, description=timeline_description)

        # Add events if provided
        if events:
            for event in events:
                timeline.add_event(event)

        # Add events from sources if provided
        if sources:
            source_list = [sources] if isinstance(sources, str) else sources
            for source in source_list:
                try:
                    timeline = _process_source(timeline, source)
                except Exception as e:
                    logger.warning(f"Failed to process source {source}: {e}")
                    result["errors"].append(f"Error processing source {source}: {str(e)}")

        # Update result with event count
        result["event_count"] = len(timeline.events)
        result["status"] = "built"

        # Export if output path provided
        if output_path and len(timeline.events) > 0:
            export_success = timeline.export(output_path, output_format)
            if export_success:
                result["status"] = "exported"
            else:
                result["errors"].append(f"Failed to export timeline to {output_path}")

        # Set success status
        result["success"] = len(result["errors"]) == 0

        # Log the operation
        log_forensic_operation(
            "build_timeline",
            result["success"],
            {
                **operation_details,
                "event_count": result["event_count"],
                "sources": sources,
                "errors": result["errors"] if result["errors"] else None
            }
        )

        # Return timeline object or result dict based on success
        if result["success"]:
            return timeline
        else:
            return result

    except Exception as e:
        logger.error(f"Failed to build timeline: {e}", exc_info=True)
        result["errors"].append(f"Error building timeline: {str(e)}")
        result["status"] = "failed"

        # Log the operation
        log_forensic_operation(
            "build_timeline",
            False,
            {
                "incident_id": incident_id,
                "output_format": output_format,
                "output_path": output_path,
                "error": str(e)
            }
        )

        return result


def _process_source(timeline: Timeline, source: str) -> Timeline:
    """
    Process a source to extract events and add them to the timeline.

    Args:
        timeline: Timeline object to add events to
        source: Source to process (file path or source ID)

    Returns:
        Updated Timeline object
    """
    # Check if source is a file
    if os.path.isfile(source):
        # Add source file to metadata
        timeline.metadata["source_files"].append(source)

        # Determine file type by extension
        _, ext = os.path.splitext(source)
        ext = ext.lower()

        if ext == '.json':
            _process_json_file(timeline, source)
        elif ext == '.csv':
            _process_csv_file(timeline, source)
        elif ext in ['.log', '.txt']:
            _process_log_file(timeline, source)
        else:
            logger.warning(f"Unsupported file type: {ext}")

    elif os.path.isdir(source):
        # Process directory
        for root, _, files in os.walk(source):
            for file in files:
                file_path = os.path.join(root, file)
                _process_source(timeline, file_path)

    else:
        # Not a file or directory, assume it's a source ID
        logger.debug(f"Source {source} is not a file or directory, assuming it's a source ID")

    return timeline


def _process_json_file(timeline: Timeline, file_path: str):
    """Process a JSON file containing event data."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check if this is a standard timeline export
        if isinstance(data, dict) and 'events' in data:
            events = data['events']
        elif isinstance(data, list):
            events = data
        else:
            logger.warning(f"JSON file doesn't contain expected events structure: {file_path}")
            return

        # Add events to timeline
        for event in events:
            if not isinstance(event, dict):
                continue

            # Ensure event has required fields
            if 'timestamp' not in event or 'description' not in event:
                continue

            # Add source if not present
            if 'source' not in event:
                event['source'] = os.path.basename(file_path)

            # Add event to timeline
            timeline.add_event(event)

    except Exception as e:
        logger.warning(f"Failed to process JSON file {file_path}: {e}")


def _process_csv_file(timeline: Timeline, file_path: str):
    """Process a CSV file containing event data."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                # Ensure event has required fields
                if 'timestamp' not in row or 'description' not in row:
                    continue

                # Add source if not present
                if 'source' not in row:
                    row['source'] = os.path.basename(file_path)

                # Add event to timeline
                timeline.add_event(row)

    except Exception as e:
        logger.warning(f"Failed to process CSV file {file_path}: {e}")


def _process_log_file(timeline: Timeline, file_path: str):
    """
    Process a log file to extract events.

    This is a simplified log parser that tries to extract timestamps and messages.
    For more sophisticated log parsing, use the extract_timeline_from_logs function
    from the forensic module if available.
    """
    # First try to use the forensic module if available
    if FORENSIC_UTILS_AVAILABLE:
        try:
            forensic_timeline = forensic_extract_from_logs(file_path)
            if forensic_timeline:
                for event in forensic_timeline.events:
                    timeline.add_event(event.to_dict() if hasattr(event, 'to_dict') else event)
                return
        except Exception as e:
            logger.debug(f"Failed to use forensic extract_from_logs: {e}")

    # Fallback to basic log parsing
    source = os.path.basename(file_path)
    regex_patterns = [
        # ISO 8601 with timezone
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z))\s+(.+)',
        # ISO 8601 without timezone
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(.+)',
        # Common format with date and time
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(.+)',
        # Syslog format
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)',
        # Common log format
        r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\s+(.+)',
    ]

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                # Try each pattern
                for pattern in regex_patterns:
                    match = re.search(pattern, line)
                    if match:
                        timestamp = match.group(1)
                        description = match.groups()[-1]

                        # Create event
                        try:
                            timeline.add_event({
                                'timestamp': timestamp,
                                'description': description,
                                'source': source,
                                'source_line': i
                            })
                        except Exception as e:
                            logger.debug(f"Skipping line {i} due to error: {e}")

                        break

    except Exception as e:
        logger.warning(f"Failed to process log file {file_path}: {e}")


def extract_timeline_from_logs(
    log_files: Union[str, List[str]],
    output_path: Optional[str] = None,
    incident_id: Optional[str] = None,
    name: Optional[str] = None
) -> Union[Timeline, Dict[str, Any]]:
    """
    Extract a timeline from log files.

    This is a wrapper around the build_timeline function that specializes in
    extracting events from log files.

    Args:
        log_files: Path to log file or list of log file paths
        output_path: Path to save the timeline output file
        incident_id: ID of the incident for the timeline
        name: Custom name for the timeline

    Returns:
        Timeline object or dict with status and summary
    """
    # Generate incident_id if not provided
    if not incident_id:
        incident_id = f"LOGTL-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    # Set default name
    if not name:
        if isinstance(log_files, str):
            name = f"Log Timeline: {os.path.basename(log_files)}"
        else:
            name = f"Log Timeline: {len(log_files)} files"

    # Build timeline
    return build_timeline(
        incident_id=incident_id,
        sources=log_files,
        output_path=output_path,
        name=name,
        description=f"Timeline extracted from log files"
    )


def merge_timelines(
    timelines: List[Union[Timeline, str]],
    output_path: Optional[str] = None,
    incident_id: Optional[str] = None,
    name: Optional[str] = None
) -> Union[Timeline, Dict[str, Any]]:
    """
    Merge multiple timelines into a single timeline.

    Args:
        timelines: List of Timeline objects or paths to timeline files
        output_path: Path to save the merged timeline
        incident_id: ID of the incident for the merged timeline
        name: Custom name for the merged timeline

    Returns:
        Merged Timeline object or dict with status and summary
    """
    # Create result dictionary
    result = {
        "success": False,
        "incident_id": incident_id,
        "output_path": output_path,
        "errors": [],
        "status": "initialized",
        "timeline_count": len(timelines)
    }

    try:
        # Generate incident_id if not provided
        if not incident_id:
            incident_id = f"MERGED-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        else:
            incident_id = sanitize_incident_id(incident_id)

        # Set default name
        if not name:
            name = f"Merged Timeline: {incident_id}"

        # Create new timeline for the result
        merged_timeline = Timeline(
            name=name,
            incident_id=incident_id,
            description=f"Merged timeline from {len(timelines)} sources"
        )

        # Process each timeline
        for i, timeline in enumerate(timelines):
            # Load timeline if it's a file path
            if isinstance(timeline, str):
                if os.path.isfile(timeline):
                    loaded_timeline = _load_timeline_file(timeline)
                    if loaded_timeline:
                        timeline = loaded_timeline
                    else:
                        result["errors"].append(f"Failed to load timeline from {timeline}")
                        continue
                else:
                    result["errors"].append(f"Timeline file not found: {timeline}")
                    continue

            # Merge the timeline
            try:
                event_count = merged_timeline.merge(timeline)
                logger.debug(f"Added {event_count} events from timeline {i+1}")
            except Exception as e:
                result["errors"].append(f"Error merging timeline {i+1}: {str(e)}")

        # Export if output path provided
        if output_path and merged_timeline.events:
            export_success = merged_timeline.export(output_path)
            if export_success:
                result["status"] = "exported"
                result["event_count"] = len(merged_timeline.events)
            else:
                result["errors"].append(f"Failed to export merged timeline to {output_path}")
                result["status"] = "error_exporting"
        else:
            result["status"] = "merged"
            result["event_count"] = len(merged_timeline.events)

        # Set success flag
        result["success"] = len(merged_timeline.events) > 0 and len(result["errors"]) == 0

        # Log operation
        log_forensic_operation(
            "merge_timelines",
            result["success"],
            {
                "incident_id": incident_id,
                "timeline_count": len(timelines),
                "event_count": len(merged_timeline.events),
                "output_path": output_path,
                "errors": result["errors"] if result["errors"] else None
            }
        )

        # Return timeline or result based on success
        if result["success"]:
            return merged_timeline
        else:
            return result

    except Exception as e:
        logger.error(f"Failed to merge timelines: {e}", exc_info=True)
        result["errors"].append(f"Error merging timelines: {str(e)}")
        result["status"] = "failed"

        # Log operation
        log_forensic_operation(
            "merge_timelines",
            False,
            {
                "incident_id": incident_id,
                "timeline_count": len(timelines),
                "output_path": output_path,
                "error": str(e)
            }
        )

        return result


def _load_timeline_file(file_path: str) -> Optional[Timeline]:
    """
    Load a timeline from a file.

    Args:
        file_path: Path to the timeline file

    Returns:
        Timeline object or None if loading fails
    """
    if not os.path.isfile(file_path):
        logger.error(f"Timeline file not found: {file_path}")
        return None

    try:
        # Determine file type from extension
        file_ext = os.path.splitext(file_path)[1].lower()

        if file_ext == '.json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Check if this is a Timeline export
            if 'metadata' in data and 'events' in data:
                # Create timeline from exported data
                timeline = Timeline(
                    name=data.get('metadata', {}).get('name', "Imported Timeline"),
                    incident_id=data.get('metadata', {}).get('incident_id'),
                    description=data.get('metadata', {}).get('description', "Imported from file")
                )

                # Add events
                for event_data in data.get('events', []):
                    timeline.add_event(event_data)

                return timeline
            else:
                # Try to interpret as generic event data
                events = data if isinstance(data, list) else [data]
                timeline = Timeline(name=f"Timeline from {os.path.basename(file_path)}")

                for event_data in events:
                    timeline.add_event(event_data)

                return timeline

        elif file_ext == '.csv':
            timeline = Timeline(name=f"Timeline from {os.path.basename(file_path)}")
            _process_csv_file(timeline, file_path)
            return timeline

        else:
            # Try to process as a log file
            timeline = Timeline(name=f"Timeline from {os.path.basename(file_path)}")
            _process_log_file(timeline, file_path)
            return timeline

    except Exception as e:
        logger.error(f"Error loading timeline from {file_path}: {e}")
        return None


def create_template_timeline(
    incident_id: str,
    template_path: Optional[str] = None,
    output_path: Optional[str] = None,
    variables: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Create a timeline document from a template.

    Args:
        incident_id: ID of the incident
        template_path: Path to the template file
        output_path: Path to save the output file
        variables: Dictionary of variables to substitute in the template

    Returns:
        Dict with status information
    """
    result = {
        "success": False,
        "incident_id": incident_id,
        "template_path": template_path,
        "output_path": output_path,
        "status": "initialized",
        "errors": []
    }

    try:
        # Use default template if not specified
        if not template_path:
            templates_dir = IR_KIT_PATH / "templates"
            template_path = templates_dir / "incident_timeline.md"

        # Check if template exists
        if not os.path.isfile(template_path):
            result["errors"].append(f"Template file not found: {template_path}")
            result["status"] = "template_not_found"
            return result

        # Set default output path if not specified
        if not output_path:
            safe_id = sanitize_incident_id(incident_id)
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
            output_path = f"incident_timeline_{safe_id}_{timestamp}.md"

        # Default variables
        default_vars = {
            "INCIDENT_ID": incident_id,
            "CLASSIFICATION": "CONFIDENTIAL",
            "DATE": datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            "LAST_UPDATED": datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            "STATUS": "DRAFT",
            "DOCUMENT_VERSION": "1.0",
            "LEAD_RESPONDER": "Incident Response Team",
            "INITIAL_ENTRY": f"Incident initialized ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')})"
        }

        # Combine with provided variables
        if variables:
            default_vars.update(variables)

        # Read template
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()

        # Replace variables
        content = template_content
        for key, value in default_vars.items():
            content = content.replace(f"{{{{{key}}}}}", str(value))

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # Write output file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        result["success"] = True
        result["status"] = "created"
        result["output_path"] = output_path

        # Log operation
        log_forensic_operation(
            "create_template_timeline",
            True,
            {
                "incident_id": incident_id,
                "template_path": template_path,
                "output_path": output_path
            }
        )

        return result

    except Exception as e:
        logger.error(f"Failed to create template timeline: {e}", exc_info=True)
        result["errors"].append(f"Error creating template timeline: {str(e)}")
        result["status"] = "failed"

        # Log operation
        log_forensic_operation(
            "create_template_timeline",
            False,
            {
                "incident_id": incident_id,
                "template_path": template_path,
                "output_path": output_path,
                "error": str(e)
            }
        )

        return result


def correlate_timelines(
    timelines: List[Union[Timeline, str]],
    window_seconds: int = 300,
    output_path: Optional[str] = None,
    incident_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Correlate events across multiple timelines to find related events.

    Args:
        timelines: List of Timeline objects or paths to timeline files
        window_seconds: Time window to consider events related (in seconds)
        output_path: Path to save the correlation results
        incident_id: ID of the incident for the correlation

    Returns:
        Dict with correlation results
    """
    result = {
        "success": False,
        "incident_id": incident_id,
        "output_path": output_path,
        "window_seconds": window_seconds,
        "status": "initialized",
        "errors": [],
        "timeline_count": len(timelines),
        "correlated_clusters": []
    }

    try:
        # Generate incident_id if not provided
        if not incident_id:
            incident_id = f"CORR-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        # First merge all timelines
        merged_timeline = merge_timelines(timelines, incident_id=incident_id)
        if isinstance(merged_timeline, dict):
            # Merge failed
            return merged_timeline

        # Sort events by timestamp
        merged_timeline.sort_events()

        # Initialize clusters
        clusters = []
        current_cluster = []

        # Find event clusters within time window
        for event in merged_timeline.events:
            # Start a new cluster if needed
            if not current_cluster:
                current_cluster = [event]
                continue

            # Check time difference between this event and last event in cluster
            time_diff = (event.timestamp - current_cluster[-1].timestamp).total_seconds()

            if time_diff <= window_seconds:
                # Add to current cluster
                current_cluster.append(event)
            else:
                # Close current cluster if it has multiple events
                if len(current_cluster) > 1:
                    clusters.append(current_cluster)

                # Start new cluster
                current_cluster = [event]

        # Add final cluster if it has multiple events
        if len(current_cluster) > 1:
            clusters.append(current_cluster)

        # Process clusters to find events from different sources
        for i, cluster in enumerate(clusters):
            # Get unique sources in this cluster
            sources = set(event.source for event in cluster if event.source)

            # Only keep clusters with events from multiple sources
            if len(sources) > 1:
                # Add cluster to results
                correlation_cluster = CorrelationCluster(
                    cluster_id=f"cluster-{i+1}",
                    events=cluster,
                    time_window=window_seconds,
                    criteria="Events from multiple sources within time window",
                    description=f"Correlated events from {', '.join(sources)}"
                )
                result["correlated_clusters"].append(correlation_cluster.to_dict())

        # Export if output path provided
        if output_path and result["correlated_clusters"]:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "incident_id": incident_id,
                    "correlation_window": f"{window_seconds} seconds",
                    "timeline_count": len(timelines),
                    "total_events": len(merged_timeline.events),
                    "cluster_count": len(clusters),
                    "correlated_clusters": result["correlated_clusters"]
                }, f, indent=2, default=lambda obj: obj.isoformat() if isinstance(obj, datetime) else str(obj))

            result["status"] = "exported"
        else:
            result["status"] = "correlated"

        # Update result
        result["success"] = True
        result["total_events"] = len(merged_timeline.events)
        result["cluster_count"] = len(clusters)
        result["correlated_cluster_count"] = len(result["correlated_clusters"])

        # Log operation
        log_forensic_operation(
            "correlate_timelines",
            True,
            {
                "incident_id": incident_id,
                "timeline_count": len(timelines),
                "window_seconds": window_seconds,
                "total_events": len(merged_timeline.events),
                "cluster_count": len(clusters),
                "correlated_clusters": len(result["correlated_clusters"]),
                "output_path": output_path
            }
        )

        return result

    except Exception as e:
        logger.error(f"Failed to correlate timelines: {e}", exc_info=True)
        result["errors"].append(f"Error correlating timelines: {str(e)}")
        result["status"] = "failed"

        # Log operation
        log_forensic_operation(
            "correlate_timelines",
            False,
            {
                "incident_id": incident_id,
                "timeline_count": len(timelines),
                "window_seconds": window_seconds,
                "output_path": output_path,
                "error": str(e)
            }
        )

        return result


class TimelineSource:
    """
    Class representing a source of timeline events.

    This allows for tracking metadata and configuration about event sources
    such as log files, system monitoring tools, or manual entries.
    """

    def __init__(
        self,
        source_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        source_type: Optional[str] = None,
        parser_config: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize a timeline source.

        Args:
            source_id: Unique identifier for the source
            name: Human-readable name for the source
            description: Detailed description of the source
            source_type: Type of source (e.g., "log_file", "api", "manual")
            parser_config: Configuration for parsing events from this source
            **kwargs: Additional source attributes
        """
        self.source_id = source_id
        self.name = name or source_id
        self.description = description
        self.source_type = source_type
        self.parser_config = parser_config or {}
        self.attributes = kwargs
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the source to a dictionary."""
        source_dict = {
            'source_id': self.source_id,
            'name': self.name,
            'created_at': self.created_at.isoformat()
        }

        # Add optional fields if present
        if self.description:
            source_dict['description'] = self.description
        if self.source_type:
            source_dict['source_type'] = self.source_type
        if self.parser_config:
            source_dict['parser_config'] = self.parser_config

        # Add all additional attributes
        source_dict.update(self.attributes)

        return source_dict


class CorrelationCluster:
    """
    Class representing a cluster of correlated timeline events.

    This is used to group related events that occurred within a specific time window
    or match other correlation criteria.
    """

    def __init__(
        self,
        cluster_id: str,
        events: List[Event],
        time_window: Optional[int] = None,
        criteria: Optional[str] = None,
        description: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize a correlation cluster.

        Args:
            cluster_id: Unique identifier for the cluster
            events: List of Event objects in this cluster
            time_window: Time window in seconds used for correlation
            criteria: Description of the correlation criteria
            description: Detailed description of the cluster
            **kwargs: Additional cluster attributes
        """
        self.cluster_id = cluster_id
        self.events = events
        self.time_window = time_window
        self.criteria = criteria
        self.description = description
        self.attributes = kwargs

        # Automatically calculate time range
        self.start_time = min(event.timestamp for event in events) if events else None
        self.end_time = max(event.timestamp for event in events) if events else None

        # Get unique sources
        self.sources = list(set(event.source for event in events if event.source))

    def to_dict(self) -> Dict[str, Any]:
        """Convert the cluster to a dictionary."""
        cluster_dict = {
            'cluster_id': self.cluster_id,
            'event_count': len(self.events),
            'sources': self.sources
        }

        # Add time range if available
        if self.start_time and self.end_time:
            cluster_dict['time_range'] = {
                'start': self.start_time.isoformat(),
                'end': self.end_time.isoformat()
            }

        # Add optional fields if present
        if self.time_window:
            cluster_dict['time_window'] = self.time_window
        if self.criteria:
            cluster_dict['criteria'] = self.criteria
        if self.description:
            cluster_dict['description'] = self.description

        # Add event details
        cluster_dict['events'] = [event.to_dict() for event in self.events]

        # Add additional attributes
        cluster_dict.update(self.attributes)

        return cluster_dict


def identify_timeline_anomalies(timeline: Timeline) -> Dict[str, Any]:
    """
    Identify anomalies in a timeline such as unusual gaps or bursts of activity.

    Args:
        timeline: Timeline object to analyze

    Returns:
        Dict with anomalies found in the timeline
    """
    result = {
        "success": False,
        "incident_id": timeline.incident_id,
        "status": "initialized",
        "errors": [],
        "anomalies": []
    }

    try:
        # Need at least 2 events to detect anomalies
        if len(timeline.events) < 2:
            result["success"] = True
            result["status"] = "no_events"
            return result

        # Sort events
        timeline.sort_events()

        # Calculate time differences between events
        time_diffs = []
        for i in range(1, len(timeline.events)):
            try:
                curr_time = timeline.events[i].timestamp
                prev_time = timeline.events[i-1].timestamp
                diff_seconds = (curr_time - prev_time).total_seconds()
                time_diffs.append(diff_seconds)
            except (ValueError, TypeError):
                time_diffs.append(None)

        # Calculate statistics (ignoring None values)
        valid_diffs = [d for d in time_diffs if d is not None]
        if not valid_diffs:
            result["success"] = True
            result["status"] = "no_valid_diffs"
            return result

        mean_diff = sum(valid_diffs) / len(valid_diffs)
        std_dev = (sum((x - mean_diff) ** 2 for x in valid_diffs) / len(valid_diffs)) ** 0.5

        # Define anomaly threshold
        anomaly_threshold = 3.0  # Number of standard deviations to consider anomalous

        # Identify anomalies
        for i, diff in enumerate(time_diffs):
            if diff is None:
                continue

            if diff > mean_diff + (anomaly_threshold * std_dev):
                # Large gap before this event
                result["anomalies"].append({
                    "type": "time_gap",
                    "event_index": i + 1,
                    "prior_event_index": i,
                    "time_gap": diff,
                    "severity": "high" if diff > (3 * mean_diff) else "medium",
                    "description": f"Unusual gap of {int(diff)} seconds before event",
                    "prior_event_timestamp": timeline.events[i].timestamp.isoformat(),
                    "event_timestamp": timeline.events[i+1].timestamp.isoformat()
                })
            elif diff < mean_diff - (anomaly_threshold * std_dev) and diff < 1.0:
                # Burst of activity (events very close together)
                result["anomalies"].append({
                    "type": "activity_burst",
                    "event_index": i + 1,
                    "prior_event_index": i,
                    "time_gap": diff,
                    "severity": "medium",
                    "description": "Unusually rapid sequence of events",
                    "prior_event_timestamp": timeline.events[i].timestamp.isoformat(),
                    "event_timestamp": timeline.events[i+1].timestamp.isoformat()
                })

        # Look for suspicious sequences of events based on event types
        if any(event.event_type for event in timeline.events):
            for i in range(len(timeline.events) - 1):
                current_event = timeline.events[i]
                next_event = timeline.events[i+1]

                # Check for privilege escalation followed by suspicious activity
                if (current_event.event_type in ["privilege_escalation", "authentication"] and
                    next_event.event_type in ["access", "file_modification", "network_activity"]):

                    time_diff = (next_event.timestamp - current_event.timestamp).total_seconds()
                    if time_diff < 300:  # Within 5 minutes
                        result["anomalies"].append({
                            "type": "suspicious_sequence",
                            "event_indexes": [i, i+1],
                            "severity": "high",
                            "description": "Privilege elevation followed quickly by suspicious activity",
                            "events": [timeline.events[i].to_dict(), timeline.events[i+1].to_dict()]
                        })

        # Update result
        result["success"] = True
        result["status"] = "analyzed"
        result["anomaly_count"] = len(result["anomalies"])
        result["event_count"] = len(timeline.events)
        result["time_statistics"] = {
            "mean_interval": mean_diff,
            "std_dev": std_dev,
            "min_interval": min(valid_diffs),
            "max_interval": max(valid_diffs)
        }

        # Log operation
        log_forensic_operation(
            "identify_timeline_anomalies",
            True,
            {
                "incident_id": timeline.incident_id,
                "event_count": len(timeline.events),
                "anomaly_count": len(result["anomalies"])
            }
        )

        return result

    except Exception as e:
        logger.error(f"Failed to identify timeline anomalies: {e}", exc_info=True)
        result["errors"].append(f"Error identifying anomalies: {str(e)}")
        result["status"] = "failed"

        # Log operation
        log_forensic_operation(
            "identify_timeline_anomalies",
            False,
            {
                "incident_id": timeline.incident_id,
                "error": str(e)
            }
        )

        return result


# Main function entry point for running as script
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Timeline builder tool for security incident response")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create timeline parser
    create_parser = subparsers.add_parser("create", help="Create a new timeline")
    create_parser.add_argument("--incident-id", "-i", required=True, help="Incident ID")
    create_parser.add_argument("--sources", "-s", nargs="+", help="Source files or directories")
    create_parser.add_argument("--events", "-e", help="JSON file containing events")
    create_parser.add_argument("--output", "-o", help="Output file path")
    create_parser.add_argument("--format", "-f", choices=SUPPORTED_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                               help="Output format")
    create_parser.add_argument("--name", "-n", help="Timeline name")
    create_parser.add_argument("--description", "-d", help="Timeline description")

    # Extract from logs parser
    extract_parser = subparsers.add_parser("extract", help="Extract timeline from log files")
    extract_parser.add_argument("--logs", "-l", required=True, nargs="+", help="Log files to process")
    extract_parser.add_argument("--incident-id", "-i", help="Incident ID")
    extract_parser.add_argument("--output", "-o", help="Output file path")
    extract_parser.add_argument("--name", "-n", help="Timeline name")

    # Merge timelines parser
    merge_parser = subparsers.add_parser("merge", help="Merge multiple timelines")
    merge_parser.add_argument("--timelines", "-t", required=True, nargs="+", help="Timeline files to merge")
    merge_parser.add_argument("--incident-id", "-i", help="Incident ID")
    merge_parser.add_argument("--output", "-o", help="Output file path")
    merge_parser.add_argument("--name", "-n", help="Timeline name")

    # Correlate timelines parser
    correlate_parser = subparsers.add_parser("correlate", help="Correlate events across timelines")
    correlate_parser.add_argument("--timelines", "-t", required=True, nargs="+", help="Timeline files to correlate")
    correlate_parser.add_argument("--window", "-w", type=int, default=300,
                                  help="Time window in seconds")
    correlate_parser.add_argument("--incident-id", "-i", help="Incident ID")
    correlate_parser.add_argument("--output", "-o", help="Output file path")

    # Analyze timeline parser
    analyze_parser = subparsers.add_parser("analyze", help="Analyze timeline for anomalies")
    analyze_parser.add_argument("--timeline", "-t", required=True, help="Timeline file to analyze")
    analyze_parser.add_argument("--output", "-o", help="Output file path")

    # Create template parser
    template_parser = subparsers.add_parser("template", help="Create a timeline from a template")
    template_parser.add_argument("--incident-id", "-i", required=True, help="Incident ID")
    template_parser.add_argument("--template", "-t", help="Template file path")
    template_parser.add_argument("--output", "-o", help="Output file path")
    template_parser.add_argument("--vars", "-v", nargs="+", help="Template variables in KEY=VALUE format")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )

    try:
        if args.command == "create":
            # Load events from JSON file if provided
            events = None
            if args.events:
                with open(args.events, 'r', encoding='utf-8') as f:
                    events = json.load(f)

            # Create timeline
            result = build_timeline(
                incident_id=args.incident_id,
                sources=args.sources,
                events=events,
                output_path=args.output,
                output_format=args.format,
                name=args.name,
                description=args.description
            )

            if isinstance(result, dict) and not result["success"]:
                print(f"Error: {result['errors']}")
                sys.exit(1)

            print(f"Timeline created with {len(result.events if isinstance(result, Timeline) else [])} events")
            if args.output:
                print(f"Timeline exported to {args.output}")

        elif args.command == "extract":
            # Extract timeline from logs
            result = extract_timeline_from_logs(
                log_files=args.logs,
                output_path=args.output,
                incident_id=args.incident_id,
                name=args.name
            )

            if isinstance(result, dict) and not result["success"]:
                print(f"Error: {result['errors']}")
                sys.exit(1)

            print(f"Timeline extracted with {len(result.events if isinstance(result, Timeline) else [])} events")
            if args.output:
                print(f"Timeline exported to {args.output}")

        elif args.command == "merge":
            # Merge timelines
            result = merge_timelines(
                timelines=args.timelines,
                output_path=args.output,
                incident_id=args.incident_id,
                name=args.name
            )

            if isinstance(result, dict) and not result["success"]:
                print(f"Error: {result['errors']}")
                sys.exit(1)

            event_count = len(result.events) if isinstance(result, Timeline) else result.get("event_count", 0)
            print(f"Merged timeline contains {event_count} events")
            if args.output:
                print(f"Merged timeline exported to {args.output}")

        elif args.command == "correlate":
            # Correlate timelines
            result = correlate_timelines(
                timelines=args.timelines,
                window_seconds=args.window,
                output_path=args.output,
                incident_id=args.incident_id
            )

            if not result["success"]:
                print(f"Error: {result['errors']}")
                sys.exit(1)

            print(f"Found {result['correlated_cluster_count']} correlated event clusters")
            if args.output:
                print(f"Correlation results exported to {args.output}")

        elif args.command == "analyze":
            # Load timeline
            timeline = _load_timeline_file(args.timeline)
            if not timeline:
                print(f"Error: Failed to load timeline from {args.timeline}")
                sys.exit(1)

            # Analyze timeline
            result = identify_timeline_anomalies(timeline)

            if not result["success"]:
                print(f"Error: {result['errors']}")
                sys.exit(1)

            print(f"Found {result['anomaly_count']} anomalies in {result['event_count']} events")

            # Output results
            if args.output:
                os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, default=lambda obj: obj.isoformat() if isinstance(obj, datetime) else str(obj))
                print(f"Analysis results exported to {args.output}")
            else:
                # Print summary to console
                for i, anomaly in enumerate(result["anomalies"]):
                    print(f"\nAnomaly {i+1}: {anomaly['type']} - {anomaly['description']}")
                    print(f"  Severity: {anomaly['severity']}")
                    if "time_gap" in anomaly:
                        print(f"  Time gap: {anomaly['time_gap']} seconds")

        elif args.command == "template":
            # Parse variables
            variables = {}
            if args.vars:
                for var in args.vars:
                    if '=' in var:
                        key, value = var.split('=', 1)
                        variables[key] = value

            # Create template timeline
            result = create_template_timeline(
                incident_id=args.incident_id,
                template_path=args.template,
                output_path=args.output,
                variables=variables
            )

            if not result["success"]:
                print(f"Error: {result['errors']}")
                sys.exit(1)

            print(f"Template timeline created at {result['output_path']}")

    except Exception as e:
        print(f"Error: {str(e)}")
        logger.error(f"Command failed: {e}", exc_info=True)
        sys.exit(1)
