"""
Timeline Builder Module for Forensic Analysis Toolkit.

This module provides capabilities for creating, manipulating, and exporting timelines
of events during security incident investigations. It enables chronological analysis
of events across multiple data sources with consistent timestamp handling.

The timeline builder supports various input sources and can correlate events from
different systems to establish an accurate chronology of security incidents.
"""

import os
import json
import csv
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from pathlib import Path

# Initialize logger
logger = logging.getLogger(__name__)

# Try to import utility modules
try:
    from admin.security.forensics.utils.validation_utils import (
        validate_path, validate_timestamp
    )
    VALIDATION_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Validation utilities not available. Using basic validation.")
    VALIDATION_UTILS_AVAILABLE = False

    # Basic validation fallback
    def validate_path(path_str: str, **kwargs) -> Tuple[bool, str]:
        """Basic path validation (fallback implementation)."""
        if not os.path.exists(path_str):
            return False, f"Path does not exist: {path_str}"
        if kwargs.get('must_be_file') and not os.path.isfile(path_str):
            return False, f"Path is not a file: {path_str}"
        return True, "Path is valid"

    def validate_timestamp(timestamp: Union[str, int, float, datetime], **kwargs) -> Tuple[bool, str]:
        """Basic timestamp validation (fallback implementation)."""
        if isinstance(timestamp, (int, float)):
            return True, "Valid timestamp number"
        elif isinstance(timestamp, str):
            try:
                datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return True, "Valid timestamp string"
            except (ValueError, TypeError):
                return False, "Invalid timestamp format"
        elif isinstance(timestamp, datetime):
            return True, "Valid datetime object"
        return False, "Invalid timestamp type"

# Try to import timestamp utilities
try:
    from admin.security.forensics.utils.timestamp_utils import (
        normalize_timestamp,
        parse_timestamp,
        format_timestamp,
        create_timeline as normalize_timeline_timestamps
    )
    TIMESTAMP_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Timestamp utilities not available. Using basic timestamp handling.")
    TIMESTAMP_UTILS_AVAILABLE = False

    # Basic timestamp handling fallback
    def normalize_timestamp(timestamp: Union[str, int, float, datetime]) -> Optional[datetime]:
        """Normalize timestamp to datetime object (fallback implementation)."""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, (int, float)):
            try:
                return datetime.fromtimestamp(timestamp, timezone.utc)
            except (ValueError, OSError, OverflowError):
                return None
        elif isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except (ValueError, TypeError):
                return None
        return None

    def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string to datetime (fallback implementation)."""
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            return None

    def format_timestamp(dt: datetime, format_type: str = "iso8601") -> Optional[str]:
        """Format datetime object to string (fallback implementation)."""
        if not isinstance(dt, datetime):
            return None
        if format_type.lower() == "iso8601":
            return dt.isoformat()
        else:
            return dt.strftime("%Y-%m-%d %H:%M:%S")

    def normalize_timeline_timestamps(events: List[Dict], *args, **kwargs) -> List[Dict]:
        """Process timestamps in events (fallback implementation)."""
        return events

# Try to import logging utilities
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    LOGGING_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Forensic logging utilities not available. Using basic logging.")
    LOGGING_UTILS_AVAILABLE = False

    # Basic logging fallback
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        """Log a forensic operation (fallback implementation)."""
        msg = f"Forensic operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logging.log(level=level, msg=msg)

# Try to import report builder for visualization
try:
    from admin.security.forensics.utils.report_builder import create_timeline_chart
    CHART_AVAILABLE = True
except ImportError:
    logger.warning("Timeline chart generation not available.")
    CHART_AVAILABLE = False


class Timeline:
    """
    Timeline class for managing chronological events during forensic investigations.

    This class provides methods to add events, merge timelines, and export the timeline
    in various formats.
    """

    def __init__(self, name: str = "Forensic Timeline", description: str = "", case_id: Optional[str] = None):
        """
        Initialize a new timeline.

        Args:
            name: Name of the timeline
            description: Description of the timeline
            case_id: Optional case identifier
        """
        self.name = name
        self.description = description
        self.case_id = case_id
        self.events: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "source_files": [],
            "event_count": 0,
            "time_range": {
                "start": None,
                "end": None
            }
        }

    def add_event(self,
                 event: Union[Dict[str, Any], List[Dict[str, Any]]],
                 source: Optional[str] = None,
                 normalize_time: bool = True) -> int:
        """
        Add one or more events to the timeline.

        Args:
            event: Event dictionary or list of event dictionaries
            source: Source of the event(s)
            normalize_time: Whether to normalize timestamps to UTC

        Returns:
            Number of events added

        Raises:
            ValueError: If event doesn't have required fields
        """
        if isinstance(event, list):
            added_count = 0
            for e in event:
                try:
                    self._add_single_event(e, source, normalize_time)
                    added_count += 1
                except ValueError as err:
                    logger.warning(f"Skipping invalid event: {err}")

            # Update metadata
            self._update_metadata(added_count)
            return added_count
        else:
            self._add_single_event(event, source, normalize_time)
            self._update_metadata(1)
            return 1

    def _add_single_event(self,
                         event: Dict[str, Any],
                         source: Optional[str] = None,
                         normalize_time: bool = True) -> None:
        """
        Add a single event to the timeline.

        Args:
            event: Event dictionary
            source: Source of the event
            normalize_time: Whether to normalize timestamp to UTC

        Raises:
            ValueError: If event doesn't have required fields
        """
        # Validate event has required fields
        if not isinstance(event, dict):
            raise ValueError("Event must be a dictionary")

        if 'timestamp' not in event:
            raise ValueError("Event must have a timestamp field")

        if 'description' not in event:
            raise ValueError("Event must have a description field")

        # Make a copy to avoid modifying the original
        event_copy = event.copy()

        # Add source if provided
        if source and 'source' not in event_copy:
            event_copy['source'] = source

        # Normalize timestamp if requested
        if normalize_time:
            valid, msg = validate_timestamp(event_copy['timestamp'])
            if valid:
                # Convert timestamp to normalized datetime
                dt = normalize_timestamp(event_copy['timestamp'])
                if dt is not None:
                    # Keep original timestamp format in a separate field if it's not already a datetime
                    if not isinstance(event_copy['timestamp'], datetime):
                        event_copy['original_timestamp'] = event_copy['timestamp']
                    # Store normalized datetime
                    event_copy['timestamp'] = dt
                else:
                    logger.warning(f"Could not normalize timestamp: {event_copy['timestamp']}")
            else:
                logger.warning(f"Invalid timestamp: {msg}")

        # Ensure event has an ID if not present
        if 'id' not in event_copy:
            event_copy['id'] = f"evt-{len(self.events) + 1:06d}"

        # Add event
        self.events.append(event_copy)

    def _update_metadata(self, added_count: int = 0) -> None:
        """
        Update timeline metadata after adding events.

        Args:
            added_count: Number of events added
        """
        self.metadata["modified"] = datetime.now(timezone.utc).isoformat()
        self.metadata["event_count"] = len(self.events)

        # Update time range if there are events
        if self.events:
            # Sort events by timestamp first
            self._sort_events()

            # Get earliest and latest timestamps
            earliest, latest = self._get_time_range()

            # Update metadata time range
            if earliest:
                self.metadata["time_range"]["start"] = self._format_time_for_metadata(earliest)
            if latest:
                self.metadata["time_range"]["end"] = self._format_time_for_metadata(latest)

    def _format_time_for_metadata(self, dt: Union[datetime, str, int, float]) -> str:
        """Format timestamp for metadata."""
        if isinstance(dt, datetime):
            return dt.isoformat()
        elif isinstance(dt, (int, float)):
            try:
                return datetime.fromtimestamp(dt, timezone.utc).isoformat()
            except (ValueError, OSError, OverflowError):
                return str(dt)
        else:
            return str(dt)

    def _sort_events(self) -> None:
        """Sort timeline events chronologically by timestamp."""
        self.events.sort(key=lambda e:
                        normalize_timestamp(e['timestamp']) or
                        datetime.fromtimestamp(0, timezone.utc))

    def _get_time_range(self) -> Tuple[Any, Any]:
        """Get earliest and latest timestamps from events."""
        if not self.events:
            return None, None

        # Sort events if needed
        if len(self.events) > 1:
            self._sort_events()

        # Return first and last timestamps
        return self.events[0]['timestamp'], self.events[-1]['timestamp']

    def merge_timelines(self, other_timeline: 'Timeline') -> int:
        """
        Merge another timeline into this one.

        Args:
            other_timeline: Another Timeline object to merge

        Returns:
            Number of events added from the other timeline

        Raises:
            TypeError: If other_timeline is not a Timeline object
        """
        if not isinstance(other_timeline, Timeline):
            raise TypeError("Can only merge with another Timeline object")

        # Get current event count for calculating added events
        current_count = len(self.events)

        # Add events from other timeline
        for event in other_timeline.events:
            # Skip duplicates based on ID if present
            if 'id' in event and any(e.get('id') == event['id'] for e in self.events):
                continue

            # Copy the event to avoid modifying the original
            self.events.append(event.copy())

        # Add source files from other timeline to metadata
        if other_timeline.metadata.get('source_files'):
            for source in other_timeline.metadata['source_files']:
                if source not in self.metadata['source_files']:
                    self.metadata['source_files'].append(source)

        # Update metadata
        added_count = len(self.events) - current_count
        self._update_metadata(added_count)

        # Log the operation if available
        if LOGGING_UTILS_AVAILABLE:
            log_forensic_operation(
                "merge_timelines",
                True,
                {
                    "timeline_name": self.name,
                    "other_timeline": other_timeline.name,
                    "events_added": added_count,
                    "total_events": len(self.events),
                    "case_id": self.case_id
                }
            )

        return added_count

    def export_timeline(self,
                       output_path: str,
                       format_type: str = "json",
                       include_metadata: bool = True) -> bool:
        """
        Export the timeline to a file.

        Args:
            output_path: Path to save the exported timeline
            format_type: Export format (json, csv, html)
            include_metadata: Whether to include timeline metadata in the export

        Returns:
            True if export was successful, False otherwise
        """
        # Validate output path
        if VALIDATION_UTILS_AVAILABLE:
            valid, msg = validate_path(
                os.path.dirname(output_path) or '.',
                must_exist=True,
                check_write=True
            )
            if not valid:
                logger.error(f"Invalid output path: {msg}")
                return False

        # Create directories if they don't exist
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        # Prepare export data
        export_data = self.events.copy()

        # Sort events before export
        self._sort_events()

        # Operation details for logging
        operation_details = {
            "timeline_name": self.name,
            "format": format_type,
            "output_path": output_path,
            "event_count": len(self.events),
            "include_metadata": include_metadata,
            "case_id": self.case_id
        }

        try:
            # Export based on format type
            if format_type.lower() == "json":
                return self._export_json(output_path, include_metadata, operation_details)

            elif format_type.lower() == "csv":
                return self._export_csv(output_path, include_metadata, operation_details)

            elif format_type.lower() == "html":
                return self._export_html(output_path, operation_details)

            else:
                logger.error(f"Unsupported export format: {format_type}")
                if LOGGING_UTILS_AVAILABLE:
                    log_forensic_operation(
                        "export_timeline",
                        False,
                        {**operation_details, "error": f"Unsupported format: {format_type}"}
                    )
                return False

        except Exception as e:
            logger.error(f"Export failed: {str(e)}", exc_info=True)
            if LOGGING_UTILS_AVAILABLE:
                log_forensic_operation(
                    "export_timeline",
                    False,
                    {**operation_details, "error": str(e)}
                )
            return False

    def _export_json(self,
                    output_path: str,
                    include_metadata: bool,
                    operation_details: Dict[str, Any]) -> bool:
        """Export timeline to JSON format."""
        export_data = {
            "events": self._prepare_events_for_json()
        }

        if include_metadata:
            export_data["metadata"] = self.metadata.copy()
            export_data["metadata"]["name"] = self.name
            export_data["metadata"]["description"] = self.description
            export_data["metadata"]["case_id"] = self.case_id

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=self._json_serializer)

        if LOGGING_UTILS_AVAILABLE:
            log_forensic_operation("export_timeline", True, operation_details)

        return True

    def _prepare_events_for_json(self) -> List[Dict[str, Any]]:
        """Prepare events for JSON serialization."""
        json_events = []
        for event in self.events:
            # Make a copy to avoid modifying the original
            event_copy = event.copy()

            # Convert datetime objects to ISO strings
            for key, value in event_copy.items():
                if isinstance(value, datetime):
                    event_copy[key] = value.isoformat()

            json_events.append(event_copy)

        return json_events

    def _json_serializer(self, obj):
        """Handle serialization of custom types to JSON."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    def _export_csv(self,
                   output_path: str,
                   include_metadata: bool,
                   operation_details: Dict[str, Any]) -> bool:
        """Export timeline to CSV format."""
        # Prepare events for CSV export
        csv_events = self._prepare_events_for_csv()

        # Get all unique fields across all events
        all_fields = set()
        for event in csv_events:
            all_fields.update(event.keys())

        # Ensure required fields come first
        fieldnames = []
        for field in ['timestamp', 'description', 'source', 'id', 'severity', 'category']:
            if field in all_fields:
                fieldnames.append(field)
                all_fields.remove(field)

        # Add remaining fields
        fieldnames.extend(sorted(all_fields))

        # Write CSV file
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_events)

        # If metadata requested, create a separate metadata file
        if include_metadata:
            metadata_path = os.path.splitext(output_path)[0] + "_metadata.json"
            metadata = self.metadata.copy()
            metadata["name"] = self.name
            metadata["description"] = self.description
            metadata["case_id"] = self.case_id

            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, default=self._json_serializer)

        if LOGGING_UTILS_AVAILABLE:
            log_forensic_operation("export_timeline", True, operation_details)

        return True

    def _prepare_events_for_csv(self) -> List[Dict[str, Any]]:
        """Prepare events for CSV serialization."""
        csv_events = []
        for event in self.events:
            # Make a copy to avoid modifying the original
            event_copy = {}

            # Convert values to strings
            for key, value in event.items():
                if isinstance(value, datetime):
                    event_copy[key] = value.isoformat()
                elif isinstance(value, (dict, list)):
                    # Flatten complex structures for CSV
                    event_copy[key] = json.dumps(value)
                else:
                    event_copy[key] = value

            csv_events.append(event_copy)

        return csv_events

    def _export_html(self, output_path: str, operation_details: Dict[str, Any]) -> bool:
        """Export timeline to interactive HTML format."""
        # Check if chart generation is available
        if not CHART_AVAILABLE:
            logger.error("HTML export requires the report_builder module with chart generation")
            if LOGGING_UTILS_AVAILABLE:
                log_forensic_operation(
                    "export_timeline",
                    False,
                    {**operation_details, "error": "HTML chart generation not available"}
                )
            return False

        # Use chart generation from report_builder
        result = create_timeline_chart(
            self.events,
            output_path=output_path,
            chart_type="html",
            title=self.name,
            include_details=True
        )

        if result and LOGGING_UTILS_AVAILABLE:
            log_forensic_operation("export_timeline", True, operation_details)

        return bool(result)


# Define the public API
def create_timeline(name: str = "Forensic Timeline",
                   description: str = "",
                   case_id: Optional[str] = None) -> Timeline:
    """
    Create a new timeline for forensic analysis.

    Args:
        name: Name of the timeline
        description: Description of the timeline
        case_id: Optional case identifier

    Returns:
        Timeline object
    """
    timeline = Timeline(name, description, case_id)

    if LOGGING_UTILS_AVAILABLE:
        log_forensic_operation(
            "create_timeline",
            True,
            {
                "name": name,
                "case_id": case_id
            }
        )

    return timeline


def add_event(timeline: Timeline,
             event: Union[Dict[str, Any], List[Dict[str, Any]]],
             source: Optional[str] = None) -> int:
    """
    Add one or more events to a timeline.

    Args:
        timeline: Timeline object to add events to
        event: Event or list of events to add
        source: Source of the events

    Returns:
        Number of events added
    """
    return timeline.add_event(event, source)


def merge_timelines(timeline1: Timeline, timeline2: Timeline) -> Timeline:
    """
    Merge two timelines.

    Args:
        timeline1: First timeline
        timeline2: Second timeline

    Returns:
        New timeline containing events from both input timelines
    """
    # Create a new timeline with metadata from first timeline
    merged = create_timeline(
        name=f"Merged: {timeline1.name} + {timeline2.name}",
        description=f"Merged timeline from {timeline1.name} and {timeline2.name}",
        case_id=timeline1.case_id or timeline2.case_id
    )

    # Add events from first timeline
    merged.add_event(timeline1.events)

    # Merge second timeline
    merged.merge_timelines(timeline2)

    # Copy source files
    merged.metadata["source_files"].extend(timeline1.metadata.get("source_files", []))
    merged.metadata["source_files"].extend(timeline2.metadata.get("source_files", []))

    # Remove duplicates from source files
    merged.metadata["source_files"] = list(set(merged.metadata["source_files"]))

    if LOGGING_UTILS_AVAILABLE:
        log_forensic_operation(
            "merge_timelines",
            True,
            {
                "timeline1": timeline1.name,
                "timeline2": timeline2.name,
                "result_name": merged.name,
                "event_count": len(merged.events),
                "case_id": merged.case_id
            }
        )

    return merged


def export_timeline(timeline: Timeline,
                   output_path: str,
                   format_type: str = "json") -> bool:
    """
    Export a timeline to a file.

    Args:
        timeline: Timeline object to export
        output_path: Path to save the exported timeline
        format_type: Export format (json, csv, html)

    Returns:
        True if export was successful, False otherwise
    """
    return timeline.export_timeline(output_path, format_type)


def load_timeline(input_path: str) -> Optional[Timeline]:
    """
    Load a timeline from a file.

    Args:
        input_path: Path to the timeline file

    Returns:
        Timeline object or None if loading failed
    """
    # Validate input path
    if VALIDATION_UTILS_AVAILABLE:
        valid, msg = validate_path(input_path, must_exist=True, must_be_file=True)
        if not valid:
            logger.error(f"Invalid input path: {msg}")
            return None
    elif not os.path.isfile(input_path):
        logger.error(f"File not found: {input_path}")
        return None

    # Operation details for logging
    operation_details = {
        "input_path": input_path
    }

    try:
        # Determine file type
        file_ext = os.path.splitext(input_path)[1].lower()

        if file_ext == ".json":
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Check if this is a timeline export
            if not isinstance(data, dict) or "events" not in data:
                logger.error(f"File does not contain a valid timeline: {input_path}")
                if LOGGING_UTILS_AVAILABLE:
                    log_forensic_operation(
                        "load_timeline",
                        False,
                        {**operation_details, "error": "Invalid timeline format"}
                    )
                return None

            # Create timeline
            metadata = data.get("metadata", {})
            timeline = create_timeline(
                name=metadata.get("name", "Loaded Timeline"),
                description=metadata.get("description", f"Loaded from {input_path}"),
                case_id=metadata.get("case_id")
            )

            # Add events
            timeline.add_event(data["events"])

            # Update metadata
            if "metadata" in data:
                for key, value in metadata.items():
                    if key not in ["name", "description", "case_id", "modified", "created"]:
                        timeline.metadata[key] = value

            # Add source file
            if input_path not in timeline.metadata["source_files"]:
                timeline.metadata["source_files"].append(input_path)

            if LOGGING_UTILS_AVAILABLE:
                log_forensic_operation(
                    "load_timeline",
                    True,
                    {
                        **operation_details,
                        "event_count": len(timeline.events),
                        "case_id": timeline.case_id
                    }
                )

            return timeline

        elif file_ext == ".csv":
            # Create timeline
            timeline = create_timeline(
                name=f"Timeline from {os.path.basename(input_path)}",
                description=f"Loaded from CSV file: {input_path}"
            )

            # Load events from CSV
            with open(input_path, 'r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                events = []
                for row in reader:
                    # Convert empty strings to None
                    event = {k: v if v != "" else None for k, v in row.items()}
                    events.append(event)

            # Add events to timeline
            timeline.add_event(events)

            # Add source file
            timeline.metadata["source_files"].append(input_path)

            if LOGGING_UTILS_AVAILABLE:
                log_forensic_operation(
                    "load_timeline",
                    True,
                    {
                        **operation_details,
                        "event_count": len(timeline.events)
                    }
                )

            return timeline

        else:
            logger.error(f"Unsupported file format: {file_ext}")
            if LOGGING_UTILS_AVAILABLE:
                log_forensic_operation(
                    "load_timeline",
                    False,
                    {**operation_details, "error": f"Unsupported format: {file_ext}"}
                )
            return None

    except Exception as e:
        logger.error(f"Failed to load timeline: {str(e)}", exc_info=True)
        if LOGGING_UTILS_AVAILABLE:
            log_forensic_operation(
                "load_timeline",
                False,
                {**operation_details, "error": str(e)}
            )
        return None


def extract_timeline_from_logs(
    log_files: Union[str, List[str]],
    pattern_config: Optional[Dict[str, Any]] = None,
    output: Optional[str] = None,
    case_id: Optional[str] = None
) -> Optional[Timeline]:
    """
    Extract a timeline from log files using pattern matching.

    Args:
        log_files: Path to log file or list of log file paths
        pattern_config: Dictionary with patterns for timestamp and message extraction
        output: Optional path to save the extracted timeline
        case_id: Optional case identifier

    Returns:
        Timeline object or None if extraction failed
    """
    # Normalize log_files to list
    if isinstance(log_files, str):
        log_files = [log_files]

    # Validate log files
    valid_files = []
    for log_file in log_files:
        if VALIDATION_UTILS_AVAILABLE:
            valid, msg = validate_path(log_file, must_exist=True, must_be_file=True)
            if valid:
                valid_files.append(log_file)
            else:
                logger.warning(f"Invalid log file: {msg}")
        elif os.path.isfile(log_file):
            valid_files.append(log_file)
        else:
            logger.warning(f"File not found: {log_file}")

    if not valid_files:
        logger.error("No valid log files provided")
        return None

    # Create timeline
    timeline = create_timeline(
        name="Log Timeline",
        description=f"Timeline extracted from {len(valid_files)} log files",
        case_id=case_id
    )

    # Add source files
    timeline.metadata["source_files"] = valid_files

    # Import regex, if possible
    try:
        import re
    except ImportError:
        logger.error("Regular expression module not available")
        return None

    # Default pattern config if none provided
    if not pattern_config:
        pattern_config = {
            # Common log timestamp patterns
            "timestamp_patterns": [
                # ISO 8601
                r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)",
                # Common log format
                r"(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})",
                # Syslog format
                r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
                # Windows event log
                r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
            ],
            # Message pattern comes after timestamp
            "message_pattern": r"(.*)",
            # Log level patterns
            "level_patterns": {
                "error": r"\b(?:ERROR|CRITICAL|FATAL|FAIL|SEVERE)\b",
                "warning": r"\b(?:WARNING|WARN|ATTENTION)\b",
                "info": r"\b(?:INFO|INFORMATION|NOTICE)\b",
                "debug": r"\b(?:DEBUG|TRACE)\b"
            }
        }

    # Process each log file
    total_events = 0
    for log_file in valid_files:
        source = os.path.basename(log_file)
        events_from_file = []

        try:
            with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    # Try each timestamp pattern
                    timestamp_match = None
                    for pattern in pattern_config["timestamp_patterns"]:
                        match = re.search(pattern, line)
                        if match:
                            timestamp_match = match.group(1)
                            remainder = line[match.end():]
                            break

                    if not timestamp_match:
                        # No timestamp found, skip line
                        continue

                    # Parse timestamp
                    dt = parse_timestamp(timestamp_match) if TIMESTAMP_UTILS_AVAILABLE else None

                    # Get message
                    message_match = re.search(pattern_config["message_pattern"], remainder)
                    if message_match:
                        message = message_match.group(1).strip()
                    else:
                        message = remainder.strip()

                    # Detect log level
                    level = "unknown"
                    for lvl, pattern in pattern_config["level_patterns"].items():
                        if re.search(pattern, line):
                            level = lvl
                            break

                    # Create event
                    event = {
                        "timestamp": dt if dt else timestamp_match,
                        "description": message,
                        "source": source,
                        "source_line": line_num,
                        "level": level,
                        "original_line": line
                    }

                    events_from_file.append(event)

            # Add events from this file
            if events_from_file:
                timeline.add_event(events_from_file, source=source)
                total_events += len(events_from_file)
                logger.info(f"Added {len(events_from_file)} events from {log_file}")

        except Exception as e:
            logger.error(f"Error processing {log_file}: {str(e)}", exc_info=True)

    # Export timeline if output path provided
    if output and total_events > 0:
        timeline.export_timeline(output)

    if LOGGING_UTILS_AVAILABLE:
        log_forensic_operation(
            "extract_timeline_from_logs",
            total_events > 0,
            {
                "log_files": valid_files,
                "total_events": total_events,
                "case_id": case_id,
                "output": output
            }
        )

    return timeline if total_events > 0 else None


def visualize_timeline(
    timeline: Timeline,
    output_path: str,
    highlight_terms: Optional[List[str]] = None,
    title: Optional[str] = None
) -> bool:
    """
    Generate a visual representation of a timeline.

    Args:
        timeline: Timeline object to visualize
        output_path: Path to save the visualization
        highlight_terms: List of terms to highlight
        title: Custom title for the visualization

    Returns:
        True if visualization was successful, False otherwise
    """
    if not CHART_AVAILABLE:
        logger.error("Timeline visualization requires the report_builder module")
        return False

    # Generate title if not provided
    if not title:
        title = f"{timeline.name} - Event Timeline"

    # Convert timeline to the format expected by create_timeline_chart
    events = timeline.events

    # Create chart
    result = create_timeline_chart(
        events=events,
        output_path=output_path,
        chart_type="html",
        title=title,
        include_details=True,
        highlight_events=highlight_terms
    )

    if LOGGING_UTILS_AVAILABLE:
        log_forensic_operation(
            "visualize_timeline",
            bool(result),
            {
                "timeline_name": timeline.name,
                "output_path": output_path,
                "event_count": len(events),
                "case_id": timeline.case_id
            }
        )

    return bool(result)


def correlate_timelines(
    timelines: List[Timeline],
    window_seconds: int = 300,
    output: Optional[str] = None,
    case_id: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Identify correlated events across multiple timelines.

    Args:
        timelines: List of Timeline objects to correlate
        window_seconds: Time window in seconds for correlation
        output: Optional path to save correlation results
        case_id: Optional case identifier

    Returns:
        Dictionary with correlation results or None if correlation failed
    """
    if not timelines or len(timelines) < 2:
        logger.error("At least two timelines are required for correlation")
        return None

    # Create merged timeline for sequential analysis
    merged = merge_timelines(timelines[0], timelines[1])
    for i in range(2, len(timelines)):
        merged = merge_timelines(merged, timelines[i])

    # Ensure events are sorted
    merged._sort_events()

    # Look for event clusters within the time window
    clusters = []
    current_cluster = []

    for i, event in enumerate(merged.events):
        # Start a new cluster if needed
        if not current_cluster:
            current_cluster = [event]
            continue

        # Get timestamps
        curr_ts = normalize_timestamp(event["timestamp"])
        prev_ts = normalize_timestamp(current_cluster[-1]["timestamp"])

        # Skip if timestamps can't be normalized
        if not curr_ts or not prev_ts:
            continue

        # Check if within time window
        time_diff = (curr_ts - prev_ts).total_seconds()

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

    # Analyze clusters to find events from different sources
    correlation_results = {
        "case_id": case_id,
        "timeline_count": len(timelines),
        "total_events": len(merged.events),
        "correlation_window": f"{window_seconds} seconds",
        "cluster_count": len(clusters),
        "correlated_clusters": []
    }

    for i, cluster in enumerate(clusters):
        # Get unique sources in this cluster
        sources = set(event.get("source", "") for event in cluster)

        # Only keep clusters with events from different sources
        if len(sources) > 1:
            # Process this correlated cluster
            cluster_info = {
                "cluster_id": f"cluster-{i+1}",
                "event_count": len(cluster),
                "unique_sources": list(sources),
                "time_range": {
                    "start": _format_timestamp(cluster[0]["timestamp"]),
                    "end": _format_timestamp(cluster[-1]["timestamp"])
                },
                "events": cluster
            }

            correlation_results["correlated_clusters"].append(cluster_info)

    # Update summary
    correlation_results["correlated_cluster_count"] = len(correlation_results["correlated_clusters"])

    # Export if output path provided
    if output and correlation_results["correlated_cluster_count"] > 0:
        try:
            os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(correlation_results, f, indent=2, default=_json_serializer)
        except Exception as e:
            logger.error(f"Failed to save correlation results: {str(e)}", exc_info=True)

    if LOGGING_UTILS_AVAILABLE:
        log_forensic_operation(
            "correlate_timelines",
            correlation_results["correlated_cluster_count"] > 0,
            {
                "timeline_count": len(timelines),
                "correlation_window": window_seconds,
                "cluster_count": correlation_results["cluster_count"],
                "correlated_clusters": correlation_results["correlated_cluster_count"],
                "case_id": case_id,
                "output": output
            }
        )

    return correlation_results


def _format_timestamp(ts: Union[datetime, str]) -> str:
    """Helper to format timestamp for output."""
    if isinstance(ts, datetime):
        return ts.isoformat()
    return str(ts)


def _json_serializer(obj):
    """Handle serialization of custom types to JSON."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


# Initialize module
if LOGGING_UTILS_AVAILABLE:
    log_forensic_operation(
        "timeline_builder_init",
        True,
        {
            "timestamp_utils_available": TIMESTAMP_UTILS_AVAILABLE,
            "validation_utils_available": VALIDATION_UTILS_AVAILABLE,
            "chart_generation_available": CHART_AVAILABLE
        }
    )
