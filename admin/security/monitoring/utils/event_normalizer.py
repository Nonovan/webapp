"""
Security Event Normalization Utilities

This module provides functions to normalize security events from various sources
into a standardized format for consistent processing and analysis. It handles
different timestamp formats, vendor-specific field mappings, and enriches events
with additional contextual information.
"""

import re
import json
import logging
import hashlib
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Set, Tuple

# Module-level constants
DEFAULT_SCHEMA_VERSION = "1.0"
EVENT_NORMALIZER_AVAILABLE = True

# Configure logger
logger = logging.getLogger(__name__)

# Standard field mapping for common security event sources
FIELD_MAPPINGS = {
    "syslog": {
        "timestamp": "timestamp",
        "hostname": "host",
        "severity": "priority",
        "facility": "facility",
        "message": "content"
    },
    "windows_event": {
        "timestamp": "TimeCreated",
        "hostname": "Computer",
        "severity": "Level",
        "event_id": "EventID",
        "message": "Message"
    },
    "cloud_trail": {
        "timestamp": "eventTime",
        "user": "userIdentity.userName",
        "source_ip": "sourceIPAddress",
        "event_name": "eventName",
        "event_type": "eventType"
    },
    "firewall": {
        "timestamp": "time",
        "source_ip": "src_ip",
        "destination_ip": "dst_ip",
        "source_port": "src_port",
        "destination_port": "dst_port",
        "action": "action"
    },
    "ids": {
        "timestamp": "timestamp",
        "source_ip": "src_ip",
        "destination_ip": "dst_ip",
        "signature_id": "sig_id",
        "signature_name": "sig_name",
        "severity": "severity"
    }
}

# Standard timestamp formats to try when normalizing
TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",           # ISO8601 with microseconds
    "%Y-%m-%dT%H:%M:%SZ",              # ISO8601
    "%Y-%m-%d %H:%M:%S.%f",            # Database timestamp with microseconds
    "%Y-%m-%d %H:%M:%S",               # Standard datetime
    "%b %d %H:%M:%S",                  # Syslog (without year)
    "%Y/%m/%d %H:%M:%S",               # Date with slashes
    "%d/%b/%Y:%H:%M:%S %z"             # Apache/Nginx log format
]

def normalize_event(
    raw_event: Dict[str, Any],
    source_type: str = "generic",
    add_context: bool = False
) -> Dict[str, Any]:
    """
    Normalize a security event from various sources into a standardized format.

    Args:
        raw_event: Raw event data to normalize
        source_type: Source type to apply appropriate field mappings
        add_context: Whether to add additional context to the event

    Returns:
        Normalized event dictionary
    """
    if not raw_event:
        logger.warning("Empty event provided to normalizer")
        return {}

    try:
        # Create standard event structure
        normalized_event = {
            "event_id": generate_event_id(raw_event),
            "timestamp": None,
            "normalized_timestamp": None,
            "source": source_type,
            "source_ip": None,
            "destination_ip": None,
            "user": None,
            "event_type": None,
            "severity": None,
            "message": None,
            "raw": raw_event  # Retain original for reference
        }

        # Apply field mappings based on source type
        field_mapping = FIELD_MAPPINGS.get(source_type, {})

        # Extract and map fields
        for target_field, source_field in field_mapping.items():
            value = extract_nested_field(raw_event, source_field)
            if value:
                normalized_event[target_field] = value

        # Apply special handling for common fields
        if "timestamp" in raw_event:
            timestamp_value = raw_event["timestamp"]
            normalized_event["timestamp"] = timestamp_value
            normalized_event["normalized_timestamp"] = standardize_timestamp(timestamp_value)

        # Try to find a timestamp in any available field if not already set
        if not normalized_event["normalized_timestamp"]:
            normalized_event["normalized_timestamp"] = find_timestamp_in_event(raw_event)

        # Handle source-specific normalizations
        if source_type == "syslog":
            _normalize_syslog_event(raw_event, normalized_event)
        elif source_type == "windows_event":
            _normalize_windows_event(raw_event, normalized_event)
        elif source_type == "cloud_trail":
            _normalize_cloud_trail_event(raw_event, normalized_event)

        # Add additional context if requested
        if add_context:
            normalized_event = enrich_event_data(normalized_event)

        # Validate the event structure
        if not validate_normalized_event(normalized_event):
            logger.warning(f"Normalized event validation failed for event {normalized_event.get('event_id')}")

        return normalized_event

    except Exception as e:
        logger.error(f"Error normalizing event: {e}", exc_info=True)
        return {"error": str(e), "raw": raw_event}

def normalize_batch(
    raw_events: List[Dict[str, Any]],
    source_type: str = "generic",
    add_geo_data: bool = False
) -> List[Dict[str, Any]]:
    """
    Normalize a batch of security events.

    Args:
        raw_events: List of raw events to normalize
        source_type: Source type to apply appropriate field mappings
        add_geo_data: Whether to add geographic data for IP addresses

    Returns:
        List of normalized events
    """
    normalized_events = []

    for raw_event in raw_events:
        try:
            normalized_event = normalize_event(raw_event, source_type, add_context=False)

            # Add geo data if requested and IP is available
            if add_geo_data and normalized_event.get("source_ip"):
                normalized_event = _add_geo_data(normalized_event)

            normalized_events.append(normalized_event)
        except Exception as e:
            logger.error(f"Error in batch normalization for event: {e}", exc_info=True)
            # Include error event with original data
            normalized_events.append({
                "error": str(e),
                "raw": raw_event,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

    return normalized_events

def get_event_schema(version: str = DEFAULT_SCHEMA_VERSION) -> Dict[str, Any]:
    """
    Get the event schema definition for normalized events.

    Args:
        version: Schema version to retrieve

    Returns:
        Dictionary containing schema definition
    """
    base_schema = {
        "type": "object",
        "version": version,
        "required": ["event_id", "timestamp", "source"],
        "properties": {
            "event_id": {"type": "string"},
            "timestamp": {"type": "string"},
            "normalized_timestamp": {"type": "string", "format": "date-time"},
            "source": {"type": "string"},
            "source_ip": {"type": "string", "format": "ipv4"},
            "destination_ip": {"type": "string", "format": "ipv4"},
            "user": {"type": "string"},
            "event_type": {"type": "string"},
            "severity": {"type": "string"},
            "message": {"type": "string"},
            "raw": {"type": "object"}
        }
    }

    # Version-specific schemas
    if version == "1.1":
        # Add extended fields in newer schema version
        base_schema["properties"].update({
            "context": {"type": "object"},
            "geo_data": {"type": "object"},
            "tags": {"type": "array", "items": {"type": "string"}}
        })

    return base_schema

def standardize_timestamp(timestamp_value: Union[str, int, float, datetime]) -> Optional[str]:
    """
    Convert various timestamp formats to ISO8601 UTC.

    Args:
        timestamp_value: Timestamp in various formats

    Returns:
        ISO8601 formatted timestamp string or None if parsing fails
    """
    if not timestamp_value:
        return None

    # Already a datetime object
    if isinstance(timestamp_value, datetime):
        # Ensure timezone info is present
        if timestamp_value.tzinfo is None:
            timestamp_value = timestamp_value.replace(tzinfo=timezone.utc)
        return timestamp_value.isoformat()

    # Unix timestamp (seconds)
    if isinstance(timestamp_value, (int, float)):
        try:
            dt = datetime.fromtimestamp(timestamp_value, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, OverflowError):
            # Try milliseconds if seconds doesn't work
            try:
                dt = datetime.fromtimestamp(timestamp_value / 1000, tz=timezone.utc)
                return dt.isoformat()
            except (ValueError, OverflowError):
                logger.warning(f"Could not convert numeric timestamp: {timestamp_value}")
                return None

    # String timestamp - try various formats
    if isinstance(timestamp_value, str):
        # Check for common ISO format first
        try:
            # Handle ISO format with timezone
            if 'T' in timestamp_value and ('Z' in timestamp_value or '+' in timestamp_value or '-' in timestamp_value):
                # Remove trailing Z and add explicit UTC
                if timestamp_value.endswith('Z'):
                    timestamp_value = timestamp_value[:-1] + '+00:00'
                dt = datetime.fromisoformat(timestamp_value)
                return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass  # Try other formats

        # Try various formats
        for fmt in TIMESTAMP_FORMATS:
            try:
                # Special case for syslog timestamp without year
                if fmt == "%b %d %H:%M:%S":
                    # Add current year
                    current_year = datetime.now().year
                    dt = datetime.strptime(f"{current_year} {timestamp_value}", f"%Y {fmt}")

                    # Handle December logs from previous year in January
                    if dt.month == 12 and datetime.now().month == 1:
                        dt = dt.replace(year=current_year-1)
                else:
                    dt = datetime.strptime(timestamp_value, fmt)

                # Add UTC timezone if not specified
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)

                return dt.isoformat()
            except ValueError:
                continue

        # Try regex for common patterns not matched above
        return _parse_timestamp_with_regex(timestamp_value)

    return None

def map_vendor_fields(event: Dict[str, Any], vendor: str, mapping: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Map vendor-specific fields to standardized fields.

    Args:
        event: Event data to map
        vendor: Vendor name to use predefined mapping
        mapping: Custom mapping to override default

    Returns:
        Event with mapped fields
    """
    result = {}

    # Determine which mapping to use
    field_mapping = mapping or FIELD_MAPPINGS.get(vendor, {})

    # Apply the mapping
    for target_field, source_field in field_mapping.items():
        value = extract_nested_field(event, source_field)
        if value is not None:
            result[target_field] = value

    # Copy any fields not in the mapping
    for field, value in event.items():
        if field not in field_mapping.values():
            result.setdefault(field, value)

    return result

def enrich_event_data(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich security event with additional context.

    Args:
        event: Event to enrich

    Returns:
        Enriched event with additional context
    """
    enriched = event.copy()

    try:
        # Add current processing timestamp
        enriched["processed_at"] = datetime.now(timezone.utc).isoformat()

        # Add event classification if possible
        if "event_type" in enriched and enriched["event_type"]:
            enriched["classification"] = _classify_event(enriched)

        # Add IP-related context if available
        if enriched.get("source_ip"):
            ip_context = _get_ip_context(enriched["source_ip"])
            if ip_context:
                enriched.setdefault("context", {}).update({"source_ip": ip_context})

        # Add severity normalized value if available
        if "severity" in enriched:
            enriched["normalized_severity"] = _normalize_severity(enriched["severity"])

        # Generate event tags based on content
        enriched["tags"] = _generate_event_tags(enriched)

    except Exception as e:
        logger.warning(f"Error enriching event data: {e}")

    return enriched

def validate_normalized_event(event: Dict[str, Any], schema_version: str = DEFAULT_SCHEMA_VERSION) -> bool:
    """
    Validate a normalized event against the schema.

    Args:
        event: Event to validate
        schema_version: Schema version to validate against

    Returns:
        True if valid, False otherwise
    """
    schema = get_event_schema(schema_version)

    # Check required fields
    for required_field in schema["required"]:
        if required_field not in event or event[required_field] is None:
            logger.debug(f"Required field '{required_field}' missing in event")
            return False

    # Simple type validation for core fields
    for field_name, field_spec in schema["properties"].items():
        if field_name in event and event[field_name] is not None:
            # Type validation
            if field_spec["type"] == "string" and not isinstance(event[field_name], str):
                logger.debug(f"Field '{field_name}' should be string but got {type(event[field_name])}")
                return False
            elif field_spec["type"] == "object" and not isinstance(event[field_name], dict):
                logger.debug(f"Field '{field_name}' should be object but got {type(event[field_name])}")
                return False
            elif field_spec["type"] == "array" and not isinstance(event[field_name], list):
                logger.debug(f"Field '{field_name}' should be array but got {type(event[field_name])}")
                return False

            # Format validation for IP addresses
            if field_spec.get("format") == "ipv4" and field_name in event and event[field_name]:
                try:
                    ipaddress.ip_address(event[field_name])
                except ValueError:
                    logger.debug(f"Invalid IP address format in field '{field_name}': {event[field_name]}")
                    return False

    return True

def extract_event_fields(event: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
    """
    Extract specific fields from an event.

    Args:
        event: Event to extract fields from
        fields: List of field names to extract

    Returns:
        Dictionary containing only the requested fields
    """
    result = {}

    for field in fields:
        value = extract_nested_field(event, field)
        if value is not None:
            # For nested fields, build the nested structure
            if '.' in field:
                parts = field.split('.')
                current = result
                for part in parts[:-1]:
                    current = current.setdefault(part, {})
                current[parts[-1]] = value
            else:
                result[field] = value

    return result

# Helper functions

def extract_nested_field(data: Dict[str, Any], field_path: str) -> Any:
    """Extract a possibly nested field using dot notation."""
    if not field_path:
        return None

    parts = field_path.split('.')
    value = data

    try:
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value
    except (KeyError, TypeError, AttributeError):
        return None

def generate_event_id(event: Dict[str, Any]) -> str:
    """Generate a unique ID for an event."""
    # Create a string representation of relevant event data
    event_data = json.dumps(event, sort_keys=True, default=str)

    # Create a hash of the event data
    event_hash = hashlib.sha256(event_data.encode()).hexdigest()

    # Use first 16 characters of hash as the ID
    return f"evt-{event_hash[:16]}"

def find_timestamp_in_event(event: Dict[str, Any]) -> Optional[str]:
    """Find and normalize a timestamp field in an event."""
    # Common timestamp field names
    timestamp_fields = [
        "timestamp", "time", "date", "eventTime", "@timestamp", "timeCreated",
        "createdAt", "created_at", "event_time", "log_time"
    ]

    # Try known timestamp fields first
    for field in timestamp_fields:
        if field in event:
            normalized = standardize_timestamp(event[field])
            if normalized:
                return normalized

    # Recursively search through all fields
    for key, value in event.items():
        if key.lower().find("time") >= 0 or key.lower().find("date") >= 0:
            normalized = standardize_timestamp(value)
            if normalized:
                return normalized

        # Look in nested dictionaries
        if isinstance(value, dict):
            nested_timestamp = find_timestamp_in_event(value)
            if nested_timestamp:
                return nested_timestamp

    # Default to current time if no timestamp found
    logger.debug(f"No timestamp found in event, using current time")
    return datetime.now(timezone.utc).isoformat()

def _parse_timestamp_with_regex(timestamp_str: str) -> Optional[str]:
    """Parse timestamp using regex patterns."""
    # Common timestamp patterns
    patterns = [
        # ISO-like formats: 2023-01-15T14:30:45.123
        r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?',
        # Date time formats: 2023-01-15 14:30:45
        r'(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})',
        # Date with slashes: 01/15/2023 14:30:45
        r'(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})',
        # Month abbreviation: Jan 15 14:30:45 2023
        r'([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})'
    ]

    for pattern in patterns:
        match = re.search(pattern, timestamp_str)
        if match:
            try:
                if pattern == patterns[0]:  # ISO-like
                    year, month, day, hour, minute, second = map(int, match.groups()[:6])
                    microsecond = int(match.group(7) or 0)
                    dt = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=timezone.utc)
                elif pattern == patterns[1]:  # Standard date time
                    year, month, day, hour, minute, second = map(int, match.groups())
                    dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
                elif pattern == patterns[2]:  # Date with slashes
                    month, day, year, hour, minute, second = map(int, match.groups())
                    dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
                else:  # Month abbreviation
                    month_abbr, day, hour, minute, second, year = match.groups()
                    month_map = {
                        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                        'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
                    }
                    month = month_map.get(month_abbr.lower(), 1)
                    dt = datetime(int(year), month, int(day), int(hour), int(minute), int(second), tzinfo=timezone.utc)

                return dt.isoformat()
            except (ValueError, KeyError):
                continue

    return None

def _normalize_syslog_event(raw_event: Dict[str, Any], normalized_event: Dict[str, Any]) -> None:
    """Apply special handling for syslog events."""
    # Extract facility and severity if available in PRI field
    if "pri" in raw_event:
        try:
            pri = int(raw_event["pri"])
            facility = pri >> 3
            severity = pri & 0x7

            normalized_event["facility"] = facility
            normalized_event["severity"] = severity
        except (ValueError, TypeError):
            pass

    # Extract program name and hostname
    if "content" in raw_event:
        content = raw_event["content"]
        program_match = re.search(r'^([^\s\[]+)(?:\[(\d+)\])?: ', content)
        if program_match:
            normalized_event["program"] = program_match.group(1)
            if program_match.group(2):
                normalized_event["pid"] = program_match.group(2)

def _normalize_windows_event(raw_event: Dict[str, Any], normalized_event: Dict[str, Any]) -> None:
    """Apply special handling for Windows events."""
    # Map Windows event level to severity
    level_map = {
        "1": "critical",
        "2": "error",
        "3": "warning",
        "4": "information",
        "5": "verbose"
    }

    if "Level" in raw_event:
        level = str(raw_event["Level"])
        normalized_event["severity"] = level_map.get(level, level)

    # Extract user information
    if "Security" in raw_event and "UserID" in raw_event["Security"]:
        normalized_event["user"] = raw_event["Security"]["UserID"]

def _normalize_cloud_trail_event(raw_event: Dict[str, Any], normalized_event: Dict[str, Any]) -> None:
    """Apply special handling for AWS CloudTrail events."""
    # Extract account information
    if "recipientAccountId" in raw_event:
        normalized_event["account_id"] = raw_event["recipientAccountId"]

    # Extract detailed user information
    if "userIdentity" in raw_event:
        user_identity = raw_event["userIdentity"]
        if "type" in user_identity:
            normalized_event["user_type"] = user_identity["type"]

        # Different user identifier fields based on type
        if "userName" in user_identity:
            normalized_event["user"] = user_identity["userName"]
        elif "sessionContext" in user_identity and "sessionIssuer" in user_identity["sessionContext"]:
            session_issuer = user_identity["sessionContext"]["sessionIssuer"]
            if "userName" in session_issuer:
                normalized_event["user"] = session_issuer["userName"]

    # Categorize event type
    if "eventType" in raw_event:
        if raw_event["eventType"] == "AwsApiCall":
            normalized_event["event_type"] = "api_call"
        elif raw_event["eventType"] == "AwsConsoleSignIn":
            normalized_event["event_type"] = "authentication"

def _add_geo_data(event: Dict[str, Any]) -> Dict[str, Any]:
    """Add geographic data for IP addresses in the event."""
    # This would integrate with a geolocation service
    # For now, just provide placeholder structure
    enriched = event.copy()

    try:
        ip = event.get("source_ip")
        if ip:
            # Check if IP is private (no geo lookup needed)
            try:
                if ipaddress.ip_address(ip).is_private:
                    enriched.setdefault("geo_data", {})["source_ip"] = {
                        "is_private": True
                    }
                else:
                    # This would typically call a geo IP service
                    # For now just add placeholder
                    enriched.setdefault("geo_data", {})["source_ip"] = {
                        "is_private": False,
                        "country_code": "--",
                        "country_name": "Unknown",
                        "city": "Unknown",
                        "latitude": 0,
                        "longitude": 0
                    }
            except ValueError:
                pass
    except Exception as e:
        logger.warning(f"Error adding geo data: {e}")

    return enriched

def _classify_event(event: Dict[str, Any]) -> str:
    """Classify an event based on its characteristics."""
    event_type = event.get("event_type", "").lower()
    message = event.get("message", "").lower()

    # Authentication-related classification
    if (event_type and ("login" in event_type or "auth" in event_type)) or \
       (message and any(x in message for x in ["login", "authentication", "password", "credential"])):
        if message and any(x in message for x in ["fail", "invalid", "incorrect", "bad"]):
            return "authentication_failure"
        return "authentication"

    # Access control classification
    if (event_type and any(x in event_type for x in ["access", "permission"])) or \
       (message and any(x in message for x in ["permission", "denied", "access", "forbidden"])):
        if message and any(x in message for x in ["denied", "forbidden", "unauthorized"]):
            return "access_denied"
        return "access_control"

    # Security-related classification
    if (event_type and any(x in event_type for x in ["security", "attack", "threat", "vuln"])) or \
       (message and any(x in message for x in ["security", "attack", "threat", "vulnerability"])):
        return "security"

    # Configuration changes
    if (event_type and "config" in event_type) or \
       (message and any(x in message for x in ["config", "setting", "parameter"])):
        return "configuration"

    # System events
    if (event_type and any(x in event_type for x in ["system", "service", "daemon"])) or \
       (message and any(x in message for x in ["system", "service", "daemon", "process"])):
        return "system"

    # Network events
    if (event_type and any(x in event_type for x in ["network", "connection", "packet"])) or \
       (message and any(x in message for x in ["network", "connection", "packet", "protocol"])):
        return "network"

    return "other"

def _normalize_severity(severity: Any) -> str:
    """Normalize different severity formats to standard levels."""
    if severity is None:
        return "unknown"

    # Convert to string for comparison
    severity_str = str(severity).lower()

    # Common severity mappings
    if severity_str in ("critical", "fatal", "emergency", "1", "crit", "emerg"):
        return "critical"
    elif severity_str in ("error", "err", "severe", "2", "3"):
        return "error"
    elif severity_str in ("warning", "warn", "4"):
        return "warning"
    elif severity_str in ("notice", "info", "information", "5", "6"):
        return "info"
    elif severity_str in ("debug", "verbose", "trace", "7"):
        return "debug"

    # Try to map numeric values
    try:
        severity_value = int(severity_str)
        if severity_value <= 1:
            return "critical"
        elif severity_value <= 3:
            return "error"
        elif severity_value <= 4:
            return "warning"
        elif severity_value <= 6:
            return "info"
        else:
            return "debug"
    except (ValueError, TypeError):
        pass

    return "unknown"

def _get_ip_context(ip: str) -> Dict[str, Any]:
    """Get additional context for an IP address."""
    result = {}

    try:
        # Check if IP is valid
        ip_obj = ipaddress.ip_address(ip)

        # Determine if private
        result["is_private"] = ip_obj.is_private

        # Determine IP version
        result["version"] = ip_obj.version

        # For IPv6, get the IPv4 mapped address if applicable
        if ip_obj.version == 6 and hasattr(ip_obj, "ipv4_mapped"):
            ipv4 = ip_obj.ipv4_mapped
            if ipv4:
                result["ipv4_mapped"] = str(ipv4)

    except ValueError:
        result["is_valid"] = False

    return result

def _generate_event_tags(event: Dict[str, Any]) -> List[str]:
    """Generate tags for an event based on its content."""
    tags = set()

    # Add tags based on event type
    event_type = event.get("event_type", "").lower()
    if event_type:
        tags.add(event_type)

    # Add tags based on classification
    classification = event.get("classification")
    if classification:
        tags.add(classification)

    # Add severity tag if available
    if "severity" in event:
        severity = _normalize_severity(event["severity"])
        if severity != "unknown":
            tags.add(f"severity:{severity}")

    # Add source tag
    source = event.get("source")
    if source:
        tags.add(f"source:{source}")

    # Add tag for IP type if available
    if event.get("source_ip"):
        try:
            ip = ipaddress.ip_address(event["source_ip"])
            if ip.is_private:
                tags.add("private_ip")
            else:
                tags.add("public_ip")
        except ValueError:
            pass

    # Add special condition tags
    if "error" in event:
        tags.add("contains_error")

    if event.get("context", {}).get("detected_anomaly"):
        tags.add("anomaly")

    return sorted(list(tags))
