"""
Indicator Matching Utilities

This module provides functions for matching indicators of compromise (IOCs) against
security events or other data. It supports various indicator types including IP addresses,
domains, file hashes, and regex patterns with configurable matching thresholds.

The module focuses on efficient matching through caching mechanisms and optimized
pattern matching algorithms for large datasets, providing confidence scores for matches.
"""

import os
import re
import logging
import json
import hashlib
import ipaddress
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Union, Pattern, Tuple
from pathlib import Path

# Setup module logging
logger = logging.getLogger(__name__)

# Try to import monitoring constants if available
try:
    from ..monitoring_constants import THREAT_INTEL
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False
    logger.debug("Monitoring constants not available, using default values")
    # Default constants if monitoring_constants.py is not available
    class THREAT_INTEL:
        """Default threat intelligence constants."""
        MATCH_THRESHOLD = 0.75
        CACHE_TTL = 3600  # seconds
        MAX_CACHE_ENTRIES = 10000

# Try to import from core security if available
try:
    from core.security import is_suspicious_ip
    from core.security.cs_metrics import get_threat_intelligence_summary
    CORE_SECURITY_AVAILABLE = True
except ImportError:
    CORE_SECURITY_AVAILABLE = False
    logger.debug("Core security module not available, using local implementations")

# Try to import threat intelligence models if available
try:
    from models.security.threat_intelligence import ThreatIndicator
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False
    logger.debug("Threat intelligence models not available, using local cache only")

# Module constants
DEFAULT_MATCH_THRESHOLD = getattr(THREAT_INTEL, 'MATCH_THRESHOLD', 0.75) if CONSTANTS_AVAILABLE else 0.75
DEFAULT_CACHE_TTL = getattr(THREAT_INTEL, 'CACHE_TTL', 3600) if CONSTANTS_AVAILABLE else 3600
DEFAULT_MAX_CACHE_SIZE = getattr(THREAT_INTEL, 'MAX_CACHE_ENTRIES', 10000) if CONSTANTS_AVAILABLE else 10000

# In-memory caches
_indicator_cache: Dict[str, Dict[str, Any]] = {}
_regex_cache: Dict[str, Pattern] = {}
_last_cache_update: datetime = datetime.now()
_local_indicator_sets: Dict[str, List[Dict[str, Any]]] = {}

def match_indicators(
    event: Dict[str, Any],
    indicators: Optional[List[Dict[str, Any]]] = None,
    indicator_set: Optional[str] = None,
    match_types: Optional[List[str]] = None,
    threshold: float = DEFAULT_MATCH_THRESHOLD,
    max_matches: int = 100
) -> List[Dict[str, Any]]:
    """
    Match event data against indicators of compromise.

    Args:
        event: The event data to check against indicators
        indicators: List of indicators to check against (optional)
        indicator_set: Named indicator set to use if indicators not provided
        match_types: Types of indicators to match (ip, domain, hash, regex)
        threshold: Confidence threshold for matches (0.0-1.0)
        max_matches: Maximum number of matches to return

    Returns:
        List of matching indicators with match details
    """
    if not event:
        logger.warning("Empty event provided to match_indicators")
        return []

    # Validate threshold
    if threshold < 0.0 or threshold > 1.0:
        logger.warning(f"Invalid threshold value: {threshold}, using default: {DEFAULT_MATCH_THRESHOLD}")
        threshold = DEFAULT_MATCH_THRESHOLD

    # Get indicators to match against
    indicator_list = []
    if indicators:
        indicator_list = indicators
    elif indicator_set:
        indicator_list = load_indicator_set(indicator_set)
    else:
        # If no indicators provided, try to use all available indicators
        if MODELS_AVAILABLE:
            # Use ThreatIndicator model if available
            try:
                from models.security.threat_intelligence import ThreatIndicator
                indicator_list = [ind.to_dict() for ind in ThreatIndicator.query.filter_by(is_active=True).limit(1000).all()]
            except Exception as e:
                logger.error(f"Error loading indicators from database: {e}")

        # If still no indicators, try to load from the default set
        if not indicator_list:
            indicator_list = load_indicator_set('active_threats')

    if not indicator_list:
        logger.warning("No indicators available to match against")
        return []

    # Determine which types to match
    if not match_types:
        match_types = ['ip', 'domain', 'hash', 'regex']

    # Extract fields from the event for matching
    ip_addresses = _extract_ip_addresses(event)
    domains = _extract_domains(event)
    file_hashes = _extract_file_hashes(event)
    text_fields = _extract_text_fields(event)

    # Collect matches
    matches = []

    # Match each indicator type if requested
    if 'ip' in match_types and ip_addresses:
        for ip in ip_addresses:
            ip_matches = match_ip_address(ip, indicator_list, threshold)
            matches.extend(ip_matches)

    if 'domain' in match_types and domains:
        for domain in domains:
            domain_matches = match_domain(domain, indicator_list, threshold)
            matches.extend(domain_matches)

    if 'hash' in match_types and file_hashes:
        for file_hash in file_hashes:
            hash_matches = match_file_hash(file_hash, indicator_list)
            matches.extend(hash_matches)

    if 'regex' in match_types and text_fields:
        regex_matches = []
        for field_name, text in text_fields.items():
            if isinstance(text, str):
                for indicator in indicator_list:
                    if indicator.get('indicator_type') == 'regex' and indicator.get('value'):
                        match = match_regex_pattern(text, indicator.get('value'), indicator, field_name)
                        if match and match.get('confidence', 0) >= threshold:
                            regex_matches.append(match)
        matches.extend(regex_matches)

    # Deduplicate matches by indicator_id
    unique_matches = {}
    for match in matches:
        indicator_id = match.get('indicator_id')
        if indicator_id:
            # Keep match with highest confidence if duplicate
            if indicator_id not in unique_matches or match.get('confidence', 0) > unique_matches[indicator_id].get('confidence', 0):
                unique_matches[indicator_id] = match
        else:
            # Use value as key if no ID
            match_value = match.get('value')
            if match_value:
                if match_value not in unique_matches or match.get('confidence', 0) > unique_matches[match_value].get('confidence', 0):
                    unique_matches[match_value] = match

    # Sort matches by confidence (descending) and limit to max_matches
    sorted_matches = sorted(
        unique_matches.values(),
        key=lambda x: x.get('confidence', 0),
        reverse=True
    )[:max_matches]

    # Add match timestamp
    for match in sorted_matches:
        match['match_timestamp'] = datetime.now().isoformat()

    return sorted_matches

def load_indicator_set(
    indicator_set: str,
    reload_cache: bool = False
) -> List[Dict[str, Any]]:
    """
    Load a named set of indicators from file, database, or cache.

    Args:
        indicator_set: Name of the indicator set to load
        reload_cache: Whether to force reload from source

    Returns:
        List of indicators in the set
    """
    global _local_indicator_sets, _last_cache_update

    # Check if we have this set in memory and it's not expired
    if (
        not reload_cache and
        indicator_set in _local_indicator_sets and
        (datetime.now() - _last_cache_update).total_seconds() < DEFAULT_CACHE_TTL
    ):
        return _local_indicator_sets[indicator_set]

    indicators = []

    # Try loading from database if available
    if MODELS_AVAILABLE:
        try:
            if indicator_set == 'active_threats':
                # Load all active threats
                from models.security.threat_intelligence import ThreatIndicator
                indicators = [ind.to_dict() for ind in ThreatIndicator.query.filter_by(is_active=True).all()]
            elif indicator_set.startswith('type:'):
                # Load by indicator type
                indicator_type = indicator_set[5:]
                from models.security.threat_intelligence import ThreatIndicator
                indicators = [ind.to_dict() for ind in ThreatIndicator.query.filter_by(
                    is_active=True,
                    indicator_type=indicator_type
                ).all()]
            elif indicator_set.startswith('tag:'):
                # Load by tag
                tag = indicator_set[4:]
                from models.security.threat_intelligence import ThreatIndicator
                indicators = []
                for ind in ThreatIndicator.query.filter_by(is_active=True).all():
                    if ind.tags and tag in ind.tags:
                        indicators.append(ind.to_dict())
        except Exception as e:
            logger.error(f"Error loading indicators from database: {e}")

    # If not found in database or no models available, try loading from file
    if not indicators:
        # Look in monitoring config directory
        potential_paths = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "threat_intel", f"{indicator_set}.json"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "threat_intel", f"{indicator_set}.yml"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", f"{indicator_set}.json")
        ]

        for path in potential_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        if path.endswith('.json'):
                            data = json.load(f)
                            if isinstance(data, dict) and 'indicators' in data:
                                indicators = data['indicators']
                            elif isinstance(data, list):
                                indicators = data
                        elif path.endswith(('.yml', '.yaml')):
                            try:
                                data = yaml.safe_load(f)
                                if isinstance(data, dict) and 'indicators' in data:
                                    indicators = data['indicators']
                                elif isinstance(data, list):
                                    indicators = data
                            except ImportError:
                                logger.warning("YAML library not available, skipping YAML file")
                        break
                except Exception as e:
                    logger.error(f"Error loading indicator set from {path}: {e}")

    # Process indicators to ensure they have the required fields
    processed_indicators = []
    for indicator in indicators:
        if not isinstance(indicator, dict):
            continue

        # Ensure required fields
        if 'value' not in indicator:
            continue

        # Add default fields if missing
        if 'indicator_type' not in indicator:
            indicator['indicator_type'] = _guess_indicator_type(indicator['value'])

        if 'confidence' not in indicator:
            indicator['confidence'] = 1.0

        # Add indicator to processed list
        processed_indicators.append(indicator)

    # Cache the indicator set
    _local_indicator_sets[indicator_set] = processed_indicators
    _last_cache_update = datetime.now()

    return processed_indicators

def match_ip_address(
    ip: str,
    indicators: List[Dict[str, Any]],
    threshold: float = DEFAULT_MATCH_THRESHOLD
) -> List[Dict[str, Any]]:
    """
    Match an IP address against indicators.

    Args:
        ip: IP address to match
        indicators: List of indicators to check against
        threshold: Confidence threshold for matches

    Returns:
        List of matching indicators with match details
    """
    if not ip or not indicators:
        return []

    matches = []

    # Validate IP address
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return []

    # Check if IP is directly in our indicators
    for indicator in indicators:
        indicator_type = indicator.get('indicator_type', '')
        indicator_value = indicator.get('value', '')

        if not indicator_value or not isinstance(indicator_value, str):
            continue

        # Check exact IP match
        if indicator_type in ('ip', 'ipv4', 'ipv6') and indicator_value == ip:
            match = {
                'indicator_id': indicator.get('id', indicator.get('indicator_id')),
                'type': 'ip_exact',
                'value': ip,
                'matched_indicator': indicator_value,
                'confidence': 1.0,
                'indicator': indicator
            }
            matches.append(match)
            continue

        # Check CIDR match
        if indicator_type in ('cidr', 'ip_range', 'network') and '/' in indicator_value:
            try:
                network = ipaddress.ip_network(indicator_value, strict=False)
                if ip_obj in network:
                    # Calculate confidence based on network size - smaller networks = higher confidence
                    # /32 (single IP) = 1.0, /24 = 0.9, /16 = 0.8, etc.
                    prefix_len = network.prefixlen
                    ip_version = ip_obj.version
                    max_prefix = 32 if ip_version == 4 else 128

                    # Calculate confidence: 1.0 for exact match, decreasing as network size increases
                    confidence = 0.7 + (0.3 * prefix_len / max_prefix)

                    if confidence >= threshold:
                        match = {
                            'indicator_id': indicator.get('id', indicator.get('indicator_id')),
                            'type': 'ip_cidr',
                            'value': ip,
                            'matched_indicator': indicator_value,
                            'confidence': confidence,
                            'indicator': indicator
                        }
                        matches.append(match)
            except ValueError:
                continue

    # Check if IP is in core security suspicious IPs
    if CORE_SECURITY_AVAILABLE and not matches:
        try:
            if is_suspicious_ip(ip):
                match = {
                    'type': 'ip_suspicious',
                    'value': ip,
                    'matched_indicator': 'core_security_suspicious_ip',
                    'confidence': 0.8,
                    'indicator': {
                        'indicator_type': 'ip',
                        'value': ip,
                        'source': 'core_security',
                        'description': 'IP address marked as suspicious by core security module'
                    }
                }
                matches.append(match)
        except Exception as e:
            logger.debug(f"Error checking core security for suspicious IP: {e}")

    return matches

def match_domain(
    domain: str,
    indicators: List[Dict[str, Any]],
    threshold: float = DEFAULT_MATCH_THRESHOLD
) -> List[Dict[str, Any]]:
    """
    Match a domain against indicators.

    Args:
        domain: Domain to match
        indicators: List of indicators to check against
        threshold: Confidence threshold for matches

    Returns:
        List of matching indicators with match details
    """
    if not domain or not indicators:
        return []

    # Normalize domain by removing leading/trailing dots and converting to lowercase
    normalized_domain = domain.strip('.').lower()

    matches = []

    # Check exact domain match and subdomain matches
    for indicator in indicators:
        indicator_type = indicator.get('indicator_type', '')
        indicator_value = indicator.get('value', '')

        if not indicator_value or not isinstance(indicator_value, str):
            continue

        # Normalize indicator value
        indicator_value = indicator_value.strip('.').lower()

        # Exact domain match
        if indicator_type in ('domain', 'hostname', 'fqdn') and indicator_value == normalized_domain:
            match = {
                'indicator_id': indicator.get('id', indicator.get('indicator_id')),
                'type': 'domain_exact',
                'value': domain,
                'matched_indicator': indicator_value,
                'confidence': 1.0,
                'indicator': indicator
            }
            matches.append(match)
            continue

        # Subdomain match - check if indicator is a parent domain of the input
        if indicator_type in ('domain', 'hostname', 'fqdn'):
            # Skip if indicator is not a valid domain pattern
            if not re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$', indicator_value):
                continue

            # Check if the domain is a subdomain of the indicator
            if normalized_domain.endswith('.' + indicator_value):
                # Calculate confidence based on subdomain specificity
                domain_parts = normalized_domain.split('.')
                indicator_parts = indicator_value.split('.')

                # More specific (longer) parent domains get higher confidence
                confidence = 0.7 + (0.3 * len(indicator_parts) / len(domain_parts))

                if confidence >= threshold:
                    match = {
                        'indicator_id': indicator.get('id', indicator.get('indicator_id')),
                        'type': 'domain_parent',
                        'value': domain,
                        'matched_indicator': indicator_value,
                        'confidence': confidence,
                        'indicator': indicator
                    }
                    matches.append(match)

    return matches

def match_file_hash(
    file_hash: str,
    indicators: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Match a file hash against indicators.

    Args:
        file_hash: Hash to match
        indicators: List of indicators to check against

    Returns:
        List of matching indicators with match details
    """
    if not file_hash or not indicators:
        return []

    # Normalize hash by converting to lowercase
    normalized_hash = file_hash.lower()

    matches = []

    # Check for exact hash matches
    for indicator in indicators:
        indicator_type = indicator.get('indicator_type', '')
        indicator_value = indicator.get('value', '')

        if not indicator_value or not isinstance(indicator_value, str):
            continue

        # Normalize indicator value
        indicator_value = indicator_value.lower()

        # Check if indicator type is a file hash
        if indicator_type in ('hash', 'md5', 'sha1', 'sha256', 'file_hash'):
            # For hash indicators, we only do exact matches
            if indicator_value == normalized_hash:
                match = {
                    'indicator_id': indicator.get('id', indicator.get('indicator_id')),
                    'type': 'hash_exact',
                    'value': file_hash,
                    'matched_indicator': indicator_value,
                    'confidence': 1.0,
                    'indicator': indicator
                }
                matches.append(match)

                # No need to check other indicators for this hash
                break

    # If no exact match found in our indicators, check for partial hash match if applicable
    if not matches and len(normalized_hash) >= 32:  # Only for longer hashes like SHA-256
        for indicator in indicators:
            indicator_type = indicator.get('indicator_type', '')
            indicator_value = indicator.get('value', '')

            if not indicator_value or not isinstance(indicator_value, str):
                continue

            # Normalize indicator value
            indicator_value = indicator_value.lower()

            # Check if this is a shorter hash (MD5 or SHA-1) that might be part of a longer hash
            if indicator_type in ('md5', 'sha1') and len(indicator_value) < len(normalized_hash):
                if normalized_hash.startswith(indicator_value):
                    match = {
                        'indicator_id': indicator.get('id', indicator.get('indicator_id')),
                        'type': 'hash_partial',
                        'value': file_hash,
                        'matched_indicator': indicator_value,
                        'confidence': 0.8,  # Lower confidence for partial match
                        'indicator': indicator
                    }
                    matches.append(match)

    return matches

def match_regex_pattern(
    text: str,
    pattern: str,
    indicator: Dict[str, Any],
    field_name: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Match text against a regex pattern indicator.

    Args:
        text: Text to match against
        pattern: Regular expression pattern string
        indicator: The indicator containing the regex pattern
        field_name: Name of the field being matched (for context)

    Returns:
        Match details if found, None otherwise
    """
    if not text or not pattern or not indicator:
        return None

    try:
        # Compile regex if not already in cache
        if pattern not in _regex_cache:
            _regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)

        compiled_pattern = _regex_cache[pattern]
        match_result = compiled_pattern.search(text)

        if match_result:
            matched_text = match_result.group(0)

            # Calculate confidence based on match length and pattern complexity
            match_length = len(matched_text)
            pattern_complexity = len(pattern)

            # Higher confidence for longer matches and more complex patterns
            confidence = min(1.0, (0.5 + (0.25 * match_length / len(text)) + (0.25 * pattern_complexity / 100)))

            return {
                'indicator_id': indicator.get('id', indicator.get('indicator_id')),
                'type': 'regex',
                'value': matched_text,
                'field_name': field_name,
                'matched_indicator': pattern,
                'confidence': confidence,
                'match_position': match_result.span(),
                'indicator': indicator
            }
    except re.error:
        logger.warning(f"Invalid regex pattern in indicator: {pattern}")
    except Exception as e:
        logger.error(f"Error matching regex pattern: {e}")

    return None

def calculate_match_confidence(
    match_details: Dict[str, Any],
    indicator: Dict[str, Any],
    base_confidence: float = 0.8
) -> float:
    """
    Calculate confidence score for a match based on various factors.

    Args:
        match_details: Details about the match
        indicator: The matched indicator
        base_confidence: Initial confidence score

    Returns:
        Confidence score between 0.0 and 1.0
    """
    confidence = base_confidence

    # Adjust confidence based on indicator-provided confidence
    indicator_confidence = indicator.get('confidence')
    if indicator_confidence is not None:
        if isinstance(indicator_confidence, (int, float)) and 0 <= indicator_confidence <= 1:
            # Weight the final confidence by the indicator's confidence
            confidence = confidence * indicator_confidence

    # Adjust confidence based on source reliability
    if 'source' in indicator:
        source = indicator['source']
        # Premium sources get higher confidence
        if source in ('premium_threat_feed', 'internal_analysis', 'incident_response'):
            confidence = min(1.0, confidence + 0.1)
        # Open source feeds get lower confidence
        elif source in ('open_source', 'community_feed'):
            confidence = max(0.1, confidence - 0.1)

    # Adjust confidence based on indicator age
    if 'created_at' in indicator:
        try:
            created_at = indicator['created_at']
            if isinstance(created_at, str):
                created_timestamp = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                age_days = (datetime.now(created_timestamp.tzinfo) - created_timestamp).days

                # Newer indicators get higher confidence
                if age_days < 7:  # Less than a week old
                    confidence = min(1.0, confidence + 0.05)
                # Older indicators get lower confidence
                elif age_days > 90:  # More than 3 months old
                    confidence = max(0.1, confidence - 0.1)
        except (ValueError, TypeError):
            pass

    # Ensure confidence is within valid range
    return max(0.0, min(1.0, confidence))

def update_indicator_cache(indicators: List[Dict[str, Any]]) -> None:
    """
    Update the in-memory indicator cache with new indicators.

    Args:
        indicators: List of indicators to cache
    """
    global _indicator_cache, _last_cache_update

    if not indicators:
        return

    # Update cache entries
    for indicator in indicators:
        if not isinstance(indicator, dict) or 'value' not in indicator:
            continue

        value = indicator['value']
        indicator_type = indicator.get('indicator_type', _guess_indicator_type(value))

        cache_key = f"{indicator_type}:{value}"
        _indicator_cache[cache_key] = indicator

    # Trim cache if it's getting too large
    if len(_indicator_cache) > DEFAULT_MAX_CACHE_SIZE:
        # Remove oldest entries
        excess_count = len(_indicator_cache) - DEFAULT_MAX_CACHE_SIZE
        # Sort by time added and remove oldest
        items = sorted(_indicator_cache.items(), key=lambda x: x[1].get('_cached_at', 0))
        keys_to_remove = [k for k, _ in items[:excess_count]]
        for key in keys_to_remove:
            _indicator_cache.pop(key, None)

    _last_cache_update = datetime.now()

# Helper functions

def _extract_ip_addresses(event: Dict[str, Any]) -> List[str]:
    """Extract IP addresses from an event."""
    ip_addresses = set()

    # Common field names that might contain IP addresses
    ip_fields = ['source_ip', 'destination_ip', 'src_ip', 'dst_ip', 'client_ip',
                'remote_ip', 'src_addr', 'dst_addr', 'client_addr', 'server_addr']

    # Extract IPs from known fields
    for field in ip_fields:
        if field in event and event[field]:
            value = event[field]
            if isinstance(value, str) and _is_valid_ip(value):
                ip_addresses.add(value)

    # Search recursively in nested fields
    nested_ips = _find_values_by_pattern(event, r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ip_addresses.update(ip for ip in nested_ips if _is_valid_ip(ip))

    return list(ip_addresses)

def _extract_domains(event: Dict[str, Any]) -> List[str]:
    """Extract domains from an event."""
    domains = set()

    # Common field names that might contain domains
    domain_fields = ['domain', 'hostname', 'fqdn', 'host', 'url', 'dns_query',
                   'src_domain', 'dst_domain', 'target', 'request_url']

    # Extract domains from known fields
    for field in domain_fields:
        if field in event and event[field]:
            value = event[field]
            if isinstance(value, str):
                # Extract domain from URL if needed
                if field in ('url', 'request_url') and ('://' in value):
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(value)
                        value = parsed.netloc
                    except Exception:
                        pass

                # Check for valid domain pattern
                if _is_valid_domain(value):
                    domains.add(value.lower())

    # Search for domain-like patterns in other fields
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'
    nested_domains = _find_values_by_pattern(event, domain_pattern)
    domains.update(domain.lower() for domain in nested_domains if _is_valid_domain(domain))

    return list(domains)

def _extract_file_hashes(event: Dict[str, Any]) -> List[str]:
    """Extract file hashes from an event."""
    hashes = set()

    # Common field names that might contain file hashes
    hash_fields = ['hash', 'file_hash', 'md5', 'sha1', 'sha256', 'imphash',
                 'process_hash', 'binary_hash']

    # Hash patterns for different algorithms
    md5_pattern = r'^[a-fA-F0-9]{32}$'
    sha1_pattern = r'^[a-fA-F0-9]{40}$'
    sha256_pattern = r'^[a-fA-F0-9]{64}$'

    # Extract hashes from known fields
    for field in hash_fields:
        if field in event and event[field]:
            value = event[field]
            if isinstance(value, str):
                # Check for valid hash patterns
                value = value.strip().lower()
                if (re.match(md5_pattern, value) or
                    re.match(sha1_pattern, value) or
                    re.match(sha256_pattern, value)):
                    hashes.add(value)

    # Search for hash-like patterns in other fields
    hash_combined_pattern = r'^[a-fA-F0-9]{32,64}$'
    nested_hashes = _find_values_by_pattern(event, hash_combined_pattern)
    for hash_value in nested_hashes:
        hash_value = hash_value.strip().lower()
        if (re.match(md5_pattern, hash_value) or
            re.match(sha1_pattern, hash_value) or
            re.match(sha256_pattern, hash_value)):
            hashes.add(hash_value)

    return list(hashes)

def _extract_text_fields(event: Dict[str, Any]) -> Dict[str, str]:
    """Extract text fields from an event for regex matching."""
    text_fields = {}

    # Fields to skip as they don't typically contain useful text
    skip_fields = {'id', 'timestamp', 'event_id', 'raw', '_id', 'time'}

    def _extract_text_recursive(data: Any, path: str = '') -> None:
        """Recursively extract text content from nested structures."""
        if isinstance(data, dict):
            for key, value in data.items():
                if key in skip_fields:
                    continue

                new_path = f"{path}.{key}" if path else key

                if isinstance(value, str) and len(value) >= 4:
                    text_fields[new_path] = value
                elif isinstance(value, (dict, list)):
                    _extract_text_recursive(value, new_path)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                if i >= 5:  # Limit array extraction to avoid excessive processing
                    break

                new_path = f"{path}[{i}]" if path else f"[{i}]"

                if isinstance(item, str) and len(item) >= 4:
                    text_fields[new_path] = item
                elif isinstance(item, (dict, list)):
                    _extract_text_recursive(item, new_path)

    # Extract text from the event
    _extract_text_recursive(event)

    # Include "message" field if available
    if event.get('message') and isinstance(event['message'], str):
        text_fields['message'] = event['message']

    # Include raw event content if small enough
    if event.get('raw') and isinstance(event['raw'], str) and len(event['raw']) < 10000:
        text_fields['raw'] = event['raw']

    return text_fields

def _find_values_by_pattern(data: Any, pattern: str) -> List[str]:
    """Find values matching a regex pattern in nested data structures."""
    values = []

    def _find_recursive(data: Any) -> None:
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    if re.match(pattern, value):
                        values.append(value)
                elif isinstance(value, (dict, list)):
                    _find_recursive(value)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    if re.match(pattern, item):
                        values.append(item)
                elif isinstance(item, (dict, list)):
                    _find_recursive(item)

    _find_recursive(data)
    return values

def _guess_indicator_type(value: str) -> str:
    """Guess the indicator type based on its value format."""
    if not isinstance(value, str):
        return 'unknown'

    # Check for IP address pattern
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return 'ip'
    elif re.match(r'^[a-fA-F0-9:]+$', value) and ':' in value:
        return 'ipv6'

    # Check for CIDR notation
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', value):
        return 'cidr'

    # Check for domain pattern
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$', value):
        return 'domain'

    # Check for common hash patterns
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'md5'
    elif re.match(r'^[a-fA-F0-9]{40}$', value):
        return 'sha1'
    elif re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'sha256'

    # Check for URL pattern
    if re.match(r'^https?://\S+$', value):
        return 'url'

    # If it starts with regex metachars, it's likely a regex
    if value.startswith('^') or value.endswith('$') or '*+?[]()' in value:
        return 'regex'

    return 'string'

def _is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def _is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain."""
    if not domain or len(domain) > 255:
        return False

    # Domain pattern check
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$', domain):
        return False

    # Check TLD validity (simplified version)
    tld = domain.split('.')[-1].lower()
    if len(tld) < 2 or not tld.isalpha():
        return False

    return True
