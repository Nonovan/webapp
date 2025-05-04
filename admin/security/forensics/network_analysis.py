"""
Network Analysis Module for Forensic Analysis Toolkit.

This module provides capabilities for analyzing network traffic captures (PCAPs)
to identify suspicious connections, extract indicators of compromise, and visualize
communication patterns. It leverages the forensic utility functions to maintain
evidence integrity throughout the analysis process.

The module follows forensic best practices to ensure all findings are properly
documented with timestamps, hashes, and chain of custody information.
"""

import os
import logging
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple, Union

# Initialize logger
logger = logging.getLogger(__name__)

# Try to import forensic utilities
try:
    from admin.security.forensics.utils.network_utils import (
        parse_pcap_file,
        extract_ips_from_pcap,
        extract_domains_from_pcap,
        extract_http_requests as utils_extract_http_requests,
        extract_dns_queries as utils_extract_dns_queries,
        classify_network_traffic,
        reassemble_tcp_stream,
        normalize_mac_address,
        normalize_ip_address,
        is_internal_ip
    )
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    from admin.security.forensics.utils.validation_utils import validate_path
    from admin.security.forensics.utils.crypto import calculate_file_hash
    FORENSIC_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Forensic utilities not fully available. Using fallback implementations.")
    FORENSIC_UTILS_AVAILABLE = False

    # Minimal fallback implementations if needed
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        """Log a forensic operation (fallback implementation)."""
        msg = f"Forensic operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logger.log(level, msg)

    def validate_path(path_str: str, **kwargs) -> Tuple[bool, str]:
        """Basic path validation (fallback implementation)."""
        if not os.path.exists(path_str):
            return False, f"Path does not exist: {path_str}"
        if kwargs.get('must_be_file') and not os.path.isfile(path_str):
            return False, f"Path is not a file: {path_str}"
        return True, "Path is valid"

    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash (fallback implementation)."""
        import hashlib
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.new(algorithm)
                for chunk in iter(lambda: f.read(4096), b''):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
            return None

def analyze_pcap(
    pcap_path: str,
    output_dir: Optional[str] = None,
    case_id: Optional[str] = None,
    analyst: Optional[str] = None,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Analyze a PCAP file to extract network communication patterns and indicators.

    This function performs a comprehensive analysis of network traffic, including:
    - Connection summaries and statistics
    - Protocol distribution analysis
    - Identification of suspicious patterns
    - Extraction of potential indicators of compromise
    - Identification of external communications

    Args:
        pcap_path: Path to the PCAP file
        output_dir: Directory for analysis output (optional)
        case_id: Case identifier for tracking and documentation (optional)
        analyst: Name of analyst performing the analysis (optional)
        options: Dictionary of analysis options (optional)
            - include_private_ips: Whether to include private IPs in analysis (default: False)
            - max_connections: Maximum connections to process (default: 100000)
            - detect_suspicious: Whether to detect suspicious network activity (default: True)

    Returns:
        Dictionary containing analysis results with sections for connections,
        DNS queries, HTTP requests, and detected anomalies

    Raises:
        FileNotFoundError: If the PCAP file doesn't exist
        ValueError: If the PCAP file is invalid or corrupted
    """
    # Default options
    if options is None:
        options = {}

    include_private_ips = options.get('include_private_ips', False)
    max_connections = options.get('max_connections', 100000)
    detect_suspicious = options.get('detect_suspicious', True)

    # Validate input file
    is_valid, msg = validate_path(pcap_path, must_be_file=True, check_read=True)
    if not is_valid:
        error_msg = f"Invalid PCAP file: {msg}"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)

    # Create operation details for logging
    operation_details = {
        "pcap_path": pcap_path,
        "output_dir": output_dir,
        "case_id": case_id,
        "analyst": analyst,
        "include_private_ips": include_private_ips,
        "max_connections": max_connections
    }

    log_forensic_operation("analyze_pcap_start", True, operation_details)

    # Initialize results dictionary
    results = {
        "pcap_file": pcap_path,
        "pcap_hash": calculate_file_hash(pcap_path),
        "analysis_timestamp": datetime.now().isoformat(),
        "analyst": analyst,
        "case_id": case_id,
        "summary": {},
        "connections": {},
        "dns_queries": {},
        "http_requests": [],
        "suspicious_activity": [],
        "output_files": []
    }

    try:
        # Create output directory if specified
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        start_time = time.time()

        # Perform traffic classification
        traffic_analysis = classify_network_traffic(pcap_path)
        results["summary"]["traffic_classification"] = {
            "protocol_distribution": traffic_analysis.get("protocol_distribution", {}),
            "external_connections_count": len(traffic_analysis.get("external_connections", [])),
            "suspicious_patterns_count": len(traffic_analysis.get("suspicious_patterns", [])),
            "top_talkers": traffic_analysis.get("top_talkers", [])[:10]  # Limit to top 10
        }

        # Extract connections
        connections = extract_connections(pcap_path, include_private=include_private_ips)
        results["connections"] = {
            "summary": {
                "total": len(connections),
                "internal": sum(1 for conn in connections if is_internal_ip(conn.get("dst_ip", ""))),
                "external": sum(1 for conn in connections if not is_internal_ip(conn.get("dst_ip", "")))
            },
            "connections": connections[:max_connections]  # Limit the number of connections
        }

        # Extract DNS queries
        dns_results = extract_dns_queries(pcap_path)
        results["dns_queries"] = {
            "count": len(dns_results),
            "queries": dns_results
        }

        # Extract HTTP requests
        http_results = extract_http_requests(pcap_path)
        results["http_requests"] = {
            "count": len(http_results),
            "requests": http_results
        }

        # Extract external connections for suspicious activity
        if detect_suspicious:
            results["suspicious_activity"] = traffic_analysis.get("suspicious_patterns", [])
            results["summary"]["external_connections"] = traffic_analysis.get("external_connections", [])[:50]  # Limit to 50

        # Save results to file if output directory is specified
        if output_dir:
            results_file = os.path.join(output_dir, "network_analysis_results.json")
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            results["output_files"].append(results_file)

            # Save additional output files for different aspects of the analysis
            if len(connections) > 0:
                connections_file = os.path.join(output_dir, "connections.json")
                with open(connections_file, 'w') as f:
                    json.dump(connections, f, indent=2)
                results["output_files"].append(connections_file)

            if len(dns_results) > 0:
                dns_file = os.path.join(output_dir, "dns_queries.json")
                with open(dns_file, 'w') as f:
                    json.dump(dns_results, f, indent=2)
                results["output_files"].append(dns_file)

            if len(http_results) > 0:
                http_file = os.path.join(output_dir, "http_requests.json")
                with open(http_file, 'w') as f:
                    json.dump(http_results, f, indent=2)
                results["output_files"].append(http_file)

        # Calculate total analysis duration
        end_time = time.time()
        results["analysis_duration_seconds"] = round(end_time - start_time, 3)

        # Update operation details with analysis stats
        operation_details.update({
            "connections_count": len(connections),
            "dns_queries_count": len(dns_results),
            "http_requests_count": len(http_results),
            "suspicious_count": len(results["suspicious_activity"]),
            "duration_seconds": results["analysis_duration_seconds"]
        })

        log_forensic_operation("analyze_pcap_complete", True, operation_details)
        return results

    except Exception as e:
        error_msg = f"PCAP analysis failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        operation_details["error"] = str(e)
        log_forensic_operation("analyze_pcap_error", False, operation_details, level=logging.ERROR)

        # Provide partial results if available
        results["error"] = str(e)
        results["status"] = "error"
        return results

def extract_connections(pcap_path: str, include_private: bool = False) -> List[Dict[str, Any]]:
    """
    Extract network connections from a PCAP file.

    Args:
        pcap_path: Path to the PCAP file
        include_private: Whether to include private/internal IP addresses

    Returns:
        List of dictionaries containing connection information
    """
    operation_details = {
        "pcap_path": pcap_path,
        "include_private": include_private
    }

    log_forensic_operation("extract_connections_start", True, operation_details)

    try:
        # Validate input file
        is_valid, msg = validate_path(pcap_path, must_be_file=True, check_read=True)
        if not is_valid:
            error_msg = f"Invalid PCAP file: {msg}"
            logger.error(error_msg)
            log_forensic_operation("extract_connections_error", False,
                                 {**operation_details, "error": error_msg},
                                 level=logging.ERROR)
            return []

        # Use the network_utils to extract IPs, then transform to connections format
        ip_data = extract_ips_from_pcap(pcap_path, include_private=include_private)

        connections = []

        # Process source IPs and their connections
        for src_ip, packets in ip_data.get('source_ips', {}).items():
            for packet in packets:
                connection = {
                    "timestamp": packet.get('timestamp'),
                    "src_ip": src_ip,
                    "dst_ip": packet.get('dst_ip', ''),
                    "src_port": packet.get('src_port'),
                    "dst_port": packet.get('dst_port'),
                    "protocol": packet.get('proto')
                }
                connections.append(connection)

        operation_details["connections_count"] = len(connections)
        log_forensic_operation("extract_connections_complete", True, operation_details)
        return connections

    except Exception as e:
        error_msg = f"Failed to extract connections: {str(e)}"
        logger.error(error_msg, exc_info=True)
        log_forensic_operation("extract_connections_error", False,
                             {**operation_details, "error": error_msg},
                             level=logging.ERROR)
        return []

def extract_dns_queries(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Extract DNS queries from a PCAP file.

    Args:
        pcap_path: Path to the PCAP file

    Returns:
        List of dictionaries containing DNS query information
    """
    operation_details = {
        "pcap_path": pcap_path
    }

    log_forensic_operation("extract_dns_queries_start", True, operation_details)

    try:
        # Validate input file
        is_valid, msg = validate_path(pcap_path, must_be_file=True, check_read=True)
        if not is_valid:
            error_msg = f"Invalid PCAP file: {msg}"
            logger.error(error_msg)
            log_forensic_operation("extract_dns_queries_error", False,
                                 {**operation_details, "error": error_msg},
                                 level=logging.ERROR)
            return []

        # Check if we have the utils implementation available
        if FORENSIC_UTILS_AVAILABLE:
            # Use the implementation from network_utils
            dns_queries = utils_extract_dns_queries(pcap_path)

            operation_details["queries_count"] = len(dns_queries)
            log_forensic_operation("extract_dns_queries_complete", True, operation_details)
            return dns_queries
        else:
            # Fallback implementation - try to parse from domain extraction
            domains = extract_domains_from_pcap(pcap_path)
            queries = []

            # Convert from domain dictionary to DNS query list
            for domain, entries in domains.items():
                for entry in entries:
                    if entry.get('source') == 'dns_query':
                        queries.append({
                            "timestamp": entry.get('timestamp'),
                            "query_name": domain,
                            "query_type": entry.get('query_type', 'A'),
                            "source_ip": entry.get('src_ip'),
                            "destination_ip": entry.get('dst_ip')
                        })

            operation_details["queries_count"] = len(queries)
            log_forensic_operation("extract_dns_queries_complete", True, operation_details)
            return queries

    except Exception as e:
        error_msg = f"Failed to extract DNS queries: {str(e)}"
        logger.error(error_msg, exc_info=True)
        log_forensic_operation("extract_dns_queries_error", False,
                             {**operation_details, "error": error_msg},
                             level=logging.ERROR)
        return []

def extract_http_requests(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Extract HTTP requests from a PCAP file.

    Args:
        pcap_path: Path to the PCAP file

    Returns:
        List of dictionaries containing HTTP request information
    """
    operation_details = {
        "pcap_path": pcap_path
    }

    log_forensic_operation("extract_http_requests_start", True, operation_details)

    try:
        # Validate input file
        is_valid, msg = validate_path(pcap_path, must_be_file=True, check_read=True)
        if not is_valid:
            error_msg = f"Invalid PCAP file: {msg}"
            logger.error(error_msg)
            log_forensic_operation("extract_http_requests_error", False,
                                 {**operation_details, "error": error_msg},
                                 level=logging.ERROR)
            return []

        # Check if we have the utils implementation available
        if FORENSIC_UTILS_AVAILABLE:
            # Use the implementation from network_utils
            http_requests = utils_extract_http_requests(pcap_path)

            operation_details["requests_count"] = len(http_requests)
            log_forensic_operation("extract_http_requests_complete", True, operation_details)
            return http_requests
        else:
            # Fallback implementation - try to parse from domain extraction with HTTP host
            domains = extract_domains_from_pcap(pcap_path)
            requests = []

            # Convert from domain dictionary to HTTP request list
            for domain, entries in domains.items():
                for entry in entries:
                    if entry.get('source') == 'http_host':
                        requests.append({
                            "timestamp": entry.get('timestamp'),
                            "method": entry.get('http_method', 'GET'),
                            "uri": entry.get('uri', '/'),
                            "host": domain,
                            "url": f"http://{domain}{entry.get('uri', '/')}",
                            "source_ip": entry.get('src_ip'),
                            "destination_ip": entry.get('dst_ip')
                        })

            operation_details["requests_count"] = len(requests)
            log_forensic_operation("extract_http_requests_complete", True, operation_details)
            return requests

    except Exception as e:
        error_msg = f"Failed to extract HTTP requests: {str(e)}"
        logger.error(error_msg, exc_info=True)
        log_forensic_operation("extract_http_requests_error", False,
                             {**operation_details, "error": error_msg},
                             level=logging.ERROR)
        return []
