#!/usr/bin/env python3

"""
Artifact Parser for Live Response Data

Parses and analyzes artifacts collected by the live response tools
(e.g., process lists, network connections, command history)
to provide structured insights for forensic investigations.
"""

import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Attempt to import core forensic utilities
try:
    from admin.security.forensics.utils.logging_utils import (
        setup_forensic_logger, log_forensic_operation
    )
    from admin.security.forensics.utils.validation_utils import validate_path
    from admin.security.forensics.utils.report_builder import save_analysis_report
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_TIMESTAMP_FORMAT,
        FORENSIC_LOG_DIR,
        DEFAULT_SECURE_FILE_PERMS
    )
    # Optional: Import evidence tracker if available
    try:
        from admin.security.forensics.utils.evidence_tracker import (
            track_analysis, get_evidence_details, register_analysis_result
        )
        EVIDENCE_TRACKING_AVAILABLE = True
    except ImportError:
        EVIDENCE_TRACKING_AVAILABLE = False
    FORENSIC_CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Core forensic utilities not found, using basic logging: {e}", file=sys.stderr)
    FORENSIC_CORE_AVAILABLE = False
    EVIDENCE_TRACKING_AVAILABLE = False
    # Basic logging fallback
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('artifact_parser_fallback')
    DEFAULT_SECURE_FILE_PERMS_FALLBACK = 0o600
    DEFAULT_TIMESTAMP_FORMAT_FALLBACK = "%Y-%m-%d %H:%M:%S %Z"

    # Dummy log_forensic_operation
    def log_forensic_operation(operation: str, success: bool, details: Dict[str, Any], level: int = logging.INFO):
        logger.log(level, f"Operation='{operation}', Success={success}, Details={json.dumps(details, default=str)}")

    # Dummy validate_path
    def validate_path(path: str, **kwargs) -> Tuple[bool, str]:
        if not os.path.exists(path):
            return False, f"Path does not exist: {path}"
        if kwargs.get('check_read') and not os.access(path, os.R_OK):
            return False, f"Path not readable: {path}"
        if kwargs.get('must_be_file') and not os.path.isfile(path):
            return False, f"Path is not a file: {path}"
        if kwargs.get('must_be_dir') and not os.path.isdir(path):
            return False, f"Path is not a directory: {path}"
        return True, "Path is valid"

    # Dummy save_analysis_report
    def save_analysis_report(data: Dict[str, Any], output_path: str, format_type: str = "json") -> bool:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                if format_type == 'json':
                    json.dump(data, f, indent=2, default=str)
                else:  # Basic text fallback
                    for key, value in data.items():
                        f.write(f"{key}:\n")
                        if isinstance(value, (list, dict)):
                            json.dump(value, f, indent=2, default=str)
                            f.write("\n")
                        else:
                            f.write(f"  {value}\n")
            # Set secure permissions
            os.chmod(output_path, DEFAULT_SECURE_FILE_PERMS)
            return True
        except IOError as e:
            logger.error(f"Failed to save report to {output_path}: {e}")
            return False

# Setup logger if core utils are available
if FORENSIC_CORE_AVAILABLE:
    setup_forensic_logger()
    logger = logging.getLogger('forensic_artifact_parser')
else:
    # logger is already set to the fallback
    pass

# --- Constants ---
APP_VERSION = "1.1.0"
APP_DATE = "2024-07-31"
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_OUTPUT_FORMATS = ["json", "text", "csv", "yaml"]
DEFAULT_ARTIFACT_DIR = "live_response_output"

# Regex for common patterns
REGEX_IP_ADDR = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
REGEX_IPV6_ADDR = re.compile(r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
REGEX_DOMAIN = re.compile(r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
REGEX_SUSPICIOUS_CMD = re.compile(
    r'(?:powershell.*(?:enc|iex|downloadstring|bypass)|'
    r'nc\s+(?:-\w*[e]\w*|[\d\.]+\s+\d+)|'
    r'wget\s+(?:-O|http)|'
    r'curl\s+(?:-o|http)|'
    r'chmod\s+(?:\+[a-zA-Z]*x|777)|'
    r'base64\s+(?:-\w*d|[-a-zA-Z0-9+/=]{20,})|'
    r'certutil\s+(?:-urlcache|-encode|-decode)|'
    r'\bdlltojpeg\b|'
    r'echo\s+.*\|\s*(?:base64|sh)|'
    r'eval\(|'
    r'dd\s+(?:if=/dev/|of=/dev/)|'
    r'mkfifo\s+.*>\s*/dev/|'
    r'\bsudo\s+(?:su\b|-\b|/bin/bash\b)|'
    r'(?:python|perl|ruby|php)\s+-[ec])',
    re.IGNORECASE
)
REGEX_PRIVILEGE_ESCALATION = re.compile(
    r'(?:sudo\s+su|sudo\s+-|sudo\s+bash|setuid|setgid|chmod\s+[u+]s|'
    r'pkexec|doas|polkit|pwnkit|CVE-\d{4}-\d+)',
    re.IGNORECASE
)
REGEX_DATA_EXFIL = re.compile(
    r'(?:scp\s+.*@|'
    r'tar\s+(?:c|z|j).*\s+\w+@\w+:|'
    r'rsync\s+-.*\s+\w+@\w+:|'
    r'sftp\s+\w+@|'
    r'ftp\s+(?:-\w+\s+)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    re.IGNORECASE
)
REGEX_COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MS RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}
REGEX_UNUSUAL_SHELL = re.compile(
    r'(?:/dev/tcp/|/dev/udp/|pty\.spawn|socat\s+(?:tcp|udp|exec))',
    re.IGNORECASE
)

# --- Argument Parser Setup ---

def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Live Response Artifact Parser and Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse all artifacts in a directory and output JSON
  python artifact_parser.py --input-dir /secure/evidence/incident-42/live_response/ --output report.json

  # Analyze process list and network connections from specific files
  python artifact_parser.py --process-file processes.txt --network-file network.json --analyze-processes --analyze-network

  # Detect suspicious commands from command history file
  python artifact_parser.py --history-file bash_history.log --detect-suspicious-commands --format text

  # Register analysis results with the evidence tracking system
  python artifact_parser.py --input-dir /secure/evidence/incident-42/live_response/ --case-id CASE-2024-42 --evidence-id E001 --analyst "jdoe"
"""
    )

    # Input sources
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--input-dir', help='Directory containing collected live response artifacts.')
    input_group.add_argument('--process-file', help='Path to process list artifact file.')

    # Additional input files
    parser.add_argument('--network-file', help='Path to network connections artifact file (if not in input-dir).')
    parser.add_argument('--history-file', help='Path to command history artifact file (if not in input-dir).')
    parser.add_argument('--file-list-file', help='Path to open files list artifact file (if not in input-dir).')
    parser.add_argument('--user-file', help='Path to user session artifact file (if not in input-dir).')
    parser.add_argument('--modules-file', help='Path to kernel modules artifact file (if not in input-dir).')

    # Analysis options
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument('--analyze-processes', action='store_true',
                              help='Analyze process list (build tree, detect suspicious).')
    analysis_group.add_argument('--analyze-network', action='store_true',
                              help='Analyze network connections (map connections, flag suspicious ports).')
    analysis_group.add_argument('--detect-suspicious-commands', action='store_true',
                              help='Analyze command history for suspicious patterns.')
    analysis_group.add_argument('--detect-data-exfil', action='store_true',
                              help='Detect potential data exfiltration attempts in commands.')
    analysis_group.add_argument('--detect-privilege-escalation', action='store_true',
                              help='Detect privilege escalation attempts in commands.')
    analysis_group.add_argument('--full-analysis', action='store_true',
                              help='Perform all available analyses.')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output', help='Path for output analysis report (default: stdout).')
    output_group.add_argument('--format', choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                            help=f'Output format (default: {DEFAULT_OUTPUT_FORMAT}).')
    output_group.add_argument('--overwrite', action='store_true',
                            help='Overwrite output file if it exists.')
    output_group.add_argument('--summary-only', action='store_true',
                            help='Output only summary information without full details.')

    # Forensic context
    forensic_group = parser.add_argument_group('Forensic Context')
    forensic_group.add_argument('--case-id', help='Case ID for forensic logging.')
    forensic_group.add_argument('--evidence-id', help='Evidence ID for forensic tracking.')
    forensic_group.add_argument('--analyst', help='Analyst name for forensic logging.')
    forensic_group.add_argument('--register-results', action='store_true',
                              help='Register analysis results with evidence tracking system (requires case-id and evidence-id).')

    # Verbosity
    parser.add_argument('--verbose', '-v', action='count', default=0,
                      help='Increase verbosity (can be used multiple times).')
    parser.add_argument('--quiet', '-q', action='store_true',
                      help='Suppress all output except errors.')
    parser.add_argument('--version', action='store_true',
                      help='Show version information and exit.')

    return parser

# --- Parsing Functions ---

def parse_process_list(file_path: str) -> List[Dict[str, Any]]:
    """
    Parses a process list artifact file.

    Supports multiple formats:
    1. Standard columns format (PID PPID USER CMD)
    2. Extended format with headers
    3. JSON format
    """
    processes = []
    logger.info(f"Parsing process list from: {file_path}")
    try:
        # First determine if this is a JSON file
        if file_path.endswith(".json"):
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        processes = data
                    elif isinstance(data, dict) and "processes" in data:
                        processes = data["processes"]
                    logger.info(f"Parsed {len(processes)} processes from JSON.")
                    return processes
                except json.JSONDecodeError:
                    logger.warning(f"File has .json extension but is not valid JSON: {file_path}. Trying text format.")

        # Text format parsing
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read the first line to determine format
            first_line = f.readline().strip()

            # If empty file, return empty list
            if not first_line:
                logger.warning(f"Empty process file: {file_path}")
                return processes

            # Reset file pointer
            f.seek(0)

            # Check if the file has headers (based on common header names)
            has_headers = any(header in first_line.lower() for header in ["pid", "ppid", "user", "command", "cmd"])

            if has_headers:
                # Process with headers
                header_line = f.readline().strip().lower()
                headers = re.split(r'\s+', header_line, maxsplit=3)

                # Try to identify column positions
                pid_idx = next((i for i, h in enumerate(headers) if "pid" == h), -1)
                ppid_idx = next((i for i, h in enumerate(headers) if "ppid" == h), -1)
                user_idx = next((i for i, h in enumerate(headers) if "user" == h), -1)
                cmd_idx = next((i for i, h in enumerate(headers) if h in ["cmd", "command"]), -1)

                if pid_idx == -1 or cmd_idx == -1:
                    logger.warning(f"Could not identify required columns in headers: {headers}")

                # Parse each process line
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Split line respecting command with spaces
                    parts = re.split(r'\s+', line, maxsplit=max(3, len(headers)-1))
                    if len(parts) >= max(pid_idx+1, cmd_idx+1):
                        try:
                            process = {
                                "pid": int(parts[pid_idx]) if pid_idx >= 0 else None,
                                "ppid": int(parts[ppid_idx]) if ppid_idx >= 0 and ppid_idx < len(parts) else None,
                                "user": parts[user_idx] if user_idx >= 0 and user_idx < len(parts) else None,
                                "command": parts[cmd_idx] if cmd_idx >= 0 else ' '.join(parts[3:]),
                                "raw_line": line
                            }
                            processes.append(process)
                        except (ValueError, IndexError) as e:
                            logger.warning(f"Skipping malformed process line: '{line}'. Error: {e}")
                    else:
                        logger.warning(f"Line has insufficient fields: '{line}'")

            else:
                # No headers - assume standard ps format (PID PPID USER COMMAND)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    parts = re.split(r'\s+', line, maxsplit=3)
                    if len(parts) >= 4:
                        try:
                            process = {
                                "pid": int(parts[0]),
                                "ppid": int(parts[1]),
                                "user": parts[2],
                                "command": parts[3],
                                "raw_line": line
                            }
                            processes.append(process)
                        except (ValueError, IndexError) as e:
                            logger.warning(f"Skipping malformed process line: '{line}'. Error: {e}")

    except IOError as e:
        logger.error(f"Error reading process file {file_path}: {e}")

    logger.info(f"Parsed {len(processes)} processes.")
    return processes

def parse_network_connections(file_path: str) -> List[Dict[str, Any]]:
    """
    Parses a network connections artifact file.

    Supports multiple formats:
    1. JSON format
    2. Text format (basic handling for netstat/ss output)
    """
    connections = []
    logger.info(f"Parsing network connections from: {file_path}")

    try:
        # First try to parse as JSON
        if file_path.endswith(".json"):
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    # Handle various JSON formats
                    if isinstance(data, list):
                        connections = data
                    elif isinstance(data, dict):
                        if "connections" in data:
                            connections = data["connections"]
                        elif "network_connections" in data:
                            connections = data["network_connections"]
                        else:
                            # Assume the entire object is the connections data
                            connections = [data]

                    logger.info(f"Parsed {len(connections)} connections from JSON.")
                    return connections
                except json.JSONDecodeError:
                    logger.warning(f"File has .json extension but is not valid JSON: {file_path}. Trying text format.")

        # Text format parsing (basic netstat/ss output format)
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read first line to check for headers
            first_line = f.readline().strip().lower()

            # Check if this looks like netstat/ss output
            has_netstat_headers = any(header in first_line for header in ["proto", "local", "foreign", "state"])

            if has_netstat_headers:
                # Skip header line
                next_line = f.readline()

                # Parse each connection line
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("Active") or line.startswith("Proto"):
                        continue

                    parts = re.split(r'\s+', line)
                    if len(parts) >= 4:
                        try:
                            # Basic parsing for netstat-like output
                            connection = {
                                "protocol": parts[0].lower(),
                                "raw_line": line
                            }

                            # Parse local address
                            local_addr = parts[3]
                            if ":" in local_addr:
                                local_parts = local_addr.rsplit(":", 1)
                                connection["local_ip"] = local_parts[0]
                                connection["local_port"] = int(local_parts[1])

                            # Parse remote address if available
                            if len(parts) > 4:
                                remote_addr = parts[4]
                                if ":" in remote_addr:
                                    remote_parts = remote_addr.rsplit(":", 1)
                                    connection["remote_ip"] = remote_parts[0]
                                    connection["remote_port"] = int(remote_parts[1])

                            # Get state if available
                            if len(parts) > 5:
                                connection["state"] = parts[5]

                            # Get PID/program if available
                            if len(parts) > 6:
                                pid_prog = parts[6]
                                if "/" in pid_prog:
                                    pid, prog = pid_prog.split("/", 1)
                                    try:
                                        connection["pid"] = int(pid)
                                        connection["program"] = prog
                                    except ValueError:
                                        connection["program"] = pid_prog

                            connections.append(connection)
                        except (ValueError, IndexError) as e:
                            logger.warning(f"Skipping malformed connection line: '{line}'. Error: {e}")
            else:
                # Reset file and try another format
                f.seek(0)

                # Simple line-by-line parsing for unknown formats
                # This is a fallback method with minimal parsing
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Minimal processing - extract IPs and ports where possible
                    ip_addresses = REGEX_IP_ADDR.findall(line)
                    connection = {"raw_line": line}

                    if len(ip_addresses) >= 1:
                        connection["local_ip"] = ip_addresses[0]
                    if len(ip_addresses) >= 2:
                        connection["remote_ip"] = ip_addresses[1]

                    # Look for port numbers
                    port_matches = re.findall(r':(\d+)\b', line)
                    if len(port_matches) >= 1:
                        try:
                            connection["local_port"] = int(port_matches[0])
                        except ValueError:
                            pass
                    if len(port_matches) >= 2:
                        try:
                            connection["remote_port"] = int(port_matches[1])
                        except ValueError:
                            pass

                    # Try to extract protocol
                    if "tcp" in line.lower():
                        connection["protocol"] = "tcp"
                    elif "udp" in line.lower():
                        connection["protocol"] = "udp"

                    # Only add connection if we extracted some useful data
                    if len(connection) > 1:
                        connections.append(connection)

    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from network file {file_path}: {e}")
    except IOError as e:
        logger.error(f"Error reading network file {file_path}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error parsing network file {file_path}: {e}")

    logger.info(f"Parsed {len(connections)} network connections.")
    return connections

def parse_command_history(file_path: str) -> List[Dict[str, Any]]:
    """
    Parses a command history file.

    Returns a list of command entries with metadata.

    Supports:
    1. Standard history files (.bash_history)
    2. JSON format
    3. Timestamped history lines
    """
    history_entries = []
    logger.info(f"Parsing command history from: {file_path}")

    try:
        # Try JSON format first if applicable
        if file_path.endswith(".json"):
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        for i, entry in enumerate(data):
                            if isinstance(entry, str):
                                history_entries.append({"line_number": i+1, "command": entry})
                            elif isinstance(entry, dict) and "command" in entry:
                                entry["line_number"] = i+1
                                history_entries.append(entry)
                    elif isinstance(data, dict) and "command_history" in data:
                        for i, entry in enumerate(data["command_history"]):
                            if isinstance(entry, str):
                                history_entries.append({"line_number": i+1, "command": entry})
                            elif isinstance(entry, dict) and "command" in entry:
                                entry["line_number"] = i+1
                                history_entries.append(entry)
                    logger.info(f"Parsed {len(history_entries)} history entries from JSON.")
                    return history_entries
                except json.JSONDecodeError:
                    logger.warning(f"File has .json extension but is not valid JSON: {file_path}. Trying text format.")
                    # Reset file pointer
                    f.seek(0)

        # Text format parsing
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            line_number = 1
            timestamp = None

            for line in f:
                line = line.strip()
                if not line:
                    line_number += 1
                    continue

                # Check for timestamp format used in HISTTIMEFORMAT output
                # Example: "#1617285942" or "# 2021-04-01 12:45:42"
                if line.startswith("#"):
                    # Try to extract timestamp
                    if re.match(r'^#\d{10,}$', line):
                        # Unix timestamp format: "#1617285942"
                        try:
                            timestamp = int(line.lstrip('#').strip())
                        except ValueError:
                            timestamp = None
                    elif re.match(r'^#\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', line):
                        # ISO-like timestamp: "# 2021-04-01 12:45:42"
                        try:
                            timestamp_str = line.lstrip('#').strip()
                            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").timestamp()
                        except ValueError:
                            timestamp = None
                    line_number += 1
                    continue

                # Regular command line
                entry = {
                    "line_number": line_number,
                    "command": line
                }

                # Add timestamp if available
                if timestamp:
                    entry["timestamp"] = timestamp
                    # Format human-readable timestamp
                    try:
                        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                        entry["timestamp_iso"] = dt.isoformat()
                    except (ValueError, TypeError):
                        pass
                    timestamp = None  # Clear timestamp for next entry

                history_entries.append(entry)
                line_number += 1

    except IOError as e:
        logger.error(f"Error reading command history file {file_path}: {e}")

    logger.info(f"Parsed {len(history_entries)} history entries.")
    return history_entries

def parse_user_sessions(file_path: str) -> List[Dict[str, Any]]:
    """Parses a user sessions file (e.g., output of 'w' or 'who')."""
    sessions = []
    logger.info(f"Parsing user sessions from: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Skip header line if present
            first_line = f.readline()

            # Check if this is a header line
            is_header = "user" in first_line.lower() or "from" in first_line.lower()

            if not is_header:
                f.seek(0)  # Reset to beginning if not a header

            # Process each line
            for line in f:
                line = line.strip()
                if not line or line.startswith("USER ") or line.startswith("up "):
                    continue

                parts = re.split(r'\s+', line, maxsplit=7)
                if len(parts) >= 5:
                    session = {
                        "user": parts[0],
                        "tty": parts[1],
                        "raw_line": line
                    }

                    # Try to extract login source (IP/hostname)
                    from_pattern = r'\(([^\)]+)\)'
                    from_match = re.search(from_pattern, line)
                    if from_match:
                        session["from"] = from_match.group(1)

                    # Try to extract login time
                    if len(parts) >= 4:
                        # Simple time extraction - format varies by system
                        session["login_time"] = " ".join(parts[2:4])

                    sessions.append(session)

    except IOError as e:
        logger.error(f"Error reading user sessions file {file_path}: {e}")

    logger.info(f"Parsed {len(sessions)} user sessions.")
    return sessions

def parse_kernel_modules(file_path: str) -> List[Dict[str, Any]]:
    """Parses a kernel modules list (e.g., output of 'lsmod')."""
    modules = []
    logger.info(f"Parsing kernel modules from: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Skip header line if present
            first_line = f.readline()

            # Check if this is a header line
            is_header = "module" in first_line.lower() or "size" in first_line.lower()

            if not is_header:
                f.seek(0)  # Reset to beginning if not a header

            # Process each line
            for line in f:
                line = line.strip()
                if not line or line.startswith("Module"):
                    continue

                parts = re.split(r'\s+', line)
                if len(parts) >= 3:
                    try:
                        module = {
                            "name": parts[0],
                            "size": int(parts[1]),
                            "raw_line": line
                        }

                        # Parse usage count
                        if len(parts) >= 3 and parts[2].isdigit():
                            module["use_count"] = int(parts[2])

                        # Parse used_by modules
                        if len(parts) >= 4:
                            used_by = parts[3].strip()
                            if used_by and used_by != "-":
                                module["used_by"] = [mod.strip() for mod in used_by.split(",")]

                        modules.append(module)
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Skipping malformed module line: '{line}'. Error: {e}")

    except IOError as e:
        logger.error(f"Error reading kernel modules file {file_path}: {e}")

    logger.info(f"Parsed {len(modules)} kernel modules.")
    return modules

def parse_open_files(file_path: str) -> List[Dict[str, Any]]:
    """Parses an open files list (e.g., output of 'lsof')."""
    open_files = []
    logger.info(f"Parsing open files from: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Skip header line if present
            first_line = f.readline()

            # Check if this is a header line
            is_header = "command" in first_line.lower() or "pid" in first_line.lower()

            if not is_header:
                f.seek(0)  # Reset to beginning if not a header

            # Process each line
            for line in f:
                line = line.strip()
                if not line or line.startswith("COMMAND"):
                    continue

                # lsof format is complex, do basic parsing
                parts = re.split(r'\s+', line)
                if len(parts) >= 7:
                    try:
                        file_entry = {
                            "command": parts[0],
                            "pid": int(parts[1]) if parts[1].isdigit() else parts[1],
                            "user": parts[2],
                            "fd": parts[3],
                            "type": parts[4],
                            "device": parts[5],
                            "size": int(parts[6]) if parts[6].isdigit() else 0,
                            "raw_line": line
                        }

                        # Extract the filename/path
                        if len(parts) >= 9:
                            file_entry["path"] = " ".join(parts[8:])
                        elif len(parts) >= 8:
                            file_entry["path"] = parts[7]

                        open_files.append(file_entry)
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Skipping malformed open file line: '{line}'. Error: {e}")

    except IOError as e:
        logger.error(f"Error reading open files list {file_path}: {e}")

    logger.info(f"Parsed {len(open_files)} open file entries.")
    return open_files

# --- Analysis Functions ---

def build_process_tree(processes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Builds a process tree from a list of processes.

    Returns a dictionary with root processes and full hierarchy.
    """
    tree = defaultdict(lambda: {"process": None, "children": []})
    process_map = {p["pid"]: p for p in processes if p.get("pid") is not None}

    # Build the tree structure
    for pid, process_data in process_map.items():
        tree[pid]["process"] = process_data
        ppid = process_data.get("ppid")
        if ppid is not None and ppid != pid:  # Avoid self-parenting
            tree[ppid]["children"].append(pid)

    # Identify root nodes (those whose parent is not in the map or is 0/1)
    root_pids = [pid for pid, data in tree.items()
                if data["process"] and (
                    data["process"].get("ppid") is None or
                    data["process"].get("ppid") not in process_map or
                    data["process"].get("ppid") in [0, 1]
                )]

    # Return a structure containing roots and the full tree map
    return {
        "roots": root_pids,
        "tree": dict(tree),
        "node_count": len(tree),
        "root_count": len(root_pids),
        "max_depth": calculate_max_tree_depth(dict(tree), root_pids)
    }

def calculate_max_tree_depth(tree: Dict[int, Dict[str, Any]], root_pids: List[int], current_depth: int = 0) -> int:
    """Calculate the maximum depth of the process tree."""
    if not root_pids:
        return current_depth

    next_level = []
    for pid in root_pids:
        if pid in tree and tree[pid].get("children"):
            next_level.extend(tree[pid]["children"])

    if not next_level:
        return current_depth + 1

    return calculate_max_tree_depth(tree, next_level, current_depth + 1)

def detect_suspicious_processes(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identifies potentially suspicious processes based on patterns.

    Includes checks for:
    1. Suspicious command patterns (obfuscation, unusual commands)
    2. Privilege escalation attempts
    3. Unusual parent-child relationships
    4. Unusual users running privileged programs
    5. Known malicious command patterns
    """
    suspicious = []
    root_user_commands = set()
    normal_users = set()
    suspicious_users = set()
    privileged_processes = {}

    # First pass - collect contextual information
    for process in processes:
        user = process.get("user", "")
        command = process.get("command", "")
        pid = process.get("pid")

        if not user or not command or pid is None:
            continue

        # Build collections of users and commands
        if user == "root":
            root_user_commands.add(command.split()[0] if command else "")
        else:
            normal_users.add(user)

        # Identify privileged processes
        if user == "root" or command.startswith("sudo "):
            privileged_processes[pid] = process

    # Second pass - analyze processes
    for process in processes:
        command = process.get("command", "")
        user = process.get("user", "")
        pid = process.get("pid")
        ppid = process.get("ppid")

        if not command or pid is None:
            continue

        reasons = []

        # Check for suspicious command patterns
        if REGEX_SUSPICIOUS_CMD.search(command):
            reasons.append({
                "type": "suspicious_command",
                "detail": "Command pattern matched suspicious regex",
                "pattern": REGEX_SUSPICIOUS_CMD.pattern
            })

        # Check for privilege escalation attempts
        if REGEX_PRIVILEGE_ESCALATION.search(command):
            reasons.append({
                "type": "privilege_escalation",
                "detail": "Possible privilege escalation attempt",
                "pattern": REGEX_PRIVILEGE_ESCALATION.pattern
            })

        # Check for unusual shells or interpreters
        if REGEX_UNUSUAL_SHELL.search(command):
            reasons.append({
                "type": "unusual_shell",
                "detail": "Unusual shell or interpreter usage",
                "pattern": REGEX_UNUSUAL_SHELL.pattern
            })

        # Check for encoded commands
        if re.search(r'base64\s+-\w*d', command) or re.search(r'echo\s+[\'"]*[A-Za-z0-9+/=]{20,}[\'"]*\s*\|\s*base64\s+-\w*d', command):
            reasons.append({
                "type": "encoded_command",
                "detail": "Possible base64-encoded command execution"
            })

        # Check for data exfiltration commands
        if REGEX_DATA_EXFIL.search(command):
            reasons.append({
                "type": "data_exfiltration",
                "detail": "Possible data exfiltration command",
                "pattern": REGEX_DATA_EXFIL.pattern
            })

        # Check for one-liner web downloads piped to bash/sh
        if re.search(r'(?:curl|wget).*\|\s*(?:bash|sh)', command):
            reasons.append({
                "type": "remote_code_execution",
                "detail": "Downloading and executing remote code"
            })

        # Check for unusual parent-child relationships
        if ppid is not None and ppid in privileged_processes and user != "root" and user != privileged_processes[ppid].get("user"):
            reasons.append({
                "type": "unusual_parent_child",
                "detail": f"Process running as {user} has parent running as {privileged_processes[ppid].get('user', 'unknown')}"
            })

        # Check for non-root users running commands typically run by root
        cmd_base = command.split()[0] if command else ""
        if user != "root" and cmd_base in root_user_commands and cmd_base not in ["ls", "cd", "pwd", "echo", "cat"]:
            reasons.append({
                "type": "unusual_user_privilege",
                "detail": f"Command '{cmd_base}' typically run by root is being run by {user}"
            })

        # If any suspicious patterns found, add to list
        if reasons:
            suspicion = {
                "pid": pid,
                "ppid": ppid,
                "user": user,
                "command": command,
                "reasons": reasons,
                "suspicious_level": len(reasons)
            }
            suspicious.append(suspicion)

    # Sort by suspicion level (highest first)
    suspicious.sort(key=lambda x: x.get("suspicious_level", 0), reverse=True)

    logger.info(f"Detected {len(suspicious)} potentially suspicious processes.")
    return suspicious

def analyze_network_connections(connections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes network connections for suspicious activity.

    Checks for:
    1. Unusual ports
    2. External connections
    3. Suspicious IP patterns
    4. Unusual process-port relationships
    """
    analysis = {
        "suspicious_ports": [],
        "external_connections": [],
        "suspicious_ips": [],
        "listening_ports": [],
        "connection_summary": defaultdict(int),  # Count by state
        "protocol_summary": defaultdict(int),    # Count by protocol
        "processes": defaultdict(list)           # Group by process
    }

    # Define known local/private IP ranges
    private_ip_patterns = [
        re.compile(r'^10\.'),  # 10.0.0.0/8
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),  # 172.16.0.0/12
        re.compile(r'^192\.168\.'),  # 192.168.0.0/16
        re.compile(r'^127\.'),  # 127.0.0.0/8 (localhost)
    ]
    known_local_ips = {"127.0.0.1", "::1", "localhost"}  # Localhost

    # Helper function to check if IP is private
    def is_private_ip(ip: str) -> bool:
        if not ip or ip in known_local_ips:
            return True

        for pattern in private_ip_patterns:
            if pattern.match(ip):
                return True

        # Check for link-local and other special IP ranges
        if re.match(r'^169\.254\.', ip):  # Link-local
            return True
        if re.match(r'^(224\.|239\.)', ip):  # Multicast
            return True

        return False

    # Process each connection
    for conn in connections:
        # Update summary stats
        state = conn.get("state", "UNKNOWN").upper()
        analysis["connection_summary"][state] += 1

        protocol = conn.get("protocol", "unknown").lower()
        analysis["protocol_summary"][protocol] += 1

        local_ip = conn.get("local_ip")
        local_port = conn.get("local_port")
        remote_ip = conn.get("remote_ip")
        remote_port = conn.get("remote_port")
        pid = conn.get("pid")

        # Track connections by process
        if pid is not None:
            analysis["processes"][pid].append(conn)

        # Check for listening ports
        if state == "LISTEN" or state == "LISTENING":
            analysis["listening_ports"].append(conn)

            # Check for unusual listening ports
            if local_port and local_port not in REGEX_COMMON_PORTS and local_port > 1024:
                analysis["suspicious_ports"].append({
                    "port": local_port,
                    "protocol": protocol,
                    "process_pid": pid,
                    "reason": "Listening on non-standard high port"
                })

        # Check for external connections
        if remote_ip and not is_private_ip(remote_ip):
            analysis["external_connections"].append(conn)

            # Check for connections to suspicious remote ports
            if remote_port:
                # Flag high ports except common ones like HTTP/HTTPS
                if remote_port not in REGEX_COMMON_PORTS and remote_port > 1024:
                    analysis["suspicious_ports"].append({
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "process_pid": pid,
                        "reason": "Connection to external IP on non-standard high port"
                    })
                # Flag unusual outbound connections to sensitive services
                elif remote_port in [22, 23, 3389]:  # SSH, Telnet, RDP
                    analysis["suspicious_ports"].append({
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "service": REGEX_COMMON_PORTS.get(remote_port, "Unknown"),
                        "process_pid": pid,
                        "reason": f"Outbound connection to sensitive service ({REGEX_COMMON_PORTS.get(remote_port, 'Unknown')})"
                    })

        # Check for suspicious IPs (hardcoded check, can be expanded)
        if remote_ip and (
            re.match(r'^(\.+|0\.0\.0\.0)', remote_ip) or  # Invalid or zero IP
            remote_ip.endswith('.0') or  # Networks
            remote_ip.count('.') != 3  # Malformed IPv4
        ):
            analysis["suspicious_ips"].append({
                "ip": remote_ip,
                "port": remote_port,
                "process_pid": pid,
                "reason": "Suspicious IP pattern"
            })

    # Process summary statistics
    analysis["total_connections"] = len(connections)
    analysis["external_connection_count"] = len(analysis["external_connections"])
    analysis["listening_port_count"] = len(analysis["listening_ports"])
    analysis["suspicious_port_count"] = len(analysis["suspicious_ports"])
    analysis["process_count"] = len(analysis["processes"])

    logger.info(f"Analyzed {len(connections)} network connections. Found {len(analysis['suspicious_ports'])} potentially suspicious port activities.")
    return analysis

def detect_suspicious_commands(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes command history for suspicious patterns.

    Performs multiple checks for:
    1. Suspicious command patterns
    2. Privilege escalation attempts
    3. Data exfiltration activities
    4. Encoded/obfuscated commands
    5. Network/system reconnaissance
    """
    analysis = {
        "suspicious_commands": [],
        "privilege_escalation": [],
        "data_exfiltration": [],
        "encoded_commands": [],
        "reconnaissance": [],
        "summary": {
            "total_commands": len(history),
            "total_suspicious": 0,
            "categories": {}
        }
    }

    # Add recon pattern to detect system enumeration
    reconnaissance_pattern = re.compile(
        r'\b(?:whoami|id\b|uname -a|cat /etc/(?:passwd|shadow|issue|os-release)|'
        r'ifconfig|ip addr|netstat|lsof|ps aux|systemctl list|'
        r'find\s+/\s+-|arp -a|route -n|nmap)\b',
        re.IGNORECASE
    )

    # Classify each command
    for entry in history:
        command = entry.get("command", "")
        if not command:
            continue

        # Check for suspicious commands
        if REGEX_SUSPICIOUS_CMD.search(command):
            finding = {
                "line_number": entry.get("line_number"),
                "command": command,
                "reason": "Command pattern matched suspicious regex",
                "category": "general_suspicious"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["suspicious_commands"].append(finding)
            analysis["summary"]["categories"]["general_suspicious"] = analysis["summary"]["categories"].get("general_suspicious", 0) + 1

        # Check for privilege escalation attempts
        if REGEX_PRIVILEGE_ESCALATION.search(command):
            finding = {
                "line_number": entry.get("line_number"),
                "command": command,
                "reason": "Potential privilege escalation attempt",
                "category": "privilege_escalation"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["privilege_escalation"].append(finding)
            analysis["summary"]["categories"]["privilege_escalation"] = analysis["summary"]["categories"].get("privilege_escalation", 0) + 1

        # Check for data exfiltration attempts
        if REGEX_DATA_EXFIL.search(command):
            finding = {
                "line_number": entry.get("line_number"),
                "command": command,
                "reason": "Potential data exfiltration activity",
                "category": "data_exfiltration"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["data_exfiltration"].append(finding)
            analysis["summary"]["categories"]["data_exfiltration"] = analysis["summary"]["categories"].get("data_exfiltration", 0) + 1

        # Check for encoded or obfuscated commands
        if re.search(r'base64\s+-\w*d', command) or \
           re.search(r'echo\s+[\'"]*[A-Za-z0-9+/=]{20,}[\'"]*\s*\|\s*base64\s+-\w*d', command):
            finding = {
                "line_number": entry.get("line_number"),
                "command": command,
                "reason": "Encoded or obfuscated command detected",
                "category": "encoded_command"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["encoded_commands"].append(finding)
            analysis["summary"]["categories"]["encoded_command"] = analysis["summary"]["categories"].get("encoded_command", 0) + 1

        # Check for reconnaissance commands
        if reconnaissance_pattern.search(command):
            finding = {
                "line_number": entry.get("line_number"),
                "command": command,
                "reason": "System reconnaissance activity",
                "category": "reconnaissance"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["reconnaissance"].append(finding)
            analysis["summary"]["categories"]["reconnaissance"] = analysis["summary"]["categories"].get("reconnaissance", 0) + 1

    # Update summary statistics
    all_suspicious = (
        analysis["suspicious_commands"] +
        analysis["privilege_escalation"] +
        analysis["data_exfiltration"] +
        analysis["encoded_commands"] +
        analysis["reconnaissance"]
    )

    # Remove duplicates (same command might be in multiple categories)
    unique_suspicious = set()
    for cmd in all_suspicious:
        unique_suspicious.add((cmd.get("line_number"), cmd.get("command")))

    analysis["summary"]["total_suspicious"] = len(unique_suspicious)
    analysis["summary"]["suspicious_percentage"] = round(len(unique_suspicious) / len(history) * 100, 2) if len(history) > 0 else 0

    return analysis

def calculate_risk_score(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate an overall risk score based on all analysis results.

    Returns a dictionary with risk scores and assessment.
    """
    risk_assessment = {
        "overall_score": 0,
        "max_score": 100,
        "risk_level": "low",
        "component_scores": {},
        "risk_factors": []
    }

    # Start with base score
    base_score = 0

    # Suspicious processes
    suspicious_processes = analysis_results.get("suspicious_processes", [])
    if suspicious_processes:
        process_score = min(30, len(suspicious_processes) * 5)
        risk_assessment["component_scores"]["suspicious_processes"] = process_score
        base_score += process_score

        if len(suspicious_processes) > 0:
            risk_assessment["risk_factors"].append(f"Found {len(suspicious_processes)} suspicious processes")

    # Network analysis
    network = analysis_results.get("network_analysis", {})
    if network:
        network_score = 0
        suspicious_ports = network.get("suspicious_ports", [])
        external_conns = network.get("external_connections", [])
        suspicious_ips = network.get("suspicious_ips", [])

        if suspicious_ports:
            port_score = min(25, len(suspicious_ports) * 5)
            network_score += port_score
            risk_assessment["risk_factors"].append(f"Found {len(suspicious_ports)} suspicious network ports")

        if external_conns:
            ext_score = min(15, len(external_conns))
            network_score += ext_score

        if suspicious_ips:
            ip_score = min(20, len(suspicious_ips) * 10)
            network_score += ip_score
            risk_assessment["risk_factors"].append(f"Found {len(suspicious_ips)} suspicious IP addresses")

        risk_assessment["component_scores"]["network"] = network_score
        base_score += network_score

    # Command history analysis
    cmd_analysis = analysis_results.get("suspicious_commands", {})
    if cmd_analysis:
        cmd_score = 0
        summary = cmd_analysis.get("summary", {})

        # Calculate based on suspicious command categories
        if summary.get("categories", {}):
            categories = summary["categories"]
            # Weighted scoring by category severity
            if categories.get("privilege_escalation", 0) > 0:
                priv_score = min(25, categories.get("privilege_escalation", 0) * 8)
                cmd_score += priv_score
                risk_assessment["risk_factors"].append(
                    f"Found {categories.get('privilege_escalation')} privilege escalation attempts"
                )

            if categories.get("data_exfiltration", 0) > 0:
                exfil_score = min(25, categories.get("data_exfiltration", 0) * 8)
                cmd_score += exfil_score
                risk_assessment["risk_factors"].append(
                    f"Found {categories.get('data_exfiltration')} potential data exfiltration commands"
                )

            if categories.get("encoded_command", 0) > 0:
                enc_score = min(20, categories.get("encoded_command", 0) * 6)
                cmd_score += enc_score
                risk_assessment["risk_factors"].append(
                    f"Found {categories.get('encoded_command')} encoded/obfuscated commands"
                )

            if categories.get("general_suspicious", 0) > 0:
                susp_score = min(15, categories.get("general_suspicious", 0) * 3)
                cmd_score += susp_score
                risk_assessment["risk_factors"].append(
                    f"Found {categories.get('general_suspicious')} generally suspicious commands"
                )

            if categories.get("reconnaissance", 0) > 0:
                recon_score = min(10, categories.get("reconnaissance", 0) * 2)
                cmd_score += recon_score
                risk_assessment["risk_factors"].append(
                    f"Found {categories.get('reconnaissance')} system reconnaissance commands"
                )

        risk_assessment["component_scores"]["command_history"] = min(40, cmd_score)
        base_score += min(40, cmd_score)  # Cap at 40 points

    # Calculate overall risk score (cap at 100)
    risk_assessment["overall_score"] = min(100, base_score)

    # Determine risk level
    if risk_assessment["overall_score"] >= 75:
        risk_assessment["risk_level"] = "critical"
    elif risk_assessment["overall_score"] >= 50:
        risk_assessment["risk_level"] = "high"
    elif risk_assessment["overall_score"] >= 25:
        risk_assessment["risk_level"] = "medium"
    else:
        risk_assessment["risk_level"] = "low"

    return risk_assessment

def generate_timeline(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate a chronological timeline of significant events from all data sources.

    Returns list of events sorted by timestamp.
    """
    timeline = []

    # Process command history entries with timestamps
    for entry in parsed_data.get("command_history", []):
        if "timestamp" in entry:
            event = {
                "timestamp": entry["timestamp"],
                "timestamp_iso": entry.get("timestamp_iso", ""),
                "type": "command",
                "description": entry["command"],
                "source": "command_history",
                "details": {
                    "line_number": entry.get("line_number")
                }
            }
            timeline.append(event)

    # Add suspicious events from analysis results
    suspicious_commands = parsed_data.get("analysis_results", {}).get("suspicious_commands", {})
    for category in ["suspicious_commands", "privilege_escalation", "data_exfiltration", "encoded_commands"]:
        for entry in suspicious_commands.get(category, []):
            if "timestamp" in entry:
                event = {
                    "timestamp": entry["timestamp"],
                    "timestamp_iso": entry.get("timestamp", ""),
                    "type": "suspicious_activity",
                    "subtype": category,
                    "description": entry["command"],
                    "source": "command_history_analysis",
                    "severity": "high" if category in ["privilege_escalation", "data_exfiltration"] else "medium",
                    "details": {
                        "reason": entry.get("reason", ""),
                        "line_number": entry.get("line_number")
                    }
                }
                timeline.append(event)

    # Sort timeline by timestamp
    timeline.sort(key=lambda x: x.get("timestamp", 0))

    return timeline

# --- Evidence Integration Functions ---

def register_with_evidence_tracker(parsed_data: Dict[str, Any], case_id: str, evidence_id: str, analyst: str) -> bool:
    """Register analysis results with the evidence tracking system."""
    if not EVIDENCE_TRACKING_AVAILABLE:
        logger.warning("Evidence tracking unavailable. Results not registered.")
        return False

    try:
        # First get the current evidence details to ensure we're working with the correct evidence
        evidence = get_evidence_details(case_id, evidence_id)
        if not evidence:
            logger.error(f"Evidence {evidence_id} not found in case {case_id}")
            return False

        # Register the analysis results
        risk_assessment = parsed_data.get("analysis_results", {}).get("risk_assessment", {})
        suspicious_processes = parsed_data.get("analysis_results", {}).get("suspicious_processes", [])
        suspicious_commands = parsed_data.get("analysis_results", {}).get("suspicious_commands", {})

        # Create a summary for evidence tracking
        analysis_summary = {
            "tool": "artifact_parser",
            "version": APP_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analyst": analyst,
            "risk_level": risk_assessment.get("risk_level", "unknown"),
            "risk_score": risk_assessment.get("overall_score", 0),
            "suspicious_processes": len(suspicious_processes),
            "suspicious_commands": suspicious_commands.get("summary", {}).get("total_suspicious", 0),
            "risk_factors": risk_assessment.get("risk_factors", [])
        }

        # Register the analysis with evidence tracking
        result = register_analysis_result(
            case_id=case_id,
            evidence_id=evidence_id,
            analyst=analyst,
            tool="artifact_parser",
            result_type="live_response_analysis",
            findings=analysis_summary,
            risk_level=risk_assessment.get("risk_level", "unknown")
        )

        if result:
            # Also log the specific analysis activity
            track_analysis(
                case_id=case_id,
                evidence_id=evidence_id,
                analyst=analyst,
                action="live_response_analysis",
                purpose="Automated analysis of live response artifacts",
                details={
                    "tool": "artifact_parser",
                    "risk_level": risk_assessment.get("risk_level", "unknown"),
                    "has_findings": len(suspicious_processes) > 0 or suspicious_commands.get("summary", {}).get("total_suspicious", 0) > 0
                }
            )

            logger.info(f"Analysis results registered for evidence {evidence_id} in case {case_id}")
            return True
        else:
            logger.error(f"Failed to register analysis results for evidence {evidence_id}")
            return False

    except Exception as e:
        logger.error(f"Error registering with evidence tracker: {e}")
        return False

# --- Main Function ---

def main() -> int:
    """
    Main execution function for artifact parser.

    Parses command-line arguments, processes artifacts, performs analysis,
    and generates reports based on live response data.

    Returns:
        int: Exit code (0 for success, 1 for errors)
    """
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Handle version display request
    if args.version:
        print(f"Artifact Parser v{APP_VERSION} ({APP_DATE})")
        return 0

    # --- Logging Setup ---
    log_level = logging.INFO
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose == 1:
        log_level = logging.DEBUG
    elif args.verbose >= 2:
        log_level = logging.DEBUG
        if not FORENSIC_CORE_AVAILABLE:
            logging.getLogger().setLevel(logging.DEBUG)

    # Set level for the specific logger being used
    logger.setLevel(log_level)

    # Prepare forensic operation logging context
    operation_details = {
        "tool": "artifact_parser",
        "version": APP_VERSION,
        "input_dir": args.input_dir,
        "process_file": args.process_file,
        "network_file": args.network_file,
        "history_file": args.history_file,
        "output_path": args.output,
        "output_format": args.format,
        "case_id": args.case_id,
        "evidence_id": args.evidence_id,
        "analyst": args.analyst,
        "analysis_flags": {
            "analyze_processes": args.analyze_processes or args.full_analysis,
            "analyze_network": args.analyze_network or args.full_analysis,
            "detect_suspicious_commands": args.detect_suspicious_commands or args.full_analysis,
            "detect_data_exfil": args.detect_data_exfil or args.full_analysis,
            "detect_privilege_escalation": args.detect_privilege_escalation or args.full_analysis
        }
    }
    log_forensic_operation("artifact_parse_start", True, operation_details, level=logging.INFO)

    # --- Locate Artifact Files ---
    process_file = args.process_file
    network_file = args.network_file
    history_file = args.history_file
    file_list_file = args.file_list_file
    user_file = args.user_file
    modules_file = args.modules_file

    if args.input_dir:
        is_valid, msg = validate_path(args.input_dir, must_be_dir=True, check_read=True)
        if not is_valid:
            logger.error(f"Input directory validation failed: {msg}")
            log_forensic_operation("artifact_parse_error", False,
                                 {**operation_details, "error": msg}, level=logging.ERROR)
            return 1

        # Auto-detect artifacts within the directory using standard naming patterns
        potential_files = {
            "process": ["processes.txt", "processes.json", "ps.txt", "ps.json", "proc_list.txt"],
            "network": ["network_state.json", "network.txt", "network.json", "netstat.txt", "connections.txt"],
            "history": ["command_history.log", ".bash_history", "history.txt", "shell_history.txt"],
            "file_list": ["open_files.txt", "lsof.txt", "file_list.txt"],
            "user": ["user_sessions.txt", "users.txt", "who.txt", "w.txt"],
            "modules": ["kernel_modules.txt", "lsmod.txt", "modules.txt"]
        }

        # Try to find each type of artifact
        for file_type, candidates in potential_files.items():
            for candidate in candidates:
                potential_file = os.path.join(args.input_dir, candidate)
                if os.path.exists(potential_file):
                    if file_type == "process" and not process_file:
                        process_file = potential_file
                    elif file_type == "network" and not network_file:
                        network_file = potential_file
                    elif file_type == "history" and not history_file:
                        history_file = potential_file
                    elif file_type == "file_list" and not file_list_file:
                        file_list_file = potential_file
                    elif file_type == "user" and not user_file:
                        user_file = potential_file
                    elif file_type == "modules" and not modules_file:
                        modules_file = potential_file
                    break  # Found one for this type, move to next

    # --- Parse Artifacts ---
    parsed_data: Dict[str, Any] = {
        "processes": [],
        "network_connections": [],
        "command_history": [],
        "open_files": [],
        "user_sessions": [],
        "kernel_modules": [],
        "analysis_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parser_version": APP_VERSION,
            "parser_date": APP_DATE,
            **operation_details
        },
        "analysis_results": {}
    }
    errors_found = False

    # Process each artifact type with proper error handling
    artifacts_to_parse = [
        (process_file, "processes", parse_process_list,
         args.analyze_processes or args.full_analysis),
        (network_file, "network_connections", parse_network_connections,
         args.analyze_network or args.full_analysis),
        (history_file, "command_history", parse_command_history,
         args.detect_suspicious_commands or args.detect_data_exfil or
         args.detect_privilege_escalation or args.full_analysis),
        (file_list_file, "open_files", parse_open_files, False),
        (user_file, "user_sessions", parse_user_sessions, False),
        (modules_file, "kernel_modules", parse_kernel_modules, False)
    ]

    for file_path, data_key, parse_function, analysis_requested in artifacts_to_parse:
        if file_path:
            is_valid, msg = validate_path(file_path, must_be_file=True, check_read=True)
            if is_valid:
                try:
                    parsed_data[data_key] = parse_function(file_path)
                except Exception as e:
                    logger.error(f"Error parsing {data_key} from {file_path}: {e}")
                    errors_found = True
            else:
                logger.error(f"{data_key.capitalize()} file validation failed: {msg}")
                errors_found = True
        elif analysis_requested:
            logger.warning(f"{data_key.capitalize()} analysis requested, but no file specified or found.")

    # --- Perform Analysis ---
    # Process analysis
    if args.analyze_processes or args.full_analysis:
        if parsed_data["processes"]:
            try:
                logger.info("Analyzing processes...")
                parsed_data["analysis_results"]["process_tree"] = build_process_tree(parsed_data["processes"])
                parsed_data["analysis_results"]["suspicious_processes"] = detect_suspicious_processes(parsed_data["processes"])
            except Exception as e:
                logger.error(f"Error analyzing processes: {e}")
                errors_found = True
        else:
            logger.warning("Skipping process analysis due to missing process data.")

    # Network analysis
    if args.analyze_network or args.full_analysis:
        if parsed_data["network_connections"]:
            try:
                logger.info("Analyzing network connections...")
                parsed_data["analysis_results"]["network_analysis"] = analyze_network_connections(
                    parsed_data["network_connections"])
            except Exception as e:
                logger.error(f"Error analyzing network connections: {e}")
                errors_found = True
        else:
            logger.warning("Skipping network analysis due to missing network data.")

    # Command history analysis (combines all command history checks)
    cmd_analysis_requested = (args.detect_suspicious_commands or
                             args.detect_data_exfil or
                             args.detect_privilege_escalation or
                             args.full_analysis)

    if cmd_analysis_requested:
        if parsed_data["command_history"]:
            try:
                logger.info("Analyzing command history...")
                parsed_data["analysis_results"]["suspicious_commands"] = detect_suspicious_commands(
                    parsed_data["command_history"])
            except Exception as e:
                logger.error(f"Error analyzing command history: {e}")
                errors_found = True
        else:
            logger.warning("Skipping command history analysis due to missing command history data.")

    # Generate timeline of events if we have data with timestamps
    if parsed_data["command_history"] and any("timestamp" in entry for entry in parsed_data["command_history"]):
        try:
            logger.info("Generating event timeline...")
            parsed_data["analysis_results"]["timeline"] = generate_timeline(parsed_data)
        except Exception as e:
            logger.error(f"Error generating timeline: {e}")
            # Not critical, continuing

    # Calculate overall risk score based on all analysis
    if parsed_data["analysis_results"]:
        try:
            logger.info("Calculating risk assessment...")
            parsed_data["analysis_results"]["risk_assessment"] = calculate_risk_score(parsed_data["analysis_results"])
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            # Not critical, continuing

    # Register with evidence tracking system if requested
    if args.register_results and args.case_id and args.evidence_id and args.analyst:
        if EVIDENCE_TRACKING_AVAILABLE:
            try:
                logger.info(f"Registering results with evidence tracker (Case: {args.case_id}, Evidence: {args.evidence_id})...")
                success = register_with_evidence_tracker(
                    parsed_data, args.case_id, args.evidence_id, args.analyst)
                if not success:
                    logger.warning("Failed to register results with evidence tracker.")
            except Exception as e:
                logger.error(f"Error during evidence registration: {e}")
        else:
            logger.warning("Evidence tracking unavailable. Results not registered.")

    # --- Output Results ---
    if args.output:
        # Check if file exists and we're not allowed to overwrite
        if os.path.exists(args.output) and not args.overwrite:
            logger.error(f"Output file {args.output} already exists. Use --overwrite to force.")
            errors_found = True
        else:
            # Make sure output directory exists
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                    logger.debug(f"Created output directory: {output_dir}")
                except OSError as e:
                    logger.error(f"Failed to create output directory {output_dir}: {e}")
                    errors_found = True

            # Skip summary-only for non-text formats
            if args.summary_only and args.format != 'text':
                logger.warning("--summary-only is only applicable for --format text. Ignoring.")

            # Format before saving
            if args.summary_only and args.format == 'text':
                summary_data = create_summary_only(parsed_data)
                saved = save_analysis_report(summary_data, args.output, format=args.format)
            else:
                saved = save_analysis_report(parsed_data, args.output, format=args.format)

            if not saved:
                logger.error(f"Failed to save report to {args.output}.")
                # Fall back to stdout
                if args.format == 'json':
                    print(json.dumps(parsed_data, indent=2, default=str))
                else:
                    print_text_report(parsed_data, summary_only=args.summary_only)
                errors_found = True
            else:
                logger.info(f"Analysis report saved to {args.output}")
    else:
        # Print to stdout
        if args.format == 'json':
            print(json.dumps(parsed_data, indent=2, default=str))
        elif args.format == 'yaml':
            if 'yaml' in sys.modules:
                import yaml
                print(yaml.safe_dump(parsed_data, default_flow_style=False))
            else:
                logger.warning("PyYAML not available, falling back to JSON format")
                print(json.dumps(parsed_data, indent=2, default=str))
        elif args.format == 'csv':
            logger.warning("CSV output to stdout not supported. Falling back to text format.")
            print_text_report(parsed_data, summary_only=args.summary_only)
        else:
            # Text format
            print_text_report(parsed_data, summary_only=args.summary_only)

    log_forensic_operation("artifact_parse_complete", not errors_found, operation_details, level=logging.INFO)
    return 1 if errors_found else 0

def print_text_report(data: Dict[str, Any], summary_only: bool = False) -> None:
    """
    Print a formatted text report to stdout.

    Args:
        data: The parsed and analyzed data
        summary_only: Whether to only print summary information
    """
    print("=== ARTIFACT PARSER ANALYSIS REPORT ===")
    print(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    print(f"Parser Version: {APP_VERSION}")
    print()

    # Print risk assessment if available
    risk = data.get("analysis_results", {}).get("risk_assessment", {})
    if risk:
        print("=== RISK ASSESSMENT ===")
        print(f"Overall Risk: {risk.get('risk_level', 'unknown').upper()} ({risk.get('overall_score', 0)}/100)")

        if risk.get("risk_factors"):
            print("\nRisk Factors:")
            for factor in risk.get("risk_factors", []):
                print(f" - {factor}")
        print()

    # Print summary counts
    print("=== ARTIFACT SUMMARY ===")
    print(f"Processes: {len(data.get('processes', []))}")
    print(f"Network Connections: {len(data.get('network_connections', []))}")
    print(f"Command History Entries: {len(data.get('command_history', []))}")
    if data.get("open_files"):
        print(f"Open Files: {len(data.get('open_files', []))}")
    if data.get("user_sessions"):
        print(f"User Sessions: {len(data.get('user_sessions', []))}")
    if data.get("kernel_modules"):
        print(f"Kernel Modules: {len(data.get('kernel_modules', []))}")
    print()

    # Print findings counts
    print("=== FINDINGS SUMMARY ===")
    suspicious_processes = data.get("analysis_results", {}).get("suspicious_processes", [])
    print(f"Suspicious Processes: {len(suspicious_processes)}")

    suspicious_commands = data.get("analysis_results", {}).get("suspicious_commands", {})
    total_suspicious_cmds = suspicious_commands.get("summary", {}).get("total_suspicious", 0)
    print(f"Suspicious Commands: {total_suspicious_cmds}")

    network_analysis = data.get("analysis_results", {}).get("network_analysis", {})
    suspicious_ports = network_analysis.get("suspicious_ports", [])
    print(f"Suspicious Network Activity: {len(suspicious_ports)}")
    print()

    # Stop here if summary only
    if summary_only:
        return

    # Print detailed findings
    if suspicious_processes:
        print("=== SUSPICIOUS PROCESSES ===")
        for i, proc in enumerate(suspicious_processes[:20], 1):  # Limit to first 20
            print(f"[{i}] PID: {proc.get('pid')} User: {proc.get('user', 'unknown')}")
            print(f"    Command: {proc.get('command', 'unknown')}")
            print(f"    Suspicion Level: {proc.get('suspicious_level', 0)}")
            for reason in proc.get('reasons', []):
                print(f"    - {reason.get('type')}: {reason.get('detail')}")
            print()
        if len(suspicious_processes) > 20:
            print(f"... and {len(suspicious_processes) - 20} more suspicious processes")
        print()

    if suspicious_commands and suspicious_commands.get("summary", {}).get("total_suspicious", 0) > 0:
        print("=== SUSPICIOUS COMMANDS ===")
        for category, findings in suspicious_commands.items():
            if category != "summary" and findings:
                print(f"\n== {category.replace('_', ' ').title()} ==")
                for i, cmd in enumerate(findings[:10], 1):  # Limit to first 10 per category
                    print(f"[{i}] {cmd.get('command', 'unknown')}")
                    if cmd.get('reason'):
                        print(f"    Reason: {cmd.get('reason')}")
                    if cmd.get('timestamp_iso'):
                        print(f"    Time: {cmd.get('timestamp_iso')}")
                    print()
                if len(findings) > 10:
                    print(f"... and {len(findings) - 10} more in this category")
        print()

    if suspicious_ports:
        print("=== SUSPICIOUS NETWORK ACTIVITY ===")
        for i, port_info in enumerate(suspicious_ports[:20], 1):  # Limit to first 20
            print(f"[{i}] {port_info.get('reason', 'Unknown issue')}")
            if port_info.get('local_port'):
                print(f"    Local Port: {port_info.get('local_port')}")
            if port_info.get('remote_ip') and port_info.get('remote_port'):
                print(f"    Connection: {port_info.get('remote_ip')}:{port_info.get('remote_port')}")
            if port_info.get('service'):
                print(f"    Service: {port_info.get('service')}")
            print()
        if len(suspicious_ports) > 20:
            print(f"... and {len(suspicious_ports) - 20} more suspicious network activities")
        print()

def create_summary_only(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a summary-only version of the full analysis data.

    Args:
        data: The full parsed and analyzed data

    Returns:
        Dict containing only summary information
    """
    summary = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parser_version": APP_VERSION
        },
        "artifact_counts": {
            "processes": len(data.get("processes", [])),
            "network_connections": len(data.get("network_connections", [])),
            "command_history": len(data.get("command_history", [])),
            "open_files": len(data.get("open_files", [])),
            "user_sessions": len(data.get("user_sessions", [])),
            "kernel_modules": len(data.get("kernel_modules", []))
        },
        "findings_summary": {
            "suspicious_processes": len(data.get("analysis_results", {}).get("suspicious_processes", [])),
            "suspicious_commands": data.get("analysis_results", {}).get("suspicious_commands", {}).get("summary", {})
        }
    }

    # Include risk assessment if available
    risk = data.get("analysis_results", {}).get("risk_assessment")
    if risk:
        summary["risk_assessment"] = {
            "risk_level": risk.get("risk_level"),
            "overall_score": risk.get("overall_score"),
            "risk_factors": risk.get("risk_factors", [])
        }

    return summary

if __name__ == "__main__":
    sys.exit(main())
