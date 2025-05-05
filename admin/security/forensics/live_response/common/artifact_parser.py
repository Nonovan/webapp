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
import yaml
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

def parse_artifacts(evidence_dir: str, artifact_types: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Parse forensic artifacts from an evidence directory.

    This is a high-level function that orchestrates the parsing of various
    artifact types collected during live response.

    Args:
        evidence_dir: Directory containing collected evidence
        artifact_types: Optional list of specific artifact types to parse
                       (defaults to all available types)

    Returns:
        Dictionary containing parsed artifacts organized by type
    """
    from pathlib import Path

    # Initialize parser with evidence directory
    try:
        # Use ArtifactParser class if available in the current context
        from admin.security.forensics.live_response import ArtifactParser
        parser = ArtifactParser(evidence_dir)

        # Find all artifacts or filter by specified types
        if artifact_types:
            artifacts = {k: v for k, v in parser.find_artifacts().items() if k in artifact_types}
        else:
            artifacts = parser.find_artifacts()

        # Parse each artifact type
        results = {
            "metadata": parser.metadata,
            "summary": parser.get_artifact_summary()
        }

        # Extract artifacts by type
        if "process" in artifacts and artifacts["process"]:
            results["processes"] = parser.extract_processes()

        if "network" in artifacts and artifacts["network"]:
            results["network_connections"] = parser.extract_network_connections()

        if "user" in artifacts and artifacts["user"]:
            results["users"] = parser.extract_users()

        # Return all parsed artifacts
        return results

    except ImportError:
        # Fallback implementation if ArtifactParser isn't available
        logger.warning("ArtifactParser class not available, using direct file parsing")

        evidence_path = Path(evidence_dir)
        if not evidence_path.exists() or not evidence_path.is_dir():
            raise ValueError(f"Invalid evidence directory: {evidence_dir}")

        results = {
            "metadata": _extract_metadata(evidence_path),
            "processes": [],
            "network_connections": [],
            "users": []
        }

        # Find process files
        process_files = list(evidence_path.glob("**/processes/*.txt")) + list(evidence_path.glob("**/ps_*.txt"))
        if process_files:
            results["processes"] = parse_process_list(str(process_files[0]))

        # Find network files
        network_files = list(evidence_path.glob("**/network/*.txt")) + list(evidence_path.glob("**/connections*.txt"))
        if network_files:
            results["network_connections"] = parse_network_connections(str(network_files[0]))

        # Find user files
        user_files = list(evidence_path.glob("**/users/*.txt")) + list(evidence_path.glob("**/passwd*.txt"))
        if user_files:
            results["users"] = parse_user_sessions(str(user_files[0]))

        return results


def detect_suspicious_processes(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect potentially suspicious processes from collected process listings.

    This function analyzes process information to identify processes that match
    known suspicious patterns including:
    - Hidden processes or those with obfuscated names
    - Processes running from unusual locations
    - Processes with suspicious command line arguments
    - Known malicious process signatures

    Args:
        processes: List of dictionaries containing process information

    Returns:
        List of dictionaries describing suspicious processes with explanation
    """
    suspicious = []

    # Regular expressions for suspicious process characteristics
    hidden_proc_pattern = re.compile(r'^\s|\[\s|\s\]|\.\s|\s\.|\s\s+|[^a-zA-Z0-9_\-\./]')
    unusual_path_pattern = re.compile(r'/tmp/|/dev/shm/|/var/tmp/|/private/tmp/|/mnt/')
    crypto_mining_pattern = re.compile(r'xmr|monero|miner|stratum|\bcoin|nanopool|minergate|\bcpu\s+usage')
    reverse_shell_pattern = re.compile(r'nc\s+-[el]|bash\s+-i|python\s+-c.*socket|perl\s+-e.*fork')

    # Check each process
    for proc in processes:
        reasons = []
        command = proc.get("command", "")
        cmd_lower = command.lower()
        proc_name = command.split()[0] if command else ""
        user = proc.get("user", "")
        pid = proc.get("pid", "")

        # Check for hidden/obfuscated process names
        if hidden_proc_pattern.search(proc_name):
            reasons.append({
                "type": "hidden_process",
                "detail": "Possible obfuscated or hidden process name",
                "pattern": hidden_proc_pattern.pattern
            })

        # Check for unusual execution paths
        if unusual_path_pattern.search(command):
            reasons.append({
                "type": "unusual_path",
                "detail": "Process running from suspicious location",
                "pattern": unusual_path_pattern.pattern
            })

        # Check for crypto mining indicators
        if crypto_mining_pattern.search(cmd_lower):
            reasons.append({
                "type": "crypto_mining",
                "detail": "Possible cryptocurrency mining activity",
                "pattern": crypto_mining_pattern.pattern
            })

        # Check for reverse shells
        if reverse_shell_pattern.search(cmd_lower):
            reasons.append({
                "type": "reverse_shell",
                "detail": "Potential reverse shell or command execution",
                "pattern": reverse_shell_pattern.pattern
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

        # Check if running as root but not a system process
        if user == "root" and not proc_name.startswith(("/usr/bin/", "/bin/", "/sbin/")) and not command.startswith(("systemd", "kthreadd", "[", "/")):
            reasons.append({
                "type": "unexpected_root",
                "detail": "Process running as root from non-standard location"
            })

        # If we found any suspicious characteristics, add to results
        if reasons:
            suspicious.append({
                "pid": pid,
                "user": user,
                "command": command,
                "reasons": reasons,
                "risk_level": "high" if len(reasons) > 1 else "medium"
            })

    # Sort by risk level (high first)
    suspicious.sort(key=lambda x: 0 if x.get("risk_level") == "high" else 1)

    logger.info(f"Found {len(suspicious)} suspicious processes out of {len(processes)} total processes")
    return suspicious


def detect_suspicious_connections(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect potentially suspicious network connections.

    This function analyzes network connection information to identify connections
    that match known suspicious patterns including:
    - Connections to unusual ports
    - Connections to known malicious IP ranges
    - Data exfiltration patterns
    - Command and control (C2) communication patterns

    Args:
        connections: List of dictionaries containing network connection information

    Returns:
        List of dictionaries describing suspicious connections with explanation
    """
    suspicious = []

    # Known suspicious ports (excluding common services)
    suspicious_ports = {
        4444: "Metasploit default",
        5555: "Common backdoor port",
        6666: "Common IRC bot port",
        8080: "Web proxy (can be benign)",
        9001: "Tor ORPort default",
        9030: "Tor DirPort default"
    }

    # Known malicious IP patterns (simplified)
    malicious_ip_pattern = re.compile(r'^(?:127\.(?!0\.0\.1)|10\.0\.0\.|192\.168\.0\.).*[^0-9]')

    # Check each connection
    for conn in connections:
        reasons = []
        local_addr = conn.get("local_addr", "")
        remote_addr = conn.get("remote_addr", "")
        state = conn.get("state", "")
        proto = conn.get("proto", "")
        pid = conn.get("pid", "")
        program = conn.get("program", "")

        # Extract IP and port
        try:
            if ":" in remote_addr:
                remote_ip, remote_port_str = remote_addr.rsplit(":", 1)
                remote_port = int(remote_port_str) if remote_port_str.isdigit() else None
            else:
                remote_ip = remote_addr
                remote_port = None
        except (ValueError, IndexError):
            remote_ip = remote_addr
            remote_port = None

        # Check for connections to suspicious ports
        if remote_port in suspicious_ports:
            reasons.append({
                "type": "suspicious_port",
                "detail": f"Connection to known suspicious port: {remote_port} ({suspicious_ports[remote_port]})"
            })

        # Check for high non-standard ports (except common ones)
        if remote_port and remote_port > 1024 and remote_port not in REGEX_COMMON_PORTS:
            if state == "ESTABLISHED":
                reasons.append({
                    "type": "high_port",
                    "detail": f"Established connection on unusual high port {remote_port}"
                })

        # Check for malicious IP patterns
        if remote_ip and malicious_ip_pattern.match(remote_ip):
            reasons.append({
                "type": "suspicious_ip",
                "detail": f"Connection to potentially suspicious IP: {remote_ip}"
            })

        # Check for connections with suspicious binaries
        if program and re.search(r'nc|netcat|ncat|socat|cryptcat|telnet', program, re.IGNORECASE):
            reasons.append({
                "type": "suspicious_program",
                "detail": f"Connection using potentially suspicious tool: {program}"
            })

        # Check for unusual listening ports (except common services)
        if state == "LISTEN" and proto == "tcp":
            try:
                if ":" in local_addr:
                    _, local_port_str = local_addr.rsplit(":", 1)
                    local_port = int(local_port_str) if local_port_str.isdigit() else None
                else:
                    local_port = None

                if local_port and local_port > 1024 and local_port not in REGEX_COMMON_PORTS:
                    reasons.append({
                        "type": "unusual_listening",
                        "detail": f"Listening on unusual port {local_port}"
                    })
            except (ValueError, IndexError):
                pass

        # Check for connections on unusual protocols
        if proto not in ["tcp", "udp", "icmp"]:
            reasons.append({
                "type": "unusual_protocol",
                "detail": f"Connection using unusual protocol: {proto}"
            })

        # If we found any suspicious characteristics, add to results
        if reasons:
            suspicious.append({
                "local_addr": local_addr,
                "remote_addr": remote_addr,
                "proto": proto,
                "state": state,
                "pid": pid,
                "program": program,
                "reasons": reasons,
                "risk_level": "high" if len(reasons) > 1 else "medium"
            })

    # Sort by risk level (high first)
    suspicious.sort(key=lambda x: 0 if x.get("risk_level") == "high" else 1)

    logger.info(f"Found {len(suspicious)} suspicious connections out of {len(connections)} total connections")
    return suspicious


def detect_suspicious_commands(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Detect potentially suspicious commands in shell history.

    This function analyzes command history to identify commands that match
    known suspicious patterns including:
    - Privilege escalation attempts
    - Data exfiltration commands
    - Persistence mechanisms
    - Encoded/obfuscated commands
    - Network scanning/reconnaissance

    Args:
        history: List of dictionaries containing command history entries

    Returns:
        Dictionary with categorized suspicious commands and summary statistics
    """
    # Initialize result structure
    analysis = {
        "general_suspicious": [],
        "privilege_escalation": [],
        "data_exfil": [],
        "persistence": [],
        "encoded_commands": [],
        "reconnaissance": [],
        "summary": {
            "total_commands": len(history),
            "total_suspicious": 0,
            "categories": {}
        }
    }

    # Process each history entry
    for entry in history:
        command = entry.get("command", "")
        if not command:
            continue

        # Check for generally suspicious commands
        if REGEX_SUSPICIOUS_CMD.search(command):
            finding = {
                "line_number": entry.get("line_number"),
                "command": command,
                "reason": "Potentially suspicious command pattern",
                "category": "general_suspicious"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["general_suspicious"].append(finding)
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
                "category": "data_exfil"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["data_exfil"].append(finding)
            analysis["summary"]["categories"]["data_exfil"] = analysis["summary"]["categories"].get("data_exfil", 0) + 1

        # Check for persistence mechanisms
        if re.search(r'crontab|\*/etc/cron|\@reboot|systemctl\s+enable|chkconfig\s+on|update-rc\.d|\.bashrc|\.profile|\.bash_profile|\.zshrc|/etc/init\.d|/etc/systemd/system', command):
            finding = {
                "line_number": entry.get("line_number"),
                "command": command,
                "reason": "Potential persistence mechanism",
                "category": "persistence"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["persistence"].append(finding)
            analysis["summary"]["categories"]["persistence"] = analysis["summary"]["categories"].get("persistence", 0) + 1

        # Check for encoded commands
        encoded_pattern = re.compile(r'base64\s+-\w*d|eval.*base64|echo\s+[\'"]*[A-Za-z0-9+/=]{20,}[\'"]*\s*\|\s*bash')
        if encoded_pattern.search(command):
            finding = {
                "line_number": entry.get("line_number"),
                "command": command,
                "reason": "Encoded or obfuscated command execution",
                "category": "encoded_command"
            }
            if "timestamp_iso" in entry:
                finding["timestamp"] = entry["timestamp_iso"]
            analysis["encoded_commands"].append(finding)
            analysis["summary"]["categories"]["encoded_command"] = analysis["summary"]["categories"].get("encoded_command", 0) + 1

        # Check for reconnaissance commands
        reconnaissance_pattern = re.compile(r'nmap|masscan|ping\s+-c|traceroute|dig\s+any|whois|netstat|lsof\s+-i|ss\s+-[alnt]|wget.*-O-|curl.*-s')
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
        len(analysis["general_suspicious"]) +
        len(analysis["privilege_escalation"]) +
        len(analysis["data_exfil"]) +
        len(analysis["persistence"]) +
        len(analysis["encoded_commands"]) +
        len(analysis["reconnaissance"])
    )

    analysis["summary"]["total_suspicious"] = all_suspicious
    analysis["summary"]["percentage_suspicious"] = round((all_suspicious / len(history)) * 100, 2) if history else 0

    logger.info(f"Analyzed {len(history)} command history entries. Found {all_suspicious} suspicious commands.")
    return analysis


def detect_data_exfil(artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect potential data exfiltration activities from collected artifacts.

    This function analyzes various artifacts to identify patterns indicative
    of data exfiltration:
    - Network connections to unusual destinations
    - File transfer commands in history
    - Use of compression/encryption tools on sensitive data
    - Unusual outbound traffic patterns

    Args:
        artifacts: Dictionary containing parsed artifacts (processes, network, commands, etc.)

    Returns:
        List of dictionaries describing potential data exfiltration activities
    """
    exfil_indicators = []

    # Check command history for exfiltration patterns
    if "command_history" in artifacts and artifacts["command_history"]:
        for entry in artifacts["command_history"]:
            command = entry.get("command", "")
            if not command:
                continue

            # Check for data packaging commands
            if re.search(r'tar\s+cz|7z\s+a|zip\s+-|gzip|xz|bzip2', command) and re.search(r'/etc|/var/log|/home|/root|\.ssh|database|backup', command):
                exfil_indicators.append({
                    "type": "data_packaging",
                    "command": command,
                    "timestamp": entry.get("timestamp_iso", "Unknown"),
                    "details": "Command for packaging potentially sensitive data",
                    "source": "command_history",
                    "risk_level": "medium"
                })

            # Check for direct file transfer commands
            if REGEX_DATA_EXFIL.search(command):
                exfil_indicators.append({
                    "type": "file_transfer",
                    "command": command,
                    "timestamp": entry.get("timestamp_iso", "Unknown"),
                    "details": "Command for transferring data to external system",
                    "source": "command_history",
                    "risk_level": "high"
                })

    # Check network connections for exfiltration patterns
    if "network_connections" in artifacts and artifacts["network_connections"]:
        for conn in artifacts["network_connections"]:
            remote_addr = conn.get("remote_addr", "")
            proto = conn.get("proto", "")
            state = conn.get("state", "")
            program = conn.get("program", "")

            # Extract IP and port
            try:
                if ":" in remote_addr:
                    remote_ip, remote_port_str = remote_addr.rsplit(":", 1)
                    remote_port = int(remote_port_str) if remote_port_str.isdigit() else None
                else:
                    remote_ip = remote_addr
                    remote_port = None
            except (ValueError, IndexError):
                remote_ip = remote_addr
                remote_port = None

            # Check for connections to file sharing/transfer ports
            if remote_port in [21, 22, 69, 2049, 445, 139]:
                service_name = {
                    21: "FTP",
                    22: "SSH/SCP",
                    69: "TFTP",
                    2049: "NFS",
                    445: "SMB",
                    139: "NetBIOS"
                }.get(remote_port, str(remote_port))

                if state == "ESTABLISHED":
                    exfil_indicators.append({
                        "type": "file_transfer_connection",
                        "local_addr": conn.get("local_addr", "Unknown"),
                        "remote_addr": remote_addr,
                        "protocol": f"{proto}/{service_name}",
                        "program": program,
                        "details": f"Established connection to {service_name} service",
                        "source": "network_connections",
                        "risk_level": "medium"
                    })

            # Check for outbound connections with data transfer tools
            if program and re.search(r'scp|sftp|ftp|nc|rsync|curl|wget', program, re.IGNORECASE):
                exfil_indicators.append({
                    "type": "data_transfer_tool",
                    "local_addr": conn.get("local_addr", "Unknown"),
                    "remote_addr": remote_addr,
                    "protocol": proto,
                    "program": program,
                    "details": f"Connection using common data transfer tool ({program})",
                    "source": "network_connections",
                    "risk_level": "medium"
                })

    # Check processes for exfiltration indicators
    if "processes" in artifacts and artifacts["processes"]:
        for proc in artifacts["processes"]:
            command = proc.get("command", "")
            if not command:
                continue

            # Check for data transfer tools
            if re.search(r'\b(scp|sftp|ftp|rsync)\b', command) and re.search(r'/etc|/var/log|/home|/root|\.ssh|database|backup', command):
                exfil_indicators.append({
                    "type": "data_transfer_process",
                    "pid": proc.get("pid", "Unknown"),
                    "user": proc.get("user", "Unknown"),
                    "command": command,
                    "details": "Process transferring potentially sensitive data",
                    "source": "processes",
                    "risk_level": "high"
                })

    # Sort by risk level
    exfil_indicators.sort(key=lambda x: 0 if x.get("risk_level") == "high" else 1)

    logger.info(f"Found {len(exfil_indicators)} potential data exfiltration indicators")
    return exfil_indicators


def detect_privilege_escalation(artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect potential privilege escalation activities from collected artifacts.

    This function analyzes various artifacts to identify patterns indicative
    of privilege escalation attempts:
    - Use of sudo, su, or similar commands
    - Exploits for known privilege escalation vulnerabilities
    - Suspicious SUID/SGID binaries
    - Modifications to system security settings

    Args:
        artifacts: Dictionary containing parsed artifacts (processes, network, commands, etc.)

    Returns:
        List of dictionaries describing potential privilege escalation activities
    """
    escalation_indicators = []

    # Check command history for privilege escalation patterns
    if "command_history" in artifacts and artifacts["command_history"]:
        for entry in artifacts["command_history"]:
            command = entry.get("command", "")
            if not command:
                continue

            # Check for privilege escalation commands
            if REGEX_PRIVILEGE_ESCALATION.search(command):
                escalation_indicators.append({
                    "type": "privilege_command",
                    "command": command,
                    "timestamp": entry.get("timestamp_iso", "Unknown"),
                    "details": "Command attempting to escalate privileges",
                    "source": "command_history",
                    "risk_level": "high"
                })

            # Check for specific CVE exploits
            cve_pattern = re.compile(r'CVE-\d{4}-\d+|exploit|pwnkit|linpeas|dirtycow|dirty_cow|dirtypipe|ptrace|pkexec')
            if cve_pattern.search(command.lower()):
                escalation_indicators.append({
                    "type": "exploit_attempt",
                    "command": command,
                    "timestamp": entry.get("timestamp_iso", "Unknown"),
                    "details": "Command referencing known privilege escalation exploit",
                    "source": "command_history",
                    "risk_level": "high"
                })

            # Check for modifications to sudoers
            if re.search(r'visudo|/etc/sudoers|sudoers\.d|NOPASSWD|chmod\s+\+w\s+/etc/sudoers', command):
                escalation_indicators.append({
                    "type": "sudoers_modification",
                    "command": command,
                    "timestamp": entry.get("timestamp_iso", "Unknown"),
                    "details": "Command modifying sudo configuration",
                    "source": "command_history",
                    "risk_level": "high"
                })

            # Check for SUID/SGID modifications
            if re.search(r'chmod\s+[u+]s|chmod\s+[g+]s|chmod\s+[0-9]+s', command):
                escalation_indicators.append({
                    "type": "suid_modification",
                    "command": command,
                    "timestamp": entry.get("timestamp_iso", "Unknown"),
                    "details": "Command setting SUID/SGID permission bit",
                    "source": "command_history",
                    "risk_level": "high"
                })

    # Check processes for privilege escalation indicators
    if "processes" in artifacts and artifacts["processes"]:
        for proc in artifacts["processes"]:
            command = proc.get("command", "")
            user = proc.get("user", "")
            if not command:
                continue

            # Check for exploit tools
            if re.search(r'exploit|linpeas|pspy|pwnkit|dirtycow|pkexec.*0x|gcc\s+-o\s+pwn', command.lower()):
                escalation_indicators.append({
                    "type": "exploit_process",
                    "pid": proc.get("pid", "Unknown"),
                    "user": user,
                    "command": command,
                    "details": "Process running potential privilege escalation exploit",
                    "source": "processes",
                    "risk_level": "high"
                })

            # Check for unexpected binaries running as root
            if user == "root" and re.search(r'^(bash|sh|dash|python|perl|php|ruby|nc|netcat|ncat)\b', command.split('/')[-1]):
                if not re.search(r'^/(usr/)?(s)?bin/', command.split()[0]):
                    escalation_indicators.append({
                        "type": "unexpected_root_process",
                        "pid": proc.get("pid", "Unknown"),
                        "user": user,
                        "command": command,
                        "details": "Interpreter running as root from non-standard location",
                        "source": "processes",
                        "risk_level": "high"
                    })

    # Sort by risk level
    escalation_indicators.sort(key=lambda x: 0 if x.get("risk_level") == "high" else 1)

    logger.info(f"Found {len(escalation_indicators)} potential privilege escalation indicators")
    return escalation_indicators


def extract_network_indicators(artifacts: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Extract network indicators of compromise from collected artifacts.

    This function identifies potential malicious network indicators:
    - IP addresses
    - Domain names
    - URLs
    - Network ports and protocols

    Args:
        artifacts: Dictionary containing parsed artifacts (processes, network, commands, etc.)

    Returns:
        Dictionary containing categorized network indicators
    """
    indicators = {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "ports": []
    }

    # Helper function to add unique indicators
    def add_unique(category, value):
        if value and value not in indicators[category]:
            indicators[category].append(value)

    # Check processes for network indicators
    if "processes" in artifacts and artifacts["processes"]:
        for proc in artifacts["processes"]:
            command = proc.get("command", "")

            # Extract IPs
            for ip in REGEX_IP_ADDR.findall(command):
                if not ip.startswith("127.") and not ip.startswith("0."):
                    add_unique("ip_addresses", ip)

            # Extract domains
            for domain in REGEX_DOMAIN.findall(command):
                add_unique("domains", domain)

            # Extract URLs
            for url in re.findall(r'https?://[^\s"\']+', command):
                add_unique("urls", url)

    # Check network connections
    if "network_connections" in artifacts and artifacts["network_connections"]:
        for conn in artifacts["network_connections"]:
            remote_addr = conn.get("remote_addr", "")

            # Extract IP and port
            try:
                if ":" in remote_addr:
                    remote_ip, remote_port_str = remote_addr.rsplit(":", 1)
                    if remote_port_str.isdigit():
                        remote_port = int(remote_port_str)
                        if remote_port not in [80, 443, 22, 53] and remote_port != 0:
                            add_unique("ports", remote_port)
                else:
                    remote_ip = remote_addr

                # Add IP if it's not a local/private address
                if remote_ip and not remote_ip.startswith("127.") and not remote_ip.startswith("0.") and not remote_ip.startswith("192.168.") and not remote_ip.startswith("10.") and not remote_ip.startswith("172."):
                    add_unique("ip_addresses", remote_ip)
            except (ValueError, IndexError):
                pass

    # Check command history
    if "command_history" in artifacts and artifacts["command_history"]:
        for entry in artifacts["command_history"]:
            command = entry.get("command", "")

            # Extract IPs
            for ip in REGEX_IP_ADDR.findall(command):
                if not ip.startswith("127.") and not ip.startswith("0."):
                    add_unique("ip_addresses", ip)

            # Extract domains
            for domain in REGEX_DOMAIN.findall(command):
                add_unique("domains", domain)

            # Extract URLs
            for url in re.findall(r'https?://[^\s"\']+', command):
                add_unique("urls", url)

    logger.info(f"Extracted network indicators: {sum(len(v) for v in indicators.values())} total")
    return indicators


def extract_file_indicators(artifacts: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Extract file-based indicators of compromise from collected artifacts.

    This function identifies potential malicious file indicators:
    - Suspicious file paths
    - File names matching malware patterns
    - Temporary files
    - Hidden files

    Args:
        artifacts: Dictionary containing parsed artifacts (processes, network, commands, etc.)

    Returns:
        Dictionary containing categorized file indicators
    """
    indicators = {
        "suspicious_paths": [],
        "temp_files": [],
        "hidden_files": [],
        "web_shells": []
    }

    # Helper function to add unique indicators
    def add_unique(category, value):
        if value and value not in indicators[category]:
            indicators[category].append(value)

    # Check processes for file indicators
    if "processes" in artifacts and artifacts["processes"]:
        for proc in artifacts["processes"]:
            command = proc.get("command", "")

            # Extract suspicious paths
            suspicious_path_pattern = re.compile(r'(/tmp/|/var/tmp/|/dev/shm/)[^\s>|]+\.([a-z0-9]{5,}|py|sh|pl|php|rb)')
            for match in suspicious_path_pattern.finditer(command):
                add_unique("suspicious_paths", match.group(0))

            # Extract temp files
            temp_file_pattern = re.compile(r'(/tmp/|/var/tmp/)[^\s>|]+')
            for match in temp_file_pattern.finditer(command):
                add_unique("temp_files", match.group(0))

            # Extract hidden files
            hidden_file_pattern = re.compile(r'/\.(?!\.)[^\s/]+')
            for match in hidden_file_pattern.finditer(command):
                path = match.group(0)
                if not any(common in path for common in ['.ssh', '.config', '.cache', '.local']):
                    add_unique("hidden_files", path)

    # Check command history
    if "command_history" in artifacts and artifacts["command_history"]:
        for entry in artifacts["command_history"]:
            command = entry.get("command", "")

            # Check for web shell patterns
            webshell_pattern = re.compile(r'(?:\.php|\.jsp|\.asp|\.aspx).*(?:passthru|shell_exec|system|phpinfo|base64_decode|edoced_46esab|eval|assert)')
            if webshell_pattern.search(command.lower()):
                if re.search(r'/var/www/|/srv/www/|/html/|/htdocs/', command):
                    # Extract the path
                    for path in re.findall(r'(?:/var/www/|/srv/www/|/html/|/htdocs/)[^\s>|]+(?:\.php|\.jsp|\.asp|\.aspx)', command):
                        add_unique("web_shells", path)

            # Extract suspicious paths created or modified
            file_operation_pattern = re.compile(r'(?:touch|echo|printf|cat|tee|vim|nano|vi|rm|cp|mv)\s+([^\s>|]+)')
            for match in file_operation_pattern.finditer(command):
                path = match.group(1)

                # Check for suspicious locations
                if re.match(r'(/tmp/|/var/tmp/|/dev/shm/)', path):
                    add_unique("temp_files", path)

                # Check for hidden files created in non-standard locations
                if '/' in path and path.split('/')[-1].startswith('.') and not any(common in path for common in ['.ssh', '.config', '.cache', '.local']):
                    add_unique("hidden_files", path)

    # Check for file paths in open files
    if "open_files" in artifacts and artifacts["open_files"]:
        for file_entry in artifacts["open_files"]:
            path = file_entry.get("path", "")
            if not path:
                continue

            # Check suspicious temporary locations
            if re.match(r'(/tmp/|/var/tmp/|/dev/shm/)', path) and re.search(r'\.(sh|py|pl|rb|php|jsp|asp|aspx|cgi)$', path.lower()):
                add_unique("suspicious_paths", path)
                add_unique("temp_files", path)

            # Check web directories for potential web shells
            if re.search(r'/var/www/|/srv/www/|/html/|/htdocs/', path) and re.search(r'\.(php|jsp|asp|aspx)$', path.lower()):
                if 'r' in file_entry.get("mode", "") and 'w' in file_entry.get("mode", ""):  # Read-write access
                    add_unique("web_shells", path)

    logger.info(f"Extracted file indicators: {sum(len(v) for v in indicators.values())} total")
    return indicators

# Helper function for extracting metadata from evidence directory (used in fallback)
def _extract_metadata(evidence_path: Path) -> Dict[str, Any]:
    metadata = {
        "collection_date": datetime.now().isoformat(),
        "processed_by": "artifact_parser.py"
    }

    # Look for metadata files
    metadata_files = ["collection_metadata.json", "collection_summary.txt", "metadata.json", "summary.txt"]

    for filename in metadata_files:
        file_path = evidence_path / filename
        if file_path.exists():
            try:
                if file_path.suffix == ".json":
                    with open(file_path, 'r') as f:
                        return json.load(f)
                else:
                    # Basic extraction from text summary
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if "Case ID:" in content:
                            metadata["case_id"] = content.split("Case ID:")[1].split("\n")[0].strip()
                        if "Collection Date:" in content:
                            metadata["collection_date"] = content.split("Collection Date:")[1].split("\n")[0].strip()
                        if "Host:" in content:
                            metadata["host"] = content.split("Host:")[1].split("\n")[0].strip()
                        if "Examiner:" in content:
                            metadata["examiner"] = content.split("Examiner:")[1].split("\n")[0].strip()
                    break
            except Exception as e:
                logger.warning(f"Failed to parse metadata file {file_path}: {e}")

    return metadata


def analyze_artifact_timeline(artifacts: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Create and analyze a timeline of events from collected artifacts.

    This function extracts timestamp information from various artifact types
    and builds a consolidated timeline to help analyze the sequence of events
    during a security incident. It identifies patterns, suspicious time gaps,
    and potential correlations between different activities.

    Args:
        artifacts: Dictionary containing parsed artifacts (processes, network, command history, etc.)
        options: Optional configuration parameters for timeline analysis
            - max_events: Maximum number of events to include
            - filter_types: List of event types to include (e.g., ["process", "network", "command"])
            - start_time: Filter events after this ISO timestamp
            - end_time: Filter events before this ISO timestamp
            - include_system_events: Whether to include routine system events (default: False)
            - correlation_window_seconds: Time window for correlating related events (default: 60)

    Returns:
        List of dictionaries representing timeline events in chronological order
    """
    if options is None:
        options = {}

    # Default configuration
    max_events = options.get("max_events", 1000)
    filter_types = options.get("filter_types", [])  # Empty means include all
    start_time = options.get("start_time")
    end_time = options.get("end_time")
    include_system_events = options.get("include_system_events", False)
    correlation_window = options.get("correlation_window_seconds", 60)

    # Initialize timeline
    timeline = []

    # Extract timestamp information from command history
    if "command_history" in artifacts and artifacts["command_history"]:
        for entry in artifacts["command_history"]:
            # Skip if no timestamp available
            if "timestamp_iso" not in entry:
                continue

            command = entry.get("command", "")
            # Skip common system commands if not including system events
            if not include_system_events and _is_routine_command(command):
                continue

            timeline.append({
                "timestamp": entry["timestamp_iso"],
                "event_type": "command",
                "description": f"Command executed: {command}",
                "user": entry.get("user", "unknown"),
                "details": {
                    "command": command,
                    "line_number": entry.get("line_number"),
                    "suspicious": _is_suspicious_command(command)
                },
                "source": "command_history"
            })

    # Extract timestamp information from process data if available
    if "processes" in artifacts and artifacts["processes"]:
        for proc in artifacts["processes"]:
            # Skip if no timestamp information
            if "start" not in proc:
                continue

            # Convert process start time to ISO format if possible
            try:
                # This will need enhancement based on the actual timestamp format in process data
                timestamp = _normalize_process_timestamp(proc.get("start", ""))
                if not timestamp:
                    continue

                timeline.append({
                    "timestamp": timestamp,
                    "event_type": "process",
                    "description": f"Process started: {proc.get('command', 'unknown')}",
                    "user": proc.get("user", "unknown"),
                    "details": {
                        "pid": proc.get("pid", "unknown"),
                        "command": proc.get("command", ""),
                        "suspicious": _is_suspicious_process(proc)
                    },
                    "source": "processes"
                })
            except Exception as e:
                logger.debug(f"Error parsing process timestamp: {e}")
                continue

    # Extract timestamp information from network connections if available
    # This is more complex as most network data doesn't include timestamps
    # We could potentially correlate with firewall logs or other sources here

    # Extract timestamps from log files if available
    if "logs" in artifacts and artifacts["logs"]:
        for log_entry in artifacts.get("logs", []):
            if "timestamp" in log_entry and "message" in log_entry:
                # Skip routine log entries if not including system events
                if not include_system_events and _is_routine_log_entry(log_entry.get("message", "")):
                    continue

                timeline.append({
                    "timestamp": log_entry["timestamp"],
                    "event_type": "log",
                    "description": f"Log entry: {log_entry.get('message', '')}",
                    "details": {
                        "level": log_entry.get("level", "info"),
                        "source": log_entry.get("source", "unknown"),
                        "message": log_entry.get("message", ""),
                        "suspicious": _is_suspicious_log_entry(log_entry.get("message", ""))
                    },
                    "source": "logs"
                })

    # Apply filters
    filtered_timeline = timeline

    # Filter by event types if specified
    if filter_types:
        filtered_timeline = [event for event in filtered_timeline if event["event_type"] in filter_types]

    # Filter by time range if specified
    if start_time:
        filtered_timeline = [event for event in filtered_timeline if event["timestamp"] >= start_time]
    if end_time:
        filtered_timeline = [event for event in filtered_timeline if event["timestamp"] <= end_time]

    # Sort timeline chronologically
    filtered_timeline.sort(key=lambda x: x["timestamp"])

    # Limit number of events if specified
    if len(filtered_timeline) > max_events:
        filtered_timeline = filtered_timeline[-max_events:]

    # Identify and group correlated events within the specified time window
    correlated_events = _correlate_timeline_events(filtered_timeline, correlation_window)

    # Add correlation information to timeline events
    for event in filtered_timeline:
        if event.get("id") in correlated_events:
            event["correlated_events"] = correlated_events[event.get("id")]

    # Add anomalies and insights to the timeline
    filtered_timeline = _identify_timeline_anomalies(filtered_timeline)

    logger.info(f"Generated timeline with {len(filtered_timeline)} events from {len(timeline)} total events")
    return filtered_timeline


def generate_artifact_report(artifacts: Dict[str, Any], report_type: str = "full",
                           output_format: str = "json",
                           output_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a comprehensive forensic report from collected artifacts.

    This function creates a structured forensic report that summarizes findings,
    identifies suspicious activities, and presents the evidence in a format
    suitable for incident response teams and stakeholders. The report can be
    generated in different formats and detail levels to meet various needs.

    Args:
        artifacts: Dictionary containing parsed artifacts and analysis results
        report_type: Type of report to generate
            - "full": Complete detailed report with all findings
            - "summary": Executive summary with key findings
            - "technical": Technical details for forensic analysts
            - "ioc": Only indicators of compromise
        output_format: Output format of the report
            - "json": JSON structured data
            - "text": Plain text report
            - "html": HTML formatted report
            - "csv": CSV format for IOCs and key findings
            - "markdown": Markdown formatted report
        output_file: Optional path to save the report (if None, return as dict/string)

    Returns:
        Dictionary containing the report data or success status if output_file provided
    """
    report_date = datetime.now(timezone.utc).isoformat()

    # Get metadata if available
    metadata = artifacts.get("metadata", {})

    # Basic report structure
    report = {
        "report_type": report_type,
        "generated_at": report_date,
        "case_info": {
            "case_id": metadata.get("case_id", "Unknown"),
            "examiner": metadata.get("examiner", "Unknown"),
            "collection_date": metadata.get("collection_date", "Unknown"),
            "host": metadata.get("host", "Unknown"),
            "collection_method": metadata.get("collection_method", "Live Response Toolkit")
        },
        "summary": _generate_report_summary(artifacts, report_type),
        "findings": _generate_report_findings(artifacts, report_type),
        "recommendations": _generate_report_recommendations(artifacts)
    }

    # Add detailed analysis based on report type
    if report_type in ["full", "technical"]:
        report["detailed_analysis"] = _generate_detailed_analysis(artifacts)

    # Add IOCs for relevant report types
    if report_type in ["full", "technical", "ioc"]:
        report["indicators_of_compromise"] = _generate_ioc_section(artifacts)

    # Add timeline for full and technical reports
    if report_type in ["full", "technical"]:
        timeline_options = {
            "max_events": 1000 if report_type == "full" else 500,
            "include_system_events": report_type == "technical",
            "correlation_window_seconds": 60
        }
        report["timeline"] = analyze_artifact_timeline(artifacts, timeline_options)

    # Output formats
    if output_file:
        if output_format == "json":
            return _save_json_report(report, output_file)
        elif output_format == "text":
            return _save_text_report(report, output_file)
        elif output_format == "html":
            return _save_html_report(report, output_file)
        elif output_format == "csv":
            return _save_csv_report(report, output_file)
        elif output_format == "markdown":
            return _save_markdown_report(report, output_file)
        else:
            logger.warning(f"Unsupported output format: {output_format}. Defaulting to JSON.")
            return _save_json_report(report, output_file)

    # If no output file, return the report data
    return report


# --- Helper Functions for Timeline Analysis ---

def _is_routine_command(command: str) -> bool:
    """Check if a command is routine system activity."""
    routine_patterns = [
        r'^ls\s+', r'^cd\s+', r'^echo\s+', r'^cat\s+',
        r'^grep\s+', r'^find\s+', r'^pwd$', r'^umask$', r'^locale$',
        r'^which\s+', r'^type\s+', r'^clear$', r'^history$',
        r'^w$', r'^who$', r'^whoami$', r'^uptime$', r'^df\s+',
        r'^top\s+', r'^ps\s+', r'^env$'
    ]
    return any(re.match(pattern, command) for pattern in routine_patterns)


def _is_suspicious_command(command: str) -> bool:
    """Check if a command is suspicious using established patterns."""
    return (REGEX_SUSPICIOUS_CMD.search(command) is not None or
            REGEX_PRIVILEGE_ESCALATION.search(command) is not None or
            REGEX_DATA_EXFIL.search(command) is not None)


def _is_suspicious_process(process: Dict[str, Any]) -> bool:
    """Check if a process is suspicious based on command and user."""
    command = process.get("command", "")
    user = process.get("user", "")

    # Check if root is running non-system processes
    if user == "root" and not _is_system_process(command):
        return True

    # Check for suspicious command patterns
    return _is_suspicious_command(command)


def _is_system_process(command: str) -> bool:
    """Check if this is a known system process that should run as root."""
    system_patterns = [
        r'^(\/usr\/|\/bin\/|\/sbin\/)(system|init|network|cron|ssh|kernel)',
        r'\[.*\]$',  # Kernel threads appear in brackets
        r'^systemd(\s|$)',
        r'^\/lib\/systemd\/',
        r'^(\/usr)?\/lib\/',
        r'^dbus-daemon',
        r'^(\/usr\/)?sbin\/'
    ]
    return any(re.search(pattern, command) for pattern in system_patterns)


def _is_routine_log_entry(message: str) -> bool:
    """Check if a log entry is routine system activity."""
    routine_patterns = [
        r'CRON\[\d+\]',
        r'(opened|closed) session',
        r'systemd\[\d+\]: Started',
        r'DHCP (REQUEST|RENEW|ACK)',
        r'pam_unix\(sshd:session\): session (opened|closed)',
        r'(Received|Sent) disconnect'
    ]
    return any(re.search(pattern, message) for pattern in routine_patterns)


def _is_suspicious_log_entry(message: str) -> bool:
    """Check if a log message contains suspicious indicators."""
    suspicious_patterns = [
        r'(authentication|login) failure',
        r'failed password',
        r'invalid user',
        r'user not in sudoers',
        r'permission denied',
        r'segfault at',
        r'(error|failed) loading',
        r'executable stack',
        r'audited system call',
        r'rejected by tcpwrapper',
        r'signature not trusted',
        r'unauthorized access',
        r'user unknown'
    ]
    return any(re.search(pattern, message, re.IGNORECASE) for pattern in suspicious_patterns)


def _normalize_process_timestamp(timestamp: str) -> Optional[str]:
    """
    Normalize process timestamp to ISO format.

    This handles various timestamp formats found in process listings.
    Returns None if timestamp cannot be parsed.
    """
    # This implementation would need to be expanded based on the actual timestamp format
    # Here's a placeholder that handles common formats:
    try:
        # For simple time format (no date) like "10:30:45"
        if re.match(r'\d{2}:\d{2}(:\d{2})?$', timestamp):
            # Use current date with the given time
            today = datetime.now().strftime("%Y-%m-%d")
            full_timestamp = f"{today} {timestamp}"
            dt = datetime.strptime(full_timestamp, "%Y-%m-%d %H:%M:%S")
            return dt.isoformat()

        # For Unix timestamp
        if timestamp.isdigit():
            dt = datetime.fromtimestamp(int(timestamp))
            return dt.isoformat()

        # For ISO-like format "YYYY-MM-DD HH:MM:SS"
        if re.match(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', timestamp):
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            return dt.isoformat()

        # For standard formats like "Jun 15 10:30:45"
        dt = datetime.strptime(timestamp, "%b %d %H:%M:%S")
        # Add current year
        current_year = datetime.now().year
        dt = dt.replace(year=current_year)
        return dt.isoformat()
    except Exception:
        return None


def _correlate_timeline_events(timeline: List[Dict[str, Any]], window_seconds: int = 60) -> Dict[str, List[str]]:
    """
    Identify correlated events based on time proximity and content similarity.

    Args:
        timeline: Sorted list of timeline events
        window_seconds: Time window to consider for correlation

    Returns:
        Dictionary mapping event IDs to lists of correlated event IDs
    """
    # Add unique IDs to events if they don't have them
    for i, event in enumerate(timeline):
        if "id" not in event:
            event["id"] = f"event_{i}"

    correlated = {}

    # For each event, find other events within the time window
    for i, event in enumerate(timeline):
        event_time = event.get("timestamp", "")
        event_id = event.get("id", f"event_{i}")
        correlated[event_id] = []

        if not event_time:
            continue

        # Try to parse the timestamp
        try:
            event_dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))

            # Check other events within the window
            for j, other in enumerate(timeline):
                if i == j:
                    continue

                other_time = other.get("timestamp", "")
                other_id = other.get("id", f"event_{j}")

                if not other_time:
                    continue

                try:
                    other_dt = datetime.fromisoformat(other_time.replace("Z", "+00:00"))
                    time_diff = abs((event_dt - other_dt).total_seconds())

                    # If within time window, check content similarity
                    if time_diff <= window_seconds:
                        # Check if the events are related based on content
                        if _are_events_related(event, other):
                            correlated[event_id].append(other_id)
                except Exception:
                    continue
        except Exception:
            continue

    return correlated


def _are_events_related(event1: Dict[str, Any], event2: Dict[str, Any]) -> bool:
    """Determine if two events are related based on their content."""
    # Same user
    if (event1.get("user") and event2.get("user") and
        event1.get("user") == event2.get("user")):
        return True

    # Related process and command
    if (event1.get("event_type") == "process" and
        event2.get("event_type") == "command"):
        # Check if command contains the process name or vice versa
        proc_cmd = event1.get("details", {}).get("command", "")
        cmd = event2.get("details", {}).get("command", "")

        if proc_cmd and cmd:
            # Extract the base command name
            proc_base = proc_cmd.split()[0].split("/")[-1]
            cmd_base = cmd.split()[0]
            if proc_base and cmd_base and (proc_base in cmd or cmd_base in proc_cmd):
                return True

    # Same process ID
    if (event1.get("details", {}).get("pid") and
        event2.get("details", {}).get("pid") and
        event1["details"]["pid"] == event2["details"]["pid"]):
        return True

    return False


def _identify_timeline_anomalies(timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify anomalies in the timeline such as unusual gaps or bursts of activity.

    Args:
        timeline: List of timeline events in chronological order

    Returns:
        Timeline with added anomaly indicators
    """
    # Need at least 2 events to detect anomalies
    if len(timeline) < 2:
        return timeline

    # Calculate time differences between consecutive events
    time_diffs = []
    for i in range(1, len(timeline)):
        try:
            curr_time = datetime.fromisoformat(timeline[i]["timestamp"].replace("Z", "+00:00"))
            prev_time = datetime.fromisoformat(timeline[i-1]["timestamp"].replace("Z", "+00:00"))
            diff_seconds = (curr_time - prev_time).total_seconds()
            time_diffs.append(diff_seconds)
        except (ValueError, KeyError):
            time_diffs.append(None)

    # Calculate statistics
    valid_diffs = [d for d in time_diffs if d is not None]
    if not valid_diffs:
        return timeline

    mean_diff = sum(valid_diffs) / len(valid_diffs)
    std_dev = (sum((x - mean_diff) ** 2 for x in valid_diffs) / len(valid_diffs)) ** 0.5

    # Identify anomalies (gaps or bursts)
    anomaly_threshold = 3.0  # Standard deviations from the mean

    for i in range(len(time_diffs)):
        diff = time_diffs[i]
        if diff is None:
            continue

        if diff > mean_diff + (anomaly_threshold * std_dev):
            # Large gap before this event
            timeline[i+1]["anomaly"] = {
                "type": "time_gap",
                "description": f"Unusual gap of {int(diff)} seconds before this event",
                "severity": "medium" if diff > (2 * mean_diff) else "low"
            }
        elif diff < mean_diff - (anomaly_threshold * std_dev) and diff < 1.0:
            # Burst of activity (events very close together)
            timeline[i+1]["anomaly"] = {
                "type": "activity_burst",
                "description": "Unusually rapid sequence of events",
                "severity": "medium"
            }

    # Look for suspicious sequences of events
    for i in range(1, len(timeline) - 1):
        # Example: privilege escalation followed by suspicious command
        if (_is_privilege_escalation_event(timeline[i]) and
            i+1 < len(timeline) and
            _is_suspicious_command_event(timeline[i+1])):

            timeline[i+1]["anomaly"] = {
                "type": "suspicious_sequence",
                "description": "Suspicious command after privilege escalation",
                "severity": "high",
                "related_event_id": timeline[i].get("id")
            }

    return timeline


def _is_privilege_escalation_event(event: Dict[str, Any]) -> bool:
    """Check if an event represents privilege escalation."""
    if event.get("event_type") == "command":
        command = event.get("details", {}).get("command", "")
        return bool(REGEX_PRIVILEGE_ESCALATION.search(command))
    return False


def _is_suspicious_command_event(event: Dict[str, Any]) -> bool:
    """Check if an event represents a suspicious command."""
    if event.get("event_type") == "command":
        command = event.get("details", {}).get("command", "")
        return bool(REGEX_SUSPICIOUS_CMD.search(command))
    return False


# --- Helper Functions for Report Generation ---

def _generate_report_summary(artifacts: Dict[str, Any], report_type: str) -> Dict[str, Any]:
    """Generate the summary section of the report."""
    summary = {
        "status": "Complete",
        "collection_metadata": artifacts.get("metadata", {})
    }

    # Add artifact counts
    artifact_counts = {
        "processes": len(artifacts.get("processes", [])),
        "network_connections": len(artifacts.get("network_connections", [])),
        "command_history": len(artifacts.get("command_history", [])),
        "open_files": len(artifacts.get("open_files", [])),
        "user_sessions": len(artifacts.get("user_sessions", [])),
        "kernel_modules": len(artifacts.get("kernel_modules", []))
    }
    summary["artifact_counts"] = artifact_counts

    # Add analysis results summary
    analysis_results = artifacts.get("analysis_results", {})
    suspicious_findings = {
        "processes": len(analysis_results.get("suspicious_processes", [])),
        "network_connections": len(analysis_results.get("network_analysis", {}).get("suspicious_ports", [])),
        "commands": (analysis_results.get("suspicious_commands", {}).get("summary", {})
                     .get("total_suspicious", 0)),
        "data_exfiltration": len(analysis_results.get("data_exfiltration_indicators", [])),
        "privilege_escalation": len(analysis_results.get("privilege_escalation_indicators", []))
    }
    summary["suspicious_findings"] = suspicious_findings

    # Calculate overall risk level
    if "risk_assessment" in analysis_results:
        summary["risk_assessment"] = {
            "risk_level": analysis_results["risk_assessment"].get("risk_level", "unknown"),
            "risk_score": analysis_results["risk_assessment"].get("overall_score", 0)
        }
    else:
        # Calculate basic risk level based on findings
        total_suspicious = sum(suspicious_findings.values())
        if total_suspicious > 10:
            risk_level = "high"
        elif total_suspicious > 3:
            risk_level = "medium"
        elif total_suspicious > 0:
            risk_level = "low"
        else:
            risk_level = "info"

        summary["risk_assessment"] = {
            "risk_level": risk_level,
            "risk_score": total_suspicious * 10
        }

    return summary


def _generate_report_findings(artifacts: Dict[str, Any], report_type: str) -> List[Dict[str, Any]]:
    """Generate the findings section of the report."""
    findings = []
    analysis_results = artifacts.get("analysis_results", {})

    # Add process findings
    for proc in analysis_results.get("suspicious_processes", []):
        findings.append({
            "type": "suspicious_process",
            "severity": proc.get("risk_level", "medium"),
            "description": f"Suspicious process: {proc.get('command', 'Unknown')}",
            "user": proc.get("user", "Unknown"),
            "pid": proc.get("pid", "Unknown"),
            "reasons": [reason.get("detail", "Unknown") for reason in proc.get("reasons", [])]
        })

    # Add network findings
    for conn in analysis_results.get("network_analysis", {}).get("suspicious_ports", []):
        findings.append({
            "type": "suspicious_network",
            "severity": "medium",
            "description": f"Suspicious network connection: {conn.get('reason', 'Unknown')}",
            "details": {
                "local_port": conn.get("local_port", "Unknown"),
                "remote_ip": conn.get("remote_ip", "Unknown"),
                "remote_port": conn.get("remote_port", "Unknown"),
                "process_pid": conn.get("process_pid", "Unknown")
            }
        })

    # Add command findings
    for category in ["privilege_escalation", "data_exfil", "encoded_commands"]:
        for cmd in analysis_results.get("suspicious_commands", {}).get(category, []):
            findings.append({
                "type": f"suspicious_command_{category}",
                "severity": "high" if category in ["privilege_escalation", "encoded_commands"] else "medium",
                "description": cmd.get("reason", f"Suspicious {category.replace('_', ' ')} command"),
                "command": cmd.get("command", "Unknown"),
                "timestamp": cmd.get("timestamp", "Unknown")
            })

    # Add data exfiltration findings
    for indicator in analysis_results.get("data_exfiltration_indicators", []):
        findings.append({
            "type": "data_exfiltration",
            "severity": indicator.get("risk_level", "medium"),
            "description": indicator.get("details", "Potential data exfiltration activity"),
            "details": {
                "type": indicator.get("type", "Unknown"),
                "source": indicator.get("source", "Unknown"),
                "command": indicator.get("command", "N/A") if "command" in indicator else "N/A"
            }
        })

    # Add privilege escalation findings
    for indicator in analysis_results.get("privilege_escalation_indicators", []):
        findings.append({
            "type": "privilege_escalation",
            "severity": indicator.get("risk_level", "high"),
            "description": indicator.get("details", "Potential privilege escalation attempt"),
            "details": {
                "type": indicator.get("type", "Unknown"),
                "source": indicator.get("source", "Unknown"),
                "command": indicator.get("command", "N/A") if "command" in indicator else "N/A"
            }
        })

    # For summary reports, limit to high severity findings
    if report_type == "summary":
        findings = [f for f in findings if f.get("severity") == "high"]

    # Sort findings by severity
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 4))

    return findings


def _generate_report_recommendations(artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate recommendations based on findings."""
    recommendations = []
    analysis_results = artifacts.get("analysis_results", {})

    # Add standard recommendations
    recommendations.append({
        "priority": "standard",
        "description": "Implement comprehensive logging and monitoring",
        "details": "Ensure all system and security logs are being collected and monitored for suspicious activity."
    })

    # Add recommendations based on findings
    if analysis_results.get("suspicious_processes", []):
        recommendations.append({
            "priority": "high",
            "description": "Investigate suspicious processes",
            "details": "Review and investigate the identified suspicious processes, especially those running with elevated privileges."
        })

    if analysis_results.get("network_analysis", {}).get("suspicious_ports", []):
        recommendations.append({
            "priority": "high",
            "description": "Review network connections",
            "details": "Investigate unusual network connections, particularly those to non-standard ports or external IP addresses."
        })

    if analysis_results.get("suspicious_commands", {}).get("privilege_escalation", []):
        recommendations.append({
            "priority": "critical",
            "description": "Investigate privilege escalation attempts",
            "details": "Review and investigate potential privilege escalation attempts. Consider isolating affected systems."
        })

    if analysis_results.get("data_exfiltration_indicators", []):
        recommendations.append({
            "priority": "critical",
            "description": "Investigate potential data exfiltration",
            "details": "Analyze potential data exfiltration activities and assess what data may have been compromised."
        })

    # Sort recommendations by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "standard": 3, "low": 4}
    recommendations.sort(key=lambda x: priority_order.get(x.get("priority"), 5))

    return recommendations


def _generate_detailed_analysis(artifacts: Dict[str, Any]) -> Dict[str, Any]:
    """Generate detailed analysis section for technical reports."""
    detailed = {}
    analysis_results = artifacts.get("analysis_results", {})

    # Process analysis
    if "suspicious_processes" in analysis_results:
        detailed["process_analysis"] = {
            "suspicious_processes": analysis_results["suspicious_processes"],
            "process_tree": analysis_results.get("process_tree", {})
        }

    # Network analysis
    if "network_analysis" in analysis_results:
        detailed["network_analysis"] = analysis_results["network_analysis"]

    # Command analysis
    if "suspicious_commands" in analysis_results:
        detailed["command_analysis"] = analysis_results["suspicious_commands"]

    # Add file system analysis if available
    if "open_files" in artifacts:
        suspicious_files = []
        for file_entry in artifacts["open_files"]:
            path = file_entry.get("path", "")
            if path and _is_suspicious_file_path(path):
                suspicious_files.append(file_entry)

        detailed["file_system_analysis"] = {
            "suspicious_files": suspicious_files,
            "file_count": len(artifacts["open_files"]),
            "suspicious_file_count": len(suspicious_files)
        }

    return detailed


def _is_suspicious_file_path(path: str) -> bool:
    """Check if a file path is suspicious."""
    suspicious_patterns = [
        r'/tmp/.*\.(sh|py|pl|rb|php)',
        r'/dev/shm/.*',
        r'/var/tmp/.*\.(sh|py|pl|rb|php)',
        r'/home/[^/]+/\.[^/]+/[^/]+\.sh',
        r'\.\./'  # Path traversal
    ]
    return any(re.search(pattern, path) for pattern in suspicious_patterns)


def _generate_ioc_section(artifacts: Dict[str, Any]) -> Dict[str, Any]:
    """Generate the indicators of compromise section."""
    iocs = {}

    # Extract network indicators
    network_indicators = artifacts.get("analysis_results", {}).get("network_indicators", {})
    if network_indicators:
        iocs["network"] = network_indicators
    else:
        # Extract manually from artifacts
        iocs["network"] = extract_network_indicators(artifacts)

    # Extract file indicators
    file_indicators = artifacts.get("analysis_results", {}).get("file_indicators", {})
    if file_indicators:
        iocs["files"] = file_indicators
    else:
        # Extract manually from artifacts
        iocs["files"] = extract_file_indicators(artifacts)

    # Extract additional IOCs from suspicious processes
    suspicious_processes = artifacts.get("analysis_results", {}).get("suspicious_processes", [])
    suspicious_commands = []
    for proc in suspicious_processes:
        cmd = proc.get("command", "")
        if cmd:
            suspicious_commands.append(cmd)

    if suspicious_commands:
        iocs["commands"] = suspicious_commands

    return iocs


# --- Output Format Helpers ---

def _save_json_report(report: Dict[str, Any], output_file: str) -> Dict[str, Any]:
    """Save the report as a JSON file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        # Set secure permissions
        try:
            os.chmod(output_file, DEFAULT_SECURE_FILE_PERMS)
        except Exception as e:
            logger.warning(f"Could not set permissions on output file: {e}")

        return {
            "success": True,
            "format": "json",
            "file_path": output_file,
            "message": f"Report saved to {output_file}"
        }
    except Exception as e:
        logger.error(f"Error saving JSON report: {e}")
        return {
            "success": False,
            "format": "json",
            "error": str(e)
        }


def _save_text_report(report: Dict[str, Any], output_file: str) -> Dict[str, Any]:
    """Save the report as a plain text file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write(f"FORENSIC ANALYSIS REPORT\n")
            f.write(f"======================\n\n")
            f.write(f"Report Type: {report.get('report_type', 'Unknown')}\n")
            f.write(f"Generated: {report.get('generated_at', 'Unknown')}\n\n")

            # Case info
            case_info = report.get("case_info", {})
            f.write(f"CASE INFORMATION\n")
            f.write(f"-----------------\n")
            f.write(f"Case ID: {case_info.get('case_id', 'Unknown')}\n")
            f.write(f"Examiner: {case_info.get('examiner', 'Unknown')}\n")
            f.write(f"Collection Date: {case_info.get('collection_date', 'Unknown')}\n")
            f.write(f"Host: {case_info.get('host', 'Unknown')}\n\n")

            # Summary
            summary = report.get("summary", {})
            f.write(f"SUMMARY\n")
            f.write(f"-------\n")

            # Artifact counts
            artifact_counts = summary.get("artifact_counts", {})
            f.write(f"Artifacts Collected:\n")
            for artifact_type, count in artifact_counts.items():
                f.write(f"  - {artifact_type.replace('_', ' ').title()}: {count}\n")
            f.write("\n")

            # Risk assessment
            risk = summary.get("risk_assessment", {})
            f.write(f"Risk Assessment:\n")
            f.write(f"  - Risk Level: {risk.get('risk_level', 'Unknown').upper()}\n")
            f.write(f"  - Risk Score: {risk.get('risk_score', 'N/A')}\n\n")

            # Findings
            findings = report.get("findings", [])
            f.write(f"KEY FINDINGS\n")
            f.write(f"-----------\n")
            if findings:
                for i, finding in enumerate(findings, 1):
                    severity = finding.get("severity", "unknown").upper()
                    f.write(f"{i}. [{severity}] {finding.get('description', 'Unknown finding')}\n")

                    # Additional details
                    if "details" in finding and isinstance(finding["details"], dict):
                        for key, value in finding["details"].items():
                            f.write(f"   - {key}: {value}\n")

                    # Reasons if available
                    if "reasons" in finding and isinstance(finding["reasons"], list):
                        f.write(f"   Reasons:\n")
                        for reason in finding["reasons"]:
                            f.write(f"   - {reason}\n")
                    f.write("\n")
            else:
                f.write("No significant findings.\n\n")

            # Recommendations
            recommendations = report.get("recommendations", [])
            f.write(f"RECOMMENDATIONS\n")
            f.write(f"--------------\n")
            if recommendations:
                for i, rec in enumerate(recommendations, 1):
                    priority = rec.get("priority", "standard").upper()
                    f.write(f"{i}. [{priority}] {rec.get('description', 'Unknown recommendation')}\n")
                    if "details" in rec:
                        f.write(f"   {rec['details']}\n")
                    f.write("\n")
            else:
                f.write("No specific recommendations.\n\n")

            # IOCs if available
            if "indicators_of_compromise" in report:
                iocs = report["indicators_of_compromise"]
                f.write(f"INDICATORS OF COMPROMISE\n")
                f.write(f"------------------------\n")

                # Network IOCs
                if "network" in iocs:
                    f.write("Network Indicators:\n")
                    if "ip_addresses" in iocs["network"]:
                        f.write("  IP Addresses:\n")
                        for ip in iocs["network"]["ip_addresses"]:
                            f.write(f"   - {ip}\n")
                    if "domains" in iocs["network"]:
                        f.write("  Domains:\n")
                        for domain in iocs["network"]["domains"]:
                            f.write(f"   - {domain}\n")
                    if "urls" in iocs["network"]:
                        f.write("  URLs:\n")
                        for url in iocs["network"]["urls"]:
                            f.write(f"   - {url}\n")
                    f.write("\n")

                # File IOCs
                if "files" in iocs:
                    f.write("File Indicators:\n")
                    for category, paths in iocs["files"].items():
                        f.write(f"  {category.replace('_', ' ').title()}:\n")
                        for path in paths:
                            f.write(f"   - {path}\n")
                    f.write("\n")

        # Set secure permissions
        try:
            os.chmod(output_file, DEFAULT_SECURE_FILE_PERMS)
        except Exception as e:
            logger.warning(f"Could not set permissions on output file: {e}")

        return {
            "success": True,
            "format": "text",
            "file_path": output_file,
            "message": f"Report saved to {output_file}"
        }
    except Exception as e:
        logger.error(f"Error saving text report: {e}")
        return {
            "success": False,
            "format": "text",
            "error": str(e)
        }


def _save_html_report(report: Dict[str, Any], output_file: str) -> Dict[str, Any]:
    """Save the report as an HTML file."""
    try:
        # Check if the HTML template exists
        template_dir = Path(__file__).parent.parent.parent / "templates" / "reports"
        html_template = template_dir / "forensic_report.html"

        if not html_template.exists():
            # Use basic HTML generation without template
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("<!DOCTYPE html>\n")
                f.write("<html lang='en'>\n")
                f.write("<head>\n")
                f.write("  <meta charset='UTF-8'>\n")
                f.write("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n")
                f.write(f"  <title>Forensic Analysis Report - {report.get('case_info', {}).get('case_id', 'Unknown')}</title>\n")
                f.write("  <style>\n")
                f.write("    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }\n")
                f.write("    h1, h2, h3 { color: #2c3e50; }\n")
                f.write("    .container { max-width: 1200px; margin: 0 auto; }\n")
                f.write("    .header { background-color: #34495e; color: white; padding: 20px; margin-bottom: 20px; }\n")
                f.write("    .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }\n")
                f.write("    .finding { margin-bottom: 15px; padding: 10px; border-left: 4px solid #3498db; background-color: #f9f9f9; }\n")
                f.write("    .finding.high { border-left-color: #e74c3c; }\n")
                f.write("    .finding.medium { border-left-color: #f39c12; }\n")
                f.write("    .finding.low { border-left-color: #3498db; }\n")
                f.write("    .recommendation { margin-bottom: 15px; padding: 10px; border-left: 4px solid #2ecc71; background-color: #f9f9f9; }\n")
                f.write("    .recommendation.critical { border-left-color: #e74c3c; }\n")
                f.write("    .recommendation.high { border-left-color: #f39c12; }\n")
                f.write("    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }\n")
                f.write("    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n")
                f.write("    th { background-color: #f2f2f2; }\n")
                f.write("  </style>\n")
                f.write("</head>\n")
                f.write("<body>\n")
                f.write("  <div class='container'>\n")

                # Header
                f.write("    <div class='header'>\n")
                f.write(f"      <h1>Forensic Analysis Report</h1>\n")
                f.write(f"      <p>Generated: {report.get('generated_at', 'Unknown')}</p>\n")
                f.write("    </div>\n")

                # Case Information
                case_info = report.get("case_info", {})
                f.write("    <div class='section'>\n")
                f.write("      <h2>Case Information</h2>\n")
                f.write("      <table>\n")
                f.write("        <tr><th>Case ID</th><td>" + case_info.get('case_id', 'Unknown') + "</td></tr>\n")
                f.write("        <tr><th>Examiner</th><td>" + case_info.get('examiner', 'Unknown') + "</td></tr>\n")
                f.write("        <tr><th>Collection Date</th><td>" + case_info.get('collection_date', 'Unknown') + "</td></tr>\n")
                f.write("        <tr><th>Host</th><td>" + case_info.get('host', 'Unknown') + "</td></tr>\n")
                f.write("      </table>\n")
                f.write("    </div>\n")

                # Summary
                summary = report.get("summary", {})
                f.write("    <div class='section'>\n")
                f.write("      <h2>Summary</h2>\n")

                # Risk Assessment
                risk = summary.get("risk_assessment", {})
                f.write("      <h3>Risk Assessment</h3>\n")
                f.write("      <p><strong>Risk Level:</strong> " + risk.get('risk_level', 'Unknown').upper() + "</p>\n")
                f.write("      <p><strong>Risk Score:</strong> " + str(risk.get('risk_score', 'N/A')) + "</p>\n")

                # Artifact Counts
                artifact_counts = summary.get("artifact_counts", {})
                f.write("      <h3>Artifacts Collected</h3>\n")
                f.write("      <table>\n")
                f.write("        <tr><th>Artifact Type</th><th>Count</th></tr>\n")
                for artifact_type, count in artifact_counts.items():
                    f.write("        <tr><td>" + artifact_type.replace('_', ' ').title() + "</td><td>" + str(count) + "</td></tr>\n")
                f.write("      </table>\n")
                f.write("    </div>\n")

                # Findings
                findings = report.get("findings", [])
                f.write("    <div class='section'>\n")
                f.write("      <h2>Key Findings</h2>\n")
                if findings:
                    for finding in findings:
                        severity = finding.get("severity", "low")
                        f.write(f"      <div class='finding {severity}'>\n")
                        f.write(f"        <h3>[{severity.upper()}] {finding.get('description', 'Unknown finding')}</h3>\n")

                        # Additional details
                        if "details" in finding and isinstance(finding["details"], dict):
                            f.write("        <ul>\n")
                            for key, value in finding["details"].items():
                                f.write(f"          <li><strong>{key}:</strong> {value}</li>\n")
                            f.write("        </ul>\n")

                        # Reasons if available
                        if "reasons" in finding and isinstance(finding["reasons"], list):
                            f.write("        <div><strong>Reasons:</strong></div>\n")
                            f.write("        <ul>\n")
                            for reason in finding["reasons"]:
                                f.write(f"          <li>{reason}</li>\n")
                            f.write("        </ul>\n")
                        f.write("      </div>\n")
                else:
                    f.write("      <p>No significant findings.</p>\n")
                f.write("    </div>\n")

                # Recommendations
                recommendations = report.get("recommendations", [])
                f.write("    <div class='section'>\n")
                f.write("      <h2>Recommendations</h2>\n")
                if recommendations:
                    for rec in recommendations:
                        priority = rec.get("priority", "standard")
                        f.write(f"      <div class='recommendation {priority}'>\n")
                        f.write(f"        <h3>[{priority.upper()}] {rec.get('description', 'Unknown recommendation')}</h3>\n")
                        if "details" in rec:
                            f.write(f"        <p>{rec['details']}</p>\n")
                        f.write("      </div>\n")
                else:
                    f.write("      <p>No specific recommendations.</p>\n")
                f.write("    </div>\n")

                # IOCs if available
                if "indicators_of_compromise" in report:
                    iocs = report["indicators_of_compromise"]
                    f.write("    <div class='section'>\n")
                    f.write("      <h2>Indicators of Compromise</h2>\n")

                    # Network IOCs
                    if "network" in iocs:
                        f.write("      <h3>Network Indicators</h3>\n")

                        if "ip_addresses" in iocs["network"] and iocs["network"]["ip_addresses"]:
                            f.write("      <h4>IP Addresses</h4>\n")
                            f.write("      <ul>\n")
                            for ip in iocs["network"]["ip_addresses"]:
                                f.write(f"        <li>{ip}</li>\n")
                            f.write("      </ul>\n")

                        if "domains" in iocs["network"] and iocs["network"]["domains"]:
                            f.write("      <h4>Domains</h4>\n")
                            f.write("      <ul>\n")
                            for domain in iocs["network"]["domains"]:
                                f.write(f"        <li>{domain}</li>\n")
                            f.write("      </ul>\n")

                        if "urls" in iocs["network"] and iocs["network"]["urls"]:
                            f.write("      <h4>URLs</h4>\n")
                            f.write("      <ul>\n")
                            for url in iocs["network"]["urls"]:
                                f.write(f"        <li>{url}</li>\n")
                            f.write("      </ul>\n")

                    # File IOCs
                    if "files" in iocs:
                        f.write("      <h3>File Indicators</h3>\n")
                        for category, paths in iocs["files"].items():
                            if paths:
                                f.write(f"      <h4>{category.replace('_', ' ').title()}</h4>\n")
                                f.write("      <ul>\n")
                                for path in paths:
                                    f.write(f"        <li>{path}</li>\n")
                                f.write("      </ul>\n")
                    f.write("    </div>\n")

                f.write("  </div>\n")
                f.write("</body>\n")
                f.write("</html>\n")
        else:
            # Use the template file (template implementation would go here)
            # This would require a template engine or a more complex implementation
            logger.warning("HTML template found but template rendering not implemented. Using basic HTML generation.")
            # Re-run the basic HTML generation
            return _save_html_report(report, output_file)

        # Set secure permissions
        try:
            os.chmod(output_file, DEFAULT_SECURE_FILE_PERMS)
        except Exception as e:
            logger.warning(f"Could not set permissions on output file: {e}")

        return {
            "success": True,
            "format": "html",
            "file_path": output_file,
            "message": f"Report saved to {output_file}"
        }
    except Exception as e:
        logger.error(f"Error saving HTML report: {e}")
        return {
            "success": False,
            "format": "html",
            "error": str(e)
        }


def _save_csv_report(report: Dict[str, Any], output_file: str) -> Dict[str, Any]:
    """Save the report as CSV files (creates multiple files)."""
    try:
        # Create base filename without extension
        base_path = output_file.rsplit('.', 1)[0]

        # Create findings CSV
        findings_path = f"{base_path}_findings.csv"
        with open(findings_path, 'w', encoding='utf-8', newline='') as f:
            import csv
            writer = csv.writer(f)
            writer.writerow(["Severity", "Type", "Description", "Details"])

            for finding in report.get("findings", []):
                # Format details as a string
                details = ""
                if "details" in finding and isinstance(finding["details"], dict):
                    details = "; ".join(f"{k}={v}" for k, v in finding["details"].items())
                elif "reasons" in finding and isinstance(finding["reasons"], list):
                    details = "; ".join(finding["reasons"])

                writer.writerow([
                    finding.get("severity", "unknown"),
                    finding.get("type", "unknown"),
                    finding.get("description", "Unknown finding"),
                    details
                ])

        # Create IOCs CSV if available
        iocs = report.get("indicators_of_compromise", {})

        if iocs:
            iocs_path = f"{base_path}_iocs.csv"
            with open(iocs_path, 'w', encoding='utf-8', newline='') as f:
                import csv
                writer = csv.writer(f)
                writer.writerow(["Type", "Indicator", "Category"])

                # Write network indicators
                if "network" in iocs:
                    for ip in iocs.get("network", {}).get("ip_addresses", []):
                        writer.writerow(["ip_address", ip, "network"])

                    for domain in iocs.get("network", {}).get("domains", []):
                        writer.writerow(["domain", domain, "network"])

                    for url in iocs.get("network", {}).get("urls", []):
                        writer.writerow(["url", url, "network"])

                # Write file indicators
                if "files" in iocs:
                    for category, paths in iocs["files"].items():
                        for path in paths:
                            writer.writerow(["file_path", path, category])

        # Set secure permissions
        try:
            os.chmod(findings_path, DEFAULT_SECURE_FILE_PERMS)
            if iocs:
                os.chmod(iocs_path, DEFAULT_SECURE_FILE_PERMS)
        except Exception as e:
            logger.warning(f"Could not set permissions on output file(s): {e}")

        return {
            "success": True,
            "format": "csv",
            "file_paths": [findings_path] + ([iocs_path] if iocs else []),
            "message": f"Report saved to {findings_path}" + (f" and {iocs_path}" if iocs else "")
        }
    except Exception as e:
        logger.error(f"Error saving CSV report: {e}")
        return {
            "success": False,
            "format": "csv",
            "error": str(e)
        }


def _save_markdown_report(report: Dict[str, Any], output_file: str) -> Dict[str, Any]:
    """Save the report as a Markdown file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Title and metadata
            f.write(f"# Forensic Analysis Report\n\n")
            f.write(f"**Report Type:** {report.get('report_type', 'Unknown')}\n")
            f.write(f"**Generated:** {report.get('generated_at', 'Unknown')}\n\n")

            # Case information
            case_info = report.get("case_info", {})
            f.write(f"## Case Information\n\n")
            f.write(f"- **Case ID:** {case_info.get('case_id', 'Unknown')}\n")
            f.write(f"- **Examiner:** {case_info.get('examiner', 'Unknown')}\n")
            f.write(f"- **Collection Date:** {case_info.get('collection_date', 'Unknown')}\n")
            f.write(f"- **Host:** {case_info.get('host', 'Unknown')}\n\n")

            # Summary
            summary = report.get("summary", {})
            f.write(f"## Summary\n\n")

            # Risk assessment
            risk = summary.get("risk_assessment", {})
            f.write(f"### Risk Assessment\n\n")
            f.write(f"- **Risk Level:** {risk.get('risk_level', 'Unknown').upper()}\n")
            f.write(f"- **Risk Score:** {risk.get('risk_score', 'N/A')}\n\n")

            # Artifact counts
            artifact_counts = summary.get("artifact_counts", {})
            f.write(f"### Artifacts Collected\n\n")
            f.write("| Artifact Type | Count |\n")
            f.write("| -------------- | ----- |\n")
            for artifact_type, count in artifact_counts.items():
                f.write(f"| {artifact_type.replace('_', ' ').title()} | {count} |\n")
            f.write("\n")

            # Findings
            findings = report.get("findings", [])
            f.write(f"## Key Findings\n\n")
            if findings:
                for i, finding in enumerate(findings, 1):
                    severity = finding.get("severity", "unknown").upper()
                    f.write(f"### {i}. [{severity}] {finding.get('description', 'Unknown finding')}\n\n")

                    # Additional details
                    if "details" in finding and isinstance(finding["details"], dict):
                        for key, value in finding["details"].items():
                            f.write(f"- **{key}:** {value}\n")
                        f.write("\n")

                    # Reasons if available
                    if "reasons" in finding and isinstance(finding["reasons"], list):
                        f.write(f"**Reasons:**\n\n")
                        for reason in finding["reasons"]:
                            f.write(f"- {reason}\n")
                        f.write("\n")
            else:
                f.write("No significant findings.\n\n")

            # Recommendations
            recommendations = report.get("recommendations", [])
            f.write(f"## Recommendations\n\n")
            if recommendations:
                for i, rec in enumerate(recommendations, 1):
                    priority = rec.get("priority", "standard").upper()
                    f.write(f"### {i}. [{priority}] {rec.get('description', 'Unknown recommendation')}\n\n")
                    if "details" in rec:
                        f.write(f"{rec['details']}\n\n")
            else:
                f.write("No specific recommendations.\n\n")

            # IOCs if available
            if "indicators_of_compromise" in report:
                iocs = report["indicators_of_compromise"]
                f.write(f"## Indicators of Compromise\n\n")

                # Network IOCs
                if "network" in iocs:
                    f.write("### Network Indicators\n\n")

                    if "ip_addresses" in iocs["network"] and iocs["network"]["ip_addresses"]:
                        f.write("#### IP Addresses\n\n")
                        for ip in iocs["network"]["ip_addresses"]:
                            f.write(f"- `{ip}`\n")
                        f.write("\n")

                    if "domains" in iocs["network"] and iocs["network"]["domains"]:
                        f.write("#### Domains\n\n")
                        for domain in iocs["network"]["domains"]:
                            f.write(f"- `{domain}`\n")
                        f.write("\n")

                    if "urls" in iocs["network"] and iocs["network"]["urls"]:
                        f.write("#### URLs\n\n")
                        for url in iocs["network"]["urls"]:
                            f.write(f"- `{url}`\n")
                        f.write("\n")

                # File IOCs
                if "files" in iocs:
                    f.write("### File Indicators\n\n")
                    for category, paths in iocs["files"].items():
                        if paths:
                            f.write(f"#### {category.replace('_', ' ').title()}\n\n")
                            for path in paths:
                                f.write(f"- `{path}`\n")
                            f.write("\n")

        # Set secure permissions
        try:
            os.chmod(output_file, DEFAULT_SECURE_FILE_PERMS)
        except Exception as e:
            logger.warning(f"Could not set permissions on output file: {e}")

        return {
            "success": True,
            "format": "markdown",
            "file_path": output_file,
            "message": f"Report saved to {output_file}"
        }
    except Exception as e:
        logger.error(f"Error saving Markdown report: {e}")
        return {
            "success": False,
            "format": "markdown",
            "error": str(e)
        }


# Define the artifact types for module-level export
ARTIFACT_TYPES = {
    "process": ["processes/ps_*.txt", "processes/pstree.txt"],
    "network": ["network/ss_*.txt", "network/*_connections.txt"],
    "memory": ["*.raw", "*.lime", "*.dump", "*.mem"],
    "user": ["users/w.txt", "users/who.txt", "users/passwd.txt"],
    "service": ["services/systemctl_*.txt", "services/*_services.txt"],
    "module": ["modules/lsmod.txt", "modules/module_*.txt"],
    "startup": ["startup/enabled_units.txt", "startup/*cron*.txt"],
    "command_history": ["history/*_history.txt"],
    "open_files": ["open_files/lsof_*.txt"],
    "mounted_devices": ["mounted_devices/mount.txt", "mounted_devices/df_*.txt"],
    "firewall": ["firewall/iptables_*.txt", "firewall/firewalld_*.txt"],
    "logs": ["*_log.txt", "*_logs.txt", "*.log"]
}


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
