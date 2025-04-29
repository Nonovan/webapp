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
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Attempt to import core forensic utilities
try:
    from admin.security.forensics.utils.logging_utils import (
        setup_forensic_logger, log_forensic_operation
    )
    from admin.security.forensics.utils.validation_utils import validate_path
    from admin.security.forensics.utils.report_builder import save_analysis_report # Assuming a similar function exists or can be adapted
    FORENSIC_CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Core forensic utilities not found, using basic logging: {e}", file=sys.stderr)
    FORENSIC_CORE_AVAILABLE = False
    # Basic logging fallback
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('artifact_parser_fallback')

    # Dummy log_forensic_operation
    def log_forensic_operation(operation: str, success: bool, details: Dict[str, Any], level: int = logging.INFO):
        logger.log(level, f"Operation='{operation}', Success={success}, Details={json.dumps(details)}")

    # Dummy validate_path
    def validate_path(path: str, **kwargs) -> Tuple[bool, str]:
        if not os.path.exists(path):
            return False, f"Path does not exist: {path}"
        if kwargs.get('check_read') and not os.access(path, os.R_OK):
            return False, f"Path not readable: {path}"
        return True, "Path is valid"

    # Dummy save_analysis_report
    def save_analysis_report(data: Dict[str, Any], output_path: str, format: str = "json") -> bool:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                if format == 'json':
                    json.dump(data, f, indent=2, default=str)
                else: # Basic text fallback
                    for key, value in data.items():
                        f.write(f"{key}:\n")
                        if isinstance(value, (list, dict)):
                            json.dump(value, f, indent=2, default=str)
                            f.write("\n")
                        else:
                            f.write(f"  {value}\n")
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
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_OUTPUT_FORMATS = ["json", "text"] # Add more as needed (e.g., csv, yaml)
DEFAULT_ARTIFACT_DIR = "live_response_output" # Default expected dir name

# Regex for common patterns (examples, expand as needed)
REGEX_IP_ADDR = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
REGEX_SUSPICIOUS_CMD = re.compile(r'(?:powershell.*(?:enc|iex)|nc\s+-|wget\s+-|curl\s+-|chmod\s+\+x)', re.IGNORECASE)
REGEX_COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MS RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3389: "RDP"
}

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
"""
    )

    # Input sources
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--input-dir', help='Directory containing collected live response artifacts.')
    input_group.add_argument('--process-file', help='Path to process list artifact file.')
    # Add arguments for specific file types if needed (e.g., --network-file, --history-file)

    parser.add_argument('--network-file', help='Path to network connections artifact file (if not in input-dir).')
    parser.add_argument('--history-file', help='Path to command history artifact file (if not in input-dir).')
    # Add more specific file inputs as needed

    # Analysis options
    parser.add_argument('--analyze-processes', action='store_true', help='Analyze process list (e.g., build tree, detect suspicious).')
    parser.add_argument('--analyze-network', action='store_true', help='Analyze network connections (e.g., map connections, flag suspicious ports).')
    parser.add_argument('--detect-suspicious-commands', action='store_true', help='Analyze command history for suspicious patterns.')
    parser.add_argument('--full-analysis', action='store_true', help='Perform all available analyses.')

    # Output options
    parser.add_argument('--output', help='Path for output analysis report (default: stdout).')
    parser.add_argument('--format', choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                        help=f'Output format (default: {DEFAULT_OUTPUT_FORMAT}).')

    # Forensic context
    parser.add_argument('--case-id', help='Case ID for forensic logging.')
    parser.add_argument('--analyst', help='Analyst name for forensic logging.')

    # Verbosity
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help='Increase verbosity (can be used multiple times).')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress all output except errors.')

    return parser

# --- Parsing Functions ---

def parse_process_list(file_path: str) -> List[Dict[str, Any]]:
    """Parses a process list artifact file (example format)."""
    processes = []
    logger.info(f"Parsing process list from: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Example: Assuming a simple text format like 'PID PPID USER CMD'
            # Adjust parsing logic based on the actual format from volatile_data.sh
            header = f.readline().strip().lower().split()
            pid_idx, ppid_idx, user_idx, cmd_idx = -1, -1, -1, -1
            try:
                pid_idx = header.index('pid')
                ppid_idx = header.index('ppid')
                user_idx = header.index('user')
                cmd_idx = header.index('cmd') # or 'command'
            except ValueError:
                 logger.warning(f"Could not find expected headers (pid, ppid, user, cmd) in {file_path}. Attempting generic parsing.")
                 # Fallback or more robust parsing needed here

            for line in f:
                parts = line.strip().split(maxsplit=3 if cmd_idx == 3 else -1) # Adjust split based on header indices
                if len(parts) >= 4: # Ensure enough parts based on expected format
                    try:
                        process = {
                            "pid": int(parts[pid_idx]) if pid_idx != -1 else None,
                            "ppid": int(parts[ppid_idx]) if ppid_idx != -1 else None,
                            "user": parts[user_idx] if user_idx != -1 else None,
                            "command": parts[cmd_idx] if cmd_idx != -1 else ' '.join(parts[3:]), # Example fallback
                            "raw_line": line.strip()
                        }
                        processes.append(process)
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Skipping malformed process line: '{line.strip()}'. Error: {e}")
    except IOError as e:
        logger.error(f"Error reading process file {file_path}: {e}")
    logger.info(f"Parsed {len(processes)} processes.")
    return processes

def parse_network_connections(file_path: str) -> List[Dict[str, Any]]:
    """Parses a network connections artifact file (example JSON format)."""
    connections = []
    logger.info(f"Parsing network connections from: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Assuming JSON output from network_state.sh
            data = json.load(f)
            # Adjust structure based on actual output format
            connections = data.get("connections", [])
            # Add parsing for routing_table, arp_cache etc. if present
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from network file {file_path}: {e}")
    except IOError as e:
        logger.error(f"Error reading network file {file_path}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error parsing network file {file_path}: {e}")

    logger.info(f"Parsed {len(connections)} network connections.")
    return connections

def parse_command_history(file_path: str) -> List[str]:
    """Parses a command history file (e.g., .bash_history)."""
    history = []
    logger.info(f"Parsing command history from: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Basic parsing, might need refinement for timestamps etc.
                history.append(line.strip())
    except IOError as e:
        logger.error(f"Error reading command history file {file_path}: {e}")
    logger.info(f"Parsed {len(history)} history entries.")
    return history

# --- Analysis Functions ---

def build_process_tree(processes: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    """Builds a process tree from a list of processes."""
    tree = defaultdict(lambda: {"process": None, "children": []})
    process_map = {p["pid"]: p for p in processes if p.get("pid") is not None}

    for pid, process_data in process_map.items():
        tree[pid]["process"] = process_data
        ppid = process_data.get("ppid")
        if ppid is not None and ppid != pid: # Avoid self-parenting
             tree[ppid]["children"].append(pid)

    # Identify root nodes (those whose parent is not in the map or is 0/1)
    root_pids = [pid for pid, data in tree.items()
                 if data["process"] and (data["process"].get("ppid") is None or
                                         data["process"].get("ppid") not in process_map or
                                         data["process"].get("ppid") in [0, 1])]

    # Return a structure containing roots and the full tree map
    return {"roots": root_pids, "tree": dict(tree)}


def detect_suspicious_processes(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identifies potentially suspicious processes based on patterns."""
    suspicious = []
    for process in processes:
        command = process.get("command", "")
        if REGEX_SUSPICIOUS_CMD.search(command):
            suspicion = {
                "pid": process.get("pid"),
                "command": command,
                "reason": "Command pattern matched suspicious regex",
                "pattern": REGEX_SUSPICIOUS_CMD.pattern
            }
            suspicious.append(suspicion)
        # Add more checks: unusual user, parent process, file path, etc.
    logger.info(f"Detected {len(suspicious)} potentially suspicious processes.")
    return suspicious

def analyze_network_connections(connections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyzes network connections for suspicious activity."""
    analysis = {
        "suspicious_ports": [],
        "external_connections": [],
        "listening_ports": [],
        "connection_summary": defaultdict(int) # Count by state
    }
    known_local_ips = {"127.0.0.1", "::1"} # Add local network ranges if needed

    for conn in connections:
        state = conn.get("state", "UNKNOWN").upper()
        analysis["connection_summary"][state] += 1

        local_port = conn.get("local_port")
        remote_ip = conn.get("remote_ip")
        remote_port = conn.get("remote_port")

        if state == "LISTEN":
            analysis["listening_ports"].append(conn)
            if local_port and local_port not in REGEX_COMMON_PORTS and local_port > 1024:
                 analysis["suspicious_ports"].append({
                     "port": local_port,
                     "process_pid": conn.get("pid"),
                     "reason": "Listening on non-standard high port"
                 })

        if remote_ip and remote_ip not in known_local_ips:
             # Basic check for private vs public IP ranges might be useful here
             analysis["external_connections"].append(conn)
             if remote_port and remote_port not in REGEX_COMMON_PORTS and remote_port > 1024:
                 analysis["suspicious_ports"].append({
                     "local_port": local_port,
                     "remote_ip": remote_ip,
                     "remote_port": remote_port,
                     "process_pid": conn.get("pid"),
                     "reason": "Connection to external IP on non-standard high port"
                 })
             elif remote_port and remote_port in REGEX_COMMON_PORTS:
                 # Could flag connections to common ports if unexpected (e.g., outbound SSH)
                 pass

    logger.info(f"Analyzed network connections. Found {len(analysis['suspicious_ports'])} potentially suspicious port activities.")
    return analysis

def detect_suspicious_commands(history: List[str]) -> List[Dict[str, Any]]:
    """Analyzes command history for suspicious patterns."""
    suspicious = []
    for i, command in enumerate(history):
        if REGEX_SUSPICIOUS_CMD.search(command):
            suspicion = {
                "line_number": i + 1,
                "command": command,
                "reason": "Command matched suspicious regex",
                "pattern": REGEX_SUSPICIOUS_CMD.pattern
            }
            suspicious.append(suspicion)
        # Add more checks: base64 decoding, file downloads, privilege escalation attempts etc.
    logger.info(f"Detected {len(suspicious)} potentially suspicious commands in history.")
    return suspicious

# --- Main Function ---

def main() -> int:
    """Main execution function."""
    parser = setup_argument_parser()
    args = parser.parse_args()

    # --- Logging Setup ---
    log_level = logging.INFO
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose == 1:
        log_level = logging.DEBUG
    elif args.verbose >= 2:
        log_level = logging.DEBUG # Or a custom TRACE level if defined
        if not FORENSIC_CORE_AVAILABLE:
             logging.getLogger().setLevel(logging.DEBUG) # Set root logger level for fallback

    # Set level for the specific logger being used
    logger.setLevel(log_level)

    # Prepare forensic operation logging context
    operation_details = {
        "tool": "artifact_parser",
        "input_dir": args.input_dir,
        "process_file": args.process_file,
        "network_file": args.network_file,
        "history_file": args.history_file,
        "output_path": args.output,
        "output_format": args.format,
        "case_id": args.case_id,
        "analyst": args.analyst,
        "analysis_flags": {
            "analyze_processes": args.analyze_processes or args.full_analysis,
            "analyze_network": args.analyze_network or args.full_analysis,
            "detect_suspicious_commands": args.detect_suspicious_commands or args.full_analysis,
        }
    }
    log_forensic_operation("artifact_parse_start", True, operation_details, level=logging.INFO)

    # --- Locate Artifact Files ---
    process_file = args.process_file
    network_file = args.network_file
    history_file = args.history_file

    if args.input_dir:
        is_valid, msg = validate_path(args.input_dir, must_be_dir=True, check_read=True)
        if not is_valid:
            logger.error(f"Input directory validation failed: {msg}")
            log_forensic_operation("artifact_parse_error", False, {**operation_details, "error": msg}, level=logging.ERROR)
            return 1

        # Auto-detect common artifact names within the directory
        # Adjust filenames based on the output of the collection scripts
        potential_process_file = os.path.join(args.input_dir, "processes.txt") # Or processes.json?
        potential_network_file = os.path.join(args.input_dir, "network_state.json")
        potential_history_file = os.path.join(args.input_dir, "command_history.log") # Or .bash_history?

        if not process_file and os.path.exists(potential_process_file):
            process_file = potential_process_file
        if not network_file and os.path.exists(potential_network_file):
            network_file = potential_network_file
        if not history_file and os.path.exists(potential_history_file):
            history_file = potential_history_file
        # Add detection for other artifact files

    # --- Parse Artifacts ---
    parsed_data: Dict[str, Any] = {
        "processes": [],
        "network_connections": [],
        "command_history": [],
        "analysis_metadata": {
            "timestamp": datetime.now().isoformat(),
            "parser_version": "1.0.0", # Add version tracking
            **operation_details # Include run parameters
        },
        "analysis_results": {}
    }
    errors_found = False

    if process_file:
        is_valid, msg = validate_path(process_file, must_be_file=True, check_read=True)
        if is_valid:
            parsed_data["processes"] = parse_process_list(process_file)
        else:
            logger.error(f"Process file validation failed: {msg}")
            errors_found = True
    elif args.analyze_processes or args.full_analysis:
         logger.warning("Process analysis requested, but no process file specified or found.")

    if network_file:
        is_valid, msg = validate_path(network_file, must_be_file=True, check_read=True)
        if is_valid:
            parsed_data["network_connections"] = parse_network_connections(network_file)
        else:
            logger.error(f"Network file validation failed: {msg}")
            errors_found = True
    elif args.analyze_network or args.full_analysis:
         logger.warning("Network analysis requested, but no network file specified or found.")

    if history_file:
        is_valid, msg = validate_path(history_file, must_be_file=True, check_read=True)
        if is_valid:
            parsed_data["command_history"] = parse_command_history(history_file)
        else:
            logger.error(f"History file validation failed: {msg}")
            errors_found = True
    elif args.detect_suspicious_commands or args.full_analysis:
         logger.warning("Command history analysis requested, but no history file specified or found.")

    # --- Perform Analysis ---
    if args.analyze_processes or args.full_analysis:
        if parsed_data["processes"]:
            logger.info("Analyzing processes...")
            parsed_data["analysis_results"]["process_tree"] = build_process_tree(parsed_data["processes"])
            parsed_data["analysis_results"]["suspicious_processes"] = detect_suspicious_processes(parsed_data["processes"])
        else:
            logger.warning("Skipping process analysis due to parsing errors or missing file.")

    if args.analyze_network or args.full_analysis:
        if parsed_data["network_connections"]:
            logger.info("Analyzing network connections...")
            parsed_data["analysis_results"]["network_analysis"] = analyze_network_connections(parsed_data["network_connections"])
        else:
            logger.warning("Skipping network analysis due to parsing errors or missing file.")

    if args.detect_suspicious_commands or args.full_analysis:
        if parsed_data["command_history"]:
            logger.info("Analyzing command history...")
            parsed_data["analysis_results"]["suspicious_commands"] = detect_suspicious_commands(parsed_data["command_history"])
        else:
             logger.warning("Skipping command history analysis due to parsing errors or missing file.")

    # --- Output Results ---
    if args.output:
        logger.info(f"Saving analysis results to {args.output} in {args.format} format.")
        # Use the report saving utility
        saved = save_analysis_report(parsed_data, args.output, format=args.format)
        if not saved:
            logger.error("Failed to save report.")
            # Fallback to stdout if saving failed?
            print(json.dumps(parsed_data, indent=2, default=str))
            errors_found = True
    else:
        # Print to stdout
        if args.format == 'json':
            print(json.dumps(parsed_data, indent=2, default=str))
        else: # Text format
            # Implement a basic text representation of the parsed_data dictionary
            print("--- Analysis Metadata ---")
            print(json.dumps(parsed_data.get("analysis_metadata", {}), indent=2, default=str))
            print("\n--- Analysis Results ---")
            print(json.dumps(parsed_data.get("analysis_results", {}), indent=2, default=str))
            # Optionally print raw parsed data if verbose
            if args.verbose > 0:
                 print("\n--- Raw Parsed Data ---")
                 # Print limited amounts of raw data
                 print(f"Processes Found: {len(parsed_data.get('processes', []))}")
                 print(f"Network Connections Found: {len(parsed_data.get('network_connections', []))}")
                 print(f"History Entries Found: {len(parsed_data.get('command_history', []))}")


    log_forensic_operation("artifact_parse_complete", not errors_found, operation_details, level=logging.INFO)
    return 1 if errors_found else 0

if __name__ == "__main__":
    sys.exit(main())
