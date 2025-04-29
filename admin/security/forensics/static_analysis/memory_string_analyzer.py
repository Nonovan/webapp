#!/usr/bin/env python3
# filepath: admin/security/forensics/static_analysis/memory_string_analyzer.py
"""
Memory String Analyzer for Forensic Static Analysis.

This tool analyzes strings extracted from memory dumps or string files to identify
forensically relevant information such as credentials, commands, network indicators,
cryptographic material, and matches against known malicious patterns.

It supports analysis of raw memory dumps or pre-extracted string files.

Usage:
    memory_string_analyzer.py --file FILE [options]
"""

import argparse
import json
import logging
import os
import re
import sys
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Pattern, Set, Tuple, Union

# Add parent directory to path for module imports
# Assumes script is run from its directory or project root adjusted elsewhere
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

try:
    # Import shared utilities from static_analysis/common
    from admin.security.forensics.static_analysis.common import (
        extract_file_strings,
        save_analysis_report,
        YaraScanner,
        YARA_SCANNER_AVAILABLE
    )
    # Import core forensic utilities if available
    from admin.security.forensics.utils.logging_utils import (
        log_forensic_operation,
        setup_forensic_logger
    )
    from admin.security.forensics.utils.file_utils import read_only_open
    from admin.security.forensics.static_analysis.common.output_constants import (
        REGEX_IPV4, REGEX_IPV6, REGEX_DOMAIN, REGEX_URL, REGEX_EMAIL,
        REGEX_MAC_ADDR, REGEX_FILEPATH_WINDOWS, REGEX_FILEPATH_LINUX,
        REGEX_PASSWORD_KW, REGEX_API_KEY, REGEX_CRYPTO_KW,
        REGEX_CMD_EXEC, REGEX_POWERSHELL_ENCODED, REGEX_COMMON_CMDS,
        DEFAULT_MIN_STRING_LENGTH
    )
    FORENSIC_CORE_AVAILABLE = True
    CONSTANTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some forensic or common static analysis modules could not be imported: {e}")
    # Define fallbacks if necessary, though core functionality might be limited
    FORENSIC_CORE_AVAILABLE = False
    YARA_SCANNER_AVAILABLE = False
    CONSTANTS_AVAILABLE = False

    # Minimal fallback for extract_file_strings if needed (basic implementation)
    def extract_file_strings(file_path: str, min_length: int = 4, encoding: str = "utf-8", context_bytes: int = 0) -> List[Dict[str, Any]]:
        print(f"Warning: Using basic fallback string extraction for {file_path}")
        results = []
        try:
            # Basic printable ASCII extraction
            printable_bytes = bytes(range(32, 127)) + b'\t\n\r'
            with open(file_path, "rb") as f:
                offset = 0
                current_string = b""
                while True:
                    byte = f.read(1)
                    if not byte:
                        break
                    if byte in printable_bytes:
                        current_string += byte
                    else:
                        if len(current_string) >= min_length:
                            results.append({
                                "string": current_string.decode('ascii', errors='ignore'),
                                "offset": offset - len(current_string),
                                "length": len(current_string)
                            })
                        current_string = b""
                    offset += 1
                if len(current_string) >= min_length: # Catch trailing string
                     results.append({
                         "string": current_string.decode('ascii', errors='ignore'),
                         "offset": offset - len(current_string),
                         "length": len(current_string)
                     })
        except Exception as ex:
            print(f"Error in fallback string extraction: {ex}")
        return results

    def save_analysis_report(analysis_data: Dict[str, Any], output_path: str, format: str = "json") -> bool:
         print(f"Warning: Using basic fallback report saving to {output_path}")
         try:
             with open(output_path, 'w') as f:
                 if format.lower() == 'json':
                     json.dump(analysis_data, f, indent=2, default=str)
                 else: # Basic text fallback
                     for key, value in analysis_data.items():
                         f.write(f"{key}: {value}\n")
             return True
         except Exception as ex:
             print(f"Error saving report: {ex}")
             return False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('memory_string_analyzer')

# --- Constants ---
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_OUTPUT_FORMATS = ["json", "text", "yaml"]
DEFAULT_MIN_STRING_LENGTH = 6 if not CONSTANTS_AVAILABLE else DEFAULT_MIN_STRING_LENGTH
DEFAULT_OUTPUT_DIR = "memory_analysis_output"
MAX_CONTEXT_DISPLAY_CHARS = 80  # Maximum characters to display for context in text output
MAX_FINDINGS_IN_TEXT_OUTPUT = 100  # Maximum number of findings to display in text output
MAX_FINDINGS_PER_TYPE = 20  # Maximum findings per type in text output

# Default regex patterns if constants not available
if not CONSTANTS_AVAILABLE:
    # Network IOCs
    REGEX_IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    REGEX_IPV6 = re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b|\b(?:[A-F0-9]{1,4}:){6}:[A-F0-9]{1,4}\b|\b(?:[A-F0-9]{1,4}:){5}(?::[A-F0-9]{1,4}){1,2}\b', re.IGNORECASE)
    REGEX_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    REGEX_URL = re.compile(r'\b(?:https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]\b', re.IGNORECASE)
    REGEX_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    REGEX_MAC_ADDR = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b')
    REGEX_FILEPATH_WINDOWS = re.compile(r'\b[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\b')
    REGEX_FILEPATH_LINUX = re.compile(r'\b/(?:[^/\0<>|\r\n]+/)*[^/\0<>|\r\n]+\b')

    # Credential patterns
    REGEX_PASSWORD_KW = re.compile(r'\b(?:password|passwd|pwd|secret|key|token|auth|credentials?)\s*[:=]\s*[\'"]?([^\s"\'&]{4,})[\'"]?', re.IGNORECASE)
    REGEX_API_KEY = re.compile(r'\b(?:api_?key|access_?key|secret_?key)\s*[:=]\s*[\'"]?([a-zA-Z0-9/+._-]{16,})[\'"]?', re.IGNORECASE)

    # Crypto patterns
    REGEX_CRYPTO_KW = re.compile(r'\b(aes|des|rsa|sha[0-9]{1,3}|md[0-9]|encrypt|decrypt|cipher|hash|salt|pbkdf[0-9]|hmac)\b', re.IGNORECASE)

    # Command patterns
    REGEX_CMD_EXEC = re.compile(r'\b(?:cmd\.exe|powershell|pwsh|bash|sh|/bin/(?:ba)?sh|system\(|exec\(|popen\(|subprocess\.|shell_exec|eval\(|child_process\.|Process\.Start|Runtime\.exec)\b', re.IGNORECASE)
    REGEX_POWERSHELL_ENCODED = re.compile(r'powershell.*-[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM]{0,4}[aA][nN][dD]? .*[A-Za-z0-9+/=]{30,}')
    REGEX_COMMON_CMDS = re.compile(r'\b(?:net\s+user|whoami|ipconfig|ifconfig|systeminfo|tasklist|ps\s+-|wget\s+|curl\s+|netstat|nslookup|ping\s+|tracert)\b', re.IGNORECASE)

# Additional patterns not imported from constants
REGEX_SHA256 = re.compile(r'\b[A-Fa-f0-9]{64}\b')
REGEX_SHA1 = re.compile(r'\b[A-Fa-f0-9]{40}\b')
REGEX_MD5 = re.compile(r'\b[A-Fa-f0-9]{32}\b')
REGEX_PRIVATE_KEY_HEADER = re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----')
REGEX_CERTIFICATE_HEADER = re.compile(r'-----BEGIN CERTIFICATE-----')
REGEX_BASE64_BLOB = re.compile(r'\b(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b')
REGEX_JWT_TOKEN = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
REGEX_GUID = re.compile(r'\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\b')
REGEX_REGISTRY_PATH = re.compile(r'\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_USERS|HKU|HKEY_CLASSES_ROOT|HKCR|HKEY_CURRENT_CONFIG|HKCC)\\[^\\]+(?:\\[^\\]+)*\b', re.IGNORECASE)
REGEX_SOCKET = re.compile(r'\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0):[0-9]{1,5}\b|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}\b')
REGEX_USER_AGENT = re.compile(r'User-Agent: .*?[\r\n]', re.IGNORECASE)
REGEX_PROCESS_MEMORY = re.compile(r'\b(?:0x)?[A-Fa-f0-9]{8,16}(?:h)?(?:\s*[-:]\s*(?:0x)?[A-Fa-f0-9]{8,16}(?:h)?)+\b')
REGEX_SQL = re.compile(r'\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b.*?\b(?:FROM|INTO|TABLE|DATABASE|WHERE)\b', re.IGNORECASE)
REGEX_HTTP_REQUEST = re.compile(r'\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH) (?:/[^ ]*) HTTP/[0-9.]+\b', re.IGNORECASE)
REGEX_SESSION_ID = re.compile(r'\b(?:SESSIONID|JSESSIONID|SESSION_ID|PHPSESSID)=([a-zA-Z0-9_.-]+)')

# --- Group patterns by category for easier handling ---
NETWORK_PATTERNS = [
    ("IPv4", REGEX_IPV4),
    ("IPv6", REGEX_IPV6),
    ("Domain Name", REGEX_DOMAIN),
    ("URL", REGEX_URL),
    ("Email Address", REGEX_EMAIL),
    ("MAC Address", REGEX_MAC_ADDR),
    ("Socket Address", REGEX_SOCKET),
    ("HTTP Request", REGEX_HTTP_REQUEST),
]

PATH_PATTERNS = [
    ("Windows Path", REGEX_FILEPATH_WINDOWS),
    ("Linux Path", REGEX_FILEPATH_LINUX),
    ("Registry Path", REGEX_REGISTRY_PATH),
]

CREDENTIAL_PATTERNS = [
    ("Potential Password", REGEX_PASSWORD_KW),
    ("Potential API Key", REGEX_API_KEY),
    ("JWT Token", REGEX_JWT_TOKEN),
    ("Session ID", REGEX_SESSION_ID),
]

CRYPTO_PATTERNS = [
    ("Private Key Header", REGEX_PRIVATE_KEY_HEADER),
    ("Certificate Header", REGEX_CERTIFICATE_HEADER),
    ("Crypto Keyword", REGEX_CRYPTO_KW),
    ("Base64 Blob", REGEX_BASE64_BLOB),
]

HASH_PATTERNS = [
    ("MD5 Hash", REGEX_MD5),
    ("SHA1 Hash", REGEX_SHA1),
    ("SHA256 Hash", REGEX_SHA256),
    ("GUID", REGEX_GUID),
]

COMMAND_PATTERNS = [
    ("Command Execution", REGEX_CMD_EXEC),
    ("PowerShell Encoded", REGEX_POWERSHELL_ENCODED),
    ("Common Command", REGEX_COMMON_CMDS),
]

# Additional categories
MISC_PATTERNS = [
    ("User Agent", REGEX_USER_AGENT),
    ("Process Memory", REGEX_PROCESS_MEMORY),
    ("SQL Query", REGEX_SQL),
]

# --- Utility Functions ---

def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Memory String Analyzer for Forensic Static Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze strings from a memory dump for common IOCs
  python memory_string_analyzer.py --file memdump.raw --extract-ioc

  # Detect credentials and commands in extracted strings file
  python memory_string_analyzer.py --file strings.txt --detect-credentials --detect-commands --input-type strings

  # Match strings against YARA rules and output to JSON
  python memory_string_analyzer.py --file memdump.raw --pattern-match common/yara_rules/suspicious/ --output analysis.json

  # Full analysis with all detection options
  python memory_string_analyzer.py --file memdump.raw --full-analysis --output full_report.txt --format text

  # Extract specific IOC types only
  python memory_string_analyzer.py --file memdump.raw --extract-ioc --ioc-type network --output network_iocs.json

  # Analyze with custom string minimum length
  python memory_string_analyzer.py --file memdump.raw --full-analysis --min-length 10 --output long_strings_analysis.json
"""
    )

    # Required arguments
    parser.add_argument('--file', required=True, help='Path to the memory dump or strings file to analyze')
    parser.add_argument('--input-type', choices=['dump', 'strings'], default='dump',
                        help='Type of input file (memory dump or pre-extracted strings) (default: dump)')

    # Output options
    parser.add_argument('--output', help='Path for output file (default: stdout)')
    parser.add_argument('--format', choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                        help=f'Output format (default: {DEFAULT_OUTPUT_FORMAT})')
    parser.add_argument('--output-dir', help='Directory for storing additional output files')
    parser.add_argument('--max-findings', type=int, default=MAX_FINDINGS_IN_TEXT_OUTPUT,
                        help=f'Maximum findings to display in text output (default: {MAX_FINDINGS_IN_TEXT_OUTPUT})')

    # String extraction options (if input-type is dump)
    parser.add_argument('--min-length', type=int, default=DEFAULT_MIN_STRING_LENGTH,
                        help=f'Minimum string length for extraction (default: {DEFAULT_MIN_STRING_LENGTH})')
    parser.add_argument('--string-encoding', default='utf-8',
                        help='String encoding for extraction (default: utf-8)')
    parser.add_argument('--filter-strings', type=str, help='Filter strings using regex pattern')

    # Analysis options
    parser.add_argument('--detect-credentials', action='store_true', help='Detect potential credentials and keys')
    parser.add_argument('--detect-crypto', action='store_true', help='Detect cryptographic constants and key headers')
    parser.add_argument('--detect-commands', action='store_true', help='Detect command-line executions')
    parser.add_argument('--detect-paths', action='store_true', help='Detect file paths and registry keys')
    parser.add_argument('--detect-sql', action='store_true', help='Detect SQL queries')
    parser.add_argument('--extract-ioc', action='store_true', help='Extract potential IOCs (IPs, domains, URLs, hashes)')
    parser.add_argument('--ioc-type', choices=['network', 'hash', 'paths', 'all'], default='all',
                        help='Specific type of IOCs to extract (default: all)')
    parser.add_argument('--pattern-match', help='Path to YARA rules file or directory for pattern matching')
    parser.add_argument('--detect-user-agents', action='store_true', help='Detect browser User-Agents')

    # Advanced options
    parser.add_argument('--generate-hashes', action='store_true',
                        help='Generate hashes for every string found (useful for correlation)')
    parser.add_argument('--context-bytes', type=int, default=0,
                        help='Extract bytes around found strings for context (memory dumps only)')
    parser.add_argument('--dedup', action='store_true',
                        help='Deduplicate identical findings')
    parser.add_argument('--group-by', choices=['type', 'offset', 'none'], default='none',
                        help='Group results by finding type or memory offset')

    # Comprehensive analysis
    parser.add_argument('--full-analysis', action='store_true',
                        help='Perform all available detection options')

    # Security/forensic options
    parser.add_argument('--case-id', help='Case identifier for forensic logging')
    parser.add_argument('--analyst', help='Analyst name for forensic logging')
    parser.add_argument('--read-only', action='store_true', default=True,
                        help='Ensure file is accessed in read-only mode (default: True)')

    # Verbosity and metadata
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help='Increase verbosity (can be used multiple times)')
    parser.add_argument('--include-metadata', action='store_true',
                        help='Include file metadata in results')

    return parser

def set_verbosity(verbose_level: int) -> None:
    """Set verbosity level for logging.

    Args:
        verbose_level: Level of verbosity (0=warning, 1=info, 2+=debug)
    """
    if verbose_level == 0:
        logger.setLevel(logging.WARNING)
    elif verbose_level == 1:
        logger.setLevel(logging.INFO)
    else:  # 2 or higher
        logger.setLevel(logging.DEBUG)

def configure_forensic_logging(args: argparse.Namespace) -> None:
    """Configure forensic logging if core is available.

    Args:
        args: Command line arguments
    """
    if FORENSIC_CORE_AVAILABLE:
        log_context = {}
        if args.case_id:
            log_context["case_id"] = args.case_id
        if args.analyst:
            log_context["analyst"] = args.analyst

        setup_forensic_logger(
            application="memory_string_analyzer",
            log_level=logging.DEBUG if args.verbose > 1 else logging.INFO,
            context=log_context
        )

def log_operation(event_type: str, success: bool, details: Dict[str, Any], level: int = logging.INFO) -> None:
    """Log forensic operation if core is available.

    Args:
        event_type: Type of event being logged
        success: Whether operation was successful
        details: Dictionary of details about operation
        level: Logging level for this operation
    """
    if FORENSIC_CORE_AVAILABLE:
        log_forensic_operation(event_type, success, details, level=level)
    else:
        # Basic logging fallback
        status = "SUCCESS" if success else "FAILURE"
        log_func = logger.info if success else logger.error
        log_func(f"{event_type} [{status}]: {details}")

# --- Analysis Functions ---

def _find_matches(text: str, pattern: Pattern, match_type: str, offset: int) -> List[Dict[str, Any]]:
    """Find regex matches in text and format them.

    Args:
        text: String to search
        pattern: Regular expression pattern to match
        match_type: Type of pattern being matched
        offset: Base offset of the string in the file

    Returns:
        List of dictionaries containing match information
    """
    findings = []
    for match in pattern.finditer(text):
        findings.append({
            "type": match_type,
            "value": match.group(0),
            "offset": offset + match.start() if offset != -1 else -1,
            "length": match.end() - match.start(),
            "context_offset": offset,  # Offset of the original string in the file
        })
    return findings

def _generate_string_hash(text: str) -> Dict[str, str]:
    """Generate multiple hash formats for a string.

    Args:
        text: String to hash

    Returns:
        Dictionary with multiple hash formats
    """
    string_bytes = text.encode('utf-8', errors='replace')
    return {
        "md5": hashlib.md5(string_bytes).hexdigest(),
        "sha1": hashlib.sha1(string_bytes).hexdigest(),
        "sha256": hashlib.sha256(string_bytes).hexdigest(),
    }

def _detect_credentials(text: str, offset: int) -> List[Dict[str, Any]]:
    """Detect potential credentials.

    Args:
        text: String to analyze
        offset: Base offset of the string in the file

    Returns:
        List of credential findings
    """
    findings = []
    for name, pattern in CREDENTIAL_PATTERNS:
        findings.extend(_find_matches(text, pattern, name, offset))
    return findings

def _detect_crypto(text: str, offset: int) -> List[Dict[str, Any]]:
    """Detect crypto constants and keys.

    Args:
        text: String to analyze
        offset: Base offset of the string in the file

    Returns:
        List of crypto-related findings
    """
    findings = []
    for name, pattern in CRYPTO_PATTERNS:
        findings.extend(_find_matches(text, pattern, name, offset))
    return findings

def _detect_commands(text: str, offset: int) -> List[Dict[str, Any]]:
    """Detect command executions.

    Args:
        text: String to analyze
        offset: Base offset of the string in the file

    Returns:
        List of command execution findings
    """
    findings = []
    for name, pattern in COMMAND_PATTERNS:
        findings.extend(_find_matches(text, pattern, name, offset))
    return findings

def _detect_paths(text: str, offset: int) -> List[Dict[str, Any]]:
    """Detect file and registry paths.

    Args:
        text: String to analyze
        offset: Base offset of the string in the file

    Returns:
        List of path findings
    """
    findings = []
    for name, pattern in PATH_PATTERNS:
        findings.extend(_find_matches(text, pattern, name, offset))
    return findings

def _extract_iocs(text: str, offset: int, ioc_type: str) -> List[Dict[str, Any]]:
    """Extract IOCs.

    Args:
        text: String to analyze
        offset: Base offset of the string in the file
        ioc_type: Type of IOC to extract (network, hash, paths, all)

    Returns:
        List of IOC findings
    """
    findings = []

    # Network IOCs
    if ioc_type in ['network', 'all']:
        for name, pattern in NETWORK_PATTERNS:
            findings.extend(_find_matches(text, pattern, name, offset))

    # Hash IOCs
    if ioc_type in ['hash', 'all']:
        for name, pattern in HASH_PATTERNS:
            findings.extend(_find_matches(text, pattern, name, offset))

    # Path IOCs
    if ioc_type in ['paths', 'all']:
        findings.extend(_detect_paths(text, offset))

    return findings

def _detect_miscellaneous(text: str, offset: int, args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Detect miscellaneous patterns based on arguments.

    Args:
        text: String to analyze
        offset: Base offset of the string in the file
        args: Command line arguments

    Returns:
        List of miscellaneous findings
    """
    findings = []

    # User agents
    if args.detect_user_agents or args.full_analysis:
        findings.extend(_find_matches(text, REGEX_USER_AGENT, "User Agent", offset))

    # SQL queries
    if args.detect_sql or args.full_analysis:
        findings.extend(_find_matches(text, REGEX_SQL, "SQL Query", offset))

    # Process memory addresses
    if args.full_analysis:
        findings.extend(_find_matches(text, REGEX_PROCESS_MEMORY, "Memory Address", offset))

    return findings

def _filter_and_deduplicate(findings: List[Dict[str, Any]], args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Filter and deduplicate findings based on arguments.

    Args:
        findings: List of findings
        args: Command line arguments

    Returns:
        Filtered list of findings
    """
    # Deduplicate if requested
    if args.dedup:
        # Use a set to track unique values with their types
        unique_findings = {}
        for finding in findings:
            key = (finding["type"], finding["value"])
            if key not in unique_findings:
                unique_findings[key] = finding

        findings = list(unique_findings.values())

    # Sort by offset if available
    findings.sort(key=lambda x: (x["offset"] if x["offset"] != -1 else sys.maxsize))

    # Generate hashes if requested
    if args.generate_hashes:
        for finding in findings:
            finding["hashes"] = _generate_string_hash(finding["value"])

    return findings

def _extract_file_metadata(file_path: str) -> Dict[str, Any]:
    """Extract basic file metadata.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with file metadata
    """
    try:
        stat_info = os.stat(file_path)
        metadata = {
            "file_name": os.path.basename(file_path),
            "file_size": stat_info.st_size,
            "last_modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "last_accessed": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            "file_extension": os.path.splitext(file_path)[1].lower() if '.' in os.path.basename(file_path) else '',
        }

        # Calculate file hash
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)

            metadata["sha256"] = sha256_hash.hexdigest()

        except Exception as e:
            logger.warning(f"Could not calculate file hash: {e}")

        return metadata
    except Exception as e:
        logger.error(f"Error extracting file metadata: {e}")
        return {"error": str(e)}

def perform_analysis(args: argparse.Namespace) -> Dict[str, Any]:
    """Perform string analysis based on command-line arguments.

    Args:
        args: Command-line arguments

    Returns:
        Dictionary with analysis results
    """
    file_path = args.file
    results: Dict[str, Any] = {
        "file_path": file_path,
        "analysis_timestamp": datetime.now().isoformat(),
        "analysis_type": "memory_string_analysis",
        "findings": [],
        "errors": [],
        "warnings": [],
        "summary": {}
    }

    # Include metadata if requested
    if args.include_metadata:
        results["metadata"] = _extract_file_metadata(file_path)

    operation_details = {
        "file": file_path,
        "tool": "memory_string_analyzer",
        "case_id": args.case_id,
        "analyst": args.analyst,
        "input_type": args.input_type
    }

    log_operation("memory_string_analysis_start", True, operation_details)

    strings_to_analyze: List[Dict[str, Any]] = []
    total_strings_processed = 0

    # 1. Get strings
    try:
        string_filter_pattern = None
        if args.filter_strings:
            try:
                string_filter_pattern = re.compile(args.filter_strings)
                logger.info(f"Using string filter pattern: {args.filter_strings}")
            except re.error as e:
                error_msg = f"Invalid filter pattern: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
                # Continue without filtering

        if args.input_type == 'dump':
            logger.info(f"Extracting strings from memory dump: {file_path}")
            try:
                strings_to_analyze = extract_file_strings(
                    file_path,
                    min_length=args.min_length,
                    encoding=args.string_encoding,
                    context_bytes=args.context_bytes
                )
                logger.info(f"Extracted {len(strings_to_analyze)} strings (min length {args.min_length})")
            except Exception as e:
                error_msg = f"Error extracting strings: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
                # Try to continue with an empty list

        elif args.input_type == 'strings':
            logger.info(f"Reading strings from file: {file_path}")
            # Use secure read if available
            try:
                file_handle = None
                if FORENSIC_CORE_AVAILABLE and args.read_only:
                    file_handle = read_only_open(file_path, mode='rt', encoding='utf-8', errors='replace')
                if file_handle is None:
                    file_handle = open(file_path, "rt", encoding='utf-8', errors='replace')

                with file_handle as f:
                    # Assuming one string per line, no offset info available
                    for i, line in enumerate(f):
                        clean_line = line.strip()
                        if len(clean_line) >= args.min_length:
                            # If filtering is enabled, check if the string matches
                            if string_filter_pattern and not string_filter_pattern.search(clean_line):
                                continue

                            strings_to_analyze.append({
                                "string": clean_line,
                                "offset": -1,  # Offset -1 indicates unknown
                                "line": i + 1,
                                "length": len(clean_line)
                            })

                logger.info(f"Read {len(strings_to_analyze)} strings from file (min length {args.min_length})")
            except Exception as e:
                error_msg = f"Error reading strings file: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)

        # Apply filtering if we're working with a dump and have a filter pattern
        if args.input_type == 'dump' and string_filter_pattern:
            filtered_strings = []
            for string_info in strings_to_analyze:
                if string_filter_pattern.search(string_info["string"]):
                    filtered_strings.append(string_info)

            strings_filtered_count = len(strings_to_analyze) - len(filtered_strings)
            strings_to_analyze = filtered_strings
            logger.info(f"Filtered out {strings_filtered_count} strings, {len(strings_to_analyze)} remaining")

    except Exception as e:
        error_msg = f"Error getting strings from {file_path}: {e}"
        logger.error(error_msg)
        results["errors"].append(error_msg)
        log_operation("memory_string_analysis_error", False, {**operation_details, "error": error_msg}, level=logging.ERROR)
        return results  # Cannot proceed without strings

    total_strings_processed = len(strings_to_analyze)
    if total_strings_processed == 0:
        warning_msg = "No strings found matching criteria. Analysis may be incomplete."
        logger.warning(warning_msg)
        results["warnings"].append(warning_msg)
        # Continue with empty list

    findings_list: List[Dict[str, Any]] = []

    # 2. Analyze strings
    run_credentials = args.detect_credentials or args.full_analysis
    run_crypto = args.detect_crypto or args.full_analysis
    run_commands = args.detect_commands or args.full_analysis
    run_iocs = args.extract_ioc or args.full_analysis
    run_paths = args.detect_paths or args.full_analysis

    analysis_types_run = []
    if run_credentials:
        analysis_types_run.append("credentials")
    if run_crypto:
        analysis_types_run.append("crypto")
    if run_commands:
        analysis_types_run.append("commands")
    if run_iocs:
        analysis_types_run.append("iocs")
    if run_paths:
        analysis_types_run.append("paths")

    # If no specific analysis requested but not full analysis, do IOC extraction as default
    if not analysis_types_run and not args.full_analysis:
        run_iocs = True
        analysis_types_run.append("iocs")

    logger.info(f"Starting string analysis with types: {', '.join(analysis_types_run)}")

    # Process each string through the selected analyzers
    for string_info in strings_to_analyze:
        text = string_info["string"]
        offset = string_info["offset"]

        if run_credentials:
            findings_list.extend(_detect_credentials(text, offset))
        if run_crypto:
            findings_list.extend(_detect_crypto(text, offset))
        if run_commands:
            findings_list.extend(_detect_commands(text, offset))
        if run_paths and not run_iocs:  # Only run if not part of IOC extraction
            findings_list.extend(_detect_paths(text, offset))
        if run_iocs:
            findings_list.extend(_extract_iocs(text, offset, args.ioc_type))

        # Miscellaneous detections
        findings_list.extend(_detect_miscellaneous(text, offset, args))

    # Filter and deduplicate findings
    findings_list = _filter_and_deduplicate(findings_list, args)

    # Add to results
    results["findings"] = findings_list
    logger.info(f"Analysis complete. Found {len(findings_list)} potential items.")

    # 3. YARA Pattern Matching (if requested and available)
    yara_matches = []
    if args.pattern_match:
        if YARA_SCANNER_AVAILABLE:
            logger.info(f"Performing YARA pattern matching using rules from: {args.pattern_match}")
            try:
                # Initialize YaraScanner - needs rule path(s)
                scanner = YaraScanner(rule_paths=[args.pattern_match])
                # Scan the original file (dump or strings file)
                yara_matches = scanner.scan_file(file_path)
                results["yara_matches"] = yara_matches
                logger.info(f"YARA scan complete. Found {len(yara_matches)} matches.")
            except Exception as e:
                error_msg = f"Error during YARA scanning: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
                log_operation("yara_scan_error", False, {**operation_details, "error": error_msg}, level=logging.ERROR)
        else:
            error_msg = "YARA scanning requested, but YaraScanner is not available (check imports)."
            logger.warning(error_msg)
            results["warnings"].append(error_msg)

    # 4. Group findings if requested
    if args.group_by != 'none':
        grouped_findings = {}

        if args.group_by == 'type':
            # Group by finding type
            for finding in findings_list:
                finding_type = finding["type"]
                if finding_type not in grouped_findings:
                    grouped_findings[finding_type] = []
                grouped_findings[finding_type].append(finding)

        elif args.group_by == 'offset':
            # Group by offset range (nearest 4KB boundary)
            for finding in findings_list:
                if finding["offset"] == -1:
                    offset_group = "unknown"
                else:
                    # Group into 4KB chunks
                    offset_group = f"{(finding['offset'] // 4096) * 4096}"

                if offset_group not in grouped_findings:
                    grouped_findings[offset_group] = []
                grouped_findings[offset_group].append(finding)

        # Replace findings with grouped structure
        results["grouped_findings"] = grouped_findings
        # Keep original list for backward compatibility
        results["findings"] = findings_list

    # 5. Summarize results
    finding_types: Dict[str, int] = {}
    for finding in findings_list:
        ftype = finding["type"]
        finding_types[ftype] = finding_types.get(ftype, 0) + 1

    results["summary"] = {
        "total_strings_processed": total_strings_processed,
        "regex_findings_count": len(findings_list),
        "yara_matches_count": len(yara_matches),
        "errors_count": len(results["errors"]),
        "warnings_count": len(results["warnings"]),
        "analysis_types": analysis_types_run,
        "findings_by_type": finding_types
    }

    # Calculate risk score based on findings
    risk_score = 0

    # Increment risk for concerning findings
    if finding_types.get("Potential Password", 0) > 0:
        risk_score += 0.3
    if finding_types.get("Potential API Key", 0) > 0:
        risk_score += 0.3
    if finding_types.get("Private Key Header", 0) > 0:
        risk_score += 0.5
    if finding_types.get("Command Execution", 0) > 0:
        risk_score += 0.4
    if finding_types.get("PowerShell Encoded", 0) > 0:
        risk_score += 0.6

    # Adjust risk based on volume
    if len(findings_list) > 100:
        risk_score += 0.2

    # Cap risk at 1.0
    risk_score = min(1.0, risk_score)
    results["summary"]["risk_score"] = risk_score

    # Add risk assessment
    if risk_score >= 0.7:
        results["summary"]["risk_assessment"] = "High"
    elif risk_score >= 0.4:
        results["summary"]["risk_assessment"] = "Medium"
    else:
        results["summary"]["risk_assessment"] = "Low"

    log_operation("memory_string_analysis_complete", True, {**operation_details, **results["summary"]})
    return results

def save_results(results: Dict[str, Any], args: argparse.Namespace) -> None:
    """Save analysis results to a file or print to stdout.

    Args:
        results: Analysis results
        args: Command-line arguments
    """
    if args.output:
        output_format = args.format.lower()
        try:
            # Use the common save function if available
            save_analysis_report(results, args.output, output_format)
            logger.info(f"Results saved to {args.output} in {output_format} format")
        except Exception as e:
            logger.error(f"Error saving results to {args.output}: {e}")
            # Fallback to basic print if save fails
            print(json.dumps(results, indent=2, default=str))
    else:
        # Print to stdout based on format
        if args.format.lower() == 'json':
            print(json.dumps(results, indent=2, default=str))
        elif args.format.lower() == 'yaml':
            try:
                import yaml
                print(yaml.dump(results, default_flow_style=False, sort_keys=False))
            except ImportError:
                logger.error("YAML output requested but PyYAML is not installed. Falling back to JSON.")
                print(json.dumps(results, indent=2, default=str))
        else:  # Text format
            print("=== Memory String Analysis Results ===")
            print(f"File: {results['file_path']}")
            print(f"Analyzed at: {results.get('analysis_timestamp', 'unknown')}")

            # Print summary information
            print("\n--- Summary ---")
            summary = results.get("summary", {})

            # Print risk assessment first if available
            if "risk_assessment" in summary:
                print(f"Risk Assessment: {summary['risk_assessment']} (Score: {summary.get('risk_score', 0):.2f})")

            print(f"Total Strings Processed: {summary.get('total_strings_processed', 0)}")
            print(f"Regex Findings: {summary.get('regex_findings_count', 0)}")
            print(f"YARA Matches: {summary.get('yara_matches_count', 0)}")

            # Print findings by type
            findings_by_type = summary.get("findings_by_type", {})
            if findings_by_type:
                print("\nFindings by Type:")
                for finding_type, count in sorted(findings_by_type.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {finding_type}: {count}")

            # Print errors and warnings if any
            if results.get("errors"):
                print("\n--- Errors ---")
                for error in results["errors"]:
                    print(f"- {error}")

            if results.get("warnings"):
                print("\n--- Warnings ---")
                for warning in results["warnings"]:
                    print(f"- {warning}")

            # Print findings with limiting based on args.max_findings
            if results.get("findings"):
                # If grouping is enabled, use grouped output
                if "grouped_findings" in results:
                    grouped_findings = results["grouped_findings"]
                    print(f"\n--- Grouped Findings ({len(results['findings'])} total) ---")

                    for group_name, group_findings in grouped_findings.items():
                        print(f"\n{group_name} ({len(group_findings)} findings):")

                        # Limit findings per group
                        findings_to_show = min(len(group_findings), MAX_FINDINGS_PER_TYPE)
                        for i, finding in enumerate(group_findings[:findings_to_show]):
                            offset_str = f" (Offset: {finding['offset']})" if finding['offset'] != -1 else ""
                            print(f"  {i+1}. {finding['type']}: {finding['value'][:MAX_CONTEXT_DISPLAY_CHARS]}{offset_str}")

                        if len(group_findings) > findings_to_show:
                            print(f"  ... and {len(group_findings) - findings_to_show} more findings in this group")

                # Otherwise, show flat list
                else:
                    print(f"\n--- Regex Findings ---")

                    findings = results["findings"]
                    max_findings = min(args.max_findings, len(findings))

                    for i, finding in enumerate(findings[:max_findings]):
                        offset_str = f" (Offset: {finding['offset']})" if finding['offset'] != -1 else ""
                        print(f"- [{finding['type']}] {finding['value'][:MAX_CONTEXT_DISPLAY_CHARS]}{offset_str}")

                        # Print hashes if generated
                        if "hashes" in finding:
                            print(f"  SHA256: {finding['hashes']['sha256']}")

                    if len(findings) > max_findings:
                        print(f"\n... and {len(findings) - max_findings} more findings (use --max-findings to show more)")

            # Print YARA matches
            if results.get("yara_matches"):
                print("\n--- YARA Matches ---")
                for i, match in enumerate(results["yara_matches"]):
                    print(f"- Rule: {match.get('rule', 'N/A')} (Namespace: {match.get('namespace', 'N/A')})")

                    if match.get('meta'):
                        description = match['meta'].get('description', 'N/A')
                        severity = match['meta'].get('severity', 'N/A')
                        print(f"  Description: {description}")
                        print(f"  Severity: {severity}")

                    if match.get('tags'):
                        print(f"  Tags: {', '.join(match['tags'])}")

                    if match.get('strings'):
                        # Show matched strings (limited)
                        print(f"  Matched {len(match['strings'])} string patterns")

                        # Limit to first few strings per match
                        for j, smatch in enumerate(match['strings'][:3]):
                            s_offset = smatch[0]
                            s_id = smatch[1]
                            s_data = smatch[2].hex()[:20]  # Show hex representation
                            print(f"    - {s_id} at offset {s_offset} (Data: {s_data}...)")

                        if len(match['strings']) > 3:
                            print(f"    ... and {len(match['strings']) - 3} more matched patterns")

def main() -> int:
    """Main function for memory string analyzer.

    Returns:
        Exit code (0 for success, 1 for errors with findings, 2 for critical errors)
    """
    parser = setup_argument_parser()
    args = parser.parse_args()

    set_verbosity(args.verbose)
    configure_forensic_logging(args)

    if not os.path.exists(args.file):
        logger.error(f"Input file not found: {args.file}")
        return 2

    try:
        # Create output directory if needed
        if args.output_dir:
            try:
                os.makedirs(args.output_dir, exist_ok=True)
                logger.info(f"Using output directory: {args.output_dir}")
            except OSError as e:
                logger.error(f"Cannot create output directory {args.output_dir}: {e}")
                return 2

        start_time = datetime.now()
        results = perform_analysis(args)
        end_time = datetime.now()

        # Add execution time
        duration = (end_time - start_time).total_seconds()
        results["execution_time_seconds"] = duration
        results["summary"]["execution_time_seconds"] = duration

        save_results(results, args)

        # Return appropriate status code
        if results.get("errors"):
            logger.warning("Analysis completed with errors")
            return 1
        return 0

    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        log_operation("memory_string_analysis_interrupted", False, {
            "file": args.file,
            "tool": "memory_string_analyzer",
            "case_id": args.case_id,
            "analyst": args.analyst
        }, level=logging.WARNING)
        return 1

    except Exception as e:
        logger.error(f"Unhandled error during analysis: {e}", exc_info=args.verbose > 0)
        log_operation("memory_string_analysis_error", False, {
            "file": args.file,
            "tool": "memory_string_analyzer",
            "error": str(e),
            "case_id": args.case_id,
            "analyst": args.analyst
        }, level=logging.ERROR)
        return 2

if __name__ == "__main__":
    sys.exit(main())
