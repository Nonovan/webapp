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
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Pattern, Set

# Add parent directory to path for module imports
# Assumes script is run from its directory or project root adjusted elsewhere
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent)) # Adjust based on actual execution context if needed

try:
    # Import shared utilities from static_analysis/common
    from admin.security.forensics.static_analysis.common import (
        extract_file_strings,
        save_analysis_report,
        YaraScanner,  # Assuming YaraScanner is exposed
        YARA_SCANNER_AVAILABLE
    )
    # Import core forensic utilities if available
    from admin.security.forensics.utils.logging_utils import (
        log_forensic_operation,
        setup_forensic_logger
    )
    from admin.security.forensics.utils.file_utils import read_only_open # For reading string files securely
    FORENSIC_CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some forensic or common static analysis modules could not be imported: {e}")
    # Define fallbacks if necessary, though core functionality might be limited
    FORENSIC_CORE_AVAILABLE = False
    YARA_SCANNER_AVAILABLE = False # Assume YARA is unavailable if common fails

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
                            results.append({"string": current_string.decode('ascii', errors='ignore'), "offset": offset - len(current_string)})
                        current_string = b""
                    offset += 1
                if len(current_string) >= min_length: # Catch trailing string
                     results.append({"string": current_string.decode('ascii', errors='ignore'), "offset": offset - len(current_string)})
        except Exception as ex:
            print(f"Error in fallback string extraction: {ex}")
        return results

    def save_analysis_report(analysis_data: Dict[str, Any], output_path: str, format: str = "json") -> bool:
         print(f"Warning: Using basic fallback report saving to {output_path}")
         try:
             with open(output_path, 'w') as f:
                 if format == 'json':
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
DEFAULT_MIN_STRING_LENGTH = 6 # Slightly higher default for memory
DEFAULT_OUTPUT_DIR = "memory_analysis_output"

# Regex Patterns for Detection
REGEX_IPV4 = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
# More specific IPv6 needed, this is basic
REGEX_IPV6 = re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE)
REGEX_URL = re.compile(r'\b(?:https?|ftp)://[^\s/$.?#].[^\s]*\b', re.IGNORECASE)
REGEX_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
REGEX_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
REGEX_SHA256 = re.compile(r'\b[A-Fa-f0-9]{64}\b')
REGEX_SHA1 = re.compile(r'\b[A-Fa-f0-9]{40}\b')
REGEX_MD5 = re.compile(r'\b[A-Fa-f0-9]{32}\b')

# Potential Credential/Key Patterns (Examples - Need Refinement)
REGEX_PASSWORD_KW = re.compile(r'\b(password|passwd|pwd|secret|key|token|auth)\b[:=]?\s*["\']?([^\s"\'&]{4,})["\']?', re.IGNORECASE)
REGEX_API_KEY = re.compile(r'\b(api_key|access_key|secret_key)[=:]?\s*["\']?([A-Za-z0-9/+_-]{16,})["\']?', re.IGNORECASE)
REGEX_PRIVATE_KEY_HEADER = re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----')
REGEX_CRYPTO_CONSTANTS = re.compile(r'\b(AES|RSA|SHA256|GCM|CBC|ECB)\b', re.IGNORECASE) # Very basic

# Command Patterns (Examples)
REGEX_CMD_EXE = re.compile(r'\bcmd\.exe\s*/[cCkK]\s+', re.IGNORECASE)
REGEX_POWERSHELL_ENC = re.compile(r'powershell\.exe\s+.*(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]+', re.IGNORECASE)
REGEX_SHELL_EXEC = re.compile(r'\b(?:/bin/sh|/bin/bash|/usr/bin/env)\s+.*(?:-c|-s)\s+', re.IGNORECASE)
REGEX_COMMON_CMDS = re.compile(r'\b(net\s+user|whoami|ipconfig|ifconfig|ps\s+|ls\s+-l|pwd|hostname)\b', re.IGNORECASE)

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

    # String extraction options (if input-type is dump)
    parser.add_argument('--min-length', type=int, default=DEFAULT_MIN_STRING_LENGTH,
                        help=f'Minimum string length for extraction (default: {DEFAULT_MIN_STRING_LENGTH})')
    parser.add_argument('--string-encoding', default='utf-8',
                        help='String encoding for extraction (default: utf-8)')

    # Analysis options
    parser.add_argument('--detect-credentials', action='store_true', help='Detect potential credentials and keys')
    parser.add_argument('--detect-crypto', action='store_true', help='Detect cryptographic constants and key headers')
    parser.add_argument('--detect-commands', action='store_true', help='Detect command-line executions')
    parser.add_argument('--extract-ioc', action='store_true', help='Extract potential IOCs (IPs, domains, URLs, hashes)')
    parser.add_argument('--ioc-type', choices=['network', 'hash', 'all'], default='all',
                        help='Specific type of IOCs to extract (default: all)')
    parser.add_argument('--pattern-match', help='Path to YARA rules file or directory for pattern matching')

    # Comprehensive analysis
    parser.add_argument('--full-analysis', action='store_true',
                        help='Perform all available detection options (credentials, crypto, commands, IOCs)')

    # Security/forensic options
    parser.add_argument('--case-id', help='Case identifier for forensic logging')
    parser.add_argument('--analyst', help='Analyst name for forensic logging')

    # Verbosity
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help='Increase verbosity (can be used multiple times)')

    return parser

def set_verbosity(verbose_level: int) -> None:
    """Set verbosity level for logging."""
    if verbose_level == 0:
        logger.setLevel(logging.WARNING)
    elif verbose_level == 1:
        logger.setLevel(logging.INFO)
    else: # 2 or higher
        logger.setLevel(logging.DEBUG)

def configure_forensic_logging(args: argparse.Namespace) -> None:
    """Configure forensic logging if core is available."""
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
    """Log forensic operation if core is available."""
    if FORENSIC_CORE_AVAILABLE:
        log_forensic_operation(event_type, success, details, level=level)
    else:
        # Basic logging fallback
        status = "SUCCESS" if success else "FAILURE"
        log_func = logger.info if success else logger.error
        log_func(f"{event_type} [{status}]: {details}")

# --- Analysis Functions ---

def _find_matches(text: str, pattern: Pattern, match_type: str, offset: int) -> List[Dict[str, Any]]:
    """Find regex matches in text and format them."""
    findings = []
    for match in pattern.finditer(text):
        findings.append({
            "type": match_type,
            "value": match.group(0),
            "offset": offset + match.start(),
            "context_offset": offset # Offset of the original string in the file
        })
    return findings

def _detect_credentials(text: str, offset: int) -> List[Dict[str, Any]]:
    """Detect potential credentials."""
    findings = _find_matches(text, REGEX_PASSWORD_KW, "Potential Password", offset)
    findings.extend(_find_matches(text, REGEX_API_KEY, "Potential API Key", offset))
    return findings

def _detect_crypto(text: str, offset: int) -> List[Dict[str, Any]]:
    """Detect crypto constants and keys."""
    findings = _find_matches(text, REGEX_PRIVATE_KEY_HEADER, "Private Key Header", offset)
    findings.extend(_find_matches(text, REGEX_CRYPTO_CONSTANTS, "Crypto Keyword", offset))
    return findings

def _detect_commands(text: str, offset: int) -> List[Dict[str, Any]]:
    """Detect command executions."""
    findings = _find_matches(text, REGEX_CMD_EXE, "CMD Execution", offset)
    findings.extend(_find_matches(text, REGEX_POWERSHELL_ENC, "PowerShell Encoded", offset))
    findings.extend(_find_matches(text, REGEX_SHELL_EXEC, "Shell Execution", offset))
    findings.extend(_find_matches(text, REGEX_COMMON_CMDS, "Common Command", offset))
    return findings

def _extract_iocs(text: str, offset: int, ioc_type: str) -> List[Dict[str, Any]]:
    """Extract IOCs."""
    findings = []
    if ioc_type in ['network', 'all']:
        findings.extend(_find_matches(text, REGEX_IPV4, "IPv4 Address", offset))
        findings.extend(_find_matches(text, REGEX_IPV6, "IPv6 Address", offset))
        findings.extend(_find_matches(text, REGEX_URL, "URL", offset))
        findings.extend(_find_matches(text, REGEX_DOMAIN, "Domain Name", offset))
        findings.extend(_find_matches(text, REGEX_EMAIL, "Email Address", offset))
    if ioc_type in ['hash', 'all']:
        findings.extend(_find_matches(text, REGEX_SHA256, "SHA256 Hash", offset))
        findings.extend(_find_matches(text, REGEX_SHA1, "SHA1 Hash", offset))
        findings.extend(_find_matches(text, REGEX_MD5, "MD5 Hash", offset))
    return findings

def perform_analysis(args: argparse.Namespace) -> Dict[str, Any]:
    """Perform string analysis based on command-line arguments."""
    file_path = args.file
    results: Dict[str, Any] = {
        "file_path": file_path,
        "analysis_timestamp": datetime.now().isoformat(),
        "findings": [],
        "errors": [],
        "summary": {}
    }
    operation_details = {
        "file": file_path,
        "tool": "memory_string_analyzer",
        "case_id": args.case_id,
        "analyst": args.analyst
    }

    log_operation("memory_string_analysis_start", True, operation_details)

    strings_to_analyze: List[Dict[str, Any]] = []
    total_strings_processed = 0

    # 1. Get strings
    try:
        if args.input_type == 'dump':
            logger.info(f"Extracting strings from memory dump: {file_path}")
            strings_to_analyze = extract_file_strings(
                file_path,
                min_length=args.min_length,
                encoding=args.string_encoding
                # Context bytes might be less useful for memory, omitting for now
            )
            logger.info(f"Extracted {len(strings_to_analyze)} strings (min length {args.min_length})")
        elif args.input_type == 'strings':
            logger.info(f"Reading strings from file: {file_path}")
            # Use secure read if available
            file_handle = None
            if FORENSIC_CORE_AVAILABLE:
                 file_handle = read_only_open(file_path, mode='rt', encoding='utf-8', errors='replace')
            if file_handle is None:
                 file_handle = open(file_path, "rt", encoding='utf-8', errors='replace')

            with file_handle as f:
                # Assuming one string per line, no offset info available
                for i, line in enumerate(f):
                    clean_line = line.strip()
                    if len(clean_line) >= args.min_length:
                        strings_to_analyze.append({"string": clean_line, "offset": -1, "line": i + 1}) # Offset -1 indicates unknown
            logger.info(f"Read {len(strings_to_analyze)} strings from file (min length {args.min_length})")

    except Exception as e:
        error_msg = f"Error getting strings from {file_path}: {e}"
        logger.error(error_msg)
        results["errors"].append(error_msg)
        log_operation("memory_string_analysis_error", False, {**operation_details, "error": error_msg}, level=logging.ERROR)
        return results # Cannot proceed without strings

    total_strings_processed = len(strings_to_analyze)
    findings_list: List[Dict[str, Any]] = []

    # 2. Analyze strings
    run_credentials = args.detect_credentials or args.full_analysis
    run_crypto = args.detect_crypto or args.full_analysis
    run_commands = args.detect_commands or args.full_analysis
    run_iocs = args.extract_ioc or args.full_analysis

    logger.info("Starting string analysis...")
    for string_info in strings_to_analyze:
        text = string_info["string"]
        offset = string_info["offset"]

        if run_credentials:
            findings_list.extend(_detect_credentials(text, offset))
        if run_crypto:
            findings_list.extend(_detect_crypto(text, offset))
        if run_commands:
            findings_list.extend(_detect_commands(text, offset))
        if run_iocs:
            findings_list.extend(_extract_iocs(text, offset, args.ioc_type))

    results["findings"] = findings_list
    logger.info(f"Regex analysis complete. Found {len(findings_list)} potential items.")

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
            results["errors"].append(error_msg)

    # 4. Summarize results
    results["summary"] = {
        "total_strings_processed": total_strings_processed,
        "regex_findings_count": len(findings_list),
        "yara_matches_count": len(yara_matches),
        "errors_count": len(results["errors"])
    }
    # Add counts by type
    finding_types: Dict[str, int] = {}
    for finding in findings_list:
        ftype = finding["type"]
        finding_types[ftype] = finding_types.get(ftype, 0) + 1
    results["summary"]["findings_by_type"] = finding_types

    log_operation("memory_string_analysis_complete", True, {**operation_details, **results["summary"]})

    return results

def save_results(results: Dict[str, Any], args: argparse.Namespace) -> None:
    """Save analysis results to a file or print to stdout."""
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
        else: # Text format
            print("=== Memory String Analysis Results ===")
            print(f"File: {results['file_path']}")
            print(f"Analyzed at: {results.get('analysis_timestamp', 'unknown')}")
            print("\n--- Summary ---")
            for key, value in results.get("summary", {}).items():
                print(f"{key}: {value}")

            if results.get("errors"):
                print("\n--- Errors ---")
                for error in results["errors"]:
                    print(f"- {error}")

            if results.get("findings"):
                print("\n--- Regex Findings ---")
                # Sort or group findings if desired
                for finding in results["findings"]:
                    offset_str = f" (Offset: {finding['offset']})" if finding['offset'] != -1 else ""
                    print(f"- Type: {finding['type']}, Value: {finding['value']}{offset_str}")

            if results.get("yara_matches"):
                print("\n--- YARA Matches ---")
                for match in results["yara_matches"]:
                    print(f"- Rule: {match.get('rule', 'N/A')}")
                    if match.get('meta'):
                        print(f"  Desc: {match['meta'].get('description', 'N/A')}")
                    if match.get('strings'):
                        # Show matched strings (limited)
                        for smatch in match['strings'][:3]: # Show first 3 string matches
                            s_offset = smatch[0]
                            s_id = smatch[1]
                            s_data = smatch[2].hex()[:20] # Show hex representation
                            print(f"  Match: {s_id} at offset {s_offset} (Data: {s_data}...)")

def main() -> int:
    """Main function for memory string analyzer."""
    parser = setup_argument_parser()
    args = parser.parse_args()

    set_verbosity(args.verbose)
    configure_forensic_logging(args)

    if not os.path.exists(args.file):
        logger.error(f"Input file not found: {args.file}")
        return 1

    try:
        results = perform_analysis(args)
        save_results(results, args)
        return 0 if not results.get("errors") else 1 # Return 1 if errors occurred

    except Exception as e:
        logger.error(f"Unhandled error during analysis: {e}", exc_info=args.verbose > 0)
        log_operation("memory_string_analysis_error", False, {
            "file": args.file, "tool": "memory_string_analyzer", "error": str(e),
            "case_id": args.case_id, "analyst": args.analyst
        }, level=logging.ERROR)
        return 2

if __name__ == "__main__":
    sys.exit(main())
