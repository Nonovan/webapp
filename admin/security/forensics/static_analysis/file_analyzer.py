#!/usr/bin/env python3
# filepath: admin/security/forensics/static_analysis/file_analyzer.py
"""
File Structure Analyzer for Forensic Static Analysis.

This tool analyzes file structure, metadata, and content to extract forensically
relevant information without executing the file, supporting incident response
and malware analysis workflows.

It provides comprehensive analysis capabilities including:
- File type identification and verification
- Metadata extraction and analysis
- String extraction and pattern matching
- Entropy analysis for encrypted/compressed/obfuscated content
- PE file structure analysis
- Resource and embedded file extraction

Usage:
    file_analyzer.py --file FILE [options]
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set, Tuple
import re

# Add parent directory to path for module imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    # Import shared utilities
    from admin.security.forensics.static_analysis.common import (
        # Core file operations
        safe_analyze_file,
        identify_file_type,
        extract_embedded_files,
        extract_file_strings,
        calculate_file_entropy,

        # Analysis functions
        extract_metadata_by_format,
        analyze_script_file,
        detect_file_obfuscation,
        save_analysis_report
    )
    # Import shared constants
    from admin.security.forensics.static_analysis.common.output_constants import (
        DEFAULT_OUTPUT_FORMAT, SUPPORTED_OUTPUT_FORMATS, DEFAULT_OUTPUT_DIR,
        DEFAULT_MIN_STRING_LENGTH, DEFAULT_ENTROPY_BLOCK_SIZE, SCRIPT_FILE_EXTENSIONS,
        REGEX_IPV4, REGEX_DOMAIN, REGEX_URL, REGEX_EMAIL,
        REGEX_PASSWORD_KW, REGEX_API_KEY, REGEX_CRYPTO_KW, REGEX_CMD_EXEC
    )
    # Import YARA if needed for pattern matching (optional dependency)
    try:
        import yara
        YARA_AVAILABLE = True
    except ImportError:
        yara = None
        YARA_AVAILABLE = False

    # Import core forensic utilities if available
    from admin.security.forensics.utils.logging_utils import (
        log_forensic_operation,
        setup_forensic_logger
    )

    FORENSIC_CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some forensic modules could not be imported: {e}")
    # Define constants locally as fallbacks if import fails
    DEFAULT_OUTPUT_FORMAT = "json"
    SUPPORTED_OUTPUT_FORMATS = ["json", "text", "yaml"]
    DEFAULT_MIN_STRING_LENGTH = 4
    DEFAULT_OUTPUT_DIR = "file_analysis_output"
    DEFAULT_ENTROPY_BLOCK_SIZE = 256
    SCRIPT_FILE_EXTENSIONS = ['.js', '.py', '.ps1', '.vbs', '.php', '.pl', '.sh', '.bat', '.cmd']
    YARA_AVAILABLE = False
    yara = None
    FORENSIC_CORE_AVAILABLE = False
    # Define dummy regexes or None if needed
    REGEX_IPV4 = REGEX_DOMAIN = REGEX_URL = REGEX_EMAIL = None
    REGEX_PASSWORD_KW = REGEX_API_KEY = REGEX_CRYPTO_KW = REGEX_CMD_EXEC = None


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('file_analyzer')


# --- Argument Parser Setup ---
def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="File Structure Analyzer for Forensic Static Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic file analysis
  python file_analyzer.py --file suspicious.exe

  # Extract strings, analyze entropy, and detect credentials in strings
  python file_analyzer.py --file suspicious.dll --extract-strings --entropy-analysis --analyze-strings --detect-credentials

  # Extract embedded files from document
  python file_analyzer.py --file document.docx --extract-embedded --output-dir extracted_files/

  # Full analysis with all options, output text summary only
  python file_analyzer.py --file malware.bin --full-analysis --output analysis_results.txt --format text --summary-only

  # Analyze file but exclude strings and PE sections from text output
  python file_analyzer.py --file app.exe --full-analysis --format text --exclude-sections strings,pe_sections
"""
    )

    # Required arguments
    parser.add_argument('--file', required=True, help='Path to the file to analyze')

    # Output options
    parser.add_argument('--output', help='Path for output file (default: stdout)')
    parser.add_argument('--output-dir', default=DEFAULT_OUTPUT_DIR,
                        help=f'Directory for extracted files (default: {DEFAULT_OUTPUT_DIR})')
    parser.add_argument('--format', choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                        help=f'Output format (default: {DEFAULT_OUTPUT_FORMAT})')
    # New Output Control Arguments
    parser.add_argument('--summary-only', action='store_true',
                        help='Output only a summary in text format')
    parser.add_argument('--exclude-sections', type=str, default="",
                        help='Comma-separated list of sections to exclude from text output (e.g., strings,metadata,pe_sections)')

    # Core analysis options
    parser.add_argument('--basic-info', action='store_true',
                        help='Basic file information only (fast)')
    parser.add_argument('--metadata', action='store_true',
                        help='Extract detailed file metadata')
    parser.add_argument('--entropy-analysis', action='store_true',
                        help='Perform entropy analysis')
    parser.add_argument('--block-entropy', action='store_true',
                        help='Calculate entropy per block rather than entire file')
    parser.add_argument('--block-size', type=int, default=DEFAULT_ENTROPY_BLOCK_SIZE,
                        help=f'Block size for entropy calculation (default: {DEFAULT_ENTROPY_BLOCK_SIZE} bytes)')

    # String extraction options
    parser.add_argument('--extract-strings', action='store_true',
                        help='Extract readable strings from the file')
    parser.add_argument('--min-length', type=int, default=DEFAULT_MIN_STRING_LENGTH,
                        help=f'Minimum string length (default: {DEFAULT_MIN_STRING_LENGTH})')
    parser.add_argument('--string-context', type=int, default=0,
                        help='Bytes of context around strings (default: 0)')
    parser.add_argument('--string-encoding', default='utf-8',
                        help='String encoding (default: utf-8)')

    # --- String Content Analysis Arguments ---
    parser.add_argument('--analyze-strings', action='store_true',
                        help='Perform content analysis on extracted strings (requires --extract-strings)')
    parser.add_argument('--detect-credentials', action='store_true',
                        help='Detect potential credentials in strings')
    parser.add_argument('--detect-crypto', action='store_true',
                        help='Detect cryptography-related keywords/patterns in strings')
    parser.add_argument('--detect-commands', action='store_true',
                        help='Detect command execution patterns in strings')
    parser.add_argument('--extract-ioc', action='store_true',
                        help='Extract potential Indicators of Compromise (IPs, domains, etc.)')
    parser.add_argument('--ioc-type', type=str, default='all',
                        help='Specific IOC type to extract (e.g., network, host, all)')
    parser.add_argument('--pattern-match', type=str,
                        help='Path to YARA rules file or directory for pattern matching in strings')

    # File type specific options
    parser.add_argument('--extract-embedded', action='store_true',
                        help='Extract embedded files')
    parser.add_argument('--pe-sections', action='store_true',
                        help='Analyze PE file sections')
    parser.add_argument('--section-entropy', action='store_true',
                        help='Calculate entropy for each PE section')
    parser.add_argument('--extract-resources', action='store_true',
                        help='Extract resources from executables')
    parser.add_argument('--check-obfuscation', action='store_true',
                        help='Check for code obfuscation techniques')

    # Comprehensive analysis
    parser.add_argument('--full-analysis', action='store_true',
                        help='Perform all available analysis options (including string content analysis)')

    # Security/forensic options
    parser.add_argument('--case-id', help='Case identifier for forensic logging')
    parser.add_argument('--analyst', help='Analyst name for forensic logging')
    parser.add_argument('--skip-unsafe', action='store_true',
                        help='Skip potentially unsafe operations')
    parser.add_argument('--read-only', action='store_true', default=True,
                        help='Ensure file is accessed in read-only mode (default: True)')

    # Verbosity
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help='Increase verbosity (can be used multiple times)')

    return parser


# --- Logging and Setup Functions ---
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
    """Configure forensic logging if available.

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
            application="file_analyzer",
            log_level=logging.DEBUG if args.verbose > 1 else logging.INFO,
            context=log_context
        )


def log_analysis_start(file_path: str, case_id: Optional[str] = None,
                      analyst: Optional[str] = None) -> None:
    """Log start of analysis to forensic log if available.

    Args:
        file_path: Path to file being analyzed
        case_id: Optional case identifier
        analyst: Optional analyst name
    """
    if FORENSIC_CORE_AVAILABLE:
        details = {
            "file": file_path,
            "tool": "file_analyzer",
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else None,
        }

        if case_id:
            details["case_id"] = case_id
        if analyst:
            details["analyst"] = analyst

        log_forensic_operation("file_analysis_start", True, details)


def log_analysis_complete(file_path: str, results: Dict[str, Any],
                         case_id: Optional[str] = None,
                         analyst: Optional[str] = None) -> None:
    """Log completion of analysis to forensic log if available.

    Args:
        file_path: Path to file that was analyzed
        results: Analysis results dictionary
        case_id: Optional case identifier
        analyst: Optional analyst name
    """
    if FORENSIC_CORE_AVAILABLE:
        details = {
            "file": file_path,
            "tool": "file_analyzer",
            "analysis_types": [],
            "found_indicators": False,
            "summary": {}
        }

        if case_id:
            details["case_id"] = case_id
        if analyst:
            details["analyst"] = analyst

        # Extract analysis types performed and summary data
        summary = {}
        if "basic_info" in results:
            details["analysis_types"].append("basic_info")

        if "metadata" in results:
            details["analysis_types"].append("metadata")

        if "entropy" in results:
            details["analysis_types"].append("entropy")
            if isinstance(results["entropy"], float):
                summary["entropy"] = results["entropy"]
            elif "entropy_summary" in results:
                summary["entropy_avg"] = results["entropy_summary"].get("avg")

        if "strings" in results:
            details["analysis_types"].append("strings")
            summary["string_count"] = results.get("string_count", 0)

        if "string_analysis" in results:  # New
            details["analysis_types"].append("string_content_analysis")
            summary["string_findings_count"] = results["string_analysis"].get("findings_count", 0)
            if summary["string_findings_count"] > 0:
                details["found_indicators"] = True

        if "embedded_files" in results:
            details["analysis_types"].append("embedded_files")
            summary["embedded_file_count"] = results.get("embedded_file_count", 0)

        if "obfuscation_analysis" in results:
            details["analysis_types"].append("obfuscation")
            summary["obfuscation_score"] = results["obfuscation_analysis"].get("obfuscation_score", 0)
            if summary["obfuscation_score"] > 0.5:
                details["found_indicators"] = True

        if "script_analysis" in results:
            details["analysis_types"].append("script_analysis")
            summary["script_risk_level"] = results["script_analysis"].get("risk_level")
            summary["script_indicator_count"] = results["script_analysis"].get("indicator_count", 0)
            if summary["script_indicator_count"] > 0:
                details["found_indicators"] = True

        if "pe_sections" in results:
            details["analysis_types"].append("pe_analysis")

        if "resources" in results:
            details["analysis_types"].append("resource_extraction")
            summary["resource_count"] = results.get("resource_count", 0)

        details["summary"] = summary
        log_forensic_operation("file_analysis_complete", True, details)


# --- Analysis Helper Functions ---

def collect_basic_info(file_path: str) -> Dict[str, Any]:
    """Collect basic information about the file.

    Args:
        file_path: Path to the file to analyze

    Returns:
        Dictionary containing basic file information
    """
    logger.info("Collecting basic file information")
    basic_info = safe_analyze_file(file_path)
    file_type = identify_file_type(file_path)
    basic_info["file_type"] = file_type
    return basic_info


def _analyze_metadata(file_path: str, results: Dict[str, Any]) -> None:
    """Extract format-specific metadata.

    Args:
        file_path: Path to the file to analyze
        results: Dictionary to store analysis results
    """
    logger.info("Extracting file metadata")
    try:
        results["metadata"] = extract_metadata_by_format(file_path)
    except Exception as e:
        logger.error(f"Error extracting metadata: {e}")
        results["metadata_error"] = str(e)


def _analyze_entropy(file_path: str, args: argparse.Namespace, results: Dict[str, Any]) -> None:
    """Perform entropy analysis.

    Args:
        file_path: Path to the file to analyze
        args: Command-line arguments
        results: Dictionary to store analysis results
    """
    logger.info("Performing entropy analysis")
    try:
        if args.block_entropy:
            entropy_data = calculate_file_entropy(file_path, block_size=args.block_size)
            results["entropy"] = entropy_data
            if isinstance(entropy_data, list) and entropy_data:
                results["entropy_summary"] = {
                    "min": min(entropy_data),
                    "max": max(entropy_data),
                    "avg": sum(entropy_data) / len(entropy_data)
                }
        else:
            results["entropy"] = calculate_file_entropy(file_path)
    except Exception as e:
        logger.error(f"Error calculating entropy: {e}")
        results["entropy_error"] = str(e)


def _analyze_strings(file_path: str, args: argparse.Namespace, results: Dict[str, Any]) -> None:
    """Extract strings and optionally perform content analysis.

    Args:
        file_path: Path to the file to analyze
        args: Command-line arguments
        results: Dictionary to store analysis results
    """
    logger.info("Extracting strings")
    extracted_strings: List[Dict[str, Any]] = []
    try:
        extracted_strings = extract_file_strings(
            file_path,
            min_length=args.min_length,
            encoding=args.string_encoding,
            context_bytes=args.string_context
        )
        results["strings"] = extracted_strings  # Store raw extracted strings
        results["string_count"] = len(extracted_strings)
    except Exception as e:
        logger.error(f"Error extracting strings: {e}")
        results["strings_error"] = str(e)
        return  # Cannot analyze if extraction failed

    # --- Integrated String Content Analysis ---
    if args.analyze_strings or args.full_analysis:
        logger.info("Performing content analysis on extracted strings")
        string_analysis_results: Dict[str, Any] = {"findings": [], "errors": [], "yara_matches": []}
        findings_list: List[Dict[str, Any]] = []

        run_credentials = args.detect_credentials or args.full_analysis
        run_crypto = args.detect_crypto or args.full_analysis
        run_commands = args.detect_commands or args.full_analysis
        run_iocs = args.extract_ioc or args.full_analysis

        for string_info in extracted_strings:
            text = string_info["string"]
            offset = string_info["offset"]  # Use offset if available

            # Add specific detection logic here, potentially calling helper functions
            # Example using imported regex (adapt from memory_string_analyzer or common util)
            if run_credentials and REGEX_PASSWORD_KW and REGEX_PASSWORD_KW.search(text):
                findings_list.append({"type": "potential_credential", "string": text, "offset": offset, "detail": "Keyword match"})
            if run_credentials and REGEX_API_KEY and REGEX_API_KEY.search(text):
                findings_list.append({"type": "potential_api_key", "string": text, "offset": offset, "detail": "Pattern match"})
            if run_crypto and REGEX_CRYPTO_KW and REGEX_CRYPTO_KW.search(text):
                findings_list.append({"type": "crypto_keyword", "string": text, "offset": offset, "detail": "Keyword match"})
            if run_commands and REGEX_CMD_EXEC and REGEX_CMD_EXEC.search(text):
                findings_list.append({"type": "command_execution", "string": text, "offset": offset, "detail": "Pattern match"})
            if run_iocs and REGEX_IPV4 and REGEX_IPV4.search(text):
                # More sophisticated IOC extraction needed
                findings_list.append({"type": "ipv4", "string": text, "offset": offset, "detail": "Pattern match"})
            if run_iocs and REGEX_DOMAIN and REGEX_DOMAIN.search(text):
                findings_list.append({"type": "domain", "string": text, "offset": offset, "detail": "Pattern match"})
            if run_iocs and REGEX_URL and REGEX_URL.search(text):
                findings_list.append({"type": "url", "string": text, "offset": offset, "detail": "Pattern match"})
            if run_iocs and REGEX_EMAIL and REGEX_EMAIL.search(text):
                findings_list.append({"type": "email", "string": text, "offset": offset, "detail": "Pattern match"})

        string_analysis_results["findings"] = findings_list
        string_analysis_results["findings_count"] = len(findings_list)

        # YARA Pattern Matching (if requested and available)
        if args.pattern_match and YARA_AVAILABLE and yara:
            try:
                logger.info(f"Applying YARA rules from: {args.pattern_match}")
                yara_matches_list = []

                # Check if path is a file or directory
                if os.path.isfile(args.pattern_match):
                    rules = yara.compile(filepath=args.pattern_match)
                    logger.debug(f"Loaded YARA rules from file: {args.pattern_match}")
                elif os.path.isdir(args.pattern_match):
                    rule_files = {}
                    for root, _, files in os.walk(args.pattern_match):
                        for file in files:
                            if file.endswith('.yar') or file.endswith('.yara'):
                                full_path = os.path.join(root, file)
                                rule_files[file] = full_path
                    if rule_files:
                        rules = yara.compile(filepaths=rule_files)
                        logger.debug(f"Loaded YARA rules from {len(rule_files)} files in directory")
                    else:
                        raise ValueError(f"No YARA rule files found in directory: {args.pattern_match}")
                else:
                    raise ValueError(f"Path does not exist or is not accessible: {args.pattern_match}")

                # Scan the file with YARA rules
                try:
                    with open(file_path, 'rb') as f:
                        matches = rules.match(data=f.read())

                    for match in matches:
                        match_details = {
                            "rule": match.rule,
                            "namespace": match.namespace,
                            "tags": match.tags,
                            "meta": match.meta,
                            "strings": []
                        }

                        for string_id, instances in match.strings:
                            for offset, matched_data in instances:
                                # Safely decode binary data
                                try:
                                    string_value = matched_data.decode('utf-8', errors='replace')
                                except:
                                    string_value = str(matched_data)

                                match_details["strings"].append({
                                    "id": string_id,
                                    "offset": offset,
                                    "value": string_value[:100]  # Truncate long strings
                                })

                        yara_matches_list.append(match_details)

                    string_analysis_results["yara_matches"] = yara_matches_list
                    string_analysis_results["yara_matches_count"] = len(yara_matches_list)
                    logger.info(f"Found {len(yara_matches_list)} YARA matches")
                except Exception as e:
                    error_msg = f"Error scanning with YARA: {e}"
                    logger.error(error_msg)
                    string_analysis_results["errors"].append(error_msg)

            except Exception as e:
                error_msg = f"Error applying YARA rules: {e}"
                logger.error(error_msg)
                string_analysis_results["errors"].append(error_msg)

        results["string_analysis"] = string_analysis_results  # Add analysis results


def _analyze_embedded_files(file_path: str, args: argparse.Namespace, results: Dict[str, Any]) -> None:
    """Extract embedded files.

    Args:
        file_path: Path to the file to analyze
        args: Command-line arguments
        results: Dictionary to store analysis results
    """
    logger.info("Extracting embedded files")
    try:
        embedded_output_dir = os.path.join(args.output_dir, "embedded_files")
        os.makedirs(embedded_output_dir, exist_ok=True)
        embedded_files = extract_embedded_files(file_path, embedded_output_dir)
        results["embedded_files"] = embedded_files
        results["embedded_file_count"] = len(embedded_files)
    except Exception as e:
        logger.error(f"Error extracting embedded files: {e}")
        results["embedded_files_error"] = str(e)


def _analyze_obfuscation(file_path: str, results: Dict[str, Any]) -> None:
    """Check for obfuscation techniques.

    Args:
        file_path: Path to the file to analyze
        results: Dictionary to store analysis results
    """
    logger.info("Checking for obfuscation")
    try:
        obfuscation_analysis = detect_file_obfuscation(file_path)
        results["obfuscation_analysis"] = obfuscation_analysis
    except Exception as e:
        logger.error(f"Error detecting obfuscation: {e}")
        results["obfuscation_error"] = str(e)


def _analyze_script(file_path: str, results: Dict[str, Any]) -> None:
    """Perform script-specific analysis.

    Args:
        file_path: Path to the file to analyze
        results: Dictionary to store analysis results
    """
    logger.info("Performing script-specific analysis")
    try:
        script_analysis = analyze_script_file(file_path)
        results["script_analysis"] = script_analysis
    except Exception as e:
        logger.error(f"Error analyzing script file: {e}")
        results["script_analysis_error"] = str(e)


def _analyze_pe(file_path: str, args: argparse.Namespace, results: Dict[str, Any]) -> None:
    """Perform PE-specific analysis.

    Args:
        file_path: Path to the file to analyze
        args: Command-line arguments
        results: Dictionary to store analysis results
    """
    logger.info("Performing PE-specific analysis")
    try:
        import pefile  # Keep import local to this function
        pe = pefile.PE(file_path)

        # Extract section information
        sections = []
        for section in pe.sections:
            section_info = {
                "name": section.Name.decode('utf-8', errors='replace').rstrip('\x00'),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "characteristics": hex(section.Characteristics),
                "entropy": section.get_entropy()
            }
            sections.append(section_info)
        results["pe_sections"] = sections

        # Extract headers information
        results["pe_headers"] = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() if pe.FILE_HEADER.TimeDateStamp else "N/A",
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase)
        }

        # Security features in DLL characteristics
        security_features = []
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
            security_features.append("ASLR enabled")
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
            security_features.append("DEP enabled")
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400:
            security_features.append("No SEH")
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000:
            security_features.append("Code integrity checks")

        results["pe_security_features"] = security_features

        # Check for imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = {}
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace')
                imports[dll_name] = []
                for imp in entry.imports:
                    if imp.name:
                        imports[dll_name].append(imp.name.decode('utf-8', errors='replace'))
                    else:
                        imports[dll_name].append(f"Ordinal: {imp.ordinal}")
            results["pe_imports"] = imports

        # Check for exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = []
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append({
                        "name": exp.name.decode('utf-8', errors='replace'),
                        "address": hex(exp.address),
                        "ordinal": exp.ordinal
                    })
                else:
                    exports.append({
                        "ordinal": exp.ordinal,
                        "address": hex(exp.address),
                        "name": "N/A"
                    })
            results["pe_exports"] = exports

        # Extract resources if requested
        if args.extract_resources or args.full_analysis:
            resources_output_dir = os.path.join(args.output_dir, "resources")
            os.makedirs(resources_output_dir, exist_ok=True)
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    resource_data = pe.get_data(data_rva, size)
                                    res_type = "unknown"
                                    if hasattr(resource_type, 'id'):
                                        res_type = pefile.RESOURCE_TYPE.get(resource_type.id, f"type_{resource_type.id}")
                                    res_name = f"{res_type}_{resource_id.id}_{resource_lang.id.id}"
                                    resource_path = os.path.join(resources_output_dir, res_name)
                                    try:
                                        with open(resource_path, 'wb') as f:
                                            f.write(resource_data)
                                        resources.append({
                                            "type": res_type, "id": resource_id.id, "language": resource_lang.id.id,
                                            "size": size, "path": resource_path
                                        })
                                    except IOError as io_err:
                                        logger.warning(f"Could not write resource {resource_path}: {io_err}")
            results["resources"] = resources
            results["resource_count"] = len(resources)

    except ImportError:
        logger.warning("pefile library not available, skipping PE-specific analysis")
        results["pe_sections_error"] = "pefile library not available"
    except pefile.PEFormatError as pe_err:
        logger.warning(f"Not a valid PE file or error parsing: {pe_err}")
        results["pe_sections_error"] = f"PE parsing error: {pe_err}"
    except Exception as e:
        logger.error(f"Error analyzing PE file: {e}", exc_info=args.verbose > 1)
        results["pe_sections_error"] = str(e)


# --- Main Analysis Orchestration ---
def perform_analysis(args: argparse.Namespace) -> Dict[str, Any]:
    """Perform file analysis based on command-line arguments.

    Args:
        args: Command-line arguments

    Returns:
        Dictionary containing analysis results
    """
    file_path = args.file
    results: Dict[str, Any] = {
        "file_path": file_path,
        "analysis_start_time": datetime.now().isoformat()
    }

    # Determine analysis types
    run_metadata = args.metadata or args.full_analysis
    run_strings = args.extract_strings or args.full_analysis or args.analyze_strings
    run_entropy = args.entropy_analysis or args.full_analysis or args.section_entropy
    run_embedded = args.extract_embedded or args.full_analysis
    run_obfuscation = args.check_obfuscation or args.full_analysis
    run_pe = args.pe_sections or args.extract_resources or args.full_analysis

    # Set up output directory if needed
    if run_embedded or args.extract_resources or args.full_analysis:
        try:
            os.makedirs(args.output_dir, exist_ok=True)
            logger.info(f"Using output directory: {args.output_dir}")
        except OSError as e:
            logger.error(f"Cannot create output directory {args.output_dir}: {e}")
            # Decide if this is fatal or just skip extraction features
            run_embedded = False
            args.extract_resources = False  # Prevent PE analysis from trying to write

    # Always collect basic info
    results["basic_info"] = collect_basic_info(file_path)

    # Run selected analyses
    if run_metadata:
        _analyze_metadata(file_path, results)

    if run_entropy:
        _analyze_entropy(file_path, args, results)

    if run_strings:
        _analyze_strings(file_path, args, results)  # Handles string content analysis internally

    if run_embedded:
        _analyze_embedded_files(file_path, args, results)

    if run_obfuscation:
        _analyze_obfuscation(file_path, results)

    # Script analysis (check type/extension)
    file_type_desc = results["basic_info"].get("file_type", {}).get("description", "")
    file_ext = os.path.splitext(file_path)[1].lower()
    is_script = file_ext in SCRIPT_FILE_EXTENSIONS or 'script' in file_type_desc.lower()
    if is_script and (args.full_analysis or args.check_obfuscation):  # Often run together
        _analyze_script(file_path, results)

    # PE analysis (check type/extension)
    is_pe = ("PE" in file_type_desc) or file_ext in ['.exe', '.dll', '.sys', '.ocx']
    if is_pe and run_pe:
        _analyze_pe(file_path, args, results)

    # Add final analysis timestamp
    results["analysis_timestamp"] = datetime.now().isoformat()

    # Add analysis duration
    start_time = datetime.fromisoformat(results["analysis_start_time"])
    end_time = datetime.fromisoformat(results["analysis_timestamp"])
    duration_seconds = (end_time - start_time).total_seconds()
    results["analysis_duration_seconds"] = duration_seconds

    return results


# --- Result Saving and Output ---
def save_results(results: Dict[str, Any], args: argparse.Namespace) -> None:
    """Save analysis results to a file or print to stdout.

    Args:
        results: Analysis results dictionary
        args: Command-line arguments
    """
    if args.output:
        output_format = args.format.lower()
        try:
            # Assuming save_analysis_report handles different formats (json, yaml, text)
            save_analysis_report(results, args.output, output_format)
            logger.info(f"Results saved to {args.output} in {output_format} format")
        except Exception as e:
            logger.error(f"Error saving results to {args.output}: {e}")
    else:
        # Print to stdout based on format
        output_format = args.format.lower()
        excluded_sections = {s.strip().lower() for s in args.exclude_sections.split(',') if s.strip()}

        if output_format == 'json':
            # JSON output ignores summary/exclude options
            print(json.dumps(results, indent=2, default=str))
        elif output_format == 'yaml':
            # YAML output ignores summary/exclude options
            try:
                import yaml
                print(yaml.dump(results, default_flow_style=False, sort_keys=False))
            except ImportError:
                logger.error("YAML output requested but PyYAML is not installed. Falling back to JSON.")
                print(json.dumps(results, indent=2, default=str))
        elif output_format == 'text':
            print("=== File Analysis Results ===")
            print(f"File: {results['file_path']}")
            print(f"Analyzed at: {results.get('analysis_timestamp', 'unknown')}")
            print(f"Analysis duration: {results.get('analysis_duration_seconds', 0):.2f} seconds")

            # --- Summary Section (if requested) ---
            if args.summary_only:
                print("\n--- Analysis Summary ---")
                if "basic_info" in results:
                    print(f"  File Size: {results['basic_info'].get('metadata', {}).get('file_size', 'N/A')} bytes")
                    print(f"  File Type: {results['basic_info'].get('file_type', {}).get('description', 'N/A')}")
                    print(f"  MD5 Hash: {results['basic_info'].get('metadata', {}).get('hash', {}).get('md5', 'N/A')}")
                    print(f"  SHA256 Hash: {results['basic_info'].get('metadata', {}).get('hash', {}).get('sha256', 'N/A')}")
                if "entropy" in results:
                    entropy_val = results['entropy']
                    if isinstance(entropy_val, float):
                        print(f"  Overall Entropy: {entropy_val:.4f}")
                    elif "entropy_summary" in results:
                        print(f"  Avg Block Entropy: {results['entropy_summary'].get('avg', 0):.4f}")
                if "string_count" in results:
                    print(f"  Strings Extracted: {results['string_count']}")
                if "string_analysis" in results:
                    print(f"  String Analysis Findings: {results['string_analysis'].get('findings_count', 0)}")
                if "embedded_file_count" in results:
                    print(f"  Embedded Files Found: {results['embedded_file_count']}")
                if "obfuscation_analysis" in results:
                    print(f"  Obfuscation Score: {results['obfuscation_analysis'].get('obfuscation_score', 0):.2f}")
                if "script_analysis" in results:
                    print(f"  Script Risk Level: {results['script_analysis'].get('risk_level', 'N/A')}")
                if "pe_sections" in results:
                    print(f"  PE Sections Found: {len(results['pe_sections'])}")
                if "pe_security_features" in results and results["pe_security_features"]:
                    print(f"  PE Security: {', '.join(results['pe_security_features'])}")
                if "resource_count" in results:
                    print(f"  PE Resources Found: {results['resource_count']}")
                # Add counts for errors if present
                error_keys = [k for k in results if k.endswith('_error')]
                if error_keys:
                    print(f"  Analysis Errors: {len(error_keys)}")
                return  # Stop after summary

            # --- Detailed Sections (respecting exclusions) ---
            if "basic_info" not in excluded_sections and "basic_info" in results:
                print("\n--- Basic Information ---")
                for key, value in results["basic_info"].items():
                    if isinstance(value, dict):
                        print(f"{key}:")
                        for k, v in value.items():
                            print(f"  {k}: {v}")
                    else:
                        print(f"{key}: {value}")

            if "metadata" not in excluded_sections and "metadata" in results:
                print("\n--- File Metadata ---")
                for key, value in results["metadata"].items():
                    if isinstance(value, dict):
                        print(f"{key}:")
                        for k, v in value.items():
                            print(f"  {k}: {v}")
                    else:
                        print(f"{key}: {value}")

            if "entropy" not in excluded_sections and "entropy" in results:
                print("\n--- Entropy Analysis ---")
                if isinstance(results["entropy"], list):
                    summary = results.get("entropy_summary", {})
                    print(f"Block entropy: Min={summary.get('min', 0):.4f}, Max={summary.get('max', 0):.4f}, Avg={summary.get('avg', 0):.4f}")
                    print("First 5 blocks:", results["entropy"][:5])
                elif isinstance(results["entropy"], float):
                    print(f"File entropy: {results['entropy']:.4f}")

            if "strings" not in excluded_sections and "strings" in results:
                print("\n--- String Extraction Summary ---")
                count = results.get('string_count', 0)
                print(f"Extracted {count} strings")
                if count > 0:
                    print("First 5 strings:")
                    for i, string_info in enumerate(results["strings"][:5]):
                        print(f"  {i+1}. Offset:{string_info.get('offset', 'N/A')} | {string_info.get('string', '')}")

            # --- String Content Analysis Output ---
            if "string_analysis" not in excluded_sections and "string_analysis" in results:
                print("\n--- String Content Analysis ---")
                analysis = results["string_analysis"]
                findings = analysis.get("findings", [])
                yara_matches = analysis.get("yara_matches", [])
                print(f"Found {len(findings)} potential items via regex.")
                if findings:
                    print("First 5 findings:")
                    for i, finding in enumerate(findings[:5]):
                        print(f"  {i+1}. Type: {finding.get('type', 'N/A')}, Offset: {finding.get('offset', 'N/A')}, Detail: {finding.get('detail', '')}")
                        print(f"     String: {finding.get('string', '')[:80]}{'...' if len(finding.get('string', '')) > 80 else ''}")  # Truncate long strings
                if yara_matches:
                    print(f"\nFound {len(yara_matches)} YARA rule matches.")
                    for i, match in enumerate(yara_matches[:3]):  # Show first 3
                        print(f"  {i+1}. Rule: {match.get('rule', 'Unknown')}")
                        if match.get('meta', {}).get('description'):
                            print(f"     Description: {match['meta'].get('description', 'N/A')}")
                        if match.get('meta', {}).get('severity'):
                            print(f"     Severity: {match['meta'].get('severity', 'N/A')}")
                        print(f"     Tags: {', '.join(match.get('tags', []))}")
                        print(f"     Matched strings: {len(match.get('strings', []))}")
                    if len(yara_matches) > 3:
                        print(f"     ... and {len(yara_matches) - 3} more matches")

            if "embedded_files" not in excluded_sections and "embedded_files" in results:
                print("\n--- Embedded Files ---")
                count = results.get('embedded_file_count', 0)
                print(f"Extracted {count} embedded files")
                if count > 0:
                    for i, file_info in enumerate(results["embedded_files"]):
                        print(f"  {i+1}. {file_info.get('path', 'N/A')} ({file_info.get('size', 0)} bytes)")

            if "obfuscation_analysis" not in excluded_sections and "obfuscation_analysis" in results:
                print("\n--- Obfuscation Analysis ---")
                obfuscation = results["obfuscation_analysis"]
                print(f"Obfuscation score: {obfuscation.get('obfuscation_score', 0):.2f}")
                print(f"Assessment: {obfuscation.get('assessment', 'Unknown')}")
                indicators = obfuscation.get("obfuscation_indicators", [])
                if indicators:
                    print(f"Found {len(indicators)} indicators:")
                    for i, indicator in enumerate(indicators[:5]):
                        print(f"  {i+1}. {indicator.get('type', 'N/A')}: {indicator.get('description', '')}")

            if "script_analysis" not in excluded_sections and "script_analysis" in results:
                print("\n--- Script Analysis ---")
                script = results["script_analysis"]
                print(f"Risk level: {script.get('risk_level', 'Unknown')}")
                count = script.get('indicator_count', 0)
                print(f"Found {count} indicators")
                indicators = script.get("indicators", [])
                if indicators:
                    print("First 5 suspicious patterns:")
                    for i, indicator in enumerate(indicators[:5]):
                        print(f"  Line {indicator.get('line', 'N/A')}: {indicator.get('content', '')[:80]}... ({indicator.get('type', 'N/A')})")

            if "pe_sections" not in excluded_sections and "pe_sections" in results:
                print("\n--- PE Sections ---")
                for i, section in enumerate(results["pe_sections"]):
                    print(f"  Section {i+1}: {section.get('name', 'N/A')}")
                    print(f"    Virtual Size: {section.get('virtual_size', 0)} bytes")
                    print(f"    Raw Size: {section.get('raw_size', 0)} bytes")
                    print(f"    Entropy: {section.get('entropy', 0):.4f}")

            if "pe_headers" not in excluded_sections and "pe_headers" in results:
                print("\n--- PE Headers ---")
                headers = results["pe_headers"]
                for key, value in headers.items():
                    print(f"  {key}: {value}")

            if "pe_security_features" not in excluded_sections and "pe_security_features" in results:
                print("\n--- PE Security Features ---")
                features = results["pe_security_features"]
                if features:
                    for feature in features:
                        print(f"  {feature}")
                else:
                    print("  No security features detected")

            if "pe_imports" not in excluded_sections and "pe_imports" in results:
                print("\n--- PE Imports ---")
                imports = results["pe_imports"]
                dll_count = len(imports)
                import_count = sum(len(funcs) for funcs in imports.values())
                print(f"  {dll_count} DLLs, {import_count} total imports")
                for i, (dll, functions) in enumerate(list(imports.items())[:3]):  # Show first 3 DLLs
                    print(f"  {i+1}. {dll}: {len(functions)} functions")
                    for j, func in enumerate(functions[:5]):  # Show first 5 functions
                        print(f"      - {func}")
                    if len(functions) > 5:
                        print(f"      ... and {len(functions) - 5} more")
                if dll_count > 3:
                    print(f"  ... and {dll_count - 3} more DLLs")

            if "resources" not in excluded_sections and "resources" in results:
                print("\n--- Resources ---")
                count = results.get('resource_count', 0)
                print(f"Extracted {count} resources")
                if count > 0:
                    resource_types = {}
                    for res in results["resources"]:
                        res_type = res.get("type", "unknown")
                        resource_types[res_type] = resource_types.get(res_type, 0) + 1
                    print("Resources by type:")
                    for res_type, num in resource_types.items():
                        print(f"  {res_type}: {num}")

            # Print Errors
            error_keys = [k for k in results if k.endswith('_error')]
            if error_keys:
                print("\n--- Analysis Errors ---")
                for key in error_keys:
                    print(f"  {key}: {results[key]}")

        else:
            logger.error(f"Unsupported output format for stdout: {output_format}. Defaulting to JSON.")
            print(json.dumps(results, indent=2, default=str))


# --- Main Execution ---
def main() -> int:
    """Main function for file analyzer.

    Returns:
        0 on success, 1 on errors, 2 on critical errors
    """
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Validate args
    if args.analyze_strings and not args.extract_strings and not args.full_analysis:
        parser.error("--analyze-strings requires --extract-strings or --full-analysis")
    if args.summary_only and args.format != 'text':
        logger.warning("--summary-only is only applicable for --format text")
        args.summary_only = False  # Disable if not text format

    set_verbosity(args.verbose)
    configure_forensic_logging(args)

    if not os.path.exists(args.file):
        logger.error(f"File not found: {args.file}")
        return 1

    try:
        log_analysis_start(args.file, args.case_id, args.analyst)
        results = perform_analysis(args)
        log_analysis_complete(args.file, results, args.case_id, args.analyst)
        save_results(results, args)
        return 0

    except Exception as e:
        logger.error(f"Critical error during analysis: {e}", exc_info=args.verbose > 0)
        if FORENSIC_CORE_AVAILABLE:
            details = {
                "file": args.file, "error": str(e), "tool": "file_analyzer",
                "case_id": args.case_id, "analyst": args.analyst
            }
            log_forensic_operation("file_analysis_error", False, {k: v for k, v in details.items() if v is not None})
        return 2


if __name__ == "__main__":
    sys.exit(main())
