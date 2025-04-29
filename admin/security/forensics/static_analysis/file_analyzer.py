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

    # Import core forensic utilities if available
    from admin.security.forensics.utils.logging_utils import (
        log_forensic_operation,
        setup_forensic_logger
    )

    FORENSIC_CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some forensic modules could not be imported: {e}")
    FORENSIC_CORE_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('file_analyzer')

# --- Constants ---
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_OUTPUT_FORMATS = ["json", "text", "yaml"]
DEFAULT_MIN_STRING_LENGTH = 4
DEFAULT_OUTPUT_DIR = "file_analysis_output"

# --- Utility Functions ---

def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="File Structure Analyzer for Forensic Static Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic file analysis
  python file_analyzer.py --file suspicious.exe

  # Extract strings and analyze entropy
  python file_analyzer.py --file suspicious.dll --extract-strings --entropy-analysis

  # Extract embedded files from document
  python file_analyzer.py --file document.docx --extract-embedded --output-dir extracted_files/

  # Full analysis with all options
  python file_analyzer.py --file malware.bin --full-analysis --output analysis_results.json
"""
    )

    # Required arguments
    parser.add_argument('--file', required=True, help='Path to the file to analyze')

    # Output options
    parser.add_argument('--output', help='Path for output file (default: stdout)')
    parser.add_argument('--output-dir', help=f'Directory for extracted files (default: {DEFAULT_OUTPUT_DIR})')
    parser.add_argument('--format', choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                        help=f'Output format (default: {DEFAULT_OUTPUT_FORMAT})')

    # Core analysis options
    parser.add_argument('--basic-info', action='store_true',
                        help='Basic file information only (fast)')
    parser.add_argument('--metadata', action='store_true',
                        help='Extract detailed file metadata')
    parser.add_argument('--entropy-analysis', action='store_true',
                        help='Perform entropy analysis')
    parser.add_argument('--block-entropy', action='store_true',
                        help='Calculate entropy per block rather than entire file')
    parser.add_argument('--block-size', type=int, default=256,
                        help='Block size for entropy calculation (default: 256 bytes)')

    # String extraction options
    parser.add_argument('--extract-strings', action='store_true',
                        help='Extract readable strings from the file')
    parser.add_argument('--min-length', type=int, default=DEFAULT_MIN_STRING_LENGTH,
                        help=f'Minimum string length (default: {DEFAULT_MIN_STRING_LENGTH})')
    parser.add_argument('--string-context', type=int, default=0,
                        help='Bytes of context around strings (default: 0)')
    parser.add_argument('--string-encoding', default='utf-8',
                        help='String encoding (default: utf-8)')

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
                        help='Perform all available analysis options')

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


def set_verbosity(verbose_level: int) -> None:
    """Set verbosity level for logging."""
    if verbose_level == 0:
        logger.setLevel(logging.WARNING)
    elif verbose_level == 1:
        logger.setLevel(logging.INFO)
    else:  # 2 or higher
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
            application="file_analyzer",
            log_level=logging.DEBUG if args.verbose > 1 else logging.INFO,
            context=log_context
        )


def log_analysis_start(file_path: str, case_id: Optional[str] = None,
                      analyst: Optional[str] = None) -> None:
    """Log start of analysis to forensic log if available."""
    if FORENSIC_CORE_AVAILABLE:
        details = {
            "file": file_path,
            "tool": "file_analyzer"
        }
        if case_id:
            details["case_id"] = case_id
        if analyst:
            details["analyst"] = analyst

        log_forensic_operation("file_analysis_start", True, details)


def log_analysis_complete(file_path: str, results: Dict[str, Any],
                         case_id: Optional[str] = None,
                         analyst: Optional[str] = None) -> None:
    """Log completion of analysis to forensic log if available."""
    if FORENSIC_CORE_AVAILABLE:
        details = {
            "file": file_path,
            "tool": "file_analyzer",
            "analysis_types": [],
            "found_indicators": False
        }

        # Add case details if provided
        if case_id:
            details["case_id"] = case_id
        if analyst:
            details["analyst"] = analyst

        # Extract analysis types performed
        if "basic_info" in results:
            details["analysis_types"].append("basic_info")
        if "metadata" in results:
            details["analysis_types"].append("metadata")
        if "entropy" in results:
            details["analysis_types"].append("entropy")
        if "strings" in results:
            details["analysis_types"].append("strings")
            details["string_count"] = len(results["strings"])
        if "embedded_files" in results:
            details["analysis_types"].append("embedded_files")
            details["embedded_file_count"] = len(results["embedded_files"])
        if "obfuscation_analysis" in results:
            details["analysis_types"].append("obfuscation")
            details["obfuscation_score"] = results["obfuscation_analysis"].get("obfuscation_score", 0)

        # Check if any suspicious indicators were found
        if results.get("obfuscation_analysis", {}).get("obfuscation_score", 0) > 0.5:
            details["found_indicators"] = True

        log_forensic_operation("file_analysis_complete", True, details)


def collect_basic_info(file_path: str) -> Dict[str, Any]:
    """
    Collect basic information about the file.

    Args:
        file_path: Path to the file to analyze

    Returns:
        Dictionary containing basic file information
    """
    logger.info("Collecting basic file information")

    basic_info = safe_analyze_file(file_path)

    # Add file type identification
    file_type = identify_file_type(file_path)
    basic_info["file_type"] = file_type

    return basic_info


def perform_analysis(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Perform file analysis based on command-line arguments.

    Args:
        args: Command-line arguments

    Returns:
        Dictionary containing analysis results
    """
    file_path = args.file
    results = {"file_path": file_path}

    # Determine analysis types
    run_metadata = args.metadata or args.full_analysis
    run_strings = args.extract_strings or args.full_analysis
    run_entropy = args.entropy_analysis or args.full_analysis or args.section_entropy
    run_embedded = args.extract_embedded or args.full_analysis
    run_obfuscation = args.check_obfuscation or args.full_analysis

    # Set up output directory if needed
    output_dir = args.output_dir or DEFAULT_OUTPUT_DIR
    if run_embedded or args.extract_resources:
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Created output directory: {output_dir}")

    # Always collect basic info
    results["basic_info"] = collect_basic_info(file_path)

    # Extract format-specific metadata
    if run_metadata:
        logger.info("Extracting file metadata")
        try:
            results["metadata"] = extract_metadata_by_format(file_path)
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")
            results["metadata_error"] = str(e)

    # Perform entropy analysis
    if run_entropy:
        logger.info("Performing entropy analysis")
        try:
            if args.block_entropy:
                results["entropy"] = calculate_file_entropy(file_path, block_size=args.block_size)
                if isinstance(results["entropy"], list):
                    results["entropy_summary"] = {
                        "min": min(results["entropy"]),
                        "max": max(results["entropy"]),
                        "avg": sum(results["entropy"]) / len(results["entropy"])
                    }
            else:
                results["entropy"] = calculate_file_entropy(file_path)
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            results["entropy_error"] = str(e)

    # Extract strings
    if run_strings:
        logger.info("Extracting strings")
        try:
            strings = extract_file_strings(
                file_path,
                min_length=args.min_length,
                encoding=args.string_encoding,
                context_bytes=args.string_context
            )
            results["strings"] = strings
            results["string_count"] = len(strings)
        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
            results["strings_error"] = str(e)

    # Extract embedded files
    if run_embedded:
        logger.info("Extracting embedded files")
        try:
            embedded_output_dir = os.path.join(output_dir, "embedded_files")
            os.makedirs(embedded_output_dir, exist_ok=True)

            embedded_files = extract_embedded_files(file_path, embedded_output_dir)
            results["embedded_files"] = embedded_files
            results["embedded_file_count"] = len(embedded_files)
        except Exception as e:
            logger.error(f"Error extracting embedded files: {e}")
            results["embedded_files_error"] = str(e)

    # Check for obfuscation techniques
    if run_obfuscation:
        logger.info("Checking for obfuscation")
        try:
            obfuscation_analysis = detect_file_obfuscation(file_path)
            results["obfuscation_analysis"] = obfuscation_analysis
        except Exception as e:
            logger.error(f"Error detecting obfuscation: {e}")
            results["obfuscation_error"] = str(e)

    # Special handling for script files
    file_type = results["basic_info"].get("file_type", {}).get("description", "")
    file_ext = os.path.splitext(file_path)[1].lower()
    if file_ext in ['.js', '.py', '.ps1', '.vbs', '.php', '.pl', '.sh'] or 'script' in file_type.lower():
        logger.info("Performing script-specific analysis")
        try:
            script_analysis = analyze_script_file(file_path)
            results["script_analysis"] = script_analysis
        except Exception as e:
            logger.error(f"Error analyzing script file: {e}")
            results["script_analysis_error"] = str(e)

    # Special handling for PE files
    if args.pe_sections or args.full_analysis:
        if (file_type and "PE" in file_type) or file_ext in ['.exe', '.dll', '.sys', '.ocx']:
            logger.info("Performing PE-specific analysis")
            try:
                # Import PE file library
                import pefile

                # Parse PE file
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

                # Extract resources if requested
                if args.extract_resources or args.full_analysis:
                    resources_output_dir = os.path.join(output_dir, "resources")
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

                                            # Determine resource type
                                            res_type = "unknown"
                                            if hasattr(resource_type, 'id'):
                                                res_type = pefile.RESOURCE_TYPE.get(resource_type.id, f"type_{resource_type.id}")

                                            # Generate resource name
                                            res_name = f"{res_type}_{resource_id.id}_{resource_lang.id.id}"

                                            # Save resource to file
                                            resource_path = os.path.join(resources_output_dir, res_name)
                                            with open(resource_path, 'wb') as f:
                                                f.write(resource_data)

                                            resources.append({
                                                "type": res_type,
                                                "id": resource_id.id,
                                                "language": resource_lang.id.id,
                                                "size": size,
                                                "path": resource_path
                                            })

                    results["resources"] = resources
                    results["resource_count"] = len(resources)

            except ImportError:
                logger.warning("pefile library not available, skipping PE-specific analysis")
                results["pe_sections_error"] = "pefile library not available"
            except Exception as e:
                logger.error(f"Error analyzing PE file: {e}")
                results["pe_sections_error"] = str(e)

    # Add analysis timestamp
    results["analysis_timestamp"] = datetime.now().isoformat()

    return results


def save_results(results: Dict[str, Any], args: argparse.Namespace) -> None:
    """
    Save analysis results to a file or print to stdout.

    Args:
        results: Analysis results to save
        args: Command-line arguments
    """
    if args.output:
        output_format = args.format.lower()
        try:
            save_analysis_report(results, args.output, output_format)
            logger.info(f"Results saved to {args.output} in {output_format} format")
        except Exception as e:
            logger.error(f"Error saving results to {args.output}: {e}")
    else:
        # Print to stdout
        if args.format.lower() == 'json':
            json_str = json.dumps(results, indent=2, default=str)
            print(json_str)
        elif args.format.lower() == 'text':
            print("=== File Analysis Results ===")
            print(f"File: {results['file_path']}")
            print(f"Analyzed at: {results.get('analysis_timestamp', 'unknown')}")

            # Print basic info
            if "basic_info" in results:
                print("\n--- Basic Information ---")
                for key, value in results["basic_info"].items():
                    if isinstance(value, dict):
                        print(f"{key}:")
                        for k, v in value.items():
                            print(f"  {k}: {v}")
                    else:
                        print(f"{key}: {value}")

            # Print metadata
            if "metadata" in results:
                print("\n--- File Metadata ---")
                for key, value in results["metadata"].items():
                    if isinstance(value, dict):
                        print(f"{key}:")
                        for k, v in value.items():
                            print(f"  {k}: {v}")
                    else:
                        print(f"{key}: {value}")

            # Print entropy
            if "entropy" in results:
                print("\n--- Entropy Analysis ---")
                if isinstance(results["entropy"], list):
                    print(f"Block entropy: Min={results['entropy_summary']['min']:.4f}, "
                          f"Max={results['entropy_summary']['max']:.4f}, "
                          f"Avg={results['entropy_summary']['avg']:.4f}")
                    print("First 5 blocks:", results["entropy"][:5])
                else:
                    print(f"File entropy: {results['entropy']:.4f}")

            # Print string summary
            if "strings" in results:
                print("\n--- String Extraction Summary ---")
                print(f"Extracted {results['string_count']} strings")
                if results['string_count'] > 0:
                    print("First 5 strings:")
                    for i, string_info in enumerate(results["strings"][:5]):
                        print(f"  {i+1}. {string_info['string']} (offset: {string_info['offset']})")

            # Print embedded files
            if "embedded_files" in results:
                print("\n--- Embedded Files ---")
                print(f"Extracted {results['embedded_file_count']} embedded files")
                if results['embedded_file_count'] > 0:
                    for i, file_info in enumerate(results["embedded_files"]):
                        print(f"  {i+1}. {file_info['path']} ({file_info['size']} bytes)")

            # Print obfuscation analysis
            if "obfuscation_analysis" in results:
                print("\n--- Obfuscation Analysis ---")
                obfuscation = results["obfuscation_analysis"]
                print(f"Obfuscation score: {obfuscation.get('obfuscation_score', 0):.2f}")
                print(f"Assessment: {obfuscation.get('assessment', 'Unknown')}")

                indicators = obfuscation.get("obfuscation_indicators", [])
                if indicators:
                    print(f"Found {len(indicators)} indicators of obfuscation:")
                    for i, indicator in enumerate(indicators[:5]):  # Show first 5
                        print(f"  {i+1}. {indicator['type']}: {indicator['description']}")

            # Print script analysis
            if "script_analysis" in results:
                print("\n--- Script Analysis ---")
                script = results["script_analysis"]
                print(f"Risk level: {script.get('risk_level', 'Unknown')}")
                print(f"Found {script.get('indicator_count', 0)} indicators")

                categories = script.get("categories", {})
                if categories:
                    print("Indicators by category:")
                    for category, count in categories.items():
                        print(f"  {category}: {count}")

                indicators = script.get("indicators", [])
                if indicators:
                    print("First 5 suspicious patterns:")
                    for i, indicator in enumerate(indicators[:5]):
                        print(f"  Line {indicator['line']}: {indicator['content']} "
                              f"({indicator['type']})")

            # Print PE section info
            if "pe_sections" in results:
                print("\n--- PE Sections ---")
                for i, section in enumerate(results["pe_sections"]):
                    print(f"  Section {i+1}: {section['name']}")
                    print(f"    Virtual Size: {section['virtual_size']} bytes")
                    print(f"    Raw Size: {section['raw_size']} bytes")
                    print(f"    Entropy: {section['entropy']:.4f}")

            # Print resources summary
            if "resources" in results:
                print("\n--- Resources ---")
                print(f"Extracted {results['resource_count']} resources")
                resource_types = {}
                for res in results["resources"]:
                    res_type = res["type"]
                    resource_types[res_type] = resource_types.get(res_type, 0) + 1

                print("Resources by type:")
                for res_type, count in resource_types.items():
                    print(f"  {res_type}: {count}")

        else:  # yaml
            try:
                import yaml
                print(yaml.dump(results, default_flow_style=False))
            except ImportError:
                logger.error("YAML output requested but PyYAML is not installed")
                print(json.dumps(results, indent=2, default=str))


def main() -> int:
    """
    Main function for file analyzer.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Configure logging verbosity
    set_verbosity(args.verbose)

    # Configure forensic logging if available
    configure_forensic_logging(args)

    if not os.path.exists(args.file):
        logger.error(f"File not found: {args.file}")
        return 1

    try:
        # Log analysis start
        log_analysis_start(args.file, args.case_id, args.analyst)

        # Perform analysis
        results = perform_analysis(args)

        # Log analysis completion
        log_analysis_complete(args.file, results, args.case_id, args.analyst)

        # Save or display results
        save_results(results, args)

        return 0

    except Exception as e:
        logger.error(f"Error analyzing file: {e}", exc_info=args.verbose > 0)

        if FORENSIC_CORE_AVAILABLE:
            details = {
                "file": args.file,
                "error": str(e),
                "tool": "file_analyzer"
            }
            if args.case_id:
                details["case_id"] = args.case_id
            if args.analyst:
                details["analyst"] = args.analyst

            log_forensic_operation("file_analysis_error", False, details)

        return 2


if __name__ == "__main__":
    sys.exit(main())
