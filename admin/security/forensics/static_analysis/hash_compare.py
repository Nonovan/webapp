"""
Hash Comparison Tool for Forensic Static Analysis

This tool calculates, compares, and verifies cryptographic and fuzzy hashes
as part of the static analysis process within the Cloud Infrastructure Platform's
Forensic Analysis Toolkit. It helps identify known malicious files, find similar
files, and verify file integrity.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add parent directory to path for module imports
# Adjust based on actual execution context if needed
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

# Attempt to import common forensic and static analysis utilities
try:
    # Common hash utilities
    from admin.security.forensics.static_analysis.common import (
        calculate_hash,
        calculate_multiple_hashes,
        calculate_fuzzy_hash,
        verify_hash,
        compare_fuzzy_hashes,
        check_hash_against_database,
        find_similar_files,
        save_analysis_report,
        SSDEEP_AVAILABLE,
        TLSH_AVAILABLE
    )
    # Core forensic logging and validation
    from admin.security.forensics.utils.logging_utils import (
        setup_forensic_logger,
        log_forensic_operation
    )
    from admin.security.forensics.utils.validation_utils import validate_path

    FORENSIC_CORE_AVAILABLE = True
    HASH_UTILS_AVAILABLE = True

except ImportError as e:
    print(f"Warning: Critical forensic or hash modules could not be imported: {e}. Functionality may be limited.")
    FORENSIC_CORE_AVAILABLE = False
    HASH_UTILS_AVAILABLE = False
    SSDEEP_AVAILABLE = False
    TLSH_AVAILABLE = False

    # Basic logging setup if forensic logger fails
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('hash_compare_fallback')

    # Dummy log function
    def log_forensic_operation(operation: str, success: bool, details: Dict[str, Any], level=logging.INFO):
        logger.log(level, f"Operation '{operation}' {'succeeded' if success else 'failed'}. Details: {details}")

    # Dummy validation
    def validate_path(path_str: str, **kwargs) -> tuple[bool, str]:
        if not os.path.exists(path_str):
            return False, f"Path does not exist: {path_str}"
        # Basic check, might need refinement based on kwargs
        if kwargs.get('must_be_file') and not os.path.isfile(path_str):
             return False, f"Path is not a file: {path_str}"
        if kwargs.get('must_be_dir') and not os.path.isdir(path_str):
             return False, f"Path is not a directory: {path_str}"
        return True, "Path is valid (fallback check)"

    # Dummy save function
    def save_analysis_report(data: Dict[str, Any], output_path: str, format: str = "json") -> bool:
        try:
            with open(output_path, 'w') as f:
                if format == 'json':
                    json.dump(data, f, indent=4)
                else: # Basic text fallback
                    for key, value in data.items():
                        f.write(f"{key}: {value}\n")
            logger.info(f"Fallback report saved to {output_path}")
            return True
        except Exception as ex:
            logger.error(f"Fallback save failed: {ex}")
            return False

    # Dummy hash functions (will prevent actual operation)
    def calculate_hash(*args, **kwargs): logger.error("calculate_hash unavailable"); return None
    def calculate_multiple_hashes(*args, **kwargs): logger.error("calculate_multiple_hashes unavailable"); return {}
    def calculate_fuzzy_hash(*args, **kwargs): logger.error("calculate_fuzzy_hash unavailable"); return None
    def verify_hash(*args, **kwargs): logger.error("verify_hash unavailable"); return False
    def compare_fuzzy_hashes(*args, **kwargs): logger.error("compare_fuzzy_hashes unavailable"); return -1
    def check_hash_against_database(*args, **kwargs): logger.error("check_hash_against_database unavailable"); return {"match": False, "error": "unavailable"}
    def find_similar_files(*args, **kwargs): logger.error("find_similar_files unavailable"); return []


# Setup logger if core utils are available
if FORENSIC_CORE_AVAILABLE:
    setup_forensic_logger() # Assumes this configures the root logger or a specific one
    logger = logging.getLogger('forensic_hash_compare') # Use a specific logger name
else:
    # Use the fallback logger defined above
    pass

# --- Constants ---
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_OUTPUT_FORMATS = ["json", "text"]
DEFAULT_ALGORITHMS = "sha256"
DEFAULT_FUZZY_ALGORITHM = "ssdeep"
DEFAULT_SIMILARITY_THRESHOLD = 70 # Default for ssdeep, adjust if needed

# --- Argument Parser Setup ---

def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Hash Comparison Tool for Forensic Static Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Calculate multiple hashes for a file
  python hash_compare.py --file suspicious.exe --algorithms md5,sha1,sha256,ssdeep

  # Verify a file's SHA256 hash
  python hash_compare.py --file image.dd --verify <expected_sha256_hash> --verify-algorithm sha256

  # Check a file's hash against a known-bad database
  python hash_compare.py --file malware.dll --check-database /path/to/malware_hashes.json

  # Find similar files in a directory using ssdeep (default threshold)
  python hash_compare.py --directory /evidence/files --find-similar

  # Find similar files using tlsh with a specific threshold (lower score = more similar for tlsh)
  # Note: Threshold interpretation differs for tlsh vs ssdeep. This example uses ssdeep-like score.
  python hash_compare.py --directory /evidence/docs --find-similar --fuzzy-algorithm tlsh --similarity-threshold 85

  # Output results to a JSON file
  python hash_compare.py --file report.pdf --algorithms sha256,sha512 --output report_hashes.json
"""
    )

    # Input sources (either file or directory is required depending on mode)
    parser.add_argument('--file', help='Path to the file for hashing or verification.')
    parser.add_argument('--directory', help='Path to the directory for finding similar files.')

    # Modes of operation
    parser.add_argument('--algorithms',
                        help='Comma-separated list of hash algorithms to calculate (e.g., md5,sha256,ssdeep,tlsh).')
    parser.add_argument('--verify', help='Expected hash value for integrity verification.')
    parser.add_argument('--verify-algorithm', default='sha256',
                        help='Algorithm used for the expected hash (default: sha256).')
    parser.add_argument('--check-database', help='Path to a hash database file (JSON format) to check against.')
    parser.add_argument('--find-similar', action='store_true', help='Find similar files in the specified directory using fuzzy hashing.')

    # Options for directory operations
    parser.add_argument('--recursive', action='store_true', default=True, help='Recursively search directory (default: True).')
    parser.add_argument('--no-recursive', action='store_false', dest='recursive', help='Disable recursive directory search.')
    parser.add_argument('--pattern', default='*', help='File pattern to match within directory (default: *).')

    # Options for fuzzy hashing and similarity
    parser.add_argument('--fuzzy-algorithm', default=DEFAULT_FUZZY_ALGORITHM, choices=['ssdeep', 'tlsh'],
                        help=f'Fuzzy hash algorithm to use (default: {DEFAULT_FUZZY_ALGORITHM}).')
    parser.add_argument('--similarity-threshold', type=int, default=DEFAULT_SIMILARITY_THRESHOLD,
                        help=f'Similarity threshold (0-100) for finding similar files (default: {DEFAULT_SIMILARITY_THRESHOLD}). Interpretation depends on algorithm.')

    # Output options
    parser.add_argument('--output', help='Path to save the analysis report (default: stdout).')
    parser.add_argument('--output-format', choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                        help=f'Format for the output report (default: {DEFAULT_OUTPUT_FORMAT}).')

    # Forensic context
    parser.add_argument('--case-id', help='Case ID for forensic logging.')
    parser.add_argument('--analyst', help='Analyst name for forensic logging.')

    # Verbosity
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging.')

    return parser

# --- Core Logic ---

def run_analysis(args: argparse.Namespace) -> Dict[str, Any]:
    """Orchestrates the hash analysis based on provided arguments."""
    results: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "parameters": vars(args),
        "analysis_results": {}
    }
    operation_details = {
        "tool": "hash_compare",
        "case_id": args.case_id,
        "analyst": args.analyst,
        **vars(args) # Include args in details, be mindful of sensitive info if any
    }

    if not HASH_UTILS_AVAILABLE:
        results["error"] = "Hash utilities are not available. Cannot perform analysis."
        log_forensic_operation("hash_analysis_error", False, {**operation_details, "error": results["error"]}, level=logging.CRITICAL)
        return results

    # --- Mode 1: Calculate Hashes for a File ---
    if args.file and args.algorithms:
        is_valid, msg = validate_path(args.file, must_be_file=True, check_read=True)
        if not is_valid:
            results["error"] = f"Invalid input file: {msg}"
            log_forensic_operation("calculate_hashes", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        algorithms_list = [alg.strip().lower() for alg in args.algorithms.split(',')]
        logger.info(f"Calculating hashes ({', '.join(algorithms_list)}) for file: {args.file}")
        hashes = calculate_multiple_hashes(args.file, algorithms=algorithms_list)
        results["analysis_results"]["calculated_hashes"] = hashes
        if not all(hashes.values()): # Check if any hash calculation failed
             log_forensic_operation("calculate_hashes", False, {**operation_details, "error": "One or more hash calculations failed"}, level=logging.WARNING)
        else:
             log_forensic_operation("calculate_hashes", True, operation_details)


    # --- Mode 2: Verify File Integrity ---
    elif args.file and args.verify:
        is_valid, msg = validate_path(args.file, must_be_file=True, check_read=True)
        if not is_valid:
            results["error"] = f"Invalid input file: {msg}"
            log_forensic_operation("verify_hash", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        logger.info(f"Verifying {args.verify_algorithm} hash for file: {args.file}")
        is_match = verify_hash(args.file, args.verify, algorithm=args.verify_algorithm)
        results["analysis_results"]["verification"] = {
            "file": args.file,
            "expected_hash": args.verify,
            "algorithm": args.verify_algorithm,
            "match": is_match
        }
        # Note: verify_hash logs its own forensic operation internally

    # --- Mode 3: Check Hash Against Database ---
    elif args.file and args.check_database:
        is_valid_file, msg_file = validate_path(args.file, must_be_file=True, check_read=True)
        is_valid_db, msg_db = validate_path(args.check_database, must_be_file=True, check_read=True)
        if not is_valid_file:
            results["error"] = f"Invalid input file: {msg_file}"
            log_forensic_operation("check_hash_database", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results
        if not is_valid_db:
            results["error"] = f"Invalid database file: {msg_db}"
            log_forensic_operation("check_hash_database", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        logger.info(f"Checking hash for file {args.file} against database: {args.check_database}")
        db_check_result = check_hash_against_database(args.file, args.check_database)
        results["analysis_results"]["database_check"] = db_check_result
        # Note: check_hash_against_database logs its own forensic operation internally

    # --- Mode 4: Find Similar Files ---
    elif args.directory and args.find_similar:
        is_valid, msg = validate_path(args.directory, must_be_dir=True, check_read=True)
        if not is_valid:
            results["error"] = f"Invalid input directory: {msg}"
            log_forensic_operation("find_similar_files", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        # Check availability of the chosen fuzzy algorithm
        if args.fuzzy_algorithm == "ssdeep" and not SSDEEP_AVAILABLE:
             results["error"] = "ssdeep library is not available for finding similar files."
             log_forensic_operation("find_similar_files", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
             return results
        if args.fuzzy_algorithm == "tlsh" and not TLSH_AVAILABLE:
             results["error"] = "tlsh library is not available for finding similar files."
             log_forensic_operation("find_similar_files", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
             return results

        logger.info(f"Finding similar files in directory: {args.directory} using {args.fuzzy_algorithm} (threshold: {args.similarity_threshold}%)")
        similar_files = find_similar_files(
            directory_path=args.directory,
            threshold=args.similarity_threshold,
            algorithm=args.fuzzy_algorithm,
            recursive=args.recursive,
            pattern=args.pattern
        )
        results["analysis_results"]["similar_files"] = similar_files
        results["analysis_results"]["similarity_parameters"] = {
            "directory": args.directory,
            "algorithm": args.fuzzy_algorithm,
            "threshold": args.similarity_threshold,
            "recursive": args.recursive,
            "pattern": args.pattern,
            "pairs_found": len(similar_files)
        }
        # Note: find_similar_files logs its own forensic operation internally

    else:
        results["error"] = "Invalid combination of arguments. Please specify a valid mode (e.g., --file with --algorithms, --file with --verify, --file with --check-database, or --directory with --find-similar)."
        logger.error(results["error"])
        log_forensic_operation("invalid_arguments", False, operation_details, level=logging.ERROR)


    return results

# --- Output Formatting ---

def format_results_text(results: Dict[str, Any]) -> str:
    """Format analysis results as a human-readable text string."""
    output_lines = ["=== Hash Comparison Report ==="]
    output_lines.append(f"Timestamp: {results.get('timestamp', 'N/A')}")

    if "error" in results:
        output_lines.append(f"\nERROR: {results['error']}")
        return "\n".join(output_lines)

    analysis = results.get("analysis_results", {})

    if "calculated_hashes" in analysis:
        output_lines.append("\n--- Calculated Hashes ---")
        output_lines.append(f"File: {results.get('parameters', {}).get('file', 'N/A')}")
        for alg, hash_val in analysis["calculated_hashes"].items():
            output_lines.append(f"  {alg.upper()}: {hash_val or 'Error calculating'}")

    if "verification" in analysis:
        output_lines.append("\n--- Hash Verification ---")
        ver = analysis["verification"]
        output_lines.append(f"File: {ver.get('file', 'N/A')}")
        output_lines.append(f"Algorithm: {ver.get('algorithm', 'N/A').upper()}")
        output_lines.append(f"Expected Hash: {ver.get('expected_hash', 'N/A')}")
        output_lines.append(f"Match: {'YES' if ver.get('match') else 'NO'}")

    if "database_check" in analysis:
        output_lines.append("\n--- Hash Database Check ---")
        chk = analysis["database_check"]
        output_lines.append(f"File: {results.get('parameters', {}).get('file', 'N/A')}")
        output_lines.append(f"Database: {results.get('parameters', {}).get('check_database', 'N/A')}")
        output_lines.append(f"Algorithm Used: {chk.get('algorithm', 'N/A').upper()}")
        output_lines.append(f"File Hash: {chk.get('hash', 'N/A')}")
        if chk.get('match'):
            output_lines.append(f"Match Found: YES (Matches entry: {chk.get('matched_path', 'N/A')})")
        else:
            output_lines.append("Match Found: NO")
        if chk.get('error'):
            output_lines.append(f"Error during check: {chk['error']}")

    if "similar_files" in analysis:
        output_lines.append("\n--- Similar File Analysis ---")
        params = analysis.get("similarity_parameters", {})
        output_lines.append(f"Directory: {params.get('directory', 'N/A')}")
        output_lines.append(f"Algorithm: {params.get('algorithm', 'N/A')}")
        output_lines.append(f"Threshold: {params.get('threshold', 'N/A')}%")
        output_lines.append(f"Pairs Found: {params.get('pairs_found', 0)}")
        if analysis["similar_files"]:
            output_lines.append("\nSimilar File Pairs:")
            for pair in analysis["similar_files"][:20]: # Limit output
                output_lines.append(f"  - Similarity: {pair['similarity']}%")
                output_lines.append(f"    File 1: {pair['file1']}")
                output_lines.append(f"    File 2: {pair['file2']}")
        else:
             output_lines.append("  No similar file pairs found above the threshold.")


    return "\n".join(output_lines)

# --- Main Execution ---

def main() -> int:
    """Main function to parse arguments and run hash comparison."""
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Basic argument validation
    if not args.file and not args.directory:
         logger.error("Either --file or --directory must be specified.")
         parser.print_help()
         return 1
    if args.file and args.directory:
         logger.error("--file and --directory cannot be used together.")
         parser.print_help()
         return 1
    if args.find_similar and not args.directory:
         logger.error("--find-similar requires --directory to be specified.")
         parser.print_help()
         return 1
    if not args.algorithms and not args.verify and not args.check_database and not args.find_similar:
         logger.error("No operation specified. Use --algorithms, --verify, --check-database, or --find-similar.")
         parser.print_help()
         return 1


    try:
        analysis_results = run_analysis(args)

        # Save or print results
        if args.output:
            logger.info(f"Saving results to {args.output} in {args.output_format} format.")
            # Use common save function if available
            saved = save_analysis_report(analysis_results, args.output, format=args.output_format)
            if not saved:
                logger.error(f"Failed to save report to {args.output}. Printing to stdout instead.")
                # Fallback to printing
                if args.output_format == 'json':
                    print(json.dumps(analysis_results, indent=4))
                else:
                    print(format_results_text(analysis_results))
        else:
            # Print to stdout
            if args.output_format == 'json':
                print(json.dumps(analysis_results, indent=4))
            else:
                print(format_results_text(analysis_results))

        # Return non-zero exit code if errors occurred during analysis
        if "error" in analysis_results or any(v == "Error calculating" for v in analysis_results.get("analysis_results", {}).get("calculated_hashes", {}).values()):
            return 1
        # Optionally return specific code for matches found
        # elif analysis_results.get("analysis_results", {}).get("database_check", {}).get("match"):
        #     return 2 # Example: Exit code 2 if hash found in DB

        return 0

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=args.verbose)
        if FORENSIC_CORE_AVAILABLE:
             log_forensic_operation("hash_compare_unexpected_error", False, {"error": str(e)}, level=logging.CRITICAL)
        return 1

if __name__ == "__main__":
    sys.exit(main())
