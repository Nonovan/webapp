"""
Hash Comparison Tool for Forensic Static Analysis

This tool calculates, compares, and verifies cryptographic and fuzzy hashes
as part of the static analysis process within the Cloud Infrastructure Platform's
Forensic Analysis Toolkit. It helps identify known malicious files, find similar
files, and verify file integrity.

Features:
- Multi-algorithm hash calculation (MD5, SHA-1, SHA-256, etc.)
- File hash verification for integrity checking
- Hash database comparison for malware identification
- Fuzzy hash comparison for similar file detection
- Support for ssdeep and tlsh fuzzy hashing algorithms
- Comprehensive logging and reporting
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple, Union, Callable

# Add parent directory to path for module imports
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
    from admin.security.forensics.utils.validation_utils import (
        validate_path,
        validate_hash_format
    )

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

    # Dummy validation functions
    def validate_path(path_str: str, **kwargs) -> tuple[bool, str]:
        if not os.path.exists(path_str):
            return False, f"Path does not exist: {path_str}"
        # Basic check, might need refinement based on kwargs
        if kwargs.get('must_be_file') and not os.path.isfile(path_str):
             return False, f"Path is not a file: {path_str}"
        if kwargs.get('must_be_dir') and not os.path.isdir(path_str):
             return False, f"Path is not a directory: {path_str}"
        return True, "Path is valid (fallback check)"

    def validate_hash_format(hash_str: str, algorithm: Optional[str] = None) -> Tuple[bool, str]:
        """Basic hash format validation (fallback)"""
        if not hash_str or not isinstance(hash_str, str):
            return False, "Invalid hash: empty or wrong type"

        if algorithm == "md5" and len(hash_str) == 32:
            return True, "Valid MD5 hash format"
        elif algorithm == "sha1" and len(hash_str) == 40:
            return True, "Valid SHA1 hash format"
        elif algorithm == "sha256" and len(hash_str) == 64:
            return True, "Valid SHA256 hash format"
        elif algorithm == "sha512" and len(hash_str) == 128:
            return True, "Valid SHA512 hash format"
        elif algorithm is None:
            # Basic check - just verify it looks like a hex string
            if all(c in "0123456789abcdefABCDEF" for c in hash_str):
                return True, "Hash has valid hex format"

        return False, "Invalid hash format"

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
    setup_forensic_logger()
    logger = logging.getLogger('forensic_hash_compare')
else:
    # Use the fallback logger defined above
    pass

# --- Constants ---
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_OUTPUT_FORMATS = ["json", "text", "csv"]
DEFAULT_ALGORITHMS = "sha256"
DEFAULT_FUZZY_ALGORITHM = "ssdeep"
DEFAULT_SIMILARITY_THRESHOLD = 70  # Default for ssdeep, adjust if needed
DEFAULT_BATCH_SIZE = 100  # Number of files to process in a batch for memory management
MAX_REPORT_SIZE = 100 * 1024 * 1024  # Maximum report size (100MB)
DANGEROUS_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1', '.vbs'}
SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha384", "sha512", "blake2b", "blake2s", "ssdeep", "tlsh"]
WEAK_HASH_ALGORITHMS = ["md5", "sha1"]

# --- Argument Parser Setup ---

def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command-line argument parser.

    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
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

  # Create a hash database from a directory of files
  python hash_compare.py --directory /evidence/files --create-database --db-output evidence_hashes.json

  # Compare two files using both cryptographic and fuzzy hashing
  python hash_compare.py --compare file1.bin file2.bin --algorithms sha256,ssdeep

  # Batch calculate hashes for all files in a directory
  python hash_compare.py --directory /evidence/files --batch-hashing --output directory_hashes.json
"""
    )

    # Input sources (either file or directory is required depending on mode)
    parser.add_argument('--file', help='Path to the file for hashing or verification.')
    parser.add_argument('--directory', help='Path to the directory for finding similar files or batch operations.')

    # Modes of operation
    parser.add_argument('--algorithms',
                        help='Comma-separated list of hash algorithms to calculate (e.g., md5,sha256,ssdeep,tlsh).')
    parser.add_argument('--verify', help='Expected hash value for integrity verification.')
    parser.add_argument('--verify-algorithm', default='sha256',
                        help='Algorithm used for the expected hash (default: sha256).')
    parser.add_argument('--check-database', help='Path to a hash database file (JSON format) to check against.')
    parser.add_argument('--find-similar', action='store_true',
                        help='Find similar files in the specified directory using fuzzy hashing.')
    parser.add_argument('--create-database', action='store_true',
                        help='Create a hash database from files in the specified directory.')
    parser.add_argument('--db-output', help='Output path for database creation mode.')
    parser.add_argument('--batch-hashing', action='store_true',
                        help='Calculate hashes for all files in a directory.')
    parser.add_argument('--compare', nargs=2, metavar=('FILE1', 'FILE2'),
                        help='Compare two files using specified hash algorithms.')

    # Options for directory operations
    parser.add_argument('--recursive', action='store_true', default=True,
                        help='Recursively search directory (default: True).')
    parser.add_argument('--no-recursive', action='store_false', dest='recursive',
                        help='Disable recursive directory search.')
    parser.add_argument('--pattern', default='*',
                        help='File pattern to match within directory (default: *).')
    parser.add_argument('--exclude', help='Pattern of files to exclude from processing.')
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE,
                        help=f'Number of files to process in a batch (default: {DEFAULT_BATCH_SIZE}).')
    parser.add_argument('--max-size', type=int, help='Maximum file size in MB to process.')

    # Options for fuzzy hashing and similarity
    parser.add_argument('--fuzzy-algorithm', default=DEFAULT_FUZZY_ALGORITHM, choices=['ssdeep', 'tlsh'],
                        help=f'Fuzzy hash algorithm to use (default: {DEFAULT_FUZZY_ALGORITHM}).')
    parser.add_argument('--similarity-threshold', type=int, default=DEFAULT_SIMILARITY_THRESHOLD,
                        help=f'Similarity threshold (0-100) for finding similar files (default: {DEFAULT_SIMILARITY_THRESHOLD}).')

    # Output options
    parser.add_argument('--output', help='Path to save the analysis report (default: stdout).')
    parser.add_argument('--output-format', choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                        help=f'Format for the output report (default: {DEFAULT_OUTPUT_FORMAT}).')
    parser.add_argument('--show-weak-hash-warning', action='store_true',
                        help='Show warnings when using weak hash algorithms (MD5, SHA1).')

    # Filtering options
    parser.add_argument('--known-good', help='Path to known-good hash database to filter out known files.')
    parser.add_argument('--skip-files-larger-than', type=int,
                        help='Skip files larger than specified size in MB.')
    parser.add_argument('--only-dangerous-extensions', action='store_true',
                        help='Only process files with potentially dangerous extensions.')

    # Forensic context
    parser.add_argument('--case-id', help='Case ID for forensic logging.')
    parser.add_argument('--analyst', help='Analyst name for forensic logging.')
    parser.add_argument('--evidence-id', help='Evidence ID for forensic logging.')

    # Advanced options
    parser.add_argument('--secure-delete-report', action='store_true',
                        help='Securely delete the report file after displaying its contents.')
    parser.add_argument('--hash-verification-db', help='Path to hash verification database with trusted file hashes.')
    parser.add_argument('--read-only', action='store_true', default=True,
                        help='Access input files in read-only mode (default: True).')
    parser.add_argument('--fail-on-weak-hashes', action='store_true',
                        help='Exit with error if weak hash algorithms are specified.')

    # Verbosity
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help='Increase verbosity. Can be used multiple times (e.g., -vv).')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress non-essential output and warnings.')

    return parser


# --- Helper Functions ---

def get_file_list(directory_path: str, recursive: bool = True, pattern: str = "*",
                 exclude_pattern: Optional[str] = None, max_size_mb: Optional[int] = None,
                 only_dangerous: bool = False) -> List[str]:
    """
    Get list of files from a directory matching specified criteria.

    Args:
        directory_path: Path to directory to scan
        recursive: Whether to search recursively
        pattern: File pattern to match
        exclude_pattern: Pattern of files to exclude
        max_size_mb: Maximum file size in MB
        only_dangerous: Only include files with potentially dangerous extensions

    Returns:
        List of file paths meeting criteria
    """
    import fnmatch

    files_to_process = []
    directory_path = os.path.abspath(directory_path)
    max_bytes = max_size_mb * 1024 * 1024 if max_size_mb else None

    try:
        if recursive:
            for root, _, files in os.walk(directory_path):
                for filename in files:
                    file_path = os.path.join(root, filename)

                    # Skip if doesn't match pattern
                    if not fnmatch.fnmatch(filename, pattern):
                        continue

                    # Skip if matches exclude pattern
                    if exclude_pattern and fnmatch.fnmatch(filename, exclude_pattern):
                        continue

                    # Skip if too large
                    if max_bytes and os.path.getsize(file_path) > max_bytes:
                        continue

                    # Skip if not a dangerous extension when filtering
                    if only_dangerous:
                        ext = os.path.splitext(filename)[1].lower()
                        if ext not in DANGEROUS_EXTENSIONS:
                            continue

                    files_to_process.append(file_path)
        else:
            for entry in os.listdir(directory_path):
                file_path = os.path.join(directory_path, entry)
                if not os.path.isfile(file_path):
                    continue

                # Apply same filters as above
                if not fnmatch.fnmatch(entry, pattern):
                    continue
                if exclude_pattern and fnmatch.fnmatch(entry, exclude_pattern):
                    continue
                if max_bytes and os.path.getsize(file_path) > max_bytes:
                    continue
                if only_dangerous:
                    ext = os.path.splitext(entry)[1].lower()
                    if ext not in DANGEROUS_EXTENSIONS:
                        continue

                files_to_process.append(file_path)

        # Sort for deterministic behavior
        files_to_process.sort()
        return files_to_process

    except (OSError, PermissionError) as e:
        logger.error(f"Error scanning directory {directory_path}: {e}")
        return []


def process_file_batches(file_list: List[str], batch_size: int,
                        process_func: Callable[[str, Any], Any], **kwargs) -> Dict[str, Any]:
    """
    Process a large list of files in batches to manage memory usage.

    Args:
        file_list: List of file paths to process
        batch_size: Number of files to process in each batch
        process_func: Function to call for each file
        **kwargs: Additional arguments to pass to process_func

    Returns:
        Combined results from all batches
    """
    results = {}
    total_files = len(file_list)

    for i in range(0, total_files, batch_size):
        batch = file_list[i:i + batch_size]
        logger.info(f"Processing batch {i // batch_size + 1}/{(total_files + batch_size - 1) // batch_size} "
                   f"({len(batch)} files)")

        batch_start = time.time()
        batch_results = {}

        for file_path in batch:
            try:
                result = process_func(file_path, **kwargs)
                if result:  # Only store if we got a result
                    batch_results[file_path] = result
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
                batch_results[file_path] = {"error": str(e)}

        # Merge batch results into overall results
        results.update(batch_results)

        batch_duration = time.time() - batch_start
        logger.info(f"Batch processed in {batch_duration:.2f} seconds "
                   f"({len(batch)/batch_duration:.2f} files/sec)")

    return results


def validate_input_hash(hash_value: str, algorithm: str) -> Tuple[bool, str]:
    """
    Validate that a provided hash has the correct format for its algorithm.

    Args:
        hash_value: Hash value to validate
        algorithm: Hash algorithm name

    Returns:
        Tuple of (is_valid, message)
    """
    is_valid, msg = validate_hash_format(hash_value, algorithm)

    if not is_valid:
        logger.error(f"Invalid hash format for {algorithm}: {msg}")
        return False, msg

    # Check for algorithm-specific requirements
    if algorithm.lower() == 'ssdeep' and ':' not in hash_value:
        return False, "Invalid ssdeep hash format: missing block size and separator"

    return True, msg


def check_algorithm_availability(algorithms: List[str]) -> Tuple[bool, List[str], List[str]]:
    """
    Check if all specified hash algorithms are available.

    Args:
        algorithms: List of algorithm names to check

    Returns:
        Tuple of (all_available, available_list, unavailable_list)
    """
    available = []
    unavailable = []

    for algorithm in algorithms:
        algorithm = algorithm.lower()

        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            unavailable.append(algorithm)
            continue

        if algorithm == 'ssdeep' and not SSDEEP_AVAILABLE:
            unavailable.append(algorithm)
        elif algorithm == 'tlsh' and not TLSH_AVAILABLE:
            unavailable.append(algorithm)
        else:
            available.append(algorithm)

    return len(unavailable) == 0, available, unavailable


def check_weak_hash_usage(algorithms: List[str], show_warning: bool = True,
                         fail_on_weak: bool = False) -> Tuple[bool, List[str]]:
    """
    Check if any weak hash algorithms are being used and handle accordingly.

    Args:
        algorithms: List of algorithm names to check
        show_warning: Whether to display warnings for weak algorithms
        fail_on_weak: Whether to treat weak algorithms as errors

    Returns:
        Tuple of (proceed_with_operation, weak_algorithms_list)
    """
    weak_algorithms = [alg for alg in algorithms if alg.lower() in WEAK_HASH_ALGORITHMS]

    if weak_algorithms:
        message = (f"Weak hash algorithm(s) specified: {', '.join(weak_algorithms)}. "
                  "These are not suitable for security-critical applications.")

        if show_warning:
            if fail_on_weak:
                logger.error(message + " Aborting due to --fail-on-weak-hashes flag.")
                return False, weak_algorithms
            else:
                logger.warning(message)

    return True, weak_algorithms


# --- Core Analysis Functions ---

def calculate_file_hashes(file_path: str, algorithms: List[str]) -> Dict[str, str]:
    """
    Calculate multiple hashes for a single file.

    Args:
        file_path: Path to the file
        algorithms: List of hash algorithms to use

    Returns:
        Dictionary mapping algorithm names to hash values
    """
    # First check that all algorithms are available
    all_available, available_algs, unavailable_algs = check_algorithm_availability(algorithms)

    if unavailable_algs:
        for alg in unavailable_algs:
            logger.warning(f"Hash algorithm {alg} is not available and will be skipped")

    if not available_algs:
        logger.error("No available hash algorithms were specified")
        return {}

    # Calculate hashes for available algorithms
    try:
        result = calculate_multiple_hashes(file_path, algorithms=available_algs)

        # Add unavailable algorithms as None or error indicator
        for alg in unavailable_algs:
            result[alg] = None

        return result

    except Exception as e:
        logger.error(f"Error calculating hashes for {file_path}: {e}")
        return {alg: None for alg in algorithms}


def compare_two_files(file1: str, file2: str, algorithms: List[str]) -> Dict[str, Any]:
    """
    Compare two files using both cryptographic and fuzzy hashes.

    Args:
        file1: Path to first file
        file2: Path to second file
        algorithms: List of hash algorithms to use

    Returns:
        Dictionary with comparison results
    """
    result = {
        "file1": file1,
        "file2": file2,
        "file1_size": os.path.getsize(file1),
        "file2_size": os.path.getsize(file2),
        "size_match": os.path.getsize(file1) == os.path.getsize(file2),
        "hashes": {},
        "match_results": {},
        "fuzzy_similarity": None
    }

    # Calculate hashes for both files
    hashes1 = calculate_file_hashes(file1, algorithms)
    hashes2 = calculate_file_hashes(file2, algorithms)

    # Store hashes
    result["hashes"] = {
        "file1": hashes1,
        "file2": hashes2
    }

    # Compare each hash
    for alg in algorithms:
        hash1 = hashes1.get(alg)
        hash2 = hashes2.get(alg)

        # Skip if either hash is None/unavailable
        if hash1 is None or hash2 is None:
            result["match_results"][alg] = None
            continue

        # For regular hashes, simple equality check
        if alg != "ssdeep" and alg != "tlsh":
            result["match_results"][alg] = (hash1 == hash2)
        else:
            # For fuzzy hashes, calculate similarity
            try:
                similarity = compare_fuzzy_hashes(hash1, hash2, algorithm=alg)

                # Only keep the highest fuzzy similarity if multiple fuzzy algorithms used
                if result["fuzzy_similarity"] is None or similarity > result["fuzzy_similarity"]:
                    result["fuzzy_similarity"] = similarity

                result["match_results"][alg] = similarity
            except Exception as e:
                logger.error(f"Error comparing fuzzy hashes: {e}")
                result["match_results"][alg] = None

    return result


def create_hash_database_from_directory(directory: str, output_file: str,
                                      algorithms: List[str], args: argparse.Namespace) -> Dict[str, Any]:
    """
    Create a hash database from all files in a directory.

    Args:
        directory: Source directory containing files
        output_file: Path to save the database
        algorithms: Hash algorithms to use
        args: Command-line arguments

    Returns:
        Dictionary with operation results
    """
    result = {
        "operation": "create_hash_database",
        "source_directory": directory,
        "output_file": output_file,
        "algorithms": algorithms,
        "start_time": datetime.now().isoformat(),
        "files_processed": 0,
        "files_hashed": 0,
        "files_skipped": 0,
        "errors": []
    }

    # Get list of files to process
    files = get_file_list(
        directory,
        recursive=args.recursive,
        pattern=args.pattern,
        exclude_pattern=args.exclude,
        max_size_mb=args.skip_files_larger_than,
        only_dangerous=args.only_dangerous_extensions
    )

    if not files:
        error_msg = f"No files found matching criteria in {directory}"
        logger.warning(error_msg)
        result["errors"].append(error_msg)
        return result

    # Initialize database structure
    database = {
        "metadata": {
            "created": datetime.now().isoformat(),
            "algorithms": algorithms,
            "source": directory,
            "file_count": len(files),
            "creator": args.analyst if args.analyst else "unknown"
        },
        "hashes": {}
    }

    # Process files in batches
    result["files_processed"] = len(files)

    def hash_file(file_path: str, algs: List[str]) -> Dict[str, str]:
        return calculate_file_hashes(file_path, algs)

    # Process in batches to manage memory usage with large directories
    all_hashes = process_file_batches(
        files,
        args.batch_size,
        hash_file,
        algs=algorithms
    )

    # Count successful hashes and errors
    for file_path, hash_result in all_hashes.items():
        if "error" in hash_result:
            result["files_skipped"] += 1
            result["errors"].append(f"Error hashing {file_path}: {hash_result['error']}")
        else:
            # Store relative path in database to avoid leaking full paths
            rel_path = os.path.relpath(file_path, directory)
            database["hashes"][rel_path] = hash_result
            result["files_hashed"] += 1

    # Save database to file
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(database, f, indent=2)

        result["status"] = "success"
        result["message"] = f"Created hash database with {result['files_hashed']} files"
        logger.info(f"Hash database created successfully: {output_file}")

    except Exception as e:
        error_msg = f"Error saving hash database: {e}"
        logger.error(error_msg)
        result["status"] = "error"
        result["message"] = error_msg
        result["errors"].append(error_msg)

    result["end_time"] = datetime.now().isoformat()
    return result


def run_analysis(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Orchestrates the hash analysis based on provided arguments.

    Args:
        args: Command-line arguments

    Returns:
        Dictionary containing analysis results
    """
    results: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "command": " ".join(sys.argv),
        "parameters": vars(args),
        "analysis_results": {}
    }
    operation_details = {
        "tool": "hash_compare",
        "case_id": args.case_id,
        "analyst": args.analyst,
        "evidence_id": args.evidence_id
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

        # Check for weak hash algorithms
        proceed, weak_algs = check_weak_hash_usage(
            algorithms_list,
            show_warning=args.show_weak_hash_warning or args.verbose > 0,
            fail_on_weak=args.fail_on_weak_hashes
        )

        if not proceed:
            results["error"] = f"Weak hash algorithms specified: {', '.join(weak_algs)}. Use --show-weak-hash-warning to override."
            log_forensic_operation("calculate_hashes", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        logger.info(f"Calculating hashes ({', '.join(algorithms_list)}) for file: {args.file}")
        start_time = time.time()

        # Check file size if max size is specified
        if args.skip_files_larger_than:
            max_bytes = args.skip_files_larger_than * 1024 * 1024
            file_size = os.path.getsize(args.file)
            if file_size > max_bytes:
                results["error"] = f"File exceeds maximum size: {file_size} bytes > {max_bytes} bytes"
                log_forensic_operation("calculate_hashes", False, {**operation_details, "error": results["error"], "file_size": file_size, "max_size": max_bytes}, level=logging.WARNING)
                return results

        # Calculate hashes
        hashes = calculate_multiple_hashes(args.file, algorithms=algorithms_list)
        end_time = time.time()

        # Add results
        results["analysis_results"]["calculated_hashes"] = hashes
        results["analysis_results"]["file_info"] = {
            "path": args.file,
            "size_bytes": os.path.getsize(args.file),
            "processing_time_seconds": round(end_time - start_time, 3)
        }

        # Log operation result
        if not all(hashes.values()): # Check if any hash calculation failed
            failed_algs = [alg for alg, value in hashes.items() if value is None]
            log_forensic_operation(
                "calculate_hashes",
                False,
                {**operation_details, "error": f"Failed to calculate: {', '.join(failed_algs)}"},
                level=logging.WARNING
            )
        else:
            log_forensic_operation(
                "calculate_hashes",
                True,
                {**operation_details, "algorithms": algorithms_list, "duration": round(end_time - start_time, 3)}
            )

    # --- Mode 2: Verify File Integrity ---
    elif args.file and args.verify:
        is_valid, msg = validate_path(args.file, must_be_file=True, check_read=True)
        if not is_valid:
            results["error"] = f"Invalid input file: {msg}"
            log_forensic_operation("verify_hash", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        # Validate hash format
        hash_is_valid, validation_msg = validate_input_hash(args.verify, args.verify_algorithm)
        if not hash_is_valid:
            results["error"] = f"Invalid hash format: {validation_msg}"
            log_forensic_operation("verify_hash", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        # Check if it's a weak hash
        proceed, _ = check_weak_hash_usage(
            [args.verify_algorithm],
            show_warning=args.show_weak_hash_warning or args.verbose > 0,
            fail_on_weak=args.fail_on_weak_hashes
        )

        if not proceed:
            results["error"] = f"Weak hash algorithm specified: {args.verify_algorithm}"
            log_forensic_operation("verify_hash", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        logger.info(f"Verifying {args.verify_algorithm} hash for file: {args.file}")
        start_time = time.time()
        is_match = verify_hash(args.file, args.verify, algorithm=args.verify_algorithm)
        end_time = time.time()

        results["analysis_results"]["verification"] = {
            "file": args.file,
            "expected_hash": args.verify,
            "algorithm": args.verify_algorithm,
            "match": is_match,
            "verification_time_seconds": round(end_time - start_time, 3)
        }

        # verify_hash logs its own forensic operation internally, but we'll log higher-level result
        log_forensic_operation(
            "hash_verification_complete",
            is_match,
            {**operation_details, "algorithm": args.verify_algorithm, "match": is_match},
            level=logging.INFO if is_match else logging.WARNING
        )

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
        start_time = time.time()
        db_check_result = check_hash_against_database(args.file, args.check_database)
        end_time = time.time()

        # Add timing information
        db_check_result["check_time_seconds"] = round(end_time - start_time, 3)
        results["analysis_results"]["database_check"] = db_check_result

        # check_hash_against_database logs its own forensic operation internally

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

        # Get list of files to process, using all filtering options
        files = get_file_list(
            args.directory,
            recursive=args.recursive,
            pattern=args.pattern,
            exclude_pattern=args.exclude,
            max_size_mb=args.skip_files_larger_than,
            only_dangerous=args.only_dangerous_extensions
        )

        if not files:
            results["error"] = "No files found matching the criteria."
            log_forensic_operation("find_similar_files", False, {**operation_details, "error": results["error"]}, level=logging.WARNING)
            return results

        logger.info(f"Finding similar files in directory: {args.directory} ({len(files)} files) using {args.fuzzy_algorithm} (threshold: {args.similarity_threshold}%)")
        start_time = time.time()
        similar_files = find_similar_files(
            directory_path=args.directory,
            threshold=args.similarity_threshold,
            algorithm=args.fuzzy_algorithm,
            recursive=args.recursive,
            pattern=args.pattern
        )
        end_time = time.time()

        # Add timing information
        results["analysis_results"]["similar_files"] = similar_files
        results["analysis_results"]["similarity_parameters"] = {
            "directory": args.directory,
            "algorithm": args.fuzzy_algorithm,
            "threshold": args.similarity_threshold,
            "recursive": args.recursive,
            "pattern": args.pattern,
            "files_analyzed": len(files),
            "pairs_found": len(similar_files),
            "analysis_time_seconds": round(end_time - start_time, 3)
        }

        # find_similar_files logs its own forensic operation internally

    # --- Mode 5: Create Hash Database ---
    elif args.directory and args.create_database:
        is_valid, msg = validate_path(args.directory, must_be_dir=True, check_read=True)
        if not is_valid:
            results["error"] = f"Invalid input directory: {msg}"
            log_forensic_operation("create_hash_database", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        if not args.db_output:
            results["error"] = "Missing --db-output parameter required for database creation."
            log_forensic_operation("create_hash_database", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        # Use default algorithm if not specified
        algorithms_list = [alg.strip().lower() for alg in args.algorithms.split(',')] if args.algorithms else ["sha256"]

        # Check for weak hash algorithms
        proceed, weak_algs = check_weak_hash_usage(
            algorithms_list,
            show_warning=args.show_weak_hash_warning or args.verbose > 0,
            fail_on_weak=args.fail_on_weak_hashes
        )

        if not proceed:
            results["error"] = f"Weak hash algorithms specified: {', '.join(weak_algs)}. Use --show-weak-hash-warning to override."
            log_forensic_operation("create_hash_database", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        start_time = time.time()
        db_result = create_hash_database_from_directory(
            args.directory,
            args.db_output,
            algorithms_list,
            args
        )
        end_time = time.time()

        # Add timing information
        db_result["duration_seconds"] = round(end_time - start_time, 3)
        results["analysis_results"]["database_creation"] = db_result

        # Log the operation
        if db_result.get("status") == "success":
            log_forensic_operation(
                "create_hash_database",
                True,
                {
                    **operation_details,
                    "files_processed": db_result.get("files_processed", 0),
                    "files_hashed": db_result.get("files_hashed", 0),
                    "output_file": args.db_output
                }
            )
        else:
            log_forensic_operation(
                "create_hash_database",
                False,
                {**operation_details, "error": db_result.get("message", "Unknown error")},
                level=logging.ERROR
            )

    # --- Mode 6: Batch Hashing ---
    elif args.directory and args.batch_hashing:
        is_valid, msg = validate_path(args.directory, must_be_dir=True, check_read=True)
        if not is_valid:
            results["error"] = f"Invalid input directory: {msg}"
            log_forensic_operation("batch_hashing", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        # Use default algorithm if not specified
        algorithms_list = [alg.strip().lower() for alg in args.algorithms.split(',')] if args.algorithms else ["sha256"]

        # Check for weak hash algorithms
        proceed, weak_algs = check_weak_hash_usage(
            algorithms_list,
            show_warning=args.show_weak_hash_warning or args.verbose > 0,
            fail_on_weak=args.fail_on_weak_hashes
        )

        if not proceed:
            results["error"] = f"Weak hash algorithms specified: {', '.join(weak_algs)}. Use --show-weak-hash-warning to override."
            log_forensic_operation("batch_hashing", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        # Get list of files to process, using all filtering options
        files = get_file_list(
            args.directory,
            recursive=args.recursive,
            pattern=args.pattern,
            exclude_pattern=args.exclude,
            max_size_mb=args.skip_files_larger_than,
            only_dangerous=args.only_dangerous_extensions
        )

        if not files:
            results["error"] = "No files found matching the criteria."
            log_forensic_operation("batch_hashing", False, {**operation_details, "error": results["error"]}, level=logging.WARNING)
            return results

        logger.info(f"Batch hashing {len(files)} files using algorithms: {', '.join(algorithms_list)}")
        start_time = time.time()

        # Process files in batches to manage memory
        hash_results = process_file_batches(
            files,
            args.batch_size,
            calculate_file_hashes,
            algorithms=algorithms_list
        )

        end_time = time.time()

        # Count successful and failed hashing operations
        success_count = sum(1 for result in hash_results.values() if "error" not in result)
        error_count = len(hash_results) - success_count

        # Prepare result structure
        results["analysis_results"]["batch_hashing"] = {
            "directory": args.directory,
            "files_processed": len(files),
            "successful_hashes": success_count,
            "failed_hashes": error_count,
            "duration_seconds": round(end_time - start_time, 3),
            "algorithms": algorithms_list,
            "file_hashes": hash_results,
        }

        # Log the operation
        log_forensic_operation(
            "batch_hashing",
            error_count == 0,  # Success if no errors
            {
                **operation_details,
                "directory": args.directory,
                "files_processed": len(files),
                "successful": success_count,
                "failed": error_count,
                "algorithms": algorithms_list
            },
            level=logging.INFO if error_count == 0 else logging.WARNING
        )

    # --- Mode 7: Compare Two Files ---
    elif args.compare:
        file1, file2 = args.compare
        is_valid1, msg1 = validate_path(file1, must_be_file=True, check_read=True)
        is_valid2, msg2 = validate_path(file2, must_be_file=True, check_read=True)

        if not is_valid1:
            results["error"] = f"Invalid first file: {msg1}"
            log_forensic_operation("compare_files", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        if not is_valid2:
            results["error"] = f"Invalid second file: {msg2}"
            log_forensic_operation("compare_files", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        # Use default algorithm if not specified
        algorithms_list = [alg.strip().lower() for alg in args.algorithms.split(',')] if args.algorithms else ["sha256", "ssdeep"]

        # Check for weak hash algorithms
        proceed, weak_algs = check_weak_hash_usage(
            algorithms_list,
            show_warning=args.show_weak_hash_warning or args.verbose > 0,
            fail_on_weak=args.fail_on_weak_hashes
        )

        if not proceed:
            results["error"] = f"Weak hash algorithms specified: {', '.join(weak_algs)}. Use --show-weak-hash-warning to override."
            log_forensic_operation("compare_files", False, {**operation_details, "error": results["error"]}, level=logging.ERROR)
            return results

        logger.info(f"Comparing files {file1} and {file2} using algorithms: {', '.join(algorithms_list)}")
        start_time = time.time()
        comparison_result = compare_two_files(file1, file2, algorithms_list)
        end_time = time.time()

        # Add timing information
        comparison_result["duration_seconds"] = round(end_time - start_time, 3)
        results["analysis_results"]["file_comparison"] = comparison_result

        # Log the operation
        identical = all(match for alg, match in comparison_result["match_results"].items()
                       if alg not in ("ssdeep", "tlsh") and match is not None)

        similarity = comparison_result["fuzzy_similarity"] if comparison_result["fuzzy_similarity"] is not None else -1

        log_forensic_operation(
            "compare_files",
            True,  # Operation itself succeeded
            {
                **operation_details,
                "file1": os.path.basename(file1),
                "file2": os.path.basename(file2),
                "identical": identical,
                "fuzzy_similarity": similarity,
                "algorithms": algorithms_list
            }
        )
    else:
        results["error"] = "Invalid combination of arguments. Please specify a valid mode."
        logger.error(results["error"])
        log_forensic_operation("invalid_arguments", False, operation_details, level=logging.ERROR)

    return results


# --- Output Formatting ---

def format_results_text(results: Dict[str, Any]) -> str:
    """Format analysis results as a human-readable text string.

    Args:
        results: Analysis results dictionary

    Returns:
        Formatted text representation
    """
    output_lines = ["=== Hash Comparison Report ==="]
    output_lines.append(f"Timestamp: {results.get('timestamp', 'N/A')}")

    if "error" in results:
        output_lines.append(f"\nERROR: {results['error']}")
        return "\n".join(output_lines)

    analysis = results.get("analysis_results", {})

    # --- Mode 1: Calculate Hashes ---
    if "calculated_hashes" in analysis:
        output_lines.append("\n--- Calculated Hashes ---")
        file_info = analysis.get("file_info", {})
        output_lines.append(f"File: {file_info.get('path', 'N/A')}")
        output_lines.append(f"Size: {file_info.get('size_bytes', 0)} bytes")
        output_lines.append(f"Processing Time: {file_info.get('processing_time_seconds', 0)} seconds")
        output_lines.append("\nHashes:")
        for alg, hash_val in analysis["calculated_hashes"].items():
            output_lines.append(f"  {alg.upper()}: {hash_val or 'Error calculating'}")

    # --- Mode 2: Hash Verification ---
    if "verification" in analysis:
        output_lines.append("\n--- Hash Verification ---")
        ver = analysis["verification"]
        output_lines.append(f"File: {ver.get('file', 'N/A')}")
        output_lines.append(f"Algorithm: {ver.get('algorithm', 'N/A').upper()}")
        output_lines.append(f"Expected Hash: {ver.get('expected_hash', 'N/A')}")
        output_lines.append(f"Match: {'YES' if ver.get('match') else 'NO'}")
        output_lines.append(f"Verification Time: {ver.get('verification_time_seconds', 0)} seconds")

    # --- Mode 3: Hash Database Check ---
    if "database_check" in analysis:
        output_lines.append("\n--- Hash Database Check ---")
        chk = analysis["database_check"]
        output_lines.append(f"File: {results.get('parameters', {}).get('file', 'N/A')}")
        output_lines.append(f"Database: {results.get('parameters', {}).get('check_database', 'N/A')}")
        output_lines.append(f"Algorithm Used: {chk.get('algorithm', 'N/A').upper()}")
        output_lines.append(f"File Hash: {chk.get('hash', 'N/A')}")
        output_lines.append(f"Check Time: {chk.get('check_time_seconds', 0)} seconds")

        if chk.get('match'):
            output_lines.append(f"Match Found: YES (Matches entry: {chk.get('matched_path', 'N/A')})")
        else:
            output_lines.append("Match Found: NO")
        if chk.get('error'):
            output_lines.append(f"Error during check: {chk['error']}")

    # --- Mode 4: Similar Files ---
    if "similar_files" in analysis:
        output_lines.append("\n--- Similar File Analysis ---")
        params = analysis.get("similarity_parameters", {})
        output_lines.append(f"Directory: {params.get('directory', 'N/A')}")
        output_lines.append(f"Algorithm: {params.get('algorithm', 'N/A')}")
        output_lines.append(f"Threshold: {params.get('threshold', 'N/A')}%")
        output_lines.append(f"Files Analyzed: {params.get('files_analyzed', 0)}")
        output_lines.append(f"Pairs Found: {params.get('pairs_found', 0)}")
        output_lines.append(f"Analysis Time: {params.get('analysis_time_seconds', 0)} seconds")

        if analysis["similar_files"]:
            output_lines.append("\nSimilar File Pairs:")
            for pair in analysis["similar_files"][:20]:  # Limit output
                output_lines.append(f"  - Similarity: {pair['similarity']}%")
                output_lines.append(f"    File 1: {pair['file1']}")
                output_lines.append(f"    File 2: {pair['file2']}")

            if len(analysis["similar_files"]) > 20:
                output_lines.append(f"    ... and {len(analysis['similar_files']) - 20} more pairs")
        else:
             output_lines.append("  No similar file pairs found above the threshold.")

    # --- Mode 5: Hash Database Creation ---
    if "database_creation" in analysis:
        output_lines.append("\n--- Hash Database Creation ---")
        db = analysis["database_creation"]
        output_lines.append(f"Source Directory: {db.get('source_directory', 'N/A')}")
        output_lines.append(f"Output Database: {db.get('output_file', 'N/A')}")
        output_lines.append(f"Algorithms: {', '.join(db.get('algorithms', []))}")
        output_lines.append(f"Files Processed: {db.get('files_processed', 0)}")
        output_lines.append(f"Files Hashed: {db.get('files_hashed', 0)}")
        output_lines.append(f"Files Skipped: {db.get('files_skipped', 0)}")
        output_lines.append(f"Duration: {db.get('duration_seconds', 0)} seconds")

        if db.get('status') == "success":
            output_lines.append(f"Status: Success - {db.get('message', '')}")
        else:
            output_lines.append(f"Status: Error - {db.get('message', '')}")

        if db.get('errors'):
            output_lines.append("\nErrors:")
            for i, error in enumerate(db['errors'][:5]):  # Show first 5 errors
                output_lines.append(f"  {i+1}. {error}")
            if len(db['errors']) > 5:
                output_lines.append(f"  ... and {len(db['errors']) - 5} more errors")

    # --- Mode 6: Batch Hashing ---
    if "batch_hashing" in analysis:
        output_lines.append("\n--- Batch Hashing Results ---")
        batch = analysis["batch_hashing"]
        output_lines.append(f"Directory: {batch.get('directory', 'N/A')}")
        output_lines.append(f"Algorithms: {', '.join(batch.get('algorithms', []))}")
        output_lines.append(f"Files Processed: {batch.get('files_processed', 0)}")
        output_lines.append(f"Successful: {batch.get('successful_hashes', 0)}")
        output_lines.append(f"Failed: {batch.get('failed_hashes', 0)}")
        output_lines.append(f"Duration: {batch.get('duration_seconds', 0)} seconds")

        # Show sample of file hashes
        hashes = batch.get('file_hashes', {})
        if hashes:
            output_lines.append("\nSample File Hashes (first 5):")
            for i, (file_path, file_hashes) in enumerate(list(hashes.items())[:5]):
                output_lines.append(f"\n  {i+1}. {file_path}")
                if "error" in file_hashes:
                    output_lines.append(f"     Error: {file_hashes['error']}")
                else:
                    for alg, hash_val in file_hashes.items():
                        if hash_val:  # Only show successful hashes
                            output_lines.append(f"     {alg.upper()}: {hash_val}")

            if len(hashes) > 5:
                output_lines.append(f"\n  ... and {len(hashes) - 5} more files")

    # --- Mode 7: File Comparison ---
    if "file_comparison" in analysis:
        output_lines.append("\n--- File Comparison ---")
        comp = analysis["file_comparison"]
        output_lines.append(f"File 1: {comp.get('file1', 'N/A')}")
        output_lines.append(f"File 2: {comp.get('file2', 'N/A')}")
        output_lines.append(f"File 1 Size: {comp.get('file1_size', 0)} bytes")
        output_lines.append(f"File 2 Size: {comp.get('file2_size', 0)} bytes")
        output_lines.append(f"Size Match: {'Yes' if comp.get('size_match') else 'No'}")
        output_lines.append(f"Duration: {comp.get('duration_seconds', 0)} seconds")

        # Show hash values for each file
        output_lines.append("\nHash Values:")
        for alg in comp.get('hashes', {}).get('file1', {}):
            hash1 = comp['hashes']['file1'][alg]
            hash2 = comp['hashes']['file2'][alg]

            if alg in ("ssdeep", "tlsh"):
                # For fuzzy hashes, show differently
                output_lines.append(f"\n  {alg.upper()}:")
                output_lines.append(f"    File 1: {hash1 or 'N/A'}")
                output_lines.append(f"    File 2: {hash2 or 'N/A'}")
                if hash1 and hash2:
                    similarity = comp['match_results'].get(alg, -1)
                    output_lines.append(f"    Similarity: {similarity}%")
            else:
                # For regular hashes, show side by side
                match = "MATCH" if comp['match_results'].get(alg) else "DIFFERENT"
                output_lines.append(f"\n  {alg.upper()}: {match}")
                output_lines.append(f"    File 1: {hash1 or 'N/A'}")
                output_lines.append(f"    File 2: {hash2 or 'N/A'}")

        # Overall similarity assessment
        if comp.get('fuzzy_similarity') is not None:
            output_lines.append(f"\nOverall Similarity: {comp.get('fuzzy_similarity')}%")

            if comp.get('fuzzy_similarity') >= 90:
                output_lines.append("Assessment: Files are highly similar")
            elif comp.get('fuzzy_similarity') >= 70:
                output_lines.append("Assessment: Files have significant similarities")
            elif comp.get('fuzzy_similarity') >= 50:
                output_lines.append("Assessment: Files have moderate similarities")
            else:
                output_lines.append("Assessment: Files appear to be different")

    return "\n".join(output_lines)


def format_results_csv(results: Dict[str, Any]) -> str:
    """Format analysis results as CSV for easy parsing.

    Args:
        results: Analysis results dictionary

    Returns:
        CSV representation
    """
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Error handling
    if "error" in results:
        writer.writerow(["Error", results["error"]])
        return output.getvalue()

    analysis = results.get("analysis_results", {})

    # --- Mode 1: Calculate Hashes ---
    if "calculated_hashes" in analysis:
        writer.writerow(["File", "Algorithm", "Hash"])
        file_path = results.get("parameters", {}).get("file", "N/A")

        for alg, hash_val in analysis["calculated_hashes"].items():
            writer.writerow([file_path, alg, hash_val or "Error calculating"])

    # --- Mode 2: Hash Verification ---
    elif "verification" in analysis:
        writer.writerow(["File", "Algorithm", "Expected Hash", "Match"])
        ver = analysis["verification"]
        writer.writerow([
            ver.get("file", "N/A"),
            ver.get("algorithm", "N/A"),
            ver.get("expected_hash", "N/A"),
            "YES" if ver.get("match") else "NO"
        ])

    # --- Mode 4: Similar Files ---
    elif "similar_files" in analysis:
        writer.writerow(["File1", "File2", "Similarity"])

        for pair in analysis["similar_files"]:
            writer.writerow([
                pair.get("file1", "N/A"),
                pair.get("file2", "N/A"),
                pair.get("similarity", 0)
            ])

    # --- Mode 6: Batch Hashing ---
    elif "batch_hashing" in analysis:
        # Get unique algorithms used
        hashes = analysis["batch_hashing"].get("file_hashes", {})
        if not hashes:
            writer.writerow(["No hash results available"])
            return output.getvalue()

        # Get list of all algorithms from first successful result
        all_algorithms = []
        for file_path, file_hashes in hashes.items():
            if "error" not in file_hashes:
                all_algorithms = list(file_hashes.keys())
                break

        # Write header with all algorithms
        header = ["File"] + all_algorithms + ["Error"]
        writer.writerow(header)

        # Write results for each file
        for file_path, file_hashes in hashes.items():
            row = [file_path]

            if "error" in file_hashes:
                # Add empty values for each algorithm
                row.extend([""] * len(all_algorithms))
                row.append(file_hashes["error"])
            else:
                # Add hash values for each algorithm
                for alg in all_algorithms:
                    row.append(file_hashes.get(alg, ""))
                row.append("")  # No error

            writer.writerow(row)

    # --- Mode 7: File Comparison ---
    elif "file_comparison" in analysis:
        comp = analysis["file_comparison"]

        # Write file information
        writer.writerow(["", "File 1", "File 2"])
        writer.writerow(["Path", comp.get("file1", "N/A"), comp.get("file2", "N/A")])

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
