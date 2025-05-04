"""
Hash Utilities for Static Analysis in Forensic Toolkit.

This module provides specialized hashing utilities for forensic analysis,
supporting multiple algorithms, optimized performance for large files,
and integration with the core forensics toolkit functionality.

Functions focus on:
- Calculating various types of cryptographic hashes (MD5, SHA-1, SHA-256, etc.)
- Computing fuzzy hashes for similarity detection
- Comparing hashes with configurable thresholds
- Optimized processing for large files
- Maintaining hash databases of known files
"""

import hashlib
import json
import logging
import os
import re
import sys
from pathlib import Path
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple, Union, Any, BinaryIO

# Try to import fuzzy hashing libraries
try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

# Attempt to use the core forensic utilities when available
try:
    from admin.security.forensics.utils.crypto import calculate_file_hash, calculate_data_hash
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    from admin.security.forensics.utils.file_utils import read_only_open
    FORENSIC_CORE_AVAILABLE = True
except ImportError:
    FORENSIC_CORE_AVAILABLE = False

# Attempt to import static analysis constants
try:
    from admin.security.forensics.static_analysis.common.output_constants import (
        DEFAULT_READ_CHUNK_SIZE,
    )
    from admin.security.forensics.utils.forensic_constants import (
        HASH_COMPARISON_THRESHOLD,
        FUZZY_HASH_THRESHOLD
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False
    DEFAULT_READ_CHUNK_SIZE = 65536  # 64KB
    LOCAL_HASH_COMPARISON_THRESHOLD = 1.0  # Exact match for cryptographic hashes
    LOCAL_FUZZY_HASH_THRESHOLD = 70  # Default threshold for fuzzy hash similarity (%)

logger = logging.getLogger(__name__)

# --- Hash Algorithm Constants ---
SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha384", "sha512", "blake2b", "blake2s"]
WEAK_HASH_ALGORITHMS = ["md5", "sha1"]

# --- Hash Utility Functions ---

def calculate_hash(file_path: str, algorithm: str = "sha256") -> Optional[str]:
    """
    Calculate hash for a file using the specified algorithm.

    Attempts to use the core forensic crypto module if available,
    otherwise falls back to a local implementation.

    Args:
        file_path: Path to the file to hash
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        String containing the hexadecimal hash value or None if error
    """
    operation_details = {
        "file": file_path,
        "algorithm": algorithm
    }

    # Normalize algorithm name to lowercase
    algorithm = algorithm.lower()

    # Validate that the algorithm is supported
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        error_msg = f"Unsupported hash algorithm: {algorithm}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_hash", False,
                                 {**operation_details, "error": error_msg})
        return None

    try:
        # Use core forensic function if available
        if FORENSIC_CORE_AVAILABLE:
            return calculate_file_hash(file_path, algorithm)

        # Fall back to local implementation
        hash_obj = hashlib.new(algorithm)

        # Check if file exists and is accessible
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            return None

        # Process file in chunks to handle large files efficiently
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(DEFAULT_READ_CHUNK_SIZE), b''):
                hash_obj.update(chunk)

        file_hash = hash_obj.hexdigest()

        logger.debug(f"Calculated {algorithm} hash for {file_path}: {file_hash}")
        return file_hash

    except (IOError, OSError) as e:
        error_msg = f"Error reading file {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_hash", False,
                                 {**operation_details, "error": error_msg})
        return None
    except Exception as e:
        error_msg = f"Unexpected error calculating hash for {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_hash", False,
                                 {**operation_details, "error": error_msg})
        return None


def calculate_multiple_hashes(file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
    """
    Calculate multiple hashes for a file using the specified algorithms.

    This is more efficient than calling calculate_hash multiple times
    as the file is only read once.

    Args:
        file_path: Path to the file to hash
        algorithms: List of hash algorithms to use (default: ["md5", "sha1", "sha256"])

    Returns:
        Dictionary mapping algorithm names to their hash values
    """
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256"]

    operation_details = {
        "file": file_path,
        "algorithms": algorithms
    }

    # Normalize algorithm names to lowercase
    algorithms = [alg.lower() for alg in algorithms]

    # Validate that all algorithms are supported
    unsupported = [alg for alg in algorithms if alg not in SUPPORTED_HASH_ALGORITHMS]
    if unsupported:
        error_msg = f"Unsupported hash algorithm(s): {', '.join(unsupported)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_multiple_hashes", False,
                                 {**operation_details, "error": error_msg})
        return {alg: None for alg in algorithms}

    # Display warning for weak hash algorithms
    weak_algs = [alg for alg in algorithms if alg in WEAK_HASH_ALGORITHMS]
    if weak_algs:
        logger.warning(f"Using weak hash algorithm(s): {', '.join(weak_algs)}")

    try:
        # Initialize hash objects for all algorithms
        hash_objects = {alg: hashlib.new(alg) for alg in algorithms}

        # Check if file exists and is accessible
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("calculate_multiple_hashes", False,
                                     {**operation_details, "error": error_msg})
            return {alg: None for alg in algorithms}

        # Process file in chunks
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(DEFAULT_READ_CHUNK_SIZE), b''):
                # Update all hash objects with the same chunk
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)

        # Calculate final hash values
        result = {alg: hash_obj.hexdigest() for alg, hash_obj in hash_objects.items()}

        # Log successful operation
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_multiple_hashes", True, operation_details)

        return result

    except (IOError, OSError) as e:
        error_msg = f"Error reading file {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_multiple_hashes", False,
                                 {**operation_details, "error": error_msg})
        return {alg: None for alg in algorithms}
    except Exception as e:
        error_msg = f"Unexpected error calculating hashes for {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_multiple_hashes", False,
                                 {**operation_details, "error": error_msg})
        return {alg: None for alg in algorithms}


def calculate_fuzzy_hash(file_path: str, algorithm: str = "ssdeep") -> Optional[str]:
    """
    Calculate a fuzzy hash for a file, which can be used for similarity matching.

    Args:
        file_path: Path to the file to hash
        algorithm: Fuzzy hash algorithm to use ('ssdeep' or 'tlsh')

    Returns:
        String containing the fuzzy hash or None if error
    """
    operation_details = {
        "file": file_path,
        "algorithm": algorithm
    }

    # Normalize algorithm name to lowercase
    algorithm = algorithm.lower()

    # Validate algorithm
    if algorithm == "ssdeep" and not SSDEEP_AVAILABLE:
        error_msg = "ssdeep library not available. Install with: pip install ssdeep"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_fuzzy_hash", False,
                                 {**operation_details, "error": error_msg})
        return None

    if algorithm == "tlsh" and not TLSH_AVAILABLE:
        error_msg = "tlsh library not available. Install with: pip install py-tlsh"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_fuzzy_hash", False,
                                 {**operation_details, "error": error_msg})
        return None

    try:
        # Check if file exists and is accessible
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("calculate_fuzzy_hash", False,
                                     {**operation_details, "error": error_msg})
            return None

        # Calculate the appropriate fuzzy hash
        if algorithm == "ssdeep":
            # Use ssdeep for context triggered piecewise hashing
            result = ssdeep.hash_from_file(file_path)
        elif algorithm == "tlsh":
            # Use TLSH (Trend Micro Locality Sensitive Hash)
            with open(file_path, 'rb') as file:
                data = file.read()
            if len(data) >= 50:  # TLSH requires a minimum amount of data
                result = tlsh.hash(data)
            else:
                error_msg = f"File too small for TLSH algorithm (< 50 bytes): {file_path}"
                logger.warning(error_msg)
                if FORENSIC_CORE_AVAILABLE:
                    log_forensic_operation("calculate_fuzzy_hash", False,
                                         {**operation_details, "error": error_msg})
                return None
        else:
            error_msg = f"Unsupported fuzzy hash algorithm: {algorithm}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("calculate_fuzzy_hash", False,
                                     {**operation_details, "error": error_msg})
            return None

        # Log successful operation
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_fuzzy_hash", True,
                                 {**operation_details, "fuzzy_hash_length": len(result)})

        return result

    except Exception as e:
        error_msg = f"Error calculating fuzzy hash for {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_fuzzy_hash", False,
                                 {**operation_details, "error": error_msg})
        return None


def compare_fuzzy_hashes(hash1: str, hash2: str, algorithm: str = "ssdeep") -> int:
    """
    Compare two fuzzy hashes and return a similarity score.

    Args:
        hash1: First fuzzy hash
        hash2: Second fuzzy hash
        algorithm: Algorithm used to generate the hashes ('ssdeep' or 'tlsh')

    Returns:
        Similarity score (0-100 for ssdeep, or distance value for tlsh)
        Higher is more similar for ssdeep; lower is more similar for tlsh.
        Returns -1 if comparison cannot be performed.
    """
    # Normalize algorithm name to lowercase
    algorithm = algorithm.lower()

    try:
        if algorithm == "ssdeep":
            if not SSDEEP_AVAILABLE:
                logger.error("ssdeep library not available")
                return -1

            # ssdeep returns 0-100 similarity score
            return ssdeep.compare(hash1, hash2)

        elif algorithm == "tlsh":
            if not TLSH_AVAILABLE:
                logger.error("tlsh library not available")
                return -1

            # tlsh returns a distance score (lower is more similar)
            # We'll convert it to a similarity score for consistency
            distance = tlsh.diff(hash1, hash2)

            # TLSH distance can be large, so we map it to a similarity score
            # where distance of 0 = 100% similar, and distance of 300+ = 0% similar
            similarity = max(0, 100 - min(distance, 300) / 3)
            return round(similarity)

        else:
            logger.error(f"Unsupported fuzzy hash algorithm: {algorithm}")
            return -1

    except Exception as e:
        logger.error(f"Error comparing fuzzy hashes: {str(e)}")
        return -1


def verify_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify that a file matches an expected hash value.

    Args:
        file_path: Path to the file to verify
        expected_hash: Expected hash value
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        True if the file hash matches the expected hash, False otherwise
    """
    operation_details = {
        "file": file_path,
        "algorithm": algorithm,
        "expected_hash": expected_hash
    }

    try:
        # Calculate actual hash
        actual_hash = calculate_hash(file_path, algorithm)

        if actual_hash is None:
            logger.error(f"Failed to calculate hash for {file_path}")
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("verify_hash", False,
                                     {**operation_details, "error": "Hash calculation failed"})
            return False

        # Compare hashes (case-insensitive)
        result = actual_hash.lower() == expected_hash.lower()

        operation_details["actual_hash"] = actual_hash
        operation_details["match"] = result

        # Log operation result
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("verify_hash", result, operation_details)

        if result:
            logger.debug(f"Hash verification successful for {file_path}")
        else:
            logger.warning(f"Hash mismatch for {file_path}. Expected: {expected_hash}, Actual: {actual_hash}")

        return result

    except Exception as e:
        error_msg = f"Error verifying hash: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("verify_hash", False,
                                 {**operation_details, "error": error_msg})
        return False


def hash_directory(directory_path: str, algorithm: str = "sha256",
                 recursive: bool = True, pattern: str = "*") -> Dict[str, str]:
    """
    Calculate hashes for all files in a directory.

    Args:
        directory_path: Path to the directory to hash
        algorithm: Hash algorithm to use (default: sha256)
        recursive: Whether to recursively hash files in subdirectories
        pattern: File pattern to match (e.g., "*.exe")

    Returns:
        Dictionary mapping relative file paths to their hash values
    """
    operation_details = {
        "directory": directory_path,
        "algorithm": algorithm,
        "recursive": recursive,
        "pattern": pattern
    }

    try:
        # Check if directory exists
        if not os.path.isdir(directory_path):
            error_msg = f"Directory not found: {directory_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("hash_directory", False,
                                     {**operation_details, "error": error_msg})
            return {}

        # Build list of files to hash
        files_to_hash = []
        directory_path = os.path.abspath(directory_path)

        if recursive:
            for root, _, files in os.walk(directory_path):
                for filename in files:
                    if fnmatch.fnmatch(filename, pattern):
                        file_path = os.path.join(root, filename)
                        if os.path.isfile(file_path):
                            files_to_hash.append(file_path)
        else:
            for entry in os.listdir(directory_path):
                if fnmatch.fnmatch(entry, pattern):
                    file_path = os.path.join(directory_path, entry)
                    if os.path.isfile(file_path):
                        files_to_hash.append(file_path)

        # Calculate hash for each file
        result = {}
        for file_path in files_to_hash:
            # Use relative path as key
            rel_path = os.path.relpath(file_path, directory_path)
            file_hash = calculate_hash(file_path, algorithm)
            if file_hash:
                result[rel_path] = file_hash

        # Log successful operation
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("hash_directory", True,
                                 {**operation_details, "files_processed": len(files_to_hash),
                                  "successful_hashes": len(result)})

        return result

    except Exception as e:
        error_msg = f"Error hashing directory {directory_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("hash_directory", False,
                                 {**operation_details, "error": error_msg})
        return {}


def create_hash_database(input_directory: str, output_file: str, algorithm: str = "sha256",
                      recursive: bool = True, pattern: str = "*") -> bool:
    """
    Create a hash database from files in a directory.

    Args:
        input_directory: Path to directory containing files to hash
        output_file: Path to output hash database file
        algorithm: Hash algorithm to use
        recursive: Whether to recursively hash files in subdirectories
        pattern: File pattern to match

    Returns:
        True if database was successfully created, False otherwise
    """
    operation_details = {
        "input_directory": input_directory,
        "output_file": output_file,
        "algorithm": algorithm,
        "recursive": recursive,
        "pattern": pattern
    }

    try:
        # Get hashes for all matching files in directory
        hashes = hash_directory(input_directory, algorithm, recursive, pattern)

        if not hashes:
            error_msg = f"No files found matching pattern '{pattern}' in {input_directory}"
            logger.warning(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("create_hash_database", False,
                                     {**operation_details, "error": error_msg})
            return False

        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

        # Write hash database to file
        with open(output_file, 'w') as f:
            json.dump({
                "algorithm": algorithm,
                "created": datetime.now().isoformat(),
                "hashes": hashes
            }, f, indent=2)

        # Set secure permissions on database file
        try:
            os.chmod(output_file, 0o600)  # Read/write for owner only
        except Exception as perm_error:
            logger.warning(f"Failed to set secure permissions on hash database: {perm_error}")

        # Log successful operation
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("create_hash_database", True,
                                 {**operation_details, "file_count": len(hashes)})

        logger.info(f"Created hash database with {len(hashes)} files at {output_file}")
        return True

    except Exception as e:
        error_msg = f"Error creating hash database: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("create_hash_database", False,
                                 {**operation_details, "error": error_msg})
        return False


def check_hash_against_database(file_path: str, database_path: str,
                             algorithm: str = None) -> Dict[str, Any]:
    """
    Check if a file's hash exists in a hash database.

    Args:
        file_path: Path to the file to check
        database_path: Path to the hash database file
        algorithm: Hash algorithm to use (if None, uses algorithm from database)

    Returns:
        Dictionary with match information:
        {
            "match": True/False,
            "matched_path": path/to/matched/file (if match is True),
            "hash": calculated hash,
            "algorithm": algorithm used
        }
    """
    operation_details = {
        "file": file_path,
        "database": database_path
    }

    try:
        # Load hash database
        with open(database_path, 'r') as f:
            database = json.load(f)

        # Use algorithm from database if not specified
        if algorithm is None:
            algorithm = database.get("algorithm", "sha256")

        operation_details["algorithm"] = algorithm

        # Calculate hash for the file
        file_hash = calculate_hash(file_path, algorithm)
        if file_hash is None:
            error_msg = f"Failed to calculate hash for {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("check_hash_against_database", False,
                                     {**operation_details, "error": error_msg})
            return {"match": False, "error": error_msg}

        # Check if hash exists in database
        hashes = database.get("hashes", {})
        match = None
        for path, hash_value in hashes.items():
            if hash_value.lower() == file_hash.lower():
                match = path
                break

        result = {
            "match": match is not None,
            "hash": file_hash,
            "algorithm": algorithm
        }

        if match:
            result["matched_path"] = match

        # Log operation result
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("check_hash_against_database", True,
                                 {**operation_details, "match": result["match"]})

        return result

    except (IOError, json.JSONDecodeError) as e:
        error_msg = f"Error reading hash database {database_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("check_hash_against_database", False,
                                 {**operation_details, "error": error_msg})
        return {"match": False, "error": error_msg}
    except Exception as e:
        error_msg = f"Unexpected error checking hash: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("check_hash_against_database", False,
                                 {**operation_details, "error": error_msg})
        return {"match": False, "error": error_msg}


def find_similar_files(directory_path: str, threshold: int = None,
                    algorithm: str = "ssdeep", recursive: bool = True,
                    pattern: str = "*") -> List[Dict[str, Any]]:
    """
    Find similar files in a directory using fuzzy hashing.

    Args:
        directory_path: Path to directory containing files to compare
        threshold: Similarity threshold (0-100 for ssdeep; default from constants)
        algorithm: Fuzzy hash algorithm to use ('ssdeep' or 'tlsh')
        recursive: Whether to recursively analyze files in subdirectories
        pattern: File pattern to match

    Returns:
        List of dictionaries containing similar file pairs:
        [
            {
                "file1": path/to/first/file,
                "file2": path/to/second/file,
                "similarity": similarity_score
            },
            ...
        ]
    """
    operation_details = {
        "directory": directory_path,
        "algorithm": algorithm,
        "recursive": recursive,
        "pattern": pattern,
        "threshold": threshold
    }

    # Use default threshold if not specified
    if threshold is None:
        threshold = FUZZY_HASH_THRESHOLD

    try:
        # Check that the required fuzzy hash library is available
        if algorithm == "ssdeep" and not SSDEEP_AVAILABLE:
            error_msg = "ssdeep library not available"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("find_similar_files", False,
                                     {**operation_details, "error": error_msg})
            return []
        elif algorithm == "tlsh" and not TLSH_AVAILABLE:
            error_msg = "tlsh library not available"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("find_similar_files", False,
                                     {**operation_details, "error": error_msg})
            return []

        # Get list of files to analyze
        files_to_analyze = []
        directory_path = os.path.abspath(directory_path)

        if recursive:
            for root, _, files in os.walk(directory_path):
                for filename in files:
                    if fnmatch.fnmatch(filename, pattern):
                        file_path = os.path.join(root, filename)
                        if os.path.isfile(file_path):
                            files_to_analyze.append(file_path)
        else:
            for entry in os.listdir(directory_path):
                if fnmatch.fnmatch(entry, pattern):
                    file_path = os.path.join(directory_path, entry)
                    if os.path.isfile(file_path):
                        files_to_analyze.append(file_path)

        # Calculate fuzzy hashes for all files
        file_hashes = {}
        for file_path in files_to_analyze:
            fuzzy_hash = calculate_fuzzy_hash(file_path, algorithm)
            if fuzzy_hash:
                file_hashes[file_path] = fuzzy_hash

        # Compare each file with every other file
        similar_files = []
        processed_pairs = set()  # To avoid duplicate comparisons

        for file1, hash1 in file_hashes.items():
            for file2, hash2 in file_hashes.items():
                if file1 == file2:
                    continue

                # Create a unique key for this pair (order doesn't matter)
                pair_key = tuple(sorted([file1, file2]))
                if pair_key in processed_pairs:
                    continue

                processed_pairs.add(pair_key)

                # Compare fuzzy hashes
                similarity = compare_fuzzy_hashes(hash1, hash2, algorithm)

                if similarity >= threshold:
                    similar_files.append({
                        "file1": file1,
                        "file2": file2,
                        "similarity": similarity
                    })

        # Log operation result
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("find_similar_files", True,
                                 {**operation_details, "files_analyzed": len(file_hashes),
                                  "similar_pairs_found": len(similar_files)})

        # Sort by similarity score (highest first)
        similar_files.sort(key=lambda x: x["similarity"], reverse=True)

        return similar_files

    except Exception as e:
        error_msg = f"Error finding similar files: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("find_similar_files", False,
                                 {**operation_details, "error": error_msg})
        return []


def import_missing_modules():
    """Import missing modules that are required for some functions."""
    global fnmatch, datetime

    import fnmatch
    from datetime import datetime


# Import any missing modules needed by functions
import_missing_modules()


# Self-test function for direct script execution
def _self_test():
    """Run self-tests when hash_utils.py is executed directly."""
    print("Running hash_utils.py self-tests...")

    # Create a temporary test file
    test_content = b"This is a test file for hash calculations."

    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        temp.write(test_content)
        test_file = temp.name

    print(f"Created test file: {test_file}")

    try:
        # Test hash calculation
        print("\n--- Testing calculate_hash ---")
        print(f"MD5: {calculate_hash(test_file, 'md5')}")
        print(f"SHA1: {calculate_hash(test_file, 'sha1')}")
        print(f"SHA256: {calculate_hash(test_file, 'sha256')}")

        # Test multiple hash calculation
        print("\n--- Testing calculate_multiple_hashes ---")
        hashes = calculate_multiple_hashes(test_file, ["md5", "sha1", "sha256"])
        for alg, hash_val in hashes.items():
            print(f"{alg}: {hash_val}")

        # Test fuzzy hash calculation
        print("\n--- Testing calculate_fuzzy_hash ---")
        if SSDEEP_AVAILABLE:
            print(f"ssdeep: {calculate_fuzzy_hash(test_file, 'ssdeep')}")
        else:
            print("ssdeep not available")

        if TLSH_AVAILABLE:
            # TLSH requires minimum 50 bytes of input
            with open(test_file, "wb") as f:
                f.write(test_content * 2)  # Make file bigger for TLSH
            print(f"tlsh: {calculate_fuzzy_hash(test_file, 'tlsh')}")
        else:
            print("tlsh not available")

        # Test hash verification
        print("\n--- Testing verify_hash ---")
        md5_hash = calculate_hash(test_file, "md5")
        print(f"Verification with correct hash: {verify_hash(test_file, md5_hash, 'md5')}")
        print(f"Verification with incorrect hash: {verify_hash(test_file, 'incorrect_hash', 'md5')}")

        print("\nAll tests completed successfully!")

    except Exception as e:
        print(f"Test error: {e}")

    finally:
        # Clean up
        if os.path.exists(test_file):
            os.unlink(test_file)


# Execute self-test when run directly
if __name__ == "__main__":
    _self_test()
