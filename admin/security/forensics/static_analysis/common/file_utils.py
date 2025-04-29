"""
File Utilities for Static Analysis in Forensic Toolkit.

This module provides specialized file handling utilities specifically designed
for forensic static analysis. It ensures safe handling of potentially malicious files,
prevents analysis-time execution, maintains forensic integrity of evidence files,
and provides functionality for extracting and analyzing file contents.

These utilities build upon the core file_utils in the forensics toolkit
but add static analysis specific capabilities for parsing, extracting,
and safely examining file structures and content.
"""

import json
import logging
import os
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple, Union, BinaryIO, Any, Generator

# Attempt to use the core forensic utilities when available
try:
    from admin.security.forensics.utils.file_utils import (
        secure_copy, get_file_metadata, verify_integrity,
        create_secure_temp_file, read_only_open
    )
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    from admin.security.forensics.utils.validation_utils import validate_path
    from admin.security.forensics.utils.crypto import calculate_file_hash
    FORENSIC_CORE_AVAILABLE = True
except ImportError:
    FORENSIC_CORE_AVAILABLE = False
    logging.warning("Core forensic utilities not available. Using static analysis fallback implementations.")

# Attempt to import static analysis constants
try:
    from admin.security.forensics.static_analysis.common.constants import (
        STATIC_ANALYSIS_TEMP_DIR,
        DEFAULT_READ_CHUNK_SIZE,
        SAFE_FILE_EXTENSIONS,
        DANGEROUS_FILE_EXTENSIONS,
        MAX_FILE_SIZE_BYTES,
        MAX_EMBEDDED_DEPTH,
        MAX_EMBEDDED_FILES
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False
    logging.warning("Static analysis constants not available. Using defaults.")
    STATIC_ANALYSIS_TEMP_DIR = "/tmp/forensic_static_analysis"
    DEFAULT_READ_CHUNK_SIZE = 65536  # 64KB chunks
    SAFE_FILE_EXTENSIONS = {".txt", ".csv", ".json", ".log", ".xml", ".yaml", ".yml"}
    DANGEROUS_FILE_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".jar", ".sh"}
    MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100MB
    MAX_EMBEDDED_DEPTH = 5
    MAX_EMBEDDED_FILES = 100


logger = logging.getLogger(__name__)

# --- Static File Analysis Core Functions ---

def safe_analyze_file(file_path: str, output_dir: Optional[str] = None,
                     check_extensions: bool = True, check_size: bool = True) -> Dict[str, Any]:
    """
    Safely analyze a file with security precautions, returning basic analysis results.

    Args:
        file_path: Path to the file to analyze
        output_dir: Directory to store extracted components (if needed)
        check_extensions: Whether to verify file extensions against safe/dangerous lists
        check_size: Whether to check if file size exceeds max allowed size

    Returns:
        Dict containing analysis results
    """
    operation_details = {
        "file": file_path,
        "operation": "static_analysis",
        "check_extensions": check_extensions,
        "check_size": check_size
    }

    try:
        # Check if file exists and is readable
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("safe_analyze_file", False,
                                      {**operation_details, "error": error_msg})
            return {"success": False, "error": error_msg}

        if not os.access(file_path, os.R_OK):
            error_msg = f"File not readable: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("safe_analyze_file", False,
                                      {**operation_details, "error": error_msg})
            return {"success": False, "error": error_msg}

        # Validate file extension if requested
        if check_extensions:
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()

            if ext in DANGEROUS_FILE_EXTENSIONS:
                warning_msg = f"File has potentially dangerous extension: {ext}"
                logger.warning(warning_msg)
                operation_details["warning"] = warning_msg

        # Check file size if requested
        if check_size:
            file_size = os.path.getsize(file_path)
            operation_details["file_size"] = file_size

            if file_size > MAX_FILE_SIZE_BYTES:
                error_msg = f"File exceeds maximum allowed size: {file_size} > {MAX_FILE_SIZE_BYTES} bytes"
                logger.error(error_msg)
                if FORENSIC_CORE_AVAILABLE:
                    log_forensic_operation("safe_analyze_file", False,
                                          {**operation_details, "error": error_msg})
                return {"success": False, "error": error_msg}

        # Get file hash for integrity
        file_hash = None
        if FORENSIC_CORE_AVAILABLE:
            file_hash = calculate_file_hash(file_path)
        else:
            # Fallback hash calculation
            import hashlib
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(DEFAULT_READ_CHUNK_SIZE), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()

        operation_details["hash"] = file_hash

        # Get basic file metadata
        if FORENSIC_CORE_AVAILABLE:
            metadata = get_file_metadata(file_path)
        else:
            # Basic metadata fallback
            stat_info = os.stat(file_path)
            metadata = {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": stat_info.st_size,
                "created_at": datetime.fromtimestamp(stat_info.st_ctime, timezone.utc).isoformat(),
                "modified_at": datetime.fromtimestamp(stat_info.st_mtime, timezone.utc).isoformat(),
                "accessed_at": datetime.fromtimestamp(stat_info.st_atime, timezone.utc).isoformat(),
                "extension": os.path.splitext(file_path)[1].lower(),
                "permissions": stat.filemode(stat_info.st_mode),
            }

        # Prepare output directory if needed for extracted components
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            operation_details["output_dir"] = output_dir

        # Build basic analysis results
        analysis_results = {
            "success": True,
            "metadata": metadata,
            "hash": file_hash,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }

        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("safe_analyze_file", True, operation_details)

        return analysis_results

    except Exception as e:
        error_msg = f"Error analyzing file {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("safe_analyze_file", False,
                                  {**operation_details, "error": error_msg})
        return {"success": False, "error": error_msg}


def extract_file_strings(file_path: str, min_length: int = 4,
                         encoding: str = "utf-8", context_bytes: int = 0) -> List[Dict[str, Any]]:
    """
    Extract string content from binary files with optional context.

    Args:
        file_path: Path to the file to extract strings from
        min_length: Minimum length of strings to extract
        encoding: Character encoding to use for string detection
        context_bytes: Number of bytes to include before/after each string for context

    Returns:
        List of dictionaries containing extracted strings and their locations
    """
    operation_details = {
        "file": file_path,
        "min_length": min_length,
        "encoding": encoding,
        "context_bytes": context_bytes
    }

    try:
        # Validate input file
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("extract_file_strings", False,
                                      {**operation_details, "error": error_msg})
            return []

        extracted_strings = []
        current_string = b""
        current_offset = 0
        string_offset = 0

        # Use read-only mode to ensure evidence integrity
        file_handle = None
        if FORENSIC_CORE_AVAILABLE:
            file_handle = read_only_open(file_path)

        # Fallback to standard open in read-binary mode if necessary
        if file_handle is None:
            file_handle = open(file_path, "rb")

        with file_handle as f:
            # Read file in chunks to handle large files efficiently
            chunk_size = DEFAULT_READ_CHUNK_SIZE

            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                for i, byte in enumerate(chunk):
                    # Check if byte is a printable ASCII or valid UTF-8 continuation
                    if (32 <= byte <= 126) or (encoding.lower() == "utf-8" and 128 <= byte <= 247):
                        if not current_string:
                            string_offset = current_offset + i
                        current_string += bytes([byte])
                    else:
                        # End of string found
                        if len(current_string) >= min_length:
                            try:
                                string_value = current_string.decode(encoding)

                                # Get context if requested
                                context_before = b""
                                context_after = b""
                                if context_bytes > 0:
                                    # Save current position
                                    current_pos = f.tell()

                                    # Get context before
                                    context_start = max(0, string_offset - context_bytes)
                                    if context_start < string_offset:
                                        f.seek(context_start)
                                        context_before = f.read(string_offset - context_start)

                                    # Get context after
                                    context_end = string_offset + len(current_string)
                                    f.seek(context_end)
                                    context_after = f.read(context_bytes)

                                    # Restore position
                                    f.seek(current_pos)

                                extracted_strings.append({
                                    "string": string_value,
                                    "offset": string_offset,
                                    "length": len(current_string),
                                    "context_before": context_before.hex() if context_bytes > 0 else None,
                                    "context_after": context_after.hex() if context_bytes > 0 else None
                                })
                            except UnicodeDecodeError:
                                # Skip strings that can't be decoded with the specified encoding
                                pass
                        current_string = b""

                current_offset += len(chunk)

            # Check for any remaining string at the end of file
            if len(current_string) >= min_length:
                try:
                    string_value = current_string.decode(encoding)
                    extracted_strings.append({
                        "string": string_value,
                        "offset": string_offset,
                        "length": len(current_string),
                        "context_before": None,
                        "context_after": None
                    })
                except UnicodeDecodeError:
                    pass

        operation_details["strings_found"] = len(extracted_strings)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("extract_file_strings", True, operation_details)

        return extracted_strings

    except Exception as e:
        error_msg = f"Error extracting strings from {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("extract_file_strings", False,
                                  {**operation_details, "error": error_msg})
        return []


def calculate_file_entropy(file_path: str, chunk_size: int = DEFAULT_READ_CHUNK_SIZE,
                          block_size: Optional[int] = None) -> Union[float, List[float]]:
    """
    Calculate Shannon entropy for a file, either as a whole or in blocks.

    Higher entropy (closer to 8.0) suggests encrypted, compressed, or random data.
    Lower entropy suggests more predictable, structured data.

    Args:
        file_path: Path to the file to analyze
        chunk_size: Size of chunks to read at once for large files
        block_size: If provided, calculate entropy in blocks of this size

    Returns:
        Float entropy value (0.0-8.0) for whole file, or list of floats for blocks
    """
    operation_details = {
        "file": file_path,
        "block_size": block_size
    }

    try:
        # Validate input file
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("calculate_file_entropy", False,
                                      {**operation_details, "error": error_msg})
            return 0.0 if block_size is None else []

        # Check if file is too large
        file_size = os.path.getsize(file_path)
        operation_details["file_size"] = file_size

        if file_size > MAX_FILE_SIZE_BYTES:
            warning_msg = f"File exceeds maximum recommended size: {file_size} > {MAX_FILE_SIZE_BYTES} bytes"
            logger.warning(warning_msg)
            operation_details["warning"] = warning_msg

        # Calculate entropy
        from math import log2

        # Use read-only mode to ensure evidence integrity
        file_handle = None
        if FORENSIC_CORE_AVAILABLE:
            file_handle = read_only_open(file_path)

        # Fallback to standard open in read-binary mode if necessary
        if file_handle is None:
            file_handle = open(file_path, "rb")

        result = []

        with file_handle as f:
            if block_size is None:
                # Calculate entropy for the entire file
                byte_counts = [0] * 256
                total_bytes = 0

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Count occurrences of each byte value
                    for byte in chunk:
                        byte_counts[byte] += 1

                    total_bytes += len(chunk)

                # Calculate entropy using Shannon formula
                entropy = 0.0
                if total_bytes > 0:
                    for count in byte_counts:
                        if count > 0:
                            probability = count / total_bytes
                            entropy -= probability * log2(probability)

                result = entropy

            else:
                # Calculate entropy in blocks
                while True:
                    block = f.read(block_size)
                    if not block:
                        break

                    # Count occurrences of each byte value in this block
                    byte_counts = [0] * 256
                    for byte in block:
                        byte_counts[byte] += 1

                    # Calculate entropy for this block
                    block_entropy = 0.0
                    for count in byte_counts:
                        if count > 0:
                            probability = count / len(block)
                            block_entropy -= probability * log2(probability)

                    result.append(block_entropy)

        operation_details["entropy"] = result if isinstance(result, float) else f"{len(result)} blocks"
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_file_entropy", True, operation_details)

        return result

    except Exception as e:
        error_msg = f"Error calculating entropy for {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("calculate_file_entropy", False,
                                  {**operation_details, "error": error_msg})
        return 0.0 if block_size is None else []


def extract_embedded_files(file_path: str, output_dir: str, recursive: bool = True,
                          max_depth: int = MAX_EMBEDDED_DEPTH,
                          max_files: int = MAX_EMBEDDED_FILES) -> List[Dict[str, Any]]:
    """
    Extract embedded files from container formats (ZIP, RAR, Office documents, etc.)

    Args:
        file_path: Path to the container file
        output_dir: Directory to save extracted files
        recursive: Whether to recursively extract embedded files within extracted files
        max_depth: Maximum recursion depth for extraction
        max_files: Maximum number of files to extract

    Returns:
        List of dictionaries with metadata about extracted files
    """
    operation_details = {
        "file": file_path,
        "output_dir": output_dir,
        "recursive": recursive,
        "max_depth": max_depth,
        "max_files": max_files
    }

    try:
        # Validate input file
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("extract_embedded_files", False,
                                      {**operation_details, "error": error_msg})
            return []

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Track extracted files
        extracted_files = []
        file_count = 0

        # Determine file type based on extension and/or magic bytes
        file_ext = os.path.splitext(file_path)[1].lower()

        # Read magic bytes to help identify file type
        with open(file_path, "rb") as f:
            magic_bytes = f.read(16)

        # Process based on file type
        if file_ext in [".zip"] or magic_bytes.startswith(b"PK\x03\x04"):
            # Handle ZIP archives
            import zipfile

            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as zip_file:
                    safe_members = [m for m in zip_file.namelist() if
                                   not any(p in m for p in ['/', '\\']) or
                                   not m.startswith('..')]

                    # Check max files limit
                    if len(safe_members) > max_files:
                        logger.warning(f"ZIP contains {len(safe_members)} files, limiting to {max_files}")
                        safe_members = safe_members[:max_files]

                    for member in safe_members:
                        try:
                            # Check for directory traversal attempts
                            out_path = os.path.join(output_dir, os.path.basename(member))

                            # Extract the file
                            with zip_file.open(member) as source, open(out_path, 'wb') as target:
                                shutil.copyfileobj(source, target)

                            # Calculate hash of extracted file
                            file_hash = None
                            if FORENSIC_CORE_AVAILABLE:
                                file_hash = calculate_file_hash(out_path)
                            else:
                                import hashlib
                                sha256_hash = hashlib.sha256()
                                with open(out_path, "rb") as f:
                                    for byte_block in iter(lambda: f.read(DEFAULT_READ_CHUNK_SIZE), b""):
                                        sha256_hash.update(byte_block)
                                file_hash = sha256_hash.hexdigest()

                            # Record extracted file
                            extracted_info = {
                                "original_path": member,
                                "extracted_path": out_path,
                                "size": os.path.getsize(out_path),
                                "hash": file_hash
                            }
                            extracted_files.append(extracted_info)
                            file_count += 1

                            # Recursive extraction if requested
                            if recursive and max_depth > 1:
                                child_output_dir = os.path.join(output_dir, f"extracted_{os.path.basename(member)}")
                                child_files = extract_embedded_files(
                                    out_path, child_output_dir,
                                    recursive=recursive,
                                    max_depth=max_depth-1,
                                    max_files=max_files-file_count
                                )

                                if child_files:
                                    extracted_info["embedded_files"] = child_files
                                    extracted_files.extend(child_files)
                                    file_count += len(child_files)

                                    # Check if we've hit the max files limit
                                    if file_count >= max_files:
                                        break

                        except Exception as inner_e:
                            logger.warning(f"Failed to extract {member}: {inner_e}")
                            continue

        elif file_ext in [".docx", ".xlsx", ".pptx"] or magic_bytes.startswith(b"PK\x03\x04"):
            # Office Open XML files are also ZIP-based
            import zipfile

            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as zip_file:
                    safe_members = [m for m in zip_file.namelist()]

                    # Check max files limit
                    if len(safe_members) > max_files:
                        logger.warning(f"Office document contains {len(safe_members)} files, limiting to {max_files}")
                        safe_members = safe_members[:max_files]

                    for member in safe_members:
                        try:
                            # Check for macros and OLE objects which might contain malicious code
                            if "vbaProject.bin" in member or "oleObject" in member:
                                logger.warning(f"Potentially suspicious Office component found: {member}")

                            # Extract the file, ensuring safe path
                            out_path = os.path.join(output_dir, os.path.basename(member.replace("/", "_")))

                            with zip_file.open(member) as source, open(out_path, 'wb') as target:
                                shutil.copyfileobj(source, target)

                            # Calculate hash of extracted file
                            file_hash = None
                            if FORENSIC_CORE_AVAILABLE:
                                file_hash = calculate_file_hash(out_path)
                            else:
                                import hashlib
                                sha256_hash = hashlib.sha256()
                                with open(out_path, "rb") as f:
                                    for byte_block in iter(lambda: f.read(DEFAULT_READ_CHUNK_SIZE), b""):
                                        sha256_hash.update(byte_block)
                                file_hash = sha256_hash.hexdigest()

                            # Record extracted file
                            extracted_info = {
                                "original_path": member,
                                "extracted_path": out_path,
                                "size": os.path.getsize(out_path),
                                "hash": file_hash
                            }
                            extracted_files.append(extracted_info)
                            file_count += 1

                        except Exception as inner_e:
                            logger.warning(f"Failed to extract {member}: {inner_e}")
                            continue

        elif file_ext in [".pdf"] or magic_bytes.startswith(b"%PDF"):
            # Extract embedded files from PDFs
            try:
                # Use PyPDF2 if available
                try:
                    import PyPDF2
                    has_pypdf2 = True
                except ImportError:
                    has_pypdf2 = False
                    logger.warning("PyPDF2 not available. Limited PDF extraction capabilities.")

                if has_pypdf2:
                    with open(file_path, 'rb') as pdf_file:
                        pdf_reader = PyPDF2.PdfFileReader(pdf_file)

                        # Check if PDF is encrypted
                        if pdf_reader.isEncrypted:
                            logger.warning(f"PDF is encrypted. Limited extraction possible.")

                        # Extract embedded files from PDF
                        for i in range(pdf_reader.numPages):
                            if file_count >= max_files:
                                break

                            page = pdf_reader.getPage(i)
                            if '/Resources' in page and '/XObject' in page['/Resources']:
                                x_objects = page['/Resources']['/XObject'].getObject()

                                for obj_name, obj in x_objects.items():
                                    if obj['/Subtype'] == '/Image':
                                        # Extract image
                                        if '/Filter' in obj:
                                            filters = obj['/Filter']
                                            if isinstance(filters, list):
                                                filter_name = filters[0]
                                            else:
                                                filter_name = filters

                                            # Determine image format based on filter
                                            extension = ".raw"
                                            if filter_name == '/DCTDecode':
                                                extension = ".jpg"
                                            elif filter_name == '/FlateDecode':
                                                extension = ".png"
                                            elif filter_name == '/JPXDecode':
                                                extension = ".jp2"

                                            # Extract image data
                                            out_path = os.path.join(output_dir, f"image_{i}_{obj_name}_{file_count}{extension}")
                                            with open(out_path, 'wb') as img_file:
                                                img_file.write(obj._data)

                                            # Record extracted file
                                            extracted_info = {
                                                "original_path": f"Page {i}, Object {obj_name}",
                                                "extracted_path": out_path,
                                                "size": os.path.getsize(out_path),
                                                "type": "image"
                                            }
                                            extracted_files.append(extracted_info)
                                            file_count += 1

            except Exception as pdf_e:
                logger.warning(f"Error extracting from PDF: {pdf_e}")

        # Add more file type handlers as needed

        operation_details["files_extracted"] = file_count
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("extract_embedded_files", True, operation_details)

        return extracted_files

    except Exception as e:
        error_msg = f"Error extracting embedded files from {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("extract_embedded_files", False,
                                  {**operation_details, "error": error_msg})
        return []


@contextmanager
def isolated_file_access(file_path: str, read_only: bool = True) -> Iterator[str]:
    """
    Context manager for safely accessing potentially malicious files within an isolated location.

    Args:
        file_path: Path to the file to access
        read_only: If True, ensures file is never opened for writing

    Yields:
        Path to the safely accessible file (possibly a copy in an isolated location)
    """
    operation_details = {
        "file": file_path,
        "read_only": read_only
    }

    temp_file = None

    try:
        # Validate input file
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("isolated_file_access", False,
                                      {**operation_details, "error": error_msg})
            raise FileNotFoundError(error_msg)

        if read_only:
            # For read-only access, we can use the original file if it's readable
            if os.access(file_path, os.R_OK):
                if FORENSIC_CORE_AVAILABLE:
                    log_forensic_operation("isolated_file_access", True,
                                          {**operation_details, "isolation_method": "original_read_only"})
                yield file_path
                return

        # Otherwise, create a secure temporary copy of the file
        if FORENSIC_CORE_AVAILABLE:
            # Create a temporary file using secure utilities
            temp_file = create_secure_temp_file(prefix="static_analysis_", suffix=os.path.splitext(file_path)[1])
            if temp_file:
                # Copy the file to the secure temp location
                secure_copy(file_path, temp_file, read_only=read_only)
                operation_details["temp_file"] = temp_file

                log_forensic_operation("isolated_file_access", True,
                                      {**operation_details, "isolation_method": "secure_copy"})
                yield temp_file
                return

        # Fallback to standard tempfile if core forensic utilities aren't available
        # Ensure the temp directory exists
        os.makedirs(STATIC_ANALYSIS_TEMP_DIR, exist_ok=True)

        # Create temporary file with a recognizable name for easier cleanup
        file_name = os.path.basename(file_path)
        temp_file = os.path.join(STATIC_ANALYSIS_TEMP_DIR,
                                f"isolated_{int(datetime.now().timestamp())}_{file_name}")

        # Copy the file
        shutil.copy2(file_path, temp_file)

        # Set appropriate permissions
        if read_only:
            os.chmod(temp_file, stat.S_IRUSR)  # User read-only

        operation_details["temp_file"] = temp_file
        logger.info(f"File {file_path} isolated at {temp_file}")

        yield temp_file

    except Exception as e:
        error_msg = f"Error creating isolated file access for {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("isolated_file_access", False,
                                  {**operation_details, "error": error_msg})
        raise

    finally:
        # Clean up temporary file if created
        if temp_file and os.path.exists(temp_file) and temp_file != file_path:
            try:
                os.unlink(temp_file)
            except Exception as e:
                logger.warning(f"Failed to clean up temporary file {temp_file}: {e}")


def identify_file_type(file_path: str) -> Dict[str, Any]:
    """
    Identify file type using multiple methods (extension, magic bytes, structure).

    Args:
        file_path: Path to the file to identify

    Returns:
        Dictionary with file type information
    """
    operation_details = {
        "file": file_path
    }

    try:
        # Validate input file
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("identify_file_type", False,
                                      {**operation_details, "error": error_msg})
            return {"error": error_msg}

        # Get file extension
        _, extension = os.path.splitext(file_path)
        extension = extension.lower()

        # Read magic bytes
        with open(file_path, "rb") as f:
            magic_bytes = f.read(16)

        # Try to use python-magic if available
        mime_type = "application/octet-stream"
        recognized_by_magic = False

        try:
            import magic
            mime_type = magic.from_file(file_path, mime=True)
            recognized_by_magic = True
        except ImportError:
            logger.debug("python-magic not available, using fallback file type detection")

            # Basic fallback magic bytes detection
            signatures = {
                b"\x50\x4B\x03\x04": {
                    "mime": "application/zip",
                    "description": "ZIP archive"
                },
                b"\x25\x50\x44\x46": {
                    "mime": "application/pdf",
                    "description": "PDF document"
                },
                b"\xFF\xD8\xFF": {
                    "mime": "image/jpeg",
                    "description": "JPEG image"
                },
                b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A": {
                    "mime": "image/png",
                    "description": "PNG image"
                },
                b"\x4D\x5A": {
                    "mime": "application/x-dosexec",
                    "description": "Windows executable (MZ)"
                },
                b"\x7F\x45\x4C\x46": {
                    "mime": "application/x-elf",
                    "description": "ELF executable"
                },
                b"\x4D\x53\x43\x46": {
                    "mime": "application/x-msdownload",
                    "description": "Microsoft Cabinet archive"
                },
                b"\x52\x61\x72\x21\x1A\x07": {
                    "mime": "application/x-rar-compressed",
                    "description": "RAR archive"
                }
            }

            # Check for known signatures
            for signature, details in signatures.items():
                if magic_bytes.startswith(signature):
                    mime_type = details["mime"]
                    recognized_by_magic = True
                    break

        # Specific file type identification (more detailed than MIME)
        file_type = "Unknown"
        file_description = "Unknown file type"

        # Try to determine from extension if magic detection failed
        common_extensions = {
            ".txt": {
                "type": "Text",
                "description": "Plain text file"
            },
            ".html": {
                "type": "HTML",
                "description": "HTML document"
            },
            ".xml": {
                "type": "XML",
                "description": "XML document"
            },
            ".json": {
                "type": "JSON",
                "description": "JSON data file"
            },
            ".docx": {
                "type": "Office Document",
                "description": "Microsoft Word Document (OOXML)"
            },
            ".xlsx": {
                "type": "Office Document",
                "description": "Microsoft Excel Spreadsheet (OOXML)"
            },
            ".pptx": {
                "type": "Office Document",
                "description": "Microsoft PowerPoint Presentation (OOXML)"
            },
            ".js": {
                "type": "Script",
                "description": "JavaScript source"
            },
            ".py": {
                "type": "Script",
                "description": "Python source"
            },
            ".exe": {
                "type": "Executable",
                "description": "Windows Executable"
            },
            ".dll": {
                "type": "Library",
                "description": "Windows Dynamic Link Library"
            },
            ".so": {
                "type": "Library",
                "description": "UNIX Shared Object"
            },
        }

        if extension in common_extensions:
            file_type = common_extensions[extension]["type"]
            file_description = common_extensions[extension]["description"]

        # Special case for text files - check if actually text
        is_text_file = False
        if mime_type.startswith("text/") or extension in [".txt", ".csv", ".log", ".md", ".xml", ".html", ".json"]:
            # Try to read as text
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    sample = f.read(1024)  # Read a sample
                    is_text_file = True
            except UnicodeDecodeError:
                is_text_file = False

        # Build result
        result = {
            "mime_type": mime_type,
            "extension": extension,
            "detected_type": file_type,
            "description": file_description,
            "is_text_file": is_text_file,
            "magic_bytes": magic_bytes.hex()[:32],  # First 16 bytes in hex
            "recognized_by_magic": recognized_by_magic
        }

        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("identify_file_type", True,
                                  {**operation_details, **result})

        return result

    except Exception as e:
        error_msg = f"Error identifying file type for {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("identify_file_type", False,
                                  {**operation_details, "error": error_msg})
        return {"error": error_msg}


def extract_metadata_by_format(file_path: str) -> Dict[str, Any]:
    """
    Extract format-specific metadata from files based on their type.

    Supports various formats such as:
    - Images (EXIF data)
    - Office documents (author, creation date)
    - PDFs (creation date, author, software)
    - Executables (PE structure information)

    Args:
        file_path: Path to the file to analyze

    Returns:
        Dictionary with format-specific metadata
    """
    operation_details = {
        "file": file_path
    }

    try:
        # Validate input file
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("extract_metadata_by_format", False,
                                      {**operation_details, "error": error_msg})
            return {"error": error_msg}

        # Identify file type
        file_info = identify_file_type(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        mime_type = file_info.get("mime_type", "")

        operation_details["file_type"] = file_info.get("detected_type", "Unknown")

        metadata = {}

        # Process based on file type
        # -----------------------------
        # Images
        # -----------------------------
        if mime_type.startswith("image/") or file_ext in [".jpg", ".jpeg", ".png", ".tiff", ".tif"]:
            try:
                # Use PIL/Pillow if available
                try:
                    from PIL import Image
                    from PIL.ExifTags import TAGS

                    with Image.open(file_path) as img:
                        metadata["format"] = img.format
                        metadata["mode"] = img.mode
                        metadata["size"] = img.size

                        # Extract EXIF data if available
                        exif_data = {}
                        if hasattr(img, '_getexif') and img._getexif():
                            for tag, value in img._getexif().items():
                                decoded = TAGS.get(tag, tag)
                                exif_data[decoded] = value

                        # Add non-binary EXIF data to metadata
                        exif_filtered = {}
                        for key, value in exif_data.items():
                            # Skip binary data and ensure serializable
                            if isinstance(value, (str, int, float)) or (
                                isinstance(value, (list, tuple)) and all(isinstance(x, (str, int, float)) for x in value)
                            ):
                                exif_filtered[key] = value

                        if exif_filtered:
                            metadata["exif"] = exif_filtered

                except ImportError:
                    metadata["note"] = "PIL/Pillow not available for detailed image metadata extraction"

            except Exception as img_e:
                metadata["error"] = f"Failed to extract image metadata: {str(img_e)}"

        # -----------------------------
        # PDFs
        # -----------------------------
        elif mime_type == "application/pdf" or file_ext == ".pdf":
            try:
                # Use PyPDF2 if available
                try:
                    import PyPDF2

                    with open(file_path, 'rb') as pdf_file:
                        try:
                            pdf_reader = PyPDF2.PdfFileReader(pdf_file)

                            # Check if PDF is encrypted
                            metadata["encrypted"] = pdf_reader.isEncrypted

                            # Get document info
                            if not pdf_reader.isEncrypted:
                                info = pdf_reader.getDocumentInfo()
                                if info:
                                    # Convert PDF info to regular dict with serializable values
                                    for key in info:
                                        value = info[key]
                                        # Ensure value is serializable
                                        if isinstance(value, (str, int, float, bool)):
                                            metadata[key[1:] if key.startswith("/") else key] = value

                                metadata["pages"] = pdf_reader.getNumPages()

                                # Get page sizes for first few pages
                                page_sizes = []
                                for i in range(min(5, pdf_reader.getNumPages())):
                                    page = pdf_reader.getPage(i)
                                    if page:
                                        page_box = page.get('/MediaBox')
                                        if page_box:
                                            page_sizes.append(f"Page {i+1}: {page_box[2]}x{page_box[3]}")

                                if page_sizes:
                                    metadata["page_sizes"] = page_sizes

                        except PyPDF2.utils.PdfReadError as pdf_e:
                            metadata["error"] = f"Failed to parse PDF: {str(pdf_e)}"
                            metadata["is_corrupted"] = True

                except ImportError:
                    metadata["note"] = "PyPDF2 not available for detailed PDF metadata extraction"

            except Exception as pdf_e:
                metadata["error"] = f"Failed to extract PDF metadata: {str(pdf_e)}"

        # -----------------------------
        # Office Documents
        # -----------------------------
        elif file_ext in [".docx", ".xlsx", ".pptx"]:
            try:
                # Office Open XML files are ZIP files with specific structure
                import zipfile

                if zipfile.is_zipfile(file_path):
                    with zipfile.ZipFile(file_path, "r") as zip_file:
                        # Check for macros
                        has_macros = any("vbaProject.bin" in name for name in zip_file.namelist())
                        metadata["has_macros"] = has_macros

                        # Try to read core.xml for document metadata
                        if "docProps/core.xml" in zip_file.namelist():
                            import xml.etree.ElementTree as ET

                            with zip_file.open("docProps/core.xml") as core_xml:
                                tree = ET.parse(core_xml)
                                root = tree.getroot()

                                # Define XML namespaces
                                namespaces = {
                                    'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                                    'dc': 'http://purl.org/dc/elements/1.1/',
                                    'dcterms': 'http://purl.org/dc/terms/',
                                    'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
                                }

                                # Extract metadata properties
                                for ns_prefix, ns_uri in namespaces.items():
                                    for elem in root.findall(f".//{{{ns_uri}}}*"):
                                        tag = elem.tag.split('}')[-1]
                                        if elem.text:
                                            metadata[tag] = elem.text

                        # Additional file-specific metadata
                        if file_ext == ".docx":
                            # Word document specific info (e.g., count of paragraphs)
                            if "word/document.xml" in zip_file.namelist():
                                metadata["type"] = "Word Document"
                        elif file_ext == ".xlsx":
                            # Excel specific info (e.g., count of sheets)
                            sheet_count = len([name for name in zip_file.namelist()
                                             if name.startswith("xl/worksheets/sheet")])
                            metadata["type"] = "Excel Spreadsheet"
                            metadata["sheet_count"] = sheet_count
                        elif file_ext == ".pptx":
                            # PowerPoint specific info (e.g., count of slides)
                            slide_count = len([name for name in zip_file.namelist()
                                             if name.startswith("ppt/slides/slide")])
                            metadata["type"] = "PowerPoint Presentation"
                            metadata["slide_count"] = slide_count

                        # List of embedded files
                        if file_ext in [".docx", ".pptx"]:
                            embedded_count = len([name for name in zip_file.namelist()
                                                if "embeddings" in name])
                            metadata["embedded_files_count"] = embedded_count

            except Exception as office_e:
                metadata["error"] = f"Failed to extract Office document metadata: {str(office_e)}"

        # -----------------------------
        # Executables (Windows PE)
        # -----------------------------
        elif file_ext in [".exe", ".dll", ".sys"] or mime_type == "application/x-dosexec":
            try:
                # Use pefile if available
                pe_info = {}

                try:
                    import pefile
                    pe = pefile.PE(file_path)

                    # Basic PE information
                    pe_info["machine_type"] = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
                    pe_info["time_date_stamp"] = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, timezone.utc).isoformat()
                    pe_info["number_of_sections"] = pe.FILE_HEADER.NumberOfSections

                    # Characteristics
                    characteristics = []
                    for flag_name, flag_value in pefile.IMAGE_CHARACTERISTICS.items():
                        if pe.FILE_HEADER.Characteristics & flag_value:
                            characteristics.append(flag_name)
                    pe_info["characteristics"] = characteristics

                    # Optional header info
                    if hasattr(pe, 'OPTIONAL_HEADER'):
                        pe_info["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, hex(pe.OPTIONAL_HEADER.Subsystem))
                        pe_info["dll_characteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics

                        # Check if ASLR, DEP, etc. are enabled
                        security_features = []
                        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                            security_features.append("ASLR enabled")
                        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                            security_features.append("DEP enabled")
                        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400:  # IMAGE_DLLCHARACTERISTICS_NO_SEH
                            security_features.append("No SEH")
                        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000:  # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
                            security_features.append("Force Integrity")

                        pe_info["security_features"] = security_features

                    # Section information
                    sections = []
                    for section in pe.sections:
                        section_name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
                        sections.append({
                            "name": section_name,
                            "virtual_address": hex(section.VirtualAddress),
                            "virtual_size": section.Misc_VirtualSize,
                            "raw_size": section.SizeOfRawData,
                            "characteristics": hex(section.Characteristics)
                        })
                    pe_info["sections"] = sections

                    # Import information
                    try:
                        imports = {}
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            dll_name = entry.dll# filepath: admin/security/forensics/static_analysis/common/file_utils.py
                            imports[dll_name.decode('utf-8', errors='replace')] = []
                            for imp in entry.imports:
                                if imp.name:
                                    imports[dll_name.decode('utf-8', errors='replace')].append(imp.name.decode('utf-8', errors='replace'))
                        pe_info["imports"] = imports
                    except AttributeError:
                        pe_info["imports"] = "No import table found"
                except ImportError:
                    pe_info["note"] = "pefile not available for detailed PE metadata extraction"
                except Exception as pe_e:
                    pe_info["error"] = f"Failed to extract PE metadata: {str(pe_e)}"
                metadata["pe_info"] = pe_info
            except Exception as exe_e:
                metadata["error"] = f"Failed to extract executable metadata: {str(exe_e)}"
        # -----------------------------
        # Archive files
        # -----------------------------
        elif mime_type in ["application/zip", "application/x-zip-compressed", "application/x-zip"]:
            metadata["type"] = "ZIP Archive"
            metadata["compression_method"] = "ZIP"
            metadata["note"] = "ZIP files may contain various file types"
        elif mime_type in ["application/x-rar-compressed", "application/x-rar"]:
            metadata["type"] = "RAR Archive"
            metadata["compression_method"] = "RAR"
            metadata["note"] = "RAR files may contain various file types"
        elif mime_type in ["application/x-tar", "application/x-gzip"]:
            metadata["type"] = "TAR Archive"
            metadata["compression_method"] = "TAR"
            metadata["note"] = "TAR files may contain various file types"
        elif mime_type in ["application/x-7z-compressed", "application/x-7z"]:
            metadata["type"] = "7-Zip Archive"
            metadata["compression_method"] = "7Z"
            metadata["note"] = "7-Zip files may contain various file types"
        elif mime_type in ["application/x-bzip2", "application/x-bzip"]:
            metadata["type"] = "BZIP2 Archive"
            metadata["compression_method"] = "BZIP2"
            metadata["note"] = "BZIP2 files may contain various file types"
        elif mime_type in ["application/x-lzip", "application/x-lzma"]:
            metadata["type"] = "LZIP Archive"
            metadata["compression_method"] = "LZIP"
            metadata["note"] = "LZIP files may contain various file types"
        elif mime_type in ["application/x-xz", "application/x-xz-compressed"]:
            metadata["type"] = "XZ Archive"
            metadata["compression_method"] = "XZ"
            metadata["note"] = "XZ files may contain various file types"
        elif mime_type in ["application/x-zip-compressed", "application/x-zip"]:
            metadata["type"] = "ZIP Archive"
            metadata["compression_method"] = "ZIP"
            metadata["note"] = "ZIP files may contain various file types"

        # Add file hash to metadata if applicable
        if FORENSIC_CORE_AVAILABLE:
            try:
                file_hash = calculate_file_hash(file_path)
                metadata["hash"] = file_hash
            except Exception as e:
                logger.debug(f"Could not calculate hash for {file_path}: {e}")

        # Add basic file information
        metadata["file_name"] = os.path.basename(file_path)
        metadata["file_size"] = os.path.getsize(file_path)
        metadata["extension"] = file_ext
        metadata["mime_type"] = mime_type

        # Log the operation
        if FORENSIC_CORE_AVAILABLE:
            operation_details["metadata_fields"] = len(metadata)
            log_forensic_operation("extract_metadata_by_format", True, operation_details)

        return metadata

    except Exception as e:
        error_msg = f"Error extracting metadata from {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("extract_metadata_by_format", False,
                                  {**operation_details, "error": error_msg})
        return {"error": error_msg}


def analyze_script_file(file_path: str) -> Dict[str, Any]:
    """
    Analyze script files (Python, JavaScript, PowerShell, etc.) for potential indicators
    of malicious activity or security issues.

    Args:
        file_path: Path to the script file to analyze

    Returns:
        Dictionary containing analysis results
    """
    operation_details = {
        "file": file_path
    }

    try:
        # Validate input file
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("analyze_script_file", False,
                                     {**operation_details, "error": error_msg})
            return {"error": error_msg}

        # Identify file type
        file_ext = os.path.splitext(file_path)[1].lower()
        file_info = identify_file_type(file_path)

        # Ensure it's a text file that we can analyze
        if not file_info.get("is_text_file", False):
            error_msg = "Not a text-based script file"
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("analyze_script_file", False,
                                     {**operation_details, "error": error_msg})
            return {"error": error_msg}

        # Read file content
        with open(file_path, 'r', errors='replace') as f:
            content = f.read()

        # Initialize analysis results
        analysis = {
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "line_count": content.count('\n') + 1,
            "indicators": []
        }

        # Define suspicious patterns by language
        suspicious_patterns = {
            # Common patterns across languages
            "common": {
                "obfuscation": [r"eval\s*\(", r"base64", r"rot13", r"chr\s*\(", r"fromCharCode"],
                "execution": [r"exec\s*\(", r"system\s*\(", r"shell_exec", r"subprocess", r"popen"],
                "networking": [r"socket\s*\(", r"connect\s*\(", r"http[s]?://", r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"],
                "file_ops": [r"write", r"chmod", r"file_put_contents", r"FileOutputStream", r"CreateFile"]
            },
            # Python-specific patterns
            ".py": {
                "obfuscation": [r"__import__\s*\(", r"compile\s*\(", r"\\x[0-9a-f]{2}"],
                "execution": [r"os\.system", r"subprocess\.(?:call|Popen|run)", r"commands\.getoutput"],
                "persistence": [r"crontab", r"startup", r"@reboot"],
                "sensitive": [r"getpass", r"hashlib", r"pwd", r"os\.environ"]
            },
            # JavaScript-specific patterns
            ".js": {
                "obfuscation": [r"unescape\s*\(", r"String\.fromCharCode", r"\\u[0-9a-f]{4}"],
                "execution": [r"eval\s*\(", r"Function\s*\(", r"setTimeout\s*\(", r"setInterval\s*\("],
                "browser": [r"document\.(?:write|cookie|location)", r"window\.(?:open|location)"],
                "persistence": [r"localStorage", r"sessionStorage", r"navigator\."]
            },
            # PowerShell-specific patterns
            ".ps1": {
                "obfuscation": [r"-enc", r"-encodedcommand", r"-join", r"\$env:"],
                "execution": [r"Invoke-Expression", r"IEX", r"Invoke-Command", r"Start-Process"],
                "bypass": [r"bypass", r"-noprofile", r"-executionpolicy", r"-windowstyle hidden"],
                "download": [r"Net\.WebClient", r"Invoke-WebRequest", r"Start-BitsTransfer"]
            }
        }

        # Match patterns based on file extension
        pattern_sets = [suspicious_patterns["common"]]
        if file_ext in suspicious_patterns:
            pattern_sets.append(suspicious_patterns[file_ext])

        # Search for patterns
        for category_name, category_patterns in [(cat, patterns) for pattern_set in pattern_sets
                                                for cat, patterns in pattern_set.items()]:
            for pattern in category_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Get some context around the match
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.end())
                    if line_end == -1:
                        line_end = len(content)

                    line = content[line_start:line_end].strip()
                    line_num = content[:match.start()].count('\n') + 1

                    analysis["indicators"].append({
                        "type": category_name,
                        "pattern": pattern,
                        "line": line_num,
                        "content": line,
                        "offset": match.start()
                    })

        # Sort indicators by line number
        analysis["indicators"] = sorted(analysis["indicators"], key=lambda x: x["line"])

        # Add summary
        analysis["indicator_count"] = len(analysis["indicators"])
        analysis["categories"] = {}
        for indicator in analysis["indicators"]:
            category = indicator["type"]
            if category not in analysis["categories"]:
                analysis["categories"][category] = 0
            analysis["categories"][category] += 1

        # Determine risk level
        if analysis["indicator_count"] > 10:
            analysis["risk_level"] = "high"
        elif analysis["indicator_count"] > 5:
            analysis["risk_level"] = "medium"
        elif analysis["indicator_count"] > 0:
            analysis["risk_level"] = "low"
        else:
            analysis["risk_level"] = "info"

        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("analyze_script_file", True,
                                 {**operation_details, "indicators": analysis["indicator_count"],
                                  "risk_level": analysis["risk_level"]})

        return analysis

    except Exception as e:
        error_msg = f"Error analyzing script file {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("analyze_script_file", False,
                                 {**operation_details, "error": error_msg})
        return {"error": error_msg}


def detect_file_obfuscation(file_path: str) -> Dict[str, Any]:
    """
    Detect potential obfuscation techniques in a file by analyzing entropy,
    unusual character distributions, encoding markers, and other indicators.

    Args:
        file_path: Path to the file to analyze

    Returns:
        Dictionary containing obfuscation analysis results
    """
    operation_details = {
        "file": file_path
    }

    try:
        # Validate input file
        if not os.path.isfile(file_path):
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("detect_file_obfuscation", False,
                                     {**operation_details, "error": error_msg})
            return {"error": error_msg}

        # Get file type information
        file_info = identify_file_type(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()

        # Initialize results
        results = {
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "file_type": file_info.get("detected_type", "Unknown"),
            "obfuscation_indicators": [],
            "obfuscation_score": 0.0
        }

        # Calculate overall file entropy
        entropy = calculate_file_entropy(file_path)
        results["entropy"] = entropy

        # High entropy can indicate encryption, compression, or obfuscation
        if entropy > 7.5:
            results["obfuscation_indicators"].append({
                "type": "high_entropy",
                "description": "Very high entropy (7.5-8.0) suggesting encryption, compression, or obfuscation",
                "score_contribution": 0.8
            })
            results["obfuscation_score"] += 0.8
        elif entropy > 6.8:
            results["obfuscation_indicators"].append({
                "type": "elevated_entropy",
                "description": "Elevated entropy (6.8-7.5) suggesting possible obfuscation or compression",
                "score_contribution": 0.5
            })
            results["obfuscation_score"] += 0.5

        # For text files, perform additional checks
        if file_info.get("is_text_file", False):
            # Load the file content
            with open(file_path, 'r', errors='replace') as f:
                content = f.read()

            # Check for base64 encoded content
            base64_pattern = r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
            base64_matches = re.finditer(base64_pattern, content)
            long_base64_data = [m.group(0) for m in base64_matches if len(m.group(0)) > 100]

            if long_base64_data:
                results["obfuscation_indicators"].append({
                    "type": "base64_encoding",
                    "description": f"Found {len(long_base64_data)} long Base64-encoded strings",
                    "count": len(long_base64_data),
                    "score_contribution": 0.6
                })
                results["obfuscation_score"] += min(0.6, 0.1 * len(long_base64_data))

            # Check for hex-encoded content
            hex_pattern = r'(?:[0-9A-Fa-f]{2}){10,}'  # At least 20 hex chars (10 bytes)
            hex_matches = re.finditer(hex_pattern, content)
            long_hex_data = [m.group(0) for m in hex_matches if len(m.group(0)) > 40]

            if long_hex_data:
                results["obfuscation_indicators"].append({
                    "type": "hex_encoding",
                    "description": f"Found {len(long_hex_data)} hex-encoded data blocks",
                    "count": len(long_hex_data),
                    "score_contribution": 0.4
                })
                results["obfuscation_score"] += min(0.4, 0.1 * len(long_hex_data))

            # Check for escaped unicode or other character escaping
            escape_pattern = r'(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){5,}'
            escape_matches = re.finditer(escape_pattern, content)
            escaped_sequences = [m.group(0) for m in escape_matches]

            if escaped_sequences:
                results["obfuscation_indicators"].append({
                    "type": "character_escaping",
                    "description": f"Found {len(escaped_sequences)} escaped character sequences",
                    "count": len(escaped_sequences),
                    "score_contribution": 0.5
                })
                results["obfuscation_score"] += min(0.5, 0.1 * len(escaped_sequences))

            # Check for common obfuscation functions
            obfuscation_functions = [
                r'eval\s*\(', r'unescape\s*\(', r'atob\s*\(', r'decodeURI\s*\(',
                r'String\.fromCharCode', r'parseInt\s*\(.+?,\s*[0-9]+\s*\)'
            ]

            for pattern in obfuscation_functions:
                matches = re.findall(pattern, content)
                if matches:
                    results["obfuscation_indicators"].append({
                        "type": "obfuscation_function",
                        "description": f"Found {len(matches)} instances of obfuscation function pattern: {pattern}",
                        "pattern": pattern,
                        "count": len(matches),
                        "score_contribution": 0.7
                    })
                    results["obfuscation_score"] += min(0.7, 0.15 * len(matches))

        # Cap the score at 1.0
        results["obfuscation_score"] = min(1.0, results["obfuscation_score"])

        # Add a summary assessment
        if results["obfuscation_score"] > 0.8:
            results["assessment"] = "High likelihood of obfuscation"
        elif results["obfuscation_score"] > 0.5:
            results["assessment"] = "Moderate likelihood of obfuscation"
        elif results["obfuscation_score"] > 0.2:
            results["assessment"] = "Some indicators of obfuscation"
        else:
            results["assessment"] = "No significant indicators of obfuscation"

        # Log operation
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("detect_file_obfuscation", True,
                                 {**operation_details, "score": results["obfuscation_score"],
                                  "indicators": len(results["obfuscation_indicators"])})

        return results

    except Exception as e:
        error_msg = f"Error analyzing file for obfuscation {file_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("detect_file_obfuscation", False,
                                 {**operation_details, "error": error_msg})
        return {"error": error_msg}


def compare_files_forensically(file_path1: str, file_path2: str) -> Dict[str, Any]:
    """
    Perform a forensic comparison of two files, identifying similarities and differences
    in content, metadata, and structure.

    Args:
        file_path1: Path to the first file
        file_path2: Path to the second file

    Returns:
        Dictionary containing comparison results
    """
    operation_details = {
        "file1": file_path1,
        "file2": file_path2
    }

    try:
        # Validate input files
        if not os.path.isfile(file_path1):
            error_msg = f"First file not found: {file_path1}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("compare_files_forensically", False,
                                     {**operation_details, "error": error_msg})
            return {"error": error_msg}

        if not os.path.isfile(file_path2):
            error_msg = f"Second file not found: {file_path2}"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("compare_files_forensically", False,
                                     {**operation_details, "error": error_msg})
            return {"error": error_msg}

        # Get file metadata
        if FORENSIC_CORE_AVAILABLE:
            metadata1 = get_file_metadata(file_path1, include_extended=True)
            metadata2 = get_file_metadata(file_path2, include_extended=True)
        else:
            # Basic metadata
            stat1 = os.stat(file_path1)
            stat2 = os.stat(file_path2)
            metadata1 = {
                "size": stat1.st_size,
                "modified": datetime.fromtimestamp(stat1.st_mtime, timezone.utc).isoformat()
            }
            metadata2 = {
                "size": stat2.st_size,
                "modified": datetime.fromtimestamp(stat2.st_mtime, timezone.utc).isoformat()
            }

        # Get file hashes
        if FORENSIC_CORE_AVAILABLE:
            hash1 = calculate_file_hash(file_path1)
            hash2 = calculate_file_hash(file_path2)
        else:
            # Calculate hashes directly
            import hashlib

            sha256_1 = hashlib.sha256()
            with open(file_path1, "rb") as f:
                for byte_block in iter(lambda: f.read(DEFAULT_READ_CHUNK_SIZE), b""):
                    sha256_1.update(byte_block)
            hash1 = sha256_1.hexdigest()

            sha256_2 = hashlib.sha256()
            with open(file_path2, "rb") as f:
                for byte_block in iter(lambda: f.read(DEFAULT_READ_CHUNK_SIZE), b""):
                    sha256_2.update(byte_block)
            hash2 = sha256_2.hexdigest()

        # Initialize comparison results
        results = {
            "file1": {
                "path": file_path1,
                "size": os.path.getsize(file_path1),
                "hash": hash1
            },
            "file2": {
                "path": file_path2,
                "size": os.path.getsize(file_path2),
                "hash": hash2
            },
            "identical": hash1 == hash2,
            "size_match": os.path.getsize(file_path1) == os.path.getsize(file_path2),
            "metadata_differences": {}
        }

        # Compare metadata
        metadata_keys = set(metadata1.keys()) | set(metadata2.keys())
        for key in metadata_keys:
            if key in metadata1 and key in metadata2:
                if metadata1[key] != metadata2[key]:
                    results["metadata_differences"][key] = {
                        "file1": metadata1[key],
                        "file2": metadata2[key]
                    }

        # If files are identical, no need for detailed comparison
        if results["identical"]:
            results["comparison_summary"] = "Files are identical (same hash)"

            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("compare_files_forensically", True,
                                     {**operation_details, "identical": True})
            return results

        # For binary files, do a rolling comparison to find where they differ
        size1 = os.path.getsize(file_path1)
        size2 = os.path.getsize(file_path2)
        min_size = min(size1, size2)

        # Compare chunks to find first difference
        with open(file_path1, 'rb') as f1, open(file_path2, 'rb') as f2:
            chunk_size = 4096
            offset = 0
            first_diff = None

            while offset < min_size:
                chunk1 = f1.read(chunk_size)
                chunk2 = f2.read(chunk_size)

                if chunk1 != chunk2:
                    # Find the exact byte where they differ
                    for i, (b1, b2) in enumerate(zip(chunk1, chunk2)):
                        if b1 != b2:
                            first_diff = {
                                "offset": offset + i,
                                "byte1": hex(b1),
                                "byte2": hex(b2)
                            }
                            break

                    if first_diff:
                        break

                offset += len(chunk1)

        results["first_difference"] = first_diff or {"offset": min_size}

        # Determine similarity percentage
        if max(size1, size2) > 0:
            non_matching_bytes = max(size1, size2) - (first_diff["offset"] if first_diff else min_size)
            similarity = 1 - (non_matching_bytes / max(size1, size2))
            results["similarity_percentage"] = round(similarity * 100, 2)
        else:
            results["similarity_percentage"] = 0

        # Text-based analysis if both are text files
        try:
            # Try to read both as text to see if they're text files
            with open(file_path1, 'r', errors='replace') as f1:
                text1 = f1.read()
            with open(file_path2, 'r', errors='replace') as f2:
                text2 = f2.read()

            # Count lines for each file
            lines1 = text1.splitlines()
            lines2 = text2.splitlines()

            results["text_comparison"] = {
                "line_count1": len(lines1),
                "line_count2": len(lines2),
                "different_line_count": sum(1 for i, (l1, l2) in enumerate(zip(lines1, lines2)) if l1 != l2),
                "added_line_count": max(0, len(lines2) - len(lines1)),
                "removed_line_count": max(0, len(lines1) - len(lines2))
            }

            # Add first line number that differs
            for i, (l1, l2) in enumerate(zip(lines1, lines2)):
                if l1 != l2:
                    results["text_comparison"]["first_different_line"] = i + 1
                    break
            else:
                # All common lines match, difference is in the line count
                if len(lines1) != len(lines2):
                    results["text_comparison"]["first_different_line"] = min(len(lines1), len(lines2)) + 1

        except UnicodeDecodeError:
            # Files aren't text files, skip text comparison
            pass

        # Add summary assessment
        if results["similarity_percentage"] > 95:
            results["comparison_summary"] = "Files are highly similar but not identical"
        elif results["similarity_percentage"] > 80:
            results["comparison_summary"] = "Files have significant similarities"
        elif results["similarity_percentage"] > 50:
            results["comparison_summary"] = "Files have moderate similarities"
        else:
            results["comparison_summary"] = "Files are mostly different"

        # Log operation
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("compare_files_forensically", True,
                                 {**operation_details, "identical": results["identical"],
                                  "similarity": results["similarity_percentage"]})

        return results

    except Exception as e:
        error_msg = f"Error comparing files {file_path1} and {file_path2}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("compare_files_forensically", False,
                                 {**operation_details, "error": error_msg})
        return {"error": error_msg}


def save_analysis_report(analysis_data: Dict[str, Any],
                        output_path: str,
                        format: str = "json") -> bool:
    """
    Save analysis results to a file in the specified format.

    Args:
        analysis_data: Analysis data to save
        output_path: Path where the report will be saved
        format: Output format ('json', 'text', or 'yaml')

    Returns:
        True if successfully saved, False otherwise
    """
    operation_details = {
        "output_path": output_path,
        "format": format
    }

    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # Save in requested format
        if format.lower() == "json":
            with open(output_path, 'w') as f:
                json.dump(analysis_data, f, indent=2, default=str)
        elif format.lower() == "text":
            with open(output_path, 'w') as f:
                # Recursively convert dict to text
                def dict_to_text(data, indent=0):
                    text = ""
                    if isinstance(data, dict):
                        for key, value in data.items():
                            if isinstance(value, (dict, list)):
                                text += "  " * indent + f"{key}:\n"
                                text += dict_to_text(value, indent + 1)
                            else:
                                text += "  " * indent + f"{key}: {value}\n"
                    elif isinstance(data, list):
                        for i, item in enumerate(data):
                            if isinstance(item, (dict, list)):
                                text += "  " * indent + f"[{i}]:\n"
                                text += dict_to_text(item, indent + 1)
                            else:
                                text += "  " * indent + f"[{i}]: {item}\n"
                    return text

                f.write(dict_to_text(analysis_data))
        elif format.lower() == "yaml":
            try:
                import yaml
                with open(output_path, 'w') as f:
                    yaml.dump(analysis_data, f, default_flow_style=False, sort_keys=False)
            except ImportError:
                error_msg = "YAML format requested but PyYAML not available"
                logger.error(error_msg)
                if FORENSIC_CORE_AVAILABLE:
                    log_forensic_operation("save_analysis_report", False,
                                         {**operation_details, "error": error_msg})
                return False
        else:
            error_msg = f"Unsupported format: {format}, use 'json', 'text', or 'yaml'"
            logger.error(error_msg)
            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation("save_analysis_report", False,
                                     {**operation_details, "error": error_msg})
            return False

        # Log operation
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("save_analysis_report", True, operation_details)

        return True

    except Exception as e:
        error_msg = f"Error saving analysis report to {output_path}: {str(e)}"
        logger.error(error_msg)
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("save_analysis_report", False,
                                 {**operation_details, "error": error_msg})
        return False


# Self-test function for direct script execution
def _self_test():
    """Run self-tests when file_utils.py is executed directly."""
    print("Running file_utils.py self-tests...")

    # Create a temporary test file
    test_text = """
    This is a test file for the static analysis utilities.
    It contains some potentially suspicious patterns:

    exec("echo 'hello'")
    eval(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))
    socket.connect(("malicious.com", 1234))

    System.fromCharCode(99, 111, 110, 110, 101, 99, 116)
    """

    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp:
        temp.write(test_text.encode('utf-8'))
        test_file = temp.name

    print(f"Created test file: {test_file}")

    try:
        # Test file identification
        print("\n--- Testing identify_file_type ---")
        file_type = identify_file_type(test_file)
        print(f"File type: {file_type}")

        # Test script analysis
        print("\n--- Testing analyze_script_file ---")
        script_analysis = analyze_script_file(test_file)
        print(f"Script analysis found {script_analysis.get('indicator_count', 0)} indicators")
        print(f"Risk level: {script_analysis.get('risk_level', 'unknown')}")

        # Test string extraction
        print("\n--- Testing extract_file_strings ---")
        strings = extract_file_strings(test_file, min_length=5)
        print(f"Extracted {len(strings)} strings")

        # Test entropy calculation
        print("\n--- Testing calculate_file_entropy ---")
        entropy = calculate_file_entropy(test_file)
        print(f"File entropy: {entropy}")

        # Test obfuscation detection
        print("\n--- Testing detect_file_obfuscation ---")
        obfuscation = detect_file_obfuscation(test_file)
        print(f"Obfuscation score: {obfuscation.get('obfuscation_score', 0)}")
        print(f"Assessment: {obfuscation.get('assessment', 'unknown')}")

        # Test saving analysis results
        print("\n--- Testing save_analysis_report ---")
        report_path = os.path.join(tempfile.gettempdir(), "analysis_report.json")
        saved = save_analysis_report(script_analysis, report_path)
        print(f"Report saved to {report_path}: {saved}")

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
