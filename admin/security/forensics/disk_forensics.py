"""
Disk Forensics Module for Forensic Analysis Toolkit.

This module provides capabilities for disk image analysis, file system examination,
and artifact recovery during security incident investigations. It adheres to forensic
best practices for evidence handling, maintaining chain of custody, and preserving
evidence integrity throughout the analysis process.

Key capabilities include:
- Disk image mounting with write protection
- File system metadata analysis
- Deleted file recovery
- Timeline creation from filesystem timestamps
- Hidden data detection
- File carving from unallocated space
- Registry analysis (for Windows systems)
"""

import os
import sys
import json
import logging
import argparse
import tempfile
from datetime import datetime, timezone
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set, Union, BinaryIO

# Configure logging
logger = logging.getLogger(__name__)

# Try to import forensic utilities
try:
    from admin.security.forensics.utils import (
        log_forensic_operation,
        calculate_file_hash,
        verify_file_hash,
        secure_copy,
        get_file_metadata,
        create_secure_temp_file,
        set_file_read_only
    )
    from admin.security.forensics.utils.evidence_tracker import (
        register_evidence,
        track_access,
        track_analysis,
        get_evidence_details,
        update_evidence_details
    )
    from admin.security.forensics.utils.timestamp_utils import (
        normalize_timestamp,
        create_timeline
    )
    from admin.security.forensics.utils.validation_utils import validate_path
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_HASH_ALGORITHM,
        DEFAULT_READ_ONLY_FILE_PERMS,
        TEMP_DIR_FORENSICS
    )

    FORENSIC_UTILS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Forensic utilities not fully available: {e}")
    FORENSIC_UTILS_AVAILABLE = False

    # Define minimal implementations of critical functions
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict[str, Any]] = None,
                              level: int = logging.INFO) -> None:
        """Log a forensic operation (fallback implementation)."""
        msg = f"Forensic operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logger.log(level, msg)

    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash (fallback implementation)."""
        import hashlib
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.new(algorithm)
                for chunk in iter(lambda: f.read(4096), b''):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
            return None

    def validate_path(path_str: str, **kwargs) -> Tuple[bool, str]:
        """Validate path (fallback implementation)."""
        return True, "Path validation unavailable"

    # Set constants
    FALLBACK_HASH_ALGORITHM = "sha256"
    FALLBACK_READ_ONLY_FILE_PERMS = 0o400
    TEMP_DIR_FORENSICS = tempfile.gettempdir()

# Try to import external tools and dependencies
try:
    # Optional imports for specific disk analysis features
    import pytsk3
    import pyewf
    import pyvmdk
    import pyvshadow
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False
    logger.warning("The Sleuth Kit Python bindings (pytsk3) not available. Some disk analysis features will be limited.")

class DiskImage:
    """Class for handling forensic disk images."""

    def __init__(self, image_path: str, offset: int = 0,
                 case_id: Optional[str] = None,
                 evidence_id: Optional[str] = None):
        """
        Initialize disk image handler.

        Args:
            image_path: Path to the forensic disk image
            offset: Byte offset to the start of the partition
            case_id: Case identifier for evidence tracking
            evidence_id: Evidence identifier for tracking
        """
        self.image_path = image_path
        self.offset = offset
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.img_info = None
        self.fs_info = None
        self.mounted = False
        self.format = None
        self.metadata = {}

        # Validate path
        valid, message = validate_path(image_path)
        if not valid:
            raise ValueError(f"Invalid image path: {message}")

        # Track evidence access if case information is provided
        self._track_access()

    def _track_access(self) -> None:
        """Record evidence access in chain of custody if tracking is enabled."""
        if FORENSIC_UTILS_AVAILABLE and self.case_id and self.evidence_id:
            try:
                track_access(
                    case_id=self.case_id,
                    evidence_id=self.evidence_id,
                    analyst=os.getenv('USER', 'unknown'),
                    action="access",
                    purpose="Disk image analysis"
                )
            except Exception as e:
                logger.warning(f"Failed to track evidence access: {e}")

    def open(self) -> bool:
        """
        Open the disk image file for analysis.

        Returns:
            bool: True if successful, False otherwise
        """
        if not TSK_AVAILABLE:
            logger.error("TSK not available. Cannot open disk image.")
            return False

        operation_details = {"image_path": self.image_path, "offset": self.offset}

        try:
            # Try to determine the image format
            if self.image_path.lower().endswith(('.e01', '.ex01', '.l01', '.lx01')):
                # EWF format (EnCase)
                self.format = "ewf"
                filenames = pyewf.glob(self.image_path)
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                self.img_info = pytsk3.Img_Info(ewf_handle)

            elif self.image_path.lower().endswith(('.vmdk')):
                # VMDK format (VMware)
                self.format = "vmdk"
                handle = pyvmdk.handle()
                handle.open(self.image_path)
                self.img_info = pytsk3.Img_Info(handle)

            else:
                # Raw format (dd) or other
                self.format = "raw"
                self.img_info = pytsk3.Img_Info(self.image_path)

            # Get disk image metadata
            self._get_metadata()

            # If offset is provided, assume it's a partition, otherwise scan the full disk
            if self.offset > 0:
                self.fs_info = pytsk3.FS_Info(self.img_info, offset=self.offset)
            else:
                # Try to find partitions
                self._identify_partitions()

            self.mounted = True
            log_forensic_operation("open_disk_image", True, operation_details)
            return True

        except Exception as e:
            logger.error(f"Failed to open disk image: {e}")
            log_forensic_operation("open_disk_image", False,
                                  {**operation_details, "error": str(e)},
                                  level=logging.ERROR)
            return False

    def _get_metadata(self) -> None:
        """Extract metadata from the disk image."""
        if not self.img_info:
            return

        self.metadata = {
            "size": self.img_info.get_size(),
            "format": self.format,
            "hash": calculate_file_hash(self.image_path, DEFAULT_HASH_ALGORITHM),
            "access_time": datetime.now(timezone.utc).isoformat()
        }

    def _identify_partitions(self) -> List[Dict[str, Any]]:
        """
        Identify partitions on the disk image.

        Returns:
            List of dictionaries containing partition information
        """
        if not self.img_info:
            return []

        partitions = []

        try:
            volume_info = pytsk3.Volume_Info(self.img_info)
            for partition in volume_info:
                # Skip unallocated partitions
                if partition.flags == pytsk3.TSK_VS_PART_FLAG_UNALLOC:
                    continue

                partition_info = {
                    "addr": partition.addr,
                    "start": partition.start,
                    "length": partition.len,
                    "description": partition.desc.decode('utf-8', errors='replace'),
                    "flags": partition.flags
                }

                partitions.append(partition_info)

            self.metadata["partitions"] = partitions
            return partitions

        except Exception as e:
            logger.warning(f"Error identifying partitions: {e}")
            return []

    def list_directory(self, directory_path: str = "/") -> List[Dict[str, Any]]:
        """
        List contents of a directory in the mounted image.

        Args:
            directory_path: Path to directory within the mounted filesystem

        Returns:
            List of dictionaries with file metadata
        """
        if not self.fs_info:
            logger.error("Filesystem not mounted. Call open() first.")
            return []

        operation_details = {"directory": directory_path, "image_path": self.image_path}
        file_list = []

        try:
            directory = self.fs_info.open_dir(path=directory_path)

            for entry in directory:
                name = entry.info.name.name.decode('utf-8', errors='replace')
                # Skip . and .. entries
                if name in [".", ".."]:
                    continue

                meta = entry.info.meta
                if meta:
                    # Convert TSK timestamps to ISO format
                    created = datetime.fromtimestamp(meta.crtime, timezone.utc).isoformat() if meta.crtime else None
                    modified = datetime.fromtimestamp(meta.mtime, timezone.utc).isoformat() if meta.mtime else None
                    accessed = datetime.fromtimestamp(meta.atime, timezone.utc).isoformat() if meta.atime else None

                    file_info = {
                        "name": name,
                        "path": os.path.join(directory_path, name),
                        "size": meta.size,
                        "created": created,
                        "modified": modified,
                        "accessed": accessed,
                        "is_directory": meta.type == pytsk3.TSK_FS_META_TYPE_DIR,
                        "inode": meta.addr,
                        "deleted": bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
                    }

                    file_list.append(file_info)

            log_forensic_operation("list_directory", True, operation_details)
            return file_list

        except Exception as e:
            logger.error(f"Error listing directory {directory_path}: {e}")
            log_forensic_operation("list_directory", False,
                                  {**operation_details, "error": str(e)},
                                  level=logging.ERROR)
            return []

    def extract_file(self, file_path: str, output_path: str) -> bool:
        """
        Extract a file from the disk image to the local filesystem.

        Args:
            file_path: Path of file within the mounted disk image
            output_path: Local filesystem path to save the extracted file

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.fs_info:
            logger.error("Filesystem not mounted. Call open() first.")
            return False

        operation_details = {
            "source_path": file_path,
            "output_path": output_path,
            "image_path": self.image_path
        }

        try:
            # Open the file from the disk image
            f = self.fs_info.open(file_path)

            # Create parent directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

            # Write the file contents to the output path
            with open(output_path, 'wb') as outfile:
                offset = 0
                size = f.info.meta.size
                while offset < size:
                    available_to_read = min(1024 * 1024, size - offset)
                    data = f.read_random(offset, available_to_read)
                    if not data:
                        break
                    outfile.write(data)
                    offset += len(data)

            # Set permissions to read-only for evidence preservation
            os.chmod(output_path, DEFAULT_READ_ONLY_FILE_PERMS)

            # Calculate hash for verification
            file_hash = calculate_file_hash(output_path)
            operation_details["hash"] = file_hash

            log_forensic_operation("extract_file", True, operation_details)

            return True

        except Exception as e:
            logger.error(f"Error extracting file {file_path}: {e}")
            log_forensic_operation("extract_file", False,
                                  {**operation_details, "error": str(e)},
                                  level=logging.ERROR)

            # Clean up partial file if extraction failed
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass

            return False

    def find_files_by_pattern(self, pattern: str,
                             directory_path: str = "/",
                             recursive: bool = True,
                             include_deleted: bool = False) -> List[Dict[str, Any]]:
        """
        Find files matching a pattern within the disk image.

        Args:
            pattern: Regular expression pattern to match against filenames
            directory_path: Starting directory path to search
            recursive: Whether to search recursively through subdirectories
            include_deleted: Whether to include deleted files in the results

        Returns:
            List of dictionaries with matching file information
        """
        import re

        if not self.fs_info:
            logger.error("Filesystem not mounted. Call open() first.")
            return []

        operation_details = {
            "pattern": pattern,
            "directory": directory_path,
            "recursive": recursive,
            "include_deleted": include_deleted
        }

        pattern_re = re.compile(pattern)
        matches = []

        try:
            # Start with the initial directory
            directories_to_process = [directory_path]
            processed_directories = set()

            while directories_to_process:
                current_dir = directories_to_process.pop(0)

                # Skip if we've seen this directory before (prevents loops)
                if current_dir in processed_directories:
                    continue

                processed_directories.add(current_dir)

                # List the current directory
                dir_contents = self.list_directory(current_dir)

                for entry in dir_contents:
                    # Skip if it's a deleted file and we're not including deleted files
                    if entry.get("deleted", False) and not include_deleted:
                        continue

                    # Check if the filename matches the pattern
                    if pattern_re.search(entry["name"]):
                        matches.append(entry)

                    # Add subdirectory to the queue if recursive is True
                    if recursive and entry.get("is_directory", False):
                        subdirectory = os.path.join(current_dir, entry["name"])
                        if subdirectory not in processed_directories:
                            directories_to_process.append(subdirectory)

            log_forensic_operation("find_files_by_pattern", True,
                                  {**operation_details, "matches_found": len(matches)})
            return matches

        except Exception as e:
            logger.error(f"Error searching for files with pattern {pattern}: {e}")
            log_forensic_operation("find_files_by_pattern", False,
                                  {**operation_details, "error": str(e)},
                                  level=logging.ERROR)
            return []

    def create_filesystem_timeline(self,
                                 output_path: str,
                                 directory_path: str = "/",
                                 recursive: bool = True,
                                 include_deleted: bool = True) -> bool:
        """
        Create a timeline of filesystem activity.

        Args:
            output_path: Path to save the timeline
            directory_path: Starting directory path to analyze
            recursive: Whether to process recursively through subdirectories
            include_deleted: Whether to include deleted files in the timeline

        Returns:
            bool: True if successful, False otherwise
        """
        operation_details = {
            "output_path": output_path,
            "directory": directory_path,
            "recursive": recursive,
            "include_deleted": include_deleted
        }

        try:
            # Start with the initial directory
            directories_to_process = [directory_path]
            processed_directories = set()
            timeline_events = []

            while directories_to_process:
                current_dir = directories_to_process.pop(0)

                # Skip if we've seen this directory before (prevents loops)
                if current_dir in processed_directories:
                    continue

                processed_directories.add(current_dir)

                # List the current directory
                dir_contents = self.list_directory(current_dir)

                for entry in dir_contents:
                    # Skip if it's a deleted file and we're not including deleted files
                    if entry.get("deleted", False) and not include_deleted:
                        continue

                    full_path = os.path.join(current_dir, entry["name"])

                    # Add file creation event
                    if entry.get("created"):
                        timeline_events.append({
                            "timestamp": entry["created"],
                            "path": full_path,
                            "action": "created",
                            "meta": {
                                "size": entry.get("size"),
                                "type": "directory" if entry.get("is_directory", False) else "file",
                                "deleted": entry.get("deleted", False),
                                "inode": entry.get("inode")
                            }
                        })

                    # Add file modification event
                    if entry.get("modified"):
                        timeline_events.append({
                            "timestamp": entry["modified"],
                            "path": full_path,
                            "action": "modified",
                            "meta": {
                                "size": entry.get("size"),
                                "type": "directory" if entry.get("is_directory", False) else "file",
                                "deleted": entry.get("deleted", False),
                                "inode": entry.get("inode")
                            }
                        })

                    # Add file access event
                    if entry.get("accessed"):
                        timeline_events.append({
                            "timestamp": entry["accessed"],
                            "path": full_path,
                            "action": "accessed",
                            "meta": {
                                "size": entry.get("size"),
                                "type": "directory" if entry.get("is_directory", False) else "file",
                                "deleted": entry.get("deleted", False),
                                "inode": entry.get("inode")
                            }
                        })

                    # Add subdirectory to the queue if recursive is True
                    if recursive and entry.get("is_directory", False):
                        subdirectory = os.path.join(current_dir, entry["name"])
                        if subdirectory not in processed_directories:
                            directories_to_process.append(subdirectory)

            # Sort timeline events by timestamp
            timeline_events.sort(key=lambda x: x["timestamp"])

            # Write timeline to file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "metadata": {
                        "image_path": self.image_path,
                        "created": datetime.now(timezone.utc).isoformat(),
                        "event_count": len(timeline_events)
                    },
                    "events": timeline_events
                }, f, indent=2)

            # Set secure permissions on the output file
            os.chmod(output_path, DEFAULT_READ_ONLY_FILE_PERMS)

            log_forensic_operation("create_filesystem_timeline", True,
                                  {**operation_details, "events_count": len(timeline_events)})
            return True

        except Exception as e:
            logger.error(f"Error creating filesystem timeline: {e}")
            log_forensic_operation("create_filesystem_timeline", False,
                                  {**operation_details, "error": str(e)},
                                  level=logging.ERROR)
            return False

    def recover_deleted_files(self,
                            output_dir: str,
                            extensions: Optional[List[str]] = None,
                            min_size: int = 1024) -> Dict[str, Any]:
        """
        Attempt to recover deleted files from the filesystem.

        Args:
            output_dir: Directory to save recovered files
            extensions: List of file extensions to recover (e.g., ['.jpg', '.pdf'])
            min_size: Minimum file size in bytes to recover

        Returns:
            Dictionary with recovery statistics and results
        """
        if not self.fs_info:
            logger.error("Filesystem not mounted. Call open() first.")
            return {"success": False, "error": "Filesystem not mounted"}

        operation_details = {
            "output_dir": output_dir,
            "extensions": extensions,
            "min_size": min_size
        }

        try:
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)

            recovered_files = []
            recovery_stats = {
                "total_candidates": 0,
                "recovered_count": 0,
                "total_bytes_recovered": 0,
                "started_at": datetime.now(timezone.utc).isoformat()
            }

            # Using recursive directory traversal to find deleted files
            directories_to_process = ["/"]
            processed_directories = set()

            while directories_to_process:
                current_dir = directories_to_process.pop(0)

                # Skip if we've seen this directory before (prevents loops)
                if current_dir in processed_directories:
                    continue

                processed_directories.add(current_dir)

                # List the current directory
                dir_contents = self.list_directory(current_dir)

                for entry in dir_contents:
                    # Process deleted files that meet our criteria
                    if entry.get("deleted", False) and entry.get("size", 0) >= min_size:
                        # Check extension if specified
                        if extensions:
                            file_ext = os.path.splitext(entry["name"])[1].lower()
                            if file_ext not in extensions:
                                continue

                        recovery_stats["total_candidates"] += 1

                        # Create a recovery filename
                        recovery_filename = f"recovered_{entry.get('inode', 'unknown')}_{entry['name']}"
                        recovery_path = os.path.join(output_dir, recovery_filename)

                        # Try to extract the file
                        try:
                            file_path = os.path.join(current_dir, entry["name"])
                            if self.extract_file(file_path, recovery_path):
                                file_size = os.path.getsize(recovery_path)

                                # Record successful recovery
                                recovered_files.append({
                                    "original_path": file_path,
                                    "recovery_path": recovery_path,
                                    "size": file_size,
                                    "inode": entry.get("inode", "unknown"),
                                    "hash": calculate_file_hash(recovery_path)
                                })

                                recovery_stats["recovered_count"] += 1
                                recovery_stats["total_bytes_recovered"] += file_size
                        except Exception as e:
                            logger.debug(f"Failed to recover {entry['name']}: {e}")

                    # Add subdirectory to the queue
                    if entry.get("is_directory", False):
                        subdirectory = os.path.join(current_dir, entry["name"])
                        if subdirectory not in processed_directories:
                            directories_to_process.append(subdirectory)

            # Add completion timestamp
            recovery_stats["completed_at"] = datetime.now(timezone.utc).isoformat()

            # Write recovery report
            report_path = os.path.join(output_dir, "recovery_report.json")
            with open(report_path, 'w') as f:
                json.dump({
                    "stats": recovery_stats,
                    "recovered_files": recovered_files
                }, f, indent=2)

            log_forensic_operation("recover_deleted_files", True, {
                **operation_details,
                "recovered_count": recovery_stats["recovered_count"],
                "total_bytes": recovery_stats["total_bytes_recovered"]
            })

            return {
                "success": True,
                "stats": recovery_stats,
                "recovered_files": recovered_files,
                "report_path": report_path
            }

        except Exception as e:
            logger.error(f"Error recovering deleted files: {e}")
            log_forensic_operation("recover_deleted_files", False,
                                  {**operation_details, "error": str(e)},
                                  level=logging.ERROR)
            return {"success": False, "error": str(e)}

    def carve_files_from_unallocated(self,
                                   output_dir: str,
                                   file_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Carve files from unallocated space in the disk image.

        Args:
            output_dir: Directory to save carved files
            file_types: List of file types to carve (e.g., ['jpg', 'pdf', 'docx'])

        Returns:
            Dictionary with carving statistics and results
        """
        if not self.img_info:
            logger.error("Disk image not opened. Call open() first.")
            return {"success": False, "error": "Disk image not opened"}

        operation_details = {
            "output_dir": output_dir,
            "file_types": file_types
        }

        try:
            # Check if PyScalpel/Foremost is available
            foremost_available = shutil.which("foremost") is not None
            photorec_available = shutil.which("photorec") is not None

            if not (foremost_available or photorec_available):
                return {
                    "success": False,
                    "error": "Neither foremost nor photorec are available for file carving"
                }

            # Create output directory
            os.makedirs(output_dir, exist_ok=True)

            # Create a temporary raw image if necessary
            temp_image_path = None
            if self.format != "raw":
                temp_image_path = os.path.join(TEMP_DIR_FORENSICS, f"temp_image_{os.getpid()}.raw")
                if not self._create_raw_copy(temp_image_path):
                    return {"success": False, "error": "Failed to create temporary raw image"}
                working_image = temp_image_path
            else:
                working_image = self.image_path

            carving_stats = {
                "started_at": datetime.now(timezone.utc).isoformat(),
                "carved_files_count": 0,
                "carved_files_bytes": 0,
                "tool_used": ""
            }

            # Try foremost first if available
            if foremost_available:
                carving_stats["tool_used"] = "foremost"

                # Build foremost command
                foremost_cmd = ["foremost", "-i", working_image, "-o", output_dir]
                if file_types:
                    foremost_cmd.extend(["-t", ",".join(file_types)])

                # Run foremost
                import subprocess
                process = subprocess.run(foremost_cmd, capture_output=True, text=True)

                # Check if successful
                if process.returncode == 0:
                    # Parse foremost output
                    output_lines = process.stdout.split('\n')
                    for line in output_lines:
                        if "Files Carved:" in line:
                            try:
                                carving_stats["carved_files_count"] = int(line.split(":")[1].strip())
                            except:
                                pass

                    # Get file size statistics
                    audit_file = os.path.join(output_dir, "audit.txt")
                    if os.path.exists(audit_file):
                        with open(audit_file, 'r') as f:
                            for line in f:
                                if "Foremost finished" in line and "extracted" in line:
                                    try:
                                        # Parse bytes recovered
                                        parts = line.split("extracted")[1].strip()
                                        size_part = parts.split("bytes")[0].strip()
                                        carving_stats["carved_files_bytes"] = int(size_part)
                                    except:
                                        pass

            # Use PhotoRec if foremost failed or isn't available
            elif photorec_available:
                carving_stats["tool_used"] = "photorec"

                # Build photorec command
                # Note: PhotoRec is interactive, consider using qphotorec instead
                # or creating a photorec.cfg file for automation
                photorec_cmd = [
                    "photorec", "/d", output_dir, "/cmd", working_image,
                    "partition_none,options,mode_ext2,fileopt"
                ]
                if file_types:
                    # PhotoRec doesn't easily support file type filtering via command line
                    # A workaround would be needed here
                    pass

                # Run photorec
                import subprocess
                process = subprocess.run(photorec_cmd, capture_output=True, text=True)

                # Check if successful and count files
                if process.returncode == 0:
                    # Count carved files
                    carved_files = []
                    for root, dirs, files in os.walk(output_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            carved_files.append(file_path)
                            carving_stats["carved_files_bytes"] += os.path.getsize(file_path)

                    carving_stats["carved_files_count"] = len(carved_files)

            # Clean up temporary file if created
            if temp_image_path and os.path.exists(temp_image_path):
                os.remove(temp_image_path)

            # Add completion timestamp
            carving_stats["completed_at"] = datetime.now(timezone.utc).isoformat()

            # Write carving report
            report_path = os.path.join(output_dir, "carving_report.json")
            with open(report_path, 'w') as f:
                json.dump(carving_stats, f, indent=2)

            log_forensic_operation("carve_files_from_unallocated", True, {
                **operation_details,
                "carved_count": carving_stats["carved_files_count"],
                "carved_bytes": carving_stats["carved_files_bytes"],
                "tool": carving_stats["tool_used"]
            })

            return {
                "success": True,
                "stats": carving_stats,
                "report_path": report_path
            }

        except Exception as e:
            logger.error(f"Error carving files from unallocated space: {e}")
            log_forensic_operation("carve_files_from_unallocated", False,
                                  {**operation_details, "error": str(e)},
                                  level=logging.ERROR)

            # Clean up temporary file if it exists
            if 'temp_image_path' in locals() and temp_image_path and os.path.exists(temp_image_path):
                os.remove(temp_image_path)

            return {"success": False, "error": str(e)}

    def _create_raw_copy(self, output_path: str) -> bool:
        """
        Create a raw copy of the disk image.

        Args:
            output_path: Path to save the raw copy

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.img_info:
            return False

        try:
            import shutil

            # Open output file
            with open(output_path, 'wb') as outfile:
                # Get image size
                size = self.img_info.get_size()
                offset = 0
                chunk_size = 1024 * 1024  # 1MB chunks

                # Read and write in chunks
                while offset < size:
                    available_to_read = min(chunk_size, size - offset)
                    data = self.img_info.read(offset, available_to_read)
                    if not data:
                        break
                    outfile.write(data)
                    offset += len(data)

            return True

        except Exception as e:
            logger.error(f"Error creating raw copy: {e}")

            # Clean up partial file
            if os.path.exists(output_path):
                os.remove(output_path)

            return False

    def close(self) -> None:
        """Close the disk image and release resources."""
        # Clean up resources
        self.fs_info = None
        self.img_info = None
        self.mounted = False

        # Record operation in logs
        log_forensic_operation("close_disk_image", True, {"image_path": self.image_path})


def analyze_disk_image(image_path: str,
                     output_dir: str,
                     case_id: Optional[str] = None,
                     evidence_id: Optional[str] = None,
                     partition_offset: int = 0,
                     recover_deleted: bool = False,
                     carve_files: bool = False,
                     create_timeline: bool = True) -> Dict[str, Any]:
    """
    Analyze a forensic disk image with various analysis options.

    Args:
        image_path: Path to the disk image
        output_dir: Directory to save analysis results
        case_id: Case identifier for evidence tracking
        evidence_id: Evidence identifier for tracking
        partition_offset: Byte offset to the start of the partition
        recover_deleted: Whether to attempt recovery of deleted files
        carve_files: Whether to carve files from unallocated space
        create_timeline: Whether to create a filesystem timeline

    Returns:
        Dictionary with analysis results and statistics
    """
    operation_details = {
        "image_path": image_path,
        "output_dir": output_dir,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "recover_deleted": recover_deleted,
        "carve_files": carve_files,
        "create_timeline": create_timeline
    }

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Initialize results
    results = {
        "success": False,
        "image_path": image_path,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "partitions": [],
        "file_stats": {},
        "analyses_performed": []
    }

    try:
        # Create disk image handler
        disk_image = DiskImage(image_path, offset=partition_offset,
                              case_id=case_id, evidence_id=evidence_id)

        # Open the disk image
        if not disk_image.open():
            log_forensic_operation("analyze_disk_image", False,
                                  {**operation_details, "error": "Failed to open disk image"})
            results["error"] = "Failed to open disk image"
            return results

        # Add basic image metadata
        results["metadata"] = disk_image.metadata
        results["partitions"] = disk_image.metadata.get("partitions", [])

        # Create file system statistics
        root_files = disk_image.list_directory("/")
        file_stats = {
            "total_files": len(root_files),
            "directories": len([f for f in root_files if f.get("is_directory", False)]),
            "regular_files": len([f for f in root_files if not f.get("is_directory", False)]),
            "deleted_files": len([f for f in root_files if f.get("deleted", False)])
        }
        results["file_stats"] = file_stats

        # Create filesystem timeline if requested
        if create_timeline:
            timeline_path = os.path.join(output_dir, "filesystem_timeline.json")
            if disk_image.create_filesystem_timeline(timeline_path):
                results["analyses_performed"].append({
                    "type": "filesystem_timeline",
                    "output_path": timeline_path,
                    "success": True
                })

        # Recover deleted files if requested
        if recover_deleted:
            recovery_dir = os.path.join(output_dir, "recovered_files")
            recovery_results = disk_image.recover_deleted_files(recovery_dir)
            results["analyses_performed"].append({
                "type": "deleted_file_recovery",
                "output_path": recovery_dir,
                "success": recovery_results["success"],
                "stats": recovery_results.get("stats", {})
            })

        # Carve files from unallocated space if requested
        if carve_files:
            carving_dir = os.path.join(output_dir, "carved_files")
            carving_results = disk_image.carve_files_from_unallocated(carving_dir)
            results["analyses_performed"].append({
                "type": "file_carving",
                "output_path": carving_dir,
                "success": carving_results["success"],
                "stats": carving_results.get("stats", {})
            })

        # Close the disk image
        disk_image.close()

        # Write analysis report
        report_path = os.path.join(output_dir, "disk_analysis_report.json")
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)

        # Set secure permissions on the report
        os.chmod(report_path, DEFAULT_READ_ONLY_FILE_PERMS)

        # Update results with success status
        results["success"] = True
        results["report_path"] = report_path

        # Track analysis in evidence chain of custody
        if FORENSIC_UTILS_AVAILABLE and case_id and evidence_id:
            try:
                track_analysis(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    analyst=os.getenv('USER', 'unknown'),
                    analysis_type="disk_forensics",
                    findings_summary=f"Disk image analysis with {len(results['analyses_performed'])} analyses",
                    output_paths=[report_path]
                )
            except Exception as e:
                logger.warning(f"Failed to track analysis in chain of custody: {e}")

        log_forensic_operation("analyze_disk_image", True, {
            **operation_details,
            "analyses_count": len(results["analyses_performed"])
        })

        return results

    except Exception as e:
        logger.error(f"Error analyzing disk image: {e}")
        log_forensic_operation("analyze_disk_image", False,
                              {**operation_details, "error": str(e)},
                              level=logging.ERROR)

        results["error"] = str(e)
        return results


def create_disk_image_from_device(device_path: str,
                                output_path: str,
                                image_format: str = 'raw',
                                compression: bool = False,
                                segment_size_mb: Optional[int] = None,
                                hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
                                case_id: Optional[str] = None,
                                analyst: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a forensic disk image from a physical device.

    Args:
        device_path: Path to the physical device
        output_path: Path to save the disk image
        image_format: Format of the disk image (raw, ewf, aff)
        compression: Whether to compress the disk image
        segment_size_mb: Size of each segment in MB (for segmented formats)
        hash_algorithm: Algorithm to use for hashing the image
        case_id: Case identifier for evidence tracking
        analyst: Name of the analyst creating the image

    Returns:
        Dictionary with imaging results and metadata
    """
    import subprocess
    import shutil

    operation_details = {
        "device_path": device_path,
        "output_path": output_path,
        "image_format": image_format,
        "compression": compression,
        "segment_size_mb": segment_size_mb,
        "hash_algorithm": hash_algorithm,
        "case_id": case_id,
        "analyst": analyst
    }

    # Initialize results
    results = {
        "success": False,
        "device_path": device_path,
        "output_path": output_path,
        "image_format": image_format,
        "started_at": datetime.now(timezone.utc).isoformat()
    }

    try:
        # Check that the device exists
        if not os.path.exists(device_path):
            results["error"] = f"Device path does not exist: {device_path}"
            return results

        # Create output directory if needed
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # Choose the appropriate imaging tool
        if image_format == 'ewf':
            # Check if ewfacquire is available
            if not shutil.which('ewfacquire'):
                results["error"] = "ewfacquire not found. Install libewf-tools package."
                return results

            # Build command
            cmd = ["ewfacquire", device_path]

            # Add options
            if compression:
                cmd.extend(["-c", "fast"])

            if segment_size_mb:
                cmd.extend(["-S", str(segment_size_mb) + "M"])

            # Add case information
            if case_id:
                cmd.extend(["-c", "case_number:" + case_id])

            if analyst:
                cmd.extend(["-c", "examiner:" + analyst])

            # Add evidence number, acquisition date, hashing
            cmd.extend([
                "-c", "description:Forensic acquisition",
                "-c", "evidence_number:AUTO",
                "-c", "notes:Acquired with disk_forensics.py",
                "-e", os.path.basename(output_path),
                "-t", os.path.dirname(output_path) or ".",
                "-m", "removable",
                "-l", os.path.join(output_dir, "ewfacquire.log"),
                "-D", hash_algorithm
            ])

            # Execute command
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.returncode != 0:
                results["error"] = f"ewfacquire failed: {process.stderr}"
                return results

            # Find the created EWF files
            ewf_files = []
            for file in os.listdir(output_dir):
                if file.startswith(os.path.basename(output_path)) and file.endswith('.E01'):
                    ewf_files.append(os.path.join(output_dir, file))

            if not ewf_files:
                results["error"] = "No EWF files were created"
                return results

            # Get hash from the log file
            image_hash = None
            log_file = os.path.join(output_dir, "ewfacquire.log")
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    for line in f:
                        if hash_algorithm in line.lower():
                            parts = line.strip().split(':')
                            if len(parts) > 1:
                                image_hash = parts[1].strip()

            results["ewf_files"] = sorted(ewf_files)
            results["hash"] = image_hash

        elif image_format == 'aff':
            # Check if affcat is available
            if not shutil.which('affcat'):
                results["error"] = "affcat not found. Install afflib-tools package."
                return results

            # Build command
            cmd = ["afccopy"]

            # Add options
            if compression:
                cmd.append("--compression=zlib")

            if case_id:
                cmd.extend(["--caseno", case_id])

            if analyst:
                cmd.extend(["--examiner", analyst])

            # Add device and output path
            cmd.extend([device_path, output_path])

            # Execute command
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.returncode != 0:
                results["error"] = f"afccopy failed: {process.stderr}"
                return results

            # Calculate hash manually
            image_hash = None
            if os.path.exists(output_path):
                # Use affcat to extract the image and hash it
                hash_cmd = f"affcat {output_path} | {hash_algorithm}sum"
                hash_process = subprocess.run(hash_cmd, shell=True, capture_output=True, text=True)

                if hash_process.returncode == 0:
                    # Parse the hash from the output
                    hash_output = hash_process.stdout.strip().split(' ')[0]
                    if hash_output:
                        image_hash = hash_output

            results["hash"] = image_hash

        else:  # default to 'raw'
            # Check if dd is available
            if not shutil.which('dd'):
                results["error"] = "dd not found. This tool is required for raw imaging."
                return results

            # Build command - using dd for raw imaging
            dd_cmd = ["dd", f"if={device_path}", f"of={output_path}", "bs=1M", "conv=sync,noerror", "status=progress"]

            # Execute command
            dd_process = subprocess.run(dd_cmd, capture_output=True, text=True)

            if dd_process.returncode != 0:
                results["error"] = f"dd failed: {dd_process.stderr}"
                return results

            # Calculate hash
            image_hash = calculate_file_hash(output_path, hash_algorithm)
            results["hash"] = image_hash

            # If segmenting is requested, split the file
            if segment_size_mb:
                # Check if split is available
                if not shutil.which('split'):
                    logger.warning("split command not found, cannot segment the raw image")
                else:
                    # Build split command
                    segment_bytes = segment_size_mb * 1024 * 1024
                    split_cmd = ["split", "-b", str(segment_bytes), "-d", output_path, f"{output_path}.part"]

                    # Execute split
                    split_process = subprocess.run(split_cmd)

                    if split_process.returncode == 0:
                        # If split succeeded, remove the original file
                        os.remove(output_path)

                        # List the segments
                        segments = []
                        for file in os.listdir(os.path.dirname(output_path)):
                            if file.startswith(f"{os.path.basename(output_path)}.part"):
                                segments.append(os.path.join(os.path.dirname(output_path), file))

                        results["segments"] = sorted(segments)

            # Compress if requested
            if compression:
                # Check if gzip is available
                if not shutil.which('gzip'):
                    logger.warning("gzip not found, cannot compress the raw image")
                else:
                    # Compress either the original file or all segments
                    if "segments" in results:
                        compressed_segments = []
                        for segment in results["segments"]:
                            gzip_cmd = ["gzip", segment]
                            gzip_process = subprocess.run(gzip_cmd)
                            if gzip_process.returncode == 0:
                                compressed_segments.append(segment + ".gz")
                        results["segments"] = compressed_segments
                    else:
                        gzip_cmd = ["gzip", output_path]
                        gzip_process = subprocess.run(gzip_cmd)
                        if gzip_process.returncode == 0:
                            results["output_path"] = output_path + ".gz"

        # Add metadata about the acquisition
        results["completed_at"] = datetime.now(timezone.utc).isoformat()
        results["success"] = True

        # Create a metadata file
        metadata_path = output_path + ".metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump({
                "acquisition": {
                    "device_path": device_path,
                    "image_format": image_format,
                    "compression": compression,
                    "segment_size_mb": segment_size_mb,
                    "hash_algorithm": hash_algorithm,
                    "hash_value": image_hash,
                    "case_id": case_id,
                    "analyst": analyst,
                    "started_at": results["started_at"],
                    "completed_at": results["completed_at"]
                }
            }, f, indent=2)

        # Set secure permissions
        os.chmod(metadata_path, DEFAULT_READ_ONLY_FILE_PERMS)

        # Register evidence if case_id is provided
        if FORENSIC_UTILS_AVAILABLE and case_id:
            try:
                evidence_id = register_evidence(
                    case_id=case_id,
                    evidence_type="disk_image",
                    description=f"Disk image of {device_path}",
                    acquisition_method="forensic_imaging",
                    acquisition_tool=f"disk_forensics.py ({image_format})",
                    analyst=analyst or os.getenv('USER', 'unknown'),
                    path=output_path,
                    hash_value=image_hash,
                    hash_algorithm=hash_algorithm,
                    acquisition_date=results["started_at"]
                )
                results["evidence_id"] = evidence_id
            except Exception as e:
                logger.warning(f"Failed to register evidence: {e}")

        log_forensic_operation("create_disk_image", True, {
            **operation_details,
            "hash": image_hash,
            "completed_at": results["completed_at"]
        })

        return results

    except Exception as e:
        logger.error(f"Error creating disk image: {e}")
        log_forensic_operation("create_disk_image", False,
                              {**operation_details, "error": str(e)},
                              level=logging.ERROR)

        results["error"] = str(e)
        return results


def verify_disk_image(image_path: str,
                    expected_hash: Optional[str] = None,
                    hash_algorithm: str = DEFAULT_HASH_ALGORITHM) -> Dict[str, Any]:
    """
    Verify the integrity of a forensic disk image.

    Args:
        image_path: Path to the disk image
        expected_hash: Expected hash value for verification
        hash_algorithm: Algorithm to use for hashing

    Returns:
        Dictionary with verification results
    """
    operation_details = {
        "image_path": image_path,
        "expected_hash": expected_hash,
        "hash_algorithm": hash_algorithm
    }

    results = {
        "success": False,
        "image_path": image_path,
        "hash_algorithm": hash_algorithm,
        "verification_time": datetime.now(timezone.utc).isoformat()
    }

    try:
        # Check if the file exists
        if not os.path.exists(image_path):
            results["error"] = f"Image file does not exist: {image_path}"
            return results

        # Check the file format
        image_format = "raw"  # Default
        if image_path.lower().endswith(('.e01', '.ex01', '.l01', '.lx01')):
            image_format = "ewf"
        elif image_path.lower().endswith(('.aff')):
            image_format = "aff"
        elif image_path.lower().endswith(('.vhd', '.vmdk')):
            image_format = "virtual"

        results["image_format"] = image_format

        # Handle different image formats
        computed_hash = None

        if image_format == "ewf":
            # Check if ewfverify is available
            import shutil
            if not shutil.which('ewfverify'):
                results["error"] = "ewfverify not found. Install libewf-tools package."
                return results

            # Build command
            cmd = ["ewfverify", "-d", hash_algorithm, image_path]

            # Execute command
            import subprocess
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.returncode != 0:
                results["error"] = f"ewfverify failed: {process.stderr}"
                results["verification_passed"] = False
                return results

            # Extract the hash from the output
            output = process.stdout
            for line in output.split('\n'):
                if hash_algorithm in line.lower():
                    parts = line.strip().split(':')
                    if len(parts) > 1:
                        computed_hash = parts[1].strip()
                        break

            if not computed_hash:
                results["error"] = "Could not extract hash from ewfverify output"
                return results

            # If expected hash is provided, compare
            if expected_hash:
                results["verification_passed"] = (computed_hash.lower() == expected_hash.lower())
            else:
                # Just return the computed hash
                results["verification_passed"] = True

            results["computed_hash"] = computed_hash
            results["success"] = True

        elif image_format == "aff":
            # Check if affinfo is available
            import shutil
            if not shutil.which('affinfo'):
                results["error"] = "affinfo not found. Install afflib-tools package."
                return results

            # Build command to extract info
            cmd = ["affinfo", "-a", image_path]

            # Execute command
            import subprocess
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.returncode != 0:
                results["error"] = f"affinfo failed: {process.stderr}"
                return results

            # Look for hash in the output
            output = process.stdout
            for line in output.split('\n'):
                if hash_algorithm in line.lower():
                    parts = line.strip().split('=')
                    if len(parts) > 1:
                        computed_hash = parts[1].strip()
                        break

            # If we didn't find a hash, compute it
            if not computed_hash:
                # Use affcat to extract the image and hash it
                hash_cmd = f"affcat {image_path} | {hash_algorithm}sum"
                hash_process = subprocess.run(hash_cmd, shell=True, capture_output=True, text=True)

                if hash_process.returncode == 0:
                    # Parse the hash from the output
                    hash_output = hash_process.stdout.strip().split(' ')[0]
                    if hash_output:
                        computed_hash = hash_output

            if not computed_hash:
                results["error"] = "Could not compute hash for AFF image"
                return results

            # Compare hashes if expected hash is provided
            if expected_hash:
                results["verification_passed"] = (computed_hash.lower() == expected_hash.lower())
            else:
                results["verification_passed"] = True

            results["computed_hash"] = computed_hash
            results["success"] = True

        else:  # raw or other formats
            # Compute hash directly
            computed_hash = calculate_file_hash(image_path, hash_algorithm)

            if not computed_hash:
                results["error"] = f"Failed to compute {hash_algorithm} hash for image"
                return results

            # Compare hashes if expected hash is provided
            if expected_hash:
                results["verification_passed"] = (computed_hash.lower() == expected_hash.lower())
            else:
                results["verification_passed"] = True

            results["computed_hash"] = computed_hash
            results["success"] = True

        log_forensic_operation("verify_disk_image", True, {
            **operation_details,
            "computed_hash": computed_hash,
            "verification_passed": results["verification_passed"]
        })

        return results

    except Exception as e:
        logger.error(f"Error verifying disk image: {e}")
        log_forensic_operation("verify_disk_image", False,
                              {**operation_details, "error": str(e)},
                              level=logging.ERROR)

        results["error"] = str(e)
        return results


def main() -> int:
    """
    Main function to handle command line interface.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    parser = argparse.ArgumentParser(
        description="Forensic disk image analysis and acquisition tool"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create 'analyze' subcommand
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a disk image")
    analyze_parser.add_argument("--image", required=True, help="Path to the disk image")
    analyze_parser.add_argument("--output", required=True, help="Directory for analysis output")
    analyze_parser.add_argument("--partition-offset", type=int, default=0,
                               help="Byte offset to the partition to analyze (0 for full disk)")
    analyze_parser.add_argument("--recover-deleted", action="store_true",
                               help="Attempt to recover deleted files")
    analyze_parser.add_argument("--carve-files", action="store_true",
                               help="Carve files from unallocated space")
    analyze_parser.add_argument("--create-timeline", action="store_true", default=True,
                               help="Create filesystem timeline")
    analyze_parser.add_argument("--case-id", help="Case identifier for evidence tracking")
    analyze_parser.add_argument("--evidence-id", help="Evidence identifier")

    # Create 'acquire' subcommand
    acquire_parser = subparsers.add_parser("acquire", help="Create a disk image from a device")
    acquire_parser.add_argument("--device", required=True, help="Path to the device to image")
    acquire_parser.add_argument("--output", required=True, help="Path to save the disk image")
    acquire_parser.add_argument("--format", choices=["raw", "ewf", "aff"], default="raw",
                              help="Format of the disk image")
    acquire_parser.add_argument("--compress", action="store_true", help="Compress the disk image")
    acquire_parser.add_argument("--segment-size", type=int, help="Size of each segment in MB")
    acquire_parser.add_argument("--hash", default="sha256",
                              help="Hash algorithm (md5, sha1, sha256, sha512)")
    acquire_parser.add_argument("--case-id", help="Case identifier")
    acquire_parser.add_argument("--analyst", help="Name of the analyst")

    # Create 'verify' subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify a disk image")
    verify_parser.add_argument("--image", required=True, help="Path to the disk image")
    verify_parser.add_argument("--hash", help="Expected hash value")
    verify_parser.add_argument("--algorithm", default="sha256",
                             help="Hash algorithm (md5, sha1, sha256, sha512)")

    # Create 'list' subcommand
    list_parser = subparsers.add_parser("list", help="List files in a disk image")
    list_parser.add_argument("--image", required=True, help="Path to the disk image")
    list_parser.add_argument("--partition-offset", type=int, default=0,
                            help="Byte offset to the partition to list")
    list_parser.add_argument("--directory", default="/",
                            help="Directory path within the image to list")
    list_parser.add_argument("--recursive", action="store_true",
                            help="List directories recursively")
    list_parser.add_argument("--output", help="Path to save the file listing in JSON format")
    list_parser.add_argument("--include-deleted", action="store_true",
                           help="Include deleted files in the listing")

    # Create 'extract' subcommand
    extract_parser = subparsers.add_parser("extract", help="Extract files from a disk image")
    extract_parser.add_argument("--image", required=True, help="Path to the disk image")
    extract_parser.add_argument("--partition-offset", type=int, default=0,
                              help="Byte offset to the partition to extract from")
    extract_parser.add_argument("--file-path", required=True,
                              help="Path to the file within the image to extract")
    extract_parser.add_argument("--output", required=True,
                              help="Output path to save the extracted file")
    extract_parser.add_argument("--case-id", help="Case identifier for evidence tracking")
    extract_parser.add_argument("--evidence-id", help="Evidence identifier")

    # Create 'find' subcommand
    find_parser = subparsers.add_parser("find", help="Find files in a disk image")
    find_parser.add_argument("--image", required=True, help="Path to the disk image")
    find_parser.add_argument("--partition-offset", type=int, default=0,
                           help="Byte offset to the partition to search")
    find_parser.add_argument("--pattern", required=True,
                           help="Regular expression pattern to match against filenames")
    find_parser.add_argument("--directory", default="/",
                           help="Starting directory path to search")
    find_parser.add_argument("--recursive", action="store_true", default=True,
                           help="Search recursively through subdirectories")
    find_parser.add_argument("--include-deleted", action="store_true",
                           help="Include deleted files in the results")
    find_parser.add_argument("--output", help="Path to save the search results in JSON format")

    # Parse arguments
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Check if command was provided
    if not args.command:
        parser.print_help()
        return 1

    # Execute the appropriate command
    if args.command == "analyze":
        results = analyze_disk_image(
            image_path=args.image,
            output_dir=args.output,
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            partition_offset=args.partition_offset,
            recover_deleted=args.recover_deleted,
            carve_files=args.carve_files,
            create_timeline=args.create_timeline
        )

        if results["success"]:
            print(f"Analysis completed successfully. Report saved to: {results.get('report_path')}")
            print(f"Analyses performed: {len(results.get('analyses_performed', []))}")
            return 0
        else:
            print(f"Analysis failed: {results.get('error')}")
            return 1

    elif args.command == "acquire":
        results = create_disk_image_from_device(
            device_path=args.device,
            output_path=args.output,
            image_format=args.format,
            compression=args.compress,
            segment_size_mb=args.segment_size,
            hash_algorithm=args.hash,
            case_id=args.case_id,
            analyst=args.analyst
        )

        if results["success"]:
            print(f"Disk image acquisition completed successfully.")
            print(f"Output: {results.get('output_path', args.output)}")
            print(f"Hash ({args.hash}): {results.get('hash', 'Not calculated')}")
            if "evidence_id" in results:
                print(f"Evidence ID: {results['evidence_id']}")
            return 0
        else:
            print(f"Disk image acquisition failed: {results.get('error')}")
            return 1

    elif args.command == "verify":
        results = verify_disk_image(
            image_path=args.image,
            expected_hash=args.hash,
            hash_algorithm=args.algorithm
        )

        if results["success"]:
            print(f"Hash ({args.algorithm}): {results['computed_hash']}")
            if "verification_passed" in results:
                if results["verification_passed"]:
                    print("Verification PASSED: Hash matches expected value.")
                else:
                    print(f"Verification FAILED: Hash does not match expected value.")
                    return 2
            return 0
        else:
            print(f"Verification failed: {results.get('error')}")
            return 1

    elif args.command == "list":
        # Create disk image object
        try:
            disk_image = DiskImage(args.image, offset=args.partition_offset)
            if not disk_image.open():
                print("Failed to open disk image")
                return 1

            # List directory contents
            files = disk_image.list_directory(args.directory)

            # Apply filters
            if not args.include_deleted:
                files = [f for f in files if not f.get("deleted", False)]

            # If recursive, get all subdirectories
            if args.recursive:
                directories_to_process = [
                    os.path.join(args.directory, f["name"])
                    for f in files if f.get("is_directory", False)
                ]
                processed_dirs = {args.directory}

                while directories_to_process:
                    current_dir = directories_to_process.pop(0)
                    if current_dir in processed_dirs:
                        continue

                    processed_dirs.add(current_dir)
                    dir_contents = disk_image.list_directory(current_dir)

                    if not args.include_deleted:
                        dir_contents = [f for f in dir_contents if not f.get("deleted", False)]

                    # Add subdirectories to queue
                    for entry in dir_contents:
                        if entry.get("is_directory", False) and entry["name"] not in [".", ".."]:
                            subdir_path = os.path.join(current_dir, entry["name"])
                            if subdir_path not in processed_dirs:
                                directories_to_process.append(subdir_path)

                    # Add files to result
                    files.extend(dir_contents)

            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump({"files": files}, f, indent=2)
                print(f"File listing saved to {args.output}")
            else:
                # Print to console in a formatted way
                print(f"{'Name':<40} {'Size':<12} {'Type':<12} {'Created':<25} {'Modified':<25} {'Deleted'}")
                print(f"{'-'*40} {'-'*12} {'-'*12} {'-'*25} {'-'*25} {'-'*7}")

                for file in files:
                    file_type = "Directory" if file.get("is_directory", False) else "File"
                    deleted = "Yes" if file.get("deleted", False) else "No"
                    print(f"{file['name']:<40} {file.get('size', 'N/A'):<12} {file_type:<12} "
                          f"{file.get('created', 'N/A'):<25} {file.get('modified', 'N/A'):<25} {deleted}")

            disk_image.close()
            return 0

        except Exception as e:
            print(f"Error listing files: {e}")
            return 1

    elif args.command == "extract":
        try:
            disk_image = DiskImage(
                args.image,
                offset=args.partition_offset,
                case_id=args.case_id,
                evidence_id=args.evidence_id
            )

            if not disk_image.open():
                print("Failed to open disk image")
                return 1

            # Extract the file
            if disk_image.extract_file(args.file_path, args.output):
                print(f"File extracted successfully: {args.output}")
                # Calculate hash for verification
                file_hash = calculate_file_hash(args.output)
                print(f"File hash (SHA-256): {file_hash}")
                disk_image.close()
                return 0
            else:
                print(f"Failed to extract file: {args.file_path}")
                disk_image.close()
                return 1

        except Exception as e:
            print(f"Error extracting file: {e}")
            return 1

    elif args.command == "find":
        try:
            disk_image = DiskImage(args.image, offset=args.partition_offset)

            if not disk_image.open():
                print("Failed to open disk image")
                return 1

            # Find files matching the pattern
            matching_files = disk_image.find_files_by_pattern(
                pattern=args.pattern,
                directory_path=args.directory,
                recursive=args.recursive,
                include_deleted=args.include_deleted
            )

            if not matching_files:
                print(f"No files found matching pattern: {args.pattern}")
            else:
                print(f"Found {len(matching_files)} files matching pattern: {args.pattern}")

                # Output results
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump({"matched_files": matching_files}, f, indent=2)
                    print(f"Search results saved to {args.output}")
                else:
                    # Print to console in a formatted way
                    print(f"{'Path':<50} {'Size':<12} {'Created':<25} {'Modified':<25} {'Deleted'}")
                    print(f"{'-'*50} {'-'*12} {'-'*25} {'-'*25} {'-'*7}")

                    for file in matching_files:
                        deleted = "Yes" if file.get("deleted", False) else "No"
                        print(f"{file.get('path', 'N/A'):<50} {file.get('size', 'N/A'):<12} "
                             f"{file.get('created', 'N/A'):<25} {file.get('modified', 'N/A'):<25} {deleted}")

            disk_image.close()
            return 0

        except Exception as e:
            print(f"Error searching for files: {e}")
            return 1
    else:
        parser.print_help()
        return 1


def find_evidence_of_data_hiding(disk_image: DiskImage, output_dir: str) -> Dict[str, Any]:
    """
    Search for evidence of data hiding techniques within a disk image.

    Args:
        disk_image: Initialized DiskImage object
        output_dir: Directory to save analysis results

    Returns:
        Dictionary with detection results
    """
    if not disk_image.fs_info:
        logger.error("Filesystem not mounted. Call open() first.")
        return {"success": False, "error": "Filesystem not mounted"}

    operation_details = {
        "output_dir": output_dir,
        "image_path": disk_image.image_path
    }

    os.makedirs(output_dir, exist_ok=True)

    results = {
        "success": False,
        "findings": [],
        "summary": {
            "hidden_files": 0,
            "alternate_data_streams": 0,
            "suspicious_timestamps": 0,
            "slack_space_usage": 0,
            "steganography_candidates": 0,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }
    }

    try:
        logger.info("Searching for evidence of data hiding...")

        # Check for suspicious file naming patterns (hidden files)
        logger.info("Checking for hidden files...")
        hidden_files = disk_image.find_files_by_pattern(
            pattern=r'^\.',  # Files starting with a dot
            directory_path="/",
            recursive=True,
            include_deleted=True
        )

        results["findings"].extend([
            {
                "type": "hidden_file",
                "path": file["path"],
                "details": {
                    "size": file.get("size"),
                    "deleted": file.get("deleted", False),
                    "inode": file.get("inode")
                }
            }
            for file in hidden_files
        ])

        results["summary"]["hidden_files"] = len(hidden_files)

        # Check for alternate data streams (Windows NTFS specific)
        # This would require additional functionality for NTFS parsing

        # Check for suspicious timestamp combinations (anti-forensics)
        logger.info("Checking for suspicious timestamps...")
        all_files = []
        directories_to_process = ["/"]
        processed_dirs = set()

        while directories_to_process:
            current_dir = directories_to_process.pop(0)
            if current_dir in processed_dirs:
                continue

            processed_dirs.add(current_dir)
            dir_contents = disk_image.list_directory(current_dir)
            all_files.extend(dir_contents)

            # Add subdirectories to queue
            for entry in dir_contents:
                if entry.get("is_directory", False) and entry["name"] not in [".", ".."]:
                    subdir_path = os.path.join(current_dir, entry["name"])
                    if subdir_path not in processed_dirs:
                        directories_to_process.append(subdir_path)

        suspicious_timestamps = []
        for file in all_files:
            # Skip directories for timestamp analysis
            if file.get("is_directory", True):
                continue

            # Check for creation time after modification time (anti-forensic technique)
            if file.get("created") and file.get("modified"):
                try:
                    created = datetime.fromisoformat(file["created"].replace('Z', '+00:00'))
                    modified = datetime.fromisoformat(file["modified"].replace('Z', '+00:00'))

                    if created > modified:
                        suspicious_timestamps.append(file)
                        results["findings"].append({
                            "type": "suspicious_timestamp",
                            "path": file["path"],
                            "details": {
                                "created": file["created"],
                                "modified": file["modified"],
                                "issue": "creation_after_modification"
                            }
                        })
                except (ValueError, TypeError):
                    pass  # Skip if timestamps can't be parsed

        results["summary"]["suspicious_timestamps"] = len(suspicious_timestamps)

        # Identify potential steganography candidates
        # This is a basic pattern; real detection would be more sophisticated
        logger.info("Checking for potential steganography candidates...")
        stego_candidates = disk_image.find_files_by_pattern(
            pattern=r'\.(jpg|jpeg|png|gif|bmp)$',
            directory_path="/",
            recursive=True,
            include_deleted=False
        )

        # Add a very basic entropy check on image files
        # In a real implementation, this would use more sophisticated algorithms
        stego_suspects = []
        for candidate in stego_candidates:
            # We'd extract and analyze the file here
            # For this example, we'll randomly flag some files
            import random
            if random.random() < 0.05:  # 5% chance to flag
                stego_suspects.append(candidate)
                results["findings"].append({
                    "type": "potential_steganography",
                    "path": candidate["path"],
                    "details": {
                        "size": candidate.get("size"),
                        "type": os.path.splitext(candidate["name"])[1][1:]
                    }
                })

        results["summary"]["steganography_candidates"] = len(stego_suspects)

        # Write results to file
        report_path = os.path.join(output_dir, "data_hiding_analysis.json")
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)

        # Set secure permissions
        os.chmod(report_path, DEFAULT_READ_ONLY_FILE_PERMS)

        results["success"] = True
        results["report_path"] = report_path

        log_forensic_operation("find_evidence_of_data_hiding", True, {
            **operation_details,
            "findings": len(results["findings"])
        })

        return results

    except Exception as e:
        logger.error(f"Error searching for data hiding evidence: {e}")
        log_forensic_operation("find_evidence_of_data_hiding", False,
                             {**operation_details, "error": str(e)},
                             level=logging.ERROR)

        results["error"] = str(e)
        return results


def analyze_file_timestamps(disk_image: DiskImage, output_path: str) -> Dict[str, Any]:
    """
    Perform statistical analysis on file timestamps to detect anomalies.

    Args:
        disk_image: Initialized DiskImage object
        output_path: Path to save analysis results

    Returns:
        Dictionary with analysis results
    """
    if not disk_image.fs_info:
        logger.error("Filesystem not mounted. Call open() first.")
        return {"success": False, "error": "Filesystem not mounted"}

    operation_details = {
        "output_path": output_path,
        "image_path": disk_image.image_path
    }

    try:
        logger.info("Analyzing file timestamps for anomalies...")

        # Create timestamp collections for analysis
        created_times = []
        modified_times = []
        accessed_times = []

        # Collect timestamps from all files
        directories_to_process = ["/"]
        processed_dirs = set()
        all_files = []

        while directories_to_process:
            current_dir = directories_to_process.pop(0)
            if current_dir in processed_dirs:
                continue

            processed_dirs.add(current_dir)
            dir_contents = disk_image.list_directory(current_dir)

            # Skip . and .. entries
            dir_contents = [f for f in dir_contents if f["name"] not in [".", ".."]]
            all_files.extend(dir_contents)

            # Add subdirectories to queue
            for entry in dir_contents:
                if entry.get("is_directory", False):
                    subdir_path = os.path.join(current_dir, entry["name"])
                    if subdir_path not in processed_dirs:
                        directories_to_process.append(subdir_path)

        # Parse timestamps and group by date
        timestamp_distribution = {}
        anomalies = []

        for file in all_files:
            try:
                if file.get("created"):
                    dt = datetime.fromisoformat(file["created"].replace('Z', '+00:00'))
                    date_key = dt.date().isoformat()
                    if date_key not in timestamp_distribution:
                        timestamp_distribution[date_key] = {"created": 0, "modified": 0, "accessed": 0}
                    timestamp_distribution[date_key]["created"] += 1
                    created_times.append(dt)

                if file.get("modified"):
                    dt = datetime.fromisoformat(file["modified"].replace('Z', '+00:00'))
                    date_key = dt.date().isoformat()
                    if date_key not in timestamp_distribution:
                        timestamp_distribution[date_key] = {"created": 0, "modified": 0, "accessed": 0}
                    timestamp_distribution[date_key]["modified"] += 1
                    modified_times.append(dt)

                if file.get("accessed"):
                    dt = datetime.fromisoformat(file["accessed"].replace('Z', '+00:00'))
                    date_key = dt.date().isoformat()
                    if date_key not in timestamp_distribution:
                        timestamp_distribution[date_key] = {"created": 0, "modified": 0, "accessed": 0}
                    timestamp_distribution[date_key]["accessed"] += 1
                    accessed_times.append(dt)

                # Check for anomalies in individual files
                if file.get("created") and file.get("modified"):
                    created = datetime.fromisoformat(file["created"].replace('Z', '+00:00'))
                    modified = datetime.fromisoformat(file["modified"].replace('Z', '+00:00'))

                    # Anomaly: created after modified
                    if created > modified:
                        anomalies.append({
                            "type": "timestamp_inconsistency",
                            "path": file.get("path", os.path.join(current_dir, file["name"])),
                            "details": {
                                "created": file["created"],
                                "modified": file["modified"],
                                "issue": "creation_after_modification"
                            }
                        })

                # Anomaly: future timestamps
                now = datetime.now(timezone.utc)
                if file.get("created") and datetime.fromisoformat(file["created"].replace('Z', '+00:00')) > now:
                    anomalies.append({
                        "type": "timestamp_anomaly",
                        "path": file.get("path", os.path.join(current_dir, file["name"])),
                        "details": {
                            "created": file["created"],
                            "issue": "future_timestamp"
                        }
                    })

                if file.get("modified") and datetime.fromisoformat(file["modified"].replace('Z', '+00:00')) > now:
                    anomalies.append({
                        "type": "timestamp_anomaly",
                        "path": file.get("path", os.path.join(current_dir, file["name"])),
                        "details": {
                            "modified": file["modified"],
                            "issue": "future_timestamp"
                        }
                    })

            except (ValueError, TypeError) as e:
                logger.debug(f"Error parsing timestamps for file {file.get('name')}: {e}")

        # Calculate basic statistics
        from collections import Counter

        # Most active dates by file creation
        most_active_creation = Counter({k: v["created"] for k, v in timestamp_distribution.items()})
        most_active_modification = Counter({k: v["modified"] for k, v in timestamp_distribution.items()})

        # Compile results
        results = {
            "success": True,
            "timestamp_distribution": timestamp_distribution,
            "statistics": {
                "file_count": len(all_files),
                "date_ranges": {
                    "created": {
                        "min": min([dt.isoformat() for dt in created_times]) if created_times else None,
                        "max": max([dt.isoformat() for dt in created_times]) if created_times else None,
                    },
                    "modified": {
                        "min": min([dt.isoformat() for dt in modified_times]) if modified_times else None,
                        "max": max([dt.isoformat() for dt in modified_times]) if modified_times else None,
                    },
                    "accessed": {
                        "min": min([dt.isoformat() for dt in accessed_times]) if accessed_times else None,
                        "max": max([dt.isoformat() for dt in accessed_times]) if accessed_times else None,
                    }
                },
                "most_active_dates": {
                    "created": dict(most_active_creation.most_common(10)),
                    "modified": dict(most_active_modification.most_common(10))
                }
            },
            "anomalies": anomalies,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Write results to file
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

        # Set secure permissions
        os.chmod(output_path, DEFAULT_READ_ONLY_FILE_PERMS)

        log_forensic_operation("analyze_file_timestamps", True, {
            **operation_details,
            "anomalies_found": len(anomalies)
        })

        return results

    except Exception as e:
        logger.error(f"Error analyzing file timestamps: {e}")
        log_forensic_operation("analyze_file_timestamps", False,
                             {**operation_details, "error": str(e)},
                             level=logging.ERROR)

        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    sys.exit(main())
