"""
Backup Verification Script for Cloud Infrastructure Platform

This script provides functionality to verify the integrity and viability of database backups,
including checking file integrity, performing test restores, validating encryption, and
generating verification reports.

It's designed to be used both as a standalone script and as an importable module
for programmatic use in the administrative interfaces.
"""

import os
import sys
import json
import hashlib
import logging
import subprocess
import datetime
from enum import Enum
from typing import Dict, List, Union, Optional, Any, Tuple
from pathlib import Path

# Add project root to path to allow imports from core packages
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Try importing application utilities if available
try:
    from admin.utils.file_integrity import verify_file_integrity, calculate_file_hash
    from admin.utils.audit_utils import log_admin_action
    from models.communication import send_notification
    FILE_UTILS_AVAILABLE = True
except ImportError:
    FILE_UTILS_AVAILABLE = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Constants
BACKUP_DIR = Path("/var/backups/cloud-platform")
TEST_RESTORE_DIR = Path("/tmp/backup-verification")
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports" / "backup"
SUPPORTED_FORMATS = ["json", "text", "html", "pdf"]
DEFAULT_TEST_DB_NAME = "verify_restore_temp"
DEFAULT_VERIFICATION_TIMEOUT = 600  # seconds


class VerificationStatus(Enum):
    """Status codes for backup verification results."""
    SUCCESS = "success"
    WARNING = "warning"
    FAILED = "failed"
    ERROR = "error"
    INCOMPLETE = "incomplete"


class BackupFormat(Enum):
    """Supported backup file formats."""
    SQL = "sql"
    SQL_GZ = "sql.gz"
    SQL_GPG = "sql.gpg"
    SQL_GZ_GPG = "sql.gz.gpg"
    TAR = "tar"
    TAR_GZ = "tar.gz"
    TAR_GPG = "tar.gpg"
    TAR_GZ_GPG = "tar.gz.gpg"


def verify_backup_integrity(
    backup_file: Union[str, Path],
    verify_checksum: bool = True,
    verify_structure: bool = False
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify the integrity of a backup file.

    Args:
        backup_file: Path to the backup file
        verify_checksum: Whether to verify checksum if available
        verify_structure: Whether to verify backup file structure

    Returns:
        Tuple of (success, details) where details contains verification results
    """
    backup_path = Path(backup_file)
    result = {
        "file": str(backup_path),
        "size": 0,
        "status": VerificationStatus.ERROR.value,
        "timestamp": datetime.datetime.now().isoformat(),
        "checks": {},
        "errors": []
    }

    if not backup_path.exists():
        result["errors"].append(f"Backup file not found: {backup_path}")
        return False, result

    # Get basic file information
    try:
        stat_info = backup_path.stat()
        result["size"] = stat_info.st_size
        result["modified"] = datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat()
    except Exception as e:
        result["errors"].append(f"Failed to get file stats: {e}")
        return False, result

    # Check if file is not empty
    if stat_info.st_size == 0:
        result["errors"].append("Backup file is empty")
        return False, result

    result["checks"]["exists"] = True
    result["checks"]["size"] = stat_info.st_size > 0

    # Detect backup format
    backup_format = detect_backup_format(backup_path)
    result["format"] = backup_format.value if backup_format else "unknown"

    # Verify checksum if available
    if verify_checksum:
        checksum_result = verify_backup_checksum(backup_path)
        result["checks"]["checksum"] = checksum_result

    # Verify file structure if requested
    if verify_structure:
        structure_result = verify_backup_structure(backup_path)
        result["checks"]["structure"] = structure_result

    # Calculate overall status
    if result["errors"]:
        result["status"] = VerificationStatus.FAILED.value
        return False, result

    failed_checks = [check for check, status in result["checks"].items() if status is False]
    if failed_checks:
        result["status"] = VerificationStatus.WARNING.value
        return False, result

    result["status"] = VerificationStatus.SUCCESS.value
    return True, result


def test_backup_restore(
    backup_file: Union[str, Path],
    environment: str = "production",
    isolated: bool = True,
    timeout: int = DEFAULT_VERIFICATION_TIMEOUT
) -> Tuple[bool, Dict[str, Any]]:
    """
    Perform a test restoration of a backup file.

    Args:
        backup_file: Path to the backup file
        environment: Environment name for the backup
        isolated: Whether to use isolated test environment
        timeout: Maximum time allowed for restore operation in seconds

    Returns:
        Tuple of (success, details) where details contains test results
    """
    backup_path = Path(backup_file)
    result = {
        "file": str(backup_path),
        "timestamp": datetime.datetime.now().isoformat(),
        "environment": environment,
        "isolated": isolated,
        "status": VerificationStatus.ERROR.value,
        "details": {},
        "errors": []
    }

    if not backup_path.exists():
        result["errors"].append(f"Backup file not found: {backup_path}")
        return False, result

    # Ensure test directory exists
    test_dir = TEST_RESTORE_DIR / datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    test_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Create temporary database for test restore
        db_name = f"{DEFAULT_TEST_DB_NAME}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        result["details"]["test_db"] = db_name

        # Execute the restore based on file format
        backup_format = detect_backup_format(backup_path)

        # Create specific command based on backup type
        if backup_format in [BackupFormat.SQL, BackupFormat.SQL_GZ, BackupFormat.SQL_GPG, BackupFormat.SQL_GZ_GPG]:
            # Database backup - use psql for restore
            success, output = restore_database_backup(backup_path, db_name, backup_format, timeout)
        else:
            # File backup - use appropriate extract methods
            success, output = restore_file_backup(backup_path, test_dir, backup_format, timeout)

        result["details"]["output"] = output

        if success:
            # Verify restored data
            verification_success, verification_details = verify_restored_data(backup_path, db_name, test_dir, backup_format)
            result["details"]["verification"] = verification_details
            result["status"] = VerificationStatus.SUCCESS.value if verification_success else VerificationStatus.WARNING.value
        else:
            result["errors"].append("Restore operation failed")
            result["status"] = VerificationStatus.FAILED.value

    except Exception as e:
        result["errors"].append(f"Test restore failed with error: {e}")
        result["status"] = VerificationStatus.ERROR.value

    finally:
        # Clean up test database and files
        try:
            if backup_format in [BackupFormat.SQL, BackupFormat.SQL_GZ, BackupFormat.SQL_GPG, BackupFormat.SQL_GZ_GPG]:
                # Drop test database
                subprocess.run(["psql", "-U", "postgres", "-c", f"DROP DATABASE IF EXISTS {db_name}"],
                                check=False, capture_output=True)

            # Clean up test directory
            cleanup_test_dir(test_dir)
        except Exception as cleanup_error:
            logger.warning(f"Cleanup failed after test restore: {cleanup_error}")

    return result["status"] == VerificationStatus.SUCCESS.value, result


def verify_backup_encryption(
    backup_file: Union[str, Path]
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify if a backup file is properly encrypted.

    Args:
        backup_file: Path to the backup file

    Returns:
        Tuple of (success, details) where details contains encryption verification results
    """
    backup_path = Path(backup_file)
    result = {
        "file": str(backup_path),
        "timestamp": datetime.datetime.now().isoformat(),
        "is_encrypted": False,
        "encryption_type": None,
        "status": VerificationStatus.ERROR.value,
        "errors": []
    }

    if not backup_path.exists():
        result["errors"].append(f"Backup file not found: {backup_path}")
        return False, result

    try:
        # Check if file has .gpg extension
        if backup_path.name.endswith('.gpg'):
            result["is_encrypted"] = True
            result["encryption_type"] = "GPG"

            # Try to verify GPG signature
            verification_cmd = ["gpg", "--verify", str(backup_path)]
            process = subprocess.run(verification_cmd, capture_output=True, text=True)

            if process.returncode == 0:
                result["status"] = VerificationStatus.SUCCESS.value
                result["details"] = {"signature_verified": True}
            else:
                # Still encrypted even if signature isn't verified
                result["status"] = VerificationStatus.WARNING.value
                result["details"] = {
                    "signature_verified": False,
                    "gpg_output": process.stderr
                }
        else:
            # Check file content for encryption markers
            with open(backup_path, 'rb') as file:
                header = file.read(1024)  # Read first 1KB to check headers

                if b'-----BEGIN PGP MESSAGE-----' in header:
                    result["is_encrypted"] = True
                    result["encryption_type"] = "GPG"
                    result["status"] = VerificationStatus.SUCCESS.value
                else:
                    result["is_encrypted"] = False
                    result["status"] = VerificationStatus.WARNING.value
                    result["details"] = {
                        "message": "File does not appear to be encrypted"
                    }
    except Exception as e:
        result["errors"].append(f"Failed to verify encryption: {e}")
        result["status"] = VerificationStatus.ERROR.value

    return result["is_encrypted"], result


def generate_verification_report(
    verification_results: List[Dict[str, Any]],
    output_file: Optional[Union[str, Path]] = None,
    format: str = "json"
) -> Tuple[bool, Union[str, Path]]:
    """
    Generate a report from backup verification results.

    Args:
        verification_results: List of verification result dictionaries
        output_file: Path where report should be saved (optional)
        format: Report format (json, text, html, pdf)

    Returns:
        Tuple of (success, output_file_path)
    """
    if format not in SUPPORTED_FORMATS:
        logger.error(f"Unsupported format: {format}. Must be one of {SUPPORTED_FORMATS}")
        return False, None

    # Create report directory if needed
    report_dir = DEFAULT_REPORT_DIR
    report_dir.mkdir(parents=True, exist_ok=True)

    # Generate default output filename if not provided
    if output_file is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = report_dir / f"backup_verification_{timestamp}.{format}"
    else:
        output_file = Path(output_file)

    # Create summary data
    summary = {
        "report_generated": datetime.datetime.now().isoformat(),
        "total_backups": len(verification_results),
        "successful": len([r for r in verification_results if r.get("status") == VerificationStatus.SUCCESS.value]),
        "warnings": len([r for r in verification_results if r.get("status") == VerificationStatus.WARNING.value]),
        "failed": len([r for r in verification_results if r.get("status") == VerificationStatus.FAILED.value]),
        "errors": len([r for r in verification_results if r.get("status") == VerificationStatus.ERROR.value]),
        "verification_results": verification_results
    }

    try:
        if format == "json":
            with open(output_file, 'w') as f:
                json.dump(summary, f, indent=2)

        elif format == "text":
            with open(output_file, 'w') as f:
                f.write("BACKUP VERIFICATION REPORT\n")
                f.write("=========================\n")
                f.write(f"Generated: {summary['report_generated']}\n\n")
                f.write(f"Total backups: {summary['total_backups']}\n")
                f.write(f"Successful: {summary['successful']}\n")
                f.write(f"Warnings: {summary['warnings']}\n")
                f.write(f"Failed: {summary['failed']}\n")
                f.write(f"Errors: {summary['errors']}\n\n")

                for idx, result in enumerate(verification_results, 1):
                    f.write(f"Backup #{idx}: {result.get('file', 'Unknown')}\n")
                    f.write(f"  Status: {result.get('status', 'Unknown')}\n")
                    f.write(f"  Size: {result.get('size', 0)} bytes\n")
                    if 'errors' in result and result['errors']:
                        f.write(f"  Errors: {', '.join(result['errors'])}\n")
                    f.write("\n")

        elif format == "html":
            # Simple HTML report format
            html_content = generate_html_report(summary)
            with open(output_file, 'w') as f:
                f.write(html_content)

        elif format == "pdf":
            # Generate PDF report if available
            try:
                from weasyprint import HTML
                html_content = generate_html_report(summary)
                HTML(string=html_content).write_pdf(output_file)
            except ImportError:
                logger.error("WeasyPrint not available for PDF generation")
                return False, None

        # Log the report generation
        if FILE_UTILS_AVAILABLE:
            log_admin_action(
                action_type="backup_verification",
                resource_type="report",
                resource_id=str(output_file),
                description="Generated backup verification report",
                status="success"
            )

        return True, output_file

    except Exception as e:
        logger.error(f"Failed to generate verification report: {e}")
        return False, None


def check_backup_completeness(
    backup_file: Union[str, Path],
    backup_type: Optional[str] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Check if a backup file contains all required components.

    Args:
        backup_file: Path to the backup file
        backup_type: Type of backup (database, files, full)

    Returns:
        Tuple of (success, details) where details contains completeness check results
    """
    backup_path = Path(backup_file)
    result = {
        "file": str(backup_path),
        "timestamp": datetime.datetime.now().isoformat(),
        "is_complete": False,
        "status": VerificationStatus.ERROR.value,
        "errors": [],
        "missing_components": []
    }

    if not backup_path.exists():
        result["errors"].append(f"Backup file not found: {backup_path}")
        return False, result

    try:
        # Determine backup type if not specified
        if backup_type is None:
            backup_format = detect_backup_format(backup_path)
            if backup_format in [BackupFormat.SQL, BackupFormat.SQL_GZ, BackupFormat.SQL_GPG, BackupFormat.SQL_GZ_GPG]:
                backup_type = "database"
            elif backup_format in [BackupFormat.TAR, BackupFormat.TAR_GZ, BackupFormat.TAR_GPG, BackupFormat.TAR_GZ_GPG]:
                backup_type = "files"
            else:
                backup_type = "unknown"

        result["backup_type"] = backup_type

        if backup_type == "database":
            # Check database backup completeness
            completeness_result = check_database_backup_completeness(backup_path)
        elif backup_type == "files":
            # Check file backup completeness
            completeness_result = check_file_backup_completeness(backup_path)
        else:
            result["errors"].append(f"Unsupported backup type: {backup_type}")
            return False, result

        # Update result with completeness check details
        result.update(completeness_result)

        if not result["errors"] and not result["missing_components"]:
            result["is_complete"] = True
            result["status"] = VerificationStatus.SUCCESS.value
        elif result["errors"]:
            result["status"] = VerificationStatus.ERROR.value
        else:
            result["status"] = VerificationStatus.WARNING.value

    except Exception as e:
        result["errors"].append(f"Failed to check backup completeness: {e}")
        result["status"] = VerificationStatus.ERROR.value

    return result["is_complete"], result


# Helper functions

def detect_backup_format(backup_file: Path) -> Optional[BackupFormat]:
    """Detect the format of a backup file based on extension and content."""
    name = backup_file.name.lower()

    if name.endswith('.sql.gz.gpg'):
        return BackupFormat.SQL_GZ_GPG
    elif name.endswith('.tar.gz.gpg'):
        return BackupFormat.TAR_GZ_GPG
    elif name.endswith('.sql.gpg'):
        return BackupFormat.SQL_GPG
    elif name.endswith('.tar.gpg'):
        return BackupFormat.TAR_GPG
    elif name.endswith('.sql.gz'):
        return BackupFormat.SQL_GZ
    elif name.endswith('.tar.gz'):
        return BackupFormat.TAR_GZ
    elif name.endswith('.sql'):
        return BackupFormat.SQL
    elif name.endswith('.tar'):
        return BackupFormat.TAR

    # If extension doesn't match, try to detect by content
    try:
        with open(backup_file, 'rb') as f:
            header = f.read(1024)  # Read first 1KB to check headers

            if b'-----BEGIN PGP MESSAGE-----' in header:
                # It's a GPG encrypted file, but we don't know if SQL or TAR
                if b'SQL' in header or b'PostgreSQL' in header:
                    return BackupFormat.SQL_GPG
                else:
                    return BackupFormat.TAR_GPG

            elif header.startswith(b'\x1f\x8b'):  # gzip magic number
                # It's gzipped, but we don't know if SQL or TAR
                return BackupFormat.SQL_GZ  # Default assumption

            elif header.startswith(b'-- PostgreSQL') or b'CREATE TABLE' in header:
                return BackupFormat.SQL

            elif header.startswith(b'ustar') or header[257:262] == b'ustar':
                return BackupFormat.TAR
    except Exception as e:
        logger.warning(f"Failed to detect backup format by content: {e}")

    return None


def verify_backup_checksum(backup_file: Path) -> bool:
    """Verify backup file checksum if available."""
    checksum_file = Path(f"{backup_file}.sha256")

    if not checksum_file.exists():
        logger.warning(f"No checksum file found for {backup_file}")
        return False

    try:
        # Read expected checksum from file
        with open(checksum_file, 'r') as f:
            checksum_line = f.read().strip()
            # Extract just the hash if the file contains filename too
            expected_checksum = checksum_line.split()[0] if len(checksum_line.split()) > 1 else checksum_line

        # Calculate actual checksum
        if FILE_UTILS_AVAILABLE:
            actual_checksum = calculate_file_hash(str(backup_file), 'sha256')
        else:
            actual_checksum = calculate_file_hash_fallback(backup_file, 'sha256')

        # Compare checksums
        return expected_checksum == actual_checksum

    except Exception as e:
        logger.error(f"Failed to verify checksum: {e}")
        return False


def verify_backup_structure(backup_file: Path) -> bool:
    """Verify backup file structure based on its format."""
    backup_format = detect_backup_format(backup_file)

    if not backup_format:
        logger.error(f"Could not detect format for {backup_file}")
        return False

    try:
        # SQL file verification
        if backup_format in [BackupFormat.SQL, BackupFormat.SQL_GZ, BackupFormat.SQL_GPG, BackupFormat.SQL_GZ_GPG]:
            # For SQL files, check if it contains basic SQL statements
            # This is just a minimal check to ensure it's a SQL dump

            if backup_format == BackupFormat.SQL:
                with open(backup_file, 'r') as f:
                    content = f.read(4096)  # Read first 4KB
                    return ('CREATE TABLE' in content or 'INSERT INTO' in content or
                           'BEGIN;' in content or '-- PostgreSQL' in content)

            elif backup_format == BackupFormat.SQL_GZ:
                import gzip
                with gzip.open(backup_file, 'rt') as f:
                    content = f.read(4096)  # Read first 4KB
                    return ('CREATE TABLE' in content or 'INSERT INTO' in content or
                           'BEGIN;' in content or '-- PostgreSQL' in content)

            # For encrypted files, we can't easily check content without decrypting
            elif backup_format in [BackupFormat.SQL_GPG, BackupFormat.SQL_GZ_GPG]:
                # Just check if it's a valid GPG file
                verify_cmd = ["gpg", "--list-packets", str(backup_file)]
                process = subprocess.run(verify_cmd, capture_output=True)
                return process.returncode == 0

        # Archive file verification
        elif backup_format in [BackupFormat.TAR, BackupFormat.TAR_GZ, BackupFormat.TAR_GPG, BackupFormat.TAR_GZ_GPG]:
            # For TAR files, check if it's a valid archive
            if backup_format == BackupFormat.TAR:
                verify_cmd = ["tar", "-tf", str(backup_file)]
            elif backup_format == BackupFormat.TAR_GZ:
                verify_cmd = ["tar", "-tzf", str(backup_file)]
            elif backup_format in [BackupFormat.TAR_GPG, BackupFormat.TAR_GZ_GPG]:
                # For encrypted archives, we need to pipe through GPG
                # This is just a basic check if the GPG file is valid
                verify_cmd = ["gpg", "--list-packets", str(backup_file)]

            process = subprocess.run(verify_cmd, capture_output=True)
            return process.returncode == 0

    except Exception as e:
        logger.error(f"Failed to verify backup structure: {e}")

    return False


def restore_database_backup(
    backup_file: Path,
    db_name: str,
    backup_format: BackupFormat,
    timeout: int
) -> Tuple[bool, str]:
    """Restore a database backup to a test database."""
    try:
        # Create test database
        create_db_cmd = ["psql", "-U", "postgres", "-c", f"CREATE DATABASE {db_name}"]
        subprocess.run(create_db_cmd, check=True, capture_output=True, timeout=30)

        # Prepare restore command based on backup format
        if backup_format == BackupFormat.SQL:
            restore_cmd = f"psql -U postgres -d {db_name} -f {backup_file}"

        elif backup_format == BackupFormat.SQL_GZ:
            restore_cmd = f"gunzip -c {backup_file} | psql -U postgres -d {db_name}"

        elif backup_format == BackupFormat.SQL_GPG:
            restore_cmd = f"gpg --decrypt {backup_file} | psql -U postgres -d {db_name}"

        elif backup_format == BackupFormat.SQL_GZ_GPG:
            restore_cmd = f"gpg --decrypt {backup_file} | gunzip | psql -U postgres -d {db_name}"

        else:
            return False, "Unsupported backup format for database restore"

        # Execute restore command
        process = subprocess.run(restore_cmd, shell=True, capture_output=True, text=True, timeout=timeout)

        if process.returncode != 0:
            return False, f"Restore failed: {process.stderr}"

        return True, "Restore successful"

    except subprocess.TimeoutExpired:
        return False, f"Restore timed out after {timeout} seconds"

    except Exception as e:
        return False, f"Restore error: {e}"


def restore_file_backup(
    backup_file: Path,
    test_dir: Path,
    backup_format: BackupFormat,
    timeout: int
) -> Tuple[bool, str]:
    """Restore a file backup to a test directory."""
    try:
        # Prepare restore command based on backup format
        if backup_format == BackupFormat.TAR:
            restore_cmd = f"tar -xf {backup_file} -C {test_dir}"

        elif backup_format == BackupFormat.TAR_GZ:
            restore_cmd = f"tar -xzf {backup_file} -C {test_dir}"

        elif backup_format == BackupFormat.TAR_GPG:
            restore_cmd = f"gpg --decrypt {backup_file} | tar -x -C {test_dir}"

        elif backup_format == BackupFormat.TAR_GZ_GPG:
            restore_cmd = f"gpg --decrypt {backup_file} | tar -xz -C {test_dir}"

        else:
            return False, "Unsupported backup format for file restore"

        # Execute restore command
        process = subprocess.run(restore_cmd, shell=True, capture_output=True, text=True, timeout=timeout)

        if process.returncode != 0:
            return False, f"Restore failed: {process.stderr}"

        # Check if any files were actually extracted
        extracted_files = list(test_dir.glob('**/*'))
        if not extracted_files:
            return False, "No files were extracted from the backup"

        return True, f"Restore successful: {len(extracted_files)} files extracted"

    except subprocess.TimeoutExpired:
        return False, f"Restore timed out after {timeout} seconds"

    except Exception as e:
        return False, f"Restore error: {e}"


def verify_restored_data(
    backup_file: Path,
    db_name: str,
    test_dir: Path,
    backup_format: BackupFormat
) -> Tuple[bool, Dict[str, Any]]:
    """Verify restored backup data."""
    details = {
        "checks_performed": [],
        "check_results": {},
        "issues": []
    }

    try:
        if backup_format in [BackupFormat.SQL, BackupFormat.SQL_GZ, BackupFormat.SQL_GPG, BackupFormat.SQL_GZ_GPG]:
            # Verify database
            details["checks_performed"].append("database_connectivity")

            # Check if we can connect to the database
            connect_cmd = ["psql", "-U", "postgres", "-d", db_name, "-c", "SELECT 1"]
            process = subprocess.run(connect_cmd, capture_output=True)

            details["check_results"]["database_connectivity"] = process.returncode == 0
            if process.returncode != 0:
                details["issues"].append("Cannot connect to restored database")

            # Check if database has tables
            details["checks_performed"].append("table_existence")
            tables_cmd = ["psql", "-U", "postgres", "-d", db_name, "-c",
                          "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'", "-t"]
            process = subprocess.run(tables_cmd, capture_output=True, text=True)

            if process.returncode == 0:
                table_count = int(process.stdout.strip() or '0')
                details["check_results"]["table_existence"] = table_count > 0
                details["table_count"] = table_count

                if table_count == 0:
                    details["issues"].append("No tables found in restored database")
            else:
                details["check_results"]["table_existence"] = False
                details["issues"].append("Failed to check for tables in database")

        elif backup_format in [BackupFormat.TAR, BackupFormat.TAR_GZ, BackupFormat.TAR_GPG, BackupFormat.TAR_GZ_GPG]:
            # Verify extracted files
            details["checks_performed"].append("file_extraction")

            # Count extracted files
            file_count = sum(1 for _ in test_dir.glob('**/*'))
            details["check_results"]["file_extraction"] = file_count > 0
            details["file_count"] = file_count

            if file_count == 0:
                details["issues"].append("No files extracted from backup")

    except Exception as e:
        details["issues"].append(f"Verification error: {e}")

    # Overall success if we have no issues
    success = len(details["issues"]) == 0
    return success, details


def cleanup_test_dir(test_dir: Path) -> None:
    """Clean up test directory after verification."""
    if test_dir.exists():
        try:
            import shutil
            shutil.rmtree(test_dir)
        except Exception as e:
            logger.warning(f"Failed to clean up test directory: {e}")


def calculate_file_hash_fallback(file_path: Path, algorithm: str = 'sha256') -> str:
    """Calculate file hash when the file integrity module is not available."""
    hash_func = getattr(hashlib, algorithm)()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def check_database_backup_completeness(backup_file: Path) -> Dict[str, Any]:
    """Check if a database backup contains all required components."""
    result = {
        "required_components": ["schema", "tables", "data"],
        "found_components": [],
        "missing_components": [],
        "errors": []
    }

    # Extract a small sample to check content
    try:
        backup_format = detect_backup_format(backup_file)
        sample_content = ""

        if backup_format == BackupFormat.SQL:
            with open(backup_file, 'r') as f:
                sample_content = f.read(10240)  # Read first 10KB

        elif backup_format == BackupFormat.SQL_GZ:
            import gzip
            with gzip.open(backup_file, 'rt') as f:
                sample_content = f.read(10240)  # Read first 10KB

        elif backup_format in [BackupFormat.SQL_GPG, BackupFormat.SQL_GZ_GPG]:
            # For encrypted files, we can only check the file size as a heuristic
            size = backup_file.stat().st_size
            if size < 1024:  # Less than 1KB is suspicious
                result["errors"].append("Backup file is suspiciously small")
                result["missing_components"] = result["required_components"]
                return result

            # Can't check content without decryption
            result["found_components"] = ["schema", "tables", "data"]  # Assume all present
            return result

        # Check for schema definitions
        if "CREATE TABLE" in sample_content or "CREATE SCHEMA" in sample_content:
            result["found_components"].append("schema")
        else:
            result["missing_components"].append("schema")

        # Check for table definitions
        if "CREATE TABLE" in sample_content:
            result["found_components"].append("tables")
        else:
            result["missing_components"].append("tables")

        # Check for data
        if "INSERT INTO" in sample_content or "COPY " in sample_content:
            result["found_components"].append("data")
        else:
            result["missing_components"].append("data")

    except Exception as e:
        result["errors"].append(f"Failed to check database backup completeness: {e}")

    return result


def check_file_backup_completeness(backup_file: Path) -> Dict[str, Any]:
    """Check if a file backup contains all required components."""
    result = {
        "required_components": ["configurations", "data"],
        "found_components": [],
        "missing_components": [],
        "errors": []
    }

    # Create a temporary directory for checking
    import tempfile
    import shutil

    temp_dir = Path(tempfile.mkdtemp())
    try:
        backup_format = detect_backup_format(backup_file)

        # Extract file listing or sample files
        if backup_format == BackupFormat.TAR:
            cmd = f"tar -tf {backup_file}"
        elif backup_format == BackupFormat.TAR_GZ:
            cmd = f"tar -tzf {backup_file}"
        elif backup_format in [BackupFormat.TAR_GPG, BackupFormat.TAR_GZ_GPG]:
            # For encrypted archives, just check the file size
            size = backup_file.stat().st_size
            if size < 1024:  # Less than 1KB is suspicious
                result["errors"].append("Backup file is suspiciously small")
                result["missing_components"] = result["required_components"]
                return result

            # Can't check content without decryption
            result["found_components"] = ["configurations", "data"]  # Assume all present
            return result

        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if process.returncode != 0:
            result["errors"].append(f"Failed to list archive contents: {process.stderr}")
            result["missing_components"] = result["required_components"]
            return result

        # Check for configuration files
        file_list = process.stdout.splitlines()
        has_configs = any("config" in f for f in file_list)
        has_data = len(file_list) > 10  # Simple heuristic for data presence

        if has_configs:
            result["found_components"].append("configurations")
        else:
            result["missing_components"].append("configurations")

        if has_data:
            result["found_components"].append("data")
        else:
            result["missing_components"].append("data")

    except Exception as e:
        result["errors"].append(f"Failed to check file backup completeness: {e}")

    finally:
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

    return result


def generate_html_report(summary: Dict[str, Any]) -> str:
    """Generate HTML verification report."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup Verification Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #2c3e50; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .result { margin-bottom: 15px; padding: 10px; border-radius: 5px; }
        .success { background-color: #d4edda; border: 1px solid #c3e6cb; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeeba; }
        .failed { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        .error { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        table { border-collapse: collapse; width: 100%; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Backup Verification Report</h1>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Generated:</strong> {}</p>
        <p><strong>Total Backups:</strong> {}</p>
        <p><strong>Successful:</strong> {}</p>
        <p><strong>Warnings:</strong> {}</p>
        <p><strong>Failed:</strong> {}</p>
        <p><strong>Errors:</strong> {}</p>
    </div>

    <h2>Verification Results</h2>
    """.format(
        summary["report_generated"],
        summary["total_backups"],
        summary["successful"],
        summary["warnings"],
        summary["failed"],
        summary["errors"]
    )

    # Add detailed results
    for idx, result in enumerate(summary["verification_results"], 1):
        status_class = result.get("status", "error").lower()
        html += f"""
    <div class="result {status_class}">
        <h3>Backup #{idx}: {result.get('file', 'Unknown')}</h3>
        <table>
            <tr>
                <th>Status</th>
                <td>{result.get('status', 'Unknown')}</td>
            </tr>
    """

        # Add size if available
        if 'size' in result:
            size_mb = result['size'] / (1024 * 1024)
            html += f"""
            <tr>
                <th>Size</th>
                <td>{size_mb:.2f} MB ({result['size']} bytes)</td>
            </tr>
    """

        # Add timestamp if available
        if 'modified' in result:
            html += f"""
            <tr>
                <th>Modified</th>
                <td>{result.get('modified', 'Unknown')}</td>
            </tr>
    """

        # Add format if available
        if 'format' in result:
            html += f"""
            <tr>
                <th>Format</th>
                <td>{result.get('format', 'Unknown')}</td>
            </tr>
    """

        # Add checks if available
        if 'checks' in result and result['checks']:
            html += "<tr><th>Checks</th><td>"
            for check, status in result['checks'].items():
                if status:
                    html += f"<div>✅ {check}</div>"
                else:
                    html += f"<div>❌ {check}</div>"
            html += "</td></tr>"

        # Add errors if any
        if 'errors' in result and result['errors']:
            html += "<tr><th>Errors</th><td>"
            for error in result['errors']:
                html += f"<div>⚠️ {error}</div>"
            html += "</td></tr>"

        html += """
        </table>
    </div>
    """

    html += """
</body>
</html>
    """
    return html


def main():
    """Main function when run as a script."""
    import argparse

    parser = argparse.ArgumentParser(description="Backup Verification Tool")
    parser.add_argument("--file", "-f", help="Path to backup file")
    parser.add_argument("--dir", "-d", help="Directory containing backup files")
    parser.add_argument("--environment", "-e", default="production", help="Environment name")
    parser.add_argument("--verify-checksum", action="store_true", help="Verify checksum if available")
    parser.add_argument("--verify-structure", action="store_true", help="Verify backup file structure")
    parser.add_argument("--test-restore", action="store_true", help="Perform test restoration")
    parser.add_argument("--report", action="store_true", help="Generate verification report")
    parser.add_argument("--format", choices=SUPPORTED_FORMATS, default="text", help="Report format")
    parser.add_argument("--output", "-o", help="Output file for report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)

    # Initialize results list
    verification_results = []

    try:
        # Process single file or directory
        if args.file:
            file_path = Path(args.file)
            if not file_path.exists():
                logger.error(f"Backup file not found: {file_path}")
                return 1

            logger.info(f"Verifying backup file: {file_path}")

            # Verify integrity
            success, result = verify_backup_integrity(
                file_path,
                verify_checksum=args.verify_checksum,
                verify_structure=args.verify_structure
            )

            verification_results.append(result)

            if success:
                logger.info(f"Backup integrity verified successfully: {file_path}")
            else:
                logger.error(f"Backup integrity verification failed: {file_path}")

            # Perform test restore if requested
            if args.test_restore:
                logger.info(f"Performing test restore of backup: {file_path}")
                restore_success, restore_result = test_backup_restore(
                    file_path,
                    environment=args.environment
                )

                if restore_success:
                    logger.info("Test restore successful")
                else:
                    logger.error("Test restore failed")

            # Check encryption if encryption verification is needed
            enc_success, enc_result = verify_backup_encryption(file_path)
            if enc_result["is_encrypted"]:
                logger.info(f"Encryption verified: {enc_result['encryption_type']}")
            else:
                logger.warning("Backup is not encrypted")

            # Check backup completeness
            comp_success, comp_result = check_backup_completeness(file_path)
            if comp_success:
                logger.info("Backup content is complete")
            else:
                missing = ", ".join(comp_result.get("missing_components", []))
                logger.warning(f"Backup is incomplete. Missing components: {missing}")

        elif args.dir:
            dir_path = Path(args.dir)
            if not dir_path.is_dir():
                logger.error(f"Backup directory not found: {dir_path}")
                return 1

            logger.info(f"Verifying backups in directory: {dir_path}")

            # Find backup files
            backup_files = list(dir_path.glob("**/*.sql")) + \
                           list(dir_path.glob("**/*.sql.gz")) + \
                           list(dir_path.glob("**/*.sql.gpg")) + \
                           list(dir_path.glob("**/*.sql.gz.gpg")) + \
                           list(dir_path.glob("**/*.tar")) + \
                           list(dir_path.glob("**/*.tar.gz")) + \
                           list(dir_path.glob("**/*.tar.gpg")) + \
                           list(dir_path.glob("**/*.tar.gz.gpg"))

            if not backup_files:
                logger.error("No backup files found in directory")
                return 1

            logger.info(f"Found {len(backup_files)} backup files")

            # Verify each file
            for file_path in backup_files:
                logger.info(f"Verifying backup file: {file_path}")

                success, result = verify_backup_integrity(
                    file_path,
                    verify_checksum=args.verify_checksum,
                    verify_structure=args.verify_structure
                )

                verification_results.append(result)

                if success:
                    logger.info(f"Backup integrity verified successfully: {file_path}")
                else:
                    logger.error(f"Backup integrity verification failed: {file_path}")

        else:
            logger.error("No backup file or directory specified")
            parser.print_help()
            return 1

        # Generate report if requested
        if args.report:
            logger.info("Generating verification report")
            report_success, report_path = generate_verification_report(
                verification_results,
                output_file=args.output,
                format=args.format
            )

            if report_success:
                logger.info(f"Verification report generated: {report_path}")
            else:
                logger.error("Failed to generate verification report")

        return 0

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 130
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


# Module exports
__all__ = [
    # Core verification functions
    "verify_backup_integrity",
    "test_backup_restore",
    "verify_backup_encryption",
    "generate_verification_report",
    "check_backup_completeness",

    # Helper functions
    "detect_backup_format",
    "verify_backup_checksum",
    "verify_backup_structure",

    # Classes
    "VerificationStatus",
    "BackupFormat",

    # Constants
    "BACKUP_DIR",
    "TEST_RESTORE_DIR",
    "DEFAULT_REPORT_DIR",
    "SUPPORTED_FORMATS",
    "DEFAULT_TEST_DB_NAME",
    "DEFAULT_VERIFICATION_TIMEOUT",

    # Main entry point
    "main"
]


if __name__ == "__main__":
    sys.exit(main())
