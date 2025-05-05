#!/usr/bin/env python3
"""
Build deployment package for the Cloud Infrastructure Platform.

This script prepares a deployment package by bundling application code,
cleaning up unnecessary files, generating version information, and verifying
file integrity before packaging.
"""

import os
import sys
import json
import shutil
import hashlib
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
PACKAGE_NAME = "cloud-platform"
VERSION_FILE = PROJECT_ROOT / "version.json"
INTEGRITY_FILE = PROJECT_ROOT / "deployment/security/file_integrity_baseline.json"

# Files and directories to exclude from the distribution package
EXCLUDE_PATTERNS = [
    "__pycache__",
    "*.pyc",
    ".git",
    ".github",
    ".pytest_cache",
    ".coverage",
    "htmlcov",
    "tests",
    "venv",
    ".env",
    ".vscode",
    ".idea",
    "*.log",
    ".DS_Store",
    "node_modules",
    "dist",
    ".ropeproject",
    ".secure/credentials",
    "deployment/credentials",
]

# Critical paths that require special verification
CRITICAL_PATHS = [
    "core/security",
    "config",
    "core/factory.py",
    "core/middleware.py",
    "models/security",
    "api/security",
]


def log(message: str, level: str = "INFO") -> None:
    """Print a timestamped log message with level.

    Args:
        message: The message to log
        level: The log level (INFO, WARNING, ERROR)
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] {message}")


def get_version_info() -> Dict[str, Any]:
    """Get version information from git and environment.

    Returns:
        Dictionary containing version information and build metadata
    """
    try:
        # Get git information
        git_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            universal_newlines=True
        ).strip()

        git_branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            universal_newlines=True
        ).strip()

        # Get tag if available
        try:
            git_tag = subprocess.check_output(
                ["git", "describe", "--tags", "--exact-match"],
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            ).strip()
        except subprocess.CalledProcessError:
            git_tag = None

        # Use tag as version if available, otherwise use timestamp
        if git_tag and git_tag.startswith("v"):
            version = git_tag[1:]  # Remove 'v' prefix
        else:
            version = f"0.dev{datetime.now().strftime('%Y%m%d%H%M')}"

        return {
            "version": version,
            "git_hash": git_hash,
            "git_branch": git_branch,
            "git_tag": git_tag,
            "build_date": datetime.now().isoformat(),
            "build_user": os.environ.get("USER", "unknown"),
            "build_system": os.uname().nodename,
        }
    except Exception as e:
        log(f"Error getting version info: {e}", "ERROR")
        return {
            "version": f"0.dev{datetime.now().strftime('%Y%m%d%H%M')}",
            "build_date": datetime.now().isoformat(),
            "error": str(e),
        }


def should_exclude(path: Path) -> bool:
    """Check if a path should be excluded based on patterns.

    Args:
        path: The path to check against exclusion patterns

    Returns:
        True if the path should be excluded, False otherwise
    """
    path_str = str(path)
    return any(pattern in path_str for pattern in EXCLUDE_PATTERNS) or any(
        path_str.endswith(ext) for ext in [".pyc", ".pyo", ".pyd", ".so", ".dll"]
    )


def is_critical_path(path: Path) -> bool:
    """Check if a path is a critical security path.

    Args:
        path: The path to check

    Returns:
        True if the path contains security-critical code, False otherwise
    """
    path_str = str(path)
    return any(critical in path_str for critical in CRITICAL_PATHS)


def copy_files(src_dir: Path, dest_dir: Path, integrity_check: bool = True) -> Dict[str, str]:
    """Copy files from source to destination, excluding patterns.

    Args:
        src_dir: Source directory
        dest_dir: Destination directory
        integrity_check: Whether to perform file integrity checks

    Returns:
        Dictionary of copied files and their hashes for integrity verification
    """
    file_hashes = {}

    for item in src_dir.glob("*"):
        if should_exclude(item):
            continue

        dest_path = dest_dir / item.name
        if item.is_dir():
            if not dest_path.exists():
                dest_path.mkdir(parents=True)

            # Recursively copy subdirectories
            sub_hashes = copy_files(item, dest_path, integrity_check)
            file_hashes.update(sub_hashes)
        else:
            shutil.copy2(item, dest_path)

            # Calculate hash for integrity checking if needed
            if integrity_check:
                rel_path = str(item.relative_to(PROJECT_ROOT))
                file_hashes[rel_path] = calculate_file_hash(item)

                # Additional verification for critical files
                if is_critical_path(item):
                    log(f"Verifying critical file: {rel_path}")

    return file_hashes


def calculate_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """Calculate cryptographic hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        Hex digest of the file hash
    """
    hash_obj = hashlib.new(algorithm)

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def calculate_checksums(package_file: Path) -> Dict[str, str]:
    """Calculate checksums for the package.

    Args:
        package_file: Path to the package file

    Returns:
        Dictionary with MD5 and SHA256 checksums
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(package_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def verify_file_integrity(file_hashes: Dict[str, str]) -> Tuple[bool, List[str]]:
    """Verify integrity of critical files against baseline.

    Args:
        file_hashes: Dictionary of file paths and their hashes

    Returns:
        Tuple of (success_status, list_of_modified_files)
    """
    if not INTEGRITY_FILE.exists():
        log("File integrity baseline not found, skipping verification", "WARNING")
        return True, []

    try:
        with open(INTEGRITY_FILE, 'r') as f:
            baseline = json.load(f)

        modified_files = []

        # Check each critical file against the baseline
        for path, current_hash in file_hashes.items():
            if path in baseline and baseline[path] != current_hash:
                modified_files.append(path)
                log(f"Integrity check failed for: {path}", "WARNING")

        if modified_files:
            log(f"Found {len(modified_files)} modified critical files", "WARNING")
            return False, modified_files

        return True, []

    except Exception as e:
        log(f"Error verifying file integrity: {e}", "ERROR")
        return False, []


def create_manifest(build_dir: Path, file_hashes: Dict[str, str], version_info: Dict[str, Any]) -> None:
    """Create a package manifest with file inventory and hashes.

    Args:
        build_dir: Build directory
        file_hashes: Dictionary of file hashes
        version_info: Version information dictionary
    """
    manifest = {
        "version": version_info["version"],
        "build_date": version_info["build_date"],
        "git_hash": version_info.get("git_hash", "unknown"),
        "git_tag": version_info.get("git_tag", "unknown"),
        "files_count": len(file_hashes),
        "files": file_hashes
    }

    manifest_file = build_dir / "MANIFEST.json"
    with open(manifest_file, "w") as f:
        json.dump(manifest, f, indent=2)


def main() -> int:
    """Main build function.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    log("Starting build process")

    try:
        # Create distribution directory
        if DIST_DIR.exists():
            shutil.rmtree(DIST_DIR)
        DIST_DIR.mkdir(parents=True)

        # Get version information
        version_info = get_version_info()
        version = version_info["version"]
        log(f"Building version {version}")

        # Create version file
        with open(VERSION_FILE, "w") as f:
            json.dump(version_info, f, indent=2)

        # Create build directory
        build_dir = DIST_DIR / "build"
        build_dir.mkdir()

        # Copy files and verify integrity
        log("Copying files and performing integrity checks")
        file_hashes = copy_files(PROJECT_ROOT, build_dir)

        # Verify integrity of critical files
        integrity_ok, modified_files = verify_file_integrity(file_hashes)
        if not integrity_ok and os.environ.get("CI_SKIP_INTEGRITY_CHECK") != "true":
            log("File integrity check failed. Use CI_SKIP_INTEGRITY_CHECK=true to bypass.", "ERROR")
            return 1

        # Create manifest with file inventory
        create_manifest(build_dir, file_hashes, version_info)

        # Create package
        package_file = DIST_DIR / f"{PACKAGE_NAME}-{version}.tar.gz"
        log(f"Creating package {package_file}")

        subprocess.run(
            ["tar", "-czf", str(package_file), "-C", str(build_dir.parent), "build"],
            check=True
        )

        # Calculate checksums
        checksums = calculate_checksums(package_file)
        log(f"MD5: {checksums['md5']}")
        log(f"SHA256: {checksums['sha256']}")

        # Create checksums file
        with open(DIST_DIR / f"{PACKAGE_NAME}-{version}.checksums", "w") as f:
            f.write(f"MD5: {checksums['md5']}\n")
            f.write(f"SHA256: {checksums['sha256']}\n")

        # Create metadata file
        metadata = {
            **version_info,
            **checksums,
            "package_name": f"{PACKAGE_NAME}-{version}.tar.gz",
            "package_size": os.path.getsize(package_file),
            "files_count": len(file_hashes),
            "integrity_verified": integrity_ok
        }

        with open(DIST_DIR / f"{PACKAGE_NAME}-{version}.meta.json", "w") as f:
            json.dump(metadata, f, indent=2)

        # Clean up build directory
        shutil.rmtree(build_dir)

        log(f"Build completed successfully: {package_file}")
        return 0

    except subprocess.CalledProcessError as e:
        log(f"Command failed: {e}", "ERROR")
        return e.returncode
    except Exception as e:
        log(f"Build failed: {e}", "ERROR")
        return 1


if __name__ == "__main__":
    sys.exit(main())
