#!/usr/bin/env python3
"""
Build deployment package for the Cloud Infrastructure Platform.

This script prepares a deployment package by bundling application code,
cleaning up unnecessary files, and generating version information.
"""

import os
import sys
import json
import shutil
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
PACKAGE_NAME = "cloud-platform"
VERSION_FILE = PROJECT_ROOT / "version.json"

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
]


def log(message):
    """Print a timestamped log message."""
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}")


def get_version_info():
    """Get version information from git and environment."""
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
        log(f"Error getting version info: {e}")
        return {
            "version": f"0.dev{datetime.now().strftime('%Y%m%d%H%M')}",
            "build_date": datetime.now().isoformat(),
            "error": str(e),
        }


def should_exclude(path):
    """Check if a path should be excluded based on patterns."""
    path_str = str(path)
    return any(pattern in path_str for pattern in EXCLUDE_PATTERNS)


def copy_files(src_dir, dest_dir):
    """Copy files from source to destination, excluding patterns."""
    for item in src_dir.glob("*"):
        if should_exclude(item):
            continue
        
        dest_path = dest_dir / item.name
        if item.is_dir():
            if not dest_path.exists():
                dest_path.mkdir(parents=True)
            copy_files(item, dest_path)
        else:
            shutil.copy2(item, dest_path)


def calculate_checksums(package_file):
    """Calculate MD5 and SHA256 checksums for the package."""
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


def main():
    """Main build function."""
    log("Starting build process")
    
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
    
    # Copy files
    log("Copying files")
    copy_files(PROJECT_ROOT, build_dir)
    
    # Create package
    package_file = DIST_DIR / f"{PACKAGE_NAME}-{version}.tar.gz"
    log(f"Creating package {package_file}")
    
    subprocess.run(
        ["tar", "-czf", package_file, "-C", build_dir.parent, "build"],
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
    }
    
    with open(DIST_DIR / f"{PACKAGE_NAME}-{version}.meta.json", "w") as f:
        json.dump(metadata, f, indent=2)
    
    # Clean up build directory
    shutil.rmtree(build_dir)
    
    log(f"Build completed successfully: {package_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
