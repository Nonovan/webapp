#!/usr/bin/env python3
"""
File integrity verification tool for Cloud Infrastructure Platform.
Compares file hashes against stored values to detect changes.
"""

import os
import sys
import json
import argparse
import hashlib
import logging
import smtplib
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Tuple, Set

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
HASH_FILE = PROJECT_ROOT / "instance" / "file_hashes.json"
LOG_FILE = Path("/var/log/cloud-platform/file_verify.log")
EMAIL_FROM = "security@cloud-platform.example.com"
EMAIL_TO = "admin@cloud-platform.example.com"

# Ensure directories exist
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
HASH_FILE.parent.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("verify_files")

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file."""
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return ""

def load_hash_file() -> Dict[str, str]:
    """Load the hash file if it exists, or return empty dict."""
    try:
        if HASH_FILE.exists():
            with open(HASH_FILE, 'r') as f:
                return json.load(f)
        else:
            logger.warning(f"Hash file {HASH_FILE} does not exist")
            return {}
    except Exception as e:
        logger.error(f"Error loading hash file: {e}")
        return {}

def update_hash_file(hashes: Dict[str, str]) -> bool:
    """Update the hash file with new hashes."""
    try:
        with open(HASH_FILE, 'w') as f:
            json.dump(hashes, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error updating hash file: {e}")
        return False

def verify_files(paths: List[str], update_hashes: bool = False) -> Tuple[Dict[str, str], Set[str], Set[str]]:
    """
    Verify file integrity by comparing hashes.
    
    Args:
        paths: List of file paths to check
        update_hashes: Whether to update the hash file with current hashes
        
    Returns:
        Tuple of (modified files, missing files, new files)
    """
    stored_hashes = load_hash_file()
    current_hashes = {}
    modified_files = {}
    missing_files = set()
    
    # Check all paths
    for path in paths:
        if os.path.isfile(path):
            current_hash = calculate_file_hash(path)
            current_hashes[path] = current_hash
            
            if path in stored_hashes:
                if current_hash != stored_hashes[path]:
                    logger.warning(f"File modified: {path}")
                    modified_files[path] = {
                        "old_hash": stored_hashes[path],
                        "new_hash": current_hash
                    }
            else:
                logger.info(f"New file detected: {path}")
    
    # Find missing files
    for path in stored_hashes:
        if path not in current_hashes:
            logger.warning(f"File missing: {path}")
            missing_files.add(path)
    
    # Find new files
    new_files = set(current_hashes.keys()) - set(stored_hashes.keys())
    
    # Update hash file if requested
    if update_hashes:
        logger.info("Updating hash file")
        if update_hash_file(current_hashes):
            logger.info("Hash file updated successfully")
        else:
            logger.error("Failed to update hash file")
    
    return modified_files, missing_files, new_files

def send_alert(modified: Dict[str, str], missing: Set[str], new: Set[str]) -> None:
    """Send email alert about file integrity issues."""
    try:
        subject = f"[ALERT] File integrity issues on {os.uname().nodename}"
        
        message_body = "File integrity verification detected the following issues:\n\n"
        
        if modified:
            message_body += "MODIFIED FILES:\n"
            for path in modified:
                message_body += f"- {path}\n"
            message_body += "\n"
        
        if missing:
            message_body += "MISSING FILES:\n"
            for path in missing:
                message_body += f"- {path}\n"
            message_body += "\n"
        
        if new:
            message_body += "NEW FILES:\n"
            for path in new:
                message_body += f"- {path}\n"
            message_body += "\n"
        
        message_body += "\nPlease investigate these changes immediately.\n"
        
        msg = MIMEText(message_body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        
        with smtplib.SMTP('localhost') as smtp:
            smtp.send_message(msg)
            
        logger.info("Alert email sent successfully")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")

def main() -> int:
    """Main function."""
    parser = argparse.ArgumentParser(description='Verify file integrity.')
    parser.add_argument('--update', action='store_true', 
                        help='Update hash file with current file hashes')
    parser.add_argument('--alert', action='store_true',
                        help='Send email alert if changes are detected')
    parser.add_argument('--paths', nargs='+', default=[],
                        help='Specific paths to verify')
    args = parser.parse_args()
    
    # Default critical paths to check if none specified
    default_paths = [
        str(PROJECT_ROOT / "app.py"),
        str(PROJECT_ROOT / "config.py"),
        str(PROJECT_ROOT / "requirements.txt"),
        str(PROJECT_ROOT / "config" / "production.py"),
        "/etc/nginx/sites-enabled/default",
        "/etc/nginx/nginx.conf",
        "/etc/cloud-platform/config.ini",
        "/etc/systemd/system/cloud-platform.service"
    ]
    
    paths_to_check = args.paths if args.paths else default_paths
    
    logger.info(f"Starting file integrity verification")
    modified, missing, new = verify_files(paths_to_check, args.update)
    
    # Log summary
    total_issues = len(modified) + len(missing) + len(new)
    if total_issues > 0:
        logger.warning(f"Integrity check found issues: {len(modified)} modified, {len(missing)} missing, {len(new)} new")
        if args.alert:
            send_alert(modified, missing, new)
    else:
        logger.info("All files verified successfully")
    
    return 0 if total_issues == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
