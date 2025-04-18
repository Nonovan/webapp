#!/usr/bin/env python3
"""Verify file integrity and permissions"""
from core.utils import detect_file_changes, get_critical_file_hashes
import json
import sys
import os

# Define critical files
critical_files = [
    'app.py', 'config.py', 'core/security_utils.py', 'core/middleware.py'
]

# Get current directory
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Generate reference hashes
reference_hashes = get_critical_file_hashes(
    [os.path.join(base_dir, f) for f in critical_files]
)

# Check for changes
changes = detect_file_changes(base_dir, reference_hashes)

if changes:
    print(f"❌ Found {len(changes)} file integrity issues:")
    print(json.dumps(changes, indent=2))
    sys.exit(1)
else:
    print("✅ All files verified successfully")
    sys.exit(0)