#!/usr/bin/env python3
# filepath: scripts/utils/dev_tools/update_imports.py
"""
Import Statement Updater for Core Utils Migration

This script automatically updates import statements across the codebase to reflect
the migration of functions from the monolithic core/utils.py to specialized modules
in core/utils/* and core/security/*.

Usage:
    python update_imports.py [--dry-run] [--path /path/to/dir] [--backup] [--verbose]

Options:
    --dry-run       Show changes without applying them
    --path          Specify a subdirectory to process (default: entire project)
    --backup        Create .bak files before modifying
    --verbose       Show detailed information during processing
    --help          Show this help message
"""

import argparse
import glob
import os
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional

# Define the import mappings - source: destination
IMPORT_MAPPINGS = {
    # File integrity and security functions to security module
    "detect_file_changes": "core.security.cs_file_integrity",
    "check_critical_file": "core.security.cs_file_integrity",
    "check_critical_files": "core.security.cs_file_integrity",
    "_check_critical_files": "core.security.cs_file_integrity",
    "_check_critical_file": "core.security.cs_file_integrity",
    "_check_known_files": "core.security.cs_file_integrity",
    "_check_file_permissions": "core.security.cs_file_integrity",
    "_check_file_ownership": "core.security.cs_file_integrity",
    "_check_file_signatures": "core.security.cs_file_integrity",
    "verify_file_signature": "core.security.cs_file_integrity",
    "log_file_integrity_event": "core.security.cs_file_integrity",
    "update_file_integrity_baseline": "core.security.cs_file_integrity",

    # Security utility functions
    "sanitize_path": "core.security.cs_utils",
    "is_within_directory": "core.security.cs_utils",
    "is_safe_file_operation": "core.security.cs_utils",
    "get_redis_client": "core.utils.system",
    "obfuscate_sensitive_data": "core.security.cs_utils",

    # Cryptographic functions
    "generate_sri_hash": "core.security.cs_crypto",
    "calculate_file_hash": "core.security.cs_crypto",
    "compute_file_hash": "core.security.cs_crypto",
    "generate_secure_token": "core.security.cs_authentication",
    "secure_compare": "core.security.cs_crypto",

    # File operation functions
    "get_critical_file_hashes": "core.utils.file",
    "get_file_metadata": "core.utils.file",

    # Logging functions
    "setup_logging": "core.loggings",
    "log_critical": "core.loggings",
    "log_error": "core.loggings",
    "log_warning": "core.loggings",
    "log_info": "core.loggings",
    "log_debug": "core.loggings",

    # System resource functions
    "get_system_resources": "core.utils.system",
    "get_process_info": "core.utils.system",
    "get_request_context": "core.utils.system",
    "measure_execution_time": "core.utils.system",

    # Date/Time functions
    "now_utc": "core.utils.date_time",
    "utcnow": "core.utils.date_time",
    "format_timestamp": "core.utils.date_time",

    # General utilities
    "generate_request_id": "core.__init__",
    "safe_json_serialize": "core.utils.collection",
}

# Keep track of special cases for handling function name conflicts
FUNCTION_MERGES = {
    "compute_file_hash": "calculate_file_hash",  # In core.security.cs_crypto
    "now_utc": "utcnow",                         # In core.utils.date_time
}

# Special cases for modules that may have custom imports needed
MODULE_DEPENDENCIES = {
    "core.security.cs_file_integrity": ["import os", "import hashlib", "import logging", "from datetime import datetime"],
    "core.utils.system": ["import psutil", "import time", "from flask import request, g, has_request_context"],
    "core.utils.date_time": ["from datetime import datetime, timezone"]
}

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Update import statements in the codebase')
    parser.add_argument('--dry-run', action='store_true', help='Show changes without applying them')
    parser.add_argument('--path', default='.', help='Path to process (default: current directory)')
    parser.add_argument('--backup', action='store_true', help='Create backup files before modifying')
    parser.add_argument('--verbose', action='store_true', help='Show detailed information')

    return parser.parse_args()

def find_python_files(base_path: str) -> List[str]:
    """Find all Python files in the given path recursively."""
    base_path = Path(base_path)

    # Skip virtual environments and other non-project directories
    excludes = {'.git', '.venv', 'venv', '__pycache__', '.pytest_cache', '.tox', 'build', 'dist', '.vscode', '.idea'}

    python_files = []

    for path in base_path.glob('**/*.py'):
        # Check if path contains any excluded directory
        if any(exclude in str(part) for part in path.parts for exclude in excludes):
            continue
        python_files.append(str(path))

    return python_files

def analyze_file_imports(file_path: str, verbose: bool = False) -> Tuple[bool, Dict[str, Set[str]]]:
    """
    Analyze imports from core.utils in the given file.

    Returns:
        Tuple[bool, Dict[str, Set[str]]]: (needs_update, imports_by_module)
            - needs_update: Whether this file needs to be updated
            - imports_by_module: Dictionary mapping modules to sets of imported functions
    """
    needs_update = False
    imports_by_module = defaultdict(set)

    # Regular expressions to match different import patterns
    from_core_utils_import_re = re.compile(r'from\s+core\.utils\s+import\s+([^#\n]+)')
    from_core_import_utils_re = re.compile(r'from\s+core\s+import\s+([^#\n]+)')
    import_core_utils_re = re.compile(r'import\s+core\.utils')

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for "from core.utils import x, y, z" pattern
        for match in from_core_utils_import_re.finditer(content):
            imported_items = match.group(1).strip()

            # Handle multi-line imports with parentheses
            if '(' in imported_items and ')' not in imported_items:
                # Find closing parenthesis
                import_end = content.find(')', match.end())
                if import_end > 0:
                    imported_items = content[match.start(1):import_end].replace('\n', ' ')

            # Split and clean the imported items
            for item in re.split(r',\s*', imported_items):
                item = item.strip().rstrip(',').strip()
                if item:
                    # Handle "as" aliasing
                    if ' as ' in item:
                        actual_item, _ = item.split(' as ', 1)
                        item = actual_item.strip()

                    if item in IMPORT_MAPPINGS:
                        needs_update = True
                        target_module = IMPORT_MAPPINGS[item]
                        imports_by_module[target_module].add(item)

                        if verbose:
                            print(f"Found import of '{item}' from core.utils in {file_path}")

        # Check for "from core import utils" pattern
        if 'from core import utils' in content or 'from core import utils,' in content:
            needs_update = True
            if verbose:
                print(f"Found 'from core import utils' in {file_path}")

        # Check for "import core.utils" pattern
        if import_core_utils_re.search(content):
            needs_update = True
            if verbose:
                print(f"Found 'import core.utils' in {file_path}")

    except Exception as e:
        print(f"Error analyzing {file_path}: {e}", file=sys.stderr)
        return False, {}

    return needs_update, imports_by_module

def update_file_imports(file_path: str, backup: bool = False, dry_run: bool = False, verbose: bool = False) -> bool:
    """
    Update imports in the given file to use the new module structure.

    Args:
        file_path: Path to the file to update
        backup: Whether to create a backup file before updating
        dry_run: If True, just report what would be changed without modifying files
        verbose: Whether to show detailed information

    Returns:
        bool: Whether any changes were made
    """
    needs_update, imports_by_module = analyze_file_imports(file_path, verbose)

    if not needs_update:
        return False

    # Create backup if requested
    if backup and not dry_run:
        backup_path = f"{file_path}.bak"
        shutil.copy2(file_path, backup_path)
        if verbose:
            print(f"Created backup at {backup_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = []
        skip_next_lines = 0
        i = 0

        while i < len(lines):
            if skip_next_lines > 0:
                skip_next_lines -= 1
                i += 1
                continue

            line = lines[i]
            modified = False

            # Handle "from core.utils import x, y, z" pattern
            from_core_utils_match = re.match(r'from\s+core\.utils\s+import\s+([^#\n]+)', line)
            if from_core_utils_match:
                imported_items = from_core_utils_match.group(1).strip()

                # Handle multi-line imports with parentheses
                is_multiline = False
                if '(' in imported_items and ')' not in imported_items:
                    is_multiline = True
                    # Find all lines until closing parenthesis
                    complete_import = line
                    j = i + 1
                    while j < len(lines) and ')' not in lines[j]:
                        complete_import += lines[j]
                        j += 1
                    if j < len(lines):
                        complete_import += lines[j]
                        skip_next_lines = j - i  # Skip these lines in the next iteration

                    # Extract all imported items
                    import_content = complete_import[complete_import.find('(') + 1:complete_import.find(')')].replace('\n', ' ')
                    imported_items = [item.strip() for item in re.split(r',\s*', import_content) if item.strip()]
                else:
                    # Single line import
                    imported_items = [item.strip() for item in imported_items.split(',') if item.strip()]

                # Group imports by destination module
                new_imports = defaultdict(list)
                remaining_imports = []

                for item in imported_items:
                    original_item = item

                    # Handle "as" aliasing
                    alias_suffix = ""
                    if ' as ' in item:
                        item, alias = item.split(' as ', 1)
                        item = item.strip()
                        alias_suffix = f" as {alias}"

                    if item in IMPORT_MAPPINGS:
                        target_module = IMPORT_MAPPINGS[item]

                        # Check if this is a function that will be merged with another
                        if item in FUNCTION_MERGES:
                            target_name = FUNCTION_MERGES[item]
                            new_imports[target_module].append(f"{target_name}{alias_suffix}")
                        else:
                            new_imports[target_module].append(f"{item}{alias_suffix}")
                    else:
                        remaining_imports.append(original_item)

                # Generate new import statements
                added_imports = []
                for module, imports in new_imports.items():
                    if imports:
                        if len(imports) > 3:  # Use multi-line format for many imports
                            added_imports.append(f"from {module} import (\n")
                            for imp in imports:
                                added_imports.append(f"    {imp},\n")
                            added_imports.append(")\n")
                        else:
                            added_imports.append(f"from {module} import {', '.join(imports)}\n")

                # Add remaining core.utils imports if any
                if remaining_imports:
                    if len(remaining_imports) > 3:  # Use multi-line format for many imports
                        added_imports.append("from core.utils import (\n")
                        for imp in remaining_imports:
                            added_imports.append(f"    {imp},\n")
                        added_imports.append(")\n")
                    else:
                        added_imports.append(f"from core.utils import {', '.join(remaining_imports)}\n")

                # Replace current line with new imports
                if added_imports:
                    if not dry_run:
                        new_lines.extend(added_imports)
                    modified = True
                    if verbose:
                        print(f"Replaced import in {file_path}:")
                        print(f"  Old: {line.strip()}")
                        for new_line in added_imports:
                            print(f"  New: {new_line.strip()}")
                else:
                    # No changes needed for this line
                    new_lines.append(line)

                # Skip additional lines for multi-line imports
                if is_multiline:
                    i += skip_next_lines
                    skip_next_lines = 0

            # Handle "from core import utils" pattern
            elif re.match(r'from\s+core\s+import\s+([^#\n]*\b)utils\b', line):
                # We need to replace with multiple imports from specific modules
                if not dry_run:
                    # Add needed imports for functions used in the file
                    added_imports = []
                    for module, functions in imports_by_module.items():
                        if functions:  # Skip if no functions from this module are used
                            function_list = sorted(list(functions))
                            if len(function_list) > 3:  # Use multi-line format for many imports
                                added_imports.append(f"from {module} import (\n")
                                for func in function_list:
                                    added_imports.append(f"    {func},\n")
                                added_imports.append(")\n")
                            else:
                                added_imports.append(f"from {module} import {', '.join(function_list)}\n")

                    # If no specific imports were found, keep original line as a fallback
                    if not added_imports:
                        new_lines.append(line)
                    else:
                        new_lines.extend(added_imports)

                modified = True
                if verbose:
                    print(f"Replaced 'from core import utils' in {file_path}")

            # Handle "import core.utils" pattern
            elif re.match(r'import\s+core\.utils\b', line):
                # We need to replace with multiple imports from specific modules
                if not dry_run:
                    # Add needed imports for functions used in the file
                    added_imports = []
                    for module, functions in imports_by_module.items():
                        if functions:  # Skip if no functions from this module are used
                            function_list = sorted(list(functions))
                            if len(function_list) > 3:  # Use multi-line format for many imports
                                added_imports.append(f"from {module} import (\n")
                                for func in function_list:
                                    added_imports.append(f"    {func},\n")
                                added_imports.append(")\n")
                            else:
                                added_imports.append(f"from {module} import {', '.join(function_list)}\n")

                    # If no specific imports were found, keep original line as a fallback
                    if not added_imports:
                        new_lines.append(line)
                    else:
                        new_lines.extend(added_imports)

                modified = True
                if verbose:
                    print(f"Replaced 'import core.utils' in {file_path}")

            else:
                # No modifications needed for this line
                if not dry_run:
                    new_lines.append(line)

            i += 1

        # Write changes back to the file
        if modified and not dry_run:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)

            if verbose:
                print(f"Updated imports in {file_path}")

        return modified

    except Exception as e:
        print(f"Error updating {file_path}: {e}", file=sys.stderr)
        return False

def main():
    """Main entry point for the script."""
    args = parse_args()

    print(f"{'DRY RUN: ' if args.dry_run else ''}Updating import statements in Python files")

    base_path = args.path
    python_files = find_python_files(base_path)
    print(f"Found {len(python_files)} Python files to analyze")

    # Statistics for reporting
    files_analyzed = 0
    files_modified = 0

    for file_path in python_files:
        if args.verbose:
            print(f"Analyzing {file_path}...")

        files_analyzed += 1
        modified = update_file_imports(
            file_path,
            backup=args.backup,
            dry_run=args.dry_run,
            verbose=args.verbose
        )

        if modified:
            files_modified += 1

    print(f"Analysis complete. {files_analyzed} files analyzed, {files_modified} files need updating.")

    if args.dry_run and files_modified > 0:
        print("\nRun without --dry-run to apply these changes.")

    if files_modified > 0:
        print("\nFunctions moved to new locations:")
        modules_printed = set()

        # Group by destination module for cleaner output
        imports_by_module = defaultdict(list)
        for func, module in IMPORT_MAPPINGS.items():
            imports_by_module[module].append(func)

        for module, functions in sorted(imports_by_module.items()):
            print(f"\n  {module}:")
            for func in sorted(functions):
                if func in FUNCTION_MERGES:
                    target_func = FUNCTION_MERGES[func]
                    print(f"    {func} -> {target_func}")
                else:
                    print(f"    {func}")

if __name__ == "__main__":
    main()
