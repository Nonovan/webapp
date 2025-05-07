#!/usr/bin/env python3
"""
Import Statement Updater for Core Utils Migration

This script automatically updates import statements across the codebase to reflect
the migration of functions from the monolithic core/utils.py to specialized modules
in core/utils/* and core/security/*.

Usage:
    python import_statement_updater.py [--dry-run] [--path /path/to/dir] [--backup] [--verbose]

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
from typing import Dict, List, Tuple, Set, Optional, Union, Any

# Import mappings - source function: destination module
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
    "generate_sri_hash": "core.security.cs_crypto",
    "calculate_file_hash": "core.security.cs_crypto",
    "compute_file_hash": "core.security.cs_crypto",
    "generate_secure_token": "core.security.cs_authentication",
    "secure_compare": "core.security.cs_crypto",
    "get_critical_file_hashes": "core.utils.file",
    "get_file_metadata": "core.utils.file",

    # Logging functions
    "setup_logging": "core.utils.logging_utils",
    "log_critical": "core.utils.logging_utils",
    "log_error": "core.utils.logging_utils",
    "log_warning": "core.utils.logging_utils",
    "log_info": "core.utils.logging_utils",
    "log_debug": "core.utils.logging_utils",

    # System utility functions
    "get_system_resources": "core.utils.system",
    "get_process_info": "core.utils.system",
    "get_request_context": "core.utils.system",
    "measure_execution_time": "core.utils.system",

    # Date/time utilities
    "now_utc": "core.utils.date_time",
    "utcnow": "core.utils.date_time",
    "format_timestamp": "core.utils.date_time",

    # Request utilities
    "generate_request_id": "core.__init__",

    # Collection utilities
    "safe_json_serialize": "core.utils.collection",

    # String utilities
    "slugify": "core.utils.string",
    "truncate_text": "core.utils.string",
    "strip_html_tags": "core.utils.string",
    "sanitize_html": "core.utils.string"
}

# Special case handling for renamed functions (old: new)
FUNCTION_MERGES = {
    "truncate_text": "truncate",
    "strip_html_tags": "strip_tags"
}

# Special case dependency handling - if we import one of these functions,
# make sure to import dependencies as well
MODULE_DEPENDENCIES = {
    "core.security.cs_file_integrity": {
        "detect_file_changes": ["calculate_file_hash"],
        "update_file_integrity_baseline": ["log_security_event"]
    },
    "core.utils.string": {
        "sanitize_html": ["strip_html_tags"]
    }
}

__all__ = [
    "IMPORT_MAPPINGS",
    "FUNCTION_MERGES",
    "MODULE_DEPENDENCIES"

    "find_python_files",
    "analyze_file_imports",
    "update_file_imports",
    "parse_args"
]

def find_python_files(start_path: str) -> List[str]:
    """Find all Python files in the given directory and subdirectories.

    Args:
        start_path: Directory to search in

    Returns:
        List of Python file paths
    """
    python_files = []

    if not os.path.exists(start_path):
        print(f"Error: Path {start_path} does not exist.")
        return []

    for root, _, files in os.walk(start_path):
        # Skip virtual environments, .git directories, and __pycache__
        if any(p in root for p in ['venv', '.venv', '.git', '__pycache__']):
            continue

        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))

    return python_files

def analyze_file_imports(filepath: str) -> Dict[str, Any]:
    """Analyze import statements in a Python file.

    Args:
        filepath: Path to the Python file to analyze

    Returns:
        Dictionary containing import information
    """
    imports = {
        'from_imports': [],
        'import_imports': [],
        'core_utils_imports': [],
        'utils_to_update': []
    }

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find direct imports (import xxx)
        import_pattern = r'^import\s+([\w\.]+)(?:\s+as\s+(\w+))?'
        for match in re.finditer(import_pattern, content, re.MULTILINE):
            module = match.group(1)
            alias = match.group(2)
            imports['import_imports'].append({
                'module': module,
                'alias': alias
            })

            # Check if this is a core.utils import
            if module == 'core.utils':
                imports['core_utils_imports'].append({
                    'type': 'direct',
                    'module': module,
                    'alias': alias or module
                })

        # Find from imports (from xxx import yyy)
        from_pattern = r'^from\s+([\w\.]+)\s+import\s+(.+?)(?:\s+#.*)?$'
        for match in re.finditer(from_pattern, content, re.MULTILINE):
            module = match.group(1)
            imports_text = match.group(2).strip()

            # Handle multi-line imports
            if '(' in imports_text:
                # Find the closing parenthesis
                paren_start = content.index('(', match.start())
                paren_end = content.index(')', paren_start)
                imports_text = content[paren_start + 1:paren_end].strip()

            # Process the imported symbols
            imported_items = []
            for item in re.split(r',\s*', imports_text):
                item = item.strip()
                if not item:
                    continue

                # Handle "as" aliases
                item_parts = item.split(' as ')
                if len(item_parts) == 2:
                    imported_items.append({
                        'name': item_parts[0].strip(),
                        'alias': item_parts[1].strip()
                    })
                else:
                    imported_items.append({
                        'name': item,
                        'alias': None
                    })

            imports['from_imports'].append({
                'module': module,
                'items': imported_items
            })

            # Check for core.utils imports
            if module == 'core.utils':
                imports['core_utils_imports'].append({
                    'type': 'from',
                    'module': module,
                    'items': imported_items
                })

                # Find items that need to be updated
                for item in imported_items:
                    name = item['name']
                    if name in IMPORT_MAPPINGS:
                        imports['utils_to_update'].append({
                            'name': name,
                            'alias': item['alias'],
                            'new_module': IMPORT_MAPPINGS[name]
                        })

        # Also check for usage of core.utils functions even if they're not explicitly imported
        # (might be used with full qualification)
        for func, module in IMPORT_MAPPINGS.items():
            pattern = rf'\bcore\.utils\.{func}\b'
            if re.search(pattern, content):
                imports['utils_to_update'].append({
                    'name': func,
                    'alias': None,
                    'new_module': module,
                    'fully_qualified': True
                })

    except Exception as e:
        print(f"Error analyzing {filepath}: {e}")

    return imports

def update_file_imports(filepath: str, dry_run: bool = False, backup: bool = False,
                        verbose: bool = False) -> Dict[str, Any]:
    """Update import statements in a Python file.

    Args:
        filepath: Path to the Python file to update
        dry_run: If True, don't make any changes
        backup: If True, create backup before modifying
        verbose: If True, print detailed information

    Returns:
        Dictionary with update statistics
    """
    results = {
        'file': filepath,
        'changes': [],
        'updated': False
    }

    # First analyze the file for imports
    imports = analyze_file_imports(filepath)
    utils_to_update = imports['utils_to_update']

    if not utils_to_update:
        if verbose:
            print(f"No updates needed in {filepath}")
        return results

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Create backup if requested
        if backup and not dry_run:
            backup_path = f"{filepath}.bak"
            shutil.copy2(filepath, backup_path)
            if verbose:
                print(f"Created backup at {backup_path}")

        # Group imports by new module
        new_imports_by_module = defaultdict(list)
        for update in utils_to_update:
            func_name = update['name']
            new_module = update['new_module']
            alias = update['alias']

            # Handle function merges (renames)
            if func_name in FUNCTION_MERGES:
                new_func_name = FUNCTION_MERGES[func_name]
                new_imports_by_module[new_module].append({
                    'name': new_func_name,
                    'alias': func_name if not alias else alias
                })
                results['changes'].append(f"Renamed import {func_name} -> {new_func_name} from {new_module}")
            else:
                new_imports_by_module[new_module].append({
                    'name': func_name,
                    'alias': alias
                })
                results['changes'].append(f"Moved import {func_name} to {new_module}")

            # Check if this function has dependencies that should also be imported
            if new_module in MODULE_DEPENDENCIES and func_name in MODULE_DEPENDENCIES[new_module]:
                for dep_func in MODULE_DEPENDENCIES[new_module][func_name]:
                    # Find which module this dependency is in
                    for f, m in IMPORT_MAPPINGS.items():
                        if f == dep_func:
                            dep_module = m
                            new_imports_by_module[dep_module].append({
                                'name': dep_func,
                                'alias': None
                            })
                            results['changes'].append(f"Added dependency {dep_func} from {dep_module}")
                            break

        # Construct new import statements
        new_import_lines = []
        for module, items in new_imports_by_module.items():
            items_text = []
            for item in items:
                if item['alias'] and item['alias'] != item['name']:
                    items_text.append(f"{item['name']} as {item['alias']}")
                else:
                    items_text.append(item['name'])

            # Format the import line
            items_joined = ', '.join(items_text)
            new_import_lines.append(f"from {module} import {items_joined}")

        # Create a pattern to find core.utils imports
        from_pattern = r'^from\s+core\.utils\s+import\s+(.+?)(?:\s+#.*)?$'

        # Create a modified version of content with updated imports
        new_content = content

        # Handle multi-line imports first
        multi_line_from_pattern = r'from\s+core\.utils\s+import\s*\(.*?\)'
        for match in re.finditer(multi_line_from_pattern, content, re.DOTALL):
            full_import_text = match.group(0)

            # Extract the imported names
            names_list = []
            for line in full_import_text.split('\n')[1:]:
                if ')' in line:
                    line = line.split(')', 1)[0]
                names_text = line.strip().rstrip(',')
                if names_text:
                    names_list.append(names_text)

            # Remove imported names that we're moving
            new_names_list = []
            for name_text in names_list:
                name_parts = name_text.split(' as ')
                name = name_parts[0].strip()
                if name not in IMPORT_MAPPINGS:
                    new_names_list.append(name_text)

            # Construct the new import statement if any names remain
            if new_names_list:
                new_import_text = "from core.utils import (\n    " + ",\n    ".join(new_names_list) + "\n)"
            else:
                new_import_text = ""

            # Replace the old import with the new one
            new_content = new_content.replace(full_import_text, new_import_text)

        # Handle single-line imports
        for match in re.finditer(from_pattern, new_content, re.MULTILINE):
            full_import_text = match.group(0)
            imports_text = match.group(1).strip()

            # Process the imported symbols
            imported_items = []
            remaining_items = []
            for item in re.split(r',\s*', imports_text):
                item = item.strip()
                if not item:
                    continue

                # Handle "as" aliases
                item_parts = item.split(' as ')
                name = item_parts[0].strip()

                if name not in IMPORT_MAPPINGS:
                    remaining_items.append(item)

            # Construct the new import statement if any items remain
            if remaining_items:
                new_import_text = f"from core.utils import {', '.join(remaining_items)}"
            else:
                new_import_text = ""

            # Replace the old import with the new one
            new_content = new_content.replace(full_import_text, new_import_text)

        # Add the new import statements after the last import or at the beginning
        # of the file if no imports exist
        last_import_match = re.search(r'^(?:import|from)\s+.+$', new_content, re.MULTILINE)
        if last_import_match:
            last_import_pos = last_import_match.end()

            # Find the position after any consecutive imports
            import_block_end = last_import_pos
            for match in re.finditer(r'^(?:import|from)\s+.+$', new_content[last_import_pos:], re.MULTILINE):
                import_block_end = last_import_pos + match.end()

            # Insert new imports after the last import
            new_imports_text = "\n" + "\n".join(new_import_lines)
            new_content = new_content[:import_block_end] + new_imports_text + new_content[import_block_end:]
        else:
            # Insert at the beginning, but after any module docstrings
            docstring_match = re.match(r'(?:""".*?"""|\'\'\'.*?\'\'\')\s*', new_content, re.DOTALL)
            if docstring_match:
                insert_pos = docstring_match.end()
            else:
                insert_pos = 0

            new_imports_text = "\n".join(new_import_lines) + "\n\n"
            new_content = new_content[:insert_pos] + new_imports_text + new_content[insert_pos:]

        # Write the modified content back to the file
        if not dry_run:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)

        results['updated'] = content != new_content

        if verbose:
            if results['updated']:
                print(f"Updated {filepath} with {len(results['changes'])} changes")
            else:
                print(f"No changes needed in {filepath}")

    except Exception as e:
        print(f"Error updating {filepath}: {e}")
        results['error'] = str(e)

    return results

def parse_args(args=None):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Update import statements for migrated core utils')
    parser.add_argument('--dry-run', action='store_true', help='Show changes without applying them')
    parser.add_argument('--path', default='.', help='Path to process (default: current directory)')
    parser.add_argument('--backup', action='store_true', help='Create .bak files before modifying')
    parser.add_argument('--verbose', action='store_true', help='Show detailed information')
    return parser.parse_args(args)

def main(args=None):
    """Main entry point for the script."""
    args = parse_args(args)

    print(f"Importing statement updater running on {args.path}")
    print(f"Dry run: {args.dry_run}, Backup: {args.backup}, Verbose: {args.verbose}")

    # Find all Python files
    python_files = find_python_files(args.path)
    print(f"Found {len(python_files)} Python files to scan")

    # Process files
    stats = {
        'total': len(python_files),
        'updated': 0,
        'skipped': 0,
        'errors': 0,
        'changes': 0
    }

    for file in python_files:
        results = update_file_imports(file, args.dry_run, args.backup, args.verbose)

        if results.get('error'):
            stats['errors'] += 1
        elif results['updated']:
            stats['updated'] += 1
            stats['changes'] += len(results['changes'])
        else:
            stats['skipped'] += 1

    # Print summary
    print("\nImport Update Summary:")
    print(f"  Files processed: {stats['total']}")
    print(f"  Files updated: {stats['updated']}")
    print(f"  Files skipped: {stats['skipped']}")
    print(f"  Errors: {stats['errors']}")
    print(f"  Total changes: {stats['changes']}")

    if args.dry_run:
        print("\nThis was a dry run - no files were modified.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
