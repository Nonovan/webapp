# Import Utilities for Cloud Infrastructure Platform

This directory contains utility scripts for managing data imports and code imports across the Cloud Infrastructure Platform. These utilities implement standardized functions for data import validation, format conversion, safe loading of various structured data formats, as well as tools for updating import statements during code refactoring.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage Examples](#usage-examples)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The import utilities provide two main sets of functionality:

1. **Data Import Utilities**: Standardized functions for importing data from various file formats (CSV, JSON, YAML, XML) with consistent validation, error handling, and security controls.

2. **Import Statement Management**: Tools for updating import statements during code refactoring, particularly when migrating functions from monolithic modules to specialized modules.

Both sets of utilities are designed with security, flexibility, and validation as core principles, ensuring consistent behavior across all data and code imports.

## Key Components

- **`import_statement_updater.py`**: Updates import statements when functions move between modules
  - Supports multiple import formats and patterns
  - Handles single-line and multi-line imports
  - Preserves import aliases
  - Manages function renames and merges
  - Creates backups before modifications

- **`csv_utils.py`**: CSV import and processing
  - CSV validation against schemas
  - Type conversion and normalization
  - Character encoding detection and handling
  - Field mapping and transformation

- **`json_utils.py`**: JSON import and processing
  - Schema validation for JSON data
  - Path-based value extraction
  - Secure parsing with size limits

- **`yaml_utils.py`**: YAML import and processing
  - Safe YAML loading (preventing code execution)
  - Schema validation for YAML data
  - Multi-document parsing

- **`xml_utils.py`**: XML import and processing
  - Secure parsing with entity handling
  - XML to dictionary conversion
  - XPath query support

- **`format_detection.py`**: Format auto-detection
  - Content-based format detection
  - Extension-based format detection
  - Encoding detection

- **`validation.py`**: Import validation
  - Schema-based validation
  - Type checking and coercion
  - Error reporting

- **`migration_transition_module.py`**: Backward compatibility module
  - Re-exports functions from their new locations
  - Provides deprecation warnings
  - Ensures smooth migration path

## Directory Structure

```plaintext
scripts/utils/dev_tools/import_utils/
├── README.md                      # This documentation
├── __init__.py                    # Package initialization and exports
├── import_statement_updater.py    # Import statement updating tool
├── migration_transition_module.py # Backward compatibility layer
├── csv_utils.py                   # CSV file import and processing
├── json_utils.py                  # JSON file import and processing
├── yaml_utils.py                  # YAML file import and processing
├── xml_utils.py                   # XML file import and processing
├── format_detection.py            # Format auto-detection utilities
└── validation.py                  # Data validation utilities
```

## Usage Examples

### Import Statement Updating

```python
from scripts.utils.dev_tools.import_utils import update_file_imports

# Update imports in a file
result = update_file_imports(
    filepath="path/to/file.py",
    dry_run=True,  # Preview changes without applying them
    backup=True    # Create backup before modifying
)

# Check what changed
if result["updated"]:
    print(f"Updated import statements with {len(result['changes'])} changes")
    for change in result["changes"]:
        print(f"- {change}")
```

### Multi-Format Data Import

```python
from scripts.utils.dev_tools.import_utils import import_data

# Import data with automatic format detection
data, stats = import_data(
    file_path="data_file.csv",
    required_fields=["id", "name", "value"]
)

# Process results
print(f"Imported {stats['valid']} valid records out of {stats['total']}")
if stats['invalid'] > 0:
    print(f"Found {stats['invalid']} invalid records")
    for error in stats['errors']:
        print(f"- {error}")
```

### Format-Specific Imports

```python
from scripts.utils.dev_tools.import_utils import (
    load_json_file, load_yaml_file, import_csv_data, xml_to_dict, parse_xml
)

# JSON import with schema validation
json_data = load_json_file(
    file_path="config.json",
    schema_path="schemas/config_schema.json"
)

# YAML import with environment variable substitution
yaml_data = load_yaml_file(
    file_path="config.yaml",
    allow_env_vars=True
)

# CSV import with field validation
csv_data, stats = import_csv_data(
    file_path="users.csv",
    required_fields=["username", "email"],
    delimiter=","
)

# XML import and conversion to dictionary
xml_doc = parse_xml("data.xml")
xml_data = xml_to_dict(xml_doc)
```

### Using the Transition Module

```python
# Old code that needs to be gradually migrated
from scripts.utils.dev_tools.import_utils.migration_transition_module import (
    compute_file_hash, sanitize_path, detect_file_changes
)

# Functions are available from their new locations but with deprecation warnings
hash_value = compute_file_hash("path/to/file")
```

## Best Practices & Security

- Always validate input files against schemas to ensure data integrity
- Use the secure loading functions that prevent code execution exploits
- Apply size limits to prevent denial of service attacks
- Set appropriate character encoding to handle international data
- Validate field contents before processing
- Use type conversion to ensure data consistency
- Handle errors gracefully with detailed error reporting
- Check file paths against path traversal vulnerabilities
- Log import operations for audit purposes
- Use dry-run mode for imports when first testing
- Create backups before applying import statement changes
- Review changes carefully after automatic code modifications

## Common Features

All import utility modules share these common features:

- **Data Validation**: Schema-based validation of imported data
- **Error Handling**: Comprehensive error collection and reporting
- **Format Detection**: Automatic detection of file formats
- **Import Statistics**: Detailed statistics about import operations
- **Path Safety**: Validation against path traversal attacks
- **Performance Optimization**: Efficient parsing and processing
- **Secure Parsing**: Protection against security vulnerabilities
- **Configurability**: Flexible configuration options for different use cases
- **Type Conversion**: Automatic type conversion based on schemas
- **Encoding Handling**: Proper character encoding detection and handling
- **Deterministic Processing**: Consistent behavior with various data formats
- **Resource Management**: Proper cleanup of resources after processing

## Related Documentation

- Data Import Guidelines
- Schema Validation Reference
- CSV Format Specification
- JSON Schema Standards
- YAML Configuration Guide
- XML Processing Guidelines
- Data Transformation Guide
- Type Conversion Reference
- Error Handling Standards
- Core Utilities Documentation
- Migration Best Practices
