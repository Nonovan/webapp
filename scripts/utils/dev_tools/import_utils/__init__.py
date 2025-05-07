"""
Import Utilities for Development Tools

This package provides utilities for managing imports across the codebase,
particularly for refactoring and migration of modules.
"""

import os
import sys
import logging
from typing import Dict, List, Tuple, Set, Optional, Any, Union

# Configure logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Package version
__version__ = "0.1.0"
__author__ = 'Cloud Infrastructure Platform Team'
__email__ = 'platform-team@example.com'

# Try importing import_statement_updater components
try:
    from .import_statement_updater import (
        update_file_imports,
        analyze_file_imports,
        find_python_files,
        parse_args,
        main as update_imports_main,
        IMPORT_MAPPINGS,
        FUNCTION_MERGES,
        MODULE_DEPENDENCIES
    )
    IMPORT_UPDATER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Import statement updater not available: {e}")
    IMPORT_UPDATER_AVAILABLE = False

# Try importing csv_utils components if available
try:
    from .csv_utils import (
        import_csv_data,
        validate_csv,
        convert_csv_to_json,
        convert_csv_to_dict,
        detect_csv_dialect,
        export_to_csv
    )
    CSV_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"CSV utilities not available: {e}")
    CSV_UTILS_AVAILABLE = False

# Try importing json_utils components if available
try:
    from .json_utils import (
        load_json_file,
        validate_json,
        get_json_value,
        save_json_file,
        merge_json_files
    )
    JSON_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"JSON utilities not available: {e}")
    JSON_UTILS_AVAILABLE = False

# Try importing yaml_utils components if available
try:
    from .yaml_utils import (
        load_yaml_file,
        save_yaml_file,
        yaml_to_dict,
        dict_to_yaml
    )
    YAML_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"YAML utilities not available: {e}")
    YAML_UTILS_AVAILABLE = False

# Try importing xml_utils components if available
try:
    from .xml_utils import (
        parse_xml,
        xml_to_dict,
        dict_to_xml,
        query_xml
    )
    XML_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"XML utilities not available: {e}")
    XML_UTILS_AVAILABLE = False

# Try importing format_detection components if available
try:
    from .format_detection import (
        detect_format,
        detect_encoding,
        validate_format
    )
    FORMAT_DETECTION_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Format detection utilities not available: {e}")
    FORMAT_DETECTION_AVAILABLE = False

# Try importing validation components if available
try:
    from .validation import (
        validate_import_data,
        validate_schema,
        normalize_data
    )
    VALIDATION_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Validation utilities not available: {e}")
    VALIDATION_AVAILABLE = False

# Import transition module for backward compatibility
try:
    from . import transition_module_for_migration
    TRANSITION_MODULE_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Transition module not available: {e}")
    TRANSITION_MODULE_AVAILABLE = False

# Combined function for all import types
def import_data(
    file_path: str,
    file_format: Optional[str] = None,
    required_fields: List[str] = None,
    schema_path: Optional[str] = None,
    **kwargs
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Import data from a file with automatic format detection if not specified.

    Args:
        file_path: Path to the data file to import
        file_format: Format of the file (json, csv, yaml, xml). Auto-detected if None.
        required_fields: List of fields that must be present in the data
        schema_path: Path to schema file for validation
        **kwargs: Additional format-specific options

    Returns:
        Tuple of (data, stats) where data is a list of dictionaries and
        stats contains processing information
    """
    stats = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "errors": [],
        "format": file_format
    }

    # Auto-detect format if not specified
    if file_format is None:
        if FORMAT_DETECTION_AVAILABLE:
            file_format = detect_format(file_path)
            stats["format"] = file_format
        else:
            # Basic extension-based detection
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.json':
                file_format = 'json'
            elif ext == '.csv':
                file_format = 'csv'
            elif ext in ('.yaml', '.yml'):
                file_format = 'yaml'
            elif ext in ('.xml', '.xhtml'):
                file_format = 'xml'
            else:
                stats["errors"].append(f"Could not determine file format for {file_path}")
                return [], stats

    # Process based on format
    try:
        if file_format == 'csv' and CSV_UTILS_AVAILABLE:
            return import_csv_data(file_path, required_fields, **kwargs)
        elif file_format == 'json' and JSON_UTILS_AVAILABLE:
            data = load_json_file(file_path, **kwargs)
            # Handle both list and dict formats
            if isinstance(data, dict):
                if "data" in data:  # Common wrapper format
                    data = data["data"]
                else:
                    data = [data]  # Convert single record to list

            # Validate if schema provided
            if schema_path and VALIDATION_AVAILABLE:
                for i, item in enumerate(data):
                    is_valid, errors = validate_schema(item, schema_path)
                    if is_valid:
                        stats["valid"] += 1
                    else:
                        stats["invalid"] += 1
                        for error in errors:
                            stats["errors"].append(f"Record {i}: {error}")
            else:
                # Basic required field validation
                stats["total"] = len(data)

                for i, item in enumerate(data):
                    if required_fields:
                        missing = [field for field in required_fields if field not in item]
                        if missing:
                            stats["invalid"] += 1
                            stats["errors"].append(f"Record {i}: Missing required fields: {missing}")
                        else:
                            stats["valid"] += 1
                    else:
                        stats["valid"] += 1

            return data, stats

        elif file_format == 'yaml' and YAML_UTILS_AVAILABLE:
            data = load_yaml_file(file_path, **kwargs)
            # Similar validation as with JSON
            stats["total"] = len(data) if isinstance(data, list) else 1
            stats["valid"] = stats["total"]  # Without schema validation
            return data if isinstance(data, list) else [data], stats

        elif file_format == 'xml' and XML_UTILS_AVAILABLE:
            data = xml_to_dict(parse_xml(file_path))
            stats["total"] = 1  # XML typically represents one structured document
            stats["valid"] = 1
            return [data], stats

        else:
            stats["errors"].append(f"Unsupported or unavailable file format: {file_format}")
            return [], stats

    except Exception as e:
        stats["errors"].append(f"Error importing {file_path}: {str(e)}")
        return [], stats


def get_available_utilities() -> dict:
    """Return a dictionary of available utilities in this package.

    Returns:
        Dictionary with utility name as key and availability as boolean value
    """
    return {
        "import_updater": IMPORT_UPDATER_AVAILABLE
    }


# Define public exports - symbols that can be imported from this package
__all__ = [
    # Version information
    "__version__",
    "__author__",
    "__email__",

    # Feature availability flags
    "IMPORT_UPDATER_AVAILABLE",

    # Package utilities
    "get_available_utilities",
    "import_data",

    # Import statement updater components
    "update_file_imports",
    "analyze_file_imports",
    "find_python_files",
    "parse_args",
    "update_imports_main",
    "IMPORT_MAPPINGS",
    "FUNCTION_MERGES",
    "MODULE_DEPENDENCIES"
]

# Conditionally add exports based on available components
if CSV_UTILS_AVAILABLE:
    __all__.extend([
        # CSV utilities
        "import_csv_data",
        "validate_csv",
        "convert_csv_to_json",
        "convert_csv_to_dict",
        "detect_csv_dialect",
        "export_to_csv"
    ])

if JSON_UTILS_AVAILABLE:
    __all__.extend([
        # JSON utilities
        "load_json_file",
        "validate_json",
        "get_json_value",
        "save_json_file",
        "merge_json_files"
    ])

if YAML_UTILS_AVAILABLE:
    __all__.extend([
        # YAML utilities
        "load_yaml_file",
        "save_yaml_file",
        "yaml_to_dict",
        "dict_to_yaml"
    ])

if XML_UTILS_AVAILABLE:
    __all__.extend([
        # XML utilities
        "parse_xml",
        "xml_to_dict",
        "dict_to_xml",
        "query_xml"
    ])

if FORMAT_DETECTION_AVAILABLE:
    __all__.extend([
        # Format detection utilities
        "detect_format",
        "detect_encoding",
        "validate_format"
    ])

if VALIDATION_AVAILABLE:
    __all__.extend([
        # Validation utilities
        "validate_import_data",
        "validate_schema",
        "normalize_data"
    ])

if TRANSITION_MODULE_AVAILABLE:
    # Import transitional components for backward compatibility
    # but don't expose them directly - they're accessed through
    # transition_module_for_migration
    __all__.extend([
        "transition_module_for_migration"
    ])

# Log initialization status
active_utils = [name for name, available in get_available_utilities().items() if available]
if active_utils:
    logger.debug(f"Import utils package initialized with: {', '.join(active_utils)}")
else:
    logger.debug("Import utils package initialized with no active utility modules.")
