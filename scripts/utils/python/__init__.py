"""
Python utilities for the Cloud Infrastructure Platform.

This package contains various Python utilities used across the platform
for data generation, file manipulation, configuration management, and more.
"""

import logging
import sys
from typing import Dict, List, Optional, Any, Union, Tuple

# Configure logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Package version
__version__ = "0.1.0"
__author__ = 'Cloud Infrastructure Platform Team'

# Feature availability flags
SAMPLE_DATA_GEN_AVAILABLE = False
FILE_UTILS_AVAILABLE = False
CONFIG_UTILS_AVAILABLE = False

# Try importing sample data generator components
try:
    from .generate_sample_data import (
        generate_sample_data,
        save_data,
        parse_args,
        main as generate_sample_data_main,
        DEFAULT_NUM_RECORDS,
        DEFAULT_OUTPUT_FILE,
        VALID_FORMATS,
        DEFAULT_FORMAT,
        FIRST_NAMES,
        LAST_NAMES,
        DOMAINS,
        DEPARTMENTS,
        STATUSES
    )
    SAMPLE_DATA_GEN_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Sample data generator not available: {e}")

# Try importing file utilities if available
try:
    from admin.security.forensics.utils.file_utils import (
        safe_read_file,
        safe_write_file,
        ensure_directory,
        get_file_checksum,
        find_files_by_pattern
    )
    FILE_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"File utilities not available: {e}")

# Try importing configuration utilities if available
try:
    # Try to import from system_configuration module in admin.cli
    # Import the correct functions based on what's actually available in the system_configuration module
    from admin.cli.system_configuration import (
        get_config_value,
        set_config_value,
        export_configs as save_config,
        import_configs as load_config,
        validate_configs as validate_config,
        merge_configs
    )
except ImportError as e:
    logger.debug(f"Configuration utilities not available: {e}")

    # Try alternate import paths if admin.cli.system_configuration fails
    try:
        # Try importing from cli.app.config which might have similar functionality
        from cli.app.config import (
            load_config,
            save_config,
            get_config_value,
            set_config_value
        )

        # Define our own validate_config function
        def validate_config(config_data: Dict[str, Any], required_keys: List[str]) -> Tuple[bool, List[str]]:
            """
            Validate configuration data against required keys.

            Args:
                config_data: Configuration data dictionary
                required_keys: List of required keys

            Returns:
                Tuple of (is_valid, missing_keys)
            """
            missing_keys = [key for key in required_keys if key not in config_data]
            return len(missing_keys) == 0, missing_keys

        # Define a merge_configs function
        def merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
            """
            Merge two configuration dictionaries, with override_config values taking precedence.

            Args:
                base_config: Base configuration dictionary
                override_config: Override configuration dictionary

            Returns:
                Merged configuration dictionary
            """
            result = base_config.copy()
            for key, value in override_config.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    # If both values are dictionaries, merge them recursively
                    result[key] = merge_configs(result[key], value)
                else:
                    # Otherwise, override the value
                    result[key] = value
            return result

        CONFIG_UTILS_AVAILABLE = True
    except ImportError as e:
        logger.debug(f"Alternate configuration utilities not available: {e}")

def get_available_utilities() -> Dict[str, bool]:
    """Return a dictionary of available utilities."""
    return {
        "sample_data_generator": SAMPLE_DATA_GEN_AVAILABLE,
        "file_utilities": FILE_UTILS_AVAILABLE,
        "config_utilities": CONFIG_UTILS_AVAILABLE
    }

# Define public exports - symbols that can be imported from this package
__all__ = [
    # Version information
    "__version__",
    "__author__",

    # Utility functions
    "get_available_utilities"
]

# Conditionally add exports based on available components
if SAMPLE_DATA_GEN_AVAILABLE:
    __all__.extend([
        # Sample data generator components
        "generate_sample_data",
        "save_data",
        "parse_args",
        "generate_sample_data_main",

        # Sample data generator constants
        "DEFAULT_NUM_RECORDS",
        "DEFAULT_OUTPUT_FILE",
        "VALID_FORMATS",
        "DEFAULT_FORMAT",
        "FIRST_NAMES",
        "LAST_NAMES",
        "DOMAINS",
        "DEPARTMENTS",
        "STATUSES"
    ])

if FILE_UTILS_AVAILABLE:
    __all__.extend([
        # File utility functions
        "safe_read_file",
        "safe_write_file",
        "ensure_directory",
        "get_file_checksum",
        "find_files_by_pattern"
    ])

if CONFIG_UTILS_AVAILABLE:
    __all__.extend([
        # Configuration utility functions
        "load_config",
        "save_config",
        "merge_configs",
        "validate_config",
        "get_config_value",
        "set_config_value"
    ])

# Log initialization status
active_utils = [name for name, available in get_available_utilities().items() if available]
if active_utils:
    logger.debug(f"Python utilities package initialized with: {', '.join(active_utils)}")
else:
    logger.debug("Python utilities package initialized with no active utility modules.")
