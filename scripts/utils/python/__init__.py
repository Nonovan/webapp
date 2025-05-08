"""
Python utilities for the Cloud Infrastructure Platform.

This package contains various Python utilities used across the platform
for data generation and file manipulation.
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
JSON_YAML_CONVERTER_AVAILABLE = False

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

# Try importing JSON/YAML converter components
try:
    from .json_yaml_converter import (
        JSONYAMLConverter,
        parse_arguments,
        configure_logging,
        get_output_format,
        main as json_yaml_converter_main
    )
    JSON_YAML_CONVERTER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"JSON/YAML converter not available: {e}")

def get_available_utilities() -> Dict[str, bool]:
    """Return a dictionary of available utilities."""
    return {
        "sample_data_generator": SAMPLE_DATA_GEN_AVAILABLE,
        "json_yaml_converter": JSON_YAML_CONVERTER_AVAILABLE,
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

if JSON_YAML_CONVERTER_AVAILABLE:
    __all__.extend([
        # JSON/YAML converter components
        "JSONYAMLConverter",
        "parse_arguments",
        "configure_logging",
        "get_output_format",
        "json_yaml_converter_main"
    ])

# Log initialization status
active_utils = [name for name, available in get_available_utilities().items() if available]
if active_utils:
    logger.debug(f"Python utilities package initialized with: {', '.join(active_utils)}")
else:
    logger.debug("Python utilities package initialized with no active utility modules.")
