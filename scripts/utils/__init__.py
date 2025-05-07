"""
Utility scripts for the Cloud Infrastructure Platform.

This package contains various utility scripts and functions used across the platform
for development, deployment, and maintenance operations. It provides a centralized
location for common functionality used by different scripts.
"""

import logging
import os
import sys
from typing import Dict, List, Optional, Any, Union, Tuple

# Configure logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Package version
__version__ = "0.1.1"
__author__ = 'Cloud Infrastructure Platform Team'

# Feature availability flags
COMMON_UTILS_AVAILABLE = False
PYTHON_UTILS_AVAILABLE = False
DEV_TOOLS_AVAILABLE = False
MODULE_UTILS_AVAILABLE = False
TESTING_UTILS_AVAILABLE = False

# Try importing common utilities
try:
    from .common_functions import (
        load_env,
        log,
        error_exit,
        warn,
        debug,
        check_command_exists,
        execute_command,
        backup_file,
        check_file_exists,
        create_directory
    )
    COMMON_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Common utilities not available: {e}")

# Try importing Python utilities
try:
    from .python import (
        # Sample data generator
        generate_sample_data,
        save_data,

        # File utilities (if available)
        safe_read_file,
        safe_write_file,
        ensure_directory,
        get_file_checksum,
        find_files_by_pattern,

        # Configuration utilities
        load_config,
        save_config,
        merge_configs,
        validate_config,
        get_config_value,
        set_config_value,

        # Get package info
        get_available_utilities as get_python_utilities
    )
    PYTHON_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Python utilities not available: {e}")

# Try importing development tools
try:
    from .dev_tools import (
        # Format conversion
        convert_files,
        check_pandoc,
        find_files,
        secure_backup,
        convert_file,
        restore_from_backup,

        # CLI documentation
        generate_cli_docs,
        generate_cli_reference,

        # Template processing
        process_template,
        load_template,
        render_template,
        save_output,
        validate_template,
        load_variables,

        # Import utilities
        update_file_imports,
        analyze_file_imports,
        find_python_files,

        # Package info
        get_available_utilities as get_dev_tools_utilities
    )
    DEV_TOOLS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Development tools not available: {e}")

# Try importing module utilities
try:
    from .modules import (
        list_modules,
        get_module_info,
        load_module,
        register_module,
        check_module_compatibility,
        enable_module,
        disable_module,
        get_module_status,
        get_modules_by_status,
        get_module_requirements
    )
    MODULE_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Module utilities not available: {e}")

# Try importing testing utilities
try:
    from .testing import (
        create_test_environment,
        cleanup_test_environment,
        mock_service,
        mock_response,
        generate_test_data,
        validate_test_result,
        run_test_scenario,
        setup_test_fixtures,
        teardown_test_fixtures,
        get_test_config
    )
    TESTING_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Testing utilities not available: {e}")

def get_available_utilities() -> dict:
    """Return a dictionary of available utility modules."""
    return {
        "common_utils": COMMON_UTILS_AVAILABLE,
        "python_utils": PYTHON_UTILS_AVAILABLE,
        "dev_tools": DEV_TOOLS_AVAILABLE,
        "module_utils": MODULE_UTILS_AVAILABLE,
        "testing_utils": TESTING_UTILS_AVAILABLE
    }

# Define what is exported from this package
__all__ = [
    # Version information
    "__version__",
    "__author__",

    # Utility functions
    "get_available_utilities"
]

# Conditionally add exports based on which components are available
if COMMON_UTILS_AVAILABLE:
    __all__.extend([
        "load_env",
        "log",
        "error_exit",
        "warn",
        "debug",
        "check_command_exists",
        "execute_command",
        "backup_file",
        "check_file_exists",
        "create_directory"
    ])

if PYTHON_UTILS_AVAILABLE:
    __all__.extend([
        # Sample data generator
        "generate_sample_data",
        "save_data",

        # File utilities
        "safe_read_file",
        "safe_write_file",
        "ensure_directory",
        "get_file_checksum",
        "find_files_by_pattern",

        # Configuration utilities
        "load_config",
        "save_config",
        "merge_configs",
        "validate_config",
        "get_config_value",
        "set_config_value",

        # Package info
        "get_python_utilities"
    ])

if DEV_TOOLS_AVAILABLE:
    __all__.extend([
        # Format conversion
        "convert_files",
        "check_pandoc",
        "find_files",
        "secure_backup",
        "convert_file",
        "restore_from_backup",

        # CLI documentation
        "generate_cli_docs",
        "generate_cli_reference",

        # Template processing
        "process_template",
        "load_template",
        "render_template",
        "save_output",
        "validate_template",
        "load_variables",

        # Import utilities
        "update_file_imports",
        "analyze_file_imports",
        "find_python_files",

        # Package info
        "get_dev_tools_utilities"
    ])

if MODULE_UTILS_AVAILABLE:
    __all__.extend([
        "list_modules",
        "get_module_info",
        "load_module",
        "register_module",
        "check_module_compatibility",
        "enable_module",
        "disable_module",
        "get_module_status",
        "get_modules_by_status",
        "get_module_requirements"
    ])

if TESTING_UTILS_AVAILABLE:
    __all__.extend([
        "create_test_environment",
        "cleanup_test_environment",
        "mock_service",
        "mock_response",
        "generate_test_data",
        "validate_test_result",
        "run_test_scenario",
        "setup_test_fixtures",
        "teardown_test_fixtures",
        "get_test_config"
    ])

# Log initialization status
active_utils = [name for name, available in get_available_utilities().items() if available]
if active_utils:
    logger.debug(f"Utils package initialized with: {', '.join(active_utils)}")
else:
    logger.debug("Utils package initialized with no active utility modules.")
