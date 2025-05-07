"""
Python utilities for development tools.

This package contains various Python utilities used by development tools
in the Cloud Infrastructure Platform. These include format conversion,
documentation generation, templating, and other developer workflow helpers.
"""

import logging
import sys
from typing import Dict, List, Optional, Any, Union, Tuple

# Configure logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Package version
__version__ = "0.1.1"
__author__ = 'Cloud Infrastructure Platform Team'

# Feature availability flags
CONVERT_FORMAT_AVAILABLE = False
CLI_DOCS_AVAILABLE = False
PROCESS_TEMPLATE_AVAILABLE = False

# Try importing convert_format components
try:
    from .python.convert_format import (
        convert_files,
        check_pandoc,
        find_files,
        secure_backup,
        convert_file,
        restore_from_backup
    )
    CONVERT_FORMAT_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Format conversion utilities not available: {e}")

# Try importing CLI documentation components
try:
    from .python.generate_cli_docs import (
        generate_cli_docs,
        generate_cli_reference,
        generate_markdown_doc,
        format_docstring,
        get_module_info,
        write_file
    )
    CLI_DOCS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"CLI documentation utilities not available: {e}")

# Try importing template processing components
try:
    from .python.process_template import (
        process_template,
        load_template,
        render_template,
        save_output,
        validate_template,
        load_variables,
        SUPPORTED_FORMATS
    )
    PROCESS_TEMPLATE_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Template processing utilities not available: {e}")

def get_available_utilities() -> Dict[str, bool]:
    """Get a dictionary of available utilities in this package."""
    return {
        "convert_format": CONVERT_FORMAT_AVAILABLE,
        "cli_docs": CLI_DOCS_AVAILABLE,
        "process_template": PROCESS_TEMPLATE_AVAILABLE
    }

# Define public exports
__all__ = [
    # Version information
    "__version__",
    "__author__",

    # Utility availability
    "get_available_utilities",

    # Convert format components (conditionally added)
    *([
        "convert_files",
        "check_pandoc",
        "find_files",
        "secure_backup",
        "convert_file",
        "restore_from_backup"
    ] if CONVERT_FORMAT_AVAILABLE else []),

    # CLI documentation components (conditionally added)
    *([
        "generate_cli_docs",
        "generate_cli_reference",
        "generate_markdown_doc",
        "format_docstring",
        "get_module_info",
        "write_file"
    ] if CLI_DOCS_AVAILABLE else []),

    # Template processing components (conditionally added)
    *([
        "process_template",
        "load_template",
        "render_template",
        "save_output",
        "validate_template",
        "load_variables",
        "SUPPORTED_FORMATS"
    ] if PROCESS_TEMPLATE_AVAILABLE else [])
]

# Log initialization status
active_utils = [name for name, available in get_available_utilities().items() if available]
if active_utils:
    logger.debug(f"Python dev tools package initialized with: {', '.join(active_utils)}")
else:
    logger.debug("Python dev tools package initialized with no active utilities.")
