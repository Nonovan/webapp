"""
Transitional module for backward compatibility during migration.

DEPRECATED: Use specialized modules in core/utils/ and core/security/ instead.
This module will be removed in future versions.
"""

import warnings

# Re-export functions from their new locations
from core.security.cs_file_integrity import (
    detect_file_changes, check_critical_file, check_critical_files
)
from core.security.cs_utils import (
    sanitize_path, is_within_directory, is_safe_file_operation, obfuscate_sensitive_data
)
# ...and so on

# Warn about deprecated usage
warnings.warn(
    "Importing from core.utils is deprecated. Use specialized modules instead.",
    DeprecationWarning,
    stacklevel=2
)
