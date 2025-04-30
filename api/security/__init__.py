"""
Security API Package.

This package contains the Flask Blueprint and API endpoint implementations
for security-related operations within the Cloud Infrastructure Platform.
It covers areas such as security incident management, vulnerability tracking,
security scanning, and threat intelligence.

Endpoints are consolidated under the '/api/security' prefix via the `security_bp` blueprint.
"""

import logging

# Import the main blueprint for the security API
from .routes import security_bp

# Import endpoint modules to ensure routes are registered with the blueprint
from . import incidents
from . import scanning
from . import threats
from . import vulnerabilities
# Add imports for any other endpoint files here

# Initialize logger for the package
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler()) # Avoid "No handler found" warnings

# Define what is available for import from this package
__all__ = [
    "security_bp"
]

logger.debug("Security API package initialized.")
