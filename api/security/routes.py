"""
Main routing file for the Security API module.

This file defines the primary Flask Blueprint for the security API (`security_bp`)
and aggregates routes defined in other modules within the `api/security` package,
such as incident management, vulnerability tracking, scanning operations, and
threat intelligence.

The blueprint consolidates all security-related API endpoints under the `/api/security` prefix.
"""

import logging
from flask import Blueprint

# Initialize module logger
logger = logging.getLogger(__name__)

# Create the main blueprint for the security API
# All routes registered in other files (incidents.py, vulnerabilities.py, etc.)
# should ideally use this blueprint instance.
security_bp = Blueprint('security_api', __name__, url_prefix='/security')

# Import routes from other modules within the security API package.
# These modules should define their routes using the 'security_bp' imported from here
# (or potentially a shared __init__.py).
# For now, we assume routes are defined within their respective files and need registration,
# OR that those files define their own blueprints to be registered later.
# If using a single blueprint approach (preferred):
# Ensure files like vulnerabilities.py import this 'security_bp' instead of creating their own.

# Example of importing routes if they were defined directly here or in submodules
# using this blueprint:
# from . import incidents  # Assuming incidents.py defines routes using security_bp
# from . import vulnerabilities # Assuming vulnerabilities.py uses security_bp
# from . import scanning # Assuming scanning.py uses security_bp
# from . import threats # Assuming threats.py uses security_bp

# If submodules define their own blueprints, they would be registered on the app
# in the main factory, not typically aggregated here. The current structure in
# vulnerabilities.py and threats.py suggests they might be defining their own,
# which might need refactoring for consistency if a single /api/security prefix is desired.

# Placeholder route example (if routes were defined directly in this file)
@security_bp.route('/status', methods=['GET'])
def get_security_status():
    """
    Placeholder endpoint for overall security status.
    Requires 'security:status:read' permission (decorator not added here).
    """
    # from core.security import require_permission
    # @require_permission('security:status:read') # Add decorator if implementing
    logger.info("Security status endpoint accessed (placeholder).")
    # In a real implementation, this would gather status from various security components.
    return {"status": "healthy", "message": "Security systems operational (placeholder)"}

# Note: This blueprint ('security_bp') needs to be registered with the main Flask app
# in the application factory (e.g., in core/factory.py or app.py).
