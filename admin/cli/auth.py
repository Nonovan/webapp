"""
Authentication handling for the administrative CLI.

This module provides functions to handle user authentication,
token management, and related functionality.
"""

import logging
from typing import Dict, Any

from admin.utils.admin_auth import get_admin_session
from core.security.cs_audit import log_security_event
from core.security.cs_authentication import authenticate_user
from core.security.cs_authorization import verify_permission

logger = logging.getLogger(__name__)

def authenticate(username: str, password: str) -> Dict[str, Any]:
    """
    Authenticate user and generate session token.

    Args:
        username: User's username
        password: User's password

    Returns:
        Authentication response with token or error
    """
    try:
        auth_result = authenticate_user(username, password)

        if not auth_result:
            logger.warning("Authentication failed for user: %s", username)
            return {"success": False, "error": "Invalid credentials"}

        # Check if user has any admin permissions
        user_id = auth_result.get("user_id")
        admin_permissions = verify_permission(user_id, "admin:*")

        if not admin_permissions:
            logger.warning("User %s authenticated but has no admin permissions", username)
            return {
                "success": False,
                "error": "User does not have administrative permissions"
            }

        # Generate session token
        token = auth_result.get("token")

        # Log successful authentication
        logger.info("Admin authentication successful for user: %s", username)
        log_security_event(
            "admin_authentication",
            "successful",
            details={"username": username, "admin_access": True}
        )

        return {
            "success": True,
            "token": token,
            "user": {
                "username": username,
                "user_id": user_id,
                "permissions": admin_permissions,
                "requires_mfa": auth_result.get("requires_mfa", False)
            }
        }

    except Exception as e:
        logger.exception("Authentication error")
        return {"success": False, "error": str(e)}
