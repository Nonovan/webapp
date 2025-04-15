"""
Authentication API module for the myproject application.

This module provides RESTful endpoints for user authentication, registration,
token management, and session handling. It serves as the entry point for 
programmatic authentication with the application.

Key endpoints:
- /api/auth/login: Authenticate and obtain JWT token
- /api/auth/register: Create new user accounts
- /api/auth/extend-session: Extend existing session duration
- /api/auth/verify: Verify token validity
- /api/auth/logout: Invalidate current token

All endpoints implement appropriate input validation, rate limiting,
and error handling to ensure secure authentication operations.
"""

# The actual routes are defined in routes.py

__all__ = []
