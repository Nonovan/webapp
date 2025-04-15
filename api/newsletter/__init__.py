"""
Newsletter API module for the myproject application.

This module provides RESTful endpoints for managing newsletter subscriptions
and operations. It enables programmatic access to newsletter functionality
including subscription management, confirmation, and unsubscription.

Key endpoints:
- /api/newsletter/subscribe: Subscribe email to newsletter
- /api/newsletter/confirm: Confirm subscription with token
- /api/newsletter/unsubscribe: Remove email from subscription list
- /api/newsletter/stats: Get newsletter statistics

All endpoints implement appropriate input validation, rate limiting, and
security measures to protect subscriber data and prevent abuse.
"""

# The actual routes are defined in routes.py

__all__ = []