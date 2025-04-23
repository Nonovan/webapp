"""
Services package for the myproject application.

This package contains service classes that implement business logic and coordinate
interactions between different parts of the application. Services encapsulate
complex operations and provide clean APIs for controllers/routes to use.

The services follow a functional core/imperative shell architecture where business
logic is separated from side effects (like database operations). This approach
enhances testability and maintainability by reducing complexity in individual components.

Key services in this package:
- AuthService: User authentication, registration, and session management
- EmailService: Email template rendering and delivery
- NewsletterService: Subscription management and newsletter distribution
"""

from .auth_service import AuthService
from .email_service import EmailService, send_email, send_template_email
from .newsletter_service import NewsletterService

# Export classes and functions to make them available when importing this package
__all__ = [
    # Service classes
    'AuthService',
    'EmailService',
    'NewsletterService',

    # Utility functions
    'send_email',
    'send_template_email',
]
