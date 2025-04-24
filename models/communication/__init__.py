"""
Communication models package for the Cloud Infrastructure Platform.

This package contains models related to various communication systems including:
- Newsletter subscribers and mailing list management
- User notifications for system alerts and events
- Webhooks for integration with external services

These models enable communication capabilities throughout the application while
maintaining proper separation of concerns and providing robust validation and
error handling.
"""

from .newsletter import Subscriber, MailingList, SubscriberList
from .notification import Notification
from .webhook import WebhookSubscription, WebhookDelivery
from .subscriber import Subscriber as SubscriberModel, SubscriberCategory

# Define exports explicitly for better control over the public API
__all__ = [
    # Newsletter models
    "Subscriber",
    "MailingList",
    "SubscriberList",

    # Notification model
    "Notification",

    # Webhook models
    "WebhookSubscription",
    "WebhookDelivery",

    # Subscriber models (from subscriber.py)
    "SubscriberCategory"
]
