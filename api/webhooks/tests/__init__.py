"""
Webhook system test suite.

This package contains comprehensive tests for the webhook system including
subscription management, delivery processing, security controls, and API endpoints.

Test modules:
- test_subscription.py: Tests for webhook subscription creation and management
- test_delivery.py: Tests for webhook delivery functionality
- test_routes.py: Tests for webhook REST API endpoints
- test_security.py: Tests for webhook security features
- test_testing.py: Tests for the webhook testing utilities themselves

The test suite validates all aspects of the webhook system:
- Proper subscription management with validation
- Secure secret generation and signature validation
- Correct delivery tracking and retry mechanisms
- REST API authentication, permissions and rate limiting
- Mock server functionality for isolated testing
"""

from unittest.mock import patch, MagicMock
import json
import uuid
import pytest

from api.webhooks import EventType, DeliveryStatus
from api.webhooks.testing import MockWebhookServer
from api.webhooks.subscription import create_subscription
from models.webhook import WebhookSubscription, WebhookDelivery

# Constants for use in tests
TEST_WEBHOOK_URL = "https://example.com/webhook"
TEST_WEBHOOK_SECRET = "test-webhook-secret"
TEST_EVENT_TYPES = [EventType.RESOURCE_CREATED, EventType.ALERT_TRIGGERED]

# Make common testing utilities available at the package level
__all__ = [
    'MockWebhookServer',
    'EventType',
    'DeliveryStatus',
    'TEST_WEBHOOK_URL',
    'TEST_WEBHOOK_SECRET',
    'TEST_EVENT_TYPES'
]
