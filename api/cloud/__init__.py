"""
Cloud API module for infrastructure monitoring and management.

This module provides API endpoints for monitoring and managing cloud infrastructure
resources across multiple providers. It exposes metrics, alerts, historical data,
and resource management capabilities through a consistent RESTful interface.

Features:
- Real-time system metrics (CPU, memory, storage, network)
- Provider-specific resource monitoring (AWS, Azure, GCP)
- Historical metrics for trend analysis
- Alert management for resource thresholds
- User activity monitoring on cloud resources
- Security event detection and notification

All endpoints in this module implement consistent security practices including:
- JWT authentication for all routes
- Rate limiting to prevent abuse
- Response caching for performance optimization
- Audit logging for compliance and security monitoring
- Proper error handling with standardized responses
"""

from flask import Blueprint

# Create cloud metrics blueprint
cloud_bp = Blueprint('cloud', __name__)

# Import routes to register them with the blueprint
from . import metric, resources, alerts, operations

# Export the metrics blueprint for registration with the main API blueprint
__all__ = ['cloud_bp']
