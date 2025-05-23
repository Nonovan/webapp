"""
Webhook API routes for Cloud Infrastructure Platform.

This module defines the REST API endpoints for webhook subscription
management and delivery status tracking.
"""

from flask import Blueprint, request, jsonify, current_app, g
from werkzeug.exceptions import BadRequest, NotFound
import json
from typing import Dict, Any
from datetime import datetime


from . import EVENT_TYPES, EVENT_CATEGORIES
from .delivery import deliver_webhook
from .subscription import create_subscription
from .services import get_circuit_breaker_stats, reset_circuit_breaker, configure_circuit_breaker
from extensions import db, limiter
from blueprints.auth.decorators import login_required, require_role
from models.communication.webhook import WebhookSubscription, WebhookDelivery

# Create webhook blueprint
webhooks_api = Blueprint('webhooks', __name__, url_prefix='/webhooks')

@webhooks_api.route('/', methods=['POST'])
@limiter.limit("30/minute")
@login_required
def create_webhook_subscription():
    """
    Create a new webhook subscription.

    Request body:
    {
        "target_url": "https://example.com/webhook",
        "event_types": ["resource.created", "alert.triggered"],
        "description": "My webhook subscription",
        "headers": {"X-Custom-Header": "value"}
    }

    Returns:
        New webhook subscription details with secret
    """
    try:
        data = request.get_json()
        if not data:
            raise BadRequest("Missing request body")

        required_fields = ['target_url', 'event_types']
        for field in required_fields:
            if field not in data:
                raise BadRequest(f"Missing required field: {field}")

        # Create subscription
        result = create_subscription(
            target_url=data['target_url'],
            event_types=data['event_types'],
            description=data.get('description'),
            headers=data.get('headers'),
            user_id=g.user.id,
            failure_threshold=data.get('failure_threshold'),
            reset_timeout=data.get('reset_timeout')
        )

        return jsonify(result), 201

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error creating webhook subscription: {e}")
        return jsonify({"error": "Failed to create webhook subscription"}), 500

@webhooks_api.route('/', methods=['GET'])
@limiter.limit("60/minute")
@login_required
def list_webhook_subscriptions():
    """
    List webhook subscriptions for the current user.

    Query parameters:
    - page: Page number (default: 1)
    - per_page: Items per page (default: 20)

    Returns:
        List of webhook subscriptions
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))

        query = WebhookSubscription.query.filter_by(user_id=g.user.id)

        pagination = query.paginate(page=page, per_page=per_page)

        result = {
            "items": [subscription.to_dict(exclude_secret=True) for subscription in pagination.items],
            "total": pagination.total,
            "page": page,
            "per_page": per_page,
            "pages": pagination.pages
        }

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Error listing webhook subscriptions: {e}")
        return jsonify({"error": "Failed to list webhook subscriptions"}), 500

@webhooks_api.route('/<subscription_id>', methods=['GET'])
@limiter.limit("60/minute")
@login_required
def get_webhook_subscription(subscription_id):
    """
    Get details for a specific webhook subscription.

    Args:
        subscription_id: ID of the subscription to retrieve

    Returns:
        Webhook subscription details
    """
    try:
        subscription = WebhookSubscription.query.filter_by(
            id=subscription_id,
            user_id=g.user.id
        ).first()

        if not subscription:
            return jsonify({"error": "Webhook subscription not found"}), 404

        return jsonify(subscription.to_dict(exclude_secret=True))

    except Exception as e:
        current_app.logger.error(f"Error retrieving webhook subscription: {e}")
        return jsonify({"error": "Failed to retrieve webhook subscription"}), 500

@webhooks_api.route('/<subscription_id>', methods=['DELETE'])
@limiter.limit("30/minute")
@login_required
def delete_webhook_subscription(subscription_id):
    """
    Delete a webhook subscription.

    Args:
        subscription_id: ID of the subscription to delete

    Returns:
        Success confirmation
    """
    try:
        subscription = WebhookSubscription.query.filter_by(
            id=subscription_id,
            user_id=g.user.id
        ).first()

        if not subscription:
            return jsonify({"error": "Webhook subscription not found"}), 404

        db.session.delete(subscription)
        db.session.commit()

        return jsonify({"success": True, "message": "Webhook subscription deleted"}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting webhook subscription: {e}")
        return jsonify({"error": "Failed to delete webhook subscription"}), 500

@webhooks_api.route('/<subscription_id>/deliveries', methods=['GET'])
@limiter.limit("60/minute")
@login_required
def list_webhook_deliveries(subscription_id):
    """
    List delivery history for a webhook subscription.

    Args:
        subscription_id: ID of the subscription

    Query parameters:
    - page: Page number (default: 1)
    - per_page: Items per page (default: 20)
    - status: Filter by status (optional)

    Returns:
        List of webhook deliveries
    """
    try:
        # Verify subscription ownership
        subscription = WebhookSubscription.query.filter_by(
            id=subscription_id,
            user_id=g.user.id
        ).first()

        if not subscription:
            return jsonify({"error": "Webhook subscription not found"}), 404

        # Parse query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        status = request.args.get('status')

        # Build query
        query = WebhookDelivery.query.filter_by(subscription_id=subscription_id)

        if status:
            query = query.filter_by(status=status)

        # Order by newest first
        query = query.order_by(WebhookDelivery.created_at.desc())

        # Paginate results
        pagination = query.paginate(page=page, per_page=per_page)

        result = {
            "items": [delivery.to_dict() for delivery in pagination.items],
            "total": pagination.total,
            "page": page,
            "per_page": per_page,
            "pages": pagination.pages
        }

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Error listing webhook deliveries: {e}")
        return jsonify({"error": "Failed to list webhook deliveries"}), 500

@webhooks_api.route('/test', methods=['POST'])
@limiter.limit("10/minute")
@login_required
def test_webhook():
    """
    Test a webhook by sending a test event.

    Request body:
    {
        "subscription_id": "uuid-here",
        "payload": {"key": "value"} // Optional custom payload
    }

    Returns:
        Delivery result details
    """
    try:
        data = request.get_json()
        if not data or 'subscription_id' not in data:
            return jsonify({"error": "Missing subscription_id"}), 400

        subscription_id = data['subscription_id']

        # Verify subscription ownership
        subscription = WebhookSubscription.query.filter_by(
            id=subscription_id,
            user_id=g.user.id
        ).first()

        if not subscription:
            return jsonify({"error": "Webhook subscription not found"}), 404

        # Create test payload
        payload = data.get('payload', {
            "message": "This is a test webhook event",
            "timestamp": datetime.utcnow().isoformat()
        })

        # Deliver test webhook
        results = deliver_webhook(
            event_type="test.event",
            payload=payload,
            subscription_id=subscription_id
        )

        if not results:
            return jsonify({"error": "Failed to initiate webhook delivery"}), 500

        return jsonify({"success": True, "delivery": results[0]})

    except Exception as e:
        current_app.logger.error(f"Error testing webhook: {e}")
        return jsonify({"error": "Failed to test webhook"}), 500

@webhooks_api.route('/events', methods=['GET'])
@limiter.limit("30/minute")
@login_required
def list_webhook_events():
    """
    List available webhook event types and categories.

    Returns:
        Event types and categories information
    """
    result = {
        "event_types": EVENT_TYPES,
        "categories": EVENT_CATEGORIES
    }

    return jsonify(result)

@webhooks_api.route('/<subscription_id>/circuit', methods=['GET'])
@limiter.limit("30/minute")
@login_required
def get_circuit_status(subscription_id):
    """
    Get circuit breaker status for a webhook subscription.

    This endpoint provides detailed information about the circuit breaker state
    for a specific webhook subscription, including failure counts, trip status,
    and timing information for automatic recovery.

    Args:
        subscription_id: ID of the subscription

    Returns:
        Circuit breaker status details
    """
    try:
        # Verify subscription ownership
        subscription = WebhookSubscription.query.filter_by(
            id=subscription_id,
            user_id=g.user.id
        ).first()

        if not subscription:
            return jsonify({"error": "Webhook subscription not found"}), 404

        # Get circuit breaker stats
        stats = get_circuit_breaker_stats(subscription_id)

        if 'error' in stats:
            return jsonify({"error": stats['error']}), 400

        return jsonify(stats), 200

    except Exception as e:
        current_app.logger.error(f"Error getting circuit breaker status: {e}")
        return jsonify({"error": "Failed to get circuit breaker status"}), 500

@webhooks_api.route('/<subscription_id>/circuit', methods=['POST'])
@limiter.limit("10/minute")
@login_required
def manage_circuit_breaker(subscription_id):
    """
    Manage circuit breaker for a webhook subscription.

    This endpoint allows actions on a webhook's circuit breaker:
    - reset: Reset circuit breaker to closed state
    - configure: Configure circuit breaker parameters

    Request body:
    {
        "action": "reset"|"configure",
        "failure_threshold": 5,  // Optional, for "configure" action
        "reset_timeout": 300     // Optional, for "configure" action
    }

    Args:
        subscription_id: ID of the subscription

    Returns:
        Success confirmation or error details
    """
    try:
        # Verify subscription ownership
        subscription = WebhookSubscription.query.filter_by(
            id=subscription_id,
            user_id=g.user.id
        ).first()

        if not subscription:
            return jsonify({"error": "Webhook subscription not found"}), 404

        # Get request data
        data = request.get_json()
        if not data or 'action' not in data:
            return jsonify({"error": "Missing required field: action"}), 400

        action = data['action']

        if action == 'reset':
            # Reset the circuit breaker
            success, error = reset_circuit_breaker(subscription_id)
            if not success:
                return jsonify({"error": error}), 400

            return jsonify({
                "success": True,
                "message": "Circuit breaker reset successfully",
                "circuit_status": "closed"
            }), 200

        elif action == 'configure':
            # Configure circuit breaker parameters
            failure_threshold = data.get('failure_threshold')
            reset_timeout = data.get('reset_timeout')

            if failure_threshold is None and reset_timeout is None:
                return jsonify({"error": "No configuration parameters provided"}), 400

            success, error = configure_circuit_breaker(
                subscription_id,
                failure_threshold=failure_threshold,
                reset_timeout=reset_timeout
            )

            if not success:
                return jsonify({"error": error}), 400

            return jsonify({
                "success": True,
                "message": "Circuit breaker configured successfully",
                "failure_threshold": failure_threshold if failure_threshold is not None else subscription.failure_threshold,
                "reset_timeout": reset_timeout if reset_timeout is not None else subscription.reset_timeout
            }), 200

        else:
            return jsonify({"error": f"Unsupported action: {action}"}), 400

    except Exception as e:
        current_app.logger.error(f"Error managing circuit breaker: {e}")
        return jsonify({"error": "Failed to manage circuit breaker"}), 500
