"""
Webhook API routes for subscription management and webhook testing.
"""

from flask import Blueprint, request, jsonify, current_app, g, abort
from flask_jwt_extended import jwt_required
from sqlalchemy.exc import SQLAlchemyError
from uuid import uuid4
from datetime import datetime
import json

from extensions import db, metrics
from models.audit_log import AuditLog
from api.webhooks.models import WebhookSubscription, WebhookDeliveryAttempt
from api.webhooks.services import trigger_webhook, validate_subscription_data
from api.webhooks import EventType, generate_webhook_signature
from core.utils import log_security_event
from api.decorators import permission_required

webhooks_bp = Blueprint('webhooks', __name__)

@webhooks_bp.route('', methods=['GET'])
@jwt_required()
@permission_required('webhooks:view')
def list_subscriptions():
    """List webhook subscriptions."""
    try:
        # Filter by user if not admin
        user_id = g.user_id
        if not g.user.has_permission('webhooks:view_all'):
            subscriptions = WebhookSubscription.query.filter_by(created_by_id=user_id).all()
        else:
            subscriptions = WebhookSubscription.query.all()
        
        return jsonify({
            'status': 'success',
            'data': [sub.to_dict() for sub in subscriptions]
        }), 200
    except SQLAlchemyError as e:
        current_app.logger.error(f"Database error in list_subscriptions: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Database error occurred while retrieving webhooks'
        }), 500

@webhooks_bp.route('', methods=['POST'])
@jwt_required()
@permission_required('webhooks:create')
def create_subscription():
    """Create a new webhook subscription."""
    try:
        data = request.json
        error = validate_subscription_data(data)
        if error:
            return jsonify({
                'status': 'error',
                'message': error
            }), 400
        
        # Generate a secure webhook secret if not provided
        if not data.get('secret'):
            import secrets
            data['secret'] = secrets.token_hex(32)
        
        subscription = WebhookSubscription(
            name=data['name'],
            url=data['url'],
            description=data.get('description', ''),
            created_by_id=g.user_id,
            event_types=data['event_types'],
            headers=data.get('headers', {}),
            secret=data['secret'],
            max_retries=data.get('max_retries', 3),
            retry_interval=data.get('retry_interval', 60)
        )
        
        db.session.add(subscription)
        db.session.commit()
        
        # Log the creation
        log_security_event(
            event_type=AuditLog.EVENT_WEBHOOK_CREATED,
            description=f"Webhook subscription '{subscription.name}' created",
            severity=AuditLog.SEVERITY_INFO
        )
        
        # Note: Return the secret only on creation
        result = subscription.to_dict()
        result['secret'] = data['secret']
        
        metrics.counter('webhook_subscriptions_created_total').inc()
        
        return jsonify({
            'status': 'success',
            'message': 'Webhook subscription created successfully',
            'data': result
        }), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Database error in create_subscription: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Database error occurred while creating webhook subscription'
        }), 500

@webhooks_bp.route('/<int:subscription_id>', methods=['GET'])
@jwt_required()
@permission_required('webhooks:view')
def get_subscription(subscription_id):
    """Get a specific webhook subscription."""
    try:
        subscription = WebhookSubscription.query.get(subscription_id)
        if not subscription:
            return jsonify({
                'status': 'error',
                'message': 'Webhook subscription not found'
            }), 404
        
        # Check ownership unless admin
        if not g.user.has_permission('webhooks:view_all') and subscription.created_by_id != g.user_id:
            return jsonify({
                'status': 'error',
                'message': 'You do not have permission to view this webhook subscription'
            }), 403
        
        return jsonify({
            'status': 'success',
            'data': subscription.to_dict()
        }), 200
    except SQLAlchemyError as e:
        current_app.logger.error(f"Database error in get_subscription: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Database error occurred while retrieving webhook subscription'
        }), 500

@webhooks_bp.route('/<int:subscription_id>/deliveries', methods=['GET'])
@jwt_required()
@permission_required('webhooks:view')
def list_deliveries(subscription_id):
    """List webhook delivery attempts for a subscription."""
    try:
        subscription = WebhookSubscription.query.get(subscription_id)
        if not subscription:
            return jsonify({
                'status': 'error',
                'message': 'Webhook subscription not found'
            }), 404
        
        # Check ownership unless admin
        if not g.user.has_permission('webhooks:view_all') and subscription.created_by_id != g.user_id:
            return jsonify({
                'status': 'error',
                'message': 'You do not have permission to view this webhook subscription'
            }), 403
        
        # Get delivery attempts, newest first
        deliveries = WebhookDeliveryAttempt.query.filter_by(
            subscription_id=subscription_id
        ).order_by(WebhookDeliveryAttempt.created_at.desc()).limit(100).all()
        
        return jsonify({
            'status': 'success',
            'data': [delivery.to_dict() for delivery in deliveries]
        }), 200
    except SQLAlchemyError as e:
        current_app.logger.error(f"Database error in list_deliveries: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Database error occurred while retrieving webhook deliveries'
        }), 500

@webhooks_bp.route('/<int:subscription_id>/test', methods=['POST'])
@jwt_required()
@permission_required('webhooks:manage')
def test_webhook(subscription_id):
    """Send a test webhook to verify the subscription is working."""
    try:
        subscription = WebhookSubscription.query.get(subscription_id)
        if not subscription:
            return jsonify({
                'status': 'error',
                'message': 'Webhook subscription not found'
            }), 404
        
        # Check ownership unless admin
        if not g.user.has_permission('webhooks:manage_all') and subscription.created_by_id != g.user_id:
            return jsonify({
                'status': 'error',
                'message': 'You do not have permission to test this webhook subscription'
            }), 403
        
        # Create test payload
        test_payload = {
            'event': 'test',
            'test': True,
            'timestamp': datetime.utcnow().isoformat(),
            'subscription_id': subscription_id
        }
        
        # Send test webhook
        success, result = trigger_webhook(
            subscription=subscription,
            event_type='test',
            payload=test_payload,
            is_test=True
        )
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Test webhook sent successfully',
                'data': result
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to send test webhook',
                'data': result
            }), 500
    except Exception as e:
        current_app.logger.error(f"Error in test_webhook: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Error testing webhook: {str(e)}'
        }), 500
