# api/newsletter/routes.py

from flask import Blueprint, request, jsonify, current_app
from sqlalchemy.exc import SQLAlchemyError
from services.newsletter_service import NewsletterService
from extensions import db, limiter

newsletter_api = Blueprint('newsletter_api', __name__, url_prefix='/api/newsletter')

# Apply rate limiting
@newsletter_api.route('/subscribe', methods=['POST'])
@limiter.limit("5/minute")
def subscribe():
    """
    Newsletter subscription endpoint
    
    Accepts POST requests with JSON payload containing email
    Validates email, stores in database, and returns success message
    
    Returns:
        JSON response with success message or error
    """
    try:
        # Get and validate JSON data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request format, JSON required'}), 400
            
        email = data.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400
            
        # Let the service handle email validation
        result = NewsletterService.subscribe_email(email)
        
        if result.get('success'):
            # Return success message from the service or default
            message = result.get('message', 'Successfully subscribed to the newsletter!')
            return jsonify({'message': message}), 200
        else:
            # Return specific error from service
            return jsonify({'error': result.get('error', 'Subscription failed')}), 400
            
    except SQLAlchemyError as e:
        # Database error handling
        current_app.logger.error(f"Database error during newsletter subscription: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Database error occurred, please try again later'}), 500
    except (ValueError, KeyError, TypeError) as e:
        # General error handling
        current_app.logger.error(f"Error in newsletter subscription: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@newsletter_api.route('/confirm/<token>', methods=['GET'])
def confirm_subscription(token):
    """
    Confirm newsletter subscription with the provided token
    
    Args:
        token: The confirmation token from the email
        
    Returns:
        JSON response with success message or error
    """
    try:
        result = NewsletterService.confirm_subscription(token)
        
        if result.get('success'):
            return jsonify({'message': result.get('message', 'Subscription confirmed successfully')}), 200
        else:
            return jsonify({'error': result.get('error', 'Invalid confirmation token')}), 400
            
    except (ValueError, KeyError, TypeError) as e:
        current_app.logger.error(f"Error confirming subscription: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    except SQLAlchemyError as e:
        current_app.logger.error(f"Database error during subscription confirmation: {str(e)}")
        return jsonify({'error': 'Database error occurred, please try again later'}), 500

@newsletter_api.route('/unsubscribe/<token>', methods=['GET'])
def unsubscribe(token):
    """
    Unsubscribe from the newsletter using a token
    
    Args:
        token: The unsubscribe token from the email
        
    Returns:
        JSON response with success message or error
    """
    try:
        result = NewsletterService.unsubscribe(token)
        
        if result.get('success'):
            return jsonify({'message': result.get('message', 'Successfully unsubscribed')}), 200
        else:
            return jsonify({'error': result.get('error', 'Invalid unsubscribe token')}), 400
            
    except (ValueError, KeyError, TypeError) as e:
        current_app.logger.error(f"Error processing unsubscribe request: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@newsletter_api.route('/stats', methods=['GET'])
def get_stats():
    """
    Get newsletter subscription statistics
    
    Returns:
        JSON with subscription statistics
    """
    try:
        stats = NewsletterService.get_stats()
        return jsonify(stats), 200
    except (SQLAlchemyError, ValueError, KeyError, TypeError) as e:
        current_app.logger.error(f"Error retrieving newsletter stats: {str(e)}")
        return jsonify({'error': 'Failed to retrieve statistics'}), 500