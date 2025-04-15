# api/newsletter/routes.py

import re
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
            
        # Validate email format
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            return jsonify({'error': 'Invalid email format'}), 400
            
        # Use service to handle subscription
        result = NewsletterService.subscribe_email(email)
        
        if result.get('success'):
            # Log successful subscription
            current_app.logger.info(f"New newsletter subscription: {email}")
            return jsonify({'message': f'Successfully subscribed to the newsletter!'}), 200
        else:
            # Return specific error from service
            return jsonify({'error': result.get('error')}), 400
            
    except SQLAlchemyError as e:
        # Database error handling
        current_app.logger.error(f"Database error during newsletter subscription: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Database error occurred, please try again later'}), 500
    except Exception as e:
        # General error handling
        current_app.logger.error(f"Error in newsletter subscription: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500