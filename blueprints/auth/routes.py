"""
Authentication routes module for myproject.

This module defines the HTTP routes for user authentication, including:
- User login with support for multi-factor authentication
- Password validation and security checks
- Session management
- Security protections against brute-force attacks

The module implements secure authentication practices including rate limiting,
proper password handling, and comprehensive error handling to prevent common
security vulnerabilities.
"""

from datetime import datetime
from typing import Union, cast
from flask import Blueprint, Response, request, render_template, flash, url_for, session, current_app
from flask import redirect as flask_redirect
from models import User
from extensions import db, limiter

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/login", methods=['GET', 'POST'])
@limiter.limit("5/minute")
def login() -> Union[str, Response]:
    """
    Handle user login requests with enhanced security.

    This route supports both GET and POST methods:
    - GET: Renders the login form
    - POST: Processes the login attempt with credentials validation

    Features:
    - Rate limiting to prevent brute force attacks
    - Two-factor authentication support when enabled
    - Comprehensive input validation
    - Session management with login tracking
    - Secure error handling

    Returns:
        Union[str, Response]:
            - On GET: Rendered login template
            - On successful POST: Redirect to home page
            - On failed POST: Error response with appropriate status code

    Rate limit:
        5 requests per minute per IP address
    """
    if request.method == 'GET':
        return render_template("auth/login.html")

    username = request.form.get("username")
    password = request.form.get("password")
    totp_code = request.form.get("totp")

    if not username or not password:
        flash("Username and password are required", "error")
        return Response(render_template("auth/login.html"), status=400)

    try:
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Check 2FA if enabled
            if user.two_factor_enabled:
                if not totp_code:
                    return render_template("auth/login.html", requires_2fa=True)
                if not user.verify_totp(totp_code):
                    flash("Invalid 2FA code", "error")
                    return Response(render_template("auth/login.html", requires_2fa=True), status=401)

            # Login successful
            session['user_id'] = user.id
            session['role'] = user.role
            session['last_active'] = datetime.utcnow().isoformat()

            # Update login tracking
            user.last_login = datetime.utcnow()
            user.login_count += 1
            db.session.commit()

            current_app.logger.info(f"User {username} logged in successfully")
            # Fix the return type to match the Union[str, Response] annotation
            return cast(Union[str, Response], flask_redirect(url_for('main.home')))

        flash("Invalid credentials", "error")
        current_app.logger.warning(f"Failed login attempt for user: {username}")
        return Response(render_template("auth/login.html"), status=401)

    except db.SQLAlchemyError as e:
        current_app.logger.error(f"Database error during login: {str(e)}")
        flash("A database error occurred. Please try again later.", "error")
        return Response(render_template("auth/login.html"), status=500)
    except ValueError as e:
        current_app.logger.error(f"Value error during login: {str(e)}")
        flash("A value error occurred. Please try again later.", "error")
        return Response(render_template("auth/login.html"), status=500)
    except RuntimeError as e:
        current_app.logger.error(f"Runtime error during login: {str(e)}")
        flash("A runtime error occurred. Please try again later.", "error")
        return Response(render_template("auth/login.html"), status=500)
