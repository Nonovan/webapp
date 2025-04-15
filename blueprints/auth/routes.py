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

from flask import Blueprint, render_template, flash, url_for, session, current_app, redirect
from forms import LoginForm


from services.auth_service import AuthService
from extensions import limiter


auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")
def login():
    """Handle user authentication and login process.
    
    This function manages the login workflow for users, including form validation,
    credential verification, session management, and security protections.
    
    Methods:
        GET: Display login form with reCAPTCHA.
        POST: Process login credentials, validate user, and establish session.
    
    Security features:
        - Rate limiting (5 requests per minute per IP)
        - Password hash verification
        - Session fixation protection
        - reCAPTCHA integration
        - Logging of login attempts
    
    Form fields:
        - username: User's username
        - password: User's password
        - remember: Optional checkbox to extend session lifetime
    
    Returns:
        GET: Rendered login template with form
        POST (success): Redirect to dashboard
        POST (failure): Rendered login template with error messages
    
    Session data set on successful login:
        - user_id: Database ID of authenticated user
        - username: Username of authenticated user
        - role: User's role for permission checks
        - last_active: Timestamp for session timeout management
    """
    
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Use AuthService to authenticate
        success, user, error_message = AuthService.authenticate_user(username, password)
        
        if success and user:
            # Use AuthService to establish session
            AuthService.login_user_session(user, remember=form.remember.data)
            
            # Handle 2FA if enabled
            if user.two_factor_enabled:
                session['awaiting_2fa'] = True
                return redirect(url_for('auth.two_factor'))
                
            return redirect(url_for('main.dashboard'))
        else:
            flash(error_message, 'danger')
    
    return render_template(
        'auth/login.html', 
        form=form, 
        recaptcha_site_key=current_app.config['RECAPTCHA_SITE_KEY']
    )

@auth_bp.route('/logout')
def logout():
    """Log out the user and redirect to login page."""
    AuthService.logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('auth.login'))
