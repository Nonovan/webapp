"""
Authentication routes for the application.

This module provides web routes for user authentication operations including
login, registration, password management, and session control. It uses the
AuthService for centralized authentication logic and security enforcement.

Routes:
    /login: User authentication and session creation
    /logout: Session termination
    /register: New account creation
    /forgot-password: Password reset initiation
    /reset-password: Password reset completion
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session

from forms.auth_forms import LoginForm, RegisterForm
from decorators import anonymous_required
from services.auth_service import AuthService
from extensions import limiter

auth_bp = Blueprint('auth', __name__, template_folder='templates')

@auth_bp.route('/login', methods=['GET', 'POST'])
@anonymous_required
@limiter.limit("5/minute")
def login():
    """
    Handle user authentication and login process.
    
    Authenticates a user based on username/password credentials and
    establishes a secure session. Includes protections against brute force
    attacks through rate limiting and account lockout mechanisms.
    
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
        
        try:
            # Use AuthService to authenticate
            success, user, error_message = AuthService.authenticate_user(username, password)
            
            if success and user:
                # Use AuthService to establish session
                AuthService.login_user_session(user, remember=form.remember.data)
                
                # Log successful login
                current_app.logger.info(f"Successful login: {username}")
                
                # Determine redirect destination (from ?next= param or default to dashboard)
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):  # Prevent open redirect
                    return redirect(next_page)
                return redirect(url_for('main.dashboard'))
            else:
                # Log failed login with generic message (avoid info disclosure)
                current_app.logger.warning(f"Failed login attempt for username: {username}")
                
                # Display lockout or error message
                flash(error_message, 'danger')
                
                # Add specific lockout information for UI
                if error_message and "locked" in error_message.lower():
                    return render_template('auth/login.html', 
                                          form=form,
                                          lockout=True,
                                          lockout_message=error_message)
        except (ValueError, KeyError) as e:  # Replace with specific exceptions
            # Log unexpected errors but show generic message to user
            current_app.logger.error(f"Login error: {str(e)}")
            flash("An unexpected error occurred. Please try again.", 'danger')
    
    # Get reCAPTCHA key from config if enabled
    recaptcha_site_key = current_app.config.get('RECAPTCHA_SITE_KEY', '')
    show_recaptcha = current_app.config.get('ENABLE_RECAPTCHA', False)
    
    return render_template('auth/login.html', 
                          form=form,
                          show_recaptcha=show_recaptcha, 
                          recaptcha_site_key=recaptcha_site_key)

@auth_bp.route('/logout')
def logout():
    """
    Log out the user and redirect to login page.
    
    Terminates the user session, removing all session data and
    invalidating the session cookie. For security, this action
    does not require confirmation and works even if already logged out.
    
    Returns:
        Redirect to the login page with a success message
    """
    # Get username before logout for logging (if available)
    username = session.get('username', 'Unknown user')
    
    # Use AuthService to clear session
    AuthService.logout_user()
    
    # Log the logout
    current_app.logger.info(f"User logged out: {username}")
    
    # Inform the user
    flash('You have been logged out successfully', 'success')
    
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
@anonymous_required
@limiter.limit("3/hour")
def register():
    """
    Handle new user registration.
    
    Creates a new user account based on the provided registration form data.
    Performs validation including username/email uniqueness checks and
    password strength requirements.
    
    Returns:
        GET: Rendered registration form 
        POST (success): Redirect to login page
        POST (failure): Rendered registration form with validation errors
    """
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Extract data from form
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        # Use AuthService to register user
        success, _, error_message = AuthService.register_user(
            username=username,
            email=email,
            password=password
        )
        
        if success:
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(error_message, 'danger')
    
    return render_template('auth/register.html', form=form)