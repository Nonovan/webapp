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
    /change-password: Password modification for authenticated users
    /mfa-setup: Multi-factor authentication configuration
    /mfa-verify: Multi-factor authentication verification
    /confirm-password: Password re-verification for sensitive operations
"""

import os
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    current_app, session, g, abort
)
from sqlalchemy.exc import SQLAlchemyError

from models.forms.auth_forms import (
    LoginForm, RegisterForm, ForgotPasswordForm, ResetPasswordForm,
    ChangePasswordForm, MFASetupForm, MFAVerifyForm, ConfirmPasswordForm
)
from blueprints.auth.decorators import anonymous_required, login_required, require_role
from blueprints.auth.utils import (
    is_safe_redirect_url, regenerate_session, record_login_success,
    record_login_failure, check_bruteforce_attempts, reset_login_attempts,
    audit_security_event
)
from extensions import limiter, db, cache, metrics
from models import User
from models.security import AuditLog
from services.auth_service import AuthService

# Create blueprint with template folder setting
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

        # Track metrics for login attempts
        metrics.info('auth_login_attempts_total', 1)

        # Check for brute force attempts
        is_locked, attempts_remaining = check_bruteforce_attempts(username)
        if is_locked:
            flash('Account temporarily locked due to too many failed attempts. Please try again later.', 'danger')
            current_app.logger.warning(f"Login attempt on locked account: {username}")
            return render_template(
                'auth/login.html',
                form=form,
                lockout=True,
                lockout_message="Account temporarily locked due to too many failed attempts."
            )

        try:
            # Use AuthService to authenticate
            success, user, error_message = AuthService.authenticate_user(
                username,
                password,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )

            if success and user:
                # Reset failed login attempts counter
                reset_login_attempts(username)

                # Use AuthService to establish session
                AuthService.login_user_session(user, remember=form.remember.data)

                # Record successful login for auditing
                record_login_success(user)

                # Regenerate session ID to prevent session fixation
                regenerate_session()

                # Determine redirect destination (from ?next= param or default to dashboard)
                next_page = request.args.get('next')
                if next_page and is_safe_redirect_url(next_page):
                    return redirect(next_page)

                return redirect(url_for('main.dashboard'))
            else:
                # Record failed login attempt for security monitoring
                record_login_failure(username, error_message or "Invalid credentials")

                # Display lockout or error message
                flash(error_message or "Invalid username or password.", 'danger')

                # Add specific lockout information for UI
                if error_message and "locked" in error_message.lower():
                    return render_template(
                        'auth/login.html',
                        form=form,
                        lockout=True,
                        lockout_message=error_message
                    )
        except SQLAlchemyError as e:
            # Database errors
            current_app.logger.error(f"Database error during login: {str(e)}", exc_info=True)
            db.session.rollback()
            flash("A system error occurred. Please try again later.", 'danger')
        except (ValueError, KeyError) as e:
            # Other unexpected errors
            current_app.logger.error(f"Login error: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", 'danger')

    # Get reCAPTCHA key from config if enabled
    recaptcha_site_key = current_app.config.get('RECAPTCHA_SITE_KEY', '')
    show_recaptcha = current_app.config.get('ENABLE_RECAPTCHA', False)

    # Track page view metric
    metrics.info('auth_page_views_total', 1, labels={'page': 'login'})

    return render_template(
        'auth/login.html',
        form=form,
        show_recaptcha=show_recaptcha,
        recaptcha_site_key=recaptcha_site_key
    )


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
    # Get user info before logout for logging (if available)
    user_id = session.get('user_id')
    username = session.get('username', 'Unknown user')

    if user_id:
        # Log security event for audit trail
        audit_security_event(
            event_type='user_logout',
            description=f"User logged out: {username}",
            severity="info"
        )

        try:
            # Update user session record if using persistent sessions
            user_session_id = session.get('session_id')
            if user_session_id:
                from models.auth import UserSession
                user_session = UserSession.query.get(user_session_id)
                if user_session:
                    user_session.is_active = False
                    user_session.ended_at = datetime.utcnow()
                    db.session.commit()
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error updating session record during logout: {str(e)}")
            db.session.rollback()

    # Use AuthService to clear session
    AuthService.logout_user()

    # Log the logout
    current_app.logger.info(f"User logged out: {username}")

    # Inform the user
    flash('You have been logged out successfully', 'success')

    # Track metrics
    metrics.info('auth_logout_total', 1)

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
    # Check if registration is enabled
    if not current_app.config.get('REGISTRATION_ENABLED', True):
        flash('Registration is currently disabled.', 'warning')
        return redirect(url_for('auth.login'))

    form = RegisterForm()

    if form.validate_on_submit():
        # Extract data from form
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Track metrics for registration attempts
        metrics.info('auth_registration_attempts_total', 1)

        try:
            # Use AuthService to register user
            success, user, error_message = AuthService.register_user(
                username=username,
                email=email,
                password=password,
                ip_address=request.remote_addr
            )

            if success:
                # Log successful registration
                current_app.logger.info(f"New user registered: {username}")
                audit_security_event(
                    event_type='user_registration',
                    description=f"New user registered: {username}",
                    severity="info"
                )

                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                # Log failed registration attempt
                current_app.logger.warning(f"Registration failed: {error_message}")
                flash(error_message, 'danger')

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error during user registration: {str(e)}", exc_info=True)
            flash('A system error occurred. Please try again later.', 'danger')

        except Exception as e:
            current_app.logger.error(f"Unexpected error during registration: {str(e)}", exc_info=True)
            flash('An unexpected error occurred. Please try again.', 'danger')

    # Track page view metric
    metrics.info('auth_page_views_total', 1, labels={'page': 'register'})

    return render_template('auth/register.html', form=form)


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@anonymous_required
@limiter.limit("5/hour")
def forgot_password():
    """
    Handle password reset requests.

    Initiates the password reset process by sending a reset link
    to the user's registered email address.

    Returns:
        GET: Rendered forgot password form
        POST (success): Redirect to login page with confirmation
        POST (failure): Rendered form with error message
    """
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data

        try:
            # Request password reset token
            success, message = AuthService.request_password_reset(email)

            # Always show success message to prevent email enumeration
            flash('If your email is registered, you will receive password reset instructions.', 'info')

            # Log the attempt (only log actual success internally)
            if success:
                current_app.logger.info(f"Password reset requested for: {email}")
            else:
                current_app.logger.info(f"Password reset requested for non-existent email: {email}")

            # Redirect to login
            return redirect(url_for('auth.login'))

        except Exception as e:
            current_app.logger.error(f"Error in forgot password: {str(e)}", exc_info=True)
            # Still show the same message to prevent information disclosure
            flash('If your email is registered, you will receive password reset instructions.', 'info')
            return redirect(url_for('auth.login'))

    # Track page view metric
    metrics.info('auth_page_views_total', 1, labels={'page': 'forgot_password'})

    return render_template('auth/forgot_password.html', form=form)


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@anonymous_required
@limiter.limit("5/hour")
def reset_password(token):
    """
    Handle password reset completion.

    Validates the reset token and allows the user to set a new password.
    Implements proper validation of the token and new password strength.

    Args:
        token: Password reset token sent to user's email

    Returns:
        GET: Rendered password reset form
        POST (success): Redirect to login page with confirmation
        POST (failure): Rendered form with validation errors
    """
    # Verify token before showing the form
    token_valid, user_id = AuthService.verify_reset_token(token)

    if not token_valid:
        flash('Invalid or expired password reset link. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        new_password = form.password.data

        try:
            # Reset the password using the AuthService
            success, message = AuthService.reset_password(token, new_password)

            if success:
                # Log the successful reset
                current_app.logger.info(f"Password reset successful for user ID: {user_id}")

                # Security audit logging
                audit_security_event(
                    event_type='password_reset',
                    description=f"Password reset completed for user ID: {user_id}",
                    severity="info"
                )

                flash('Your password has been reset successfully. You can now log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash(message, 'danger')

        except Exception as e:
            current_app.logger.error(f"Error in password reset: {str(e)}", exc_info=True)
            flash('An unexpected error occurred. Please try again.', 'danger')

    # Track page view metric
    metrics.info('auth_page_views_total', 1, labels={'page': 'reset_password'})

    return render_template('auth/reset_password.html', form=form, token=token)


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("10/hour")
def change_password():
    """
    Handle password changes for authenticated users.

    Allows users to change their password after verifying their current password.
    Implements proper validation of password strength.

    Returns:
        GET: Rendered change password form
        POST (success): Redirect to profile page with confirmation
        POST (failure): Rendered form with validation errors
    """
    form = ChangePasswordForm()

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        try:
            # Change the password using the AuthService
            success, message = AuthService.change_password(
                g.user.id,
                current_password,
                new_password
            )

            if success:
                # Log the successful password change
                current_app.logger.info(f"Password changed for user: {g.user.username}")

                # Security audit logging
                audit_security_event(
                    event_type='password_change',
                    description=f"Password changed for user: {g.user.username}",
                    severity="info"
                )

                # Force a session regeneration for security
                regenerate_session()

                flash('Your password has been changed successfully.', 'success')
                return redirect(url_for('main.profile'))
            else:
                flash(message, 'danger')

        except SQLAlchemyError as e:
            current_app.logger.error(f"Database error during password change: {str(e)}", exc_info=True)
            db.session.rollback()
            flash('A system error occurred. Please try again later.', 'danger')

        except Exception as e:
            current_app.logger.error(f"Error changing password: {str(e)}", exc_info=True)
            flash('An unexpected error occurred. Please try again.', 'danger')

    # Track page view metric
    metrics.info('auth_page_views_total', 1, labels={'page': 'change_password'})

    return render_template('auth/change_password.html', form=form)


@auth_bp.route('/mfa-setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    """
    Set up multi-factor authentication for a user account.

    Generates and displays a TOTP secret and QR code for the user to scan
    with an authenticator app. Verifies the setup with a confirmation code
    before enabling MFA on the account.

    Returns:
        GET: Rendered MFA setup form with QR code
        POST (success): Redirect to profile with confirmation
        POST (failure): Rendered form with validation errors
    """
    # Check if MFA is already set up
    if g.user.two_factor_enabled:
        flash('Multi-factor authentication is already enabled for your account.', 'info')
        return redirect(url_for('main.profile'))

    form = MFASetupForm()

    # Generate a new TOTP secret if not already in session
    if 'mfa_setup_secret' not in session:
        session['mfa_setup_secret'] = AuthService.generate_totp_secret()

    # Get QR code for the secret
    secret = session['mfa_setup_secret']
    qr_code_url = AuthService.get_totp_qr_code(g.user.username, secret)

    if form.validate_on_submit():
        verification_code = form.verification_code.data

        try:
            # Verify the code against the secret
            if AuthService.verify_totp_code(secret, verification_code):
                # Enable MFA for the user
                success = AuthService.enable_totp_mfa(g.user.id, secret)

                if success:
                    # Generate backup codes and store them to show to user
                    backup_codes = AuthService.generate_backup_codes(g.user.id)

                    # Clear the setup secret from the session
                    session.pop('mfa_setup_secret', None)

                    # Log the MFA setup
                    current_app.logger.info(f"MFA enabled for user: {g.user.username}")

                    # Security audit logging
                    audit_security_event(
                        event_type='mfa_enabled',
                        description=f"MFA enabled for user: {g.user.username}",
                        severity="info"
                    )

                    flash('Multi-factor authentication has been enabled for your account.', 'success')

                    # Show backup codes to the user once
                    return render_template(
                        'auth/mfa_backup_codes.html',
                        backup_codes=backup_codes
                    )
                else:
                    flash('Failed to enable multi-factor authentication. Please try again.', 'danger')
            else:
                flash('Invalid verification code. Please try again.', 'danger')

        except Exception as e:
            current_app.logger.error(f"Error setting up MFA: {str(e)}", exc_info=True)
            flash('An unexpected error occurred. Please try again.', 'danger')

    # Track page view metric
    metrics.info('auth_page_views_total', 1, labels={'page': 'mfa_setup'})

    return render_template(
        'auth/mfa_setup.html',
        form=form,
        qr_code_url=qr_code_url,
        secret=secret
    )


@auth_bp.route('/mfa-verify', methods=['GET', 'POST'])
@login_required
@limiter.limit("10/minute")
def mfa_verify():
    """
    Verify a multi-factor authentication code during login.

    This route is used during the login flow when MFA is enabled for a user.
    It validates the TOTP code or backup code provided by the user.

    Returns:
        GET: Rendered MFA verification form
        POST (success): Redirect to original destination
        POST (failure): Rendered form with validation error
    """
    # Verify that we're in the middle of an MFA verification flow
    if 'awaiting_mfa' not in session or not session['awaiting_mfa']:
        flash('No multi-factor authentication in progress.', 'warning')
        return redirect(url_for('main.dashboard'))

    form = MFAVerifyForm()

    if form.validate_on_submit():
        verification_code = form.verification_code.data
        use_backup = form.use_backup.data

        try:
            # Verify the code using the AuthService
            success = AuthService.verify_mfa(
                g.user.id,
                verification_code,
                use_backup=use_backup
            )

            if success:
                # Mark MFA as completed in the session
                session['mfa_verified'] = True
                session['awaiting_mfa'] = False

                # Log the successful MFA verification
                current_app.logger.info(f"MFA verified for user: {g.user.username}")

                # Get the original destination or default to dashboard
                next_url = session.pop('mfa_redirect_to', url_for('main.dashboard'))

                flash('Multi-factor authentication successful.', 'success')
                return redirect(next_url)
            else:
                flash('Invalid verification code. Please try again.', 'danger')

                # Track metrics for failed MFA attempts
                metrics.info('auth_mfa_failed_attempts_total', 1)

        except Exception as e:
            current_app.logger.error(f"Error verifying MFA: {str(e)}", exc_info=True)
            flash('An unexpected error occurred. Please try again.', 'danger')

    # Track page view metric
    metrics.info('auth_page_views_total', 1, labels={'page': 'mfa_verify'})

    return render_template('auth/mfa_verify.html', form=form)


@auth_bp.route('/confirm-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("10/minute")
def confirm_password():
    """
    Handle password confirmation for sensitive operations.

    This route is used to re-verify a user's password before performing
    sensitive operations like changing account settings.

    Returns:
        GET: Rendered password confirmation form
        POST (success): Redirect to original destination
        POST (failure): Rendered form with validation error
    """
    # Check if there's a destination to go to after confirmation
    if 'password_confirm_next' not in session:
        flash('No sensitive operation pending confirmation.', 'warning')
        return redirect(url_for('main.dashboard'))

    form = ConfirmPasswordForm()

    if form.validate_on_submit():
        password = form.password.data

        try:
            # Verify the password
            success = AuthService.verify_password(g.user.id, password)

            if success:
                # Mark password as confirmed in session
                session['password_confirmed_at'] = datetime.utcnow().isoformat()

                # Get the destination URL
                next_url = session.pop('password_confirm_next', url_for('main.dashboard'))

                # Security audit logging
                audit_security_event(
                    event_type='password_confirmed',
                    description=f"Password confirmed for sensitive operation by user: {g.user.username}",
                    severity="info"
                )

                return redirect(next_url)
            else:
                flash('Incorrect password. Please try again.', 'danger')

                # Track metrics for failed password confirmation
                metrics.info('auth_password_confirmation_failed_total', 1)

        except Exception as e:
            current_app.logger.error(f"Error confirming password: {str(e)}", exc_info=True)
            flash('An unexpected error occurred. Please try again.', 'danger')

    # Track page view metric
    metrics.info('auth_page_views_total', 1, labels={'page': 'confirm_password'})

    return render_template('auth/confirm_password.html', form=form)


@auth_bp.route('/mfa-disable', methods=['POST'])
@login_required
@require_role('admin')
def mfa_disable():
    """
    Disable multi-factor authentication for a user account.

    This is an administrative function for helping users who have
    lost their MFA device. It requires admin privileges.

    Returns:
        Redirect to user management with confirmation
    """
    # Verify that a user ID was provided
    user_id = request.form.get('user_id')
    if not user_id:
        flash('No user specified.', 'danger')
        return redirect(url_for('admin.users'))

    try:
        # Convert to integer
        user_id = int(user_id)

        # Disable MFA for the user
        success = AuthService.disable_mfa(user_id)

        if success:
            # Get the username for logging
            user = User.query.get(user_id)
            username = user.username if user else f"ID: {user_id}"

            # Log the MFA disable action
            current_app.logger.warning(f"MFA disabled for user {username} by admin: {g.user.username}")

            # Security audit logging
            audit_security_event(
                event_type='mfa_disabled_admin',
                description=f"MFA disabled for user {username} by admin: {g.user.username}",
                severity="warning"
            )

            flash(f'Multi-factor authentication has been disabled for user {username}.', 'success')
        else:
            flash('Failed to disable multi-factor authentication.', 'danger')

    except (ValueError, TypeError):
        flash('Invalid user ID provided.', 'danger')

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Database error disabling MFA: {str(e)}", exc_info=True)
        flash('A database error occurred. Please try again.', 'danger')

    except Exception as e:
        current_app.logger.error(f"Error disabling MFA: {str(e)}", exc_info=True)
        flash('An unexpected error occurred.', 'danger')

    return redirect(url_for('admin.users'))


@auth_bp.route('/access-denied')
def access_denied():
    """
    Display an access denied page.

    This route is used when a user attempts to access a resource
    they don't have permission for.

    Returns:
        Rendered access denied template with 403 status code
    """
    # Track metrics for access denied events
    metrics.info('auth_access_denied_total', 1)

    return render_template('auth/access_denied.html'), 403
