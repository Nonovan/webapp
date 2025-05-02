"""
Authentication form definitions for the Cloud Infrastructure Platform.

This module provides form classes for authentication operations including
login, registration, password management, and multi-factor authentication.
All forms implement proper validation, CSRF protection, and security measures.

Forms:
    LoginForm: User authentication
    RegisterForm: New account creation
    ForgotPasswordForm: Password reset request
    ResetPasswordForm: Password reset completion
    ChangePasswordForm: Password modification for authenticated users
    MFASetupForm: Multi-factor authentication configuration
    MFAVerifyForm: Multi-factor authentication verification
    ConfirmPasswordForm: Password re-verification for sensitive operations
"""

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, BooleanField, SubmitField,
    HiddenField, ValidationError
)
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, Regexp, Optional
)
from flask import current_app

class LoginForm(FlaskForm):
    """Form for user authentication."""

    username = StringField('Username or Email', validators=[
        DataRequired(message="Please enter your username or email address.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Please enter your password.")
    ])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')


class RegisterForm(FlaskForm):
    """Form for new user registration."""

    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=3, max=64, message="Username must be between 3 and 64 characters."),
        Regexp(r'^[a-zA-Z0-9_-]+$', message="Username can only contain letters, numbers, underscores, and hyphens.")
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Email address is required."),
        Email(message="Please enter a valid email address."),
        Length(max=120, message="Email address is too long.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=12, message="Password must be at least 12 characters long."),
        Regexp(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]+',
               message="Password must include at least one lowercase letter, one uppercase letter, one number, and one special character.")
    ])
    confirm = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo('password', message="Passwords must match.")
    ])
    accept_terms = BooleanField('I accept the Terms and Conditions', validators=[
        DataRequired(message="You must accept the Terms and Conditions.")
    ])
    submit = SubmitField('Register')

    def validate_username(self, field):
        """Check if username is unique."""
        from models.auth import User
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username is already in use. Please choose a different username.')

    def validate_email(self, field):
        """Check if email is unique."""
        from models.auth import User
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email address is already registered.')


class ForgotPasswordForm(FlaskForm):
    """Form for requesting password reset."""

    email = StringField('Email', validators=[
        DataRequired(message="Email address is required."),
        Email(message="Please enter a valid email address."),
        Length(max=120, message="Email address is too long.")
    ])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm(FlaskForm):
    """Form for completing password reset."""

    password = PasswordField('New Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=12, message="Password must be at least 12 characters long."),
        Regexp(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]+',
               message="Password must include at least one lowercase letter, one uppercase letter, one number, and one special character.")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Please confirm your new password."),
        EqualTo('password', message="Passwords must match.")
    ])
    submit = SubmitField('Reset Password')


class ChangePasswordForm(FlaskForm):
    """Form for changing password."""

    current_password = PasswordField('Current Password', validators=[
        DataRequired(message="Please enter your current password.")
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=12, message="Password must be at least 12 characters long."),
        Regexp(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]+',
               message="Password must include at least one lowercase letter, one uppercase letter, one number, and one special character.")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Please confirm your new password."),
        EqualTo('new_password', message="Passwords must match.")
    ])
    submit = SubmitField('Change Password')


class MFASetupForm(FlaskForm):
    """Form for setting up multi-factor authentication."""

    verification_code = StringField('Verification Code', validators=[
        DataRequired(message="Verification code is required."),
        Length(min=6, max=6, message="Verification code must be 6 digits."),
        Regexp(r'^\d+$', message="Verification code must contain only numbers.")
    ])
    submit = SubmitField('Verify and Enable MFA')


class MFAVerifyForm(FlaskForm):
    """Form for verifying multi-factor authentication."""

    verification_code = StringField('Verification Code', validators=[
        DataRequired(message="Verification code is required."),
        Length(min=6, max=10, message="Verification code must be 6-10 characters."),
        Regexp(r'^[a-z0-9]+$', message="Verification code must contain only lowercase letters and numbers.")
    ])
    use_backup = BooleanField('Use Backup Code', default=False)
    submit = SubmitField('Verify')


class ConfirmPasswordForm(FlaskForm):
    """Form for confirming password for sensitive operations."""

    password = PasswordField('Current Password', validators=[
        DataRequired(message="Please enter your password.")
    ])
    next = HiddenField()
    submit = SubmitField('Confirm')
