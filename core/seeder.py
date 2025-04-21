"""
Database seeding module for myproject.

This module provides functionality for populating the database with initial data
required for application operation. It creates default users, test data, and
reference values needed for development, testing, and initial deployment.

Database seeding is typically performed:
- During initial application setup
- When setting up development environments
- During testing to ensure consistent test data
- When deploying to new environments

The module implements idempotent seeding operations that can be safely run
multiple times without creating duplicate data.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional
import logging
from flask import current_app
import click
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.user import User
from models.audit_log import AuditLog
from models.security_incident import SecurityIncident
from models.system_config import SystemConfig
from models.role import Role
from models.permission import Permission


def seed_database(force: bool = False, verbose: bool = False) -> bool:
    """
    Seed the database with initial required data.
    
    This function creates necessary initial data for the application to function:
    - Admin user
    - Test users
    - Sample audit logs
    - Security incidents
    - System configuration settings
    
    Args:
        force: If True, will recreate data even if it already exists
        verbose: If True, will output detailed progress information
        
    Returns:
        bool: True if seeding was successful, False if an error occurred
        
    Example:
        # Seed database during application initialization
        with app.app_context():
            success = seed_database(verbose=True)
    """
    try:
        if verbose:
            print("Starting database seeding process...")
        
        # Check if database is already seeded
        if not force and is_database_seeded():
            if verbose:
                print("Database already contains seed data. Use --force to override.")
            return True
            
        # Create roles and permissions first (required for users)
        roles = seed_roles_and_permissions(verbose)
        
        # Create users
        admin_user = seed_admin_user(force, verbose)
        test_users = seed_test_users(force, verbose)
        
        # Create reference and sample data
        seed_system_config(force, verbose)
        seed_audit_logs(admin_user.id if admin_user else None, force, verbose)
        seed_security_incidents(force, verbose)
        
        if verbose:
            print("✅ Database seeding completed successfully")
        return True
        
    except SQLAlchemyError as e:
        db.session.rollback()
        error_msg = f"Database seeding error: {str(e)}"
        logging.error(error_msg)
        print(f"❌ {error_msg}")
        return False
    except Exception as e:
        db.session.rollback()
        error_msg = f"Unexpected error during database seeding: {str(e)}"
        logging.error(error_msg)
        print(f"❌ {error_msg}")
        return False


def is_database_seeded() -> bool:
    """
    Check if the database already has seed data by looking for admin user.
    
    Returns:
        bool: True if database appears to be seeded, False otherwise
    """
    try:
        admin_exists = User.query.filter_by(username='admin').first() is not None
        return admin_exists
    except SQLAlchemyError:
        # If we can't query the database, assume it's not seeded
        return False


def seed_roles_and_permissions(verbose: bool = False) -> Dict[str, Role]:
    """
    Create basic roles and permissions in the database.
    
    Args:
        verbose: If True, will output detailed progress information
        
    Returns:
        dict: Dictionary of created role objects keyed by role name
    """
    if verbose:
        print("Creating roles and permissions...")
    
    # Define permissions
    permissions = {
        'view_users': Permission.create_or_update('view_users', 'Can view user list'),
        'manage_users': Permission.create_or_update('manage_users', 'Can create/edit users'),
        'view_logs': Permission.create_or_update('view_logs', 'Can view audit logs'),
        'manage_system': Permission.create_or_update('manage_system', 'Can modify system configuration'),
        'manage_security': Permission.create_or_update('manage_security', 'Can manage security incidents'),
    }
    
    # Define roles and their permissions
    roles = {
        'admin': {
            'description': 'Administrator with full access',
            'permissions': list(permissions.values())
        },
        'manager': {
            'description': 'Manager with limited administrative access',
            'permissions': [
                permissions['view_users'],
                permissions['view_logs'],
                permissions['manage_security']
            ]
        },
        'user': {
            'description': 'Standard user',
            'permissions': [
                permissions['view_logs']
            ]
        }
    }
    
    role_objects = {}
    
    # Create roles and assign permissions
    for role_name, role_info in roles.items():
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name, description=role_info['description'])
            db.session.add(role)
        
        # Assign permissions to role
        role.permissions = role_info['permissions']
        role_objects[role_name] = role
    
    db.session.commit()
    
    if verbose:
        print(f"Created {len(role_objects)} roles with permissions")
    
    return role_objects


def seed_admin_user(force: bool = False, verbose: bool = False) -> Optional[User]:
    """
    Create the default admin user if it doesn't exist.
    
    Args:
        force: If True, will recreate admin user even if it already exists
        verbose: If True, will output detailed progress information
        
    Returns:
        User: The admin user object or None if creation failed
    """
    if verbose:
        print("Creating admin user...")
    
    # Get admin role
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        if verbose:
            print("Warning: Admin role not found. Creating admin user without role.")
    
    # Check if admin user exists
    admin_user = User.query.filter_by(username='admin').first()
    
    if admin_user and force:
        # Delete existing admin user if forcing recreation
        db.session.delete(admin_user)
        db.session.commit()
        admin_user = None
        
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@example.com',
            first_name='Admin',
            last_name='User',
            active=True,
            created_at=datetime.now(timezone.utc)
        )
        admin_user.set_password('admin123')  # This should be changed after deployment
        
        if admin_role:
            admin_user.roles = [admin_role]
        
        db.session.add(admin_user)
        db.session.commit()
        
        if verbose:
            print("Created admin user with username 'admin'")
    elif verbose:
        print("Admin user already exists")
    
    return admin_user


def seed_test_users(force: bool = False, verbose: bool = False) -> List[User]:
    """
    Create test users for development environments.
    
    Args:
        force: If True, will recreate test users even if they already exist
        verbose: If True, will output detailed progress information
        
    Returns:
        list: The created test user objects
    """
    if verbose:
        print("Creating test users...")
    
    # Get roles
    roles = {
        'manager': Role.query.filter_by(name='manager').first(),
        'user': Role.query.filter_by(name='user').first()
    }
    
    test_users = [
        {
            'username': 'manager',
            'email': 'manager@example.com',
            'password': 'manager123',
            'first_name': 'Test',
            'last_name': 'Manager',
            'role': 'manager'
        },
        {
            'username': 'user1',
            'email': 'user1@example.com',
            'password': 'user123',
            'first_name': 'Test',
            'last_name': 'User',
            'role': 'user'
        },
        {
            'username': 'user2',
            'email': 'user2@example.com',
            'password': 'user123',
            'first_name': 'Another',
            'last_name': 'User',
            'role': 'user'
        }
    ]
    
    created_users = []
    
    for user_data in test_users:
        username = user_data['username']
        user = User.query.filter_by(username=username).first()
        
        if user and force:
            # Delete existing user if forcing recreation
            db.session.delete(user)
            db.session.commit()
            user = None
            
        if not user:
            user = User(
                username=username,
                email=user_data['email'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                active=True,
                created_at=datetime.now(timezone.utc)
            )
            user.set_password(user_data['password'])
            
            # Assign role if it exists
            role_name = user_data['role']
            if role_name in roles and roles[role_name]:
                user.roles = [roles[role_name]]
            
            db.session.add(user)
            created_users.append(user)
            
            if verbose:
                print(f"Created test user: {username}")
    
    db.session.commit()
    
    if verbose:
        print(f"Created {len(created_users)} test users")
    
    return created_users


def seed_audit_logs(admin_id: Optional[int] = None, force: bool = False, verbose: bool = False) -> List[AuditLog]:
    """
    Create sample audit logs.
    
    Args:
        admin_id: ID of admin user to use for logs, if available
        force: If True, will recreate logs even if they already exist
        verbose: If True, will output detailed progress information
        
    Returns:
        list: The created audit log objects
    """
    if verbose:
        print("Creating sample audit logs...")
    
    # Check if audit logs already exist
    existing_logs_count = AuditLog.query.count()
    if existing_logs_count > 0 and not force:
        if verbose:
            print(f"Skipping audit log creation, {existing_logs_count} logs already exist")
        return []
    elif force and existing_logs_count > 0:
        if verbose:
            print(f"Clearing {existing_logs_count} existing audit logs")
        AuditLog.query.delete()
        db.session.commit()
        
    # Define sample log events
    log_events = [
        ('User login', 'User logged in successfully', 'auth', 'info'),
        ('User logout', 'User logged out', 'auth', 'info'),
        ('Failed login attempt', 'Invalid password provided', 'auth', 'warning'),
        ('Password reset', 'User requested password reset', 'auth', 'info'),
        ('System startup', 'Application services started', 'system', 'info'),
        ('System configuration changed', 'Database connection settings updated', 'system', 'warning'),
        ('Security alert', 'Multiple failed login attempts detected', 'security', 'critical'),
        ('Database backup', 'Automated backup completed successfully', 'maintenance', 'info'),
        ('API rate limit exceeded', 'Too many requests from client', 'api', 'warning'),
        ('New user registered', 'User account created', 'user', 'info')
    ]
    
    created_logs = []
    
    # Create logs over the past 7 days
    now = datetime.now(timezone.utc)
    for i in range(50):  # Create 50 sample logs
        # Randomly select an event
        event_title, event_desc, category, level = random.choice(log_events)
        
        # Generate a random timestamp within the past 7 days
        days_ago = random.randint(0, 7)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        timestamp = now - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
        
        # Create the audit log entry
        log_entry = AuditLog(
            timestamp=timestamp,
            event=event_title,
            description=event_desc,
            category=category,
            level=level,
            user_id=admin_id if random.choice([True, False]) else None  # Randomly assign to admin or None
        )
        
        db.session.add(log_entry)
        created_logs.append(log_entry)
    
    db.session.commit()
    
    if verbose:
        print(f"Created {len(created_logs)} audit log entries")
    
    return created_logs


def seed_security_incidents(force: bool = False, verbose: bool = False) -> List[SecurityIncident]:
    """
    Create sample security incidents.
    
    Args:
        force: If True, will recreate incidents even if they already exist
        verbose: If True, will output detailed progress information
        
    Returns:
        list: The created security incident objects
    """
    if verbose:
        print("Creating sample security incidents...")
    
    # Check if incidents already exist
    existing_incidents_count = SecurityIncident.query.count()
    if existing_incidents_count > 0 and not force:
        if verbose:
            print(f"Skipping security incident creation, {existing_incidents_count} incidents already exist")
        return []
    elif force and existing_incidents_count > 0:
        if verbose:
            print(f"Clearing {existing_incidents_count} existing security incidents")
        SecurityIncident.query.delete()
        db.session.commit()
    
    # Define sample incidents
    incident_data = [
        {
            'title': 'Suspicious Login Attempts',
            'description': 'Multiple failed login attempts from unusual IP addresses',
            'severity': 'medium',
            'status': 'resolved',
            'days_ago': 15
        },
        {
            'title': 'Potential SQL Injection Attempt',
            'description': 'Malformed SQL query detected in user input fields',
            'severity': 'high',
            'status': 'investigation',
            'days_ago': 2
        },
        {
            'title': 'Unauthorized Access Attempt',
            'description': 'Attempt to access restricted API endpoints without valid credentials',
            'severity': 'medium',
            'status': 'resolved',
            'days_ago': 7
        },
        {
            'title': 'Data Export Volume Anomaly',
            'description': 'Unusual volume of data exported by authorized user',
            'severity': 'low',
            'status': 'monitoring',
            'days_ago': 1
        },
        {
            'title': 'DDoS Attack Identified',
            'description': 'Distributed denial of service attack against authentication service',
            'severity': 'critical',
            'status': 'resolved',
            'days_ago': 30
        }
    ]
    
    now = datetime.now(timezone.utc)
    created_incidents = []
    
    for data in incident_data:
        # Calculate timestamps
        detected_at = now - timedelta(days=data['days_ago'])
        resolved_at = None
        if data['status'] == 'resolved':
            resolution_days = random.randint(1, 3)  # Resolved 1-3 days after detection
            resolved_at = detected_at + timedelta(days=resolution_days)
        
        incident = SecurityIncident(
            title=data['title'],
            description=data['description'],
            severity=data['severity'],
            status=data['status'],
            detected_at=detected_at,
            resolved_at=resolved_at
        )
        
        db.session.add(incident)
        created_incidents.append(incident)
    
    db.session.commit()
    
    if verbose:
        print(f"Created {len(created_incidents)} security incidents")
    
    return created_incidents


def seed_system_config(force: bool = False, verbose: bool = False) -> List[SystemConfig]:
    """
    Create essential system configuration settings.
    
    Args:
        force: If True, will recreate settings even if they already exist
        verbose: If True, will output detailed progress information
        
    Returns:
        list: The created system config objects
    """
    if verbose:
        print("Creating system configuration settings...")
    
    # Define default configuration
    default_configs = [
        ('maintenance_mode', 'false', 'system', 'Flag to enable/disable maintenance mode'),
        ('session_timeout', '30', 'security', 'Session timeout in minutes'),
        ('max_login_attempts', '5', 'security', 'Maximum failed login attempts before lockout'),
        ('password_expiry_days', '90', 'security', 'Number of days before passwords expire'),
        ('backup_retention_days', '30', 'maintenance', 'Number of days to retain database backups'),
        ('allowed_file_extensions', 'jpg,png,pdf,docx,xlsx', 'security', 'Allowed file upload extensions'),
        ('enable_audit_logging', 'true', 'system', 'Enable detailed audit logging')
    ]
    
    created_configs = []
    
    for key, value, category, description in default_configs:
        config = SystemConfig.query.filter_by(key=key).first()
        
        if config and force:
            # Update existing config if force is True
            config.value = value
            config.updated_at = datetime.now(timezone.utc)
            if verbose:
                print(f"Updated system config: {key}={value}")
        elif not config:
            # Create new config
            config = SystemConfig(
                key=key,
                value=value,
                category=category,
                description=description,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(config)
            created_configs.append(config)
            if verbose:
                print(f"Created system config: {key}={value}")
    
    db.session.commit()
    
    if verbose:
        print(f"Created/updated {len(created_configs)} system configuration settings")
    
    return created_configs


def seed_development_data(force: bool = False, verbose: bool = False) -> bool:
    """
    Seed additional data for development environments.
    This includes more sample data than would be used in production seeding.
    
    Args:
        force: If True, will recreate data even if it already exists
        verbose: If True, will output detailed progress information
        
    Returns:
        bool: True if seeding was successful, False if an error occurred
    """
    try:
        if verbose:
            print("Starting development data seeding...")
        
        # Add more test users with different roles
        seed_additional_users(force, verbose)
        
        # Add more sample data specific to development
        seed_extensive_audit_logs(force, verbose)
        
        if verbose:
            print("✅ Development data seeding completed successfully")
        return True
        
    except SQLAlchemyError as e:
        db.session.rollback()
        error_msg = f"Development data seeding error: {str(e)}"
        logging.error(error_msg)
        print(f"❌ {error_msg}")
        return False
    except Exception as e:
        db.session.rollback()
        error_msg = f"Unexpected error during development data seeding: {str(e)}"
        logging.error(error_msg)
        print(f"❌ {error_msg}")
        return False


def seed_additional_users(force: bool = False, verbose: bool = False) -> List[User]:
    """
    Create additional test users for development environments.
    
    Args:
        force: If True, will recreate users even if they already exist
        verbose: If True, will output detailed progress information
        
    Returns:
        list: The created user objects
    """
    if verbose:
        print("Creating additional development users...")
    
    # Create 10 more test users
    roles = {
        'admin': Role.query.filter_by(name='admin').first(),
        'manager': Role.query.filter_by(name='manager').first(),
        'user': Role.query.filter_by(name='user').first()
    }
    
    created_users = []
    
    for i in range(1, 11):
        role_key = random.choice(['user', 'user', 'user', 'manager', 'admin'])  # 60% users, 20% managers, 20% admins
        username = f"dev_user{i}"
        
        # Skip if user exists and not forcing recreation
        user = User.query.filter_by(username=username).first()
        if user and not force:
            continue
        elif user and force:
            db.session.delete(user)
            db.session.commit()
        
        # Create new user
        new_user = User(
            username=username,
            email=f"{username}@example.com",
            first_name=f"Dev{i}",
            last_name=f"User{i}",
            active=True,
            created_at=datetime.now(timezone.utc) - timedelta(days=random.randint(0, 90))
        )
        new_user.set_password("password123")
        
        # Assign role
        if roles[role_key]:
            new_user.roles = [roles[role_key]]
        
        db.session.add(new_user)
        created_users.append(new_user)
        
        if verbose and (i % 5 == 0 or i == 1):
            print(f"Created {i} development users so far...")
    
    db.session.commit()
    
    if verbose:
        print(f"Created {len(created_users)} additional development users")
    
    return created_users


def seed_extensive_audit_logs(force: bool = False, verbose: bool = False) -> List[AuditLog]:
    """
    Create a large number of audit logs for testing pagination and filtering.
    
    Args:
        force: If True, will create logs even if many already exist
        verbose: If True, will output detailed progress information
        
    Returns:
        list: The created audit log objects
    """
    if verbose:
        print("Creating extensive audit logs for development...")
    
    # Check if we already have many logs
    existing_count = AuditLog.query.count()
    if existing_count > 100 and not force:
        if verbose:
            print(f"Skipping extensive log creation, {existing_count} logs already exist")
        return []
    
    # Log event templates
    log_events = [
        ('User login', 'User {user} logged in successfully', 'auth', 'info'),
        ('User logout', 'User {user} logged out', 'auth', 'info'),
        ('Failed login attempt', 'Invalid password provided for {user}', 'auth', 'warning'),
        ('Password changed', 'User {user} changed their password', 'auth', 'info'),
        ('Permission denied', 'User {user} attempted to access unauthorized resource', 'security', 'warning'),
        ('Record created', 'User {user} created a new {resource}', 'data', 'info'),
        ('Record updated', 'User {user} updated {resource} with ID {id}', 'data', 'info'),
        ('Record deleted', 'User {user} deleted {resource} with ID {id}', 'data', 'warning'),
        ('API request', 'External API request to {endpoint}', 'api', 'info'),
        ('API error', 'Error in API request to {endpoint}: {error}', 'api', 'error'),
        ('System alert', '{message}', 'system', 'critical')
    ]
    
    # Resource types for logs
    resources = ['user', 'report', 'invoice', 'customer', 'order', 'product', 'ticket']
    
    # User list for log attribution
    users = User.query.all()
    user_ids = [user.id for user in users] if users else [None]
    
    # System alert messages
    system_alerts = [
        'Disk space running low',
        'CPU usage exceeded threshold',
        'Memory usage exceeded threshold',
        'Database connection pool nearly exhausted',
        'Background job queue backed up',
        'Redis cache hit ratio below threshold'
    ]
    
    # API endpoints
    endpoints = [
        '/api/v1/users',
        '/api/v1/auth/token',
        '/api/v1/reports/generate',
        '/api/v1/orders',
        '/api/v1/products',
        '/api/v1/analytics'
    ]
    
    # API errors
    api_errors = [
        'Connection timeout',
        'Invalid request format',
        'Authentication failed',
        'Rate limit exceeded',
        'Resource not found',
        'Internal server error'
    ]
    
    created_logs = []
    now = datetime.now(timezone.utc)
    
    # Create 200 logs over the past 90 days
    for i in range(200):
        # Select random event template
        event_title, event_desc, category, level = random.choice(log_events)
        
        # Format the description with appropriate values
        formatted_desc = event_desc
        if '{user}' in formatted_desc:
            user = User.query.get(random.choice(user_ids))
            formatted_desc = formatted_desc.replace('{user}', user.username if user else 'unknown')
            
        if '{resource}' in formatted_desc:
            formatted_desc = formatted_desc.replace('{resource}', random.choice(resources))
            
        if '{id}' in formatted_desc:
            formatted_desc = formatted_desc.replace('{id}', str(random.randint(1, 1000)))
            
        if '{endpoint}' in formatted_desc:
            formatted_desc = formatted_desc.replace('{endpoint}', random.choice(endpoints))
            
        if '{error}' in formatted_desc:
            formatted_desc = formatted_desc.replace('{error}', random.choice(api_errors))
            
        if '{message}' in formatted_desc:
            formatted_desc = formatted_desc.replace('{message}', random.choice(system_alerts))
        
        # Generate a random timestamp within the past 90 days
        days_ago = random.randint(0, 90)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        timestamp = now - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
        
        # Create the audit log entry
        log_entry = AuditLog(
            timestamp=timestamp,
            event=event_title,
            description=formatted_desc,
            category=category,
            level=level,
            user_id=random.choice(user_ids)
        )
        
        db.session.add(log_entry)
        created_logs.append(log_entry)
        
        # Commit in batches to avoid memory issues
        if i % 50 == 0:
            db.session.commit()
            if verbose:
                print(f"Created {i} audit logs so far...")
    
    db.session.commit()
    
    if verbose:
        print(f"Created {len(created_logs)} additional audit logs for development")
    
    return created_logs
