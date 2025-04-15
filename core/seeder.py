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
from datetime import datetime, timedelta
from typing import List
from flask import current_app
import click
from extensions import db
from models.user import User
from models.audit_log import AuditLog
from models.security_incident import SecurityIncident
from models.notification import Notification


def seed_database() -> bool:
    """
    Seed database with initial data.

    Populates the database with initial users and required application data.
    This function checks if data already exists before adding new records to
    prevent duplicates when run multiple times.

    Returns:
        bool: True if seeding was successful, False if already seeded

    Raises:
        Exception: If seeding fails

    Example:
        # Seed database during application initialization
        with app.app_context():
            seed_database()
    """
    try:
        # Check if already seeded
        if User.query.count() > 0:
            current_app.logger.info("Database already seeded. Skipping.")
            return False

        with click.progressbar(length=5, label='Seeding database') as bar_line:
            # Create admin user
            admin = User()
            admin.username = "admin"
            admin.email = "admin@example.com"
            admin.role = "admin"
            admin.status = "active"
            admin.created_at = datetime.utcnow()
            admin.set_password("AdminPass123!")
            db.session.add(admin)
            bar_line.update(1)

            # Create test users
            test_users: List[User] = []
            for i in range(1, 4):
                user = User()
                user.username = f"user{i}"
                user.email = f"user{i}@example.com"
                user.role = "user"
                user.status = "active"
                user.created_at = datetime.utcnow() - timedelta(days=i)
                user.set_password("UserPass123!")
                test_users.append(user)

            db.session.add_all(test_users)
            bar_line.update(1)
            
            # Create test audit log entries
            audit_logs = []
            event_types = [
                AuditLog.EVENT_LOGIN_SUCCESS, 
                AuditLog.EVENT_LOGIN_FAILED,
                AuditLog.EVENT_PASSWORD_RESET,
                AuditLog.EVENT_API_ACCESS,
                AuditLog.EVENT_PERMISSION_DENIED
            ]
            ip_addresses = [
                '192.168.1.100', 
                '10.0.0.15', 
                '172.16.1.25', 
                '192.168.10.55'
            ]
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
            ]
            
            # Generate audit logs for the past 7 days
            for i in range(30):  # Generate 30 logs
                days_ago = random.randint(0, 7)
                hours_ago = random.randint(0, 23)
                minutes_ago = random.randint(0, 59)
                
                event_time = datetime.utcnow() - timedelta(
                    days=days_ago, 
                    hours=hours_ago, 
                    minutes=minutes_ago
                )
                
                event_type = random.choice(event_types)
                user_id = random.choice([None, admin.id, test_users[0].id, test_users[1].id])
                
                # Determine severity based on event type
                if event_type == AuditLog.EVENT_LOGIN_FAILED or event_type == AuditLog.EVENT_PERMISSION_DENIED:
                    severity = random.choice([AuditLog.SEVERITY_WARNING, AuditLog.SEVERITY_ERROR])
                else:
                    severity = AuditLog.SEVERITY_INFO
                
                # Generate appropriate details based on event type
                if event_type == AuditLog.EVENT_LOGIN_SUCCESS:
                    details = "User login successful"
                elif event_type == AuditLog.EVENT_LOGIN_FAILED:
                    details = "Failed login attempt - invalid password"
                elif event_type == AuditLog.EVENT_PASSWORD_RESET:
                    details = "Password reset requested"
                elif event_type == AuditLog.EVENT_API_ACCESS:
                    details = "API endpoint accessed: /api/v1/users"
                elif event_type == AuditLog.EVENT_PERMISSION_DENIED:
                    details = "Permission denied for resource: /admin/settings"
                
                # Initialize 'details' with a default value
                details = "No details provided"

                # Generate appropriate details based on event type
                if event_type == AuditLog.EVENT_LOGIN_SUCCESS:
                    details = "User login successful"
                elif event_type == AuditLog.EVENT_LOGIN_FAILED:
                    details = "Failed login attempt - invalid password"
                elif event_type == AuditLog.EVENT_PASSWORD_RESET:
                    details = "Password reset requested"
                elif event_type == AuditLog.EVENT_API_ACCESS:
                    details = "API endpoint accessed: /api/v1/users"
                elif event_type == AuditLog.EVENT_PERMISSION_DENIED:
                    details = "Permission denied for resource: /admin/settings"

                log = AuditLog(
                    event_type=event_type,
                    user_id=user_id,
                    ip_address=random.choice(ip_addresses),
                    user_agent=random.choice(user_agents),
                    details=details,
                    severity=severity,
                    created_at=event_time  # Pass 'created_at' in the constructor if supported
                )
                
                audit_logs.append(log)
            
            db.session.add_all(audit_logs)
            bar_line.update(1)
            
            # Create security incidents
            incidents = []
            
            # Create one resolved incident
            resolved_incident = SecurityIncident(
                title="Suspicious Login Attempts Detected",
                threat_level=6,
                details="""Multiple failed login attempts from IP 192.168.1.100.
                Detected 5 failed attempts within 10 minutes.""",
                status="resolved",
                detected_at=datetime.utcnow() - timedelta(days=5),
                source="system",
            )
            incidents.append(resolved_incident)
            
            # Create one open incident
            open_incident = SecurityIncident(
                title="Unusual File Access Pattern Detected",
                threat_level=7,
                details="""User accessed multiple sensitive files in rapid succession.
                This behavior deviates from normal usage patterns.""",
                status="investigating",
                detected_at=datetime.utcnow() - timedelta(hours=6),
                source="system",
            )
            incidents.append(open_incident)
            
            db.session.add_all(incidents)
            bar_line.update(1)
            
            # Create notifications
            notifications = []
            
            # Security alert notification
            security_notification = Notification(
                user_id=admin.id,
                type="security_alert",
                title="Security Incident Detected",
                message="A new security incident has been reported. Please review the details and take appropriate action.",
                created_at=datetime.utcnow() - timedelta(hours=6),
                read=False
            )
            notifications.append(security_notification)
            
            # System notification
            system_notification = Notification(
                user_id=admin.id,
                type="system",
                title="System Update Available",
                message="A new system update is available. Please update at your earliest convenience.",
                created_at=datetime.utcnow() - timedelta(days=1),
                read=True
            )
            notifications.append(system_notification)
            
            # User notification
            for user in test_users:
                user_notification = Notification(
                    user_id=user.id,
                    type="account",
                    title="Password Expiration Notice",
                    message="Your password will expire in 7 days. Please update your password.",
                    created_at=datetime.utcnow() - timedelta(days=3),
                    read=random.choice([True, False])
                )
                notifications.append(user_notification)
            
            db.session.add_all(notifications)
            bar_line.update(1)

            # Commit changes
            db.session.commit()

            current_app.logger.info(f"Database seeded with {len(test_users) + 1} users, " +
                                   f"{len(audit_logs)} audit logs, {len(incidents)} incidents, " +
                                   f"and {len(notifications)} notifications")
            return True

    except Exception as e:
        current_app.logger.error(f"Database seeding failed: {e}")
        db.session.rollback()
        raise


def seed_development_data() -> bool:
    """
    Seed additional development data.
    
    This function adds extra data that's useful during development but
    should not be included in production seeding. It includes test
    security events, monitoring data, and sample incidents.
    
    Returns:
        bool: True if seeding was successful, False if skipped
        
    Example:
        # Only seed dev data in development environment
        if app.config['ENVIRONMENT'] == 'development':
            seed_development_data()
    """
    try:
        # Only run in development environment
        if current_app.config.get('ENVIRONMENT') != 'development':
            current_app.logger.info("Skipping development data seeding in non-development environment.")
            return False
            
        # Skip if we already have development data
        if SecurityIncident.query.count() > 5:
            current_app.logger.info("Development data already seeded. Skipping.")
            return False
            
        current_app.logger.info("Seeding development data...")
        
        # Get existing users
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            current_app.logger.warning("No admin user found. Run seed_database() first.")
            return False
            
        # Create more security incidents with various threat levels
        incidents = []
        
        # High threat level incident
        incidents.append(SecurityIncident(
            title="Potential Data Exfiltration Detected",
            threat_level=9,
            details="""Large data transfer detected to external IP.
            User transferred 2.3GB of data to external FTP server.""",
            status="open",
            detected_at=datetime.utcnow() - timedelta(hours=2),
            source="system"
        ))
        
        # Medium threat level incident
        incidents.append(SecurityIncident(
            title="Configuration File Modified",
            threat_level=6,
            details="""Critical configuration file was modified outside of change window.
            File: config/security.ini""",
            status="investigating",
            detected_at=datetime.utcnow() - timedelta(days=1),
            source="file_monitor"
        ))
        
        # Low threat level incident (resolved)
        incidents.append(SecurityIncident(
            title="Failed API Authentication Attempts",
            threat_level=3,
            details="""Multiple failed API authentication attempts from developer IP range.
            10 failed attempts over 30 minutes.""",
            status="resolved",
            detected_at=datetime.utcnow() - timedelta(days=3),
            source="api_gateway",
            resolution="Confirmed as developer testing new integration.",
            resolved_at=datetime.utcnow() - timedelta(days=2),
            assigned_to=admin.id
        ))
        
        db.session.add_all(incidents)
        
        # Create more detailed audit logs covering common security scenarios
        audit_logs = []
        
        # Suspicious activity pattern - multiple failed logins followed by success
        suspicious_ip = "45.33.22.85"
        base_time = datetime.utcnow() - timedelta(hours=8)
        
        # Failed login attempts
        for i in range(4):
            log = AuditLog(
                event_type=AuditLog.EVENT_LOGIN_FAILED,
                user_id=None,  # Unknown user
                ip_address=suspicious_ip,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
                details=f"Failed login attempt for username: admin",
                severity=AuditLog.SEVERITY_WARNING
            )
            log.created_at = base_time + timedelta(minutes=i*2)
            audit_logs.append(log)
        
        # Successful login after failures
        success_log = AuditLog(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user_id=admin.id,
            ip_address=suspicious_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
            details="Successful login",
            severity=AuditLog.SEVERITY_INFO,
            created_at=base_time + timedelta(minutes=10)
        )
        audit_logs.append(success_log)
        
        # Sensitive operation after suspicious login
        sensitive_log = AuditLog(
            event_type=AuditLog.EVENT_DATABASE_ACCESS,
            user_id=admin.id,
            ip_address=suspicious_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
            details="Access to users table with SELECT * query",
            severity=AuditLog.SEVERITY_WARNING,
            created_at=base_time + timedelta(minutes=12)
        )
        audit_logs.append(sensitive_log)
        
        db.session.add_all(audit_logs)
        db.session.commit()
        
        current_app.logger.info(f"Development data seeded with {len(incidents)} additional incidents " +
                               f"and {len(audit_logs)} additional audit logs")
        return True
        
    except Exception as e:
        current_app.logger.error(f"Development data seeding failed: {e}")
        db.session.rollback()
        raise


if __name__ == "__main__":
    from app import create_app
    app = create_app()
    with app.app_context():
        seed_database()
        if app.config.get('ENVIRONMENT') == 'development':
            seed_development_data()