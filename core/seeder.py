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
from typing import List
from flask import current_app
import click
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models.user import User
from models.audit_log import AuditLog
from models.security_incident import SecurityIncident
from models.system_config import SystemConfig


def seed_database() -> bool:
    """
    Seed the database with initial required data.
    
    This function creates necessary initial data for the application to function:
    - Admin user
    - Test users
    - Sample audit logs
    - Security incidents
    
    It checks if the database is already seeded by looking for existing users
    to prevent duplicate data.
    
    Returns:
        bool: True if seeding was successful, False if already seeded or error occurred
        
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

        with click.progressbar(length=5, label='Seeding database') as bar:
            # Create admin user
            admin = User(
                username="admin",
                email="admin@example.com",
                role="admin",
                status="active",
                created_at=datetime.utcnow()
            )
            admin.set_password("AdminPass123!")
            db.session.add(admin)
            bar.update(1)

            # Create test users
            test_users: List[User] = []
            for i in range(1, 4):
                user = User(
                    username=f"user{i}",
                    email=f"user{i}@example.com",
                    role="user",
                    status="active",
                    created_at=datetime.utcnow() - timedelta(days=i)
                )
                user.set_password("UserPass123!")
                test_users.append(user)

            db.session.add_all(test_users)
            bar.update(1)

            # Create test audit log entries
            audit_logs = []
            event_types = [
                AuditLog.EVENT_LOGIN_SUCCESS, 
                AuditLog.EVENT_LOGIN_FAILED,
                AuditLog.EVENT_PASSWORD_RESET,
                AuditLog.EVENT_API_ACCESS,
                AuditLog.EVENT_PERMISSION_DENIED
            ]

            # Sample realistic IP addresses
            ip_addresses = [
                "192.168.1.101",
                "10.0.0.15",
                "172.16.0.25",
                "192.168.0.254"
            ]

            # Sample user agents
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
            ]

            # Generate audit logs for the past 7 days
            for i in range(30):  # Generate 30 logs
                # Randomize timestamps for realistic data
                days_ago = random.randint(0, 7)
                hours_ago = random.randint(0, 23)
                minutes_ago = random.randint(0, 59)

                event_time = datetime.utcnow() - timedelta(
                    days=days_ago, 
                    hours=hours_ago, 
                    minutes=minutes_ago
                )

                # Select random event type and user
                event_type = random.choice(event_types)
                user_id = random.choice([None, admin.id, test_users[0].id, test_users[1].id])

                # Determine severity based on event type
                if event_type in (AuditLog.EVENT_LOGIN_FAILED, AuditLog.EVENT_PERMISSION_DENIED):
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
                    details = f"API endpoint accessed: /api/users/{random.randint(1, 100)}"
                elif event_type == AuditLog.EVENT_PERMISSION_DENIED:
                    details = "Permission denied to access restricted resource"
                else:
                    details = "System event logged"

                # Create audit log entry with realistic data
                log = AuditLog(
                    event_type=event_type,
                    user_id=user_id,
                    ip_address=random.choice(ip_addresses),
                    user_agent=random.choice(user_agents),
                    description=details,
                    severity=severity,
                    created_at=event_time
                )
                audit_logs.append(log)

            db.session.add_all(audit_logs)
            bar.update(1)

            # Create sample security incidents
            incidents = []
            incident_types = ["brute_force", "suspicious_access", "data_leak", "malware_detected"]
            sources = ["system", "user_report", "security_scan", "api_gateway"]

            for i in range(5):
                incident_type = random.choice(incident_types)

                # Create realistic incident descriptions
                if incident_type == "brute_force":
                    title = "Multiple Failed Login Attempts"
                    description = "Multiple failed login attempts detected from IP address"
                    details = f"Detected {random.randint(5, 20)} failed login attempts within 10 minutes from the same IP address."
                    severity = random.choice(["high", "medium"])
                elif incident_type == "suspicious_access":
                    title = "Unusual Access Pattern Detected"
                    description = "Unusual access pattern detected for user account"
                    details = "User accessed system resources outside normal working hours from an unrecognized IP address."
                    severity = random.choice(["medium", "low"])
                elif incident_type == "data_leak":
                    title = "Potential Data Exposure"
                    description = "Potential data exposure through insecure API endpoint"
                    details = "Large data transfer detected through API endpoint that may have exposed sensitive customer information."
                    severity = "critical"
                else:  # malware_detected
                    title = "Suspicious File Upload"
                    description = "Suspicious file upload detected and quarantined"
                    details = "File with potentially malicious code signature uploaded and automatically quarantined by security system."
                    severity = "high"

                # Randomize creation dates for realistic data
                days_ago = random.randint(1, 30)
                created_at = datetime.utcnow() - timedelta(days=days_ago)

                # More recent incidents are more likely to be open
                if days_ago < 7:
                    status = random.choice(["open", "investigating"])
                    resolved_at = None
                    resolution = None
                else:
                    status = random.choice(["resolved", "closed"])
                    resolved_at = created_at + timedelta(hours=random.randint(12, 72))
                    resolution = "Issue investigated and addressed according to security protocols." if status == "resolved" else "Incident closed after investigation determined no further action required."

                # Create the incident
                incident = SecurityIncident(
                    title=title,
                    incident_type=incident_type,
                    description=description,
                    details=details,
                    user_id=random.choice([None, admin.id, test_users[0].id]),
                    ip_address=random.choice(ip_addresses),
                    severity=severity,
                    status=status,
                    source=random.choice(sources),
                    created_at=created_at,
                    updated_at=created_at + timedelta(hours=random.randint(1, 24)),
                    resolved_at=resolved_at,
                    resolution=resolution,
                    assigned_to=admin.id if status in ["investigating", "resolved"] else None
                )
                incidents.append(incident)

            db.session.add_all(incidents)
            bar.update(1)

            # Set up system configuration
            configs = [
                SystemConfig(key="maintenance_mode", value="false", 
                             description="Enable site maintenance mode"),
                SystemConfig(key="max_login_attempts", value="5", 
                             description="Maximum failed login attempts before account lockout"),
                SystemConfig(key="session_timeout", value="30", 
                             description="Session timeout in minutes"),
                SystemConfig(key="security_level", value="high", 
                             description="Application security level (low, medium, high)")
            ]
            db.session.add_all(configs)
            bar.update(1)

        # Commit all changes
        db.session.commit()
        current_app.logger.info("Database successfully seeded with initial data")
        return True

    except (SQLAlchemyError, ValueError) as e:
        db.session.rollback()
        current_app.logger.error(f"Database seeding failed: {e}")
        return False


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

        # Create more security incidents with various severity levels
        incidents = []

        # High severity incident
        incidents.append(SecurityIncident(
            title="Potential Data Exfiltration Detected",
            incident_type="data_leak",
            description="Large data transfer detected to external IP address",
            details="User transferred 2.3GB of data to external FTP server from internal database.",
            severity="critical",
            status="open",
            source="system",
            ip_address="203.0.113.45",
            created_at=datetime.now(timezone.utc) - timedelta(hours=2),
            updated_at=datetime.now(timezone.utc) - timedelta(hours=2)
        ))

        # Medium severity incident
        incidents.append(SecurityIncident(
            title="Configuration File Modified",
            incident_type="suspicious_access",
            description="Critical configuration file was modified outside of change window",
            details="File: config/security.ini was modified by user without change approval",
            severity="medium",
            status="investigating",
            source="file_monitor",
            ip_address="10.0.12.25",
            assigned_to=admin.id,
            created_at=datetime.now(timezone.utc) - timedelta(days=1),
            updated_at=datetime.now(timezone.utc) - timedelta(days=1)
        ))

        # Low severity incident (resolved)
        incidents.append(SecurityIncident(
            title="Failed API Authentication Attempts",
            incident_type="brute_force",
            description="Multiple failed API authentication attempts from developer IP range",
            details="10 failed attempts over 30 minutes from development subnet",
            severity="low",
            status="resolved",
            source="api_gateway",
            ip_address="192.168.15.10",
            resolution="Confirmed as developer testing new integration. No security breach occurred.",
            resolved_at=datetime.now(timezone.utc) - timedelta(days=2),
            assigned_to=admin.id,
            created_at=datetime.now(timezone.utc) - timedelta(days=3),
            updated_at=datetime.now(timezone.utc) - timedelta(days=2)
        ))

        db.session.add_all(incidents)
        current_app.logger.info(f"Created {len(incidents)} development security incidents")

        # Create more detailed audit logs covering common security scenarios
        audit_logs = []

        # Suspicious activity pattern - multiple failed logins followed by success
        suspicious_ip = "45.33.22.85"
        base_time = datetime.utcnow() - timedelta(hours=8)

        # Failed login attempts - create a realistic brute force pattern
        for i in range(4):
            log = AuditLog(
                event_type=AuditLog.EVENT_LOGIN_FAILED,
                user_id=None,  # Unknown user
                description=f"Failed login attempt #{i+1} from suspicious IP",
                ip_address=suspicious_ip,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
                details="Failed login attempt for username: admin. Invalid password provided.",
                severity=AuditLog.SEVERITY_WARNING,
                created_at=base_time + timedelta(minutes=i*2)
            )
            audit_logs.append(log)

        # Successful login after failures (potential credential stuffing success)
        success_log = AuditLog(
            event_type=AuditLog.EVENT_LOGIN_SUCCESS,
            user_id=admin.id,
            description="Successful login after multiple failures",
            ip_address=suspicious_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
            details="Successful login for user: admin. Note: Preceded by multiple failed attempts from same IP.",
            severity=AuditLog.SEVERITY_INFO,
            created_at=base_time + timedelta(minutes=10)
        )
        audit_logs.append(success_log)

        # Sensitive operation after suspicious login - database access
        sensitive_log = AuditLog(
            event_type=AuditLog.EVENT_DATABASE_ACCESS,
            user_id=admin.id,
            description="Sensitive database table accessed after suspicious login pattern",
            ip_address=suspicious_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
            details="User admin executed query: SELECT * FROM users WHERE role='admin'",
            severity=AuditLog.SEVERITY_WARNING,
            created_at=base_time + timedelta(minutes=12)
        )
        audit_logs.append(sensitive_log)

        # Config change after suspicious access
        config_change_log = AuditLog(
            event_type=AuditLog.EVENT_CONFIG_CHANGE,
            user_id=admin.id,
            description="Configuration changed after suspicious login pattern",
            ip_address=suspicious_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
            details="User modified security settings: 'max_login_attempts' changed from 5 to 10",
            severity=AuditLog.SEVERITY_ERROR,
            created_at=base_time + timedelta(minutes=15)
        )
        audit_logs.append(config_change_log)

        # Permission denied attempt (indicator of privilege escalation attempt)
        permission_denied_log = AuditLog(
            event_type=AuditLog.EVENT_PERMISSION_DENIED,
            user_id=admin.id,
            description="Access attempt to restricted resource",
            ip_address=suspicious_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
            details="User attempted to access /admin/system/settings without required permissions",
            severity=AuditLog.SEVERITY_WARNING,
            created_at=base_time + timedelta(minutes=18)
        )
        audit_logs.append(permission_denied_log)

        # File integrity issue detected
        file_integrity_log = AuditLog(
            event_type=AuditLog.EVENT_FILE_INTEGRITY,
            user_id=None,
            description="Critical file modification detected",
            ip_address=None,
            user_agent=None,
            details="File: config/security.py has been modified outside the deployment process",
            severity=AuditLog.SEVERITY_CRITICAL,
            created_at=base_time + timedelta(minutes=25)
        )
        audit_logs.append(file_integrity_log)

        # Security countermeasure triggered
        countermeasure_log = AuditLog(
            event_type=AuditLog.EVENT_SECURITY_COUNTERMEASURE,
            user_id=None,
            description="Automated security response initiated",
            ip_address=suspicious_ip,
            user_agent=None,
            details="IP address temporarily blocked due to suspicious activity pattern",
            severity=AuditLog.SEVERITY_WARNING,
            created_at=base_time + timedelta(minutes=28)
        )
        audit_logs.append(countermeasure_log)

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
