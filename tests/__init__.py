"""
Test configuration and fixtures package for the cloud services platform.

This package contains pytest fixtures and configuration for the application's test suite.
It provides the testing infrastructure needed to run isolated, repeatable tests against
all components of the application including routes, models, and utilities.

Key elements provided by this package:
- Application test fixtures with controlled configurations
- Database fixtures with isolated test databases
- User authentication fixtures with different permission levels
- Cloud provider and resource mocking
- Security testing helpers and vulnerability scanners
- Mock metrics and monitoring data
- Test client configuration for API testing

The fixtures are designed to be modular, allowing tests to request only the
dependencies they need, and are automatically cleaned up after each test to
maintain isolation between test cases.
"""

from datetime import datetime, timedelta
import json
import logging
import os
import random
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, current_app
from flask.testing import FlaskClient
import jwt

from app import create_app
from extensions import db, cache, metrics
from models.user import User
from models.cloud_resource import CloudResource
from models.cloud_provider import CloudProvider
from models.cloud_metric import CloudMetric
from models.cloud_alert import CloudAlert
from models.security_incident import SecurityIncident
from models.audit_log import AuditLog

# Application Fixtures
@pytest.fixture
def app() -> Flask:
    """
    Create an application instance configured for testing.

    This fixture creates a Flask application with testing-specific configuration
    including an in-memory SQLite database, disabled CSRF protection, and enhanced
    logging for test visibility.

    Returns:
        Flask: Flask application instance configured for testing

    Example:
        def test_app_config(app):
            assert app.config['TESTING'] is True
            assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'
    """
    test_app = create_app('testing')
    test_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost.localdomain',
        'CLOUD_PROVIDERS_ENABLED': True,
        'METRICS_ENABLED': False,  # Disable metrics during tests
        'JWT_SECRET_KEY': 'test-jwt-secret',
        'SECURITY_LOG_LEVEL': 'INFO',  # Lower security log level for testing
        'CACHE_TYPE': 'simple',  # Use simple cache for testing
        'MAIL_SUPPRESS_SEND': True  # Don't actually send emails during tests
    })
    
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()

    # Setup test logging
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    test_app.logger.handlers = [handler]
    test_app.logger.setLevel(logging.DEBUG)

    return test_app

@pytest.fixture
def client(test_app) -> Any:
    """
    Create a Flask test client for making requests.

    This fixture provides a test client that can be used to make requests against
    the application without running a server, enabling fast and direct testing of
    routes and views.

    Args:
        test_app: The Flask application fixture

    Returns:
        Any: Flask test client instance

    Example:
        def test_home_page(client):
            response = client.get('/')
            assert response.status_code == 200
            assert b'Welcome' in response.data
    """
    return test_app.test_client()

@pytest.fixture
def runner(test_app) -> Any:
    """
    Create a CLI test runner for testing command-line commands.

    This fixture provides a test CLI runner that can be used to invoke and test
    Flask CLI commands within the application context.

    Args:
        test_app: The Flask application fixture

    Returns:
        Any: Flask CLI test runner

    Example:
        def test_init_db_command(runner):
            result = runner.invoke(init_db)
            assert 'Initialized' in result.output
    """
    return test_app.test_cli_runner()

# Database Fixtures
@pytest.fixture
def init_database(test_app):
    """
    Initialize and clean up test database.

    This fixture creates all database tables before each test and drops them
    afterward, ensuring each test runs with a clean database state. It also
    provides the database session for test use.

    Args:
        test_app: The Flask application fixture

    Yields:
        SQLAlchemy: Database instance for test use

    Example:
        def test_create_user(init_database):
            user = User(username='test', email='test@example.com')
            init_database.session.add(user)
            init_database.session.commit()
            assert User.query.count() == 1
    """
    with test_app.app_context():
        db.create_all()
        yield db
        db.session.remove()
        db.drop_all()

# User Fixtures
@pytest.fixture
def test_user(test_app) -> User:
    """
    Create a standard test user.

    This fixture creates a user with standard permissions that can be used for
    testing authentication and user-specific functionality.

    Args:
        test_app: The Flask application fixture

    Returns:
        User: A User model instance with standard permissions

    Example:
        def test_user_profile(client, test_user):
            # Login as test user
            # Test profile page access
    """
    with test_app.app_context():
        user = User()
        user.username = 'testuser'
        user.email = 'test@example.com'
        user.role = 'user'
        user.status = 'active'
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        return user

@pytest.fixture
def admin_user(test_app) -> User:
    """
    Create an admin user for testing admin functionality.

    This fixture creates a user with administrative permissions that can be used
    for testing admin-only functionality and permission-based access control.

    Args:
        test_app: The Flask application fixture

    Returns:
        User: A User model instance with admin permissions

    Example:
        def test_admin_panel(client, admin_user):
            # Login as admin
            # Test admin panel access
    """
    with test_app.app_context():
        admin = User()
        admin.username = 'admin'
        admin.email = 'admin@example.com'
        admin.role = 'admin'
        admin.status = 'active'
        admin.set_password('AdminPass123!')
        db.session.add(admin)
        db.session.commit()
        return admin

@pytest.fixture
def auth_headers(user_fixture) -> Dict[str, str]:
    """
    Generate authentication headers for API testing.

    This fixture creates HTTP headers containing an authentication token for
    the specified user, enabling authenticated API requests in tests.

    Args:
        user_fixture: A User model instance to generate a token for

    Returns:
        Dict[str, str]: HTTP headers dictionary with authentication token

    Example:
        def test_protected_api(client, auth_headers):
            response = client.get('/api/protected', headers=auth_headers)
            assert response.status_code == 200
    """
    token = user_fixture.generate_token()
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def mock_data() -> Dict[str, Any]:
    """
    Provide mock data for testing.

    This fixture generates a standard set of mock data that can be used for
    testing data processing, rendering, and API responses.

    Returns:
        Dict[str, Any]: Dictionary of mock data for testing

    Example:
        def test_metrics_display(client, mock_data):
            # Patch data source to return mock_data
            # Test rendering of metrics
    """
    return {
        'metrics': {
            'cpu_usage': 45.2,
            'memory_usage': 62.8,
            'disk_usage': 78.5
        },
        'timestamp': datetime.utcnow().isoformat()
    }

@pytest.fixture
def mock_db_session(mocker) -> Any:
    """
    Mock database session for unit testing.

    This fixture provides a mock database session that can be used to test
    database interactions without accessing a real database.

    Args:
        mocker: pytest-mock fixture

    Returns:
        Any: Mock database session object

    Example:
        def test_user_creation(mock_db_session):
            mock_db_session.add.return_value = None
            mock_db_session.commit.return_value = None
            # Test function that uses db.session
    """
    session = mocker.MagicMock()
    mocker.patch('extensions.db.session', session)
    return session

@pytest.fixture
def mock_cache(mocker) -> Any:
    """
    Mock cache for unit testing.

    This fixture provides a mock cache object that can be used to test
    caching behavior without using a real cache.

    Args:
        mocker: pytest-mock fixture

    Returns:
        Any: Mock cache object

    Example:
        def test_cached_function(mock_cache):
            mock_cache.get.return_value = None
            mock_cache.set.return_value = True
            # Test function that uses cache
    """
    mock_cache_instance = mocker.MagicMock()
    mocker.patch('extensions.cache', mock_cache_instance)
    return mock_cache_instance
