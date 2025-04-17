"""
Test fixtures for the cloud infrastructure platform.

This module provides a comprehensive collection of pytest fixtures used across the test suite,
enabling consistent test setup and dependency injection. These fixtures include:

- Application configuration and initialization
- Database setup and teardown
- User authentication with different roles
- JWT token generation for API testing
- Mock data generation for various test scenarios
- Test client configuration
- Cloud provider and resource mocking
- Metrics and monitoring test helpers

The fixtures are designed to be composable, allowing tests to request only the
dependencies they need while maintaining isolation between test cases.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
import os
import random
import uuid
from unittest.mock import MagicMock, patch

import jwt
import pytest
from flask import Flask
from flask.testing import FlaskClient

from app import create_app
from extensions import db, cache, metrics
from models.user import User
from models.cloud_resource import CloudResource
from models.cloud_provider import CloudProvider
from models.cloud_metric import CloudMetric
from models.cloud_alert import CloudAlert

@pytest.fixture
def test_app() -> Flask:
    """
    Create test application instance.

    Returns:
        Flask application configured for testing with an in-memory SQLite database
        and test-specific configuration settings.
    """
    app = create_app('testing')
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost.localdomain',
        'SECRET_KEY': 'test-secret-key',
        'JWT_SECRET_KEY': 'test-jwt-key',
        'CACHE_TYPE': 'simple',
        'METRICS_ENABLED': False,
        'CLOUD_PROVIDERS_ENABLED': True,
        'CLOUD_METRICS_RETENTION_DAYS': 7
    })

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def test_client(app_instance) -> Any:
    """
    Create Flask test client.

    Args:
        app_instance: Flask application fixture

    Returns:
        Flask test client for making requests in tests
    """
    return app_instance.test_client()

@pytest.fixture
def test_db() -> Any:
    """
    Provide a database instance for testing.

    Returns:
        SQLAlchemy database instance ready for testing
    """
    return db

@pytest.fixture
def test_user(database) -> Any:
    """
    Create a standard test user in the database.

    Args:
        database: SQLAlchemy database instance

    Returns:
        User: A user instance with 'user' role
    """
    # Create user based on actual User model parameters
    user = User()
    user.username = 'testuser'
    user.email = 'test@example.com'
    user.role = 'user'
    user.status = 'active'
    user.set_password('Password123!')
    database.session.add(user)
    database.session.commit()
    return user

@pytest.fixture
def auth_token_with_role(app_instance, user_fixture) -> Any:
    """
    Generate authentication token with user role information.

    Args:
        app_instance: Flask application fixture
        user_fixture: User model instance

    Returns:
        str: JWT token with user ID and role claims
    """
    token = jwt.encode(
        {
            'user_id': user_fixture.id,
            'role': user_fixture.role,
            'exp': datetime.utcnow() + timedelta(hours=1)
        },
        app_instance.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
    return token

@pytest.fixture
def auth_headers_with_token(auth_token) -> dict:
    """
    Create authentication headers with bearer token.

    Args:
        auth_token: JWT authentication token

    Returns:
        dict: HTTP headers dictionary with Authorization and Content-Type
    """
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def basic_mock_data() -> dict:
    """
    Provide basic mock data for testing.

    Returns:
        dict: Sample data structure with users and system metrics
    """
    return {
        'users': [
            {'username': 'user1', 'email': 'user1@example.com'},
            {'username': 'user2', 'email': 'user2@example.com'}
        ],
        'metrics': {
            'cpu_usage': 45.2,
            'memory_usage': 62.8,
            'disk_usage': 78.5
        }
    }

@pytest.fixture
def admin_user_with_database(database) -> User:
    """
    Create an admin user with database access for testing.

    Args:
        database: SQLAlchemy database instance

    Returns:
        User: User instance with 'admin' role
    """
    user = User()
    user.username = 'admin'
    user.email = 'admin@example.com'
    user.role = 'admin'
    user.status = 'active'
    user.set_password('AdminPass123!')
    database.session.add(user)
    database.session.commit()
    return user

@pytest.fixture
def mock_metrics() -> dict:
    """
    Provide mock system metrics data.

    Returns:
        dict: Sample metrics data with CPU, memory and disk usage values
    """
    return {
        'cpu_usage': 45.2,
        'memory_usage': 62.8,
        'disk_usage': 78.5
    }

@pytest.fixture
def api_headers(auth_token) -> dict:
    """
    Create headers for API requests.

    Args:
        auth_token: JWT authentication token

    Returns:
        dict: HTTP headers for authenticated API requests
    """
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def auth_token_without_role(app_instance, user_fixture) -> Any:
    """
    Generate authentication token without role information.

    Creates a token with only user ID for testing role-specific access controls.

    Args:
        app_instance: Flask application fixture
        user_fixture: User model instance

    Returns:
        str: JWT token with user ID but no role claim
    """
    token = jwt.encode(
        {
            'user_id': user_fixture.id,
            'exp': datetime.utcnow() + timedelta(hours=1)
        },
        app_instance.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return token

@pytest.fixture
def auth_headers(auth_token) -> dict:
    """
    Create standard authentication headers.

    Args:
        auth_token: JWT authentication token

    Returns:
        dict: HTTP headers with Authorization and Content-Type
    """
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def mock_data() -> dict:
    """
    Provide comprehensive mock data for testing.

    Returns:
        dict: Detailed mock data structure with users, system metrics, and database information
    """
    return {
        'users': [
            {'username': 'user1', 'email': 'user1@example.com', 'role': 'user'},
            {'username': 'user2', 'email': 'user2@example.com', 'role': 'operator'},
            {'username': 'admin', 'email': 'admin@example.com', 'role': 'admin'}
        ],
        'system': {
            'cpu': {
                'usage': 45.2,
                'cores': 8,
                'load': [2.1, 1.8, 1.6]
            },
            'memory': {
                'total': 16384,
                'used': 10240,
                'free': 6144
            },
            'disk': {
                'total': 512000,
                'used': 402000,
                'free': 110000
            }
        },
        'database': {
            'connections': 5,
            'active_queries': 3,
            'slow_queries': 1,
            'cache_hits': 95.5
        }
    }

@pytest.fixture
def mock_system_metrics() -> Dict[str, Any]:
    """
    Provide detailed system metrics test data.

    Returns:
        Dict[str, Any]: System metrics including CPU, memory, and disk information
    """
    return {
        'cpu': {
            'usage': 45.2,
            'cores': 8,
            'load': [2.1, 1.8, 1.6]
        },
        'memory': {
            'total': 16384,
            'used': 10240,
            'free': 6144
        },
        'disk': {
            'total': 512000,
            'used': 402000,
            'free': 110000
        }
    }

@pytest.fixture
def mock_db_metrics() -> Dict[str, Any]:
    """
    Provide database metrics test data.

    Returns:
        Dict[str, Any]: Database metrics including connection counts and performance statistics
    """
    return {
        'connections': 5,
        'active_queries': 3,
        'slow_queries': 1,
        'cache_hits': 95.5
    }

@pytest.fixture
def admin_user(database) -> User:
    """
    Create admin user fixture.

    Args:
        database: SQLAlchemy database instance

    Returns:
        User: User instance with 'admin' role
    """
    user = User()
    user.username = 'admin'
    user.email = 'admin@example.com'
    user.role = 'admin'
    user.status = 'active'
    user.set_password('AdminPass123!')
    database.session.add(user)
    database.session.commit()
    return user

@pytest.fixture
def operator_user(database) -> User:
    """
    Create operator user fixture.

    Args:
        database: SQLAlchemy database instance

    Returns:
        User: User instance with 'operator' role for testing operator-specific functionality
    """
    user = User()
    user.username = 'operator'
    user.email = 'operator@example.com'
    user.role = 'operator'
    user.status = 'active'
    user.set_password('OperatorPass123!')
    database.session.add(user)
    database.session.commit()
    return user
