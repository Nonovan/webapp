from typing import Dict, Any
from datetime import datetime, timedelta
import jwt
import pytest
from app import create_app
from extensions import db
from models.user import User

@pytest.fixture
def test_app():
    """Create test application instance."""
    app = create_app('testing')
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost.localdomain',
        'SECRET_KEY': 'test-secret-key',
        'JWT_SECRET_KEY': 'test-jwt-key',
        'CACHE_TYPE': 'simple'
    })
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def test_client(app_instance):
    """Create test client."""
    return app_instance.test_client()

@pytest.fixture
def test_db():
    """Create test database."""
    return db

@pytest.fixture
def test_user(database):
    """Create test user."""
    user = User(
        username='testuser',
        email='test@example.com',
        role='user',
        status='active'
    )
    user.set_password('Password123!')
    database.session.add(user)
    database.session.commit()
    return user

@pytest.fixture
def auth_token_with_role(app_instance, user_fixture):
    """Generate authentication token with role."""
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
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def basic_mock_data() -> dict:
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
    user = User(
        username='admin',
        email='admin@example.com',
        role='admin',
        status='active'
    )
    user.set_password('AdminPass123!')
    database.session.add(user)
    database.session.commit()
    return user

@pytest.fixture
def mock_metrics() -> dict:
    return {
        'cpu_usage': 45.2,
        'memory_usage': 62.8,
        'disk_usage': 78.5
    }

@pytest.fixture
def api_headers(auth_token) -> dict:
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }
    
@pytest.fixture
def auth_token_without_role(app_instance, user_fixture):
    """Generate authentication token without role."""
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
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def mock_data() -> dict:
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
    """System metrics test data."""
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
    """Database metrics test data."""
    return {
        'connections': 5,
        'active_queries': 3,
        'slow_queries': 1,
        'cache_hits': 95.5
    }

@pytest.fixture
def admin_user(database) -> User:
    """Create admin user fixture."""
    user = User(
        username='admin',
        email='admin@example.com',
        role='admin',
        status='active'
    )
    user.set_password('AdminPass123!')
    database.session.add(user)
    database.session.commit()
    return user

@pytest.fixture
def operator_user(database) -> User:
    """Create operator user fixture."""
    user = User(
        username='operator',
        email='operator@example.com',
        role='operator', 
        status='active'
    )
    user.set_password('OperatorPass123!')
    database.session.add(user)
    database.session.commit()
    return user
