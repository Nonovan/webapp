from datetime import datetime
import logging
from typing import Any, Dict
import pytest
from sqlalchemy.orm import Session
from app import create_app
from extensions import db
from models.user import User

# Application Fixtures
@pytest.fixture
def app() -> Any:
    """Create application for testing."""
    test_app = create_app('testing')
    test_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost.localdomain',
        'SECRET_KEY': 'test-key'
    })

    # Setup test logging
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    test_app.logger.handlers = [handler]
    test_app.logger.setLevel(logging.DEBUG)

    return test_app

@pytest.fixture
def client(app) -> Any:
    """Create test client."""
    return app.test_client()

@pytest.fixture
def runner(app) -> Any:
    """Create test CLI runner."""
    return app.test_cli_runner()

# Database Fixtures
@pytest.fixture
def init_database(app) -> Session:
    """Initialize test database."""
    with app.app_context():
        db.create_all()
        yield db
        db.session.remove()
        db.drop_all()

# User Fixtures
@pytest.fixture
def test_user() -> User:
    """Create test user."""
    user = User(
        username='testuser',
        email='test@example.com',
        role='user',
        status='active'
    )
    user.set_password('TestPass123!')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def admin_user() -> User:
    """Create admin user."""
    admin = User(
        username='admin',
        email='admin@example.com',
        role='admin',
        status='active'
    )
    admin.set_password('AdminPass123!')
    db.session.add(admin)
    db.session.commit()
    return admin

@pytest.fixture
def auth_headers(user_fixture) -> Dict[str, str]:
    """Authentication headers for testing."""
    token = user_fixture.generate_token()
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def mock_data() -> Dict[str, Any]:
    """Mock data for testing."""
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
    """Mock database session."""
    session = mocker.MagicMock()
    mocker.patch('extensions.db.session', session)
    return session

@pytest.fixture
def mock_cache(mocker) -> Any:
    """Mock cache."""
    cache = mocker.MagicMock()
    mocker.patch('extensions.cache', cache)
    return cache
