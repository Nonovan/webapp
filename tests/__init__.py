from datetime import datetime
import logging
import pytest
from app import create_app
from extensions import db
from models.user import User

@pytest.fixture
def app():
    """Create application for testing."""
    app = create_app('testing')
    app.config.update({
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
    app.logger.handlers = [handler]
    app.logger.setLevel(logging.DEBUG)

    return app

@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Create test CLI runner."""
    return app.test_cli_runner()

@pytest.fixture
def init_database(app):
    """Initialize test database."""
    with app.app_context():
        db.create_all()
        yield db
        db.session.remove()
        db.drop_all()

@pytest.fixture
def test_user(init_database):
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
def admin_user(init_database):
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
def auth_headers(test_user):
    """Authentication headers for testing."""
    token = test_user.generate_token()
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def mock_data():
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
def mock_db_session(mocker):
    """Mock database session."""
    session = mocker.MagicMock()
    mocker.patch('extensions.db.session', session)
    return session

@pytest.fixture
def mock_cache(mocker):
    """Mock cache."""
    cache = mocker.MagicMock()
    mocker.patch('extensions.cache', cache)
    return cache
