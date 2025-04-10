from datetime import datetime, timedelta
import jwt
import pytest
from app import create_app
from extensions import db
from models.user import User

@pytest.fixture
def test_app():
    app = create_app('testing')
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost.localdomain',
        'SECRET_KEY': 'test-secret-key'
    })
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def test_client(test_app):
    return test_app.test_client()

@pytest.fixture
def test_db(test_app):
    return db

@pytest.fixture
def test_user(test_db):
    user = User(
        username='testuser',
        email='test@example.com',
        role='user',
        status='active'
    )
    user.set_password('Password123!')
    test_db.session.add(user)
    test_db.session.commit()
    return user

@pytest.fixture
def auth_token(test_app, test_user):
    token = jwt.encode(
        {
            'user_id': test_user.id,
            'exp': datetime.utcnow() + timedelta(hours=1)
        },
        test_app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return token

@pytest.fixture
def auth_headers(auth_token):
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def mock_data():
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
def admin_user(test_db):
    user = User(
        username='admin',
        email='admin@example.com',
        role='admin',
        status='active'
    )
    user.set_password('AdminPass123!')
    test_db.session.add(user)
    test_db.session.commit()
    return user

@pytest.fixture
def mock_metrics():
    return {
        'cpu_usage': 45.2,
        'memory_usage': 62.8,
        'disk_usage': 78.5
    }

@pytest.fixture
def api_headers(auth_token):
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }
    
@pytest.fixture
def auth_token(test_app, test_user):
    token = jwt.encode(
        {
            'user_id': test_user.id,
            'exp': datetime.utcnow() + timedelta(hours=1)
        },
        test_app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return token

@pytest.fixture
def auth_headers(auth_token):
    return {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def mock_data():
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
def admin_user(test_db):
    user = User(
        username='admin',
        email='admin@example.com',
        role='admin',
        status='active'
    )
    user.set_password('AdminPass123!')
    test_db.session.add(user)
    test_db.session.commit()
    return user

@pytest.fixture
def operator_user(test_db):
    """Create operator user fixture."""
    user = User(
        username='operator',
        email='operator@example.com',
        role='operator',
        status='active'
    )
    user.set_password('OperatorPass123!')
    test_db.session.add(user)
    test_db.session.commit()
    return user

@pytest.fixture 
def mock_metrics():
    """Create mock metrics fixture."""
    return {
        'system': {
            'cpu': {
                'usage': 45.2,
                'cores': 8,
                'load': [2.1, 1.8, 1.6]
            },
            'memory': {
                'total': 16384,
                'used': 10240,
                'free': 6144,
                'usage': 62.8
            },
            'disk': {
                'total': 512000,
                'used': 402000,
                'free': 110000,
                'usage': 78.5
            },
            'network': {
                'bytes_sent': 1024000,
                'bytes_recv': 2048000,
                'packets_sent': 1000,
                'packets_recv': 2000
            }
        },
        'database': {
            'connections': 5,
            'active_queries': 3,
            'slow_queries': 2,
            'cache_hit_ratio': 0.95,
            'queries_per_second': 100,
            'table_sizes': [
                ('users', '1.2 MB'),
                ('sessions', '4.5 MB'),
                ('logs', '10.8 MB')
            ]
        },
        'application': {
            'response_time': 0.125,
            'error_rate': 0.5,
            'uptime': 3600,
            'active_users': 25,
            'requests_per_minute': 350
        },
        'timestamp': datetime.utcnow().isoformat()
    }