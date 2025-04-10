import time
import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from models import User

class TestUser:
    """Test suite for User model."""

    def test_password_hashing(self) -> None:
        """Test password hashing and verification."""
        u = User(username='test')
        u.set_password('SecurePass123!')
        assert u.password != 'SecurePass123!'
        assert u.check_password('SecurePass123!')
        assert not u.check_password('wrongpass')

    def test_user_creation(self, test_db) -> None:
        """Test user creation with required fields."""
        u = User(
            username='test',
            email='test@example.com',
            status='active',
            role='user'
        )
        test_db.session.add(u)
        test_db.session.commit()

        assert u.id is not None
        assert u.username == 'test'
        assert u.status == 'active'
        assert u.role == 'user'
        assert u.created_at is not None

    def test_username_unique(self, test_db) -> None:
        """Test username uniqueness constraint."""
        u1 = User(
            username='test',
            email='test1@example.com'
        )
        u2 = User(
            username='test',
            email='test2@example.com'
        )
        test_db.session.add(u1)
        test_db.session.commit()

        with pytest.raises(IntegrityError):
            test_db.session.add(u2)
            test_db.session.commit()

    def test_invalid_email(self, test_db) -> None:
        """Test email validation."""
        invalid_emails = [
            'invalid',
            'user@',
            '@domain.com',
            'user@.com'
        ]
        for email in invalid_emails:
            u = User(username='test', email=email)
            with pytest.raises(ValueError, match='Invalid email format'):
                test_db.session.add(u)
                test_db.session.commit()

    def test_role_default(self, test_db) -> None:
        """Test default role assignment."""
        u = User(username='test')
        test_db.session.add(u)
        test_db.session.commit()
        assert u.role == 'user'

def test_status_transitions():
    """Test user status state transitions."""
    u = User(username='test')
    assert u.status == User.STATUS_PENDING

    u.activate()
    assert u.status == User.STATUS_ACTIVE

    u.deactivate()
    assert u.status == User.STATUS_INACTIVE

    u.suspend()
    assert u.status == User.STATUS_SUSPENDED

def test_login_tracking(test_db) -> None:
    """Test login attempt tracking."""
    u = User(username='test')
    test_db.session.add(u)
    test_db.session.commit()

    # Successful login
    u.record_login()
    assert u.last_login is not None
    assert u.login_count == 1
    assert u.failed_login_count == 0

    # Failed login
    u.record_failed_login()
    assert u.failed_login_count == 1
    assert u.last_failed_login is not None

def test_token_generation(test_db) -> None:
    """Test token generation and validation."""
    u = User(username='test', role='user')
    test_db.session.add(u)
    test_db.session.commit()

    token = u.generate_token()
    assert token is not None

    decoded = User.verify_token(token)
    assert decoded is not None, "Token verification failed"
    assert decoded['user_id'] == u.id
    assert decoded['role'] == u.role

def test_token_expiration(test_db) -> None:
    """Test token expiration."""
    u = User(username='test')
    test_db.session.add(u)
    test_db.session.commit()

    token = u.generate_token(expires_in=1)
    time.sleep(2)
    assert User.verify_token(token) is None

def test_password_validation() -> None:
    """Test password strength requirements."""
    u = User(username='test')

    with pytest.raises(ValueError):
        u.set_password('short')  # Too short

    with pytest.raises(ValueError):
        u.set_password('nocapitals123!')  # No capitals

    with pytest.raises(ValueError):
        u.set_password('NOCAPS123!')  # No lowercase

    with pytest.raises(ValueError):
        u.set_password('NoSpecials123')  # No special chars

def test_profile_updates(test_db) -> None:
    """Test user profile updates."""
    u = User(username='test', email='test@example.com')
    test_db.session.add(u)
    test_db.session.commit()

    profile_data = {
        'first_name': 'Test',
        'last_name': 'User',
        'bio': 'Test bio',
        'avatar_url': 'https://example.com/avatar.jpg'
    }
    u.update_profile(**profile_data)

    for key, value in profile_data.items():
        assert getattr(u, key) == value

def test_role_management() -> None:
    """Test role assignment and verification."""
    # Admin user
    admin = User(username='admin', role='admin')
    assert admin.is_admin
    assert admin.has_role('admin')

    # Regular user
    user = User(username='user', role='user')
    assert not user.is_admin
    assert user.has_role('user')
    assert not user.has_role('admin')

def test_user_search() -> None:
    """Test user search functionality."""
    # Create test users
    users = [
        User(username='test1', email='test1@example.com'),
        User(username='test2', email='test2@example.com'),
        User(username='other', email='other@example.com')
    ]
    for u in users:
        u.save()

    # Test search
    results = User.search('test')
    assert len(results) == 2
    assert all(u.username.startswith('test') for u in results)


def test_last_login_update(test_db: Session) -> None:
    """Test user login timestamp tracking."""
    # Create test user
    u = User(username='test', email='test@example.com')
    test_db.session.add(u)
    test_db.session.commit()

    # Initial login should be None
    assert u.last_login is None
    assert u.login_count == 0

    # First login
    u.update_last_login()
    first_login = u.last_login
    assert first_login is not None
    assert u.login_count == 1

    # Wait briefly to ensure timestamp changes
    time.sleep(0.1)

    # Subsequent login
    u.update_last_login()
    assert u.last_login > first_login
    assert u.login_count == 2

    # Verify stored in database
    test_db.session.refresh(u)
    assert u.last_login is not None
    assert u.login_count == 2
