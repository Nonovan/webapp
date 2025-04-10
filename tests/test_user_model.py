import pytest
from app import User
from sqlalchemy.exc import IntegrityError

def test_password_hashing(test_db):
    u = User(username='test')
    u.set_password('mypassword')
    assert u.password != 'mypassword'
    assert u.check_password('mypassword')
    assert not u.check_password('wrongpass')

def test_user_creation(test_db):
    u = User(username='test', status='approved')
    test_db.session.add(u)
    test_db.session.commit()
    assert u.id is not None
    assert u.username == 'test'
    assert u.status == 'approved'

def test_username_unique(test_db):
    u1 = User(username='test', email='test1@example.com')
    u2 = User(username='test', email='test2@example.com')
    test_db.session.add(u1)
    test_db.session.commit()
    with pytest.raises(IntegrityError):
        test_db.session.add(u2)
        test_db.session.commit()

def test_invalid_email(test_db):
    u = User(username='test', email='invalid')
    with pytest.raises(ValueError):
        test_db.session.add(u)
        test_db.session.commit()

def test_role_default(test_db):
    """Test default role assignment."""
    u = User(username='test')
    test_db.session.add(u)
    test_db.session.commit()
    assert u.role == 'user'

def test_status_transitions(test_db):
    """Test user status state transitions."""
    u = User(username='test')
    assert u.status == User.STATUS_PENDING

    u.activate()
    assert u.status == User.STATUS_ACTIVE

    u.deactivate()
    assert u.status == User.STATUS_INACTIVE

    u.suspend()
    assert u.status == User.STATUS_SUSPENDED

def test_token_generation_and_verification(test_app, test_db):
    """Test JWT token generation and verification."""
    u = User(username='test')
    test_db.session.add(u)
    test_db.session.commit()

    token = u.generate_token()
    assert token is not None

    verified_user = User.verify_token(token)
    assert verified_user.id == u.id
    assert verified_user.role == u.role

def test_token_expiration(test_app, test_db):
    """Test token expiration."""
    u = User(username='test')
    test_db.session.add(u)
    test_db.session.commit()

    token = u.generate_token(expires_in=1)
    import time
    time.sleep(2)
    assert User.verify_token(token) is None

def test_profile_updates(test_db):
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

def test_role_management(test_db):
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

def test_user_search(test_db):
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

def test_last_login_update(test_db):
    u = User(username='test')
    test_db.session.add(u)
    test_db.session.commit()
    old_login = u.last_login
    u.update_last_login()
    assert u.last_login > old_login
