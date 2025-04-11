"""
User model testing module for myproject.

This module contains tests for the User model, verifying its functionality for
authentication, data validation, and user management operations. The tests ensure
that the model handles user data correctly, enforces security rules, and maintains
data integrity.

Areas tested include:
- Password hashing and verification
- User creation and database interactions
- Field validation (email, username, etc.)
- Login tracking and authentication
- Token generation and validation
- Role-based permissions

Each test focuses on specific functionality to provide comprehensive coverage
of the User model's capabilities and constraints.
"""

from datetime import datetime
import time
import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from models import User

class TestUser:
    """
    Test suite for User model functionality.

    This class contains tests for core User model functionality including
    authentication, data validation, and database operations.
    """

    def test_password_hashing(self) -> None:
        """
        Test password hashing and verification.

        Verifies that:
        - Passwords are properly hashed (not stored in plaintext)
        - Password verification works for correct passwords
        - Password verification fails for incorrect passwords
        """
        user = User(email='test@example.com')
        user.set_password('SecurePass123!')

        assert user.password != 'SecurePass123!'
        assert user.check_password('SecurePass123!')
        assert not user.check_password('wrongpass')

    def test_user_creation(self, test_db: Session) -> None:
        """
        Test user creation with required fields.

        Verifies that a user can be created with all required fields
        and that database insertion works correctly.

        Args:
            test_db: Database session fixture
        """
        user = User(
            username='test',
            email='test@example.com',
            status='active',
            role='user'
        )

        test_db.session.add(user)
        test_db.session.commit()

        assert user.id is not None
        assert user.username == 'test'
        assert user.email == 'test@example.com'
        assert user.status == 'active'
        assert user.role == 'user'
        assert isinstance(user.created_at, datetime)

    def test_username_unique(self, test_db: Session) -> None:
        """
        Test username uniqueness constraint.

        Verifies that the database enforces username uniqueness by
        raising an exception when attempting to create a duplicate.

        Args:
            test_db: Database session fixture
        """
        user1 = User(
            username='test',
            email='test1@example.com'
        )
        test_db.session.add(user1)
        test_db.session.commit()

        user2 = User(
            username='test',
            email='test2@example.com'
        )
        with pytest.raises(IntegrityError):
            test_db.session.add(user2)
            test_db.session.commit()

    def test_invalid_email(self, test_db) -> None:
        """
        Test email validation.

        Verifies that the model rejects invalid email formats, enforcing
        email validity rules.

        Args:
            test_db: Database session fixture
        """
        invalid_emails = [
            'invalid',
            'user@',
            '@domain.com',
            'user@.com'
        ]
        for email in invalid_emails:
            u = User()
            u.username = 'test'
            u.email = email
            with pytest.raises(ValueError, match='Invalid email format'):
                test_db.session.add(u)
                test_db.session.commit()

    def test_role_default(self, test_db) -> None:
        """
        Test default role assignment.

        Verifies that users are assigned the default 'user' role when
        no explicit role is specified.

        Args:
            test_db: Database session fixture
        """
        u = User()
        u.username = 'test'
        test_db.session.add(u)
        test_db.session.commit()
        assert u.role == 'user'

def test_status_transitions(test_db) -> None:
    """
    Test user status state transitions.

    Verifies that a user's status can be updated through the defined
    state transitions and that these changes persist to the database.

    Args:
        test_db: Database session fixture
    """
    u = User(username='test')
    u.email = 'test@example.com'
    u.status = 'pending'
    test_db.session.add(u)
    test_db.session.commit()
    assert u.status == 'pending'

    u.status = 'active'
    test_db.session.commit()
    assert u.status == 'active'

    u.status = 'inactive'
    test_db.session.commit()
    assert u.status == 'inactive'

    u.status = 'suspended'
    test_db.session.commit()
    assert u.status == 'suspended'

def test_login_tracking(test_db) -> None:
    """
    Test login attempt tracking.

    Verifies that the User model correctly tracks successful and failed
    login attempts with appropriate timestamps and counters.

    Args:
        test_db: Database session fixture
    """
    u = User()
    u.username = 'test'
    u.email = 'test@example.com'
    test_db.session.add(u)
    test_db.session.commit()

    # Successful login
    u.update_last_login()
    assert u.last_login is not None
    assert u.login_count == 1
    assert u.failed_login_count == 0

    # Failed login
    # Using record_login_failure method instead of record_failed_login_attempt
    u.record_login_failure()
    assert u.failed_login_count == 1
    assert u.last_failed_login is not None

def test_token_generation(test_db) -> None:
    """
    Test token generation and validation.

    Verifies that authentication tokens can be generated for users
    and that these tokens can be verified to retrieve the user.

    Args:
        test_db: Database session fixture
    """
    u = User()
    u.username = 'test'
    u.role = 'user'
    test_db.session.add(u)
    test_db.session.commit()

    token = u.generate_token()
    assert token is not None

    decoded = User.verify_token(token)
    assert decoded is not None, "Token verification failed"
    assert decoded.id == u.id
    assert decoded.role == u.role

def test_token_expiration(test_db) -> None:
    """
    Test token expiration.

    Verifies that authentication tokens properly expire after the
    specified time and cannot be used after expiration.

    Args:
        test_db: Database session fixture
    """
    u = User()
    u.username = 'test'
    test_db.session.add(u)
    test_db.session.commit()

    token = u.generate_token(expires_in=1)
    time.sleep(2)
    assert User.verify_token(token) is None

def test_password_validation() -> None:
    """
    Test password strength requirements.

    Verifies that the password validation enforces strength requirements
    including length, character types, and complexity.
    """
    u = User(email='test@example.com')

    with pytest.raises(ValueError):
        u.set_password('short')  # Too short

    with pytest.raises(ValueError):
        u.set_password('nocapitals123!')  # No capitals

    with pytest.raises(ValueError):
        u.set_password('NOCAPS123!')  # No lowercase

    with pytest.raises(ValueError):
        u.set_password('NoSpecials123')  # No special chars

def test_profile_updates(test_db) -> None:
    """
    Test user profile updates.

    Verifies that user profile attributes can be updated and that
    these changes persist correctly to the database.

    Args:
        test_db: Database session fixture
    """
    u = User()
    u.username = 'test'
    u.email = 'test@example.com'
    test_db.session.add(u)
    test_db.session.commit()

    # Set profile attributes directly
    u.first_name = 'Test'
    u.last_name = 'User'
    u.bio = 'Test bio'
    u.avatar_url = 'https://example.com/avatar.jpg'
    test_db.session.commit()

    # Verify profile attributes were set correctly
    assert u.first_name == 'Test'
    assert u.last_name == 'User'
    assert u.bio == 'Test bio'
    assert u.avatar_url == 'https://example.com/avatar.jpg'

def test_role_management(test_db) -> None:
    """
    Test role assignment and verification.

    Verifies that roles can be assigned to users and that role-based
    permission checks function correctly.

    Args:
        test_db: Database session fixture
    """
    # Admin user
    admin = User()
    admin.username = 'admin'
    admin.email = 'admin@example.com'
    admin.role = 'admin'
    test_db.session.add(admin)
    test_db.session.commit()

    assert admin.role == 'admin'
    assert admin.is_admin is True

    # Regular user
    user = User()
    user.username = 'user'
    user.email = 'user@example.com'
    user.role = 'user'
    test_db.session.add(user)
    test_db.session.commit()

    assert user.role == 'user'
    assert user.is_admin is False
    assert user.role != 'admin'

def test_user_search(test_db) -> None:
    """
    Test user search functionality.

    Verifies that users can be found by search criteria such as username
    prefixes, demonstrating the model's query capabilities.

    Args:
        test_db: Database session fixture
    """
    # Create test users
    users = [
        User(email='test1@example.com'),
        User(email='test2@example.com'),
        User(email='other@example.com')
    ]

    # Set usernames after creation
    users[0].username = 'test1'
    users[1].username = 'test2'
    users[2].username = 'other'

    for u in users:
        test_db.session.add(u)
    test_db.session.commit()

    # Test search
    results = test_db.session.query(User).filter(User.username.like('test%')).all()
    assert len(results) == 2
    assert all(u.username.startswith('test') for u in results)


def test_last_login_update(test_db: Session) -> None:
    """
    Test user login timestamp tracking.

    Verifies that the last login timestamp is correctly updated when
    a user logs in and that the login count is properly incremented.

    Args:
        test_db: Database session fixture
    """
    # Create test user
    u = User()
    u.username = 'test'
    u.email = 'test@example.com'
    test_db.add(u)
    test_db.commit()

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
    test_db.refresh(u)
    assert u.last_login is not None
    assert u.login_count == 2
