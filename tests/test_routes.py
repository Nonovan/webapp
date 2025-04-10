import pytest
from Flask import session

# Auth Route Tests
def test_login_route(test_client):
    """Test login functionality."""
    response = test_client.post('/auth/login', data={
        'username': 'testuser',
        'password': 'Password123!'
    })
    assert response.status_code == 200
    assert b'Login successful' in response.data

def test_protected_route_redirect(test_client):
    response = test_client.get('/cloud')
    assert response.status_code == 302
    assert '/login' in response.location

def test_successful_login(test_client, test_user):
    response = test_client.post('/login', data={
        'username': 'testuser',
        'password': 'Password123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Welcome' in response.data
    assert 'user_id' in session

def test_invalid_login(test_client):
    response = test_client.post('/login', data={
        'username': 'nonexistent',
        'password': 'wrongpass'
    })
    assert response.status_code == 200
    assert b'Invalid credentials' in response.data

def test_logout(test_client, auth_token):
    test_client.set_cookie('session', auth_token)
    response = test_client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert 'user_id' not in session

def test_cloud_access_authenticated(test_client, auth_headers):
    response = test_client.get('/cloud', headers=auth_headers)
    assert response.status_code == 200
    assert b'Cloud Dashboard' in response.data

def test_register_route(test_client):
    """Test registration with valid data."""
    response = test_client.post('/auth/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'NewPass123!',
        'confirm': 'NewPass123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Registration successful' in response.data

def test_rate_limit(test_client):
    """Test rate limiting."""
    # Test multiple endpoints
    endpoints = ['/cloud', '/api/users', '/admin']

    for endpoint in endpoints:
        # Reset counter between endpoints
        test_client.get('/reset-ratelimit')

        # Test limit
        for _ in range(31):  # Limit is 30/minute
            response = test_client.get(endpoint)
        assert response.status_code == 429
        assert b'Too Many Requests' in response.data

def test_csrf_protection(test_client):
    """Test CSRF protection on forms."""
    forms = [
        ('/auth/login', {'username': 'test', 'password': 'test'}),
        ('/auth/register', {'username': 'test', 'email': 'test@test.com'}),
        ('/profile/update', {'name': 'Test User'})
    ]

    for endpoint, data in forms:
        response = test_client.post(endpoint,
            data=data,
            headers={'X-CSRF-Token': 'invalid'}
        )
        assert response.status_code == 400
        assert b'CSRF validation failed' in response.data

def test_input_validation(test_client):
    """Test input sanitization and validation."""
    invalid_inputs = [
        {'username': '<script>alert("xss")</script>'},
        {'email': 'invalid-email'},
        {'password': 'short'},
        {'name': '' * 300}  # Too long
    ]

    for data in invalid_inputs:
        response = test_client.post('/register', data=data)
        assert response.status_code == 400
        assert b'Invalid input' in response.data

def test_admin_authorization(test_client, admin_token, user_token):
    """Test admin access control."""
    admin_endpoints = [
        '/admin/users',
        '/admin/metrics',
        '/admin/settings'
    ]

    # Test with admin token
    for endpoint in admin_endpoints:
        response = test_client.get(endpoint, headers={'Authorization': f'Bearer {admin_token}'})
        assert response.status_code == 200

    # Test with regular user token
    for endpoint in admin_endpoints:
        response = test_client.get(endpoint, headers={'Authorization': f'Bearer {user_token}'})
        assert response.status_code == 403

def test_password_reset_flow(test_client):
    """Test complete password reset flow."""
    # Request reset
    response = test_client.post('/auth/reset-password', data={
        'email': 'test@example.com'
    })
    assert response.status_code == 200
    assert b'Reset instructions sent' in response.data

    # Invalid token
    response = test_client.post('/auth/reset-password/invalid', data={
        'password': 'NewPass123!',
        'confirm': 'NewPass123!'
    })
    assert response.status_code == 400

    # Valid token
    response = test_client.post('/auth/reset-password/valid-token', data={
        'password': 'NewPass123!',
        'confirm': 'NewPass123!'
    })
    assert response.status_code == 200
    assert b'Password updated' in response.data

def test_api_security(test_client, auth_headers):
    """Test API security measures."""
    endpoints = ['/api/users', '/api/metrics', '/api/settings']

    # Test without auth
    for endpoint in endpoints:
        response = test_client.get(endpoint)
        assert response.status_code == 401

    # Test with auth
    for endpoint in endpoints:
        response = test_client.get(endpoint, headers=auth_headers)
        assert response.status_code == 200

def test_invalid_input(test_client):
    response = test_client.post('/register', data={
        'username': '<script>alert("xss")</script>',
        'email': 'invalid-email',
        'password': 'short'
    })
    assert response.status_code == 400
    assert b'Invalid input' in response.data

def test_admin_access(test_client, admin_token):
    test_client.set_cookie('session', admin_token)
    response = test_client.get('/admin/users')
    assert response.status_code == 200
    assert b'User Management' in response.data

def test_password_reset(test_client):
    # Request reset
    response = test_client.post('/reset-password', data={
        'email': 'test@example.com'
    })
    assert response.status_code == 200
    assert b'Reset instructions sent' in response.data

    # Confirm reset
    response = test_client.post('/reset-password/token123', data={
        'password': 'NewPass123!',
        'confirm': 'NewPass123!'
    })
    assert response.status_code == 200
    assert b'Password updated' in response.data

def test_api_endpoints(test_client, auth_headers):
    # Test GET
    response = test_client.get('/api/users', headers=auth_headers)
    assert response.status_code == 200
    assert response.json['users'] is not None

    # Test POST
    response = test_client.post('/api/users',
        headers=auth_headers,
        json={'username': 'apiuser', 'email': 'api@example.com'}
    )
    assert response.status_code == 201
