"""
Route testing module for myproject.

This module contains tests for the application's HTTP routes and API endpoints.
It verifies that routes handle requests correctly, enforce proper authentication
and authorization, and return appropriate responses with correct status codes.

The tests cover:
- Authentication routes (login, logout, registration)
- API endpoints and response validation
- Access control and permission enforcement
- Error handling and validation
- Security features like CSRF protection and rate limiting

Each test focuses on a specific aspect of route functionality, using fixtures
to provide consistent test data and authentication context.
"""

from flask import session

class TestAuthRoutes:
    """
    Test suite for authentication routes.

    This class contains tests that verify the functionality of authentication-related
    routes including login, logout, and registration. It checks both successful
    and error cases to ensure the routes handle all scenarios correctly.
    """

    def test_login_basic(self, test_client) -> None:
        """Test basic login without redirect."""
        response = test_client.post('/auth/login', data={
            'username': 'testuser',
            'password': 'Password123!'
        })
        assert response.status_code == 200
        assert b'Login successful' in response.data
        assert 'user_id' in session

    def test_login_with_redirect(self, test_client) -> None:
        """Test login with follow redirects."""
        response = test_client.post('/auth/login', data={
            'username': 'testuser',
            'password': 'Password123!'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Welcome' in response.data
        assert 'user_id' in session

    def test_login_invalid_credentials(self, test_client) -> None:
        """Test login with invalid credentials."""
        response = test_client.post('/auth/login', data={
            'username': 'nonexistent',
            'password': 'wrongpass'
        })
        assert response.status_code == 401
        assert b'Invalid credentials' in response.data
        assert 'user_id' not in session

    def test_protected_route_access(self, test_client) -> None:
        """Test protected route redirection."""
        response = test_client.get('/cloud')
        assert response.status_code == 302
        assert '/auth/login' in response.location

    def test_logout(self, test_client, auth_token) -> None:
        """Test logout and session cleanup."""
        test_client.set_cookie('session', auth_token)
        response = test_client.get('/auth/logout', follow_redirects=True)
        assert response.status_code == 200
        assert 'user_id' not in session

    def test_cloud_access(self, test_client, auth_headers) -> None:
        """Test authenticated cloud dashboard access."""
        response = test_client.get('/cloud', headers=auth_headers)
        assert response.status_code == 200
        assert b'Cloud Dashboard' in response.data

    def test_register(self, test_client) -> None:
        """Test registration with validation."""
        response = test_client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'NewPass123!',
            'confirm': 'NewPass123!'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Registration successful' in response.data

    def test_register_duplicate(self, test_client, test_user) -> None:
        """Test duplicate registration."""
        response = test_client.post('/auth/register', data={
            'username': test_user.username,
            'email': 'new@example.com',
            'password': 'NewPass123!',
            'confirm': 'NewPass123!'
        })
        assert response.status_code == 400
        assert b'Username already exists' in response.data


def test_cloud_resource_operations(test_client, admin_token, mock_cloud_provider) -> None:
    """
    Test cloud resource CRUD operations.
    
    Ensures that cloud resources can be properly created, read, updated, and deleted
    with appropriate permissions and validation.
    """
    # Create a cloud resource
    create_data = {
        'name': 'test-vm',
        'resource_type': 'vm',
        'provider_id': mock_cloud_provider.id,
        'region': 'us-east-1',
        'config': {'instance_type': 't2.micro', 'disk_size_gb': 30}
    }
    
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    
    # Create resource
    response = test_client.post('/api/cloud/resources', json=create_data, headers=headers)
    assert response.status_code == 201
    resource_data = response.get_json()
    resource_id = resource_data['id']
    
    # Get resource
    response = test_client.get(f'/api/cloud/resources/{resource_id}', headers=headers)
    assert response.status_code == 200
    assert response.get_json()['name'] == 'test-vm'
    
    # Update resource
    update_data = {'status': 'running'}
    response = test_client.patch(f'/api/cloud/resources/{resource_id}', 
                                json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.get_json()['status'] == 'running'
    
    # Delete resource
    response = test_client.delete(f'/api/cloud/resources/{resource_id}', headers=headers)
    assert response.status_code == 204

def test_cloud_metrics_collection(test_client, admin_token, mock_cloud_resource) -> None:
    """
    Test cloud metrics collection and retrieval.
    
    Verifies that metrics can be collected, stored, and retrieved for cloud resources,
    and that time-based queries work correctly.
    """
    # Add sample metrics
    metrics_data = [
        {
            'resource_id': mock_cloud_resource.id,
            'provider_id': mock_cloud_resource.provider_id,
            'metric_name': 'cpu_usage',
            'value': 45.5,
            'unit': 'percent',
            'collection_method': 'api'
        },
        {
            'resource_id': mock_cloud_resource.id,
            'provider_id': mock_cloud_resource.provider_id,
            'metric_name': 'memory_usage',
            'value': 2048.0,
            'unit': 'MB',
            'collection_method': 'api'
        }
    ]
    
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    
    # Create metrics in batch
    response = test_client.post('/api/cloud/metrics/batch', json={'metrics': metrics_data}, headers=headers)
    assert response.status_code == 201
    
    # Query metrics for resource
    response = test_client.get(
        f'/api/cloud/metrics?resource_id={mock_cloud_resource.id}&metric_name=cpu_usage', 
        headers=headers
    )
    assert response.status_code == 200
    metrics = response.get_json()
    assert len(metrics) > 0
    assert metrics[0]['metric_name'] == 'cpu_usage'
    
    # Test aggregated metrics
    response = test_client.get(
        f'/api/cloud/metrics/aggregated?resource_id={mock_cloud_resource.id}&metric_name=cpu_usage&interval=1%20hour', 
        headers=headers
    )
    assert response.status_code == 200
    agg_data = response.get_json()
    assert 'avg_value' in agg_data[0]




def test_rate_limit(test_client, test_user) -> None:
    """
    Test rate limiting functionality.

    Verifies that rate limiting correctly restricts access to endpoints
    after the specified number of requests, returning 429 Too Many Requests.

    Args:
        test_client: Flask test client fixture
        test_user: Test user fixture
    """
    endpoints = ['/cloud', '/api/users', '/admin']
    headers = {'Authorization': f'Bearer {test_user.generate_token()}'}

    for endpoint in endpoints:
        # Reset counter
        test_client.get('/reset-ratelimit')

        # Test authenticated requests
        for i in range(31):
            response = test_client.get(endpoint, headers=headers)
            if i < 30:
                assert response.status_code in (200, 403)  # Allow both success and forbidden
            else:
                assert response.status_code == 429
                assert b'Too Many Requests' in response.data

def test_csrf_protection(test_client, test_user) -> None:
    """
    Test CSRF protection for form submissions.

    Verifies that form submissions without valid CSRF tokens are rejected,
    protecting against cross-site request forgery attacks.

    Args:
        test_client: Flask test client fixture
        test_user: Test user fixture
    """
    forms = [
        ('/auth/login', {'username': 'test', 'password': 'test'}),
        ('/auth/register', {'username': 'test', 'email': 'test@test.com'}),
        ('/profile/update', {'name': 'Test User'})
    ]
    headers = {
        'Authorization': f'Bearer {test_user.generate_token()}',
        'X-CSRF-Token': 'invalid'
    }

    for endpoint, data in forms:
        response = test_client.post(endpoint, data=data, headers=headers)
        assert response.status_code == 400
        assert b'CSRF validation failed' in response.data

def test_input_validation(test_client) -> None:
    """
    Test input validation for form submissions.

    Verifies that input validation correctly identifies and rejects
    invalid input data, preventing security issues and data integrity problems.

    Args:
        test_client: Flask test client fixture
    """
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

def test_admin_authorization(test_client, admin_token, user_token) -> None:
    """
    Test role-based access control for admin routes.

    Verifies that admin routes properly restrict access based on user role,
    allowing admin users while rejecting regular users.

    Args:
        test_client: Flask test client fixture
        admin_token: Admin authentication token fixture
        user_token: Regular user authentication token fixture
    """
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

def test_password_reset_flow(test_client) -> None:
    """
    Test complete password reset workflow.

    Verifies the entire password reset process including requesting a reset,
    validating the reset token, and setting a new password.

    Args:
        test_client: Flask test client fixture
    """
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

def test_api_security(test_client, auth_headers) -> None:
    """
    Test API endpoint security.

    Verifies that API endpoints properly enforce authentication,
    rejecting unauthenticated requests while accepting authenticated ones.

    Args:
        test_client: Flask test client fixture
        auth_headers: Authentication headers fixture
    """
    endpoints = ['/api/users', '/api/metrics', '/api/settings']

    # Test without auth
    for endpoint in endpoints:
        response = test_client.get(endpoint)
        assert response.status_code == 401

    # Test with auth
    for endpoint in endpoints:
        response = test_client.get(endpoint, headers=auth_headers)
        assert response.status_code == 200

def test_invalid_input(test_client) -> None:
    """
    Test application handling of malicious input.

    Verifies that the application properly sanitizes and validates input
    data to prevent security vulnerabilities like XSS and injection attacks.

    Args:
        test_client: Flask test client fixture
    """
    response = test_client.post('/register', data={
        'username': '<script>alert("xss")</script>',
        'email': 'invalid-email',
        'password': 'short'
    })
    assert response.status_code == 400
    assert b'Invalid input' in response.data

def test_admin_access(test_client, admin_token) -> None:
    """
    Test admin panel access for admin users.

    Verifies that admin users can successfully access the admin panel
    with proper authentication.

    Args:
        test_client: Flask test client fixture
        admin_token: Admin authentication token fixture
    """
    test_client.set_cookie('session', admin_token)
    response = test_client.get('/admin/users')
    assert response.status_code == 200
    assert b'User Management' in response.data

def test_password_reset(test_client) -> None:
    """
    Test password reset functionality.

    Verifies that the password reset system correctly handles reset requests
    and password changes.

    Args:
        test_client: Flask test client fixture
    """
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

def test_api_endpoints(test_client, auth_headers) -> None:
    """
    Test RESTful API endpoints.

    Verifies that API endpoints correctly handle different HTTP methods
    and return appropriate responses.

    Args:
        test_client: Flask test client fixture
        auth_headers: Authentication headers fixture
    """
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
