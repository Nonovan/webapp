# Authentication for API Access

This document describes the authentication mechanisms available for the Cloud Infrastructure Platform APIs, including setup, usage patterns, and security recommendations.

## Contents

- Authentication Methods
- Authentication Flow
- Error Responses
- Multi-Factor Authentication
- Rate Limiting
- Request Headers
- Security Best Practices
- Token Management

## Authentication Methods

The API supports the following authentication methods:

### JWT Token Authentication

JSON Web Tokens (JWT) are used as the primary authentication mechanism for the API endpoints. This provides a stateless, secure method for API access with token-based claims for authorization.

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "example_user",
  "password": "secure_password"
}
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "example_user",
    "role": "developer"
  },
  "expires_at": "2023-12-20T15:30:00Z"
}
```

### Multi-Factor Authentication (MFA)

For sensitive operations, the API enforces Multi-Factor Authentication. This requires a secondary verification step after the initial login.

```http
POST /api/auth/mfa/verify
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "code": "123456"
}
```

Response:

```json
{
  "verified": true,
  "message": "MFA verification successful",
  "session_upgraded": true
}
```

### Session-Based Authentication

For web application access, session-based authentication is used alongside JWT tokens:

- Secure cookie storage with appropriate flags
- CSRF token protection for all state-changing requests
- Session regeneration to prevent session fixation attacks
- Device fingerprinting for suspicious access detection

### API Keys

For service-to-service communication, long-lived API keys can be used:

```http
GET /api/resources
X-API-Key: api_key_example_123456789
```

API keys must be created through the administrative interface and can be scoped to specific operations and resources.

## Authentication Flow

1. **Initial Authentication**
   - Client submits credentials via `/api/auth/login` endpoint
   - Server validates credentials and issues JWT token
   - Client stores token securely

2. **Accessing Protected Resources**
   - Client includes token in Authorization header
   - Server validates token signature, expiration, and claims
   - Server authorizes request based on token claims

3. **Token Refreshing**
   - Client monitors token expiration
   - Client requests new token via `/api/auth/extend_session` before expiration
   - Server issues new token with extended validity period

4. **Logout Process**
   - Client calls `/api/auth/logout` to invalidate token
   - Server adds token to blocklist until original expiration time
   - Client discards token

## Error Responses

Authentication errors follow a consistent format:

```json
{
  "error": "Error type identifier",
  "message": "Human-readable error description",
  "status_code": 401
}
```

Common authentication error types:

| Error Type | Description |
|------------|-------------|
| `INVALID_CREDENTIALS` | Username or password is incorrect |
| `EXPIRED_TOKEN` | Authentication token has expired |
| `INSUFFICIENT_PERMISSIONS` | User lacks required permissions |
| `INVALID_TOKEN` | Token signature verification failed |
| `MFA_REQUIRED` | Multi-factor authentication required |
| `RATE_LIMITED` | Too many authentication attempts |

## Multi-Factor Authentication

The API supports two MFA methods:

### Time-Based One-Time Password (TOTP)

TOTP method requires registering an authenticator app:

Setup TOTP:

```http
POST /api/auth/mfa/setup
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "type": "totp"
}
```

Response:

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KGgo...",
  "setup_token": "a1b2c3d4e5f6"
}
```

Then, Verify TOTP setup:

```http
POST /api/auth/mfa/verify
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "code": "123456",
  "setup_token": "a1b2c3d4e5f6"
}
```

### Backup Codes

During MFA setup, backup codes are provided:

```json
{
  "backup_codes": [
    "12345-67890",
    "abcde-fghij",
    "54321-09876",
    "zyxwv-utsrq",
    "98765-43210"
  ]
}
```

These codes should be stored securely and can be used once each for authentication if the primary MFA method is unavailable.

## Rate Limiting

Authentication endpoints implement rate limiting to prevent abuse:

| Endpoint | Rate Limit |
|----------|------------|
| `/api/auth/login` | 10 attempts per minute |
| `/api/auth/register` | 5 attempts per hour |
| `/api/auth/mfa/verify` | 10 attempts per minute |
| `/api/auth/password/reset` | 3 attempts per hour |
| `/api/auth/extend_session` | 30 attempts per minute |

When rate limits are exceeded, the API returns a `429 Too Many Requests` response with a `Retry-After` header indicating the number of seconds to wait before retrying.

## Request Headers

Authentication headers required for API access:

### Bearer Token Authentication

```plaintext
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key Authentication

```plaintext
X-API-Key: your_api_key_here
```

### CSRF Protection (Web Sessions)

For browser-based requests that change state:

```plaintext
X-CSRFToken: csrf_token_from_cookie_or_meta_tag
```

## Security Best Practices

### Client-Side

1. **Secure Storage**
   - Store tokens securely using appropriate mechanisms for your platform
   - For web applications, use HttpOnly cookies with Secure and SameSite flags
   - For mobile applications, use secure key stores
   - Never store tokens in local storage for web applications

2. **Token Management**
   - Monitor token expiration and refresh before expiry
   - Implement proper logout to invalidate tokens
   - Handle token rotation during suspected security incidents

3. **Error Handling**
   - Implement appropriate handling for authentication errors
   - Redirect users to login when authentication fails
   - Implement exponential backoff for repeated failures

### Server-Side

1. **Token Security**
   - Use appropriate JWT signing algorithms (RS256 preferred over HS256 for production)
   - Implement token blocklisting for compromised tokens
   - Keep signing keys secure and implement proper key rotation

2. **Password Security**
   - Implement proper password hashing (bcrypt with appropriate cost factor)
   - Enforce strong password policies
   - Implement account lockout after failed attempts

3. **MFA Implementation**
   - Enforce MFA for administrative and sensitive operations
   - Secure the MFA enrollment process
   - Provide recovery options for lost MFA devices

## Token Management

### Token Structure

JWT tokens contain the following claims:

```json
{
  "sub": "123",                      // User ID
  "iat": 1634567890,                 // Issued At timestamp
  "exp": 1634571490,                 // Expiration timestamp
  "role": "admin",                   // User role
  "permissions": ["user:read"],      // User permissions
  "jti": "a1b2c3d4-e5f6-g7h8-i9j0"  // Unique token ID
}
```

### Token Verification

To verify a token:

```http
POST /api/auth/verify
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Response:

```json
{
  "valid": true,
  "user": {
    "id": 1,
    "username": "example_user",
    "role": "developer"
  },
  "expires_at": "2023-12-20T15:30:00Z"
}
```

### Token Extension

To extend a session before token expiration:

```http
POST /api/auth/extend_session
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2023-12-20T16:00:00Z"
}
```

### Token Invalidation

To explicitly invalidate a token (logout):

```http
POST /api/auth/logout
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "success": true,
  "message": "Successfully logged out"
}
```
