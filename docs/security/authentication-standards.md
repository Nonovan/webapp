# Authentication Standards

This document defines the authentication standards for the Cloud Infrastructure Platform, covering the policies, protocols, and technologies used to verify identity across all systems and services.

## Contents

- Authentication Factors
- Authentication Flows
- Best Practices
- Compliance Requirements
- Configuration Guidelines
- Implementation Guidelines
- Key Components
- Monitoring and Auditing
- OAuth and OIDC Standards
- Overview
- Password Standards
- Related Documentation
- SAML Standards
- Session Management
- Token Standards
- Version History

## Overview

The authentication standards provide a comprehensive framework for securely verifying the identity of users and systems accessing the Cloud Infrastructure Platform. These standards implement defense-in-depth principles with multiple verification mechanisms, contextual authentication, and consistent security controls across all authentication interfaces.

## Key Components

- **Authentication Factors**: Multi-factor authentication framework
  - Knowledge factors (passwords, PINs)
  - Ownership factors (hardware tokens, mobile devices)
  - Biometric factors (when applicable)
  - Location and context factors

- **Authentication Methods**: Supported authentication technologies
  - Certificate-based authentication
  - Federation with identity providers
  - Password-based authentication
  - Token-based authentication

- **Identity Verification**: Methods to confirm user identity
  - Account recovery procedures
  - Identity proofing requirements
  - Multi-factor enrollment validation
  - Risk-based authentication triggers

- **Security Controls**: Authentication security measures
  - Brute force protections
  - Credential encryption standards
  - Rate limiting and lockout policies
  - Session security controls

## Authentication Factors

### Knowledge Factors

- **Passwords**: Primary knowledge factor
  - Complex password requirements (see Password Standards section)
  - Regular rotation requirements
  - Password history limitations
  - Password strength enforcement

- **Security Questions**: Limited use as secondary factor
  - Minimum of three questions required
  - Custom questions encouraged
  - Answers stored with secure hashing
  - Limited to account recovery scenarios

### Ownership Factors (Something You Have)

- **Mobile Authenticator Apps**: Preferred second factor
  - TOTP implementation per RFC 6238
  - 30-second rotation interval
  - Secure enrollment workflow
  - Backup code generation

- **Hardware Security Keys**: Highest security level
  - FIDO2/WebAuthn compliant
  - Support for U2F legacy devices
  - Physical presence verification
  - Multiple keys per account supported

- **Email/SMS**: Restricted use cases only
  - Limited to account recovery
  - Not considered secure for primary MFA
  - Rate limited to prevent abuse
  - Requires pre-registration

### Biometric Factors (Something You Are)

- **Supported Options**: Limited to endpoint authentication
  - Fingerprint authentication (when available)
  - Facial recognition (when available)
  - Voice authentication (special cases only)

- **Implementation Requirements**:
  - Local device verification only
  - Biometric data never transmitted
  - Fallback mechanisms required
  - Compliance with privacy regulations

### Location and Context Factors

- **Location Verification**:
  - IP geolocation validation
  - GPS verification for high-security scenarios
  - Known locations tracking
  - Anomalous location alerting

- **Device Recognition**:
  - Device fingerprinting
  - Trusted device registration
  - Anomaly detection for new devices
  - Device health attestation for sensitive operations

## Password Standards

### Complexity Requirements

- Minimum length: 12 characters
- Must include characters from at least three of the following categories:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Special characters (!@#$%^&*()-_=+{};:,<.>)
- Must not contain dictionary words
- Must not contain username or email address
- Must not match common password patterns
- Must not match previously used passwords (last 24)

### Password Lifecycle

- Maximum password age: 90 days
- Minimum password age: 1 day (prevents immediate reuse)
- Password history: 24 passwords remembered
- Early warning for expiration: 14 days before required change

### Password Storage

- Passwords must be hashed using approved algorithms:
  - Argon2id (preferred)
  - bcrypt (minimum cost factor 12)
  - PBKDF2 with HMAC-SHA256 (minimum 310,000 iterations)
- Plain text storage prohibited
- Reversible encryption prohibited
- Salt requirements:
  - Unique per user
  - Random, cryptographically secure
  - Minimum 32 bytes in length

### Account Lockout Policy

- Account lockout threshold: 5 failed attempts
- Lockout duration: 30 minutes (automatic unlock)
- Progressive lockout enforcement:
  - First lockout: 30 minutes
  - Second lockout: 1 hour
  - Third+ lockout: 4 hours or manual unlock
- Admin accounts require manual unlock after third failure

### Password Recovery

- Secure self-service recovery options:
  - Email reset link (time limited to 15 minutes)
  - SMS verification code (where applicable)
  - Recovery through secondary authentication factor
- No password hints or security questions for high-privilege accounts
- Administrative reset requires identity verification
- All recovery events are fully logged and audited

## Multi-Factor Authentication (MFA)

### MFA Requirements

| Account Type | MFA Requirement |
|-------------|------------------|
| Administrative accounts | Required for all access |
| Service accounts | Required for enrollment, key rotation |
| Standard user accounts | Required for production environments |
| Standard user accounts | Required for sensitive data access |
| Standard user accounts | Optional but encouraged for all other access |

### Supported MFA Methods

1. **Authenticator Applications** (Preferred)
   - Time-based one-time password (TOTP)
   - Compliant with RFC 6238
   - 30-second code validity
   - Secure enrollment process with QR codes
   - Supported apps: Google Authenticator, Microsoft Authenticator, Authy

2. **Hardware Security Keys**
   - FIDO2/WebAuthn compliant devices
   - U2F support for legacy devices
   - Multiple keys per account for backup
   - Phishing-resistant authentication

3. **Push Notifications** (Limited approval)
   - Approved secure mobile applications only
   - Cryptographically signed challenges
   - Limited validity period (30 seconds)
   - Out-of-band verification channel

4. **Backup Codes**
   - Single-use recovery codes
   - Minimum of 10 codes generated
   - Codes expire after use
   - Secure delivery and storage requirements

### MFA Configuration

- Default of 5 per user MFA device enrollment limit
- Require re-verification of MFA every 30 days
- Enable MFA for all privileged actions
- Minimum key strength for certificate-based authentication: 2048 bits

### MFA Exceptions

Limited exceptions to MFA requirements:

- Emergency access protocols (documented separately)
- Specific automated service accounts with appropriate compensating controls
- All exceptions require documented approval from the Security Team and CISO

## Authentication Flows

### User Authentication

1. **Initial Authentication Flow**
   - Username/password verification
   - Risk assessment (location, device, behavior)
   - MFA challenge if required
   - Session establishment with appropriate timeout
   - Activity and device tracking

2. **Continuous Authentication**
   - Session monitoring for anomalous behavior
   - Periodic reauthentication for sensitive operations
   - Context validation for high-risk actions
   - Session termination on suspicious activity

### Service Authentication

1. **API Authentication Flow**
   - API key or client certificate validation
   - Request signing verification
   - Rate limiting enforcement
   - Scope validation against requested resources
   - Audit logging of access

2. **Service-to-Service Authentication**
   - Mutual TLS authentication (mTLS)
   - Service account credential validation
   - OAuth client credentials flow
   - Short-lived token issuance
   - Certificate trust chain validation

## Session Management

### Session Configuration

- **Session Timeout Settings**:
  - Administrative sessions: 15 minutes of inactivity
  - Standard user sessions: 4 hours of inactivity
  - API token sessions: Configurable, default 1 hour

- **Session Security Controls**:
  - Secure cookie attributes (HttpOnly, Secure, SameSite=Strict)
  - Anti-CSRF token implementation
  - Session binding to IP address and/or device fingerprint
  - Session regeneration on privilege level change

### Session Monitoring

- Active session inventory for users
- Concurrent session limitations
  - Administrative users: 1 active session
  - Standard users: 5 active sessions
- Forced session termination capabilities
- Anomalous session activity detection and alerting

## OAuth and OIDC Standards

### Supported OAuth Flows

- **Authorization Code Flow**: For web applications
  - PKCE extension required
  - State parameter required
  - Redirect URI validation
  - Short-lived authorization codes (5 minute max)

- **Client Credentials Flow**: For service-to-service
  - Restricted to trusted services
  - Limited scope assignments
  - Enhanced monitoring and auditing
  - Client authentication required

- **Device Flow**: For limited input devices
  - User verification required on separate device
  - Limited to appropriate device types
  - Short-lived device codes (15 minute max)

### OAuth Security Requirements

- **Token Security**:
  - Access tokens: 1 hour maximum lifetime
  - Refresh tokens: 30 day maximum lifetime, single use
  - Signed JWTs using RS256 or ES256 algorithms
  - Encryption of sensitive claims when needed

- **Client Application Security**:
  - Client secrets minimum 32 bytes random value
  - Confidential clients only for sensitive applications
  - Dynamic client registration restricted to trusted systems
  - Regular client credential rotation (90 days)

### OpenID Connect Implementation

- Discovery endpoint for automatic configuration
- Standard claim support for user information
- ID token issuance for authentication flows
- Support for multiple signing keys with rotation
- Userinfo endpoint with appropriate scope requirements

## SAML Standards

### SAML Configuration

- **Identity Provider Requirements**:
  - Metadata exchange for trust establishment
  - XML signing using RSA-SHA256
  - Encryption using AES-256
  - Artifact resolution service (optional)

- **Service Provider Configuration**:
  - Entity ID uniqueness requirements
  - Assertion Consumer Service URL validation
  - Request signing requirements
  - SAML response validation

### SAML Security Controls

- XML Signature validation for all assertions
- Audience restriction validation
- NotBefore and NotOnOrAfter condition validation
- InResponseTo validation to prevent replay
- Destination attribute validation
- Recipient attribute validation

## Token Standards

### JWT Implementation

- **Signature Algorithms**:
  - RS256 (RSA + SHA-256) preferred
  - ES256 (ECDSA + P-256 + SHA-256) supported
  - HS256 (HMAC + SHA-256) for limited internal use only

- **Standard Claims**:
  - `iss` (Issuer): Validated against trusted issuers
  - `sub` (Subject): Unique identifier for the user
  - `aud` (Audience): Validated against service identifier
  - `exp` (Expiration Time): Maximum 1 hour for access tokens
  - `nbf` (Not Before): Validated against current time
  - `iat` (Issued At): Used for token age verification
  - `jti` (JWT ID): Unique identifier for token revocation

### Token Security Controls

- Token revocation capabilities for compromise scenarios
- Token refresh controls with original grant validation
- Token audience restriction enforcement
- Encrypted tokens for sensitive payloads using JWE
- Regular key rotation (90 days for signing keys)

## Implementation Guidelines

### Authentication Implementation Checklist

1. **Secure Authentication Forms**
   - CSRF protection implementation
   - Rate limiting enforcement
   - Secure error messages (no user enumeration)
   - Password field security practices

2. **API Authentication Implementation**
   - TLS 1.2+ requirement
   - Token validation for every request
   - Scope enforcement for authorization
   - API key management best practices

3. **Service Authentication**
   - Certificate-based authentication setup
   - mTLS configuration
   - Service account credential management
   - Automated rotation of service credentials

4. **Application Authentication Integration**
   - Secure credential storage
   - Proper token handling practices
   - Browser security headers implementation
   - Application session management

## Configuration Guidelines

### Identity Provider Configuration

1. **Standard Configuration**
   - HTTPS endpoint requirements
   - Certificate requirements and rotation
   - Algorithm requirements (RSA 2048+ or ECDSA P-256+)
   - Protocol version requirements

2. **Security Settings**
   - Session lifetime limitations
   - MFA enforcement configuration
   - Risk-based authentication settings
   - Access control policy configuration

### Authentication Service Configuration

1. **Core Authentication Services**
   - Password policy enforcement
   - Authentication rate limiting
   - Logging and monitoring configuration
   - Account lockout parameters

2. **MFA Configuration**
   - TOTP settings (interval, algorithm)
   - WebAuthn/FIDO2 configuration
   - Backup methods configuration
   - Grace period settings

3. **Federation Configuration**
   - Identity provider metadata management
   - Claim mapping configuration
   - Group mapping settings
   - Federation trust establishment

## Monitoring and Auditing

### Authentication Monitoring

1. **Required Monitoring**
   - Failed authentication attempts
   - Account lockout events
   - MFA failures and bypasses
   - Password reset activities
   - New device authentications
   - Authentication from unusual locations
   - Service account authentication patterns
   - Token revocation and compromise events

2. **Authentication Metrics**
   - Average authentication success rate
   - MFA adoption rate
   - Authentication latency
   - Failed authentication ratio

### Authentication Audit Trail

All authentication events must be logged with the following information:

- Timestamp with millisecond precision
- User identifier (username or ID)
- Service account identifier (where applicable)
- Source IP address and geolocation
- Device information
- Authentication method used
- Success/failure outcome
- Failure reason (for failed attempts)
- MFA method used (if applicable)
- Request identifiers for correlation

## Best Practices

- **Defense in Depth**: Use multiple authentication factors
- **Phishing Resistance**: Implement FIDO2/WebAuthn where possible
- **Continuous Authentication**: Validate context throughout sessions
- **Secure Storage**: Use appropriate hashing for credential storage
- **Fail Secure**: Deny access when authentication systems fail
- **Progressive Enhancement**: Add security based on risk level
- **User Experience**: Balance security with usability
- **Secure Defaults**: Configure secure options by default
- **Regular Testing**: Conduct authentication security testing
- **Seamless MFA**: Implement user-friendly multi-factor options

## Compliance Requirements

This standard ensures compliance with:

- **ISO 27001**: Control A.9.4 - System and application access control
- **NIST SP 800-63B**: Digital Identity Guidelines - Authentication
- **PCI DSS**: Requirements 8.1 - 8.6 for authentication
- **HIPAA**: Access control and unique user identification
- **SOC 2**: Access control criteria for authentication
- **GDPR**: Technical measures for ensuring authorized access

## Related Documentation

- Certificate Management - Certificate lifecycle procedures
- Crypto Standards - Cryptography standards
- IAM Policies - Identity and access management policies
- Security Architecture Overview - Overall security architecture
- Security Update Policy - Security update procedures

## Version History

| Version | Date | Description | Author |
|---------|------|-------------|--------|
| 1.0 | 2023-07-25 | Initial document | Security Team |
| 1.1 | 2023-10-12 | Added FIDO2/WebAuthn requirements | Authentication Team |
| 1.2 | 2024-01-08 | Updated password requirements | Security Architect |
| 1.3 | 2024-03-15 | Enhanced token security standards | Identity Team |
| 1.4 | 2024-05-22 | Added OAuth/OIDC security controls | Security Standards Team |
