# Web Application Hardening Guide

## Contents

- [Overview](#overview)
- [Security Headers Implementation](#security-headers-implementation)
- [Input Validation](#input-validation)
- [Output Encoding](#output-encoding)
- [Authentication Hardening](#authentication-hardening)
- [Session Management](#session-management)
- [Access Control Enhancements](#access-control-enhancements)
- [Security Configuration](#security-configuration)
- [API Security](#api-security)
- [Dependency Management](#dependency-management)
- [Implementation Reference](#implementation-reference)
- [Available Functions](#available-functions)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

This guide provides structured approaches for hardening web applications against common security threats. It covers essential security controls, configuration settings, and implementation strategies for establishing a robust security posture. These hardening measures should be applied as part of the recovery phase following a security incident, as well as proactively to prevent security compromises.

Web application hardening encompasses multiple layers of defense, from secure coding practices to robust configuration settings. By implementing the practices described in this guide, security teams can significantly reduce the attack surface of web applications, mitigate common vulnerabilities, and establish a strong security foundation.

## Security Headers Implementation

### Essential HTTP Security Headers

| Header | Description | Recommended Value | Implementation |
|--------|-------------|-------------------|----------------|
| **Content-Security-Policy** | Controls resources browser can load | `default-src 'self'; script-src 'self'` | Web server config, application code |
| **X-Content-Type-Options** | Prevents MIME-type sniffing | `nosniff` | Web server config, middleware |
| **X-Frame-Options** | Prevents clickjacking | `DENY` or `SAMEORIGIN` | Web server config, middleware |
| **X-XSS-Protection** | Enables browser XSS filtering | `1; mode=block` | Web server config, middleware |
| **Strict-Transport-Security** | Enforces HTTPS | `max-age=31536000; includeSubDomains` | Web server config, middleware |
| **Referrer-Policy** | Controls referrer information | `strict-origin-when-cross-origin` | Web server config, middleware |
| **Permissions-Policy** | Controls browser features | `geolocation=(), microphone=()` | Web server config, middleware |
| **Cache-Control** | Controls caching of sensitive content | `no-store, max-age=0` | Application code, conditional |

### Content Security Policy Implementation

1. **Basic Policy Implementation**
   - Create baseline policy for script sources
   - Add style source directives
   - Configure connect-src for API endpoints
   - Implement img-src restrictions
   - Document CSP implementation

2. **Policy Tuning**
   - Implement CSP in report-only mode initially
   - Analyze violation reports
   - Refine policy based on legitimate usage
   - Gradually transition to enforcement mode
   - Document exception handling

3. **Nonce-Based Approach**
   - Implement per-request nonce generation
   - Include nonce in script tags
   - Update CSP header to include nonce
   - Verify nonce validation in browsers
   - Document nonce implementation

4. **Hash-Based Approach**
   - Generate hashes of inline scripts
   - Add script hashes to CSP
   - Validate hash correctness
   - Document hash generation process
   - Implement hash update mechanism

### Implementation Example

```python
from core.security import configure_security_headers

# Configure security headers for application
headers_config = configure_security_headers(
    application="customer_portal",
    csp_policy={
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://trusted-cdn.example.com"],
        "style-src": ["'self'", "https://trusted-cdn.example.com"],
        "img-src": ["'self'", "https://trusted-cdn.example.com", "data:"],
        "connect-src": ["'self'", "https://api.example.com"],
        "frame-ancestors": ["'none'"],
        "form-action": ["'self'"]
    },
    hsts_max_age=31536000,
    hsts_include_subdomains=True,
    xss_protection="1; mode=block",
    content_type_options="nosniff",
    frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin",
    permissions_policy="geolocation=(), microphone=()"
)

# Apply security headers to application
apply_result = headers_config.apply(
    verification=True,
    backup_config=True,
    notification=True
)

print(f"Security headers configured: {apply_result.success}")
print(f"Headers applied: {', '.join(apply_result.applied_headers)}")
```

## Input Validation

### Input Validation Strategies

1. **Syntactic Validation**
   - Implement type checking
   - Apply format validation (regex patterns)
   - Enforce length restrictions
   - Check character set limitations
   - Document validation rules

2. **Semantic Validation**
   - Validate against business rules
   - Implement range checking
   - Ensure logical consistency
   - Validate interdependent fields
   - Document business validation logic

3. **Centralized Validation Framework**
   - Implement validation rule repository
   - Create reusable validation components
   - Apply consistent validation across application
   - Document framework usage guidelines
   - Include validation bypass detection

### Implementation Architecture

1. **Server-Side Implementation**
   - Apply validation before processing
   - Implement validation at API boundaries
   - Create field-specific validators
   - Avoid client-side validation bypass
   - Document server-side validation logic

2. **Client-Side Enhancement**
   - Add client-side validation for usability
   - Never rely solely on client validation
   - Sync validation rules with server
   - Provide immediate user feedback
   - Document client-side implementation

3. **Handling Validation Failures**
   - Return descriptive error messages
   - Log validation failures
   - Alert on suspicious patterns
   - Implement rate limiting after failures
   - Document failure handling procedures

### Implementation Example

```python
from core.security import input_validation
from core.security.cs_constants import ValidationStrategy, ValidationType

# Configure input validation for API endpoint
validation_config = input_validation.create_validation_scheme(
    endpoint="/api/users",
    fields=[
        {
            "name": "username",
            "type": ValidationType.STRING,
            "required": True,
            "min_length": 3,
            "max_length": 50,
            "pattern": r"^[a-zA-Z0-9_\.-]+$",
            "error_message": "Username must be 3-50 characters and can only contain letters, numbers, and _.-"
        },
        {
            "name": "email",
            "type": ValidationType.EMAIL,
            "required": True,
            "error_message": "Please provide a valid email address"
        },
        {
            "name": "age",
            "type": ValidationType.INTEGER,
            "required": False,
            "min_value": 18,
            "max_value": 120,
            "error_message": "Age must be between 18 and 120"
        },
        {
            "name": "role",
            "type": ValidationType.STRING,
            "required": True,
            "allowed_values": ["user", "admin", "moderator"],
            "error_message": "Role must be one of: user, admin, moderator"
        }
    ],
    strategy=ValidationStrategy.REJECT_INVALID,
    log_violations=True,
    alert_on_suspicious=True
)

# Apply validation configuration
validation_result = input_validation.apply_validation(
    validation_config=validation_config,
    application="customer_portal"
)

print(f"Validation configured: {validation_result.success}")
print(f"Endpoints covered: {len(validation_result.endpoints)}")
```

## Output Encoding

### Context-Based Encoding

1. **HTML Context**
   - Encode for HTML entity encoding
   - Handle special characters
   - Properly escape quotation marks
   - Document HTML encoding procedures
   - Test against XSS payloads

2. **JavaScript Context**
   - Apply JavaScript string encoding
   - Handle JavaScript-specific sequences
   - Encode Unicode characters
   - Document JavaScript encoding practices
   - Test against JavaScript injection

3. **CSS Context**
   - Implement CSS hex encoding
   - Handle CSS-specific characters
   - Validate against style-based attacks
   - Document CSS encoding guidelines
   - Test against CSS injection

4. **URL Context**
   - Apply proper URL encoding
   - Handle path vs. query parameter differences
   - Document URL encoding practices
   - Test against URL-based attacks
   - Implement URL validation

### Common Encoding Problems

| Context | Risk | Solution | Implementation |
|---------|------|----------|----------------|
| **HTML Body** | XSS through unencoded content | HTML entity encoding | Templating library encoding function |
| **HTML Attribute** | XSS via attribute injection | Attribute-specific encoding | Custom encoding function |
| **JavaScript** | JavaScript execution or data theft | JavaScript string encoding | JavaScript encoder function |
| **CSS** | CSS-based attacks | CSS hex encoding | CSS encoder function |
| **URL** | URL manipulation | URL encoding | URL encoding function |
| **XML** | XML injection | XML entity encoding | XML library encoding function |

### Implementation Example

```python
from core.security import output_encoding

# Configure output encoding for application
encoding_config = output_encoding.configure_encoding(
    application="customer_portal",
    contexts=[
        {
            "name": "html_body",
            "encoder": output_encoding.Encoder.HTML,
            "apply_to": ["user_content", "product_descriptions"]
        },
        {
            "name": "javascript",
            "encoder": output_encoding.Encoder.JAVASCRIPT,
            "apply_to": ["dynamic_data", "user_preferences"]
        },
        {
            "name": "html_attribute",
            "encoder": output_encoding.Encoder.HTML_ATTRIBUTE,
            "apply_to": ["data_attributes", "user_generated_ids"]
        },
        {
            "name": "url",
            "encoder": output_encoding.Encoder.URL,
            "apply_to": ["redirect_urls", "dynamic_links"]
        }
    ],
    default_encoding=output_encoding.Encoder.HTML,
    enable_automatic_detection=True
)

# Apply encoding configuration
encoding_result = output_encoding.apply_encoding(
    encoding_config=encoding_config,
    verify_implementation=True
)

print(f"Output encoding configured: {encoding_result.success}")
print(f"Contexts configured: {len(encoding_result.contexts)}")
```

## Authentication Hardening

### Password Policy Implementation

1. **Password Complexity Requirements**
   - Require minimum length (12+ characters)
   - Enforce character diversity
   - Check against common password lists
   - Document policy requirements
   - Implement policy enforcement

2. **Secure Password Storage**
   - Use strong adaptive hashing (Argon2, bcrypt)
   - Implement proper salt generation
   - Configure appropriate work factors
   - Document hashing implementation
   - Test password verification

3. **Account Lockout Policies**
   - Implement progressive delays
   - Configure lockout thresholds
   - Create unlock mechanisms
   - Document lockout policies
   - Test lockout effectiveness

### Multi-Factor Authentication

1. **MFA Implementation**
   - Support TOTP-based authenticators
   - Implement WebAuthn/FIDO2 options
   - Configure recovery mechanisms
   - Document MFA setup process
   - Test MFA workflow

2. **Risk-Based Authentication**
   - Implement device fingerprinting
   - Create risk assessment model
   - Configure step-up authentication
   - Document risk assessment factors
   - Test risk scoring accuracy

3. **Session Hardening**
   - Generate strong session identifiers
   - Implement secure session storage
   - Configure appropriate timeouts
   - Document session security features
   - Test session security controls

### Implementation Example

```python
from core.security import authentication_hardening
from core.security.cs_constants import PasswordPolicy, MFAMethod, AuthenticationRisk

# Configure authentication hardening
auth_config = authentication_hardening.configure_authentication(
    application="customer_portal",
    password_policy={
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special_chars": True,
        "check_common_passwords": True,
        "password_history": 10,
        "max_age_days": 90,
        "hash_algorithm": PasswordPolicy.HASH_ALGORITHM_ARGON2ID,
        "hash_memory_cost": 65536,
        "hash_time_cost": 3
    },
    lockout_policy={
        "max_attempts": 5,
        "lockout_duration_minutes": 15,
        "reset_counter_after_minutes": 30,
        "progressive_delays": True
    },
    mfa_settings={
        "required_for": ["administrators", "high_value_accounts"],
        "available_methods": [MFAMethod.TOTP, MFAMethod.WEBAUTHN],
        "remember_device_days": 30,
        "bypass_rate_limit": 3
    },
    risk_based_auth={
        "enabled": True,
        "risk_factors": [
            AuthenticationRisk.NEW_DEVICE,
            AuthenticationRisk.NEW_LOCATION,
            AuthenticationRisk.UNUSUAL_TIME,
            AuthenticationRisk.UNUSUAL_BEHAVIOR
        ],
        "high_risk_action": "require_mfa"
    }
)

# Apply authentication configuration
auth_result = authentication_hardening.apply_authentication_hardening(
    auth_config=auth_config,
    backup_config=True
)

print(f"Authentication hardening configured: {auth_result.success}")
print(f"Configuration applied: {', '.join(auth_result.applied_components)}")
```

## Session Management

### Secure Session Handling

1. **Session Generation**
   - Implement cryptographically secure ID generation
   - Ensure adequate ID length and entropy
   - Create server-side session mapping
   - Document session creation process
   - Test ID randomness and uniqueness

2. **Session Storage**
   - Implement secure server-side storage
   - Configure session encryption
   - Establish session data access controls
   - Document storage architecture
   - Test storage security

3. **Cookie Security**
   - Set proper cookie flags (Secure, HttpOnly)
   - Configure SameSite attribute
   - Implement cookie prefixes
   - Document cookie configuration
   - Test cookie security flags

### Session Lifecycle Management

1. **Session Expiration**
   - Configure absolute timeouts
   - Implement idle timeouts
   - Create timeout notifications
   - Document timeout policies
   - Test timeout enforcement

2. **Session Validation**
   - Verify session integrity
   - Implement additional context validation
   - Create session binding mechanisms
   - Document validation procedures
   - Test against session-based attacks

3. **Session Termination**
   - Implement proper logout functionality
   - Clear session data completely
   - Invalidate tokens on logout
   - Document termination procedures
   - Test logout effectiveness

### Implementation Example

```python
from core.security import session_hardening
from core.security.cs_constants import SessionStorage, CookiePolicy

# Configure session security
session_config = session_hardening.configure_sessions(
    application="customer_portal",
    session_storage=SessionStorage.SERVER_SIDE,
    session_id_settings={
        "length_bytes": 32,
        "generation_method": "crypto_random",
        "regeneration_on_privilege_change": True
    },
    cookie_settings={
        "http_only": True,
        "secure": True,
        "same_site": CookiePolicy.SAME_SITE_LAX,
        "prefix": "__Host-",
        "path": "/",
        "domain_strict": True
    },
    expiration_settings={
        "absolute_timeout_minutes": 240,
        "idle_timeout_minutes": 30,
        "remember_me_days": 14
    },
    validation_settings={
        "validate_ip": True,
        "validate_user_agent": True,
        "validate_origin": True,
        "additional_context_data": ["device_id"]
    },
    integrity_protection={
        "sign_session_data": True,
        "encrypt_sensitive_data": True
    }
)

# Apply session security configuration
session_result = session_hardening.apply_session_hardening(
    session_config=session_config,
    verify_configuration=True
)

print(f"Session hardening configured: {session_result.success}")
print(f"Session components secured: {', '.join(session_result.secured_components)}")
```

## Access Control Enhancements

### Authorization Framework

1. **Role-Based Access Control**
   - Define role hierarchy
   - Implement role-based permissions
   - Create role assignment workflows
   - Document role definitions
   - Test access control enforcement

2. **Attribute-Based Access Control**
   - Define attribute policies
   - Implement dynamic authorization
   - Create policy evaluation engine
   - Document attribute assignments
   - Test complex authorization scenarios

3. **Permission Models**
   - Implement resource-based permissions
   - Create permission verification hooks
   - Establish permission inheritance
   - Document permission structure
   - Test permission enforcement

### Access Control Implementation

1. **Access Control Points**
   - Identify all authorization boundaries
   - Implement consistent checks
   - Create centralized verification
   - Document control points
   - Test access control boundaries

2. **API Authorization**
   - Implement endpoint-specific permissions
   - Create resource ownership validation
   - Establish API access hierarchies
   - Document API authorization
   - Test API access controls

3. **Frontend Protection**
   - Implement UI rendering based on permissions
   - Create server-side verification
   - Establish consistent authorization UX
   - Document frontend security measures
   - Test against forced browsing

### Implementation Example

```python
from core.security import access_control_hardening
from core.security.cs_constants import AccessControlModel, ResourceType

# Configure access control model
access_control_config = access_control_hardening.configure_access_control(
    application="customer_portal",
    access_model=AccessControlModel.HYBRID_RBAC_ABAC,
    roles_configuration={
        "role_hierarchy": {
            "admin": ["manager", "user"],
            "manager": ["user"],
            "user": []
        },
        "default_role": "user",
        "assignment_validation": True
    },
    permissions_configuration={
        "resource_types": [
            {
                "type": ResourceType.API_ENDPOINT,
                "permission_scheme": ["read", "write", "delete", "admin"]
            },
            {
                "type": ResourceType.DATA_OBJECT,
                "permission_scheme": ["view", "edit", "delete", "share"]
            },
            {
                "type": ResourceType.FEATURE,
                "permission_scheme": ["access", "configure"]
            }
        ],
        "enforcement_points": ["api_gateway", "service_layer", "data_access_layer"]
    },
    attributes_configuration={
        "supported_attributes": ["department", "location", "clearance_level"],
        "context_attributes": ["time", "ip_address", "device_type"],
        "attribute_sources": ["user_directory", "context_provider"]
    },
    enforcement_configuration={
        "fail_closed": True,
        "verify_frontend_requests": True,
        "log_access_denials": True,
        "alert_on_suspicious_access": True
    }
)

# Apply access control configuration
access_result = access_control_hardening.apply_access_control(
    access_control_config=access_control_config,
    verify_implementation=True
)

print(f"Access control hardening configured: {access_result.success}")
print(f"Protected resources: {len(access_result.protected_resources)}")
```

## Security Configuration

### Web Server Hardening

1. **Server Security Headers**
   - Configure security headers at server level
   - Implement consistent header delivery
   - Create header validation tests
   - Document server header configuration
   - Test header implementation

2. **TLS Configuration**
   - Enable TLS 1.2+ only
   - Configure secure cipher suites
   - Implement HSTS policy
   - Document TLS configuration
   - Test TLS implementation strength

3. **Server Exposure Minimization**
   - Remove server information headers
   - Disable unnecessary modules
   - Limit exposed error information
   - Document exposure minimization
   - Test information disclosure

### Framework Security

1. **Framework Updates**
   - Maintain current framework versions
   - Track security advisories
   - Apply security patches promptly
   - Document update procedures
   - Test framework security features

2. **Framework-Specific Hardening**
   - Enable framework security features
   - Configure secure defaults
   - Implement security middleware
   - Document framework security
   - Test framework vulnerabilities

3. **Error Handling**
   - Implement custom error pages
   - Create secure error logging
   - Configure error handling rules
   - Document error handling
   - Test error handling security

### Implementation Example

```python
from core.security import server_hardening
from core.security.cs_constants import ServerType, TLSVersion, ServerExposureLevel

# Configure web server hardening
server_config = server_hardening.configure_web_server(
    server_type=ServerType.NGINX,
    servers=["web-server-01", "web-server-02"],
    tls_configuration={
        "min_version": TLSVersion.TLS_1_2,
        "preferred_ciphers": [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256"
        ],
        "disable_ciphers": [
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA"
        ],
        "key_exchange_params": {
            "dh_param_size": 2048,
            "prefer_server_ciphers": True
        },
        "certificate_settings": {
            "min_rsa_key_size": 2048,
            "prefer_ecdsa": True,
            "trusted_ca_verification": True
        }
    },
    security_headers={
        "apply_at_server_level": True,
        "override_application_headers": False
    },
    exposure_control={
        "level": ServerExposureLevel.MINIMAL,
        "hide_server_tokens": True,
        "hide_framework_info": True,
        "custom_server_name": "",
        "restrict_methods": ["GET", "POST", "PUT", "DELETE"],
        "remove_default_files": True
    },
    error_handling={
        "custom_error_pages": True,
        "sanitize_error_messages": True,
        "log_detailed_errors": True
    }
)

# Apply web server hardening
server_result = server_hardening.apply_web_server_hardening(
    server_config=server_config,
    backup_config=True
)

print(f"Web server hardening applied: {server_result.success}")
print(f"Servers hardened: {', '.join(server_result.hardened_servers)}")
```

## API Security

### API Authentication & Authorization

1. **Authentication Methods**
   - Implement token-based authentication
   - Support OAuth 2.0 with PKCE
   - Configure API keys for service clients
   - Document authentication options
   - Test auth implementation security

2. **Authorization Controls**
   - Implement fine-grained API permissions
   - Create scope-based authorization
   - Establish resource ownership checks
   - Document authorization model
   - Test authorization boundaries

3. **Token Security**
   - Configure proper token lifetimes
   - Implement token validation
   - Establish token revocation
   - Document token handling
   - Test token security controls

### Request Validation & Rate Limiting

1. **Input Validation**
   - Implement schema validation
   - Create parameter validation
   - Establish content type restrictions
   - Document validation procedures
   - Test against validation bypass

2. **Rate Limiting**
   - Configure per-client limits
   - Implement endpoint-specific throttling
   - Create tiered rate limiting
   - Document rate limiting policies
   - Test rate limiting effectiveness

3. **API Gateway Controls**
   - Configure request filtering
   - Implement traffic monitoring
   - Create anomaly detection
   - Document gateway security
   - Test gateway protections

### Implementation Example

```python
from core.security import api_security
from core.security.cs_constants import AuthMethod, RateLimitStrategy

# Configure API security
api_config = api_security.configure_api_security(
    application="customer_portal",
    api_gateways=["api-gateway-01", "api-gateway-02"],
    authentication={
        "methods": [AuthMethod.JWT, AuthMethod.OAUTH2, AuthMethod.API_KEY],
        "token_configuration": {
            "access_token_lifetime_minutes": 15,
            "refresh_token_lifetime_days": 7,
            "token_validation_mode": "strict",
            "token_revocation_enabled": True
        },
        "api_key_configuration": {
            "rotation_policy_days": 90,
            "key_entropy_bits": 256,
            "per_endpoint_keys": True
        }
    },
    authorization={
        "scope_enforcement": True,
        "resource_ownership_validation": True,
        "permission_granularity": "endpoint"
    },
    request_validation={
        "schema_validation": True,
        "content_type_validation": True,
        "parameter_sanitization": True,
        "maximum_request_size_kb": 1024,
        "maximum_url_length": 2048
    },
    rate_limiting={
        "strategy": RateLimitStrategy.ADAPTIVE,
        "base_limits": {
            "requests_per_minute": 60,
            "requests_per_hour": 1000
        },
        "endpoint_specific_limits": {
            "/api/auth/*": {"requests_per_minute": 10},
            "/api/admin/*": {"requests_per_minute": 30}
        },
        "client_tiers": {
            "standard": 1.0,
            "premium": 2.0,
            "internal": 5.0
        }
    },
    monitoring={
        "log_all_requests": True,
        "anomaly_detection": True,
        "sensitive_operation_alerts": True
    }
)

# Apply API security configuration
api_result = api_security.apply_api_security(
    api_config=api_config,
    verify_implementation=True
)

print(f"API security hardening applied: {api_result.success}")
print(f"Protected endpoints: {api_result.protected_endpoint_count}")
```

## Dependency Management

### Secure Dependency Handling

1. **Dependency Scanning**
   - Implement automated vulnerability scanning
   - Configure SBOM generation
   - Create version pinning policies
   - Document scanning procedures
   - Test vulnerability detection

2. **Dependency Policy**
   - Establish approved dependency sources
   - Create version approval workflows
   - Implement license compliance checks
   - Document dependency policies
   - Test policy enforcement

3. **Dependency Updates**
   - Automate security updates
   - Configure dependency patching
   - Create update testing workflows
   - Document update procedures
   - Test update safety

### Library Security Configuration

1. **Library-Specific Hardening**
   - Configure secure library defaults
   - Implement security-focused configurations
   - Establish library usage guidelines
   - Document library security features
   - Test library security configurations

2. **Vulnerable Dependency Mitigation**
   - Create vulnerability patching priorities
   - Implement temporary mitigations
   - Establish vulnerable component isolation
   - Document mitigation strategies
   - Test mitigation effectiveness

### Implementation Example

```python
from core.security import dependency_management
from core.security.cs_constants import DependencySeverity, UpdateStrategy

# Configure dependency security management
dependency_config = dependency_management.configure_dependency_security(
    application="customer_portal",
    scanning_configuration={
        "tools": ["npm_audit", "snyk", "owasp_dependency_check"],
        "schedule": "daily",
        "generate_sbom": True,
        "sbom_format": "cyclonedx",
        "ci_cd_integration": True
    },
    policy_configuration={
        "approved_sources": ["npm", "maven_central", "pypi", "nuget"],
        "license_restrictions": ["GPL-3.0", "AGPL-3.0"],
        "version_pinning_required": True,
        "lock_files_required": True
    },
    update_configuration={
        "security_updates_strategy": UpdateStrategy.AUTOMATIC,
        "regular_updates_strategy": UpdateStrategy.SCHEDULED,
        "testing_required": True,
        "update_documentation_required": True
    },
    vulnerability_handling={
        "critical_severity": {
            "action": "update_immediately",
            "sla_hours": 24
        },
        "high_severity": {
            "action": "update_scheduled",
            "sla_hours": 72
        },
        "medium_severity": {
            "action": "evaluate_and_plan",
            "sla_hours": 168
        },
        "low_severity": {
            "action": "track_and_update",
            "sla_hours": 336
        }
    },
    mitigation_strategies={
        "temporary_patching": True,
        "virtual_patching": True,
        "component_isolation": True
    }
)

# Apply dependency security configuration
dependency_result = dependency_management.apply_dependency_security(
    dependency_config=dependency_config
)

print(f"Dependency security hardening applied: {dependency_result.success}")
print(f"Scanned dependencies: {dependency_result.dependency_count}")
print(f"Vulnerabilities detected: {dependency_result.vulnerability_count}")
```

## Implementation Reference

### Command Line Reference

1. **Security Header Configuration**

   ```bash
   # Apply security headers to web application
   python3 -m admin.security.incident_response_kit.recovery.security_hardening \
   --target web-application --component security-headers \
   --csp "default-src 'self'" --hsts --xframe deny \
   --referrer strict-origin-when-cross-origin
   ```

2. **Input Validation Configuration**

   ```bash
   # Configure input validation for application
   python3 -m admin.security.incident_response_kit.recovery.security_hardening \
   --target customer-portal --component input-validation \
   --validation-file /secure/validation_rules.json \
   --test-validation --alert-on-bypass
   ```

3. **Authentication Hardening**

   ```bash
   # Apply authentication hardening measures
   python3 -m admin.security.incident_response_kit.recovery.security_hardening \
   --target auth-service --component authentication \
   --pwd-policy strong --mfa required --lockout-attempts 5 \
   --session-timeout 30
   ```

4. **Session Security Configuration**

   ```bash
   # Configure secure session handling
   python3 -m admin.security.incident_response_kit.recovery.security_hardening \
   --target web-application --component sessions \
   --secure --httponly --samesite strict \
   --absolute-timeout 240 --idle-timeout 30
   ```

5. **API Security Enhancements**

   ```bash
   # Enhance API security
   python3 -m admin.security.incident_response_kit.recovery.security_hardening \
   --target api-gateway --component api-security \
   --auth-method oauth2 --rate-limit 60 \
   --request-validation strict --scope-enforcement
   ```

### Script Examples

1. **Web Application Hardening Script**

   ```python
   from admin.security.incident_response_kit.recovery import security_hardening
   from core.security.cs_constants import ApplicationType, HardeningComponent

   # Perform comprehensive web application hardening
   result = security_hardening.harden_application(
       target="customer_portal",
       application_type=ApplicationType.WEB,
       components=[
           HardeningComponent.SECURITY_HEADERS,
           HardeningComponent.INPUT_VALIDATION,
           HardeningComponent.OUTPUT_ENCODING,
           HardeningComponent.AUTHENTICATION,
           HardeningComponent.SESSION_MANAGEMENT,
           HardeningComponent.ACCESS_CONTROL,
           HardeningComponent.API_SECURITY
       ],
       configuration_file="/secure/hardening/web_app_hardening_config.json",
       incident_id="IR-2023-047",
       backup_configurations=True,
       verify_after_hardening=True,
       generate_report=True,
       report_path="/secure/reports/hardening_report_IR-2023-047.pdf"
   )

   # Display hardening results
   print(f"Hardening completed: {result.success}")
   print(f"Components hardened: {', '.join(result.hardened_components)}")
   print(f"Issues fixed: {result.issues_fixed}")
   print(f"Report location: {result.report_path}")
   ```

2. **Security Header Implementation**

   ```python
   from core.security import security_headers

   # Configure and apply security headers
   headers_config = security_headers.create_security_headers_config(
       application="customer_portal",
       content_security_policy="default-src 'self'; script-src 'self' https://trusted-cdn.example.com",
       x_frame_options="DENY",
       x_content_type_options="nosniff",
       x_xss_protection="1; mode=block",
       strict_transport_security="max-age=31536000; includeSubDomains",
       referrer_policy="strict-origin-when-cross-origin",
       permissions_policy="geolocation=(), microphone=()"
   )

   # Apply headers to different environments
   development_result = security_headers.apply_security_headers(
       config=headers_config,
       environment="development"
   )

   production_result = security_headers.apply_security_headers(
       config=headers_config,
       environment="production"
   )

   # Print results
   print(f"Development headers applied: {development_result.success}")
   print(f"Production headers applied: {production_result.success}")
   ```

3. **Input Validation Implementation**

   ```python
   from core.security import input_validation

   # Configure input validation rules
   validation_schema = input_validation.create_validation_schema(
       endpoint_patterns=["/api/users/*", "/api/accounts/*"],
       validation_rules=[
           {
               "field": "username",
               "rules": ["required", "string", "min:3", "max:50", "alphanumeric"],
               "error_message": "Username must be 3-50 alphanumeric characters"
           },
           {
               "field": "email",
               "rules": ["required", "email"],
               "error_message": "Must be a valid email address"
           },
           {
               "field": "password",
               "rules": ["required", "string", "min:12", "password_complexity"],
               "error_message": "Password must be at least 12 characters with mixed cases, numbers and symbols"
           },
           {
               "field": "account_type",
               "rules": ["required", "in:personal,business,enterprise"],
               "error_message": "Account type must be personal, business, or enterprise"
           }
       ],
       security_settings={
           "log_validation_failures": True,
           "alert_on_repeated_failures": True,
           "failure_threshold": 5,
           "block_after_threshold": True
       }
   )

   # Apply validation schema
   validation_result = input_validation.apply_validation_schema(
       schema=validation_schema,
       application="customer_portal",
       backup_existing=True
   )

   # Print results
   print(f"Validation applied: {validation_result.success}")
   print(f"Protected endpoints: {len(validation_result.protected_endpoints)}")
   print(f"Total rules applied: {validation_result.rule_count}")
   ```

## Available Functions

### Security Hardening Module

```python
from admin.security.incident_response_kit.recovery import security_hardening
```

#### Web Application Hardening Functions

- **`harden_application()`** - Apply comprehensive hardening to web application
  - Parameters:
    - `target`: Target application name
    - `application_type`: Type of application (web, api, mobile-api)
    - `components`: List of hardening components to apply
    - `configuration_file`: Path to hardening configuration
    - `incident_id`: Associated incident ID
    - `backup_configurations`: Whether to backup existing configs
    - `verify_after_hardening`: Whether to verify changes
    - `generate_report`: Whether to generate hardening report
    - `report_path`: Where to save the report
  - Returns: Hardening result object with details

- **`apply_security_headers()`** - Configure security headers for application
  - Parameters:
    - `target`: Target application name
    - `headers_config`: Security header configuration
    - `environments`: Target environments
    - `backup_config`: Whether to backup existing config
  - Returns: Header application result with status

- **`implement_input_validation()`** - Add input validation to application
  - Parameters:
    - `target`: Target application name
    - `validation_config`: Validation rule configuration
    - `test_validation`: Whether to test validation rules
    - `backup_existing`: Whether to backup existing validation
  - Returns: Validation implementation result

- **`configure_output_encoding()`** - Set up context-specific output encoding
  - Parameters:
    - `target`: Target application name
    - `encoding_config`: Output encoding configuration
    - `validate_implementation`: Whether to validate encoding
    - `generate_tests`: Whether to generate encoding tests
  - Returns: Encoding configuration result

- **`harden_authentication()`** - Apply authentication security improvements
  - Parameters:
    - `target`: Target application name
    - `auth_config`: Authentication hardening configuration
    - `affected_components`: List of components to harden
    - `verify_changes`: Whether to verify hardening
  - Returns: Authentication hardening result

- **`secure_session_management()`** - Improve session security
  - Parameters:
    - `target`: Target application name
    - `session_config`: Session security configuration
    - `backup_config`: Whether to backup existing config
    - `test_changes`: Whether to test changes
  - Returns: Session security result

- **`enhance_access_control()`** - Strengthen access control mechanisms
  - Parameters:
    - `target`: Target application name
    - `access_config`: Access control configuration
    - `verify_implementation`: Whether to verify implementation
    - `generate_tests`: Whether to generate test cases
  - Returns: Access control enhancement result

- **`secure_api_endpoints()`** - Enhance API security
  - Parameters:
    - `target`: Target API name
    - `api_security_config`: API security configuration
    - `test_security`: Whether to test security changes
    - `backup_config`: Whether to backup existing config
  - Returns: API security result

- **`secure_dependencies()`** - Implement dependency security
  - Parameters:
    - `target`: Target application name
    - `dependency_config`: Dependency security configuration
    - `scan_dependencies`: Whether to scan dependencies
    - `update_vulnerable`: Whether to update vulnerable dependencies
  - Returns: Dependency security result

### Core Security Module

```python
from core.security import security_headers, input_validation, output_encoding
from core.security import authentication, session_management, access_control
from core.security import api_security, dependency_management
```

#### Security Header Functions

- **`create_security_headers_config()`** - Create security header configuration
  - Parameters:
    - `application`: Target application name
    - `content_security_policy`: CSP policy string
    - `x_frame_options`: X-Frame-Options header value
    - [Additional security header parameters...]
  - Returns: Security headers configuration object

- **`apply_security_headers()`** - Apply security headers to environment
  - Parameters:
    - config: Headers configuration object
    - `environment`: Target environment
  - Returns: Application result

- **`validate_headers()`** - Validate security headers implementation
  - Parameters:
    - `target_url`: URL to validate
    - `expected_config`: Expected header configuration
  - Returns: Validation result

#### Input Validation Functions

- **`create_validation_schema()`** - Create input validation schema
  - Parameters:
    - `endpoint_patterns`: List of endpoint patterns
    - `validation_rules`: List of validation rules
    - `security_settings`: Security-related settings
  - Returns: Validation schema object

- **`apply_validation_schema()`** - Apply validation schema to application
  - Parameters:
    - `schema`: Validation schema object
    - `application`: Target application
    - `backup_existing`: Whether to backup existing schemas
  - Returns: Application result

#### Security Constants

```python
from core.security.cs_constants import (
    ApplicationType, HardeningComponent, ServerType, TLSVersion,
    AuthMethod, SessionStorage, AccessControlModel, DependencySeverity
)
```

- **`ApplicationType`** - Types of applications
  - `WEB`: Web application
  - API: API service
  - `MOBILE_API`: Mobile backend API
  - `MICROSERVICE`: Microservice component
  - `ADMIN_INTERFACE`: Administrative interface

- **`HardeningComponent`** - Security hardening components
  - `SECURITY_HEADERS`: HTTP security headers
  - `INPUT_VALIDATION`: Input validation controls
  - `OUTPUT_ENCODING`: Output encoding mechanisms
  - `AUTHENTICATION`: Authentication systems
  - `SESSION_MANAGEMENT`: Session handling mechanisms
  - `ACCESS_CONTROL`: Authorization components
  - `API_SECURITY`: API-specific security
  - `DEPENDENCY_SECURITY`: Dependency management

- **`ServerType`** - Web server types
  - `APACHE`: Apache HTTP server
  - `NGINX`: NGINX web server
  - `IIS`: Internet Information Services
  - `TOMCAT`: Apache Tomcat
  - `NODEJS`: Node.js server

- **`TLSVersion`** - TLS protocol versions
  - `TLS_1_0`: TLS version 1.0
  - `TLS_1_1`: TLS version 1.1
  - `TLS_1_2`: TLS version 1.2
  - `TLS_1_3`: TLS version 1.3

- **`AuthMethod`** - Authentication methods
  - `PASSWORD`: Standard password authentication
  - `JWT`: JSON Web Token authentication
  - `OAUTH2`: OAuth 2.0 authentication
  - `API_KEY`: API key authentication
  - `CERTIFICATE`: Client certificate authentication
  - `SAML`: SAML-based authentication
  - `OIDC`: OpenID Connect authentication

## Best Practices & Security

- **Defense in Depth**: Implement multiple security controls at different layers
- **Secure by Default**: Configure applications with security enabled by default
- **Least Privilege**: Apply the principle of least privilege to all access controls
- **Fail Closed**: Design security controls to fail securely (deny by default)
- **Input Validation**: Validate all input at server side regardless of client validation
- **Output Encoding**: Always apply context-specific output encoding
- **Secure Headers**: Configure appropriate security headers for all responses
- **Authentication Security**: Implement strong authentication mechanisms
- **Session Protection**: Secure session handling with appropriate timeouts
- **Dependency Management**: Keep dependencies updated and regularly scan for vulnerabilities
- **Configuration Security**: Store security configuration securely
- **Testing Rigor**: Test all security implementations against bypass attempts
- **Change Validation**: Validate all security changes for effectiveness
- **Documentation**: Document all security implementations and configurations
- **Progressive Enhancement**: Implement core security controls immediately, enhance incrementally
- **Regular Review**: Schedule periodic reviews of security configurations
- **Threat Monitoring**: Implement monitoring for security control bypass attempts
- **Security APIs**: Use secure, well-tested security libraries and frameworks
- **Error Handling**: Implement secure error handling that doesn't leak sensitive information
- **API Security**: Secure API endpoints with appropriate authentication and authorization
- **TLS Configuration**: Use modern TLS protocols and secure cipher configurations

## Related Documentation

- WAF Rule Development Guide - Guide for developing WAF rules
- Traffic Analysis Guide - Network traffic analysis procedures
- Denial of Service Response Playbook - DoS incident response
- Web Application Attack Response Playbook - Web attack response
- Security Hardening Profiles - Security hardening templates
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/) - Top web application security risks
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) - Security requirements
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) - HTTP security headers
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security) - Web security best practices
- [Content Security Policy Reference](https://content-security-policy.com/) - CSP implementation guide
