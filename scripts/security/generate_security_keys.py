#!/usr/bin/env python3
"""Generate security keys for application configuration"""
import os
import secrets
import base64

# Generate a secure key for Flask sessions
secret_key = secrets.token_hex(32)
print(f"SECRET_KEY={secret_key}")

# Generate a JWT secret key
jwt_secret = secrets.token_hex(32)
print(f"JWT_SECRET_KEY={jwt_secret}")

# Generate an encryption key for sensitive data
encryption_key = base64.b64encode(os.urandom(32)).decode('utf-8')
print(f"ENCRYPTION_KEY={encryption_key}")