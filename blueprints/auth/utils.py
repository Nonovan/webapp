import re
from datetime import datetime, timedelta
from functools import wraps
from flask import current_app, session, request, redirect, abort
import jwt
from extensions import limiter, cache, metrics

def validate_input(text: str) -> bool:
    """Validate and sanitize general text input."""
    if not text or not isinstance(text, str):
        return False
    text = text.strip()
    return bool(re.match(r'^[\w\s-]{1,100}$', text))

def validate_password(password: str) -> tuple[bool, str | None]:
    """Enhanced password strength validation."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not re.search("[a-z]", password):
        return False, "Must include lowercase letter"
    if not re.search("[A-Z]", password):
        return False, "Must include uppercase letter" 
    if not re.search("[0-9]", password):
        return False, "Must include number"
    if not re.search("[^A-Za-z0-9]", password):
        return False, "Must include special character"
    return True, None

def generate_token(user_id: int, role: str, expires_in: int = 3600) -> str:
    """Generate JWT token with role and expiration."""
    try:
        token = jwt.encode(
            {
                'user_id': user_id,
                'role': role,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(seconds=expires_in)
            },
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        metrics.increment('token_generation_total')
        return token
    except Exception as e:
        current_app.logger.error(f"Token generation failed: {e}")
        metrics.increment('token_generation_error')
        raise

@cache.memoize(timeout=300)
def verify_token(token: str) -> dict | None:
    """Verify JWT token with caching."""
    try:
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        metrics.increment('token_verification_success')
        current_app.logger.info(f'Token verified for user {payload.get("user_id")}')
        return payload
    except jwt.ExpiredSignatureError:
        metrics.increment('token_verification_expired')
        current_app.logger.warning('Expired token detected')
        return None
    except jwt.InvalidTokenError as e:
        metrics.increment('token_verification_invalid')
        current_app.logger.warning(f'Invalid token: {e}')
        return None

def require_role(role):
    """Require specific role for access."""
    def decorator(f):
        @wraps(f)
        @limiter.limit("30/minute")
        def decorated_function(*args, **kwargs):
            if not session.get('role') == role:
                current_app.logger.warning(f'Unauthorized access attempt: {request.url}')
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def login_required(f):
    """Enhanced login requirement check."""
    @wraps(f)
    @limiter.limit("60/minute")
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            current_app.logger.warning(f'Unauthenticated access attempt: {request.url}')
            return redirect('/auth/login')
        if datetime.utcnow() - datetime.fromisoformat(session['last_active']) > timedelta(minutes=30):
            session.clear()
            current_app.logger.warning('Session expired')
            return redirect('/auth/login')
        session['last_active'] = datetime.utcnow().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(limit="5/minute"):
    """Apply rate limiting to routes."""
    return limiter.limit(limit)

def sanitize_input(text):
    """Sanitize user input."""
    if not text or not isinstance(text, str):
        return ""
    return re.sub(r'[<>\'";]', '', text.strip())
