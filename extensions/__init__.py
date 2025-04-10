from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_caching import Cache
from flask_mail import Mail
from flask_session import Session
from prometheus_flask_exporter import PrometheusMetrics

# Database - Required for models
db = SQLAlchemy()
migrate = Migrate()

# Security - Required for protection
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
cors = CORS()

# Performance - Required for scaling
cache = Cache(config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300
})

# Email
mail = Mail()

# Session handling - Required for auth
session = Session()

# Monitoring - Required for ops
metrics = PrometheusMetrics.for_app_factory()

__all__ = ['db', 'migrate', 'csrf', 'limiter', 'cors', 'cache', 'mail', 'session', 'metrics']
