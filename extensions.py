# Core extensions needed
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_session import Session
from prometheus_flask_exporter import PrometheusMetrics
from flask_cors import CORS

# Database - Required for models
db = SQLAlchemy()
migrate = Migrate()

# Security - Required for protection
csrf = CSRFProtect() 
cors = CORS()

# Performance - Required for scaling
cache = Cache(config={
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 300
})

# Session handling - Required for auth
session = Session()

# Monitoring - Required for ops
metrics = PrometheusMetrics.for_app_factory()

__all__ = ['db', 'migrate', 'csrf', 'cache', 'session', 'metrics', 'cors']
