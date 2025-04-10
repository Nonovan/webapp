from typing import Dict, Any
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

# Database extensions
db = SQLAlchemy()
migrate = Migrate()

# Security extensions
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
cors = CORS(
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=True
)

# Cache configuration
CACHE_CONFIG: Dict[str, Any] = {
    'CACHE_TYPE': 'redis',
    'CACHE_KEY_PREFIX': 'myapp_',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_REDIS_URL': 'redis://localhost:6379/0'
}
cache = Cache(config=CACHE_CONFIG)

# Email configuration
mail = Mail()

# Session configuration
session = Session()

# Metrics configuration
metrics = PrometheusMetrics.for_app_factory(
    app_name='myapp',
    path='/metrics',
    group_by=['endpoint', 'http_status']
)

__all__ = [
    'db',
    'migrate', 
    'csrf',
    'limiter',
    'cors',
    'cache',
    'mail',
    'session',
    'metrics'
]