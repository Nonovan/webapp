import os
from datetime import timedelta
from typing import Dict, Any

class Config:
    @classmethod
    def load(cls) -> Dict[str, Any]:
        """Centralized config loading with validation"""
        # Required environment variables
        required = ['SECRET_KEY', 'DATABASE_URL']
        missing = [var for var in required if not os.getenv(var)]
        if missing:
            raise RuntimeError(f"Missing required config vars: {', '.join(missing)}")

        # Base configuration
        config = {
            # Environment
            'ENVIRONMENT': os.getenv('ENVIRONMENT', 'development'),
            'DEBUG': os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
            'TESTING': False,
            
            # Security
            'SECRET_KEY': os.getenv('SECRET_KEY'),
            'WTF_CSRF_SECRET_KEY': os.getenv('CSRF_SECRET_KEY', os.urandom(32)),
            'PERMANENT_SESSION_LIFETIME': timedelta(days=int(os.getenv('SESSION_DAYS', 1))),
            
            # Database
            'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL'),
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'SQLALCHEMY_POOL_SIZE': int(os.getenv('DB_POOL_SIZE', 5)),
            
            # Cache
            'REDIS_URL': os.getenv('REDIS_URL', 'redis://localhost:6379'),
            'CACHE_TYPE': 'redis',
            'CACHE_DEFAULT_TIMEOUT': int(os.getenv('CACHE_TIMEOUT', 300)),
            
            # Logging
            'LOG_LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
            
            # Security Headers
            'SESSION_COOKIE_SECURE': True,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'REMEMBER_COOKIE_SECURE': True,
            
            # Rate Limiting
            'RATELIMIT_DEFAULT': '100/hour',
            'RATELIMIT_STORAGE_URL': os.getenv('REDIS_URL'),
            
            # API Versions
            'API_VERSIONS': ['v1', 'v2'],
            
            # Metrics
            'METRICS_ENABLED': os.getenv('METRICS_ENABLED', 'True').lower() == 'true',
            'STATSD_HOST': os.getenv('STATSD_HOST', 'localhost'),
            'STATSD_PORT': int(os.getenv('STATSD_PORT', 8125))
        }

        return config