from datetime import timedelta
from typing import Dict, Any, List
import os

class Config:
    # Required environment variables
    REQUIRED_VARS: List[str] = [
        'SECRET_KEY',
        'DATABASE_URL', 
        'JWT_SECRET_KEY',
        'CSRF_SECRET_KEY',
        'SESSION_KEY'
    ]

    # Environment defaults
    ENV_DEFAULTS: Dict[str, Any] = {
        'ENVIRONMENT': 'development',
        'DEBUG': False,
        'TESTING': False,
        'LOG_LEVEL': 'INFO'
    }

    @classmethod 
    def load(cls) -> Dict[str, Any]:
        """Load and validate configuration."""
        # Validate required variables
        missing = [var for var in cls.REQUIRED_VARS if not os.getenv(var)]
        if missing:
            raise RuntimeError(f"Missing required config vars: {', '.join(missing)}")

        return {
            # Environment
            'ENVIRONMENT': os.getenv('ENVIRONMENT', cls.ENV_DEFAULTS['ENVIRONMENT']),
            'DEBUG': os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
            'TESTING': cls.ENV_DEFAULTS['TESTING'],
            
            # Security
            'SECRET_KEY': os.getenv('SECRET_KEY'),
            'WTF_CSRF_SECRET_KEY': os.getenv('CSRF_SECRET_KEY'),
            'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY'),
            'PERMANENT_SESSION_LIFETIME': timedelta(days=int(os.getenv('SESSION_DAYS', '1'))),
            
            # Database
            'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL'),
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'SQLALCHEMY_POOL_SIZE': int(os.getenv('DB_POOL_SIZE', '5')),
            'SQLALCHEMY_POOL_TIMEOUT': int(os.getenv('DB_POOL_TIMEOUT', '30')),
            
            # Cache
            'REDIS_URL': os.getenv('REDIS_URL', 'redis://localhost:6379'),
            'CACHE_TYPE': 'redis',
            'CACHE_DEFAULT_TIMEOUT': int(os.getenv('CACHE_TIMEOUT', '300')),
            
            # Logging and Monitoring
            'LOG_LEVEL': os.getenv('LOG_LEVEL', cls.ENV_DEFAULTS['LOG_LEVEL']),
            'SENTRY_DSN': os.getenv('SENTRY_DSN'),
            'METRICS_ENABLED': os.getenv('METRICS_ENABLED', 'True').lower() == 'true',
            'STATSD_HOST': os.getenv('STATSD_HOST', 'localhost'),
            'STATSD_PORT': int(os.getenv('STATSD_PORT', '8125'))
        }

    @staticmethod
    def load_from_name(name: str) -> Dict[str, Any]:
        """Load configuration by environment name."""
        configs = {
            'development': {
                'DEBUG': True,
                'TESTING': False
            },
            'production': {
                'DEBUG': False,
                'TESTING': False
            },
            'testing': {
                'DEBUG': False,
                'TESTING': True
            }
        }
        
        if name not in configs:
            raise ValueError(f"Unknown configuration name: {name}")
            
        return configs[name]