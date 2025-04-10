import os
from core.config import Config as CoreConfig

class BaseConfig(CoreConfig):
    """Extended configuration with environment-specific settings"""

    @classmethod
    def load(cls, env='development'):
        # Get base config
        config = super().load()

        # Add environment-specific overrides
        env_config = {
            'development': {
                'DEBUG': True,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': False,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DEV_DATABASE_URL')
            },
            'production': {
                'DEBUG': False,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': True,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL')
            },
            'testing': {
                'DEBUG': False,
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'SESSION_COOKIE_SECURE': False,
                'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'
            },
            'staging': {
                'DEBUG': False,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': True,
                'CACHE_TYPE': 'redis',
                'SQLALCHEMY_DATABASE_URI': os.getenv('STAGING_DATABASE_URL'),
                'CELERY_BROKER_URL': os.getenv('STAGING_REDIS_URL'),
                'SENTRY_ENVIRONMENT': 'staging'
            },
            'ci': {
                'DEBUG': False,
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'CACHE_TYPE': 'simple',
                'CELERY_ALWAYS_EAGER': True,
                'SQLALCHEMY_DATABASE_URI': 'postgresql://ci:ci@localhost/ci_test'
            }
        }

        # Update base config with environment settings
        config.update(env_config.get(env, env_config['development']))
        return config

config = BaseConfig
