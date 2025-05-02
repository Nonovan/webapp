"""
Flask extensions for the Cloud Infrastructure Platform.

This module initializes and configures all Flask extensions used in the application,
ensuring they're properly set up and available throughout the system.
"""

import logging
import os
from typing import Dict, Any, Optional, Callable, Union

import redis
from flask import Flask, request, g
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy

# Existing imports
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)

# Configure module logger
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()

# Initialize Redis client
redis_client = None

# Initialize GeoIP reader
geoip = None

# Import and initialize metrics
try:
    from .metrics import (
        metrics,
        db_query_counter,
        cloud_resource_gauge,
        socketio_connection_count,
        socketio_message_counter,
        socketio_error_counter,
        socketio_latency,
        emit_with_metrics
    )
except ImportError as e:
    logger.warning(f"Metrics module not available: {e}")
    metrics = None
    db_query_counter = None
    cloud_resource_gauge = None
    socketio_connection_count = None
    socketio_message_counter = None
    socketio_error_counter = None
    socketio_latency = None
    emit_with_metrics = None

# Import and initialize circuit breaker
try:
    from .circuit_breaker import (
        CircuitBreaker,
        CircuitBreakerState,
        CircuitOpenError,
        circuit_breaker,
        create_circuit_breaker,
        reset_circuit,
        reset_all_circuits,
        get_all_circuits,
        rate_limit,
        RateLimitExceededError,
        create_limiter,
        get_user_id,
        get_ip_address,
        get_api_key,
        get_combined_key,
        FIXED_WINDOW,
        SLIDING_WINDOW,
        TOKEN_BUCKET,
        init_app as init_circuit_breaker
    )
except ImportError as e:
    logger.warning(f"Circuit breaker module not available: {e}")
    CircuitBreaker = None
    CircuitBreakerState = None
    CircuitOpenError = None
    circuit_breaker = None
    create_circuit_breaker = None
    reset_circuit = None
    reset_all_circuits = None
    get_all_circuits = None
    rate_limit = None
    RateLimitExceededError = None
    create_limiter = None
    get_user_id = None
    get_ip_address = None
    get_api_key = None
    get_combined_key = None
    FIXED_WINDOW = None
    SLIDING_WINDOW = None
    TOKEN_BUCKET = None
    init_circuit_breaker = None

# Import and initialize cache
try:
    from flask_caching import Cache
    cache = Cache()
except ImportError as e:
    logger.warning(f"Cache module not available: {e}")
    cache = None

# Import and initialize Celery
try:
    from .celery_app import celery, init_celery
except ImportError as e:
    logger.warning(f"Celery module not available: {e}")
    celery = None
    init_celery = None

# Import and initialize Socket.IO
try:
    from .socketio import socketio, init_socketio
except ImportError as e:
    logger.warning(f"Socket.IO module not available: {e}")
    socketio = None
    init_socketio = None


def get_redis_client() -> Optional[redis.Redis]:
    """
    Get the Redis client instance.

    Returns:
        Redis client instance or None if not connected
    """
    return redis_client


def init_redis(app: Flask) -> None:
    """
    Initialize Redis connection.

    Args:
        app: Flask application
    """
    global redis_client

    redis_url = app.config.get('REDIS_URL')
    if not redis_url:
        app.logger.warning("Redis URL not configured. Rate limiting and session features will be limited.")
        return

    try:
        redis_client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=app.config.get('REDIS_TIMEOUT', 5),
            socket_connect_timeout=app.config.get('REDIS_CONNECT_TIMEOUT', 5),
            health_check_interval=app.config.get('REDIS_HEALTH_CHECK_INTERVAL', 30)
        )
        # Test the connection
        redis_client.ping()
        app.logger.info("Redis connection established successfully")
    except redis.RedisError as e:
        app.logger.error(f"Failed to connect to Redis: {e}")
        redis_client = None


def init_geoip(app: Flask) -> None:
    """
    Initialize GeoIP database reader.

    Args:
        app: Flask application
    """
    global geoip

    geoip_path = app.config.get('GEOIP_DB_PATH')
    if not geoip_path:
        app.logger.warning("GeoIP database path not configured. Geolocation features will be disabled.")
        return

    try:
        import geoip2.database
        import geoip2.errors

        if not os.path.exists(geoip_path):
            app.logger.warning(f"GeoIP database not found at {geoip_path}. Geolocation features will be disabled.")
            return

        geoip = {
            'reader': geoip2.database.Reader(geoip_path),
            'get_location': lambda ip: _get_location_from_ip(ip)
        }
        app.logger.info("GeoIP database loaded successfully")
    except ImportError as e:
        app.logger.warning(f"GeoIP module not available: {e}")
    except FileNotFoundError as e:
        app.logger.error(f"GeoIP database file error: {e}")
    except PermissionError as e:
        app.logger.error(f"GeoIP database permission error: {e}")
    except Exception as e:
        app.logger.error(f"Failed to initialize GeoIP: {e}")
        geoip = None


def _get_location_from_ip(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get location information from an IP address.

    Args:
        ip: IP address to geolocate

    Returns:
        Dictionary with location information or None if not found
    """
    if not geoip or not geoip.get('reader'):
        return None

    try:
        import geoip2.errors

        response = geoip['reader'].city(ip)
        return {
            'city': response.city.name,
            'country': response.country.iso_code,
            'country_name': response.country.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except geoip2.errors.AddressNotFoundError:
        # IP address not found in database
        logger.debug(f"IP address not found in GeoIP database: {ip}")
        return None
    except ValueError:
        # Invalid IP address format
        logger.warning(f"Invalid IP address format for GeoIP lookup: {ip}")
        return None
    except Exception as e:
        logger.error(f"Error looking up IP location: {e}")
        return None


def init_extensions(app: Flask) -> None:
    """
    Initialize all Flask extensions with the app.

    Args:
        app: Flask application
    """
    # Initialize SQLAlchemy
    db.init_app(app)

    # Initialize JWT
    jwt.init_app(app)

    # Initialize Redis
    init_redis(app)

    # Initialize GeoIP
    init_geoip(app)

    # Initialize Cache if available
    if cache:
        cache.init_app(app)

    # Initialize Celery if available
    if init_celery:
        init_celery(app)

    # Initialize limiter
    limiter.init_app(app)

    # Initialize metrics if available
    if metrics and hasattr(metrics, 'init_app'):
        metrics.init_app(app)

    # Initialize Socket.IO if available
    if socketio and init_socketio:
        init_socketio(app)

    # Initialize circuit breaker and rate limiting if available
    if init_circuit_breaker:
        init_circuit_breaker(app)

    # Log successful initialization
    app.logger.info("All extensions initialized successfully")


__all__ = [
    # Core extensions
    'db',
    'jwt',
    'cache',
    'limiter',
    'metrics',
    'celery',
    'socketio',

    # Utility functions
    'get_redis_client',
    'init_extensions',

    # Metrics
    'db_query_counter',
    'cloud_resource_gauge',
    'socketio_connection_count',
    'socketio_message_counter',
    'socketio_error_counter',
    'socketio_latency',
    'emit_with_metrics',

    # Circuit breaker
    'CircuitBreaker',
    'CircuitBreakerState',
    'CircuitOpenError',
    'circuit_breaker',
    'create_circuit_breaker',
    'reset_circuit',
    'reset_all_circuits',
    'get_all_circuits',

    # Rate limiting
    'rate_limit',
    'RateLimitExceededError',
    'create_limiter',
    'get_user_id',
    'get_ip_address',
    'get_api_key',
    'get_combined_key',
    'FIXED_WINDOW',
    'SLIDING_WINDOW',
    'TOKEN_BUCKET',

    # GeoIP
    'geoip'
]
