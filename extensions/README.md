# Flask Extensions

## Overview

The extensions module centralizes Flask extension initialization and configuration for the Cloud Infrastructure Platform. It manages database connectivity, authentication, security features, caching, metrics collection, and other core application services. This modular approach allows for consistent configuration across different application components while maintaining separation of concerns.

## Key Components

- **`__init__.py`**: Core extension initialization and configuration
  - **Usage**: Central initialization point for all Flask extensions
  - **Features**:
    - Lazy initialization pattern for Flask extensions
    - Redis client factory with connection pooling
    - Unified extension initialization function
    - Prometheus metrics configuration
    - GeoIP client for IP geolocation
    - Exception tracking and monitoring

- **`metrics.py`**: Application metrics collection utilities
  - **Usage**: Use this file to define custom metrics and monitoring integration
  - **Features**:
    - Counter, gauge, histogram, and summary metrics
    - Request latency tracking and performance monitoring
    - Database query performance metrics
    - Cloud resource tracking
    - Security event monitoring
    - System health metrics and dependency tracking
    - Circuit breaker pattern for error handling
    - Task execution monitoring

- **`socketio.py`**: Real-time communication functionality
  - **Usage**: Provides WebSocket-based real-time communication
  - **Features**:
    - Socket.IO server implementation
    - Event-based communication
    - Connection management and monitoring
    - Redis-based message queues for horizontal scaling
    - Automatic metrics collection for real-time events
    - Error handling and error rate tracking

## Directory Structure

```plaintext
extensions/
├── __init__.py           # Extension initialization and configuration
├── metrics.py            # Metrics collection and configuration
├── socketio.py           # Socket.IO server and real-time communication
└── README.md             # This documentation
```

## Configuration

The extensions module supports the following configuration options:

```ini
[Redis]
REDIS_URL=redis://localhost:6379/0  # Redis connection URI (preferred method)
REDIS_HOST=localhost                # Redis host (used if REDIS_URL not specified)
REDIS_PORT=6379                     # Redis port
REDIS_DB=0                          # Redis database number
REDIS_PASSWORD=secret               # Redis password for authentication
REDIS_SSL=False                     # Whether to use SSL for Redis connection
REDIS_SOCKET_TIMEOUT=5              # Socket timeout in seconds
REDIS_SOCKET_CONNECT_TIMEOUT=5      # Socket connection timeout in seconds
REDIS_HEALTH_CHECK_INTERVAL=30      # Health check interval in seconds

[Security]
SECURITY_HEADERS_ENABLED=True       # Enable security headers via Talisman
FORCE_HTTPS=True                    # Force HTTPS in production
STRICT_TRANSPORT_SECURITY=True      # Enable HSTS headers
HSTS_PRELOAD=False                  # Enable HSTS preloading
REFERRER_POLICY=strict-origin-when-cross-origin  # Referrer policy setting
CONTENT_SECURITY_POLICY={}          # CSP configuration dictionary

[Metrics]
METRICS_AUTH_ENABLED=False          # Enable authentication for metrics endpoint
METRICS_USERNAME=prometheus         # Username for metrics authentication
METRICS_PASSWORD=secret             # Password for metrics authentication
METRICS_ENDPOINT_PATH=/metrics      # Custom path for metrics endpoint
METRICS_REGISTER_VIEWS=True         # Whether to register metrics views
METRICS_PREFIX=cloud_platform       # Prefix for all metrics names
METRICS_ENABLED=True                # Enable metrics collection

[SocketIO]
SOCKETIO_CORS_ALLOWED_ORIGINS=*     # CORS allowed origins for Socket.IO
SOCKETIO_ASYNC_MODE=eventlet        # Async mode (eventlet, gevent, threading)
SOCKETIO_MESSAGE_QUEUE=             # Optional message queue URI (uses REDIS_URL if not set)

[GeoIP]
GEOIP_DB_PATH=/path/to/geoip.mmdb   # Path to MaxMind GeoIP database file
```

## Best Practices & Security

- Initialize extensions in the recommended order using `init_extensions(app)`
- Configure proper CORS settings in production environments
- Enable security headers in production
- Use environment variables for sensitive configuration
- Configure rate limiting appropriate to application needs
- Use the Redis client factory to ensure proper connection pooling
- Follow the principle of least privilege for all connections
- Ensure metrics are properly labeled for effective monitoring
- Implement circuit breaker patterns for external service calls
- Use secure WebSocket connections in production environments
- Apply authentication for real-time communication
- Keep GeoIP database updated regularly

## Common Features

- Lazy initialization of extensions to support application factory pattern
- Consistent metrics naming and labeling
- Robust error handling for external services
- Redis connection pooling for improved performance
- Comprehensive security headers configuration
- Performance monitoring with detailed metrics
- Automatic tracking of important system parameters
- Real-time event broadcasting and monitoring
- IP geolocation services for security and analytics

## Usage

### Initialize All Extensions

```python
from flask import Flask
from extensions import init_extensions

app = Flask(__name__)
app.config.from_object('config.ProductionConfig')
init_extensions(app)
```

### Access Individual Extensions

```python
from extensions import db, jwt, cache

# Use the SQLAlchemy extension
users = db.session.query(User).all()

# Use the JWT extension
token = jwt.create_access_token(identity=user_id)

# Use the cache extension
result = cache.get('expensive_operation_result')
```

### Use Redis Client

```python
from extensions import get_redis_client

redis_client = get_redis_client()
redis_client.set('key', 'value')
value = redis_client.get('key')
```

### Track Custom Metrics

```python
from extensions import metrics, db_query_counter
from flask import g

# Set context for database metrics
g.db_operation = 'select'
g.db_model = 'User'
g.db_status = 'success'

# Increment counter with current context
db_query_counter.inc()
```

### Monitor Task Performance

```python
from extensions.metrics import monitor_task_execution

@monitor_task_execution('data_processing')
def process_data(data):
    # Processing logic here
    return processed_data
```

### Track System Health

```python
from extensions.metrics import update_system_health, update_dependency_health

# Update component health status (0-1 scale)
update_system_health('database', 'connection_pool', 0.95)

# Record dependency availability
update_dependency_health('redis_cache', True, 'production')
```

### Track Security Events

```python
from extensions.metrics import track_security_event

# Record security events with appropriate severity
track_security_event('failed_login_attempt', 'warning')
track_security_event('unauthorized_access', 'critical')
```

### Time Function Execution

```python
from extensions.metrics import timed

@timed('user_validation')
def validate_user_permissions(user_id, resource):
    # Validation logic here
    return is_authorized
```

### Use Socket.IO for Real-time Communication

```python
from extensions.socketio import socketio

# Define Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('message')
def handle_message(data):
    # Process received message
    print('Received message:', data)

    # Send response back to client
    return {'status': 'received'}

# Broadcast to all clients
socketio.emit('update', {'data': 'New data available'})

# Broadcast with metrics tracking
from extensions import emit_with_metrics
emit_with_metrics('status_update', {'status': 'operational'})
```

### Use GeoIP Services

```python
from extensions import geoip

# Get location information from an IP address
ip_address = request.remote_addr
location = geoip['get_location'](ip_address)

if location:
    print(f"User location: {location['city']}, {location['country']}")

    # Use for security or analytics
    if location['country'] in restricted_countries:
        log_security_event('restricted_country_access', ip_address)
```

## Related Docs & Extending

- [Flask Application Factory Pattern](https://flask.palletsprojects.com/en/2.0.x/patterns/appfactories/)
- [Flask Extensions Documentation](https://flask.palletsprojects.com/en/2.0.x/extensions/)
- [Flask-SocketIO Documentation](https://flask-socketio.readthedocs.io/)
- [Prometheus Python Client](https://github.com/prometheus/client_python)
- [Redis-py Documentation](https://redis-py.readthedocs.io/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)
- [MaxMind GeoIP2 Documentation](https://maxmind.github.io/GeoIP2-python/)
- [Socket.IO Documentation](https://socket.io/docs/v4/)

When adding new extensions:

1. Import and initialize the extension in **init__.py**
2. Add extension to `__all__` list for easy importing
3. Include configuration in the `init_extensions` function
4. Update this README with new functionality
5. Add appropriate tests in the `tests/extensions` directory
6. Ensure metrics tracking is implemented for the extension
7. Add appropriate error handling and circuit breakers
8. Document security considerations specific to the extension
