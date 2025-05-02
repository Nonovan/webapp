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

- **`celery_app.py`**: Celery task queue integration
  - **Usage**: Provides distributed task processing capabilities
  - **Features**:
    - Task queue configuration with Redis broker
    - Flask application context integration for tasks
    - Automatic task failure/success tracking
    - Task time limit enforcement
    - Task event monitoring
    - Worker management configuration
    - Scheduled tasks support
    - Security settings for task broker

- **`circuit_breaker.py`**: Protection against cascading failures and rate limiting
  - **Usage**: Prevents system overload during service disruptions and protects APIs
  - **Features**:
    - **Circuit Breaker Pattern**:
      - Configurable failure thresholds and recovery timeouts
      - Half-open state testing for graceful recovery
      - Circuit state tracking and statistics
      - Decorator-based usage for easy integration
      - Admin endpoints for monitoring and management
      - CLI commands for circuit management
    - **Rate Limiting**:
      - Multiple rate limiting strategies (fixed-window, sliding-window, token-bucket)
      - Redis-based storage for distributed environments
      - Memory fallback when Redis is unavailable
      - Automatic rate limit headers in responses
      - Custom key functions for flexible limiting policies
      - Comprehensive metrics for monitoring

## Directory Structure

```plaintext
extensions/
├── __init__.py           # Extension initialization and configuration
├── metrics.py            # Metrics collection and configuration
├── socketio.py           # Socket.IO server and real-time communication
├── celery_app.py         # Celery task queue integration
├── circuit_breaker.py    # Circuit breaker and rate limiting implementation
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

[Celery]
CELERY_BROKER_URL=redis://localhost:6379/0  # Task broker URL (default: Redis)
CELERY_RESULT_BACKEND=redis://localhost:6379/0  # Result backend URL
CELERY_ALWAYS_EAGER=False           # Run tasks synchronously (for testing)
CELERY_EAGER_PROPAGATES=False       # Propagate exceptions in eager mode
CELERY_MAX_TASKS_PER_CHILD=1000     # Max tasks per worker before restart
CELERY_PREFETCH_MULTIPLIER=4        # Number of tasks to prefetch
CELERY_TASK_ACKS_LATE=True          # Acknowledge task after execution
CELERY_DEFAULT_QUEUE=default        # Default task queue name
CELERY_TASK_TIME_LIMIT=3600         # Task time limit in seconds (1 hour)
CELERY_TASK_SOFT_TIME_LIMIT=3300    # Soft time limit (55 minutes)
CELERY_SEND_TASK_EVENTS=True        # Send task events for monitoring
CELERY_TRACK_STARTED=True           # Track when tasks are started
CELERY_BROKER_USE_SSL=False         # Use SSL for broker communication
CELERY_BROKER_SSL_CONFIG={}         # SSL configuration dictionary if needed

[GeoIP]
GEOIP_DB_PATH=/path/to/geoip.mmdb   # Path to MaxMind GeoIP database file
GEOLOCATION_ENABLED=True            # Enable geolocation features
GEOLOCATION_API=ipapi              # Geolocation API to use (ipapi or ipinfo)
GEOLOCATION_USE_HTTPS=False         # Use HTTPS for geolocation API calls
GEOLOCATION_RATE_LIMIT=60           # API call rate limit per minute
IPAPI_KEY=                         # API key for ip-api.com (for pro accounts)
IPINFO_API_KEY=                    # API key for ipinfo.io

[Circuit Breaker]
CIRCUIT_BREAKER_ADMIN_ENABLED=True  # Enable admin endpoints for circuit breaker
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5 # Default failure threshold before opening circuit
CIRCUIT_BREAKER_RESET_TIMEOUT=60.0  # Default seconds before resetting failure count
CIRCUIT_BREAKER_HALF_OPEN_AFTER=30.0 # Default seconds before trying test request
CIRCUIT_BREAKERS={}                 # Preconfigured circuit breakers dictionary

[Rate Limiting]
RATELIMIT_ENABLED=True              # Enable rate limiting
RATELIMIT_STORAGE_URL=              # Redis URL for rate limit storage (uses REDIS_URL if not set)
RATELIMIT_STRATEGY=fixed-window     # Rate limiting strategy (fixed-window, sliding-window, token-bucket)
RATELIMIT_HEADERS_ENABLED=True      # Add rate limit headers to responses
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
- Configure Celery task time limits to prevent runaway tasks
- Use SSL for Celery broker in production environments
- Define focused tasks with clear failure handling
- Apply rate limits to public endpoints to prevent abuse
- Configure appropriate circuit breaker thresholds based on service SLAs

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
- Distributed task processing with monitoring
- Background task scheduling
- Task retries with exponential backoff
- Circuit breaking for service protection
- Rate limiting for API protection
- Tamper-resistant logging mechanisms

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

### Apply Circuit Breaker

```python
from extensions import circuit_breaker, CircuitOpenError

# Create a circuit breaker with custom parameters
@circuit_breaker("external_api", failure_threshold=5, reset_timeout=60.0, half_open_after=30.0)
def call_external_service(data):
    # Code that might fail due to service issues
    response = requests.post("https://api.example.com/endpoint", json=data)
    response.raise_for_status()
    return response.json()

# Handle circuit breaker errors
try:
    result = call_external_service(data)
except CircuitOpenError:
    # Handle service unavailable case
    result = get_cached_fallback()
```

### Create and Manage Circuit Breakers

```python
from extensions import create_circuit_breaker, reset_circuit, get_all_circuits

# Create a named circuit breaker
api_circuit = create_circuit_breaker(
    "payment_gateway",
    failure_threshold=3,
    reset_timeout=120.0
)

# Apply the circuit breaker to a function
@api_circuit
def process_payment(payment_data):
    # Payment processing logic
    pass

# Reset a circuit breaker after issues are resolved
reset_circuit("payment_gateway")

# Get status of all circuit breakers
circuit_states = get_all_circuits()
for name, state in circuit_states.items():
    print(f"Circuit {name}: {state['state']}, Failures: {state.get('failures', 0)}")
```

### Apply Rate Limiting

```python
from extensions import rate_limit, RateLimitExceededError

# Simple rate limiting decorator
@rate_limit("10 per minute")
def limited_function():
    return "This function is rate limited"

# Use custom key function and parameters
from extensions import get_user_id, get_ip_address, get_api_key

@rate_limit("5 per minute", key_function=get_user_id)
def user_specific_function():
    return "Limited per user"

# Create a custom limiter
from extensions import create_limiter, TOKEN_BUCKET

api_limiter = create_limiter(
    name="api_calls",
    limit=100,
    window=60,
    strategy=TOKEN_BUCKET
)

@rate_limit(api_limiter)
def api_function():
    return "API response"

# Handle rate limit exceptions
try:
    result = api_function()
except RateLimitExceededError:
    return "Rate limit exceeded, please try again later"
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

### Use Celery for Background Tasks

```python
from extensions.celery_app import celery

# Define a task
@celery.task(bind=True, max_retries=3, rate_limit='10/m')
def process_data_task(self, data_id):
    try:
        # Process data
        result = process_complex_data(data_id)
        return result
    except TemporaryError as e:
        # Retry with exponential backoff
        self.retry(exc=e, countdown=60 * 2 ** self.request.retries)

# Call the task asynchronously
task_result = process_data_task.delay(data_id=123)

# Check task status
task_id = task_result.id
status = process_data_task.AsyncResult(task_id).status

# Schedule a periodic task (in CELERY_BEAT_SCHEDULE config)
CELERY_BEAT_SCHEDULE = {
    'cleanup-expired-data': {
        'task': 'app.tasks.maintenance.cleanup_expired_data',
        'schedule': 3600.0,  # Every hour
        'args': (),
    },
}
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

## Related Documentation

- [Flask Application Factory Pattern](https://flask.palletsprojects.com/en/2.0.x/patterns/appfactories/)
- [Flask Extensions Documentation](https://flask.palletsprojects.com/en/2.0.x/extensions/)
- [Flask-SocketIO Documentation](https://flask-socketio.readthedocs.io/)
- [Prometheus Python Client](https://github.com/prometheus/client_python)
- [Redis-py Documentation](https://redis-py.readthedocs.io/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)
- [MaxMind GeoIP2 Documentation](https://maxmind.github.io/GeoIP2-python/)
- [Socket.IO Documentation](https://socket.io/docs/v4/)
- [Celery Documentation](https://docs.celeryproject.org/)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Rate Limiting Patterns](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)

## Extending the Extensions

When adding new extensions:

1. Import and initialize the extension in `init.py`
2. Add extension to `__all__` list for easy importing
3. Include configuration in the `init_extensions` function
4. Update this README with new functionality
5. Add appropriate tests in the `tests/extensions` directory
6. Ensure metrics tracking is implemented for the extension
7. Add appropriate error handling and circuit breakers
8. Document security considerations specific to the extension
