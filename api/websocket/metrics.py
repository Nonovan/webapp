"""
WebSocket metrics collection and monitoring for the Cloud Infrastructure Platform.

This module implements comprehensive metrics tracking for WebSocket connections
and message processing, including:
- Connection statistics (active connections, duration, disconnection reasons)
- Message throughput by type and channel
- Performance measurements (latency, processing time)
- Error monitoring and categorization
- Resource utilization tracking

These metrics integrate with the platform's core monitoring system to provide
real-time visibility into WebSocket performance and usage patterns.
"""

import time
import logging
import psutil
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Callable

from flask import current_app, request, has_app_context, g
from flask_socketio import emit

from extensions import metrics, cache
from core.metrics import track_metrics
from core.security import log_security_event
from core.security.cs_general_sec import RateLimiter

# Initialize logger
logger = logging.getLogger(__name__)

# Define metric retention periods (in seconds)
METRICS_RETENTION = {
    'high_frequency': 86400,     # 1 day for high-frequency metrics (e.g., messages)
    'medium_frequency': 604800,  # 1 week for medium-frequency metrics (e.g., commands)
    'low_frequency': 2592000     # 30 days for low-frequency metrics (e.g., connections)
}

# Metrics counters and gauges
ws_connection_count = metrics.gauge(
    'websocket_connections_active',
    'Current number of active WebSocket connections',
    labels=['channel', 'role'],
    multiprocess_mode='livesum'
)

ws_message_counter = metrics.counter(
    'websocket_messages_total',
    'Total WebSocket messages',
    labels=['event_type', 'channel', 'direction'],
    multiprocess_mode='livesum'
)

ws_error_counter = metrics.counter(
    'websocket_errors_total',
    'Total WebSocket errors',
    labels=['error_type', 'channel'],
    multiprocess_mode='livesum'
)

ws_latency = metrics.histogram(
    'websocket_message_latency_seconds',
    'WebSocket message processing latency in seconds',
    labels=['event_type'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

ws_subscription_gauge = metrics.gauge(
    'websocket_subscriptions_active',
    'Current number of active channel subscriptions',
    labels=['channel'],
    multiprocess_mode='livesum'
)

ws_connection_duration = metrics.histogram(
    'websocket_connection_duration_seconds',
    'Duration of WebSocket connections in seconds',
    labels=['role', 'disconnect_reason'],
    buckets=(1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200)
)

ws_auth_counter = metrics.counter(
    'websocket_auth_attempts_total',
    'Total WebSocket authentication attempts',
    labels=['status', 'has_mfa'],
    multiprocess_mode='livesum'
)

ws_resource_usage = metrics.gauge(
    'websocket_resource_usage',
    'Resource usage by WebSocket connections',
    labels=['resource_type'],  # cpu, memory, connections
    multiprocess_mode='livesum'
)


def track_connection(channel: str, role: str = 'user') -> None:
    """
    Track a new WebSocket connection.

    Args:
        channel: The channel being connected to
        role: User role making the connection
    """
    try:
        ws_connection_count.inc(1, labels={
            'channel': channel,
            'role': role
        })

        # Update resource metrics
        _update_resource_metrics()

    except Exception as e:
        logger.error(f"Error tracking WebSocket connection: {str(e)}", exc_info=True)


def track_disconnection(channel: str, role: str = 'user', duration_seconds: float = 0.0, reason: str = 'normal') -> None:
    """
    Track a WebSocket disconnection.

    Args:
        channel: The channel being disconnected from
        role: User role that was connected
        duration_seconds: How long the connection was active
        reason: Reason for disconnection
    """
    try:
        ws_connection_count.dec(1, labels={
            'channel': channel,
            'role': role
        })

        # Track connection duration
        ws_connection_duration.observe(duration_seconds, labels={
            'role': role,
            'disconnect_reason': reason
        })

        # Update resource metrics
        _update_resource_metrics()

    except Exception as e:
        logger.error(f"Error tracking WebSocket disconnection: {str(e)}", exc_info=True)


def track_message(event_type: str, channel: str, direction: str = 'received') -> None:
    """
    Track a WebSocket message.

    Args:
        event_type: Type of message/event
        channel: Channel the message was sent on
        direction: Direction of message (received/sent)
    """
    try:
        ws_message_counter.inc(1, labels={
            'event_type': event_type,
            'channel': channel,
            'direction': direction
        })
    except Exception as e:
        logger.error(f"Error tracking WebSocket message: {str(e)}", exc_info=True)


def track_error(error_type: str, channel: str = 'global') -> None:
    """
    Track a WebSocket error.

    Args:
        error_type: Type of error that occurred
        channel: Channel where the error occurred
    """
    try:
        ws_error_counter.inc(1, labels={
            'error_type': error_type,
            'channel': channel
        })

        # Log security events for specific error types
        if error_type in ('authentication_failure', 'permission_denied', 'rate_limit_exceeded', 'token_invalid'):
            log_security_event(
                event_type=f"websocket_{error_type}",
                description=f"WebSocket error: {error_type} on channel {channel}",
                severity='warning',
                user_id=g.get('user_id') if hasattr(g, 'user_id') else None,
                ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None,
                details={
                    'channel': channel,
                    'error_type': error_type
                }
            )
    except Exception as e:
        logger.error(f"Error tracking WebSocket error: {str(e)}", exc_info=True)


def track_latency(event_type: str, latency: float) -> None:
    """
    Track WebSocket message processing latency.

    Args:
        event_type: Type of message/event
        latency: Processing time in seconds
    """
    try:
        ws_latency.observe(latency, labels={
            'event_type': event_type
        })
    except Exception as e:
        logger.error(f"Error tracking WebSocket latency: {str(e)}", exc_info=True)


def track_subscription(channel: str, increment: bool = True) -> None:
    """
    Track channel subscription changes.

    Args:
        channel: Channel being subscribed to
        increment: True to increment the counter, False to decrement
    """
    try:
        if increment:
            ws_subscription_gauge.inc(1, labels={'channel': channel})
        else:
            ws_subscription_gauge.dec(1, labels={'channel': channel})
    except Exception as e:
        logger.error(f"Error tracking WebSocket subscription: {str(e)}", exc_info=True)


def track_authentication(status: str, has_mfa: bool = False) -> None:
    """
    Track WebSocket authentication attempts.

    Args:
        status: Authentication outcome (success/failure)
        has_mfa: Whether MFA was used
    """
    try:
        ws_auth_counter.inc(1, labels={
            'status': status,
            'has_mfa': str(has_mfa).lower()
        })

        # Log security events for authentication failures
        if status == 'failure':
            log_security_event(
                event_type="websocket_auth_failure",
                description="WebSocket authentication failure",
                severity='medium',
                user_id=g.get('user_id') if hasattr(g, 'user_id') else None,
                ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None
            )
    except Exception as e:
        logger.error(f"Error tracking WebSocket authentication: {str(e)}", exc_info=True)


@track_metrics('ws_metrics')
def get_metrics_summary() -> Dict[str, Any]:
    """
    Get a summary of WebSocket metrics for monitoring dashboards.

    Returns:
        Dictionary containing key WebSocket metrics
    """
    try:
        # Get high-level metrics summary
        return {
            'active_connections': _get_total_connections(),
            'message_rate': _get_message_rate(),
            'error_rate': _get_error_rate(),
            'avg_latency_ms': _get_average_latency() * 1000,  # Convert to ms
            'active_channels': _get_active_channels(),
            'p95_latency_ms': _get_percentile_latency(95) * 1000,  # Convert to ms
            'most_active_channel': _get_most_active_channel(),
            'resources': {
                'memory_mb': _get_memory_usage(),
                'cpu_percent': _get_cpu_usage()
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Error generating metrics summary: {str(e)}", exc_info=True)
        return {
            'error': 'Failed to generate metrics summary',
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def configure_metrics_retention() -> None:
    """
    Configure retention policies for WebSocket metrics.

    This applies appropriate retention periods based on metric type.
    """
    try:
        # Apply retention policy to counters (short-lived data)
        metrics.configure_retention(ws_message_counter, METRICS_RETENTION['high_frequency'])
        metrics.configure_retention(ws_error_counter, METRICS_RETENTION['medium_frequency'])
        metrics.configure_retention(ws_auth_counter, METRICS_RETENTION['medium_frequency'])

        # Apply retention policy to gauges (longer-lived data)
        metrics.configure_retention(ws_connection_count, METRICS_RETENTION['low_frequency'])
        metrics.configure_retention(ws_subscription_gauge, METRICS_RETENTION['low_frequency'])
        metrics.configure_retention(ws_resource_usage, METRICS_RETENTION['medium_frequency'])

        # Apply retention policy to histograms (mid-range retention)
        metrics.configure_retention(ws_latency, METRICS_RETENTION['medium_frequency'])
        metrics.configure_retention(ws_connection_duration, METRICS_RETENTION['medium_frequency'])

        logger.info("WebSocket metrics retention configured")

    except Exception as e:
        logger.error(f"Failed to configure metrics retention: {str(e)}", exc_info=True)


def emit_metrics(target_channel: str = 'metrics') -> Dict[str, Any]:
    """
    Emit current WebSocket metrics to the specified channel.

    Args:
        target_channel: Channel to send metrics to

    Returns:
        Dictionary of metrics data that was sent
    """
    try:
        # Collect metrics data
        metrics_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'connections': {
                'total': _get_total_connections(),
                'by_channel': _get_connections_by_channel(),
                'by_role': _get_connections_by_role()
            },
            'messages': {
                'total': _get_total_messages(),
                'by_type': _get_messages_by_type(),
                'rate': _get_message_rate()
            },
            'errors': {
                'total': _get_total_errors(),
                'by_type': _get_errors_by_type(),
                'rate': _get_error_rate()
            },
            'performance': {
                'avg_latency': _get_average_latency(),
                'p95_latency': _get_percentile_latency(95),
                'p99_latency': _get_percentile_latency(99)
            },
            'resources': {
                'memory_mb': _get_memory_usage(),
                'cpu_percent': _get_cpu_usage(),
                'connection_count': _get_total_connections()
            }
        }

        # Emit metrics to the specified channel
        if has_app_context():
            emit('metrics_update', metrics_data, namespace='/ws', room=target_channel)

        return metrics_data

    except Exception as e:
        logger.error(f"Error emitting WebSocket metrics: {str(e)}", exc_info=True)
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': 'Failed to collect metrics',
            'error_details': str(e)
        }


# --- Helper Functions ---

def _update_resource_metrics() -> None:
    """Update resource usage metrics for WebSocket connections."""
    try:
        # Get process memory usage
        process = psutil.Process()
        memory_mb = process.memory_info().rss / (1024 * 1024)  # Convert to MB

        # Update memory gauge
        ws_resource_usage.set(memory_mb, labels={'resource_type': 'memory_mb'})

        # Update CPU usage gauge (non-blocking CPU measurement)
        cpu_percent = process.cpu_percent(interval=None)
        ws_resource_usage.set(cpu_percent, labels={'resource_type': 'cpu_percent'})

        # Update connection count
        total_connections = _get_total_connections()
        ws_resource_usage.set(total_connections, labels={'resource_type': 'connections'})

    except ImportError:
        logger.debug("psutil not available, skipping detailed resource metrics")
    except Exception as e:
        logger.error(f"Error updating resource metrics: {str(e)}")


def _get_memory_usage() -> float:
    """Get current memory usage in MB."""
    try:
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)  # Convert to MB
    except (ImportError, Exception):
        return 0.0


def _get_cpu_usage() -> float:
    """Get current CPU usage percentage."""
    try:
        process = psutil.Process()
        return process.cpu_percent(interval=None)
    except (ImportError, Exception):
        return 0.0


def _get_total_connections() -> int:
    """Get total number of active connections."""
    try:
        # Get from routes module if available
        from .routes import active_connections
        return len(active_connections)
    except ImportError:
        # Fallback to metrics registry if routes not available
        return int(metrics.get_gauge_value(ws_connection_count) or 0)


def _get_connections_by_channel() -> Dict[str, int]:
    """Get active connections by channel."""
    try:
        from .routes import active_connections
        channels = {}
        for conn_data in active_connections.values():
            for channel in conn_data.get('channels', []):
                channels[channel] = channels.get(channel, 0) + 1
        return channels
    except ImportError:
        # Fallback to metrics registry
        connections = metrics.get_gauge_values(ws_connection_count, group_by='channel')
        return {k: int(v) for k, v in connections.items()}


def _get_connections_by_role() -> Dict[str, int]:
    """Get active connections by user role."""
    try:
        from .routes import active_connections
        roles = {}
        for conn_data in active_connections.values():
            role = conn_data.get('role', 'unknown')
            roles[role] = roles.get(role, 0) + 1
        return roles
    except ImportError:
        # Fallback to metrics registry
        connections = metrics.get_gauge_values(ws_connection_count, group_by='role')
        return {k: int(v) for k, v in connections.items()}


def _get_total_messages() -> int:
    """Get total count of WebSocket messages."""
    return int(metrics.get_counter_value(ws_message_counter) or 0)


def _get_messages_by_type() -> Dict[str, int]:
    """Get message counts by event type."""
    message_counts = metrics.get_counter_values(ws_message_counter, group_by='event_type')
    return {k: int(v) for k, v in message_counts.items() if k}


def _get_total_errors() -> int:
    """Get total count of WebSocket errors."""
    return int(metrics.get_counter_value(ws_error_counter) or 0)


def _get_errors_by_type() -> Dict[str, int]:
    """Get error counts by error type."""
    error_counts = metrics.get_counter_values(ws_error_counter, group_by='error_type')
    return {k: int(v) for k, v in error_counts.items() if k}


def _get_message_rate() -> float:
    """Get current message rate (messages per second)."""
    try:
        # Get from metrics library if rate function is available
        if hasattr(metrics, 'get_rate'):
            return metrics.get_rate(ws_message_counter, window_seconds=60) or 0.0
        # Fallback with cached values
        elif cache:
            current_count = _get_total_messages()
            prev_count = cache.get('ws_message_prev_count') or current_count
            prev_time = cache.get('ws_message_prev_time') or time.time()

            current_time = time.time()
            time_diff = current_time - prev_time

            if time_diff > 0:
                rate = (current_count - prev_count) / time_diff
            else:
                rate = 0.0

            # Update cache for next calculation
            if time_diff >= 5:  # Only update cache every 5 seconds
                cache.set('ws_message_prev_count', current_count, timeout=120)
                cache.set('ws_message_prev_time', current_time, timeout=120)

            return rate
        else:
            return 0.0
    except Exception:
        return 0.0


def _get_error_rate() -> float:
    """Get current error rate (percentage of messages)."""
    message_count = _get_total_messages()
    error_count = _get_total_errors()

    if message_count == 0:
        return 0.0

    return (error_count / message_count) * 100


def _get_average_latency() -> float:
    """Get average message processing latency in seconds."""
    if hasattr(metrics, 'get_histogram_average'):
        return metrics.get_histogram_average(ws_latency) or 0.0
    return 0.0


def _get_percentile_latency(percentile: int) -> float:
    """Get specified percentile of message processing latency in seconds."""
    if hasattr(metrics, 'get_histogram_percentile'):
        return metrics.get_histogram_percentile(ws_latency, percentile) or 0.0
    return 0.0


def _get_active_channels() -> int:
    """Get number of active channels with subscriptions."""
    try:
        from .routes import active_connections
        channels = set()
        for conn_data in active_connections.values():
            for channel in conn_data.get('channels', []):
                channels.add(channel)
        return len(channels)
    except ImportError:
        channels = metrics.get_gauge_values(ws_subscription_gauge)
        return len([ch for ch, count in channels.items() if count > 0]) if channels else 0


def _get_most_active_channel() -> str:
    """Get the most active channel by connection count."""
    channels = _get_connections_by_channel()
    if not channels:
        return "none"
    return max(channels.items(), key=lambda x: x[1])[0]


# Initialize metrics when module is loaded
def initialize_metrics() -> None:
    """Initialize metrics configuration."""
    try:
        # Configure retention policies
        configure_metrics_retention()

        # Initialize resource usage metrics
        _update_resource_metrics()

        logger.info("WebSocket metrics initialized")

    except Exception as e:
        logger.error(f"Failed to initialize WebSocket metrics: {str(e)}", exc_info=True)
