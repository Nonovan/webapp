"""
WebSocket metrics collection and monitoring for the Administrative WebSocket API.

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
from models.security.rate_limiter import RateLimiter

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
    'admin_ws_connections_active',
    'Current number of active admin WebSocket connections',
    labels=['channel', 'role'],
    multiprocess_mode='livesum'
)

ws_message_counter = metrics.counter(
    'admin_ws_messages_total',
    'Total admin WebSocket messages',
    labels=['event_type', 'channel', 'direction'],
    multiprocess_mode='livesum'
)

ws_command_counter = metrics.counter(
    'admin_ws_commands_total',
    'Total admin commands executed via WebSocket',
    labels=['command', 'status'],
    multiprocess_mode='livesum'
)

ws_error_counter = metrics.counter(
    'admin_ws_errors_total',
    'Total admin WebSocket errors',
    labels=['error_type', 'channel'],
    multiprocess_mode='livesum'
)

ws_latency = metrics.histogram(
    'admin_ws_message_latency_seconds',
    'Admin WebSocket message processing latency in seconds',
    labels=['event_type'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

ws_subscription_gauge = metrics.gauge(
    'admin_ws_subscriptions_active',
    'Current number of active channel subscriptions',
    labels=['channel'],
    multiprocess_mode='livesum'
)

ws_connection_duration = metrics.histogram(
    'admin_ws_connection_duration_seconds',
    'Duration of WebSocket connections in seconds',
    labels=['role', 'disconnect_reason'],
    buckets=(1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200)
)

ws_command_duration = metrics.histogram(
    'admin_ws_command_duration_seconds',
    'Time to execute WebSocket admin commands in seconds',
    labels=['command'],
    buckets=(0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0)
)

ws_auth_counter = metrics.counter(
    'admin_ws_auth_attempts_total',
    'Total WebSocket authentication attempts',
    labels=['status', 'has_mfa'],
    multiprocess_mode='livesum'
)

ws_resource_usage = metrics.gauge(
    'admin_ws_resource_usage',
    'Resource usage by WebSocket connections',
    labels=['resource_type'],  # cpu, memory, connections
    multiprocess_mode='livesum'
)


def track_connection(channel: str, role: str = 'user') -> None:
    """
    Track a new WebSocket connection.

    Args:
        channel: The channel being connected to
        role: The role of the connected user
    """
    try:
        if metrics:
            ws_connection_count.inc(1, labels={'channel': channel, 'role': role})

            # Record resource metrics
            _update_resource_metrics()

            logger.debug(f"Tracked new WebSocket connection to channel '{channel}' by role '{role}'")
    except Exception as e:
        logger.error(f"Error tracking WebSocket connection: {str(e)}", exc_info=True)


def track_disconnection(channel: str, role: str = 'user', duration_seconds: float = 0.0, reason: str = 'normal') -> None:
    """
    Track a WebSocket disconnection.

    Args:
        channel: The channel being disconnected from
        role: The role of the disconnected user
        duration_seconds: How long the connection was active
        reason: Reason for disconnection
    """
    try:
        if metrics:
            # Decrement active connections counter
            ws_connection_count.dec(1, labels={'channel': channel, 'role': role})

            # Record connection duration
            ws_connection_duration.observe(
                duration_seconds,
                labels={'role': role, 'disconnect_reason': reason}
            )

            # Update resource metrics
            _update_resource_metrics()

            logger.debug(f"Tracked WebSocket disconnection from channel '{channel}' "
                        f"after {duration_seconds:.2f}s with reason '{reason}'")
    except Exception as e:
        logger.error(f"Error tracking WebSocket disconnection: {str(e)}", exc_info=True)


def track_message(event_type: str, channel: str, direction: str = 'received') -> None:
    """
    Track a WebSocket message.

    Args:
        event_type: Type of message event
        channel: Channel the message is on
        direction: Direction of message (received/sent)
    """
    try:
        if metrics:
            ws_message_counter.inc(1, labels={
                'event_type': event_type,
                'channel': channel,
                'direction': direction
            })

            logger.debug(f"Tracked WebSocket {direction} message of type '{event_type}' on channel '{channel}'")
    except Exception as e:
        logger.error(f"Error tracking WebSocket message: {str(e)}", exc_info=True)


def track_command(command: str, status: str = 'success', duration: float = 0.0) -> None:
    """
    Track a WebSocket administrative command.

    Args:
        command: Command being executed
        status: Status of command execution (success/error)
        duration: How long the command took to execute
    """
    try:
        if metrics:
            # Increment command counter
            ws_command_counter.inc(1, labels={
                'command': command,
                'status': status
            })

            # Record command duration
            ws_command_duration.observe(duration, labels={'command': command})

            logger.debug(f"Tracked WebSocket command '{command}' with status '{status}' "
                        f"(duration: {duration:.3f}s)")

            # Record detailed command metrics in the audit log if failure or slow execution
            if status == 'error' or duration > 1.0:
                if has_app_context():
                    log_security_event(
                        event_type='admin_ws_command',
                        description=f"WebSocket admin command execution: {command}",
                        severity='warning' if status == 'error' else 'info',
                        details={
                            'command': command,
                            'status': status,
                            'duration': duration,
                            'slow': duration > 1.0
                        }
                    )
    except Exception as e:
        logger.error(f"Error tracking WebSocket command: {str(e)}", exc_info=True)


def track_error(error_type: str, channel: str = 'global') -> None:
    """
    Track a WebSocket error.

    Args:
        error_type: Type of error that occurred
        channel: Channel where error occurred
    """
    try:
        if metrics:
            ws_error_counter.inc(1, labels={'error_type': error_type, 'channel': channel})
            logger.debug(f"Tracked WebSocket error '{error_type}' on channel '{channel}'")
    except Exception as e:
        logger.error(f"Error tracking WebSocket error: {str(e)}", exc_info=True)


def track_latency(event_type: str, latency: float) -> None:
    """
    Track WebSocket message processing latency.

    Args:
        event_type: Type of message event
        latency: Latency in seconds
    """
    try:
        if metrics:
            ws_latency.observe(latency, labels={'event_type': event_type})
    except Exception as e:
        logger.error(f"Error tracking WebSocket latency: {str(e)}", exc_info=True)


def track_subscription(channel: str, increment: bool = True) -> None:
    """
    Track channel subscription changes.

    Args:
        channel: Channel being subscribed to or unsubscribed from
        increment: True if subscribing, False if unsubscribing
    """
    try:
        if metrics:
            if increment:
                ws_subscription_gauge.inc(1, labels={'channel': channel})
            else:
                ws_subscription_gauge.dec(1, labels={'channel': channel})

            logger.debug(f"Tracked WebSocket {'subscription to' if increment else 'unsubscription from'} channel '{channel}'")
    except Exception as e:
        logger.error(f"Error tracking WebSocket subscription: {str(e)}", exc_info=True)


def track_authentication(status: str, has_mfa: bool = False) -> None:
    """
    Track WebSocket authentication attempts.

    Args:
        status: Authentication status (success/failure)
        has_mfa: Whether MFA was used
    """
    try:
        if metrics:
            ws_auth_counter.inc(1, labels={
                'status': status,
                'has_mfa': 'true' if has_mfa else 'false'
            })

            logger.debug(f"Tracked WebSocket authentication attempt: status='{status}', has_mfa={has_mfa}")
    except Exception as e:
        logger.error(f"Error tracking WebSocket authentication: {str(e)}", exc_info=True)


def emit_metrics(target_channel: str = 'admin:metrics') -> Dict[str, Any]:
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
                'by_type': _get_messages_by_type()
            },
            'errors': {
                'total': _get_total_errors(),
                'by_type': _get_errors_by_type()
            },
            'commands': {
                'total': _get_total_commands(),
                'success_rate': _get_command_success_rate(),
                'most_used': _get_most_used_commands(limit=5)
            },
            'performance': {
                'avg_latency': _get_average_latency(),
                'p95_latency': _get_percentile_latency(95),
                'avg_command_duration': _get_average_command_duration()
            },
            'resources': {
                'memory_mb': _get_memory_usage(),
                'cpu_percent': _get_cpu_usage(),
                'connection_count': _get_total_connections()
            }
        }

        # Emit metrics to the specified channel
        if has_app_context():
            emit('metrics_update', metrics_data, namespace='/admin', room=target_channel)

        return metrics_data

    except Exception as e:
        logger.error(f"Error emitting WebSocket metrics: {str(e)}", exc_info=True)
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': 'Failed to collect metrics',
            'error_details': str(e)
        }


def configure_metrics_retention() -> None:
    """
    Configure retention policies for WebSocket metrics.

    This applies appropriate retention periods based on metric type.
    """
    try:
        # Apply retention policy to counters (short-lived data)
        metrics.configure_retention(ws_message_counter, METRICS_RETENTION['high_frequency'])
        metrics.configure_retention(ws_command_counter, METRICS_RETENTION['medium_frequency'])
        metrics.configure_retention(ws_error_counter, METRICS_RETENTION['medium_frequency'])
        metrics.configure_retention(ws_auth_counter, METRICS_RETENTION['medium_frequency'])

        # Apply retention policy to gauges (longer-lived data)
        metrics.configure_retention(ws_connection_count, METRICS_RETENTION['low_frequency'])
        metrics.configure_retention(ws_subscription_gauge, METRICS_RETENTION['low_frequency'])
        metrics.configure_retention(ws_resource_usage, METRICS_RETENTION['medium_frequency'])

        # Apply retention policy to histograms (mid-range retention)
        metrics.configure_retention(ws_latency, METRICS_RETENTION['medium_frequency'])
        metrics.configure_retention(ws_connection_duration, METRICS_RETENTION['medium_frequency'])
        metrics.configure_retention(ws_command_duration, METRICS_RETENTION['medium_frequency'])

        logger.info("WebSocket metrics retention configured")

    except Exception as e:
        logger.error(f"Failed to configure metrics retention: {str(e)}", exc_info=True)


@track_metrics('ws_metrics')
def get_metrics_summary() -> Dict[str, Any]:
    """
    Get a summary of WebSocket metrics for admin dashboard.

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
            'success_rate': _get_command_success_rate(),
            'most_active_channel': _get_most_active_channel()
        }
    except Exception as e:
        logger.error(f"Error generating metrics summary: {str(e)}", exc_info=True)
        return {
            'error': 'Failed to generate metrics summary',
            'message': str(e)
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
    # This is a placeholder - in a real implementation we would
    # query the metrics registry or database to get actual values
    return metrics.get_gauge_value(ws_connection_count) or 0


def _get_connections_by_channel() -> Dict[str, int]:
    """Get connection count by channel."""
    # This is a placeholder - in a real implementation we would
    # query the metrics registry to get actual values
    return metrics.get_gauge_values(ws_connection_count, group_by='channel') or {}


def _get_connections_by_role() -> Dict[str, int]:
    """Get connection count by role."""
    # This is a placeholder - in a real implementation we would
    # query the metrics registry to get actual values
    return metrics.get_gauge_values(ws_connection_count, group_by='role') or {}


def _get_total_messages() -> int:
    """Get total number of messages."""
    return metrics.get_counter_value(ws_message_counter) or 0


def _get_messages_by_type() -> Dict[str, int]:
    """Get message count by event type."""
    return metrics.get_counter_values(ws_message_counter, group_by='event_type') or {}


def _get_total_errors() -> int:
    """Get total number of errors."""
    return metrics.get_counter_value(ws_error_counter) or 0


def _get_errors_by_type() -> Dict[str, int]:
    """Get error count by error type."""
    return metrics.get_counter_values(ws_error_counter, group_by='error_type') or {}


def _get_total_commands() -> int:
    """Get total number of commands."""
    return metrics.get_counter_value(ws_command_counter) or 0


def _get_command_success_rate() -> float:
    """Get percentage of successful commands."""
    values = metrics.get_counter_values(ws_command_counter, group_by='status')
    if not values:
        return 100.0

    success = values.get('success', 0)
    total = sum(values.values())

    return (success / total * 100) if total > 0 else 100.0


def _get_most_used_commands(limit: int = 5) -> List[Dict[str, Any]]:
    """Get list of most used commands."""
    commands = metrics.get_counter_values(ws_command_counter, group_by='command')
    if not commands:
        return []

    # Sort and limit
    top_commands = sorted(
        [{'command': cmd, 'count': count} for cmd, count in commands.items()],
        key=lambda x: x['count'],
        reverse=True
    )

    return top_commands[:limit]


def _get_average_latency() -> float:
    """Get average message processing latency in seconds."""
    return metrics.get_histogram_value(ws_latency, 'avg') or 0.0


def _get_percentile_latency(percentile: float) -> float:
    """Get percentile latency value in seconds."""
    return metrics.get_histogram_value(ws_latency, f'p{percentile}') or 0.0


def _get_average_command_duration() -> float:
    """Get average command execution time in seconds."""
    return metrics.get_histogram_value(ws_command_duration, 'avg') or 0.0


def _get_message_rate() -> float:
    """Get current message rate (messages per second)."""
    # This would ideally use a rate() function from the metrics library
    # This is a simplified placeholder implementation
    return metrics.get_rate(ws_message_counter, window_seconds=60) or 0.0


def _get_error_rate() -> float:
    """Get current error rate (percentage of messages)."""
    message_count = _get_total_messages()
    error_count = _get_total_errors()

    if message_count == 0:
        return 0.0

    return (error_count / message_count) * 100


def _get_active_channels() -> int:
    """Get number of active channels with subscriptions."""
    channels = metrics.get_gauge_values(ws_subscription_gauge)
    return len([ch for ch, count in channels.items() if count > 0]) if channels else 0


def _get_most_active_channel() -> str:
    """Get the most active channel by message count."""
    channels = metrics.get_counter_values(ws_message_counter, group_by='channel')
    if not channels:
        return 'None'

    # Find channel with highest message count
    most_active = max(channels.items(), key=lambda x: x[1], default=(None, 0))
    return most_active[0] or 'None'
