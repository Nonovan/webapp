"""
Celery integration for Cloud Infrastructure Platform.

This module provides Celery task queue functionality for the application,
allowing for asynchronous task processing, scheduled tasks, and distributed
workloads.
"""

import logging
from flask import Flask
from celery import Celery

# Configure logging
logger = logging.getLogger(__name__)

# Initialize Celery instance
celery = Celery()

def init_celery(app: Flask = None) -> Celery:
    """
    Initialize Celery with the Flask application configuration.

    Args:
        app: Flask application instance

    Returns:
        Configured Celery instance
    """
    if app is None:
        # Return the pre-configured instance for imports
        return celery

    # Configure Celery from Flask config
    celery.conf.update(
        broker_url=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
        result_backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone=app.config.get('TIMEZONE', 'UTC'),
        task_always_eager=app.config.get('CELERY_ALWAYS_EAGER', False),
        task_eager_propagates=app.config.get('CELERY_EAGER_PROPAGATES', False),
        worker_hijack_root_logger=False,
        worker_max_tasks_per_child=app.config.get('CELERY_MAX_TASKS_PER_CHILD', 1000),
        worker_prefetch_multiplier=app.config.get('CELERY_PREFETCH_MULTIPLIER', 4),
        task_acks_late=app.config.get('CELERY_TASK_ACKS_LATE', True),
        task_default_queue=app.config.get('CELERY_DEFAULT_QUEUE', 'default'),
        task_queues=app.config.get('CELERY_TASK_QUEUES', None),
        task_routes=app.config.get('CELERY_TASK_ROUTES', None),
        task_time_limit=app.config.get('CELERY_TASK_TIME_LIMIT', 3600),  # 1 hour
        task_soft_time_limit=app.config.get('CELERY_TASK_SOFT_TIME_LIMIT', 3300),  # 55 minutes
        worker_send_task_events=app.config.get('CELERY_SEND_TASK_EVENTS', True),
        worker_concurrency=app.config.get('CELERY_CONCURRENCY', None)
    )

    # Security settings if configured
    if app.config.get('CELERY_BROKER_USE_SSL', False):
        celery.conf.broker_use_ssl = app.config.get('CELERY_BROKER_SSL_CONFIG', {})

    # Set up task tracking
    if app.config.get('CELERY_TRACK_STARTED', True):
        celery.conf.task_track_started = True

    # Configure scheduled tasks if specified
    if 'CELERY_BEAT_SCHEDULE' in app.config:
        celery.conf.beat_schedule = app.config['CELERY_BEAT_SCHEDULE']

    # Configure error handling
    celery.conf.task_annotations = {
        '*': {
            'on_failure': _handle_task_failure,
            'on_success': _handle_task_success
        }
    }

    # Make Celery recognize Flask application context
    TaskBase = celery.Task

    class AppContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

        def on_failure(self, exc, task_id, args, kwargs, einfo):
            with app.app_context():
                logger.error(f"Celery task {task_id} failed: {str(exc)}")
                return TaskBase.on_failure(self, exc, task_id, args, kwargs, einfo)

    celery.Task = AppContextTask
    logger.info("Celery initialized successfully")

    return celery


def _handle_task_failure(task, exception, traceback, *args, **kwargs):
    """Handle task failure by logging details."""
    logger.error(f"Task {task.name}[{task.request.id}] failed: {str(exception)}")

    # Try to log to security event log if available
    try:
        from core.security import log_security_event
        log_security_event(
            event_type="background_task_failure",
            description=f"Background task {task.name} failed: {str(exception)}",
            severity="warning",
            details={
                "task_id": task.request.id,
                "task_name": task.name,
                "error": str(exception),
                "queue": getattr(task.request, 'delivery_info', {}).get('routing_key', 'unknown')
            }
        )
    except ImportError:
        pass


def _handle_task_success(task, *args, **kwargs):
    """Handle task success for metrics tracking."""
    # Try to increment task success metrics if metrics are available
    try:
        from extensions import metrics
        metrics.increment('celery_tasks_completed', 1, {
            'task_name': task.name,
            'status': 'success'
        })
    except (ImportError, AttributeError):
        pass
