"""
Health check system for application monitoring.

This module provides health check endpoints for application monitoring, 
including database connectivity, cache availability, storage access,
external service availability, and system resource usage.

These endpoints are critical for:
- Cloud infrastructure monitoring
- Container orchestration systems like Kubernetes
- Load balancer health probes
- DevOps monitoring tools
- ICS system status verification
"""

import os
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Tuple
import psutil

from flask import Blueprint, jsonify, current_app, Response
from sqlalchemy.exc import SQLAlchemyError
from redis.exceptions import RedisError

from extensions import db, cache
from models.system_config import SystemConfig
from core.security_utils import log_security_event
from core.utils import get_critical_file_hashes

logger = logging.getLogger(__name__)

def register_health_endpoints(app):
    """Register health check endpoints with the Flask application."""
    health_bp = Blueprint('health', __name__, url_prefix='/health')

    @health_bp.route('', methods=['GET'])
    def basic_health_check() -> Tuple[Response, int]:
        """
        Basic health check endpoint for load balancers and container orchestration.
        
        Returns a simple 200 OK response if the application is running.
        This is the primary endpoint that should be used by load balancers
        and container orchestration systems.
        
        Returns:
            Tuple[Response, int]: JSON response with status and HTTP status code
        """
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": current_app.config.get('VERSION', 'unknown')
        }), 200

    @health_bp.route('/detail', methods=['GET'])
    def detailed_health_check() -> Tuple[Response, int]:
        """
        Detailed health check for comprehensive system status.
        
        Checks all critical dependencies of the application including:
        - Database connectivity
        - Redis/cache availability
        - File system access
        - Memory usage
        - CPU load
        
        Returns:
            Tuple[Response, int]: JSON response with detailed status and HTTP status code
        """
        status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": current_app.config.get('VERSION', 'unknown'),
            "checks": {}
        }

        http_status = 200

        # Check database
        db_status = check_database()
        status["checks"]["database"] = db_status
        if db_status["status"] != "healthy":
            status["status"] = "degraded"
            http_status = 500

        # Check Redis/cache if configured
        if current_app.config.get('REDIS_URL'):
            cache_status = check_cache()
            status["checks"]["cache"] = cache_status
            if cache_status["status"] != "healthy":
                status["status"] = "degraded"

        # Check filesystem
        fs_status = check_filesystem()
        status["checks"]["filesystem"] = fs_status
        if fs_status["status"] != "healthy":
            status["status"] = "degraded"

        # Check system resources
        resources = check_system_resources()
        status["checks"]["resources"] = resources

        # Check maintenance mode
        try:
            maintenance_mode = SystemConfig.query.filter_by(key="maintenance_mode").first()
            if maintenance_mode and maintenance_mode.value.lower() == "true":
                status["status"] = "maintenance"
                status["maintenance_message"] = maintenance_mode.description
        except SQLAlchemyError:
            pass

        return jsonify(status), http_status

    @health_bp.route('/readiness', methods=['GET'])
    def readiness_check() -> Tuple[Response, int]:
        """
        Readiness check for container orchestration systems.
        
        Verifies if the application is ready to serve requests by checking
        critical dependencies and confirming application initialization is complete.
        
        Returns:
            Tuple[Response, int]: JSON response with status and HTTP status code
        """
        # Application is considered ready if database is available
        db_status = check_database()
        is_ready = db_status["status"] == "healthy"

        if is_ready:
            return jsonify({
                "status": "ready",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200
        else:
            return jsonify({
                "status": "not_ready",
                "reason": "Database connection failed",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 503

    @health_bp.route('/liveness', methods=['GET'])
    def liveness_check() -> Tuple[Response, int]:
        """
        Liveness check for container orchestration systems.
        
        Verifies if the application is still running and not deadlocked.
        
        Returns:
            Tuple[Response, int]: JSON response with status and HTTP status code
        """
        # Application is considered alive if this endpoint responds
        return jsonify({
            "status": "alive",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    @health_bp.route('/security', methods=['GET'])
    def security_check() -> Tuple[Response, int]:
        """
        Security health check for monitoring critical security components.
        
        Verifies security-critical files have not been modified and
        security configurations are properly set.
        
        Returns:
            Tuple[Response, int]: JSON response with security status and HTTP status code
        """
        status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {}
        }

        # Check file integrity
        if current_app.config.get('SECURITY_CHECK_FILE_INTEGRITY', True):
            critical_files = current_app.config.get('SECURITY_CRITICAL_FILES', [
                'app.py',
                'config.py',
                'core/security_utils.py',
                'core/middleware.py'
            ])

            try:
                # Get current hashes of critical files
                current_hashes = get_critical_file_hashes(critical_files)

                # Check if we have stored hashes
                stored_config = SystemConfig.query.filter_by(key="file_hashes").first()

                # If no stored hashes, store current ones and consider it healthy
                if not stored_config:
                    new_config = SystemConfig(
                        key="file_hashes",
                        value=str(current_hashes),
                        description="Security-critical file hashes"
                    )
                    db.session.add(new_config)
                    db.session.commit()
                    status["checks"]["file_integrity"] = {
                        "status": "healthy",
                        "message": "File hashes initialized"
                    }
                else:
                    # Compare with stored hashes
                    import ast
                    stored_hashes = ast.literal_eval(stored_config.value)
                    modified_files = []

                    for file, hash_value in current_hashes.items():
                        if file in stored_hashes and stored_hashes[file] != hash_value:
                            modified_files.append(file)

                    if modified_files:
                        status["status"] = "critical"
                        status["checks"]["file_integrity"] = {
                            "status": "critical",
                            "message": f"Modified files detected: {', '.join(modified_files)}"
                        }

                        # Log security event
                        log_security_event(
                            event_type="file_integrity_violation",
                            description=f"Modified security-critical files detected: {', '.join(modified_files)}",
                            severity="critical"
                        )
                    else:
                        status["checks"]["file_integrity"] = {
                            "status": "healthy",
                            "message": "All critical files intact"
                        }
            except (OSError, IOError) as e:
                status["checks"]["file_integrity"] = {
                    "status": "warning",
                    "message": f"Failed to check file integrity: {str(e)}"
                }

        # Check security headers
        security_headers = current_app.config.get('SECURITY_HEADERS_ENABLED', True)
        if not security_headers:
            status["checks"]["security_headers"] = {
                "status": "warning",
                "message": "Security headers disabled"
            }
        else:
            status["checks"]["security_headers"] = {
                "status": "healthy",
                "message": "Security headers enabled"
            }

        # Check session security
        session_secure = current_app.config.get('SESSION_COOKIE_SECURE', False)
        session_httponly = current_app.config.get('SESSION_COOKIE_HTTPONLY', True)
        session_samesite = current_app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')

        if not (session_secure and session_httponly and session_samesite):
            status["checks"]["session_security"] = {
                "status": "warning",
                "message": "Session cookies not fully secured"
            }
        else:
            status["checks"]["session_security"] = {
                "status": "healthy",
                "message": "Session cookies properly secured"
            }

        http_status = 200
        if status["status"] == "critical":
            http_status = 500

        return jsonify(status), http_status

    def check_database() -> Dict[str, Any]:
        """Check database connectivity."""
        try:
            # Simple query to test database connectivity
            db.session.execute("SELECT 1").fetchall()
            return {
                "status": "healthy",
                "latency_ms": measure_db_latency()
            }
        except SQLAlchemyError as e:
            logger.error("Database health check failed: %s", str(e))
            return {
                "status": "critical",
                "message": f"Database error: {str(e)}"
            }

    def check_cache() -> Dict[str, Any]:
        """Check Redis/cache availability."""
        try:
            # Test cache by setting and getting a value
            test_key = "health_check_test"
            test_value = datetime.now(timezone.utc).isoformat()
            cache.set(test_key, test_value, timeout=10)
            retrieved = cache.get(test_key)

            if retrieved == test_value:
                return {
                    "status": "healthy",
                    "latency_ms": measure_cache_latency()
                }
            else:
                return {
                    "status": "degraded",
                    "message": "Cache retrieval mismatch"
                }
        except RedisError as e:
            logger.error("Cache health check failed: %s", str(e))
            return {
                "status": "degraded",
                "message": f"Cache error: {str(e)}"
            }
        except (RedisError, TypeError, ValueError) as e:
            logger.error("Cache health check failed with unexpected error: %s", str(e))
            return {
                "status": "degraded",
                "message": f"Cache error: {str(e)}"
            }

    def check_filesystem() -> Dict[str, Any]:
        """Check filesystem access."""
        try:
            # Check if we can write to a temp directory
            temp_dir = current_app.config.get('TEMP_FOLDER', '/tmp')
            test_file = os.path.join(temp_dir, f"health_check_{int(time.time())}.txt")

            with open(test_file, "w", encoding="utf-8") as f:
                f.write("health check")

            os.remove(test_file)

            # Check disk space
            disk_usage = psutil.disk_usage('/')
            disk_percent = disk_usage.percent

            status = "healthy"
            message = "Filesystem operational"

            if disk_percent > 90:
                status = "warning"
                message = f"Disk usage high: {disk_percent}%"

            return {
                "status": status,
                "message": message,
                "disk_usage_percent": disk_percent,
                "disk_free_gb": round(disk_usage.free / (1024 ** 3), 2)
            }
        except (OSError, IOError) as e:
            logger.error("Filesystem health check failed: %s", str(e))
            return {
                "status": "warning",
                "message": f"Filesystem error: {str(e)}"
            }

    def check_system_resources() -> Dict[str, Any]:
        """Check system resource usage."""
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.1)

            status = "healthy"
            if memory.percent > 90 or cpu_percent > 90:
                status = "warning"

            return {
                "status": status,
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_mb": round(memory.available / (1024 ** 2), 2),
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None
            }
        except (psutil.Error, OSError) as e:
            logger.error("System resources check failed: %s", str(e))
            return {
                "status": "unknown",
                "message": f"Error checking system resources: {str(e)}"
            }

    def measure_db_latency() -> float:
        """Measure database query latency in milliseconds."""
        try:
            start = time.time()
            db.session.execute("SELECT 1").fetchall()
            end = time.time()
            return round((end - start) * 1000, 2)
        except (psutil.Error, OSError):
            return -1

    def measure_cache_latency() -> float:
        """Measure cache operation latency in milliseconds."""
        try:
            test_key = "latency_test"
            test_value = "test"

            start = time.time()
            cache.set(test_key, test_value, timeout=5)
            cache.get(test_key)
            end = time.time()

            return round((end - start) * 1000, 2)
        except (psutil.Error, OSError):
            return -1

    app.register_blueprint(health_bp)

    # Log successful setup
    logger.info("Health check endpoints registered at /health")
