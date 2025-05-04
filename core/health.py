"""
Health check system for application monitoring.

This module provides health check endpoints for application monitoring,
including database connectivity, cache availability, storage access,
external service availability, system resource usage, and security status verification.

These endpoints are critical for:
- Cloud infrastructure monitoring
- Container orchestration systems like Kubernetes
- Load balancer health probes
- DevOps monitoring tools
- ICS system status verification
- Security monitoring and compliance reporting
"""

import os
import time
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, List, Optional
import psutil

from flask import Blueprint, jsonify, current_app, Response, request
from sqlalchemy.exc import SQLAlchemyError
from redis.exceptions import RedisError

from extensions import db, cache
from models import SystemConfig
from core.utils import format_timestamp

# Initialize logger
logger = logging.getLogger(__name__)

# High-level health check function for non-endpoint usage
def healthcheck() -> Dict[str, Any]:
    """
    Perform basic health check of system components.

    This function provides a programmatic way to check system health
    without requiring an HTTP context or Flask application.

    Returns:
        Dict[str, Any]: Health status information
    """
    health_info = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {}
    }

    # Check database if available
    try:
        from extensions import db
        if db:
            # Simple database check
            db.session.execute("SELECT 1").scalar()
            health_info["components"]["database"] = "healthy"
    except (ImportError, SQLAlchemyError, Exception) as e:
        logger.error(f"Database health check failed: {str(e)}")
        health_info["components"]["database"] = "unhealthy"
        health_info["status"] = "degraded"

    # Check cache if available
    try:
        from extensions import cache
        if cache:
            test_key = f"health_check_{time.time()}"
            cache.set(test_key, "ok", timeout=10)
            if cache.get(test_key) == "ok":
                health_info["components"]["cache"] = "healthy"
            else:
                health_info["components"]["cache"] = "degraded"
                if health_info["status"] == "healthy":
                    health_info["status"] = "degraded"
            cache.delete(test_key)
    except (ImportError, Exception) as e:
        logger.error(f"Cache health check failed: {str(e)}")
        health_info["components"]["cache"] = "unknown"

    # Add system resources
    try:
        health_info["resources"] = {
            "memory": {
                "percent": psutil.virtual_memory().percent,
                "available_mb": round(psutil.virtual_memory().available / (1024 * 1024), 2)
            },
            "cpu": {
                "percent": psutil.cpu_percent(interval=0.1)
            }
        }

        # Check if resources are critical
        if (health_info["resources"]["memory"]["percent"] > 95 or
            health_info["resources"]["cpu"]["percent"] > 95):
            health_info["status"] = "critical"
        elif (health_info["resources"]["memory"]["percent"] > 85 or
              health_info["resources"]["cpu"]["percent"] > 85):
            health_info["status"] = "warning"
    except Exception as e:
        logger.error(f"Resource check failed: {e}")
        health_info["resources"] = {"error": str(e)}

    return health_info

# Database-specific health check
def check_database_health() -> Dict[str, Any]:
    """
    Check database connection health.

    Returns:
        Dict[str, Any]: Database health information
    """
    result = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        start_time = time.time()
        db.session.execute("SELECT 1").fetchall()
        query_time = time.time() - start_time

        result.update({
            "latency_ms": round(query_time * 1000, 2),
            "message": "Database is accessible"
        })
    except SQLAlchemyError as e:
        logger.error(f"Database health check failed: {str(e)}")
        result.update({
            "status": "critical",
            "message": f"Database connection error: {str(e)}"
        })

    return result

# Cache-specific health check
def check_cache_health() -> Dict[str, Any]:
    """
    Check cache health.

    Returns:
        Dict[str, Any]: Cache health information
    """
    result = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        test_key = f"health_check_{time.time()}"
        test_value = datetime.now(timezone.utc).isoformat()

        start_time = time.time()
        cache.set(test_key, test_value, timeout=10)
        retrieved = cache.get(test_key)
        operation_time = time.time() - start_time

        if retrieved == test_value:
            result.update({
                "latency_ms": round(operation_time * 1000, 2),
                "message": "Cache is operational"
            })
        else:
            result.update({
                "status": "degraded",
                "message": "Cache retrieval mismatch"
            })

        # Clean up test key
        cache.delete(test_key)
    except Exception as e:
        logger.error(f"Cache health check failed: {str(e)}")
        result.update({
            "status": "critical",
            "message": f"Cache error: {str(e)}"
        })

    return result

# Redis-specific health check
def check_redis_health() -> Dict[str, Any]:
    """
    Check Redis health.

    Returns:
        Dict[str, Any]: Redis health information
    """
    result = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Check if we're using Redis
    redis_client = None
    try:
        redis_url = current_app.config.get('REDIS_URL')
        if not redis_url:
            return {
                "status": "skipped",
                "message": "Redis is not configured"
            }

        # Try to get Redis client from app.extensions
        if hasattr(current_app, 'extensions') and 'redis' in current_app.extensions:
            redis_client = current_app.extensions['redis']

        # Try to get Redis client directly
        if not redis_client and hasattr(current_app, 'redis'):
            redis_client = current_app.redis

        if not redis_client:
            return {
                "status": "unknown",
                "message": "Redis client not available"
            }

        # Check Redis connectivity
        start_time = time.time()
        response = redis_client.ping()
        operation_time = time.time() - start_time

        if response:
            result.update({
                "latency_ms": round(operation_time * 1000, 2),
                "message": "Redis is responding to ping"
            })
        else:
            result.update({
                "status": "critical",
                "message": "Redis did not respond to ping"
            })
    except ImportError:
        result.update({
            "status": "skipped",
            "message": "Redis package not installed"
        })
    except Exception as e:
        logger.error(f"Redis health check failed: {str(e)}")
        result.update({
            "status": "critical",
            "message": f"Redis error: {str(e)}"
        })

    return result

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
        start_time = time.time()

        status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": current_app.config.get('VERSION', 'unknown'),
            "environment": current_app.config.get('ENVIRONMENT', 'production'),
            "checks": {}
        }

        http_status = 200

        # Check database
        db_status = check_database()
        status["checks"]["database"] = db_status
        if db_status["status"] == "critical":
            status["status"] = "critical"
            http_status = 500
        elif db_status["status"] != "healthy" and status["status"] != "critical":
            status["status"] = "degraded"

        # Check Redis/cache if configured
        if current_app.config.get('REDIS_URL'):
            cache_status = check_cache()
            status["checks"]["cache"] = cache_status
            if cache_status["status"] == "critical":
                status["status"] = "critical"
                http_status = 500
            elif cache_status["status"] != "healthy" and status["status"] != "critical":
                status["status"] = "degraded"

        # Check filesystem
        fs_status = check_filesystem()
        status["checks"]["filesystem"] = fs_status
        if fs_status["status"] == "critical":
            status["status"] = "critical"
            http_status = 500
        elif fs_status["status"] != "healthy" and status["status"] != "critical":
            status["status"] = "degraded"

        # Check system resources
        resources = check_system_resources()
        status["checks"]["resources"] = resources
        if resources["status"] == "critical":
            status["status"] = "critical"
            http_status = 500
        elif resources["status"] != "healthy" and status["status"] != "critical":
            status["status"] = "degraded"

        # Check maintenance mode
        try:
            maintenance_mode = SystemConfig.query.filter_by(key="maintenance_mode").first()
            if maintenance_mode and maintenance_mode.value.lower() == "true":
                status["status"] = "maintenance"
                status["maintenance_message"] = maintenance_mode.description
        except SQLAlchemyError:
            # If we can't check maintenance mode, continue without changing status
            pass

        # Add response time information
        status["response_time_ms"] = round((time.time() - start_time) * 1000, 2)

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

        response = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": current_app.config.get('VERSION', 'unknown')
        }

        if is_ready:
            response["status"] = "ready"
            return jsonify(response), 200
        else:
            response["status"] = "not_ready"
            response["reason"] = db_status.get("message", "Database connection failed")
            return jsonify(response), 503

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

        # Check file integrity with enhanced monitoring
        if current_app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            status["checks"]["file_integrity"] = check_file_integrity()

            # Update overall status based on file integrity check
            if status["checks"]["file_integrity"]["status"] == "critical":
                status["status"] = "critical"
            elif status["checks"]["file_integrity"]["status"] == "warning" and status["status"] != "critical":
                status["status"] = "warning"

        # Check security headers
        security_headers = current_app.config.get('SECURITY_HEADERS_ENABLED', True)
        if not security_headers:
            status["checks"]["security_headers"] = {
                "status": "warning",
                "message": "Security headers disabled"
            }
            if status["status"] != "critical":
                status["status"] = "warning"
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
            if status["status"] != "critical":
                status["status"] = "warning"
        else:
            status["checks"]["session_security"] = {
                "status": "healthy",
                "message": "Session cookies properly secured"
            }

        # Check if CSRF protection is enabled
        csrf_enabled = current_app.config.get('WTF_CSRF_ENABLED', True)
        if not csrf_enabled:
            status["checks"]["csrf_protection"] = {
                "status": "critical",
                "message": "CSRF protection disabled"
            }
            status["status"] = "critical"
        else:
            status["checks"]["csrf_protection"] = {
                "status": "healthy",
                "message": "CSRF protection enabled"
            }

        # Check if automatic baseline updates are enabled in production
        if (current_app.config.get('ENVIRONMENT', '') in ('production', 'staging') and
            current_app.config.get('AUTO_UPDATE_BASELINE', False)):
            status["checks"]["baseline_security"] = {
                "status": "warning",
                "message": "Automatic baseline updates should be disabled in production"
            }
            if status["status"] != "critical":
                status["status"] = "warning"

        http_status = 200
        if status["status"] == "critical":
            http_status = 500

        return jsonify(status), http_status

    @health_bp.route('/integrity', methods=['GET'])
    def file_integrity_check() -> Tuple[Response, int]:
        """
        Comprehensive file integrity status check.

        Provides detailed information about file integrity monitoring status,
        including baseline information, recent changes, and configuration.

        Returns:
            Tuple[Response, int]: JSON response with integrity status and HTTP status code
        """
        # Check if user has appropriate permissions
        has_admin_access = check_admin_access()

        status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "monitoring_enabled": current_app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True),
            "auto_baseline_update": current_app.config.get('AUTO_UPDATE_BASELINE', False),
            "check_frequency": current_app.config.get('FILE_INTEGRITY_CHECK_FREQUENCY', 100),
            "algorithm": current_app.config.get('FILE_HASH_ALGORITHM', 'sha256')
        }

        # Get integrity status with full details if admin, limited details otherwise
        integrity_status = check_file_integrity(full_details=has_admin_access)
        status.update(integrity_status)

        # Determine HTTP status code
        http_status = 200
        if status.get("status") == "critical":
            http_status = 500

        return jsonify(status), http_status

    def check_file_integrity(full_details: bool = False) -> Dict[str, Any]:
        """
        Check file integrity status using the enhanced monitoring system.

        Args:
            full_details: Whether to include detailed file information

        Returns:
            Dict[str, Any]: Status information about file integrity
        """
        result = {
            "status": "healthy",
            "message": "File integrity monitoring operational",
            "last_check": None,
            "baseline_info": {}
        }

        try:
            # Use the specialized security module for integrity checking
            try:
                from core.security.cs_file_integrity import (
                    check_critical_file_integrity,
                    get_last_integrity_status
                )

                # First check if we have recent integrity status
                last_status = get_last_integrity_status()
                if last_status:
                    result["last_check"] = last_status.get("timestamp")
                    result["baseline_info"]["last_updated"] = last_status.get("baseline_updated")
                    result["baseline_info"]["monitored_files"] = last_status.get("monitored_files_count", 0)

                    # Add violation info if available
                    violations = last_status.get("violations", 0)
                    if violations > 0:
                        result["status"] = "critical" if last_status.get("critical_violations", 0) > 0 else "warning"
                        result["message"] = f"File integrity violations detected: {violations}"
                        result["violations"] = {
                            "total": violations,
                            "critical": last_status.get("critical_violations", 0),
                            "high": last_status.get("high_violations", 0),
                            "medium": last_status.get("medium_violations", 0)
                        }

                        # Include detailed changes for admins
                        if full_details and "changes" in last_status:
                            result["detected_changes"] = last_status["changes"]

                    return result

                # If no cached status, perform a new check
                status_ok, changes = check_critical_file_integrity(current_app)

                if status_ok:
                    result["message"] = "All files integrity verified"

                    # Include baseline information
                    baseline_path = current_app.config.get('FILE_BASELINE_PATH')
                    if baseline_path and os.path.exists(baseline_path):
                        try:
                            mtime = os.path.getmtime(baseline_path)
                            result["baseline_info"]["path"] = baseline_path
                            result["baseline_info"]["last_modified"] = datetime.fromtimestamp(
                                mtime, tz=timezone.utc
                            ).isoformat()

                            # Count files in baseline
                            with open(baseline_path, 'r') as f:
                                baseline_data = json.load(f)
                                result["baseline_info"]["monitored_files"] = len(baseline_data)
                        except (IOError, json.JSONDecodeError) as e:
                            logger.warning(f"Could not read baseline file: {e}")
                else:
                    # Integrity violations detected
                    # Count by severity
                    critical = [c for c in changes if c.get('severity') == 'critical']
                    high = [c for c in changes if c.get('severity') == 'high']
                    medium = [c for c in changes if c.get('severity') == 'medium']

                    result["status"] = "critical" if critical else "warning"
                    result["message"] = (f"File integrity violations detected: "
                                        f"{len(critical)} critical, {len(high)} high, {len(medium)} medium")

                    result["violations"] = {
                        "total": len(changes),
                        "critical": len(critical),
                        "high": len(high),
                        "medium": len(medium)
                    }

                    # Include detailed changes for admins
                    if full_details:
                        # Limit to most severe issues first, cap at 20 entries
                        detailed_changes = critical + high + medium
                        result["detected_changes"] = [
                            {
                                "path": c.get("path", "unknown"),
                                "status": c.get("status", "unknown"),
                                "severity": c.get("severity", "unknown"),
                                "timestamp": c.get("timestamp", format_timestamp())
                            }
                            for c in detailed_changes[:20]  # Limit to 20 entries
                        ]

                return result

            except ImportError:
                # Fall back to legacy implementation
                logger.info("Using legacy file integrity check")

                # Legacy implementation - using hashes stored in SystemConfig
                from core.utils import get_critical_file_hashes

                critical_files = current_app.config.get('SECURITY_CRITICAL_FILES', [
                    'app.py', 'config.py', 'core/security_utils.py', 'core/middleware.py'
                ])

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

                    result["message"] = "File integrity baseline initialized"
                    result["baseline_info"]["monitored_files"] = len(current_hashes)
                    result["baseline_info"]["last_updated"] = datetime.now(timezone.utc).isoformat()

                    return result

                # Compare with stored hashes
                import ast
                stored_hashes = ast.literal_eval(stored_config.value)
                modified_files = []

                for file_path, hash_value in current_hashes.items():
                    if file_path in stored_hashes and stored_hashes[file_path] != hash_value:
                        modified_files.append(file_path)

                if modified_files:
                    result["status"] = "critical"
                    result["message"] = f"File integrity violations detected: {len(modified_files)} file(s)"

                    result["violations"] = {
                        "total": len(modified_files),
                        "critical": len(modified_files),  # Legacy behavior treats all as critical
                        "high": 0,
                        "medium": 0
                    }

                    # Include modified file details if admin
                    if full_details:
                        result["detected_changes"] = [
                            {
                                "path": file_path,
                                "status": "modified",
                                "severity": "critical",
                                "timestamp": format_timestamp()
                            }
                            for file_path in modified_files
                        ]

                # Log security event
                try:
                    from core.security.cs_audit import log_security_event
                    log_security_event(
                        event_type="file_integrity_violation",
                        description=f"Modified security-critical files detected: {', '.join(modified_files)}",
                        severity="critical"
                    )
                except ImportError:
                    logger.error("Could not import log_security_event function")

            return result

        except Exception as e:
            logger.error(f"Error in check_file_integrity: {str(e)}")
            return {
                "status": "warning",
                "message": f"Error checking file integrity: {str(e)}",
                "error": str(e)
            }

    def check_database() -> Dict[str, Any]:
        """Check database connectivity."""
        try:
            # Simple query to test database connectivity
            start_time = time.time()
            db.session.execute("SELECT 1").fetchall()
            query_time = time.time() - start_time

            return {
                "status": "healthy",
                "latency_ms": round(query_time * 1000, 2)
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

            start_time = time.time()
            cache.set(test_key, test_value, timeout=10)
            retrieved = cache.get(test_key)
            operation_time = time.time() - start_time

            if retrieved == test_value:
                return {
                    "status": "healthy",
                    "latency_ms": round(operation_time * 1000, 2)
                }
            else:
                return {
                    "status": "degraded",
                    "message": "Cache retrieval mismatch"
                }
        except (RedisError, TypeError, ValueError) as e:
            logger.error("Cache health check failed: %s", str(e))
            return {
                "status": "degraded",
                "message": f"Cache error: {str(e)}"
            }

    def check_filesystem() -> Dict[str, Any]:
        """Check filesystem access and key directories."""
        try:
            # Check temp directory
            temp_dir = current_app.config.get('TEMP_DIR', '/tmp')
            instance_dir = current_app.instance_path
            upload_dir = current_app.config.get('UPLOAD_FOLDER')

            # Directory status tracking
            dir_status = {}
            overall_status = "healthy"

            # Check temp directory
            temp_status = check_directory_access(temp_dir, writable=True)
            dir_status["temp_dir"] = temp_status
            if temp_status["status"] == "critical":
                overall_status = "critical"
            elif temp_status["status"] != "healthy" and overall_status != "critical":
                overall_status = temp_status["status"]

            # Check instance directory
            instance_status = check_directory_access(instance_dir, writable=True)
            dir_status["instance_dir"] = instance_status
            if instance_status["status"] == "critical":
                overall_status = "critical"
            elif instance_status["status"] != "healthy" and overall_status != "critical":
                overall_status = instance_status["status"]

            # Check upload directory if configured
            if upload_dir:
                upload_status = check_directory_access(upload_dir, writable=True)
                dir_status["upload_dir"] = upload_status
                if upload_status["status"] == "critical":
                    overall_status = "critical"
                elif upload_status["status"] != "healthy" and overall_status != "critical":
                    overall_status = upload_status["status"]

            # Check disk space usage
            try:
                disk_usage = psutil.disk_usage('/')
                disk_percent = disk_usage.percent
                disk_free_gb = round(disk_usage.free / (1024 ** 3), 2)

                # Determine disk status based on usage
                disk_status = "healthy"
                if disk_percent > 95:
                    disk_status = "critical"
                elif disk_percent > 90:
                    disk_status = "warning"
                elif disk_percent > 80:
                    disk_status = "attention"

                if disk_status == "critical":
                    overall_status = "critical"
                elif disk_status != "healthy" and overall_status != "critical":
                    overall_status = disk_status

                dir_status["disk_space"] = {
                    "status": disk_status,
                    "usage_percent": disk_percent,
                    "free_gb": disk_free_gb
                }
            except Exception as e:
                logger.warning(f"Could not check disk space: {str(e)}")
                dir_status["disk_space"] = {
                    "status": "unknown",
                    "message": str(e)
                }

            return {
                "status": overall_status,
                "directories": dir_status
            }
        except Exception as e:
            logger.error(f"Filesystem health check failed: {str(e)}")
            return {
                "status": "warning",
                "message": f"Filesystem error: {str(e)}"
            }

    def check_directory_access(directory: str, writable: bool = False) -> Dict[str, Any]:
        """
        Check if a directory exists and is accessible.

        Args:
            directory: Directory path to check
            writable: Whether to check for write access

        Returns:
            Dictionary with status information
        """
        try:
            if not os.path.exists(directory):
                return {
                    "status": "warning",
                    "exists": False,
                    "message": f"Directory does not exist: {directory}"
                }

            if not os.path.isdir(directory):
                return {
                    "status": "warning",
                    "exists": True,
                    "is_dir": False,
                    "message": f"Path exists but is not a directory: {directory}"
                }

            # Check read access
            readable = os.access(directory, os.R_OK)
            if not readable:
                return {
                    "status": "warning",
                    "exists": True,
                    "is_dir": True,
                    "readable": False,
                    "writable": False,
                    "message": f"Directory is not readable: {directory}"
                }

            # Check write access if requested
            result = {
                "status": "healthy",
                "exists": True,
                "is_dir": True,
                "readable": True,
                "writable": False
            }

            if writable:
                can_write = os.access(directory, os.W_OK)
                result["writable"] = can_write

                if not can_write:
                    result["status"] = "warning"
                    result["message"] = f"Directory is not writable: {directory}"

                # Additional write test to verify actual permissions
                if can_write:
                    try:
                        test_file = os.path.join(directory, f".health_check_test_{int(time.time())}")
                        with open(test_file, 'w') as f:
                            f.write('test')
                        os.unlink(test_file)
                    except (IOError, OSError) as e:
                        result["status"] = "warning"
                        result["writable"] = False
                        result["message"] = f"Cannot write to directory despite permissions: {str(e)}"

            return result
        except Exception as e:
            return {
                "status": "warning",
                "message": f"Error checking directory {directory}: {str(e)}"
            }

    def check_system_resources() -> Dict[str, Any]:
        """Check system resource usage."""
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.1)

            # Determine status based on resource usage
            status = "healthy"
            if memory.percent > 95 or cpu_percent > 95:
                status = "critical"
            elif memory.percent > 90 or cpu_percent > 90:
                status = "warning"
            elif memory.percent > 80 or cpu_percent > 80:
                status = "attention"

            result = {
                "status": status,
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_mb": round(memory.available / (1024 ** 2), 2)
            }

            # Add load average on Unix systems
            if hasattr(os, 'getloadavg'):
                result["load_average"] = os.getloadavg()

                # Check if load average is extremely high
                if result["load_average"][0] > os.cpu_count() * 2:
                    if status != "critical":
                        status = "warning"
                    result["status"] = status

            return result
        except (psutil.Error, OSError) as e:
            logger.error(f"System resources check failed: {str(e)}")
            return {
                "status": "unknown",
                "message": f"Error checking system resources: {str(e)}"
            }

    def check_admin_access() -> bool:
        """
        Check if the current user has admin access for detailed health data.

        Returns:
            bool: True if user has admin access, False otherwise
        """
        # If we're not in a request context, deny admin access
        if not request:
            return False

        # Check for admin token in query params
        admin_token = request.args.get('admin_token')
        if admin_token:
            expected_token = current_app.config.get('HEALTH_ADMIN_TOKEN')
            if expected_token and admin_token == expected_token:
                return True

        # Check for admin user in session
        from flask import session
        if 'user_id' in session:
            user_id = session['user_id']
            user_roles = session.get('roles', [])

            # Check if user has admin role
            if 'admin' in user_roles:
                return True

        return False

    app.register_blueprint(health_bp)

    # Log successful setup
    logger.info("Health check endpoints registered at /health")

    # Additional logging for security-related health checks
    if current_app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
        logger.info("File integrity health checks enabled")

# Make explicitly available what is public API
__all__ = [
    'healthcheck',
    'register_health_endpoints',
    'check_database_health',
    'check_cache_health',
    'check_redis_health'
]
