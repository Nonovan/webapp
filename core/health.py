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
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, List, Optional
import psutil
import shutil
import glob
import re

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

    # Check filesystem metrics
    try:
        health_info["components"]["filesystem"] = check_filesystem_metrics_basic()
        if health_info["components"]["filesystem"]["status"] != "healthy":
            if health_info["components"]["filesystem"]["status"] == "critical":
                health_info["status"] = "critical"
            elif health_info["status"] == "healthy":
                health_info["status"] = "degraded"
    except Exception as e:
        logger.error(f"Filesystem metrics check failed: {str(e)}")
        health_info["components"]["filesystem"] = {
            "status": "unknown",
            "error": str(e)
        }

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

# Filesystem-specific metrics check (basic version)
def check_filesystem_metrics_basic() -> Dict[str, Any]:
    """
    Perform a basic check of filesystem metrics.

    This is a lightweight version for quick health checks.

    Returns:
        Dict[str, Any]: Basic filesystem status information
    """
    result = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        partitions = []
        for partition in psutil.disk_partitions(all=False):
            if not partition.mountpoint or not os.path.isdir(partition.mountpoint):
                continue

            try:
                usage = psutil.disk_usage(partition.mountpoint)
                partition_status = "healthy"
                if usage.percent >= 95:
                    partition_status = "critical"
                    result["status"] = "critical"
                elif usage.percent >= 90:
                    partition_status = "warning"
                    if result["status"] == "healthy":
                        result["status"] = "warning"
                elif usage.percent >= 80:
                    partition_status = "attention"

                partitions.append({
                    "mountpoint": partition.mountpoint,
                    "device": partition.device,
                    "fstype": partition.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "free_gb": round(usage.free / (1024**3), 2),
                    "usage_percent": usage.percent,
                    "status": partition_status
                })
            except PermissionError:
                continue

        result["partitions"] = partitions
        result["partitions_count"] = len(partitions)

        # Add inode usage information for Unix-like systems
        if hasattr(os, "statvfs"):
            inodes = []
            critical_inodes = False
            for partition in partitions:
                try:
                    mountpoint = partition["mountpoint"]
                    stats = os.statvfs(mountpoint)
                    if stats.f_files > 0:  # Ensure division is safe
                        free_inodes_percent = (stats.f_ffree * 100) / stats.f_files
                        used_inodes_percent = 100 - free_inodes_percent

                        inode_status = "healthy"
                        if used_inodes_percent >= 95:
                            inode_status = "critical"
                            critical_inodes = True
                        elif used_inodes_percent >= 90:
                            inode_status = "warning"

                        inodes.append({
                            "mountpoint": mountpoint,
                            "total_inodes": stats.f_files,
                            "free_inodes": stats.f_ffree,
                            "used_percent": round(used_inodes_percent, 2),
                            "status": inode_status
                        })
                except (PermissionError, OSError):
                    continue

            if inodes:
                result["inodes"] = inodes
                if critical_inodes and result["status"] != "critical":
                    result["status"] = "critical"

    except Exception as e:
        logger.error(f"Error in filesystem metrics check: {str(e)}")
        result["status"] = "unknown"
        result["error"] = str(e)

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

        # Check detailed filesystem metrics
        fs_metrics = check_detailed_filesystem_metrics()
        status["checks"]["filesystem_metrics"] = fs_metrics
        if fs_metrics["status"] == "critical":
            status["status"] = "critical"
            http_status = 500
        elif fs_metrics["status"] != "healthy" and status["status"] != "critical":
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

    @health_bp.route('/filesystem', methods=['GET'])
    def filesystem_check() -> Tuple[Response, int]:
        """
        Comprehensive filesystem metrics check.

        Provides detailed information about filesystem usage, performance metrics,
        storage trends, and potential issues.

        Returns:
            Tuple[Response, int]: JSON response with filesystem metrics and HTTP status code
        """
        # Check if user has appropriate permissions for detailed info
        has_admin_access = check_admin_access()

        fs_metrics = check_detailed_filesystem_metrics(full_details=has_admin_access)

        # Determine HTTP status code
        http_status = 200
        if fs_metrics.get("status") == "critical":
            http_status = 500

        return jsonify(fs_metrics), http_status

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

    def check_detailed_filesystem_metrics(full_details: bool = False) -> Dict[str, Any]:
        """
        Detailed filesystem metrics check.

        Collects comprehensive metrics about filesystem usage,
        performance, and potential issues.

        Args:
            full_details: Whether to include detailed per-directory information

        Returns:
            Dict[str, Any]: Detailed filesystem metrics
        """
        result = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        try:
            # Try to use FileSystemMetrics class if available
            try:
                from core.metrics import FileSystemMetrics

                # Get filesystem metrics
                fs_metrics = FileSystemMetrics.get_filesystem_metrics()

                # Basic metrics
                result["partitions"] = fs_metrics.get("partitions", [])
                result["overall_status"] = fs_metrics.get("overall_status", "healthy")
                result["status"] = result["overall_status"]

                # IO counters if available
                if "io_counters" in fs_metrics:
                    result["io_metrics"] = {
                        "read_count": fs_metrics["io_counters"].get("read_count", 0),
                        "write_count": fs_metrics["io_counters"].get("write_count", 0),
                        "read_bytes": fs_metrics["io_counters"].get("read_bytes", 0),
                        "write_bytes": fs_metrics["io_counters"].get("write_bytes", 0),
                        "read_time": fs_metrics["io_counters"].get("read_time", 0),
                        "write_time": fs_metrics["io_counters"].get("write_time", 0)
                    }

                # Include inode usage if available
                if "inodes" in fs_metrics:
                    result["inodes"] = fs_metrics["inodes"]

                # Include per-disk IO metrics if requested and available
                if full_details and "per_disk_io" in fs_metrics:
                    result["per_disk_io"] = fs_metrics["per_disk_io"]

                # Try to get storage trend metrics
                try:
                    trend_metrics = FileSystemMetrics.get_storage_trend_metrics(days=7)
                    if trend_metrics.get("trend_available"):
                        result["storage_trends"] = {
                            "daily_growth_rate": trend_metrics.get("daily_growth_rate"),
                            "current_usage": trend_metrics.get("current_value"),
                            "days_until_critical": trend_metrics.get("days_until_critical"),
                            "trend_status": trend_metrics.get("trend_status", "healthy")
                        }

                        # Update status if trend is critical
                        if trend_metrics.get("trend_status") == "critical" and result["status"] != "critical":
                            result["status"] = "warning"
                except Exception as trend_err:
                    logger.debug(f"Could not get storage trends: {trend_err}")

                # Add recommendations based on status
                if result["status"] == "critical":
                    result["recommendations"] = [
                        "Immediate action required: Clean up disk space on critically full partitions",
                        "Consider expanding storage for affected partitions",
                        "Check for large log files or temporary files that can be pruned"
                    ]
                elif result["status"] == "warning":
                    result["recommendations"] = [
                        "Monitor disk usage closely for continued growth",
                        "Review storage allocation and consider cleanup procedures",
                        "Verify backup procedures are in place for critical data"
                    ]

                return result

            except ImportError:
                # Fall back to direct implementation
                logger.debug("FileSystemMetrics not available, using fallback")
                pass

            # Direct implementation without relying on FileSystemMetrics
            partitions = []
            overall_status = "healthy"
            critical_partitions = []
            warning_partitions = []

            # Check each disk partition
            for partition in psutil.disk_partitions(all=False):
                if not partition.mountpoint:
                    continue

                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    status = "healthy"

                    if usage.percent >= 95:
                        status = "critical"
                        overall_status = "critical"
                        critical_partitions.append(partition.mountpoint)
                    elif usage.percent >= 90:
                        status = "warning"
                        if overall_status == "healthy":
                            overall_status = "warning"
                        warning_partitions.append(partition.mountpoint)
                    elif usage.percent >= 80:
                        status = "degraded"
                        if overall_status == "healthy":
                            overall_status = "degraded"

                    partition_info = {
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total_gb": round(usage.total / (1024**3), 2),
                        "used_gb": round(usage.used / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2),
                        "usage_percent": usage.percent,
                        "status": status
                    }

                    # Get additional per-directory metrics for important paths
                    if full_details and partition.mountpoint == "/":
                        # Check specific application paths
                        important_paths = [
                            current_app.instance_path,
                            current_app.config.get('LOG_DIR'),
                            current_app.config.get('UPLOAD_FOLDER'),
                            current_app.config.get('TEMP_DIR', '/tmp')
                        ]

                        path_metrics = []
                        for path in important_paths:
                            if path and os.path.exists(path) and os.path.isdir(path):
                                try:
                                    path_size = get_directory_size(path)
                                    path_metrics.append({
                                        "path": path,
                                        "size_mb": round(path_size / (1024 * 1024), 2),
                                        "file_count": count_files(path)
                                    })
                                except Exception:
                                    pass

                        if path_metrics:
                            partition_info["directory_metrics"] = path_metrics

                    partitions.append(partition_info)
                except (PermissionError, OSError):
                    # Skip inaccessible partitions
                    continue

            # Add inode usage if on Unix-like systems
            inodes = []
            if hasattr(os, 'statvfs'):
                for partition_info in partitions:
                    try:
                        mountpoint = partition_info["mountpoint"]
                        stats = os.statvfs(mountpoint)

                        # Calculate inode usage
                        total_inodes = stats.f_files
                        free_inodes = stats.f_ffree
                        if total_inodes > 0:
                            used_inodes = total_inodes - free_inodes
                            usage_percent = (used_inodes / total_inodes) * 100

                            inode_status = "healthy"
                            if usage_percent > 95:
                                inode_status = "critical"
                                if overall_status != "critical":
                                    overall_status = "critical"
                            elif usage_percent > 90:
                                inode_status = "warning"
                                if overall_status == "healthy":
                                    overall_status = "warning"

                            inodes.append({
                                "mountpoint": mountpoint,
                                "total_inodes": total_inodes,
                                "free_inodes": free_inodes,
                                "used_inodes": used_inodes,
                                "usage_percent": round(usage_percent, 2),
                                "status": inode_status
                            })
                    except Exception:
                        continue

            # Calculate IO metrics if available
            io_metrics = {}
            try:
                io_counters = psutil.disk_io_counters()
                if io_counters:
                    io_metrics = {
                        "read_count": io_counters.read_count,
                        "write_count": io_counters.write_count,
                        "read_bytes": io_counters.read_bytes,
                        "write_bytes": io_counters.write_bytes
                    }

                    # Add read/write times if available
                    if hasattr(io_counters, 'read_time'):
                        io_metrics["read_time"] = io_counters.read_time
                    if hasattr(io_counters, 'write_time'):
                        io_metrics["write_time"] = io_counters.write_time
            except Exception:
                pass

            result["partitions"] = partitions
            result["partitions_count"] = len(partitions)
            result["status"] = overall_status

            if inodes:
                result["inodes"] = inodes

            if io_metrics:
                result["io_metrics"] = io_metrics

            # Check for large files growth
            if full_details:
                try:
                    large_files = find_large_files(current_app.instance_path)
                    if large_files:
                        result["large_files"] = large_files[:10]  # Top 10 largest files
                except Exception:
                    pass

            # Add recommendations based on status
            if critical_partitions:
                result["recommendations"] = [
                    f"Immediate action required: Clean up disk space on critical partitions: {', '.join(critical_partitions)}",
                    "Check for large log files or temporary files that can be removed",
                    "Consider adding more storage capacity"
                ]
            elif warning_partitions:
                result["recommendations"] = [
                    f"Monitor partitions approaching capacity: {', '.join(warning_partitions)}",
                    "Review data retention policies",
                    "Schedule maintenance for cleanup procedures"
                ]

            return result

        except Exception as e:
            logger.error(f"Error checking detailed filesystem metrics: {str(e)}")
            return {
                "status": "warning",
                "message": f"Error checking filesystem metrics: {str(e)}",
                "error": str(e)
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

    def get_directory_size(path: str) -> int:
        """
        Calculate the total size of a directory in bytes.

        Args:
            path: Directory path to check

        Returns:
            int: Total size in bytes
        """
        total_size = 0
        try:
            for dirpath, _, filenames in os.walk(path):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    if os.path.isfile(file_path):
                        total_size += os.path.getsize(file_path)
        except (PermissionError, OSError):
            pass
        return total_size

    def count_files(path: str) -> int:
        """
        Count the number of files in a directory.

        Args:
            path: Directory path to check

        Returns:
            int: Number of files
        """
        file_count = 0
        try:
            for dirpath, _, filenames in os.walk(path):
                file_count += len(filenames)
        except (PermissionError, OSError):
            pass
        return file_count

    def find_large_files(path: str, min_size_mb: int = 50) -> List[Dict[str, Any]]:
        """
        Find large files in a directory.

        Args:
            path: Directory path to check
            min_size_mb: Minimum file size to include in MB

        Returns:
            List[Dict[str, Any]]: List of large files with metadata
        """
        large_files = []
        min_bytes = min_size_mb * 1024 * 1024

        try:
            for dirpath, _, filenames in os.walk(path):
                for filename in filenames:
                    try:
                        file_path = os.path.join(dirpath, filename)
                        if os.path.isfile(file_path):
                            size = os.path.getsize(file_path)
                            if size >= min_bytes:
                                large_files.append({
                                    "path": file_path,
                                    "size_mb": round(size / (1024 * 1024), 2),
                                    "last_modified": datetime.fromtimestamp(
                                        os.path.getmtime(file_path), tz=timezone.utc
                                    ).isoformat()
                                })
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            pass

        # Sort by size (largest first)
        return sorted(large_files, key=lambda x: x["size_mb"], reverse=True)

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
    'check_redis_health',
    'check_filesystem_metrics_basic'
]
