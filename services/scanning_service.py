"""
Scanning Service for Cloud Infrastructure Platform.

This service provides functionality for managing security scanning operations across
different infrastructure components. It handles scan initiation, monitoring, and
results processing, integrating with various scanning engines and tools.

The service supports multiple scan types including vulnerability scanning, compliance
checking, configuration analysis, security posture assessment, penetration testing,
code analysis, container scanning, and IAM reviews.
"""

import logging
import json
import uuid
import os
import time
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timezone, timedelta
import threading
import queue
import traceback

# Core imports
from core.security import log_security_event
from extensions import metrics, cache, celery, db

# Models
try:
    from models.security import SecurityScan, AuditLog
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False
    logging.warning("Security models not available in ScanningService")

# Constants for scan profiles
DEFAULT_PROFILES = {
    "standard": {
        "id": "standard",
        "name": "Standard Scan",
        "description": "Balanced security scan with moderate depth",
        "scan_types": ["vulnerability", "configuration", "compliance"],
        "intensity": "standard",
        "is_default": True,
        "parameters": {
            "depth": "medium",
            "parallel_checks": 4,
            "timeout": 3600,
            "non_invasive": True
        }
    },
    "quick": {
        "id": "quick",
        "name": "Quick Scan",
        "description": "Fast scan with limited depth for critical vulnerabilities",
        "scan_types": ["vulnerability", "configuration"],
        "intensity": "low",
        "is_default": False,
        "parameters": {
            "depth": "low",
            "parallel_checks": 6,
            "timeout": 1800,
            "non_invasive": True,
            "critical_only": True
        }
    },
    "full": {
        "id": "full",
        "name": "Full Scan",
        "description": "Comprehensive deep scan across all security dimensions",
        "scan_types": ["vulnerability", "configuration", "compliance", "posture", "code"],
        "intensity": "high",
        "is_default": False,
        "parameters": {
            "depth": "high",
            "parallel_checks": 2,
            "timeout": 7200,
            "non_invasive": False,
            "follow_dependencies": True
        }
    },
    "compliance": {
        "id": "compliance",
        "name": "Compliance Scan",
        "description": "Focused on regulatory compliance requirements",
        "scan_types": ["compliance", "configuration", "iam"],
        "intensity": "standard",
        "is_default": False,
        "parameters": {
            "depth": "medium",
            "parallel_checks": 4,
            "timeout": 3600,
            "frameworks": ["pci-dss", "hipaa", "gdpr", "iso27001"]
        }
    }
}

# Configure logging
logger = logging.getLogger(__name__)

# Worker threads and queues for scan execution
scan_queue = queue.Queue()
scan_workers = {}
MAX_CONCURRENT_SCANS = 5  # Maximum number of concurrent scans

class ScanningService:
    """
    Service for managing security scans across the platform.

    This service handles:
    - Starting and scheduling scans
    - Managing scan execution across different engines
    - Processing and storing scan results
    - Providing scan metrics and insights
    """

    @staticmethod
    def get_available_scan_profiles() -> List[Dict[str, Any]]:
        """
        Get available scan profiles.

        Returns:
            List of scan profile configurations
        """
        # In a real implementation, this might be loaded from a database or configuration
        # For now, we'll use our predefined profiles
        return list(DEFAULT_PROFILES.values())

    @staticmethod
    def get_profile(profile_id: str) -> Dict[str, Any]:
        """
        Get a specific scan profile by ID.

        Args:
            profile_id: ID of the profile to retrieve

        Returns:
            Profile configuration or default if not found
        """
        return DEFAULT_PROFILES.get(profile_id, DEFAULT_PROFILES["standard"])

    @staticmethod
    def start_scan(scan: Any) -> bool:
        """
        Start a security scan.

        Args:
            scan: SecurityScan object to start

        Returns:
            bool: True if scan was successfully queued, False otherwise
        """
        if not MODELS_AVAILABLE:
            logger.error("Cannot start scan: Security models not available")
            return False

        try:
            # Log the start attempt
            logger.info("Attempting to start scan ID %s of type %s", scan.id, scan.scan_type)

            # For asynchronous execution via Celery
            if celery:
                try:
                    # Import here to avoid circular imports
                    from celery_tasks.security import execute_security_scan
                    task = execute_security_scan.delay(scan.id)
                    logger.info("Queued scan %s with Celery task ID %s", scan.id, task.id)
                    return True
                except ImportError:
                    logger.warning("Celery tasks not available, falling back to thread pool")
                except Exception as e:
                    logger.error("Failed to queue Celery task for scan %s: %s", scan.id, str(e))

            # Fall back to thread pool execution
            # Check if we already have too many scans running
            active_scans = len([w for w in scan_workers.values() if w.is_alive()])
            if active_scans >= MAX_CONCURRENT_SCANS:
                logger.warning("Maximum concurrent scans reached (%d). Queuing scan %s",
                              MAX_CONCURRENT_SCANS, scan.id)

            # Queue the scan for execution
            scan_queue.put(scan.id)

            # Start a worker thread if needed
            worker_name = f"scan-worker-{str(uuid.uuid4())[:8]}"
            if worker_name not in scan_workers or not scan_workers[worker_name].is_alive():
                worker = threading.Thread(
                    target=ScanningService._scan_worker_thread,
                    name=worker_name,
                    daemon=True
                )
                scan_workers[worker_name] = worker
                worker.start()
                logger.debug("Started new scan worker thread: %s", worker_name)

            return True

        except Exception as e:
            logger.error("Failed to start scan %s: %s", scan.id if hasattr(scan, 'id') else 'unknown', str(e))
            log_security_event(
                event_type=getattr(AuditLog, 'EVENT_SECURITY_SCAN_ERROR', 'security_scan_error'),
                description=f"Failed to start security scan: {str(e)}",
                severity="error",
                details={"scan_id": scan.id if hasattr(scan, 'id') else None, "error": str(e)}
            )
            return False

    @staticmethod
    def _scan_worker_thread() -> None:
        """Background worker thread that processes scans from the queue."""
        while True:
            try:
                # Get next scan ID with a timeout
                scan_id = scan_queue.get(timeout=60)

                if scan_id is None:
                    # Special sentinel value to stop the thread
                    break

                try:
                    # Fetch the scan object
                    scan = SecurityScan.find_by_id(scan_id)
                    if not scan:
                        logger.warning("Scan %s not found, skipping execution", scan_id)
                        continue

                    # Mark scan as in progress
                    scan.mark_in_progress()
                    scan.save()

                    # Execute the actual scan
                    ScanningService._execute_scan(scan)

                except Exception as e:
                    logger.error("Error processing scan %s: %s", scan_id, str(e), exc_info=True)
                    try:
                        # Try to mark the scan as failed
                        scan = SecurityScan.find_by_id(scan_id)
                        if scan:
                            scan.mark_failed(f"Internal error: {str(e)}")
                            scan.save()
                    except Exception:
                        pass
                finally:
                    scan_queue.task_done()

            except queue.Empty:
                # Queue timeout, check if we should continue running
                continue
            except Exception as e:
                logger.error("Unexpected error in scan worker thread: %s", str(e), exc_info=True)
                # Sleep briefly to avoid CPU spinning on repeated errors
                time.sleep(1)

    @staticmethod
    def _execute_scan(scan: 'SecurityScan') -> None:
        """
        Execute a security scan using the appropriate scanner for its type.

        Args:
            scan: The SecurityScan object to execute
        """
        logger.info("Executing scan %s of type %s", scan.id, scan.scan_type)
        scan_type = scan.scan_type

        try:
            # Get scan profile configuration
            profile = ScanningService.get_profile(scan.profile or "standard")

            # Choose appropriate scanner for the scan type
            if scan_type == SecurityScan.TYPE_VULNERABILITY:
                findings = ScanningService._run_vulnerability_scan(scan, profile)
            elif scan_type == SecurityScan.TYPE_COMPLIANCE:
                findings = ScanningService._run_compliance_scan(scan, profile)
            elif scan_type == SecurityScan.TYPE_CONFIGURATION:
                findings = ScanningService._run_configuration_scan(scan, profile)
            elif scan_type == SecurityScan.TYPE_CODE:
                findings = ScanningService._run_code_scan(scan, profile)
            elif scan_type == SecurityScan.TYPE_CONTAINER:
                findings = ScanningService._run_container_scan(scan, profile)
            elif scan_type == SecurityScan.TYPE_IAM:
                findings = ScanningService._run_iam_scan(scan, profile)
            else:
                findings = ScanningService._run_generic_scan(scan, profile)

            # Add findings to scan
            success = scan.add_findings(findings)
            if not success:
                logger.warning("Failed to add findings to scan %s", scan.id)

            # Create scan result summary
            summary = {
                "scan_id": scan.id,
                "scan_type": scan.scan_type,
                "total_findings": len(findings),
                "target_count": scan.target_count,
                "by_severity": {
                    "critical": sum(1 for f in findings if f.get('severity') == 'critical'),
                    "high": sum(1 for f in findings if f.get('severity') == 'high'),
                    "medium": sum(1 for f in findings if f.get('severity') == 'medium'),
                    "low": sum(1 for f in findings if f.get('severity') == 'low'),
                    "info": sum(1 for f in findings if f.get('severity') == 'info')
                },
                "scan_parameters": {
                    "profile": scan.profile,
                    "options": scan.options
                }
            }

            # Mark scan as completed
            scan.mark_completed(summary)
            scan.save()

            # Record successful completion in metrics
            metrics.info('security_scans_executed_total', 1, {
                'type': scan.scan_type,
                'status': 'completed',
                'finding_count': len(findings)
            })

            logger.info("Scan %s completed successfully with %d findings", scan.id, len(findings))

        except Exception as e:
            error_msg = f"Error executing scan {scan.id}: {str(e)}"
            logger.error(error_msg, exc_info=True)

            # Record the failure
            metrics.info('security_scans_executed_total', 1, {
                'type': scan.scan_type,
                'status': 'failed'
            })

            # Mark scan as failed
            scan.mark_failed(error_msg)
            scan.save()

    @staticmethod
    def _run_vulnerability_scan(scan: 'SecurityScan', profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run a vulnerability scan against target systems.

        Args:
            scan: SecurityScan to execute
            profile: Scan profile configuration

        Returns:
            List of vulnerability findings
        """
        findings = []
        targets = scan.targets
        logger.info("Running vulnerability scan on %d targets", len(targets))

        # Simulate vulnerability scanning on each target
        for target in targets:
            target_id = target.get('id') if isinstance(target, dict) else target

            # In a real implementation, we would integrate with actual scanning tools
            # For demonstration, we'll generate simulated findings
            findings.extend(ScanningService._generate_simulated_findings(
                scan_type='vulnerability',
                target=target_id,
                count=3
            ))

        return findings

    @staticmethod
    def _run_compliance_scan(scan: 'SecurityScan', profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run a compliance scan against targets."""
        findings = []
        targets = scan.targets
        logger.info("Running compliance scan on %d targets", len(targets))

        # Get compliance frameworks from profile
        frameworks = profile.get('parameters', {}).get('frameworks', ['default'])

        # Simulate compliance checking on each target
        for target in targets:
            target_id = target.get('id') if isinstance(target, dict) else target

            # Generate simulated compliance findings
            findings.extend(ScanningService._generate_simulated_findings(
                scan_type='compliance',
                target=target_id,
                count=5,
                metadata={'frameworks': frameworks}
            ))

        return findings

    @staticmethod
    def _run_configuration_scan(scan: 'SecurityScan', profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run a configuration scan against targets."""
        findings = []
        targets = scan.targets
        logger.info("Running configuration scan on %d targets", len(targets))

        # Simulate configuration scanning
        for target in targets:
            target_id = target.get('id') if isinstance(target, dict) else target

            findings.extend(ScanningService._generate_simulated_findings(
                scan_type='configuration',
                target=target_id,
                count=4
            ))

        return findings

    @staticmethod
    def _run_code_scan(scan: 'SecurityScan', profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run a code security scan."""
        findings = []
        targets = scan.targets
        logger.info("Running code security scan")

        # In a real implementation, we would integrate with SAST tools like:
        # - Bandit for Python
        # - ESLint+Security for JavaScript
        # - Semgrep for multiple languages

        for target in targets:
            target_id = target.get('id') if isinstance(target, dict) else target

            findings.extend(ScanningService._generate_simulated_findings(
                scan_type='code',
                target=target_id,
                count=3
            ))

        return findings

    @staticmethod
    def _run_container_scan(scan: 'SecurityScan', profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run a container security scan."""
        findings = []
        targets = scan.targets
        logger.info("Running container security scan")

        # In a real implementation, we would integrate with tools like:
        # - Trivy
        # - Clair
        # - Anchore

        for target in targets:
            target_id = target.get('id') if isinstance(target, dict) else target

            findings.extend(ScanningService._generate_simulated_findings(
                scan_type='container',
                target=target_id,
                count=3
            ))

        return findings

    @staticmethod
    def _run_iam_scan(scan: 'SecurityScan', profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run an IAM configuration scan."""
        findings = []
        targets = scan.targets
        logger.info("Running IAM security scan")

        for target in targets:
            target_id = target.get('id') if isinstance(target, dict) else target

            findings.extend(ScanningService._generate_simulated_findings(
                scan_type='iam',
                target=target_id,
                count=2
            ))

        return findings

    @staticmethod
    def _run_generic_scan(scan: 'SecurityScan', profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run a generic security scan."""
        findings = []
        targets = scan.targets
        logger.info("Running generic security scan of type: %s", scan.scan_type)

        for target in targets:
            target_id = target.get('id') if isinstance(target, dict) else target

            findings.extend(ScanningService._generate_simulated_findings(
                scan_type=scan.scan_type,
                target=target_id,
                count=2
            ))

        return findings

    @staticmethod
    def _generate_simulated_findings(
        scan_type: str,
        target: str,
        count: int = 3,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate simulated security findings for testing and development.

        Args:
            scan_type: Type of scan
            target: Target identifier
            count: Number of findings to generate
            metadata: Additional metadata to include

        Returns:
            List of simulated findings
        """
        finding_templates = {
            'vulnerability': [
                {
                    'title': 'SQL Injection Vulnerability',
                    'description': 'SQL injection vulnerability found in application endpoint',
                    'severity': 'critical',
                    'remediation': 'Use parameterized queries and input validation',
                    'cve': 'CVE-2021-12345'
                },
                {
                    'title': 'Cross-Site Scripting (XSS)',
                    'description': 'Reflected XSS vulnerability in user input field',
                    'severity': 'high',
                    'remediation': 'Implement proper output encoding',
                    'cve': None
                },
                {
                    'title': 'Outdated SSL/TLS Version',
                    'description': 'Server supports outdated TLS 1.0 protocol',
                    'severity': 'medium',
                    'remediation': 'Disable TLS 1.0/1.1 and enable only TLS 1.2+',
                    'cve': None
                },
                {
                    'title': 'Insecure HTTP Headers',
                    'description': 'Missing security headers: X-XSS-Protection, X-Content-Type-Options',
                    'severity': 'low',
                    'remediation': 'Configure web server to include recommended security headers',
                    'cve': None
                }
            ],
            'compliance': [
                {
                    'title': 'Missing Data Encryption',
                    'description': 'Sensitive data is not encrypted at rest',
                    'severity': 'high',
                    'remediation': 'Implement encryption for sensitive data storage',
                    'compliance_refs': ['PCI-DSS 3.4', 'GDPR Art. 32']
                },
                {
                    'title': 'Insufficient Audit Logging',
                    'description': 'Security-relevant events are not properly logged',
                    'severity': 'medium',
                    'remediation': 'Enable comprehensive audit logging',
                    'compliance_refs': ['ISO 27001 A.12.4.1', 'HIPAA 164.312(b)']
                },
                {
                    'title': 'Missing Access Review Process',
                    'description': 'No evidence of regular access permission reviews',
                    'severity': 'medium',
                    'remediation': 'Implement quarterly access review process',
                    'compliance_refs': ['SOC2 CC6.3', 'ISO 27001 A.9.2.5']
                }
            ],
            'configuration': [
                {
                    'title': 'Default Credentials',
                    'description': 'System using default or weak passwords',
                    'severity': 'critical',
                    'remediation': 'Change default passwords and implement password policy'
                },
                {
                    'title': 'Excessive Permissions',
                    'description': 'Service account has more permissions than required',
                    'severity': 'high',
                    'remediation': 'Apply principle of least privilege'
                },
                {
                    'title': 'Insecure Configuration',
                    'description': 'Debug mode enabled in production environment',
                    'severity': 'medium',
                    'remediation': 'Disable debug features in production'
                }
            ],
            'code': [
                {
                    'title': 'Hardcoded Secret',
                    'description': 'API key found hardcoded in source code',
                    'severity': 'critical',
                    'remediation': 'Move credentials to secure storage or environment variables',
                    'location': 'src/api/client.py:45'
                },
                {
                    'title': 'Insecure Deserialization',
                    'description': 'Unsafe deserialization of user input',
                    'severity': 'high',
                    'remediation': 'Use safe deserialization methods',
                    'location': 'src/utils/parser.py:120'
                },
                {
                    'title': 'Directory Traversal',
                    'description': 'Path not properly sanitized, allowing directory traversal',
                    'severity': 'high',
                    'remediation': 'Validate and sanitize file paths',
                    'location': 'src/services/file_service.py:87'
                }
            ],
            'container': [
                {
                    'title': 'Container Running as Root',
                    'description': 'Container process running with root privileges',
                    'severity': 'high',
                    'remediation': 'Use non-root user in Dockerfile'
                },
                {
                    'title': 'Outdated Base Image',
                    'description': 'Container using outdated base image with known vulnerabilities',
                    'severity': 'high',
                    'remediation': 'Update to latest patched base image'
                },
                {
                    'title': 'Excessive Container Capabilities',
                    'description': 'Container has unnecessary Linux capabilities',
                    'severity': 'medium',
                    'remediation': 'Drop unnecessary capabilities in container configuration'
                }
            ],
            'iam': [
                {
                    'title': 'Overly Permissive IAM Policy',
                    'description': 'IAM policy grants excessive permissions',
                    'severity': 'high',
                    'remediation': 'Apply least privilege principle to IAM policies'
                },
                {
                    'title': 'Missing MFA',
                    'description': 'Privileged users not required to use multi-factor authentication',
                    'severity': 'high',
                    'remediation': 'Enable MFA requirement for all privileged accounts'
                },
                {
                    'title': 'Inactive User Accounts',
                    'description': 'Multiple user accounts inactive for >90 days',
                    'severity': 'medium',
                    'remediation': 'Implement automated deactivation of inactive accounts'
                }
            ]
        }

        # Use generic findings if scan type not found in templates
        templates = finding_templates.get(scan_type, finding_templates['vulnerability'])
        findings = []

        # Generate random findings from the templates
        import random
        for i in range(min(count, len(templates))):
            template = random.choice(templates)
            finding_id = str(uuid.uuid4())

            finding = {
                'id': finding_id,
                'title': template['title'],
                'description': template['description'],
                'severity': template['severity'],
                'remediation': template['remediation'],
                'scan_type': scan_type,
                'target_id': target,
                'status': 'open',
                'discovered_at': datetime.now(timezone.utc).isoformat(),
                'details': {}
            }

            # Add type-specific details
            if 'cve' in template and template['cve']:
                finding['details']['cve'] = template['cve']

            if 'compliance_refs' in template:
                finding['details']['compliance_refs'] = template['compliance_refs']

            if 'location' in template:
                finding['details']['location'] = template['location']

            # Add provided metadata
            if metadata:
                finding['metadata'] = metadata

            findings.append(finding)

        return findings

    @staticmethod
    def estimate_scan_duration(scan_type: str, targets: List[Dict[str, Any]], profile: str = "standard") -> int:
        """
        Estimate scan duration in minutes based on scan type, targets and profile.

        Args:
            scan_type: Type of scan to execute
            targets: List of scan targets
            profile: Scan profile name

        Returns:
            Estimated duration in minutes
        """
        # Get profile configuration
        profile_config = ScanningService.get_profile(profile)
        intensity = profile_config.get('intensity', 'standard')

        # Base times per scan type (in minutes)
        base_times = {
            'vulnerability': 15,
            'compliance': 20,
            'configuration': 10,
            'posture': 25,
            'penetration': 40,
            'code': 12,
            'container': 8,
            'iam': 5
        }

        # Intensity multipliers
        intensity_multipliers = {
            'low': 0.5,
            'standard': 1.0,
            'high': 2.0
        }

        # Calculate base time
        base_time = base_times.get(scan_type, 10)

        # Apply intensity multiplier
        multiplier = intensity_multipliers.get(intensity, 1.0)

        # Calculate target count (with a minimum of 1)
        target_count = max(1, len(targets))

        # Calculate estimated duration
        estimated_minutes = int(base_time * multiplier * target_count)

        # Add a small random variation (±20%)
        import random
        variation_factor = random.uniform(0.8, 1.2)
        estimated_minutes = int(estimated_minutes * variation_factor)

        return max(1, estimated_minutes)  # Ensure minimum 1 minute

    @staticmethod
    def cancel_scan(scan: Any) -> bool:
        """
        Cancel a running or queued scan.

        Args:
            scan: SecurityScan object to cancel

        Returns:
            bool: True if cancellation was successful
        """
        if not MODELS_AVAILABLE:
            logger.error("Cannot cancel scan: Security models not available")
            return False

        try:
            scan_id = scan.id
            logger.info("Attempting to cancel scan ID %s", scan_id)

            # If scan is queued but not yet running, remove from queue
            # This is an approximation since we can't easily check the queue
            # In a real implementation, we might use a more robust task queue with cancellation

            # For now, we just mark the scan as cancelled and let any running processes
            # check for this state
            logger.info("Scan ID %s marked as cancelled", scan_id)

            # Log cancellation event
            log_security_event(
                event_type=getattr(AuditLog, 'EVENT_SECURITY_SCAN_STATUS_CHANGE', 'security_scan_status_change'),
                description=f"Security scan cancelled: {scan_id}",
                severity="info",
                details={"scan_id": scan_id}
            )

            return True

        except Exception as e:
            logger.error("Failed to cancel scan %s: %s",
                       scan.id if hasattr(scan, 'id') else 'unknown', str(e))
            return False

    @staticmethod
    def get_scan_health_metrics() -> Dict[str, Any]:
        """
        Get health metrics for scanning operations.

        Returns:
            Dict containing scan health metrics
        """
        if not MODELS_AVAILABLE:
            logger.error("Cannot get scan metrics: Security models not available")
            return {
                'health_status': 'unknown',
                'error': 'Security models not available'
            }

        try:
            # Get metrics from model method
            return SecurityScan.get_scan_health_metrics()

        except Exception as e:
            logger.error("Error getting scan health metrics: %s", str(e))
            return {
                'health_status': 'unknown',
                'error': str(e)
            }

    @staticmethod
    def shutdown_workers() -> None:
        """
        Shutdown all scan worker threads gracefully.
        Call this during application shutdown.
        """
        logger.info("Shutting down scan workers...")

        # Add None to queue for each worker to signal shutdown
        for _ in scan_workers:
            scan_queue.put(None)

        # Wait for workers to finish (with timeout)
        for worker_name, worker in scan_workers.items():
            worker.join(timeout=2.0)
            if worker.is_alive():
                logger.warning("Worker %s did not shut down gracefully", worker_name)

# Initialize scan workers on module import
def _init_scan_workers():
    """Initialize the scan worker threads."""
    # Start a single initial worker
    if MODELS_AVAILABLE:
        worker_name = "scan-worker-initial"
        worker = threading.Thread(
            target=ScanningService._scan_worker_thread,
            name=worker_name,
            daemon=True
        )
        scan_workers[worker_name] = worker
        worker.start()
        logger.debug("Started initial scan worker thread")

# Run initialization if this is the main thread
if threading.current_thread() is threading.main_thread():
    _init_scan_workers()

# Register shutdown handler
import atexit
atexit.register(ScanningService.shutdown_workers)
