#!/usr/bin/env python3
"""
Configuration Analyzer

This tool analyzes system configurations against security baselines and compliance requirements.
It identifies misconfigurations, security policy violations, and configuration drift across systems.

Features:
- Configuration comparison against security baselines
- Hardening validation against CIS benchmarks
- Configuration drift detection
- Policy compliance checking
- Detailed remediation guidance
- Historical configuration tracking
- Customizable configuration checks
- Multi-system consistency validation
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union

# Add parent directory to path to allow imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from core_assessment_tools.common import (
        AssessmentBase,
        AssessmentStatus,
        AssessmentTarget,
        Finding,
        FindingSeverity,
        Evidence,
        Remediation,
        CVSS,

        # Import permission utilities
        check_assessment_permission,
        verify_target_access,
        secure_operation,

        # Import logging utilities
        setup_assessment_logging,
        log_assessment_event,
        log_security_finding,

        # Import common utilities
        validate_target,
        validate_output_format,
        validate_compliance_framework
    )
except ImportError as e:
    print(f"Error importing core assessment modules: {e}", file=sys.stderr)
    print("Please ensure that the core_assessment_tools package is properly installed.", file=sys.stderr)
    sys.exit(1)

# Constants
TOOL_NAME = "Configuration Analyzer"
TOOL_VERSION = "1.0.0"
DEFAULT_OUTPUT_FORMAT = "standard"
DEFAULT_BASELINE = "default"
DEFAULT_LOG_DIR = "logs/configuration_analyzer"

# Security baseline categories
BASELINE_CATEGORIES = {
    "authentication": {"severity": FindingSeverity.HIGH, "impact": 0.8},
    "authorization": {"severity": FindingSeverity.HIGH, "impact": 0.8},
    "encryption": {"severity": FindingSeverity.HIGH, "impact": 0.7},
    "logging": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "network": {"severity": FindingSeverity.HIGH, "impact": 0.7},
    "updates": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "hardening": {"severity": FindingSeverity.MEDIUM, "impact": 0.5},
    "services": {"severity": FindingSeverity.MEDIUM, "impact": 0.5},
    "file_permissions": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "default_settings": {"severity": FindingSeverity.LOW, "impact": 0.4},
}


class ConfigurationAnalyzer(AssessmentBase):
    """
    Main class for analyzing system configurations against security baselines.
    """

    def __init__(
        self,
        target: AssessmentTarget,
        baseline_name: str = DEFAULT_BASELINE,
        compliance_framework: Optional[str] = None,
        critical_only: bool = False,
        detect_drift: bool = False,
        include_remediation: bool = True,
        assessment_id: Optional[str] = None,
        output_format: str = DEFAULT_OUTPUT_FORMAT,
        output_file: Optional[str] = None,
        evidence_collection: bool = False,
        **kwargs
    ):
        """
        Initialize the configuration analyzer.

        Args:
            target: Target system to analyze
            baseline_name: Name of the baseline to compare against
            compliance_framework: Optional compliance framework to check against
            critical_only: Focus only on critical security controls
            detect_drift: Enable configuration drift detection
            include_remediation: Include remediation guidance in findings
            assessment_id: Optional identifier for this assessment
            output_format: Format for assessment output
            output_file: Optional file to write results to
            evidence_collection: Whether to collect evidence during assessment
            **kwargs: Additional parameters
        """
        super().__init__(
            TOOL_NAME,
            target,
            assessment_id=assessment_id,
            output_format=output_format,
            output_file=output_file,
            profile_name="default",
            compliance_framework=compliance_framework,
            evidence_collection=evidence_collection,
            non_invasive=True,
            **kwargs
        )

        self.baseline_name = baseline_name
        self.critical_only = critical_only
        self.detect_drift = detect_drift
        self.include_remediation = include_remediation

        self.baseline_data = {}
        self.system_config = {}
        self.config_diff = {}
        self.historical_configs = []
        self.drift_findings = []

        self.logger.info(f"Configuration analyzer initialized for target: {target.target_id}")
        self.logger.info(f"Using baseline: {baseline_name}")
        if compliance_framework:
            self.logger.info(f"Compliance framework: {compliance_framework}")
        if critical_only:
            self.logger.info("Focus mode: Critical security controls only")
        if detect_drift:
            self.logger.info("Configuration drift detection enabled")

    @secure_operation("assessment:execute")
    def initialize(self) -> bool:
        """
        Initialize the assessment by loading configuration and baselines.

        Returns:
            bool: Whether initialization was successful
        """
        self.logger.info(f"Starting {TOOL_NAME} initialization...")

        try:
            # Create assessment evidence directory if needed
            if self.evidence_collection:
                self.evidence_paths.append(self._create_evidence_directory())

            # Check for required permissions to run this assessment
            if not verify_target_access(self.target, "configuration_analysis"):
                self.add_error(f"No permission to analyze configuration on {self.target.target_id}")
                return False

            # Load security baseline
            success = self._load_security_baseline()
            if not success:
                return False

            # Set assessment status to initialized
            self.status = AssessmentStatus.INITIALIZED
            self.logger.info(f"Successfully initialized {TOOL_NAME}")
            return True

        except Exception as e:
            self.add_error(f"Failed to initialize assessment: {str(e)}")
            self.logger.exception(f"Initialization error in {TOOL_NAME}")
            return False

    @secure_operation("assessment:execute")
    def execute(self) -> bool:
        """
        Execute the configuration analysis.

        Returns:
            bool: Whether the assessment completed successfully
        """
        if self.status != AssessmentStatus.INITIALIZED:
            self.add_error("Cannot execute assessment: not properly initialized")
            return False

        try:
            self.status = AssessmentStatus.RUNNING
            self.start_time = datetime.now()
            self.logger.info(f"Starting configuration analysis for {self.target.target_id}")

            # Collect current configuration from target system
            success = self._collect_system_configuration()
            if not success:
                self.add_error("Failed to collect system configuration")
                self.status = AssessmentStatus.FAILED
                return False

            # Compare configuration against baseline
            self._compare_with_baseline()

            # Check for configuration drift if requested
            if self.detect_drift:
                self._detect_configuration_drift()

            # Apply compliance checks if a framework was specified
            if self.compliance_framework:
                self._apply_compliance_checks()

            self.status = AssessmentStatus.COMPLETED
            self.end_time = datetime.now()
            self.logger.info(f"Configuration analysis completed successfully")

            return True

        except Exception as e:
            self.status = AssessmentStatus.FAILED
            self.logger.exception(f"Error during configuration analysis: {str(e)}")
            self.add_error(f"Assessment failed with error: {str(e)}")
            return False

    def analyze_findings(self) -> List[Finding]:
        """
        Analyze assessment results to produce findings.

        Returns:
            List of findings from the assessment
        """
        findings = []

        # Process baseline comparison findings
        for category, issues in self.config_diff.items():
            if not issues:
                continue

            # Skip non-critical findings if critical_only is enabled
            if self.critical_only and BASELINE_CATEGORIES.get(category, {}).get("severity") not in [
                FindingSeverity.CRITICAL, FindingSeverity.HIGH
            ]:
                continue

            for issue in issues:
                severity = issue.get("severity", BASELINE_CATEGORIES.get(category, {}).get("severity", FindingSeverity.MEDIUM))

                # Create remediation guidance if requested
                remediation = None
                if self.include_remediation and "remediation" in issue:
                    remediation = Remediation(
                        description=issue["remediation"],
                        steps=issue.get("remediation_steps", []),
                        resources=issue.get("remediation_resources", []),
                        effort=issue.get("remediation_effort", "medium"),
                    )

                # Create finding
                finding = Finding(
                    title=issue["title"],
                    description=issue["description"],
                    severity=severity,
                    category=category,
                    affected_resource=issue.get("resource", self.target.target_id),
                    remediation=remediation,
                    evidence=self._collect_finding_evidence(issue) if self.evidence_collection else None,
                    references=issue.get("references", []),
                    cvss=self._calculate_cvss_vector(category, severity) if severity != FindingSeverity.INFO else None,
                    compliance_impacts=issue.get("compliance_impacts", []),
                    details=issue
                )

                findings.append(finding)

        # Add drift findings if any were detected
        findings.extend(self.drift_findings)

        self.logger.info(f"Generated {len(findings)} findings from configuration analysis")
        return findings

    def _create_evidence_directory(self) -> str:
        """
        Create directory for storing evidence.

        Returns:
            Path to the evidence directory
        """
        evidence_dir = os.path.join(
            "evidence",
            "configuration",
            self.target.target_id,
            self.assessment_id,
            datetime.now().strftime("%Y%m%d_%H%M%S")
        )

        os.makedirs(evidence_dir, exist_ok=True)
        self.logger.info(f"Created evidence directory: {evidence_dir}")

        return evidence_dir

    def _load_security_baseline(self) -> bool:
        """
        Load the security baseline for comparison.

        Returns:
            bool: Whether the baseline was loaded successfully
        """
        try:
            # Determine if this is a system type baseline or a custom baseline
            if self.baseline_name in ["linux_server_baseline", "web_server_baseline",
                                      "database_baseline", "application_baseline",
                                      "container_baseline", "cloud_service_baseline",
                                      "identity_management_baseline", "web_server_baseline",
                                      "network_appliance_baseline"]:
                baseline_path = Path(parent_dir) / "config_files" / "security_baselines" / f"{self.baseline_name}.json"
            else:
                baseline_path = Path(parent_dir) / "config_files" / "custom_baselines" / f"{self.baseline_name}.json"

            # Check for baseline existence
            if not baseline_path.exists():
                # Try default path as fallback
                default_path = Path(parent_dir) / "config_files" / "security_baselines" / "default.json"
                if default_path.exists():
                    self.logger.warning(f"Baseline {self.baseline_name} not found, using default baseline")
                    baseline_path = default_path
                else:
                    self.add_error(f"Security baseline '{self.baseline_name}' not found")
                    return False

            # Load baseline data
            with open(baseline_path, 'r') as f:
                self.baseline_data = json.load(f)

            # Apply compliance framework specifics if needed
            if self.compliance_framework:
                self._apply_compliance_baseline()

            self.logger.info(f"Loaded security baseline: {baseline_path}")
            return True

        except json.JSONDecodeError as e:
            self.add_error(f"Invalid baseline format: {str(e)}")
            self.logger.error(f"Failed to parse baseline JSON: {str(e)}")
            return False

        except Exception as e:
            self.add_error(f"Failed to load security baseline: {str(e)}")
            self.logger.error(f"Error loading baseline: {str(e)}")
            return False

    def _apply_compliance_baseline(self) -> None:
        """
        Apply compliance-specific requirements to the baseline.
        """
        try:
            compliance_path = Path(parent_dir) / "config_files" / "assessment_profiles" / "compliance" / f"{self.compliance_framework}.json"

            if not compliance_path.exists():
                self.logger.warning(f"Compliance profile {self.compliance_framework} not found")
                self.add_warning(f"Compliance profile {self.compliance_framework} not found")
                return

            with open(compliance_path, 'r') as f:
                compliance_data = json.load(f)

            # Merge compliance requirements with the baseline
            if "security_controls" in compliance_data:
                if "security_controls" not in self.baseline_data:
                    self.baseline_data["security_controls"] = {}

                for category, controls in compliance_data["security_controls"].items():
                    if category not in self.baseline_data["security_controls"]:
                        self.baseline_data["security_controls"][category] = {}

                    self.baseline_data["security_controls"][category].update(controls)

            self.logger.info(f"Applied compliance requirements from {self.compliance_framework}")

        except Exception as e:
            self.logger.warning(f"Error applying compliance requirements: {str(e)}")
            self.add_warning(f"Could not apply compliance requirements: {str(e)}")

    def _collect_system_configuration(self) -> bool:
        """
        Collect current system configuration from the target system.

        Returns:
            bool: Whether configuration collection was successful
        """
        self.logger.info(f"Collecting configuration from {self.target.target_id}")

        try:
            # In a real implementation, this would connect to the target system
            # and collect actual configuration data. For the demo, we'll simulate this.

            # Collect configuration using appropriate collector based on target type
            if self.target.target_type == "server":
                self._collect_server_configuration()
            elif self.target.target_type == "database":
                self._collect_database_configuration()
            elif self.target.target_type == "cloud_service":
                self._collect_cloud_service_configuration()
            elif self.target.target_type == "web_application":
                self._collect_web_application_configuration()
            elif self.target.target_type == "network_appliance":
                self._collect_network_appliance_configuration()
            else:
                # Generic configuration collection
                self._collect_generic_configuration()

            # Store a snapshot of the configuration for evidence
            if self.evidence_collection:
                self._save_configuration_snapshot()

            self.logger.info(f"Successfully collected configuration data")
            return True

        except Exception as e:
            self.logger.error(f"Failed to collect configuration: {str(e)}")
            self.add_error(f"Configuration collection failed: {str(e)}")
            return False

    def _collect_server_configuration(self) -> None:
        """
        Collect configuration from a server system.
        """
        # In a real implementation, this would SSH into the server
        # and collect system configuration information.
        # For the demo, we'll simulate a server configuration.

        self.system_config = {
            "hostname": self.target.hostname,
            "os": {
                "type": "linux",
                "version": "Ubuntu 22.04 LTS",
                "kernel": "5.15.0-48-generic",
                "last_update": "2023-04-15"
            },
            "authentication": {
                "password_policy": {
                    "min_length": 8,  # Baseline might require 12
                    "complexity_required": True,
                    "max_age_days": 180,  # Baseline might require 90
                    "history_count": 10,
                    "account_lockout": True,
                    "lockout_threshold": 5,
                    "lockout_duration_minutes": 30
                },
                "mfa": {
                    "enabled": False,  # Baseline might require True
                    "methods": []
                },
                "ssh": {
                    "permit_root_login": "no",
                    "password_authentication": True,  # Baseline might require False
                    "protocol_version": 2
                }
            },
            "network": {
                "firewall": {
                    "enabled": True,
                    "default_deny": True,
                    "logging": True
                },
                "open_ports": [22, 80, 443, 3306],
                "listening_services": ["sshd", "apache2", "mysql"]
            },
            "services": {
                "unnecessary_services": ["telnet", "rsh"],
                "systemd_services": ["ssh", "apache2", "mysql"]
            },
            "updates": {
                "auto_updates": False,  # Baseline might require True
                "security_updates_only": True
            },
            "logging": {
                "enabled": True,
                "remote_logging": False,  # Baseline might require True
                "log_rotation": True,
                "retention_days": 30
            },
            "file_permissions": {
                "secure_permissions": True,
                "world_writable_files": 5
            }
        }

    def _collect_database_configuration(self) -> None:
        """
        Collect configuration from a database system.
        """
        # Simulated database configuration
        self.system_config = {
            "hostname": self.target.hostname,
            "database": {
                "type": "MySQL",
                "version": "8.0.28",
                "last_update": "2023-03-20"
            },
            "authentication": {
                "password_policy": {
                    "min_length": 10,
                    "complexity_required": True,
                    "account_lockout": True,
                    "lockout_threshold": 5
                },
                "default_users_removed": True,
                "anonymous_access": False
            },
            "network": {
                "bind_address": "127.0.0.1",
                "ssl_enabled": True,
                "ssl_enforced": False,  # Baseline might require True
                "tls_version": "TLSv1.2"
            },
            "security": {
                "encrypted_connections": True,
                "encrypted_storage": False,  # Baseline might require True
                "audit_logging": True,
                "privilege_separation": True,
                "least_privilege": False  # Baseline might require True
            }
        }

    def _collect_cloud_service_configuration(self) -> None:
        """
        Collect configuration from a cloud service.
        """
        # Simulated cloud service configuration
        self.system_config = {
            "service_id": self.target.target_id,
            "provider": "AWS",
            "service_type": "S3",
            "region": "us-east-1",
            "security": {
                "encryption": {
                    "at_rest": True,
                    "in_transit": True,
                    "key_management": "AWS KMS"
                },
                "access_control": {
                    "public_access_blocked": True,
                    "bucket_policy": "restrictive",
                    "iam_roles": ["app-read", "backup-service"],
                    "least_privilege": True
                },
                "logging": {
                    "enabled": True,
                    "log_retention_days": 90
                },
                "versioning": {
                    "enabled": True,
                    "mfa_delete": False  # Baseline might require True
                },
                "monitoring": {
                    "enabled": True,
                    "alerts_configured": False  # Baseline might require True
                }
            }
        }

    def _collect_web_application_configuration(self) -> None:
        """
        Collect configuration from a web application.
        """
        # Simulated web application configuration
        self.system_config = {
            "application_name": self.target.target_id,
            "framework": "Django",
            "version": "4.1.3",
            "environment": "production",
            "security": {
                "authentication": {
                    "method": "username_password",
                    "mfa_enabled": False,  # Baseline might require True
                    "password_strength": "medium",
                    "session_timeout_minutes": 60
                },
                "headers": {
                    "csp": True,
                    "hsts": True,
                    "x_content_type": True,
                    "x_frame_options": "DENY",
                    "referrer_policy": "strict-origin-when-cross-origin"
                },
                "csrf_protection": True,
                "sql_injection_protection": True,
                "xss_protection": True,
                "https_only": True,
                "api_rate_limiting": False,  # Baseline might require True
                "input_validation": True,
                "output_encoding": True,
                "error_handling": {
                    "custom_error_pages": True,
                    "detailed_errors_public": False
                },
                "logging": {
                    "security_events": True,
                    "authentication_events": True,
                    "api_access": False  # Baseline might require True
                }
            }
        }

    def _collect_network_appliance_configuration(self) -> None:
        """
        Collect configuration from a network appliance.
        """
        # Simulated network appliance configuration
        self.system_config = {
            "device_name": self.target.target_id,
            "type": "Firewall",
            "model": "Cisco ASA",
            "firmware_version": "9.12.4",
            "last_update": "2023-02-10",
            "security": {
                "management": {
                    "admin_accounts": 3,
                    "strong_passwords": True,
                    "session_timeout_minutes": 15,
                    "access_restricted_to_management_networks": True
                },
                "authentication": {
                    "method": "local_and_tacacs",
                    "mfa_enabled": False,  # Baseline might require True
                    "admin_lockout": True,
                    "lockout_threshold": 3
                },
                "logging": {
                    "enabled": True,
                    "remote_syslog": True,
                    "log_level": "informational",
                    "full_packet_capture": False
                },
                "rules": {
                    "default_deny": True,
                    "unused_rules": 5,  # Baseline might require 0
                    "overly_permissive_rules": 2,  # Baseline might require 0
                    "documented_rules": True
                },
                "advanced": {
                    "ids_enabled": True,
                    "threat_detection": True,
                    "botnet_filtering": False,  # Baseline might require True
                    "application_inspection": True
                }
            }
        }

    def _collect_generic_configuration(self) -> None:
        """
        Generic configuration collection for unknown target types.
        """
        # Simulated generic configuration
        self.system_config = {
            "identifier": self.target.target_id,
            "type": self.target.target_type,
            "hostname": self.target.hostname,
            "ip_address": self.target.ip_address,
            "security": {
                "authentication": {
                    "method": "password",
                    "password_policy_exists": True,
                    "mfa_enabled": False
                },
                "authorization": {
                    "rbac_implemented": True,
                    "least_privilege": False
                },
                "encryption": {
                    "data_at_rest": False,
                    "data_in_transit": True
                },
                "logging": {
                    "enabled": True,
                    "centralized": False
                },
                "updates": {
                    "automatic": False,
                    "last_updated": "unknown"
                },
                "backup": {
                    "enabled": True,
                    "encrypted": False
                }
            }
        }

    def _save_configuration_snapshot(self) -> None:
        """
        Save a snapshot of the current configuration for evidence.
        """
        if not self.evidence_paths:
            return

        snapshot_path = os.path.join(self.evidence_paths[0], "configuration_snapshot.json")

        try:
            with open(snapshot_path, 'w') as f:
                json.dump(self.system_config, f, indent=2)

            self.logger.info(f"Configuration snapshot saved as evidence: {snapshot_path}")

            # Add as evidence
            evidence = Evidence(
                path=snapshot_path,
                description="System configuration snapshot",
                source=self.target.target_id,
                type="configuration",
                timestamp=datetime.now().isoformat(),
                hash_algorithm="SHA-256",
                hash_value=self._calculate_file_hash(snapshot_path)
            )

            self.add_evidence(snapshot_path)

        except Exception as e:
            self.logger.warning(f"Failed to save configuration snapshot: {str(e)}")

    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file.

        Args:
            file_path: Path to file to hash

        Returns:
            Hash value as string
        """
        import hashlib

        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "hash_calculation_failed"

    def _compare_with_baseline(self) -> None:
        """
        Compare collected configuration with the security baseline.
        """
        self.logger.info("Comparing configuration with security baseline")
        self.config_diff = {}

        # Process each category in the baseline
        for category, baseline_controls in self.baseline_data.get("security_controls", {}).items():
            self.logger.debug(f"Checking category: {category}")

            # Skip category if we don't have corresponding system configuration
            if category not in self.system_config and category not in self.system_config.get("security", {}):
                self.logger.debug(f"Skipping category {category}: not present in system configuration")
                continue

            # Get current system configuration for this category
            system_category_config = self.system_config.get(category, self.system_config.get("security", {}).get(category, {}))

            # Check each control in this category
            for control_name, baseline_value in baseline_controls.items():
                self.logger.debug(f"Checking control: {control_name}")

                # Get system's configured value for this control
                if isinstance(system_category_config, dict) and control_name in system_category_config:
                    system_value = system_category_config[control_name]
                elif "." in control_name:
                    # Handle nested controls like "ssh.permit_root_login"
                    parts = control_name.split(".")
                    current = system_category_config
                    for part in parts[:-1]:
                        if isinstance(current, dict) and part in current:
                            current = current[part]
                        else:
                            current = None
                            break
                    system_value = current.get(parts[-1], None) if current is not None else None
                else:
                    system_value = None

                # If system value couldn't be found, this is a missing control
                if system_value is None:
                    self._add_config_diff(category, {
                        "title": f"Missing control: {control_name}",
                        "description": f"Required control '{control_name}' was not found in the system configuration.",
                        "severity": BASELINE_CATEGORIES.get(category, {}).get("severity", FindingSeverity.MEDIUM),
                        "resource": f"{self.target.target_id}/{category}/{control_name}",
                        "baseline_value": baseline_value,
                        "system_value": "not configured",
                        "remediation": f"Implement the {control_name} control as required by the security baseline.",
                        "remediation_steps": [
                            f"1. Review the baseline requirements for {control_name}",
                            f"2. Configure {control_name} with appropriate value",
                            f"3. Verify the configuration change"
                        ]
                    })
                    continue

                # Compare values
                if system_value != baseline_value:
                    # Handle special comparison cases
                    if isinstance(baseline_value, list) and isinstance(system_value, list):
                        # Check if all required items are present
                        missing_items = [item for item in baseline_value if item not in system_value]
                        if not missing_items:
                            continue  # All required items are present

                    # Add to configuration differences
                    self._add_config_diff(category, {
                        "title": f"Misconfiguration: {control_name}",
                        "description": f"Control '{control_name}' is configured incorrectly. Expected '{baseline_value}', found '{system_value}'.",
                        "severity": BASELINE_CATEGORIES.get(category, {}).get("severity", FindingSeverity.MEDIUM),
                        "resource": f"{self.target.target_id}/{category}/{control_name}",
                        "baseline_value": baseline_value,
                        "system_value": system_value,
                        "remediation": f"Update {control_name} configuration to match the security baseline requirements.",
                        "remediation_steps": [
                            f"1. Access the configuration for {category}",
                            f"2. Change {control_name} from '{system_value}' to '{baseline_value}'",
                            f"3. Apply the configuration change",
                            f"4. Verify the change is effective"
                        ]
                    })

        # Add to evidence if applicable
        if self.evidence_collection and self.evidence_paths:
            diff_path = os.path.join(self.evidence_paths[0], "baseline_comparison.json")
            try:
                with open(diff_path, 'w') as f:
                    json.dump(self.config_diff, f, indent=2)
                self.add_evidence(diff_path)
            except Exception as e:
                self.logger.warning(f"Failed to save baseline comparison: {str(e)}")

    def _add_config_diff(self, category: str, issue: Dict[str, Any]) -> None:
        """
        Add a configuration difference to the tracking dictionary.

        Args:
            category: Configuration category
            issue: Issue details dictionary
        """
        if category not in self.config_diff:
            self.config_diff[category] = []

        self.config_diff[category].append(issue)

    def _detect_configuration_drift(self) -> None:
        """
        Detect configuration drift by comparing with historical configurations.
        """
        self.logger.info("Checking for configuration drift")

        # In a real implementation, this would load historical configuration data
        # from a database or configuration management system.
        # For the demo, we'll simulate historical data.

        self._load_historical_configurations()

        if not self.historical_configs:
            self.logger.info("No historical configurations available for drift detection")
            return

        # Compare current configuration with historical data
        drift_detected = False
        drift_details = []

        for category in self.system_config.keys():
            try:
                # Get corresponding category from most recent historical configuration
                if category in self.historical_configs[0]:
                    if self.system_config[category] != self.historical_configs[0][category]:
                        drift_detected = True
                        drift_details.append({
                            "category": category,
                            "current": self.system_config[category],
                            "previous": self.historical_configs[0][category]
                        })
            except (KeyError, IndexError):
                continue

        if drift_detected:
            self.logger.info(f"Configuration drift detected in {len(drift_details)} categories")

            # Create finding for configuration drift
            drift_finding = Finding(
                title="Configuration Drift Detected",
                description=f"System configuration has changed from the previously recorded state in {len(drift_details)} categories.",
                severity=FindingSeverity.MEDIUM,
                category="configuration_drift",
                affected_resource=self.target.target_id,
                remediation=Remediation(
                    description="Review configuration changes and verify they are authorized.",
                    steps=[
                        "1. Review the detected changes in each category",
                        "2. Determine if changes were authorized",
                        "3. Revert unauthorized changes",
                        "4. Document approved changes in change management system"
                    ],
                    effort="medium"
                ),
                details={
                    "drift_categories": [detail["category"] for detail in drift_details],
                    "change_count": len(drift_details)
                }
            )

            self.drift_findings.append(drift_finding)

            # Add to evidence if applicable
            if self.evidence_collection and self.evidence_paths:
                drift_path = os.path.join(self.evidence_paths[0], "configuration_drift.json")
                try:
                    with open(drift_path, 'w') as f:
                        json.dump(drift_details, f, indent=2)
                    self.add_evidence(drift_path)
                except Exception as e:
                    self.logger.warning(f"Failed to save drift evidence: {str(e)}")
        else:
            self.logger.info("No configuration drift detected")

    def _load_historical_configurations(self) -> None:
        """
        Load historical configuration snapshots for drift detection.
        """
        # In a real implementation, this would retrieve historical configurations
        # from a database or configuration management system.
        # For the demo, we'll simulate a historical configuration.

        # Create a simulated historical configuration based on the current one
        historical_config = {
            key: value for key, value in self.system_config.items()
        }

        # Modify a few values to simulate historical differences
        if "authentication" in historical_config and isinstance(historical_config["authentication"], dict):
            if "mfa" in historical_config["authentication"] and isinstance(historical_config["authentication"]["mfa"], dict):
                historical_config["authentication"]["mfa"]["enabled"] = True  # Different from current

        if "updates" in historical_config and isinstance(historical_config["updates"], dict):
            historical_config["updates"]["last_update"] = "2023-01-01"  # Different from current

        # Add metadata for the historical snapshot
        historical_config["_metadata"] = {
            "timestamp": "2023-04-01T00:00:00Z",
            "collector": "system_admin",
            "reason": "Scheduled assessment"
        }

        self.historical_configs = [historical_config]

    def _apply_compliance_checks(self) -> None:
        """
        Apply additional compliance-specific checks.
        """
        self.logger.info(f"Applying {self.compliance_framework} compliance checks")

        # Load compliance requirements
        compliance_requirements = self._get_compliance_requirements()

        for category, requirements in compliance_requirements.items():
            # Skip categories not relevant to this target type
            if category not in self.system_config and category not in self.system_config.get("security", {}):
                continue

            system_config = self.system_config.get(category, self.system_config.get("security", {}).get(category, {}))

            for req_name, req_details in requirements.items():
                check_func = req_details.get("check_function")
                if check_func and hasattr(self, check_func):
                    # Call the check function
                    getattr(self, check_func)(req_name, req_details, system_config)
                else:
                    # Basic key-value check
                    expected_value = req_details.get("value")
                    if expected_value is not None:
                        current_value = system_config.get(req_name)
                        if current_value != expected_value:
                            severity = FindingSeverity[req_details.get("severity", "MEDIUM").upper()]
                            self._add_compliance_finding(
                                category, req_name, expected_value, current_value,
                                req_details.get("description", ""),
                                severity,
                                req_details.get("references", [])
                            )

        self.logger.info(f"Completed {self.compliance_framework} compliance checks")

    def _get_compliance_requirements(self) -> Dict[str, Any]:
        """
        Get compliance requirements for the configured framework.

        Returns:
            Dict of compliance requirements by category
        """
        # In a real implementation, this would load from compliance framework files.
        # For the demo, we'll simulate requirements for common frameworks.

        if self.compliance_framework == "pci-dss":
            return {
                "authentication": {
                    "password_policy": {
                        "description": "PCI DSS Requirement 8.2.3: Password requirements must include minimum length of 7 characters and both numeric and alphabetic characters.",
                        "check_function": "_check_pci_password_policy",
                        "severity": "HIGH",
                        "references": ["PCI DSS v3.2.1, Req. 8.2.3"]
                    },
                    "account_lockout": {
                        "description": "PCI DSS Requirement 8.1.6: Limit repeated access attempts by locking out user after not more than six attempts.",
                        "check_function": "_check_pci_account_lockout",
                        "severity": "HIGH",
                        "references": ["PCI DSS v3.2.1, Req. 8.1.6"]
                    },
                    "idle_timeout": {
                        "description": "PCI DSS Requirement 8.1.8: System session idle timeout must not exceed 15 minutes.",
                        "value": True,
                        "severity": "MEDIUM",
                        "references": ["PCI DSS v3.2.1, Req. 8.1.8"]
                    }
                },
                "logging": {
                    "audit_logging": {
                        "description": "PCI DSS Requirement 10.2: Implement automated audit trails for all system components.",
                        "value": True,
                        "severity": "HIGH",
                        "references": ["PCI DSS v3.2.1, Req. 10.2"]
                    },
                    "log_review": {
                        "description": "PCI DSS Requirement 10.6: Review logs for all system components at least daily.",
                        "check_function": "_check_pci_log_review",
                        "severity": "MEDIUM",
                        "references": ["PCI DSS v3.2.1, Req. 10.6"]
                    }
                }
            }
        elif self.compliance_framework == "hipaa":
            return {
                "encryption": {
                    "data_at_rest": {
                        "description": "HIPAA Security Rule - Encryption of PHI at rest.",
                        "value": True,
                        "severity": "HIGH",
                        "references": ["45 CFR § 164.312(a)(2)(iv)"]
                    },
                    "data_in_transit": {
                        "description": "HIPAA Security Rule - Encryption of PHI during transmission.",
                        "value": True,
                        "severity": "HIGH",
                        "references": ["45 CFR § 164.312(e)(2)(ii)"]
                    }
                },
                "logging": {
                    "audit_controls": {
                        "description": "HIPAA Security Rule - Implement hardware, software, and/or procedural mechanisms to record and examine access and other activity in systems containing PHI.",
                        "value": True,
                        "severity": "HIGH",
                        "references": ["45 CFR § 164.312(b)"]
                    }
                },
                "authentication": {
                    "unique_user_identification": {
                        "description": "HIPAA Security Rule - Assign a unique name and/or number for identifying and tracking user identity.",
                        "value": True,
                        "severity": "MEDIUM",
                        "references": ["45 CFR § 164.312(a)(2)(i)"]
                    }
                }
            }
        else:
            # Generic compliance requirements
            return {}

    def _check_pci_password_policy(self, req_name: str, req_details: Dict[str, Any], system_config: Dict[str, Any]) -> None:
        """
        Check PCI DSS password policy requirements.

        Args:
            req_name: Requirement name
            req_details: Requirement details
            system_config: System configuration to check
        """
        if not isinstance(system_config, dict):
            return

        # Check minimum length
        min_length = system_config.get("min_length", 0)
        if min_length < 7:
            self._add_compliance_finding(
                "authentication",
                "password_policy.min_length",
                "7 or greater",
                str(min_length),
                "PCI DSS requires passwords to be at least 7 characters long.",
                FindingSeverity.HIGH,
                ["PCI DSS v3.2.1, Req. 8.2.3"]
            )

        # Check complexity requirements
        complexity = system_config.get("complexity_required", False)
        if not complexity:
            self._add_compliance_finding(
                "authentication",
                "password_policy.complexity_required",
                "True",
                "False",
                "PCI DSS requires passwords to contain both numeric and alphabetic characters.",
                FindingSeverity.HIGH,
                ["PCI DSS v3.2.1, Req. 8.2.3"]
            )

    def _check_pci_account_lockout(self, req_name: str, req_details: Dict[str, Any], system_config: Dict[str, Any]) -> None:
        """
        Check PCI DSS account lockout requirements.

        Args:
            req_name: Requirement name
            req_details: Requirement details
            system_config: System configuration to check
        """
        if not isinstance(system_config, dict):
            return

        # Check if account lockout is enabled
        lockout_enabled = system_config.get("account_lockout", False)
        if not lockout_enabled:
            self._add_compliance_finding(
                "authentication",
                "account_lockout",
                "True",
                "False",
                "PCI DSS requires account lockout after repeated access attempts.",
                FindingSeverity.HIGH,
                ["PCI DSS v3.2.1, Req. 8.1.6"]
            )
            return

        # Check lockout threshold
        lockout_threshold = system_config.get("lockout_threshold", 999)
        if lockout_threshold > 6:
            self._add_compliance_finding(
                "authentication",
                "lockout_threshold",
                "6 or less",
                str(lockout_threshold),
                "PCI DSS requires account lockout after not more than 6 invalid access attempts.",
                FindingSeverity.HIGH,
                ["PCI DSS v3.2.1, Req. 8.1.6"]
            )

    def _check_pci_log_review(self, req_name: str, req_details: Dict[str, Any], system_config: Dict[str, Any]) -> None:
        """
        Check PCI DSS log review requirements.

        Args:
            req_name: Requirement name
            req_details: Requirement details
            system_config: System configuration to check
        """
        if not isinstance(system_config, dict):
            return

        # Check if log review is configured
        log_review_frequency = system_config.get("review_frequency_hours", 999)
        if log_review_frequency > 24:
            self._add_compliance_finding(
                "logging",
                "review_frequency_hours",
                "24 or less",
                str(log_review_frequency),
                "PCI DSS requires daily log review for all system components.",
                FindingSeverity.MEDIUM,
                ["PCI DSS v3.2.1, Req. 10.6"]
            )

    def _add_compliance_finding(
        self,
        category: str,
        setting: str,
        expected: str,
        actual: str,
        description: str,
        severity: FindingSeverity,
        references: List[str]
    ) -> None:
        """
        Add a compliance-related finding.

        Args:
            category: Configuration category
            setting: Setting name
            expected: Expected value
            actual: Actual configured value
            description: Description of the compliance requirement
            severity: Finding severity
            references: Reference documents
        """
        if category not in self.config_diff:
            self.config_diff[category] = []

        self.config_diff[category].append({
            "title": f"Compliance Issue: {setting}",
            "description": description,
            "severity": severity,
            "resource": f"{self.target.target_id}/{category}/{setting}",
            "baseline_value": expected,
            "system_value": actual,
            "remediation": f"Update {setting} configuration to meet compliance requirements.",
            "compliance_impacts": [self.compliance_framework],
            "references": references
        })

    def _collect_finding_evidence(self, issue: Dict[str, Any]) -> Optional[Evidence]:
        """
        Collect evidence for a finding.

        Args:
            issue: Issue details dictionary

        Returns:
            Evidence object or None
        """
        if not self.evidence_collection or not self.evidence_paths:
            return None

        category = issue.get("resource", "").split("/")[1] if issue.get("resource") else "unknown"
        setting = issue.get("resource", "").split("/")[2] if issue.get("resource") and len(issue.get("resource", "").split("/")) > 2 else "unknown"

        evidence_path = os.path.join(self.evidence_paths[0], f"finding_{category}_{setting}.json")

        try:
            with open(evidence_path, 'w') as f:
                json.dump({
                    "issue": issue,
                    "system_config": self.system_config.get(category, {}),
                    "baseline": self.baseline_data.get("security_controls", {}).get(category, {})
                }, f, indent=2)

            return Evidence(
                path=evidence_path,
                description=f"Configuration finding evidence for {category}.{setting}",
                source=self.target.target_id,
                type="configuration_finding",
                timestamp=datetime.now().isoformat(),
                hash_algorithm="SHA-256",
                hash_value=self._calculate_file_hash(evidence_path)
            )
        except Exception as e:
            self.logger.warning(f"Failed to save finding evidence: {str(e)}")
            return None

    def _calculate_cvss_vector(self, category: str, severity: FindingSeverity) -> str:
        """
        Calculate CVSS vector for a finding.

        Args:
            category: Finding category
            severity: Finding severity

        Returns:
            CVSS vector string
        """
        # Base vectors by severity
        vectors = {
            FindingSeverity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # Network, Low complexity, 9.0+
            FindingSeverity.HIGH: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L",      # Network, Low complexity, 7.0-8.9
            FindingSeverity.MEDIUM: "AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L",    # Local, Low complexity, 4.0-6.9
            FindingSeverity.LOW: "AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",       # Local, High complexity, 0.1-3.9
            FindingSeverity.INFO: "AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"       # Local, High complexity, 0.0
        }

        # Category-specific adjustments
        if category == "authentication":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L"  # Network attack, high impact
            else:
                return "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"  # Local attack, high confidentiality

        elif category == "authorization":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"  # Network attack with existing privileges
            else:
                return "AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N"  # Local attack with high privileges

        elif category == "encryption":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # Network attack, high confidentiality impact
            else:
                return "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"  # Local attack, high confidentiality impact

        elif category == "logging":
            # Logging issues typically don't directly lead to compromise
            if severity == FindingSeverity.CRITICAL:
                return "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"  # Could help attacker during network attack
            else:
                return "AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"  # Could help attacker during local attack

        # Default based on severity
        return vectors.get(severity, vectors[FindingSeverity.MEDIUM])


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Analyze system configurations against security baselines.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument("--target", required=True,
                       help="Target system to analyze")

    # Optional arguments
    parser.add_argument("--baseline", default=DEFAULT_BASELINE,
                       help="Security baseline name")
    parser.add_argument("--compliance",
                       help="Compliance framework to check against (e.g., pci-dss, hipaa)")
    parser.add_argument("--critical-only", action="store_true",
                       help="Focus only on critical security controls")
    parser.add_argument("--detect-drift", action="store_true",
                       help="Enable configuration drift detection")
    parser.add_argument("--remediation", action="store_true", default=True,
                       help="Include remediation guidance in findings")
    parser.add_argument("--no-remediation", action="store_false", dest="remediation",
                       help="Exclude remediation guidance from findings")
    parser.add_argument("--target-group",
                       help="Group of targets to analyze (overrides --target)")
    parser.add_argument("--target-list",
                       help="File containing list of targets to analyze (overrides --target)")

    # Output options
    parser.add_argument("--output-format", default=DEFAULT_OUTPUT_FORMAT,
                       help="Output format (json, csv, html, markdown, etc.)")
    parser.add_argument("--output-file",
                       help="Output file path")
    parser.add_argument("--evidence-collection", action="store_true",
                       help="Enable evidence collection")

    # Misc options
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug logging")
    parser.add_argument("--version", action="version",
                       version=f"{TOOL_NAME} v{TOOL_VERSION}")

    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the configuration analyzer tool.

    Returns:
        Exit code
    """
    args = parse_arguments()

    # Configure logging
    log_level = "DEBUG" if args.debug else "INFO"
    logger = setup_assessment_logging("configuration_analyzer", log_level=log_level)

    logger.info(f"Starting {TOOL_NAME} v{TOOL_VERSION}")

    try:
        # Validate target
        if args.target_group:
            logger.error("Target group analysis not implemented in this version")
            return 1
        elif args.target_list:
            logger.error("Target list analysis not implemented in this version")
            return 1

        # Create target object
        target = AssessmentTarget(
            target_id=args.target,
            target_type="server",  # Default type, in a real implementation would be determined dynamically
            hostname=args.target,
            ip_address=None  # Would be resolved in a real implementation
        )

        # Validate output format
        if not validate_output_format(args.output_format):
            logger.error(f"Invalid output format: {args.output_format}")
            return 1

        # Create configuration analyzer
        analyzer = ConfigurationAnalyzer(
            target=target,
            baseline_name=args.baseline,
            compliance_framework=args.compliance,
            critical_only=args.critical_only,
            detect_drift=args.detect_drift,
            include_remediation=args.remediation,
            output_format=args.output_format,
            output_file=args.output_file,
            evidence_collection=args.evidence_collection
        )

        # Initialize analyzer
        if not analyzer.initialize():
            logger.error("Failed to initialize configuration analyzer")
            return 1

        # Execute assessment
        success = analyzer.execute()
        if not success:
            logger.error("Configuration analysis failed")
            return 2

        # Get and output results
        results = analyzer.get_results()
        logger.info(f"Assessment complete. Found {len(results.get('findings', []))} findings.")

        return 0

    except Exception as e:
        logger.exception(f"Unhandled exception: {str(e)}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
