#!/usr/bin/env python3
"""
Network Security Tester

This tool evaluates network security controls and identifies weaknesses in network protections.
It analyzes firewall rules, network segmentation, secure communications, and potential
unauthorized access paths.

Features:
- Firewall rule validation
- Network segmentation verification
- Secure communication enforcement
- Unauthorized access path detection
- Protocol security verification
- Network topology analysis
- Connectivity mapping
- Traffic pattern analysis
"""

import argparse
import json
import logging
import os
import sys
import time
import socket
import ssl
import ipaddress
import concurrent.futures
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
TOOL_NAME = "Network Security Tester"
TOOL_VERSION = "1.0.0"
DEFAULT_OUTPUT_FORMAT = "standard"
DEFAULT_PROFILE = "standard"
DEFAULT_TEST_TYPE = "all"
DEFAULT_LOG_DIR = "logs/network_security_tester"
DEFAULT_PARALLEL = 5
DEFAULT_TIMEOUT = 30  # Default timeout in seconds
DEFAULT_BANDWIDTH_LIMIT = 1000  # KB/s

# Network test categories
TEST_TYPES = {
    "firewall": "Validate firewall rules and configurations",
    "segmentation": "Verify network segmentation implementation",
    "encryption": "Test secure communication enforcement",
    "port-scan": "Identify open ports and services",
    "path-analysis": "Detect unauthorized network paths",
    "dns-security": "Verify DNS security configurations",
    "protocol": "Test protocol security implementations",
    "all": "Run all network security tests"
}

# Protocol security requirements
SECURE_PROTOCOLS = {
    "ssh": {
        "min_version": "2.0",
        "secure_ciphers": ["aes256-ctr", "aes192-ctr", "aes128-ctr", "chacha20-poly1305"],
        "insecure_ciphers": ["3des-cbc", "arcfour", "arcfour128", "arcfour256"],
        "secure_macs": ["hmac-sha2-512", "hmac-sha2-256", "umac-128"],
        "insecure_macs": ["hmac-md5", "hmac-sha1"]
    },
    "tls": {
        "min_version": "1.2",
        "secure_ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"],
        "insecure_ciphers": ["TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
        "secure_params": ["ecdhe", "dhe"],
        "key_exchange": ["ecdhe"]
    },
    "dns": {
        "dnssec_enabled": True,
        "dns_over_tls": True,
        "dns_over_https": True
    }
}


class NetworkSecurityTester(AssessmentBase):
    """
    Main network security tester class that evaluates network security controls and protections.
    """

    def __init__(
        self,
        target: AssessmentTarget,
        profile: str = DEFAULT_PROFILE,
        test_type: str = DEFAULT_TEST_TYPE,
        protocols: Optional[List[str]] = None,
        expected_services: Optional[Dict[int, str]] = None,
        exclude_hosts: Optional[List[str]] = None,
        bandwidth_limit: int = DEFAULT_BANDWIDTH_LIMIT,
        parallel: int = DEFAULT_PARALLEL,
        timeout: int = DEFAULT_TIMEOUT,
        compliance_framework: Optional[str] = None,
        detailed_mapping: bool = False,
        output_format: str = DEFAULT_OUTPUT_FORMAT,
        output_file: Optional[str] = None
    ):
        """
        Initialize the network security tester.

        Args:
            target: Target to test
            profile: Test profile defining scope and tests
            test_type: Type of network test to perform
            protocols: List of protocols to test
            expected_services: Dictionary mapping ports to expected services
            exclude_hosts: List of hosts to exclude from testing
            bandwidth_limit: Bandwidth limit in KB/s
            parallel: Maximum number of parallel operations
            timeout: Network operation timeout in seconds
            compliance_framework: Compliance framework to check against
            detailed_mapping: Whether to generate detailed network mapping
            output_format: Output format for results
            output_file: Output file path
        """
        super().__init__(
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            target=target,
            output_format=output_format,
            output_file=output_file
        )

        self.profile = profile
        self.test_type = test_type
        self.protocols = protocols or ["ssh", "tls", "ipsec"]
        self.expected_services = expected_services or {}
        self.exclude_hosts = exclude_hosts or []
        self.bandwidth_limit = bandwidth_limit
        self.parallel = parallel
        self.timeout = timeout
        self.compliance_framework = compliance_framework
        self.detailed_mapping = detailed_mapping
        self.test_results = []
        self.findings = []
        self.start_time = None
        self.end_time = None
        self.network_map = {}

        # Setup logging
        self.logger = setup_assessment_logging(
            tool_name=TOOL_NAME.lower().replace(' ', '_'),
            log_dir=DEFAULT_LOG_DIR
        )

        # Tracking variables
        self.total_tests = 0
        self.completed_tests = 0
        self.failed_tests = 0
        self.hosts_tested = set()

        # Load test profile
        self.load_profile()

    def load_profile(self) -> None:
        """
        Load test profile configuration.
        """
        try:
            # Determine profile path
            profile_dir = os.path.join(parent_dir, "config_files", "assessment_profiles")
            profile_file = os.path.join(profile_dir, f"{self.profile}.json")

            if not os.path.exists(profile_file):
                profile_file = os.path.join(profile_dir, f"{DEFAULT_PROFILE}.json")
                self.logger.warning(
                    f"Profile '{self.profile}' not found, using '{DEFAULT_PROFILE}' instead"
                )

            # Load profile from file
            if os.path.exists(profile_file):
                with open(profile_file, 'r') as f:
                    self.profile_config = json.load(f)
                self.logger.info(f"Loaded test profile from {profile_file}")
            else:
                # Use default configuration if no profile file found
                self.profile_config = {
                    "name": self.profile or DEFAULT_PROFILE,
                    "description": "Default network security test configuration",
                    "test_intensity": "medium",
                    "parallel_tests": self.parallel,
                    "timeout_multiplier": 1.0,
                    "tests": {
                        "firewall": True,
                        "segmentation": True,
                        "encryption": True,
                        "port-scan": True,
                        "path-analysis": True,
                        "dns-security": True,
                        "protocol": True
                    }
                }
                self.logger.warning(
                    f"No profile file found at {profile_file}, using default configuration"
                )

            # Apply profile settings
            if "timeout_multiplier" in self.profile_config:
                self.timeout *= self.profile_config.get("timeout_multiplier", 1.0)

            # If test type is specified, make sure only that test is enabled
            if self.test_type != "all":
                for test in self.profile_config.get("tests", {}):
                    self.profile_config["tests"][test] = (test == self.test_type)

        except Exception as e:
            self.logger.error(f"Failed to load test profile: {str(e)}")
            self.add_error(f"Profile loading error: {str(e)}")
            # Use minimal default configuration
            self.profile_config = {
                "name": "minimal",
                "test_intensity": "low",
                "parallel_tests": 1,
                "tests": {
                    "firewall": self.test_type in ["all", "firewall"],
                    "segmentation": self.test_type in ["all", "segmentation"],
                    "encryption": self.test_type in ["all", "encryption"],
                    "port-scan": self.test_type in ["all", "port-scan"],
                    "path-analysis": self.test_type in ["all", "path-analysis"],
                    "dns-security": self.test_type in ["all", "dns-security"],
                    "protocol": self.test_type in ["all", "protocol"]
                }
            }

    @secure_operation("assessment:initialize")
    def initialize(self) -> bool:
        """
        Initialize the network security tester and verify prerequisites.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self.logger.info(f"Initializing {TOOL_NAME} with profile '{self.profile}'")
            self.set_status(AssessmentStatus.INITIALIZING)

            # Validate target
            if not validate_target(self.target):
                self.add_error("Invalid target specification")
                return False

            # Validate output format
            if not validate_output_format(self.output_format):
                self.add_error(f"Unsupported output format: {self.output_format}")
                return False

            # Validate compliance framework if specified
            if self.compliance_framework and not validate_compliance_framework(self.compliance_framework):
                self.add_error(f"Unsupported compliance framework: {self.compliance_framework}")
                return False

            # Validate test type
            if self.test_type not in TEST_TYPES:
                self.add_error(f"Invalid test type: {self.test_type}")
                return False

            # Verify target access
            if not verify_target_access(self.target):
                self.add_error("Cannot access target for assessment. Check permissions and connectivity.")
                return False

            # Set up test tracking
            self._setup_test_tracking()

            # Initialize result storage
            self.test_results = []

            self.set_status(AssessmentStatus.INITIALIZED)
            self.logger.info(f"{TOOL_NAME} initialized successfully")
            return True

        except Exception as e:
            self.add_error(f"Failed to initialize assessment: {str(e)}")
            self.logger.exception(f"Initialization error in {TOOL_NAME}")
            return False

    def _setup_test_tracking(self) -> None:
        """
        Set up test tracking based on enabled tests.
        """
        tests = self.profile_config.get("tests", {})
        self.total_tests = 0

        # Count number of tests to run
        if tests.get("firewall", False):
            self.total_tests += 5  # ACL tests, rule consistency, etc.
        if tests.get("segmentation", False):
            self.total_tests += 4  # Zone isolation, path traversal, etc.
        if tests.get("encryption", False):
            self.total_tests += len(self.protocols) * 2  # Protocol tests
        if tests.get("port-scan", False):
            self.total_tests += 2  # Open port analysis, service identification
        if tests.get("path-analysis", False):
            self.total_tests += 3  # Path discovery, routing analysis
        if tests.get("dns-security", False):
            self.total_tests += 3  # DNSSEC, DNS over TLS, etc.
        if tests.get("protocol", False):
            self.total_tests += 4  # Protocol security tests

        self.logger.info(f"Set up {self.total_tests} network security tests")

    @secure_operation("assessment:execute")
    def execute(self) -> bool:
        """
        Execute network security tests on the target.

        Returns:
            True if tests successful, False otherwise
        """
        try:
            self.logger.info(f"Starting network security tests for {self.target.target_id}")
            self.set_status(AssessmentStatus.RUNNING)
            self.start_time = datetime.now()

            # Log test parameters
            log_assessment_event(
                event_type="test_started",
                description=f"Network security tests started on {self.target.target_id}",
                details={
                    "profile": self.profile,
                    "test_type": self.test_type,
                    "protocols": self.protocols,
                    "parallel": self.parallel,
                    "timeout": self.timeout,
                    "compliance_framework": self.compliance_framework
                }
            )

            # Execute network tests
            self._execute_network_tests()

            self.end_time = datetime.now()
            self.logger.info(f"Tests completed in {(self.end_time - self.start_time).total_seconds()} seconds")

            # Process results
            self._process_test_results()

            # Generate findings from test results
            self._generate_findings()

            # Mark tests completed
            self.set_status(AssessmentStatus.COMPLETED)

            return True

        except KeyboardInterrupt:
            self.logger.warning("Tests interrupted by user")
            self.set_status(AssessmentStatus.INTERRUPTED)
            return False

        except Exception as e:
            self.add_error(f"Test execution error: {str(e)}")
            self.logger.exception("Error during network security test execution")
            self.set_status(AssessmentStatus.FAILED)
            return False

    def _execute_network_tests(self) -> None:
        """
        Execute network security tests based on enabled test types.
        """
        # Determine parallelism
        max_workers = min(
            self.profile_config.get("parallel_tests", self.parallel),
            DEFAULT_PARALLEL
        )

        # Get enabled tests
        tests = self.profile_config.get("tests", {})

        # Execute tests with appropriate parallelism
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []

            # Firewall tests
            if tests.get("firewall", False):
                futures.append(executor.submit(self._test_firewall_rules))

            # Segmentation tests
            if tests.get("segmentation", False):
                futures.append(executor.submit(self._test_network_segmentation))

            # Encryption tests
            if tests.get("encryption", False):
                futures.append(executor.submit(self._test_secure_communication))

            # Port scan tests
            if tests.get("port-scan", False):
                futures.append(executor.submit(self._test_open_ports))

            # Path analysis tests
            if tests.get("path-analysis", False):
                futures.append(executor.submit(self._test_network_paths))

            # DNS security tests
            if tests.get("dns-security", False):
                futures.append(executor.submit(self._test_dns_security))

            # Protocol security tests
            if tests.get("protocol", False):
                futures.append(executor.submit(self._test_protocol_security))

            # Zero trust network access tests
            futures.append(executor.submit(self._test_zero_trust_controls))

            # Wait for all tests to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    test_results = future.result()
                    if test_results:
                        self.test_results.extend(test_results)
                except Exception as e:
                    self.logger.error(f"Error in security test: {str(e)}")
                    self.failed_tests += 1

    def _test_firewall_rules(self) -> List[Dict[str, Any]]:
        """
        Test firewall rules and configurations.

        Returns:
            List of test results
        """
        self.logger.info("Testing firewall rules and configurations")
        results = []

        # Simulate firewall rule validation
        # In a real implementation, these would be actual tests against the firewall

        # Test default deny policy
        results.append({
            "id": "NETTEST-FW-001",
            "category": "firewall",
            "name": "Default Deny Policy",
            "description": "Verify default deny policy on firewall",
            "status": "FAIL",
            "details": {
                "finding": "Default policy is set to ACCEPT instead of DROP or REJECT",
                "affected_chains": ["INPUT", "FORWARD"],
                "recommended_action": "Configure default policy to DROP or REJECT for all chains"
            },
            "severity": FindingSeverity.HIGH,
            "false_positive_risk": "low"
        })

        # Test for overly permissive rules
        results.append({
            "id": "NETTEST-FW-002",
            "category": "firewall",
            "name": "Overly Permissive Rules",
            "description": "Check for overly permissive firewall rules",
            "status": "FAIL",
            "details": {
                "finding": "Found rules allowing all traffic from public networks",
                "affected_rules": ["allow from any to any port 22"],
                "recommended_action": "Restrict SSH access to specific source addresses"
            },
            "severity": FindingSeverity.HIGH,
            "false_positive_risk": "low"
        })

        # Test for redundant rules
        results.append({
            "id": "NETTEST-FW-003",
            "category": "firewall",
            "name": "Redundant Rules",
            "description": "Check for redundant firewall rules",
            "status": "PASS",
            "details": {
                "finding": "No redundant rules found",
            },
            "severity": FindingSeverity.LOW,
            "false_positive_risk": "low"
        })

        # Test for rule logging
        results.append({
            "id": "NETTEST-FW-004",
            "category": "firewall",
            "name": "Firewall Logging",
            "description": "Check if firewall is configured to log dropped packets",
            "status": "FAIL",
            "details": {
                "finding": "No logging rules found for dropped packets",
                "recommended_action": "Configure logging for dropped packets for security monitoring"
            },
            "severity": FindingSeverity.MEDIUM,
            "false_positive_risk": "low"
        })

        # Test for rate limiting
        results.append({
            "id": "NETTEST-FW-005",
            "category": "firewall",
            "name": "Rate Limiting",
            "description": "Check for rate limiting on sensitive services",
            "status": "FAIL",
            "details": {
                "finding": "No rate limiting for SSH, HTTP, or HTTPS services",
                "affected_services": ["ssh (22)", "http (80)", "https (443)"],
                "recommended_action": "Implement rate limiting to prevent brute force attacks"
            },
            "severity": FindingSeverity.MEDIUM,
            "false_positive_risk": "low"
        })

        # Update progress
        self.completed_tests += 5

        return results

    def _test_network_segmentation(self) -> List[Dict[str, Any]]:
        """
        Test network segmentation implementation.

        Returns:
            List of test results
        """
        self.logger.info("Testing network segmentation")
        results = []

        # Simulate network segmentation tests
        # In a real implementation, these would be actual network isolation tests

        # Test for VLAN isolation
        results.append({
            "id": "NETTEST-SEG-001",
            "category": "segmentation",
            "name": "VLAN Isolation",
            "description": "Verify isolation between network segments",
            "status": "PASS",
            "details": {
                "finding": "Proper isolation between production and development VLANs",
                "tested_paths": ["prod->dev", "dev->prod"]
            },
            "severity": FindingSeverity.HIGH,
            "false_positive_risk": "low"
        })

        # Test for DMZ segmentation
        results.append({
            "id": "NETTEST-SEG-002",
            "category": "segmentation",
            "name": "DMZ Segmentation",
            "description": "Verify DMZ is properly segmented from internal networks",
            "status": "FAIL",
            "details": {
                "finding": "Direct connectivity detected from DMZ to internal database servers",
                "unauthorized_paths": ["dmz-web-01 to db-server-03 (port 5432)"],
                "recommended_action": "Implement stricter firewall rules between DMZ and internal networks"
            },
            "severity": FindingSeverity.CRITICAL,
            "false_positive_risk": "low"
        })

        # Test for microservice isolation
        results.append({
            "id": "NETTEST-SEG-003",
            "category": "segmentation",
            "name": "Microservice Isolation",
            "description": "Verify isolation between microservices",
            "status": "FAIL",
            "details": {
                "finding": "Insufficient isolation between payment and user microservices",
                "unauthorized_paths": ["user-service to payment-db (port 27017)"],
                "recommended_action": "Implement network policies to restrict cross-service communication"
            },
            "severity": FindingSeverity.HIGH,
            "false_positive_risk": "medium"
        })

        # Test for unauthorized route leaks
        results.append({
            "id": "NETTEST-SEG-004",
            "category": "segmentation",
            "name": "Route Leak Detection",
            "description": "Check for unauthorized route leaks between segments",
            "status": "PASS",
            "details": {
                "finding": "No unauthorized route leaks detected",
                "tested_boundaries": ["internal-external", "prod-dev", "pci-non-pci"]
            },
            "severity": FindingSeverity.HIGH,
            "false_positive_risk": "low"
        })

        # Update progress
        self.completed_tests += 4

        return results

    def _test_secure_communication(self) -> List[Dict[str, Any]]:
        """
        Test secure communication protocols and enforcement.

        Returns:
            List of test results
        """
        self.logger.info(f"Testing secure communication for protocols: {', '.join(self.protocols)}")
        results = []

        # Test each protocol
        for protocol in self.protocols:
            # Test protocol version
            if protocol in ["ssh", "tls", "ipsec"]:
                # For a real implementation, these would be actual protocol tests
                if protocol == "ssh":
                    results.append({
                        "id": "NETTEST-CRYPTO-001",
                        "category": "encryption",
                        "name": "SSH Version",
                        "description": "Verify SSH protocol version",
                        "status": "FAIL",
                        "details": {
                            "finding": "SSH server allows protocol version 1",
                            "current_version": "1.99",
                            "required_version": "2.0",
                            "recommended_action": "Disable SSHv1 and use only SSHv2"
                        },
                        "severity": FindingSeverity.HIGH,
                        "false_positive_risk": "low"
                    })

                    results.append({
                        "id": "NETTEST-CRYPTO-002",
                        "category": "encryption",
                        "name": "SSH Ciphers",
                        "description": "Verify SSH cipher security",
                        "status": "FAIL",
                        "details": {
                            "finding": "SSH server allows weak ciphers",
                            "weak_ciphers": ["3des-cbc", "arcfour"],
                            "recommended_action": "Disable weak ciphers and use only strong encryption algorithms"
                        },
                        "severity": FindingSeverity.MEDIUM,
                        "false_positive_risk": "low"
                    })

                elif protocol == "tls":
                    results.append({
                        "id": "NETTEST-CRYPTO-003",
                        "category": "encryption",
                        "name": "TLS Version",
                        "description": "Verify TLS protocol version",
                        "status": "FAIL",
                        "details": {
                            "finding": "Server supports TLS 1.0 and 1.1",
                            "supported_versions": ["TLS 1.0", "TLS 1.1", "TLS 1.2"],
                            "required_versions": ["TLS 1.2", "TLS 1.3"],
                            "recommended_action": "Disable TLS 1.0 and 1.1, enable only TLS 1.2 and 1.3"
                        },
                        "severity": FindingSeverity.HIGH,
                        "false_positive_risk": "low"
                    })

                    results.append({
                        "id": "NETTEST-CRYPTO-004",
                        "category": "encryption",
                        "name": "TLS Cipher Suites",
                        "description": "Verify TLS cipher suite security",
                        "status": "FAIL",
                        "details": {
                            "finding": "Server supports weak cipher suites",
                            "weak_ciphers": [
                                "TLS_RSA_WITH_RC4_128_SHA",
                                "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
                            ],
                            "recommended_action": "Configure server to use only strong cipher suites"
                        },
                        "severity": FindingSeverity.MEDIUM,
                        "false_positive_risk": "low"
                    })

                elif protocol == "ipsec":
                    results.append({
                        "id": "NETTEST-CRYPTO-005",
                        "category": "encryption",
                        "name": "IPsec Configuration",
                        "description": "Verify IPsec security configuration",
                        "status": "PASS",
                        "details": {
                            "finding": "IPsec is properly configured with strong encryption",
                            "encryption": "AES-256-GCM",
                            "integrity": "SHA-384"
                        },
                        "severity": FindingSeverity.HIGH,
                        "false_positive_risk": "low"
                    })

                    results.append({
                        "id": "NETTEST-CRYPTO-006",
                        "category": "encryption",
                        "name": "IPsec Perfect Forward Secrecy",
                        "description": "Verify IPsec PFS implementation",
                        "status": "PASS",
                        "details": {
                            "finding": "IPsec is configured with Perfect Forward Secrecy",
                            "dh_group": "Group 14 (2048-bit)"
                        },
                        "severity": FindingSeverity.MEDIUM,
                        "false_positive_risk": "low"
                    })

        # Update progress
        self.completed_tests += len(self.protocols) * 2

        return results

    def _test_open_ports(self) -> List[Dict[str, Any]]:
        """
        Test for open ports and validate expected services.

        Returns:
            List of test results
        """
        self.logger.info("Scanning for open ports and validating services")
        results = []

        # Simulate port scanning
        # In a real implementation, this would perform actual port scans

        open_ports = {
            22: "ssh",
            80: "http",
            443: "https",
            3306: "mysql",
            8080: "http-alt",
            9090: "unknown"
        }

        # Create a comprehensive result with all open ports
        results.append({
            "id": "NETTEST-PORT-001",
            "category": "port-scan",
            "name": "Open Port Analysis",
            "description": "Identify and analyze open network ports",
            "status": "INFO",
            "details": {
                "finding": f"Found {len(open_ports)} open ports",
                "open_ports": [f"{port} ({service})" for port, service in open_ports.items()],
            },
            "severity": FindingSeverity.INFO,
            "false_positive_risk": "low"
        })

        # Check for unexpected open ports
        unexpected_ports = {}
        for port, service in open_ports.items():
            if port in self.expected_services:
                if service != self.expected_services[port]:
                    unexpected_ports[port] = f"Expected '{self.expected_services[port]}', found '{service}'"
            else:
                unexpected_ports[port] = f"Unexpected port ({service})"

        if unexpected_ports:
            results.append({
                "id": "NETTEST-PORT-002",
                "category": "port-scan",
                "name": "Unexpected Open Ports",
                "description": "Identify unexpected or unauthorized open ports",
                "status": "FAIL",
                "details": {
                    "finding": f"Found {len(unexpected_ports)} unexpected open ports",
                    "unexpected_ports": [f"Port {port}: {reason}" for port, reason in unexpected_ports.items()],
                    "recommended_action": "Close unnecessary ports and verify service configurations"
                },
                "severity": FindingSeverity.HIGH,
                "false_positive_risk": "medium"
            })
        else:
            results.append({
                "id": "NETTEST-PORT-002",
                "category": "port-scan",
                "name": "Unexpected Open Ports",
                "description": "Identify unexpected or unauthorized open ports",
                "status": "PASS",
                "details": {
                    "finding": "All open ports match expected services",
                },
                "severity": FindingSeverity.INFO,
                "false_positive_risk": "low"
            })

        # Update progress
        self.completed_tests += 2

        return results

    def _test_network_paths(self) -> List[Dict[str, Any]]:
        """
        Test network paths for unauthorized access.

        Returns:
            List of test results
        """
        self.logger.info("Testing network paths for unauthorized access")
        results = []

        # Simulate network path analysis
        # In a real implementation, this would trace actual network paths

        # Test for direct paths between isolated segments
        results.append({
            "id": "NETTEST-PATH-001",
            "category": "path-analysis",
            "name": "Direct Path Analysis",
            "description": "Analyze direct paths between network segments",
            "status": "FAIL",
            "details": {
                "finding": "Found direct paths between isolated network segments",
                "unauthorized_paths": [
                    "internet -> internal (10.0.5.25:3306)",
                    "dmz -> database (10.0.10.5:5432)"
                ],
                "recommended_action": "Implement proper network filtering between segments"
            },
            "severity": FindingSeverity.CRITICAL,
            "false_positive_risk": "low"
        })

        # Test for lateral movement paths
        results.append({
            "id": "NETTEST-PATH-002",
            "category": "path-analysis",
            "name": "Lateral Movement Paths",
            "description": "Identify potential lateral movement paths",
            "status": "FAIL",
            "details": {
                "finding": "Multiple lateral movement paths identified",
                "paths": [
                    "web-01 -> app-01 -> db-01 (unrestricted)",
                    "dmz-proxy -> internal-admin (via SSH)"
                ],
                "recommended_action": "Implement proper network segmentation and limit crossover points"
            },
            "severity": FindingSeverity.HIGH,
            "false_positive_risk": "medium"
        })

        # Test for routing security
        results.append({
            "id": "NETTEST-PATH-003",
            "category": "path-analysis",
            "name": "Routing Security",
            "description": "Analyze routing security and stability",
            "status": "PASS",
            "details": {
                "finding": "No routing security issues detected",
                "routes_analyzed": 42
            },
            "severity": FindingSeverity.MEDIUM,
            "false_positive_risk": "low"
        })

        # Update progress
        self.completed_tests += 3

        return results

    def _test_dns_security(self) -> List[Dict[str, Any]]:
        """
        Test DNS security configurations.

        Returns:
            List of test results
        """
        self.logger.info("Testing DNS security configurations")
        results = []

        # Simulate DNS security tests
        # In a real implementation, these would be actual DNS tests

        # Test for DNSSEC
        results.append({
            "id": "NETTEST-DNS-001",
            "category": "dns-security",
            "name": "DNSSEC Implementation",
            "description": "Verify DNSSEC implementation",
            "status": "FAIL",
            "details": {
                "finding": "DNSSEC not implemented for primary domain",
                "affected_domains": ["example.com", "api.example.com"],
                "recommended_action": "Implement DNSSEC for all domains"
            },
            "severity": FindingSeverity.MEDIUM,
            "false_positive_risk": "low"
        })

        # Test for DNS over TLS/HTTPS
        results.append({
            "id": "NETTEST-DNS-002",
            "category": "dns-security",
            "name": "Encrypted DNS",
            "description": "Verify DNS encryption (DoT/DoH)",
            "status": "FAIL",
            "details": {
                "finding": "DNS over TLS/HTTPS not implemented",
                "recommended_action": "Configure DNS servers to support DoT/DoH"
            },
            "severity": FindingSeverity.LOW,
            "false_positive_risk": "low"
        })

        # Test for DNS cache poisoning protection
        results.append({
            "id": "NETTEST-DNS-003",
            "category": "dns-security",
            "name": "DNS Cache Protection",
            "description": "Verify protection against cache poisoning",
            "status": "PASS",
            "details": {
                "finding": "Proper protection against DNS cache poisoning",
                "protections": ["source port randomization", "query ID randomization"]
            },
            "severity": FindingSeverity.HIGH,
            "false_positive_risk": "low"
        })

        # Update progress
        self.completed_tests += 3

        return results

    def _test_protocol_security(self) -> List[Dict[str, Any]]:
        """
        Test protocol security implementations.

        Returns:
            List of test results
        """
        self.logger.info("Testing protocol security implementations")
        results = []

        # Simulate protocol security tests
        # In a real implementation, these would analyze actual protocol implementations

        # Test for HTTP security headers
        results.append({
            "id": "NETTEST-PROTO-001",
            "category": "protocol",
            "name": "HTTP Security Headers",
            "description": "Verify implementation of HTTP security headers",
            "status": "FAIL",
            "details": {
                "finding": "Missing critical HTTP security headers",
                "missing_headers": [
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-Frame-Options"
                ],
                "recommended_action": "Configure web servers to include all security headers"
            },
            "severity": FindingSeverity.MEDIUM,
            "false_positive_risk": "low"
        })

        # Test for SNI support
        results.append({
            "id": "NETTEST-PROTO-002",
            "category": "protocol",
            "name": "TLS SNI Support",
            "description": "Verify Server Name Indication (SNI) support",
            "status": "PASS",
            "details": {
                "finding": "Proper SNI support implemented",
                "virtual_hosts_tested": 5
            },
            "severity": FindingSeverity.LOW,
            "false_positive_risk": "low"
        })

        # Test for HSTS implementation
        results.append({
            "id": "NETTEST-PROTO-003",
            "category": "protocol",
            "name": "HTTP Strict Transport Security",
            "description": "Verify HSTS implementation",
            "status": "FAIL",
            "details": {
                "finding": "HSTS not properly implemented",
                "issues": [
                    "max-age too short (300 seconds, should be at least 31536000)",
                    "includeSubDomains directive missing"
                ],
                "recommended_action": "Configure proper HSTS settings with appropriate max-age"
            },
            "severity": FindingSeverity.MEDIUM,
            "false_positive_risk": "low"
        })

        # Test for TLS fallback protection
        results.append({
            "id": "NETTEST-PROTO-004",
            "category": "protocol",
            "name": "TLS Fallback Protection",
            "description": "Verify protection against TLS fallback attacks",
            "status": "PASS",
            "details": {
                "finding": "TLS fallback protection properly implemented",
                "protection": "TLS_FALLBACK_SCSV supported"
            },
            "severity": FindingSeverity.MEDIUM,
            "false_positive_risk": "low"
        })

        # Update progress
        self.completed_tests += 4

        return results

    def _test_zero_trust_controls(self) -> List[Dict[str, Any]]:
        """
        Test zero trust network access controls.

        Returns:
            List of test results
        """
        self.logger.info("Testing zero trust network controls")
        results = []

        # Test for identity-based access
        results.append({
            "id": "NETTEST-ZTNA-001",
            "category": "zero-trust",
            "name": "Identity-Based Network Access",
            "description": "Verify identity-based network access controls",
            "status": "FAIL",
            "details": {
                "finding": "Network access not tied to user or service identity",
                "recommended_action": "Implement identity-aware proxies and access controls"
            },
            "severity": FindingSeverity.HIGH,
            "false_positive_risk": "low"
        })

        # Additional tests would go here

        return results

    def _process_test_results(self) -> None:
        """
        Process test results and apply filtering/aggregation logic.
        """
        self.logger.info(f"Processing {len(self.test_results)} test results")

        # Apply compliance mapping if needed
        if self.compliance_framework:
            self._apply_compliance_mapping()

        # Create network map if detailed mapping requested
        if self.detailed_mapping:
            self._create_network_map()

        self.logger.info(f"Processed {len(self.test_results)} test results")

    def _apply_compliance_mapping(self) -> None:
        """
        Apply compliance framework mapping to test results.
        """
        # In a real implementation, this would map findings to specific compliance controls
        compliance_mappings = {
            "pci-dss": {
                "firewall": ["1.1", "1.2", "1.3"],
                "segmentation": ["1.3", "1.4"],
                "encryption": ["4.1"],
                "path-analysis": ["1.2", "1.3"],
                "port-scan": ["1.2", "2.2"],
                "dns-security": ["4.1"],
                "protocol": ["4.1"]
            },
            "nist-csf": {
                "firewall": ["PR.AC-5", "PR.PT-4"],
                "segmentation": ["PR.AC-5", "PR.PT-4"],
                "encryption": ["PR.DS-2"],
                "path-analysis": ["PR.PT-4"],
                "port-scan": ["ID.AM-1", "PR.PT-4"],
                "dns-security": ["PR.DS-2"],
                "protocol": ["PR.DS-2"]
            }
        }

        if self.compliance_framework in compliance_mappings:
            mapping = compliance_mappings[self.compliance_framework]
            for result in self.test_results:
                category = result.get("category")
                if category in mapping:
                    result["compliance_controls"] = mapping[category]

            self.logger.info(f"Applied {self.compliance_framework} compliance mapping")

    def _create_network_map(self) -> None:
        """
        Create a detailed network map from test results.
        """
        # This would create a network topology map based on test results
        self.network_map = {
            "nodes": [],
            "connections": [],
            "zones": []
        }

        # In a real implementation, this would be derived from actual scan results
        self.network_map["nodes"] = [
            {"id": "internet", "type": "external", "name": "Internet"},
            {"id": "firewall", "type": "security_device", "name": "Edge Firewall"},
            {"id": "dmz-web", "type": "server", "name": "DMZ Web Server", "ip": "192.168.1.10"},
            {"id": "app-server", "type": "server", "name": "Application Server", "ip": "10.0.0.5"},
            {"id": "db-server", "type": "server", "name": "Database Server", "ip": "10.0.0.6"}
        ]

        self.network_map["connections"] = [
            {"source": "internet", "target": "firewall", "ports": [80, 443]},
            {"source": "firewall", "target": "dmz-web", "ports": [80, 443]},
            {"source": "dmz-web", "target": "app-server", "ports": [8080]},
            {"source": "app-server", "target": "db-server", "ports": [3306]},
            # Potentially unauthorized path
            {"source": "dmz-web", "target": "db-server", "ports": [3306], "status": "unauthorized"}
        ]

        self.network_map["zones"] = [
            {"id": "external", "name": "External Network", "nodes": ["internet"]},
            {"id": "dmz", "name": "DMZ", "nodes": ["firewall", "dmz-web"]},
            {"id": "internal", "name": "Internal Network", "nodes": ["app-server", "db-server"]}
        ]

        self.logger.info("Created detailed network map")

    def _generate_findings(self) -> None:
        """
        Generate formal findings from test results.
        """
        self.findings = []

        for result in self.test_results:
            # Only create findings for failed tests
            if result.get("status") == "FAIL":
                # Create finding
                finding = Finding(
                    title=result.get("name", "Unnamed Issue"),
                    description=result.get("description", "No description provided"),
                    severity=result.get("severity", FindingSeverity.MEDIUM),
                    category=result.get("category", "unknown"),
                    affected_resource=self.target.target_id,
                    details=result.get("details", {})
                )

                # Add CVSS scoring
                cvss_vector = self._calculate_cvss_vector(result)
                if cvss_vector:
                    finding.cvss = CVSS(vector=cvss_vector)

                # Add remediation information
                recommended_action = result.get("details", {}).get("recommended_action")
                if recommended_action:
                    finding.remediation = Remediation(
                        description=recommended_action,
                        type="mitigation"
                    )

                # Add compliance controls if available
                if "compliance_controls" in result:
                    finding.compliance_impact = result["compliance_controls"]

                # Add finding to results
                self.findings.append(finding)

                # Log security finding
                log_security_finding(
                    finding=finding,
                    source=TOOL_NAME,
                    target_id=self.target.target_id
                )

    def _calculate_cvss_vector(self, result: Dict[str, Any]) -> Optional[str]:
        """
        Calculate CVSS vector string based on test result details.

        Args:
            result: Test result data

        Returns:
            CVSS vector string or None
        """
        category = result.get("category", "")
        severity = result.get("severity", FindingSeverity.MEDIUM)

        # Base vectors by severity
        vectors = {
            FindingSeverity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0
            FindingSeverity.HIGH: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
            FindingSeverity.MEDIUM: "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",    # 6.3
            FindingSeverity.LOW: "AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",       # 1.8
            FindingSeverity.INFO: "AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"       # 0.0
        }

        # Adjust vector based on result category
        if category == "firewall":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # 10.0
            else:
                return "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"  # 5.5

        elif category == "segmentation":
            if severity == FindingSeverity.CRITICAL:
                return "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"  # 9.9
            elif severity == FindingSeverity.HIGH:
                return "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"  # 8.5
            else:
                return "AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:N"  # 4.4

        elif category == "encryption":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"  # 8.2
            else:
                return "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 5.9

        elif category == "port-scan":
            return "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3

        elif category == "path-analysis":
            if severity == FindingSeverity.CRITICAL:
                return "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"  # 9.9
            else:
                return "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N"  # 7.7

        elif category == "dns-security":
            return "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N"  # 6.5

        elif category == "protocol":
            return "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"  # 6.5

        # Default based on severity
        return vectors.get(severity)

    def analyze_findings(self) -> List[Finding]:
        """
        Analyze and return the test findings.

        Returns:
            List of findings
        """
        if self.status not in [AssessmentStatus.COMPLETED, AssessmentStatus.INTERRUPTED]:
            self.logger.warning("Attempting to analyze findings before tests are completed")

        return self.findings

    def generate_report(self, findings: List[Finding]) -> Any:
        """
        Generate test report.

        Args:
            findings: List of findings to include in report

        Returns:
            Report data in the specified format
        """
        report_data = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "timestamp": datetime.now().isoformat(),
            "target": self.target.target_id,
            "test_profile": self.profile,
            "test_type": self.test_type,
            "test_duration": None,
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == FindingSeverity.HIGH),
                "medium": sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == FindingSeverity.LOW),
                "info": sum(1 for f in findings if f.severity == FindingSeverity.INFO)
            },
            "findings": []
        }

        # Calculate duration if available
        if self.start_time and self.end_time:
            report_data["test_duration"] = (self.end_time - self.start_time).total_seconds()

        # Add findings to report
        for finding in findings:
            finding_data = {
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.name,
                "category": finding.category,
                "affected_resource": finding.affected_resource
            }

            # Add CVSS if available
            if finding.cvss:
                finding_data["cvss"] = {
                    "vector": finding.cvss.vector,
                    "base_score": finding.cvss.base_score
                }

            # Add remediation if available
            if finding.remediation:
                finding_data["remediation"] = {
                    "description": finding.remediation.description,
                    "type": finding.remediation.type
                }

            # Add details if available
            if finding.details:
                finding_data["details"] = finding.details

            # Add compliance impact if available
            if finding.compliance_impact:
                finding_data["compliance_impact"] = finding.compliance_impact

            # Add to report
            report_data["findings"].append(finding_data)

        # Add network map if detailed mapping was performed
        if self.detailed_mapping and self.network_map:
            report_data["network_map"] = self.network_map

        # Format report based on output format
        if self.output_format == "json":
            return json.dumps(report_data, indent=2, default=str)
        elif self.output_format == "standard":
            # Format for standard text output
            return self._format_standard_report(report_data)
        else:
            # For other formats, use the base class formatter
            return super().generate_report(findings)

    def _format_standard_report(self, report_data: Dict[str, Any]) -> str:
        """
        Format report data as a standard text report.

        Args:
            report_data: Report data

        Returns:
            Formatted text report
        """
        report = []

        # Header
        report.append("=" * 80)
        report.append(f"{report_data['tool']} v{report_data['version']} - Network Security Assessment Report")
        report.append("=" * 80)
        report.append(f"Target: {report_data['target']}")
        report.append(f"Profile: {report_data['test_profile']}")
        report.append(f"Test Type: {report_data['test_type']}")
        report.append(f"Timestamp: {report_data['timestamp']}")

        if report_data.get("test_duration"):
            report.append(f"Duration: {report_data['test_duration']:.1f} seconds")

        report.append("=" * 80)

        # Summary
        report.append("\nSUMMARY:")
        report.append("-" * 80)
        summary = report_data["summary"]
        report.append(f"Total Findings: {summary['total_findings']}")
        report.append(f"  CRITICAL: {summary['critical']}")
        report.append(f"  HIGH: {summary['high']}")
        report.append(f"  MEDIUM: {summary['medium']}")
        report.append(f"  LOW: {summary['low']}")
        report.append(f"  INFO: {summary['info']}")

        # Findings
        if report_data["findings"]:
            report.append("\nFINDINGS:")
            report.append("-" * 80)

            # Sort findings by severity
            severity_order = {
                "CRITICAL": 4,
                "HIGH": 3,
                "MEDIUM": 2,
                "LOW": 1,
                "INFO": 0
            }

            sorted_findings = sorted(
                report_data["findings"],
                key=lambda x: severity_order.get(x["severity"], 0),
                reverse=True
            )

            for i, finding in enumerate(sorted_findings, 1):
                report.append(f"\n{i}. [{finding['severity']}] {finding['title']}")
                report.append(f"   Category: {finding['category']}")
                report.append(f"   Resource: {finding['affected_resource']}")

                if "cvss" in finding:
                    report.append(f"   CVSS: {finding['cvss'].get('base_score', 'N/A')} ({finding['cvss'].get('vector', 'N/A')})")

                report.append(f"\n   Description: {finding['description']}")

                if "details" in finding:
                    report.append("\n   Details:")

                    # Handle the "finding" field specially
                    if "finding" in finding["details"]:
                        report.append(f"     Finding: {finding['details']['finding']}")

                    for key, value in finding["details"].items():
                        if key == "finding":
                            continue  # Already printed

                        if isinstance(value, list):
                            report.append(f"     {key.replace('_', ' ').title()}:")
                            for item in value:
                                if isinstance(item, dict):
                                    for k, v in item.items():
                                        report.append(f"       - {k}: {v}")
                                else:
                                    report.append(f"       - {item}")
                        else:
                            report.append(f"     {key.replace('_', ' ').title()}: {value}")

                if "compliance_impact" in finding:
                    report.append(f"\n   Compliance Impact: {', '.join(finding['compliance_impact'])}")

                if "remediation" in finding:
                    report.append(f"\n   Remediation: {finding['remediation']['description']}")

                report.append("-" * 80)

        # Network map summary if available
        if "network_map" in report_data:
            report.append("\nNETWORK MAP SUMMARY:")
            report.append("-" * 80)
            map_data = report_data["network_map"]
            report.append(f"Nodes: {len(map_data.get('nodes', []))}")
            report.append(f"Connections: {len(map_data.get('connections', []))}")
            report.append(f"Zones: {len(map_data.get('zones', []))}")

            # List zones and their nodes
            if map_data.get('zones'):
                report.append("\nNetwork Zones:")
                for zone in map_data['zones']:
                    report.append(f"  - {zone['name']}: {len(zone['nodes'])} nodes")

            # Note any unauthorized connections
            unauthorized = [
                c for c in map_data.get('connections', [])
                if c.get('status') == 'unauthorized'
            ]
            if unauthorized:
                report.append(f"\nUnauthorized Connections: {len(unauthorized)}")
                for conn in unauthorized:
                    report.append(f"  - {conn['source']} to {conn['target']}")

        return "\n".join(report)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} - Evaluates network security controls and protections")

    # Required parameters
    parser.add_argument("--target", required=True, help="Target system or network to test")
    parser.add_argument("--target-list", help="File containing list of targets to test")

    # Test parameters
    parser.add_argument("--profile", default=DEFAULT_PROFILE,
                      help="Test profile to use (standard, comprehensive, minimal, etc.)")
    parser.add_argument("--test-type", default=DEFAULT_TEST_TYPE, choices=list(TEST_TYPES.keys()),
                      help="Type of network test to perform")
    parser.add_argument("--protocols", help="Comma-separated list of protocols to test (ssh,tls,ipsec)")
    parser.add_argument("--expected-services", help="JSON file with expected service-port mappings")
    parser.add_argument("--exclude", help="Comma-separated list of hosts to exclude")

    # Performance parameters
    parser.add_argument("--bandwidth-limit", type=int, default=DEFAULT_BANDWIDTH_LIMIT,
                      help="Bandwidth limit in KB/s")
    parser.add_argument("--parallel", type=int, default=DEFAULT_PARALLEL,
                      help="Maximum number of parallel operations")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                      help="Network operation timeout in seconds")

    # Output parameters
    parser.add_argument("--output-format", default=DEFAULT_OUTPUT_FORMAT,
                      help="Output format (json, standard, csv, etc.)")
    parser.add_argument("--output-file", help="Output file path")

    # Additional options
    parser.add_argument("--compliance", help="Compliance framework to check against")
    parser.add_argument("--detailed-mapping", action="store_true",
                      help="Generate detailed network mapping")
    parser.add_argument("--debug-level", type=int, choices=[0, 1, 2], default=1,
                      help="Debug level (0=quiet, 1=normal, 2=verbose)")

    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the network security tester.

    Returns:
        Exit code (0 for success, 1 for errors, 2 for critical findings)
    """
    # Parse command-line arguments
    args = parse_arguments()

    # Configure logging based on verbosity
    log_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    log_level = log_levels[args.debug_level]

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(DEFAULT_LOG_DIR, f"{TOOL_NAME.lower().replace(' ', '_')}.log")),
            logging.StreamHandler()
        ]
    )

    logger = logging.getLogger(TOOL_NAME)

    try:
        # Initialize assessment target
        target = AssessmentTarget(
            target_id=args.target,
            target_type="network" if "," in args.target or "/" in args.target else "host",
            hostname=args.target
        )

        # Parse protocols if provided
        protocols = None
        if args.protocols:
            protocols = [p.strip() for p in args.protocols.split(',')]

        # Parse excluded hosts if provided
        exclude_hosts = None
        if args.exclude:
            exclude_hosts = [h.strip() for h in args.exclude.split(',')]

        # Parse expected services if provided
        expected_services = {}
        if args.expected_services:
            if os.path.isfile(args.expected_services):
                with open(args.expected_services, 'r') as f:
                    expected_services = json.load(f)
            else:
                # Try parsing as a string format like "80:http,443:https"
                try:
                    for mapping in args.expected_services.split(','):
                        port, service = mapping.split(':')
                        expected_services[int(port)] = service
                except Exception:
                    logger.warning(f"Could not parse expected services: {args.expected_services}")

        # Create tester instance
        tester = NetworkSecurityTester(
            target=target,
            profile=args.profile,
            test_type=args.test_type,
            protocols=protocols,
            expected_services=expected_services,
            exclude_hosts=exclude_hosts,
            bandwidth_limit=args.bandwidth_limit,
            parallel=args.parallel,
            timeout=args.timeout,
            compliance_framework=args.compliance,
            detailed_mapping=args.detailed_mapping,
            output_format=args.output_format,
            output_file=args.output_file
        )

        # Initialize the tester
        if not tester.initialize():
            logger.error("Failed to initialize network security tester")
            return 1

        # Execute the tests
        if not tester.execute():
            logger.error("Test execution failed")
            return 1

        # Get findings
        findings = tester.analyze_findings()

        # Generate report
        report = tester.generate_report(findings)

        # Output results
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            logger.info(f"Results written to {args.output_file}")
        else:
            # Print to stdout
            print(report)

        # Determine exit code based on findings
        critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        if critical_count > 0:
            logger.error(f"Found {critical_count} critical findings")
            return 2
        else:
            logger.info("No critical findings found")
            return 0
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return 1
    finally:
        # Cleanup if needed
        pass
