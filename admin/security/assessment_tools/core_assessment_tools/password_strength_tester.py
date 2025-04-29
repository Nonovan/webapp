#!/usr/bin/env python3
"""
Password Strength Tester

This tool tests password policies and identifies weak credentials in authentication systems.
It validates policy configuration, credential strength, brute force protection,
and password storage security.

Features:
- Password policy enforcement validation
- Credential strength assessment
- Brute force resistance testing
- Password storage security verification
- Authentication system integration
- Multi-factor authentication validation
- Account lockout verification
- Password reset flow security testing
"""

import argparse
import base64
import csv
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Counter

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
TOOL_NAME = "Password Strength Tester"
TOOL_VERSION = "1.0.0"
DEFAULT_OUTPUT_FORMAT = "standard"
DEFAULT_LOG_DIR = "logs/password_strength_tester"

# Password policy categories with severity levels
POLICY_CATEGORIES = {
    "min_length": {"severity": FindingSeverity.HIGH, "impact": 0.8},
    "complexity": {"severity": FindingSeverity.HIGH, "impact": 0.7},
    "history": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "expiration": {"severity": FindingSeverity.LOW, "impact": 0.5},
    "lockout": {"severity": FindingSeverity.HIGH, "impact": 0.7},
    "mfa": {"severity": FindingSeverity.CRITICAL, "impact": 0.9},
    "storage": {"severity": FindingSeverity.CRITICAL, "impact": 0.9},
    "weak_credentials": {"severity": FindingSeverity.CRITICAL, "impact": 0.9}
}

# Policy strength score thresholds
POLICY_THRESHOLDS = {
    "weak": 40,
    "moderate": 65,
    "strong": 85
}

# Minimum secure policy requirements by standard
COMPLIANCE_STANDARDS = {
    "pci-dss": {
        "min_length": 7,
        "complexity_required": True,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numeric": True,
        "require_special": False,
        "history_size": 4,
        "max_days": 90,
        "lockout_threshold": 6,
        "lockout_duration": 30,  # minutes
        "mfa_required": "sensitive_operations"
    },
    "nist": {
        "min_length": 8,
        "complexity_required": True,
        "require_uppercase": False,
        "require_lowercase": False,
        "require_numeric": False,
        "require_special": False,
        "history_size": 5,
        "max_days": 0,  # NIST recommends against forced rotation
        "lockout_threshold": 5,
        "lockout_duration": 15,  # minutes
        "mfa_required": "privileged_access"
    },
    "cis": {
        "min_length": 14,
        "complexity_required": True,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numeric": True,
        "require_special": True,
        "history_size": 24,
        "max_days": 90,
        "lockout_threshold": 5,
        "lockout_duration": 15,  # minutes
        "mfa_required": "all_users"
    }
}

# Secure hashing algorithms
SECURE_HASH_ALGORITHMS = ["bcrypt", "argon2", "pbkdf2_hmac_sha256", "scrypt"]

# Common default credentials (simplified list)
DEFAULT_CREDENTIALS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "administrator", "password": "administrator"},
    {"username": "root", "password": "root"},
    {"username": "user", "password": "user"},
    {"username": "guest", "password": "guest"},
    {"username": "demo", "password": "demo"},
    {"username": "test", "password": "test"},
    {"username": "system", "password": "system"},
    {"username": "default", "password": "default"}
]


class PasswordStrengthTester(AssessmentBase):
    """
    Main class for testing password policies and identifying weak credentials.
    """

    def __init__(
        self,
        target: AssessmentTarget,
        policy_only: bool = False,
        default_creds: bool = True,
        dictionary_path: Optional[str] = None,
        check_storage: bool = True,
        policy_test: bool = True,
        check_mfa: bool = True,
        check_lockout: bool = True,
        attempts: int = 5,
        lockout_period: int = 15,
        compliance_framework: Optional[str] = None,
        output_format: str = DEFAULT_OUTPUT_FORMAT,
        output_file: Optional[str] = None
    ):
        """
        Initialize the password strength tester.

        Args:
            target: Target authentication system to test
            policy_only: Only test policy configuration, not actual credentials
            default_creds: Test for default credentials
            dictionary_path: Path to custom dictionary file
            check_storage: Verify password storage security
            policy_test: Test password policy enforcement
            check_mfa: Validate MFA implementation
            check_lockout: Test lockout policy
            attempts: Number of attempts for lockout testing
            lockout_period: Expected lockout period in minutes
            compliance_framework: Compliance framework to check against
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

        self.policy_only = policy_only
        self.default_creds = default_creds
        self.dictionary_path = dictionary_path
        self.check_storage = check_storage
        self.policy_test = policy_test
        self.check_mfa = check_mfa
        self.check_lockout = check_lockout
        self.attempts = attempts
        self.lockout_period = lockout_period
        self.compliance_framework = compliance_framework

        # Results storage
        self.findings = []
        self.policy_findings = []
        self.weak_credentials = []
        self.test_results = []

        # Setup logging
        self.logger = setup_assessment_logging(
            tool_name=TOOL_NAME.lower().replace(' ', '_'),
            log_dir=DEFAULT_LOG_DIR
        )

    @secure_operation("assessment:initialize")
    def initialize(self) -> bool:
        """
        Initialize the tester and verify prerequisites.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self.logger.info(f"Initializing {TOOL_NAME}")
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

            # Verify target access
            if not verify_target_access(self.target):
                self.add_error("Cannot access target for assessment. Check permissions and connectivity.")
                return False

            # Validate dictionary file if specified
            if self.dictionary_path and not os.path.exists(self.dictionary_path):
                self.add_error(f"Dictionary file not found: {self.dictionary_path}")
                return False

            self.set_status(AssessmentStatus.INITIALIZED)
            self.logger.info(f"{TOOL_NAME} initialized successfully")
            return True

        except Exception as e:
            self.add_error(f"Failed to initialize assessment: {str(e)}")
            self.logger.exception(f"Initialization error in {TOOL_NAME}")
            return False

    @secure_operation("assessment:execute")
    def execute(self) -> bool:
        """
        Execute the password policy and strength testing.

        Returns:
            True if execution successful, False otherwise
        """
        try:
            self.logger.info(f"Starting password assessment of {self.target.target_id}")
            self.set_status(AssessmentStatus.RUNNING)
            self.start_time = datetime.now()

            # Log assessment parameters
            log_assessment_event(
                event_type="assessment_started",
                description=f"Password strength assessment started on {self.target.target_id}",
                details={
                    "policy_only": self.policy_only,
                    "default_creds": self.default_creds,
                    "check_storage": self.check_storage,
                    "policy_test": self.policy_test,
                    "check_mfa": self.check_mfa,
                    "check_lockout": self.check_lockout,
                    "compliance_framework": self.compliance_framework
                }
            )

            # Execute tests
            self._execute_tests()

            self.end_time = datetime.now()
            self.logger.info(f"Assessment completed in {(self.end_time - self.start_time).total_seconds()} seconds")

            # Process results
            self._process_results()

            # Generate findings
            self._generate_findings()

            # Mark assessment completed
            self.set_status(AssessmentStatus.COMPLETED)

            return True

        except KeyboardInterrupt:
            self.logger.warning("Assessment interrupted by user")
            self.set_status(AssessmentStatus.INTERRUPTED)
            return False

        except Exception as e:
            self.add_error(f"Assessment execution error: {str(e)}")
            self.logger.exception("Error during password strength assessment execution")
            self.set_status(AssessmentStatus.FAILED)
            return False

    def _execute_tests(self) -> None:
        """
        Execute all enabled password tests.
        """
        # Test password policy if enabled
        if self.policy_test:
            self._test_password_policy()

        # Test for default credentials if enabled
        if self.default_creds and not self.policy_only:
            self._test_default_credentials()

        # Test against dictionary if specified and not policy only mode
        if self.dictionary_path and not self.policy_only:
            self._test_dictionary_passwords()

        # Test password storage security if enabled
        if self.check_storage:
            self._test_password_storage()

        # Check MFA implementation if enabled
        if self.check_mfa:
            self._test_mfa_implementation()

        # Check account lockout if enabled
        if self.check_lockout and not self.policy_only:
            self._test_account_lockout()

    def _test_password_policy(self) -> None:
        """
        Test password policy configuration against best practices.
        """
        self.logger.info("Testing password policy configuration")

        # Get the policy from target system
        policy = self._get_password_policy()

        # Skip this test if we couldn't retrieve the policy
        if not policy:
            self.add_error("Unable to retrieve password policy from target system")
            return

        # Compare with baseline requirements
        baseline = {}
        if self.compliance_framework and self.compliance_framework in COMPLIANCE_STANDARDS:
            baseline = COMPLIANCE_STANDARDS[self.compliance_framework]
        else:
            # Use CIS as default baseline (most stringent)
            baseline = COMPLIANCE_STANDARDS["cis"]

        # Check minimum length
        min_length = policy.get("min_length", 0)
        required_min = baseline.get("min_length", 12)
        if min_length < required_min:
            self.policy_findings.append({
                "id": "POLICY-LENGTH-001",
                "category": "min_length",
                "name": "Insufficient Password Length",
                "description": f"Password policy allows passwords that are too short.",
                "details": {
                    "current_policy": f"Minimum length: {min_length}",
                    "recommended": f"Minimum length: {required_min} or greater",
                    "standard": self.compliance_framework or "Best practice",
                    "remediation": "Update password policy to enforce longer passwords."
                },
                "severity": POLICY_CATEGORIES["min_length"]["severity"],
                "false_positive_risk": "low"
            })

        # Check complexity requirements
        if baseline.get("complexity_required", True) and not policy.get("complexity_required", False):
            self.policy_findings.append({
                "id": "POLICY-COMPLEX-001",
                "category": "complexity",
                "name": "No Complexity Requirements",
                "description": "Password policy does not enforce character complexity.",
                "details": {
                    "current_policy": "No complexity requirements",
                    "recommended": "Require diverse character sets",
                    "standard": self.compliance_framework or "Best practice",
                    "remediation": "Update password policy to enforce character diversity."
                },
                "severity": POLICY_CATEGORIES["complexity"]["severity"],
                "false_positive_risk": "low"
            })

        # Check character set requirements
        for char_type in ["uppercase", "lowercase", "numeric", "special"]:
            if baseline.get(f"require_{char_type}", True) and not policy.get(f"require_{char_type}", False):
                self.policy_findings.append({
                    "id": f"POLICY-COMPLEX-{char_type.upper()}",
                    "category": "complexity",
                    "name": f"No {char_type.capitalize()} Character Requirement",
                    "description": f"Password policy does not require {char_type} characters.",
                    "details": {
                        "current_policy": f"Does not require {char_type} characters",
                        "recommended": f"Require {char_type} characters",
                        "standard": self.compliance_framework or "Best practice",
                        "remediation": f"Update password policy to require {char_type} characters."
                    },
                    "severity": POLICY_CATEGORIES["complexity"]["severity"],
                    "false_positive_risk": "low"
                })

        # Check password history
        history_size = policy.get("history_size", 0)
        required_history = baseline.get("history_size", 24)
        if history_size < required_history:
            self.policy_findings.append({
                "id": "POLICY-HISTORY-001",
                "category": "history",
                "name": "Insufficient Password History",
                "description": "Password policy does not prevent reuse of recent passwords.",
                "details": {
                    "current_policy": f"Remembers {history_size} previous passwords",
                    "recommended": f"Remember at least {required_history} previous passwords",
                    "standard": self.compliance_framework or "Best practice",
                    "remediation": "Increase the password history size to prevent password reuse."
                },
                "severity": POLICY_CATEGORIES["history"]["severity"],
                "false_positive_risk": "low"
            })

        # Check password expiration (unless standard recommends against it, like NIST)
        if baseline.get("max_days", 0) > 0:
            max_days = policy.get("max_days", 0)
            required_max = baseline.get("max_days", 90)
            if max_days == 0 or max_days > required_max:
                self.policy_findings.append({
                    "id": "POLICY-EXPIRY-001",
                    "category": "expiration",
                    "name": "Missing or Excessive Password Expiration",
                    "description": "Password expiration policy not configured correctly.",
                    "details": {
                        "current_policy": f"Maximum password age: {max_days if max_days > 0 else 'Not enforced'} days",
                        "recommended": f"Maximum password age: {required_max} days",
                        "standard": self.compliance_framework or "Best practice",
                        "remediation": f"Configure password expiration to {required_max} days."
                    },
                    "severity": POLICY_CATEGORIES["expiration"]["severity"],
                    "false_positive_risk": "medium"
                })

        # Check account lockout threshold
        lockout_threshold = policy.get("lockout_threshold", 0)
        required_threshold = baseline.get("lockout_threshold", 5)
        if lockout_threshold == 0 or lockout_threshold > required_threshold:
            self.policy_findings.append({
                "id": "POLICY-LOCKOUT-001",
                "category": "lockout",
                "name": "Insufficient Account Lockout Threshold",
                "description": "Account lockout threshold too high or not enforced.",
                "details": {
                    "current_policy": f"Locks after {lockout_threshold if lockout_threshold > 0 else 'infinite'} failed attempts",
                    "recommended": f"Lock after {required_threshold} failed attempts",
                    "standard": self.compliance_framework or "Best practice",
                    "remediation": f"Configure account lockout after {required_threshold} failed login attempts."
                },
                "severity": POLICY_CATEGORIES["lockout"]["severity"],
                "false_positive_risk": "low"
            })

        # Check lockout duration
        lockout_duration = policy.get("lockout_duration", 0)
        required_duration = baseline.get("lockout_duration", 15)
        if lockout_duration == 0 or lockout_duration < required_duration:
            self.policy_findings.append({
                "id": "POLICY-LOCKOUT-002",
                "category": "lockout",
                "name": "Insufficient Account Lockout Duration",
                "description": "Account lockout duration too short or not enforced.",
                "details": {
                    "current_policy": f"Lockout duration: {lockout_duration if lockout_duration > 0 else 'Not enforced'} minutes",
                    "recommended": f"Lockout duration: At least {required_duration} minutes",
                    "standard": self.compliance_framework or "Best practice",
                    "remediation": f"Configure account lockout duration to at least {required_duration} minutes."
                },
                "severity": POLICY_CATEGORIES["lockout"]["severity"],
                "false_positive_risk": "low"
            })

        # Check MFA requirements
        mfa_required = policy.get("mfa_required", "none")
        recommended_mfa = baseline.get("mfa_required", "sensitive_operations")

        # Determine if the MFA policy is sufficient
        mfa_levels = ["none", "sensitive_operations", "privileged_access", "all_users"]
        current_level = mfa_levels.index(mfa_required) if mfa_required in mfa_levels else 0
        required_level = mfa_levels.index(recommended_mfa) if recommended_mfa in mfa_levels else 1

        if current_level < required_level:
            self.policy_findings.append({
                "id": "POLICY-MFA-001",
                "category": "mfa",
                "name": "Insufficient MFA Requirements",
                "description": "Multi-factor authentication requirements are insufficient.",
                "details": {
                    "current_policy": f"MFA required for: {mfa_required}",
                    "recommended": f"MFA required for: {recommended_mfa}",
                    "standard": self.compliance_framework or "Best practice",
                    "remediation": f"Update authentication policy to require MFA for {recommended_mfa}."
                },
                "severity": POLICY_CATEGORIES["mfa"]["severity"],
                "false_positive_risk": "low"
            })

    def _get_password_policy(self) -> Dict[str, Any]:
        """
        Retrieve password policy from target system.

        In a real implementation, this would connect to the target system and
        retrieve the actual policy configuration.

        Returns:
            Dictionary containing password policy settings
        """
        # This is a simulated implementation
        # In a real implementation, this would query the target system's authentication settings

        self.logger.info(f"Retrieving password policy from {self.target.target_id}")

        # Simulate retrieving policy from a server - this would be replaced with
        # actual API calls or authentication system integration in production
        simulated_policies = {
            # Strong policy example
            "auth-service": {
                "min_length": 14,
                "complexity_required": True,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numeric": True,
                "require_special": True,
                "history_size": 24,
                "max_days": 90,
                "lockout_threshold": 5,
                "lockout_duration": 30,
                "mfa_required": "privileged_access"
            },
            # Weak policy example
            "web-portal": {
                "min_length": 8,
                "complexity_required": False,
                "require_uppercase": False,
                "require_lowercase": True,
                "require_numeric": True,
                "require_special": False,
                "history_size": 5,
                "max_days": 180,
                "lockout_threshold": 10,
                "lockout_duration": 5,
                "mfa_required": "none"
            },
            # Moderate policy example
            "admin-panel": {
                "min_length": 10,
                "complexity_required": True,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numeric": True,
                "require_special": False,
                "history_size": 12,
                "max_days": 120,
                "lockout_threshold": 7,
                "lockout_duration": 15,
                "mfa_required": "sensitive_operations"
            }
        }

        # Generate a policy based on target name or use a default policy
        target_name = self.target.target_id.lower()

        if "admin" in target_name:
            return simulated_policies.get("admin-panel", {})
        elif "auth" in target_name:
            return simulated_policies.get("auth-service", {})
        else:
            return simulated_policies.get("web-portal", {})

    def _test_default_credentials(self) -> None:
        """
        Test for default or common credentials.
        """
        self.logger.info("Testing for default credentials")

        # In a real implementation, this would attempt authentication with common
        # credentials against the target system

        # Simulated test - in a real implementation, this would use the target's
        # authentication mechanism to test real credentials
        successful_logins = []

        for cred in DEFAULT_CREDENTIALS:
            username = cred["username"]
            password = cred["password"]

            # Simulate a login attempt and check if it succeeded
            # In reality, this would be a real login attempt against the target
            if self._simulate_login_attempt(username, password):
                successful_logins.append({
                    "username": username,
                    "password": password
                })

        # Record findings for successful logins
        for login in successful_logins:
            self.weak_credentials.append({
                "id": "CRED-DEFAULT-001",
                "category": "weak_credentials",
                "name": "Default Credentials Accepted",
                "description": f"System accepts default or common credentials.",
                "details": {
                    "username": login["username"],
                    "password": login["password"],
                    "note": "These are widely known default credentials",
                    "remediation": "Change this password immediately and implement a strong password policy."
                },
                "severity": POLICY_CATEGORIES["weak_credentials"]["severity"],
                "false_positive_risk": "very_low"
            })

    def _test_dictionary_passwords(self) -> None:
        """
        Test for common passwords from a dictionary file.
        """
        dictionary_file = self.dictionary_path
        if not dictionary_file:
            # Use a default small dictionary for demo purposes
            # In a real implementation, a comprehensive wordlist would be used
            common_passwords = ["123456", "password", "admin123", "welcome1", "P@ssword1"]
        else:
            # Read passwords from the specified dictionary file
            try:
                with open(dictionary_file, 'r') as f:
                    common_passwords = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(common_passwords)} passwords from dictionary file")
            except Exception as e:
                self.logger.error(f"Error reading dictionary file: {str(e)}")
                self.add_error(f"Could not read dictionary file: {str(e)}")
                return

        # Get a list of usernames to test with
        usernames = self._get_usernames_to_test()

        # Limit the number of attempts to avoid excessive testing
        max_attempts = 100
        attempted = 0
        successful_logins = []

        self.logger.info(f"Testing {len(usernames)} users with dictionary passwords")

        # For each username, try the most likely passwords
        for username in usernames:
            # Try username-based variations first
            username_variations = [
                username.lower(),
                username.capitalize(),
                f"{username}123",
                f"{username}@123",
                f"{username}!",
                f"{username}#"
            ]

            # Try these variations first
            for password in username_variations:
                if attempted >= max_attempts:
                    break

                if self._simulate_login_attempt(username, password):
                    successful_logins.append({
                        "username": username,
                        "password": password,
                        "type": "username_variation"
                    })

                attempted += 1

            # Try common passwords from dictionary
            for password in common_passwords:
                if attempted >= max_attempts:
                    break

                if self._simulate_login_attempt(username, password):
                    successful_logins.append({
                        "username": username,
                        "password": password,
                        "type": "dictionary"
                    })

                attempted += 1

                # Avoid excessive testing
                if attempted % 10 == 0:
                    time.sleep(0.1)  # Small delay to prevent overwhelming the target

        # Record findings for successful logins
        for login in successful_logins:
            self.weak_credentials.append({
                "id": "CRED-WEAK-001",
                "category": "weak_credentials",
                "name": "Weak Password Detected",
                "description": f"User account has a weak password.",
                "details": {
                    "username": login["username"],
                    "password_type": login["type"],
                    "remediation": "Change this password immediately and educate users about strong passwords."
                },
                "severity": POLICY_CATEGORIES["weak_credentials"]["severity"],
                "false_positive_risk": "low"
            })

    def _get_usernames_to_test(self) -> List[str]:
        """
        Get a list of usernames to test against.

        In a real implementation, this would be retrieved from the target system
        or provided by the user.

        Returns:
            List of usernames
        """
        # This is a simulated implementation
        # In a real-world scenario, this would:
        # 1. Either use a provided list of users to test
        # 2. Or retrieve a list of valid users from the target system if permitted

        return ["admin", "user", "operator", "guest", "support", "system"]

    def _simulate_login_attempt(self, username: str, password: str) -> bool:
        """
        Simulate a login attempt against the target system.

        In a real implementation, this would actually attempt to authenticate
        against the target system.

        Args:
            username: Username to attempt
            password: Password to attempt

        Returns:
            Whether the login was successful
        """
        # This is a simulated implementation
        # In a real implementation, this would use the target's authentication mechanism

        # Simulate some default/weak credentials as "successful" logins
        weak_combinations = {
            "admin": ["admin", "password", "admin123"],
            "user": ["user", "password", "user123"],
            "guest": ["guest", "guest123", ""],
            "system": ["system", "password", "admin"]
        }

        # Check if this username/password combination is in our simulated weak list
        if username in weak_combinations and password in weak_combinations[username]:
            return True

        return False

    def _test_password_storage(self) -> None:
        """
        Test password storage security (hashing, encryption, etc).
        """
        self.logger.info("Testing password storage security")

        # In a real implementation, this would examine the password storage mechanism
        # to check for proper hashing, salting, etc.

        # Get storage information from target system
        storage_info = self._get_password_storage_info()

        # Check hashing algorithm
        hash_algorithm = storage_info.get("hash_algorithm", "").lower()
        if not hash_algorithm:
            self.policy_findings.append({
                "id": "STORAGE-HASH-001",
                "category": "storage",
                "name": "Unknown Password Hashing",
                "description": "Unable to determine password hashing algorithm.",
                "details": {
                    "finding": "No password hashing information available",
                    "recommended": f"Use a strong algorithm like {', '.join(SECURE_HASH_ALGORITHMS)}",
                    "remediation": "Implement secure password hashing with a modern algorithm."
                },
                "severity": POLICY_CATEGORIES["storage"]["severity"],
                "false_positive_risk": "medium"
            })
        elif hash_algorithm == "plaintext":
            self.policy_findings.append({
                "id": "STORAGE-HASH-002",
                "category": "storage",
                "name": "Plaintext Password Storage",
                "description": "Passwords are stored in plaintext.",
                "details": {
                    "finding": "Passwords stored as plaintext",
                    "recommended": f"Use a strong algorithm like {', '.join(SECURE_HASH_ALGORITHMS)}",
                    "remediation": "Immediately implement secure password hashing."
                },
                "severity": POLICY_CATEGORIES["storage"]["severity"],
                "false_positive_risk": "very_low"
            })
        elif hash_algorithm in ["md5", "sha1"]:
            self.policy_findings.append({
                "id": "STORAGE-HASH-003",
                "category": "storage",
                "name": "Weak Password Hashing Algorithm",
                "description": f"Passwords are hashed with weak algorithm ({hash_algorithm}).",
                "details": {
                    "current": f"Using {hash_algorithm} for password hashing",
                    "recommended": f"Use a strong algorithm like {', '.join(SECURE_HASH_ALGORITHMS)}",
                    "remediation": "Migrate to a modern password hashing algorithm."
                },
                "severity": POLICY_CATEGORIES["storage"]["severity"],
                "false_positive_risk": "low"
            })

        # Check salting
        if not storage_info.get("uses_salt", False):
            self.policy_findings.append({
                "id": "STORAGE-SALT-001",
                "category": "storage",
                "name": "Unsalted Password Hashes",
                "description": "Password hashes are not salted.",
                "details": {
                    "finding": "No salt used in password hashing",
                    "recommended": "Use unique random salt for each password",
                    "remediation": "Implement proper salting with password hashing."
                },
                "severity": POLICY_CATEGORIES["storage"]["severity"],
                "false_positive_risk": "low"
            })

        # Check salt uniqueness
        if not storage_info.get("unique_salt", False) and storage_info.get("uses_salt", False):
            self.policy_findings.append({
                "id": "STORAGE-SALT-002",
                "category": "storage",
                "name": "Non-unique Password Salt",
                "description": "Password hashes use shared salt instead of unique per-user salt.",
                "details": {
                    "finding": "Shared salt used across user passwords",
                    "recommended": "Use unique random salt for each password",
                    "remediation": "Modify hashing implementation to use unique salts."
                },
                "severity": POLICY_CATEGORIES["storage"]["severity"],
                "false_positive_risk": "low"
            })

        # Check for pepper or additional secret
        if not storage_info.get("uses_pepper", False):
            self.policy_findings.append({
                "id": "STORAGE-PEPPER-001",
                "category": "storage",
                "name": "No Server-Side Secret",
                "description": "Password hashing doesn't use a server-side secret (pepper).",
                "details": {
                    "finding": "No server-side secret used in password hashing",
                    "recommended": "Use a server-side secret in addition to unique salts",
                    "remediation": "Implement a server-side secret in the password hashing process."
                },
                "severity": FindingSeverity.MEDIUM,
                "false_positive_risk": "medium"
            })

        # Check work factor if using bcrypt, PBKDF2, etc.
        if hash_algorithm in ["bcrypt", "pbkdf2"] and "work_factor" in storage_info:
            work_factor = storage_info["work_factor"]
            min_factor = {"bcrypt": 12, "pbkdf2": 310000}.get(hash_algorithm, 0)

            if work_factor < min_factor:
                self.policy_findings.append({
                    "id": "STORAGE-WORK-001",
                    "category": "storage",
                    "name": "Insufficient Hashing Work Factor",
                    "description": f"{hash_algorithm.upper()} work factor is too low.",
                    "details": {
                        "current": f"Work factor: {work_factor}",
                        "recommended": f"Work factor: {min_factor} or higher",
                        "remediation": f"Increase the {hash_algorithm} work factor to at least {min_factor}."
                    },
                    "severity": POLICY_CATEGORIES["storage"]["severity"],
                    "false_positive_risk": "low"
                })

    def _get_password_storage_info(self) -> Dict[str, Any]:
        """
        Get information about password storage implementation.

        In a real implementation, this would query the target system for
        details about its password storage mechanism.

        Returns:
            Dictionary with password storage information
        """
        # This is a simulated implementation
        # In a real implementation, this would be retrieved from the target system

        # Simulate different storage mechanisms based on target name
        target_name = self.target.target_id.lower()
        storage_types = {
            # Secure implementation
            "secure": {
                "hash_algorithm": "bcrypt",
                "uses_salt": True,
                "unique_salt": True,
                "uses_pepper": True,
                "work_factor": 14  # Good bcrypt cost factor
            },
            # Older but acceptable implementation
            "legacy": {
                "hash_algorithm": "pbkdf2_hmac_sha256",
                "uses_salt": True,
                "unique_salt": True,
                "uses_pepper": False,
                "work_factor": 310000  # Minimally acceptable iteration count
            },
            # Insecure implementation
            "weak": {
                "hash_algorithm": "md5",
                "uses_salt": False,
                "unique_salt": False,
                "uses_pepper": False
            },
            # Very insecure implementation
            "critical": {
                "hash_algorithm": "plaintext",
                "uses_salt": False,
                "unique_salt": False,
                "uses_pepper": False
            }
        }

        if "secure" in target_name or "auth" in target_name:
            return storage_types["secure"]
        elif "admin" in target_name:
            return storage_types["legacy"]
        elif "test" in target_name or "dev" in target_name:
            return storage_types["weak"]
        elif "demo" in target_name:
            return storage_types["critical"]
        else:
            return storage_types["legacy"]

    def _test_mfa_implementation(self) -> None:
        """
        Test multi-factor authentication implementation.
        """
        self.logger.info("Testing MFA implementation")

        # In a real implementation, this would check the target system's
        # MFA configuration and test its implementation

        # Get MFA information from target system
        mfa_info = self._get_mfa_info()

        # Check if MFA is implemented
        if not mfa_info.get("implemented", False):
            self.policy_findings.append({
                "id": "MFA-IMPL-001",
                "category": "mfa",
                "name": "MFA Not Implemented",
                "description": "Multi-factor authentication is not implemented.",
                "details": {
                    "finding": "No MFA capability detected",
                    "recommended": "Implement multi-factor authentication",
                    "remediation": "Add MFA support for user authentication."
                },
                "severity": POLICY_CATEGORIES["mfa"]["severity"],
                "false_positive_risk": "low"
            })
            return

        # Check MFA methods
        methods = mfa_info.get("methods", [])
        if not methods:
            self.policy_findings.append({
                "id": "MFA-METHOD-001",
                "category": "mfa",
                "name": "No MFA Methods Available",
                "description": "MFA is configured but no methods are available.",
                "details": {
                    "finding": "MFA framework exists but no methods are configured",
                    "recommended": "Implement at least TOTP-based MFA",
                    "remediation": "Configure and enable MFA methods."
                },
                "severity": POLICY_CATEGORIES["mfa"]["severity"],
                "false_positive_risk": "low"
            })

        # Check for SMS-only MFA (less secure)
        if methods == ["sms"] or (len(methods) == 1 and "sms" in methods):
            self.policy_findings.append({
                "id": "MFA-METHOD-002",
                "category": "mfa",
                "name": "SMS-Only MFA",
                "description": "Only SMS is offered as an MFA method.",
                "details": {
                    "current": "SMS is the only MFA method",
                    "recommended": "Offer app-based TOTP or security keys",
                    "remediation": "Implement additional, more secure MFA methods."
                },
                "severity": FindingSeverity.MEDIUM,
                "false_positive_risk": "low"
            })

        # Check if MFA can be bypassed
        if mfa_info.get("can_bypass", False):
            self.policy_findings.append({
                "id": "MFA-ENFORCE-001",
                "category": "mfa",
                "name": "MFA Can Be Bypassed",
                "description": "Multi-factor authentication can be bypassed.",
                "details": {
                    "finding": "MFA can be bypassed or is not strictly enforced",
                    "recommended": "Strictly enforce MFA for all applicable accounts",
                    "remediation": "Remove MFA bypass options and enforce MFA usage."
                },
                "severity": POLICY_CATEGORIES["mfa"]["severity"],
                "false_positive_risk": "low"
            })

        # Check if backup codes are implemented securely
        if "backup_codes" in methods:
            backup_code_security = mfa_info.get("backup_code_security", {})

            if not backup_code_security.get("hashed", False):
                self.policy_findings.append({
                    "id": "MFA-BACKUP-001",
                    "category": "mfa",
                    "name": "Insecure Backup Code Storage",
                    "description": "MFA backup codes are not securely stored.",
                    "details": {
                        "finding": "Backup codes are not stored using secure hashing",
                        "recommended": "Store backup codes using secure hashing algorithms",
                        "remediation": "Implement secure storage for MFA backup codes."
                    },
                    "severity": FindingSeverity.HIGH,
                    "false_positive_risk": "low"
                })

            if not backup_code_security.get("rate_limited", False):
                self.policy_findings.append({
                    "id": "MFA-BACKUP-002",
                    "category": "mfa",
                    "name": "No Backup Code Rate Limiting",
                    "description": "MFA backup code usage is not rate limited.",
                    "details": {
                        "finding": "No rate limiting on backup code attempts",
                        "recommended": "Implement rate limiting for backup code usage",
                        "remediation": "Add rate limiting to prevent brute forcing of backup codes."
                    },
                    "severity": FindingSeverity.MEDIUM,
                    "false_positive_risk": "medium"
                })

    def _get_mfa_info(self) -> Dict[str, Any]:
        """
        Get information about MFA implementation.

        In a real implementation, this would query the target system for
        details about its MFA configuration.

        Returns:
            Dictionary with MFA information
        """
        # This is a simulated implementation
        # In a real implementation, this would be retrieved from the target system

        # Simulate different MFA implementations based on target name
        target_name = self.target.target_id.lower()
        mfa_types = {
            # Strong MFA implementation
            "secure": {
                "implemented": True,
                "methods": ["totp", "security_key", "backup_codes"],
                "can_bypass": False,
                "enforced_for": "all_users",
                "backup_code_security": {
                    "hashed": True,
                    "rate_limited": True
                }
            },
            # Acceptable MFA implementation
            "standard": {
                "implemented": True,
                "methods": ["totp", "sms", "backup_codes"],
                "can_bypass": False,
                "enforced_for": "privileged_access",
                "backup_code_security": {
                    "hashed": True,
                    "rate_limited": False
                }
            },
            # Weak MFA implementation
            "weak": {
                "implemented": True,
                "methods": ["sms", "email"],
                "can_bypass": True,
                "enforced_for": "sensitive_operations",
                "backup_code_security": {
                    "hashed": False,
                    "rate_limited": False
                }
            },
            # No MFA implementation
            "none": {
                "implemented": False,
                "methods": [],
                "can_bypass": True,
                "enforced_for": "none"
            }
        }

        if "secure" in target_name or "sso" in target_name:
            return mfa_types["secure"]
        elif "admin" in target_name or "auth" in target_name:
            return mfa_types["standard"]
        elif "portal" in target_name:
            return mfa_types["weak"]
        else:
            return mfa_types["none"]

    def _test_account_lockout(self) -> None:
        """
        Test account lockout implementation.
        """
        self.logger.info("Testing account lockout implementation")

        # In a real implementation, this would test the target system's
        # account lockout mechanism by deliberately failing login attempts

        # Get lockout information from target system by testing
        lockout_info = self._test_lockout_mechanism()

        # Check if lockout is implemented
        if not lockout_info.get("implemented", False):
            self.policy_findings.append({
                "id": "LOCKOUT-IMPL-001",
                "category": "lockout",
                "name": "No Account Lockout",
                "description": "Account lockout is not implemented.",
                "details": {
                    "finding": "No account lockout detected after multiple failed attempts",
                    "recommended": "Implement account lockout after consecutive failed attempts",
                    "remediation": "Configure account lockout for security against brute force attacks."
                },
                "severity": POLICY_CATEGORIES["lockout"]["severity"],
                "false_positive_risk": "low"
            })
            return

        # Check lockout threshold
        threshold = lockout_info.get("threshold", 0)
        expected_threshold = self.attempts
        if threshold == 0 or threshold > expected_threshold:
            self.policy_findings.append({
                "id": "LOCKOUT-THRESHOLD-001",
                "category": "lockout",
                "name": "High Lockout Threshold",
                "description": "Account lockout threshold is too high.",
                "details": {
                    "current": f"Account locks after {threshold} failed attempts" if threshold > 0 else "No threshold detected",
                    "recommended": f"Lock after {expected_threshold} failed attempts",
                    "remediation": f"Lower the account lockout threshold to {expected_threshold} attempts."
                },
                "severity": POLICY_CATEGORIES["lockout"]["severity"],
                "false_positive_risk": "medium"
            })

        # Check lockout duration
        duration = lockout_info.get("duration", 0)
        expected_duration = self.lockout_period

        if duration == 0:
            self.policy_findings.append({
                "id": "LOCKOUT-DURATION-001",
                "category": "lockout",
                "name": "No Automatic Lockout Release",
                "description": "Accounts remain locked until administrator intervention.",
                "details": {
                    "current": "Manual unlock required for locked accounts",
                    "recommended": f"Automatic unlock after {expected_duration} minutes",
                    "note": "Manual unlock can be acceptable for high-security environments",
                    "remediation": "Consider implementing automatic account unlock for normal users."
                },
                "severity": FindingSeverity.LOW,
                "false_positive_risk": "high"
            })
        elif duration < expected_duration:
            self.policy_findings.append({
                "id": "LOCKOUT-DURATION-002",
                "category": "lockout",
                "name": "Short Lockout Duration",
                "description": "Account lockout duration is too short.",
                "details": {
                    "current": f"Accounts unlock after {duration} minutes",
                    "recommended": f"Lock for at least {expected_duration} minutes",
                    "remediation": f"Increase account lockout duration to at least {expected_duration} minutes."
                },
                "severity": POLICY_CATEGORIES["lockout"]["severity"],
                "false_positive_risk": "low"
            })

        # Check if there's no incremental lockout (progressive delays)
        if not lockout_info.get("progressive", False):
            self.policy_findings.append({
                "id": "LOCKOUT-PROGRESSIVE-001",
                "category": "lockout",
                "name": "No Progressive Lockout",
                "description": "Account lockout doesn't use progressive delays.",
                "details": {
                    "current": "Fixed lockout duration regardless of attempt count",
                    "recommended": "Progressive lockout duration that increases with repeated failures",
                    "remediation": "Implement progressive lockout mechanism."
                },
                "severity": FindingSeverity.LOW,
                "false_positive_risk": "medium"
            })

    def _test_lockout_mechanism(self) -> Dict[str, Any]:
        """
        Test account lockout mechanism by attempting logins.

        In a real implementation, this would make deliberate failed login
        attempts to test the lockout mechanism.

        Returns:
            Dictionary with lockout information
        """
        # This is a simulated implementation
        # In a real implementation, this would perform actual login attempts

        # Simulate different lockout implementations based on target name
        target_name = self.target.target_id.lower()
        lockout_types = {
            # Strong lockout implementation
            "secure": {
                "implemented": True,
                "threshold": 3,
                "duration": 30,
                "progressive": True,
                "notify_user": True
            },
            # Standard lockout implementation
            "standard": {
                "implemented": True,
                "threshold": 5,
                "duration": 15,
                "progressive": False,
                "notify_user": True
            },
            # Weak lockout implementation
            "weak": {
                "implemented": True,
                "threshold": 10,
                "duration": 5,
                "progressive": False,
                "notify_user": False
            },
            # No lockout implementation
            "none": {
                "implemented": False,
                "threshold": 0,
                "duration": 0,
                "progressive": False,
                "notify_user": False
            }
        }

        if "secure" in target_name:
            return lockout_types["secure"]
        elif "admin" in target_name or "auth" in target_name:
            return lockout_types["standard"]
        elif "portal" in target_name or "service" in target_name:
            return lockout_types["weak"]
        else:
            return lockout_types["none"]

    def _process_results(self) -> None:
        """
        Process test results and calculate final scores.
        """
        self.logger.info("Processing assessment results")

        # Organize findings by category
        policy_by_category = {}
        for finding in self.policy_findings:
            category = finding["category"]
            if category not in policy_by_category:
                policy_by_category[category] = []
            policy_by_category[category].append(finding)

        # Calculate policy strength score
        max_score = 100
        deductions = {
            FindingSeverity.CRITICAL: 25,
            FindingSeverity.HIGH: 15,
            FindingSeverity.MEDIUM: 10,
            FindingSeverity.LOW: 5,
            FindingSeverity.INFO: 0
        }

        score = max_score
        for finding in self.policy_findings:
            severity = finding["severity"]
            if isinstance(severity, str):
                severity = FindingSeverity[severity]

            score -= deductions.get(severity, 0)

        # Ensure score is within bounds
        score = max(0, min(score, max_score))

        # Create a summary of results
        self.summary = {
            "score": score,
            "strength": "strong" if score >= POLICY_THRESHOLDS["strong"] else
                       "moderate" if score >= POLICY_THRESHOLDS["moderate"] else
                       "weak",
            "policy_findings": len(self.policy_findings),
            "credential_findings": len(self.weak_credentials),
            "policy_by_severity": self._count_by_severity(self.policy_findings),
            "policy_by_category": {k: len(v) for k, v in policy_by_category.items()},
            "weak_accounts": len(set(item["details"].get("username", "") for item in self.weak_credentials))
        }

        # Prepare final test results
        self.test_results = {
            "summary": self.summary,
            "policy_findings": self.policy_findings,
            "credential_findings": self.weak_credentials
        }

    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Count findings by severity level.

        Args:
            findings: List of findings to count

        Returns:
            Dictionary with counts by severity
        """
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        for finding in findings:
            severity = finding["severity"]
            if isinstance(severity, FindingSeverity):
                severity = severity.name

            if severity in counts:
                counts[severity] += 1

        return counts

    def _generate_findings(self) -> None:
        """
        Generate formal findings from test results.
        """
        self.findings = []

        # Convert policy findings to Finding objects
        for result in self.policy_findings:
            finding = Finding(
                title=result.get("name", "Unnamed Issue"),
                description=result.get("description", "No description provided"),
                severity=result.get("severity", FindingSeverity.MEDIUM),
                category=result.get("category", "policy"),
                affected_resource=self.target.target_id,
                details=result.get("details", {})
            )

            # Add CVSS scoring if applicable
            cvss_vector = self._calculate_cvss_vector(result)
            if cvss_vector:
                finding.cvss = CVSS(vector=cvss_vector)

            # Add remediation information
            remediation_text = result.get("details", {}).get("remediation", "")
            if remediation_text:
                finding.remediation = Remediation(
                    description=remediation_text,
                    type="mitigation"
                )

            # Add finding to results
            self.findings.append(finding)

            # Log security finding
            log_security_finding(
                finding=finding,
                source=TOOL_NAME,
                target_id=self.target.target_id
            )

        # Convert credential findings to Finding objects
        for result in self.weak_credentials:
            # Sanitize the output to avoid including actual passwords
            details = result.get("details", {}).copy()
            if "password" in details:
                del details["password"]

            finding = Finding(
                title=result.get("name", "Unnamed Issue"),
                description=result.get("description", "No description provided"),
                severity=result.get("severity", FindingSeverity.CRITICAL),
                category=result.get("category", "credentials"),
                affected_resource=self.target.target_id,
                details=details
            )

            # Add CVSS scoring
            cvss_vector = self._calculate_cvss_vector(result)
            if cvss_vector:
                finding.cvss = CVSS(vector=cvss_vector)

            # Add remediation information
            remediation_text = details.get("remediation", "")
            if remediation_text:
                finding.remediation = Remediation(
                    description=remediation_text,
                    type="mitigation"
                )

            # Add finding to results
            self.findings.append(finding)

            # Log security finding
            log_security_finding(
                finding=finding,
                source=TOOL_NAME,
                target_id=self.target.target_id
            )

    def _calculate_cvss_vector(self, result: Dict[str, Any]) -> str:
        """
        Calculate CVSS vector string based on finding category and severity.

        Args:
            result: Finding data

        Returns:
            CVSS vector string
        """
        category = result.get("category", "policy")
        severity = result.get("severity", FindingSeverity.MEDIUM)

        # Base vectors by severity
        vectors = {
            FindingSeverity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0
            FindingSeverity.HIGH: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
            FindingSeverity.MEDIUM: "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",    # 6.3
            FindingSeverity.LOW: "AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",       # 1.8
            FindingSeverity.INFO: "AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"       # 0.0
        }

        # Category-specific vectors
        category_vectors = {
            "min_length": {
                FindingSeverity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
                FindingSeverity.HIGH: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",      # 8.6
                FindingSeverity.MEDIUM: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",    # 6.5
            },
            "complexity": {
                FindingSeverity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
                FindingSeverity.HIGH: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",      # 8.6
                FindingSeverity.MEDIUM: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",    # 6.5
            },
            "history": {
                FindingSeverity.HIGH: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",      # 6.5
                FindingSeverity.MEDIUM: "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",    # 6.3
                FindingSeverity.LOW: "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",       # 5.3
            },
            "expiration": {
                FindingSeverity.MEDIUM: "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",    # 4.8
                FindingSeverity.LOW: "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",       # 3.7
            },
            "lockout": {
                FindingSeverity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
                FindingSeverity.HIGH: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 7.5
                FindingSeverity.MEDIUM: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",    # 5.3
                FindingSeverity.LOW: "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",       # 4.0
            },
            "mfa": {
                FindingSeverity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0
                FindingSeverity.HIGH: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",      # 9.1
            },
            "storage": {
                FindingSeverity.CRITICAL: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",  # 9.9
                FindingSeverity.HIGH: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",      # 8.5
            },
            "weak_credentials": {
                FindingSeverity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0
            }
        }

        # Use category-specific vector if available, otherwise default to severity-based
        if category in category_vectors and severity in category_vectors[category]:
            return category_vectors[category][severity]

        return vectors.get(severity)

    def analyze_findings(self) -> List[Finding]:
        """
        Analyze and return the password security findings.

        Returns:
            List of findings
        """
        if self.status not in [AssessmentStatus.COMPLETED, AssessmentStatus.INTERRUPTED]:
            self.logger.warning("Attempting to analyze findings before assessment is completed")

        return self.findings

    def generate_report(self, findings: List[Finding]) -> Any:
        """
        Generate assessment report.

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
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == FindingSeverity.HIGH),
                "medium": sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == FindingSeverity.LOW),
                "info": sum(1 for f in findings if f.severity == FindingSeverity.INFO)
            }
        }

        # Add assessment summary if available
        if hasattr(self, 'summary'):
            report_data["policy_score"] = self.summary.get("score", 0)
            report_data["policy_strength"] = self.summary.get("strength", "unknown")
            report_data["policy_findings"] = self.summary.get("policy_findings", 0)
            report_data["credential_findings"] = self.summary.get("credential_findings", 0)
            report_data["weak_accounts"] = self.summary.get("weak_accounts", 0)
            report_data["policy_by_severity"] = self.summary.get("policy_by_severity", {})
            report_data["policy_by_category"] = self.summary.get("policy_by_category", {})
        else:
            report_data["policy_score"] = 0
            report_data["policy_strength"] = "unknown"
            report_data["policy_findings"] = 0
            report_data["credential_findings"] = 0
            report_data["weak_accounts"] = 0
            report_data["policy_by_severity"] = {}
            report_data["policy_by_category"] = {}
        # Add findings to report
        report_data["findings"] = [f.to_dict() for f in findings]
        return report_data

    def get_report(self, format: str = "json") -> Any:
        """
        Get the report in the specified format.

        Args:
            format: Format to return the report in (json, html, text, pdf, etc.)

        Returns:
            Report data in the requested format
        """
        if self.status not in [AssessmentStatus.COMPLETED, AssessmentStatus.INTERRUPTED]:
            self.logger.warning("Attempting to get report before assessment is completed")

        # Get findings
        findings = self.analyze_findings()

        # Generate base report data
        report_data = self.generate_report(findings)

        # Format based on requested output format
        if format.lower() == "json":
            return json.dumps(report_data, indent=2, default=str)
        elif format.lower() == "html":
            return self._format_html_report(report_data)
        elif format.lower() == "text":
            return self._format_text_report(report_data)
        elif format.lower() == "markdown" or format.lower() == "md":
            return self._format_markdown_report(report_data)
        else:
            # Default to standard report format
            return report_data

    def _format_text_report(self, report_data: Dict[str, Any]) -> str:
        """
        Format report data as plain text.

        Args:
            report_data: Report data to format

        Returns:
            Plain text report
        """
        lines = []

        # Add header
        lines.append("=" * 80)
        lines.append(f"{report_data['tool']} v{report_data['version']} - Password Assessment Report")
        lines.append("=" * 80)
        lines.append(f"Target: {report_data['target']}")
        lines.append(f"Timestamp: {report_data['timestamp']}")
        lines.append("=" * 80)

        # Add summary
        lines.append("\nSUMMARY:")
        lines.append("-" * 80)
        summary = report_data["summary"]
        lines.append(f"Total Findings: {summary['total_findings']}")
        lines.append(f"  CRITICAL: {summary['critical']}")
        lines.append(f"  HIGH: {summary['high']}")
        lines.append(f"  MEDIUM: {summary['medium']}")
        lines.append(f"  LOW: {summary['low']}")
        lines.append(f"  INFO: {summary['info']}")

        # Add policy strength info
        lines.append(f"\nPassword Policy Strength: {report_data['policy_strength'].upper()}")
        lines.append(f"Policy Score: {report_data['policy_score']}/100")
        lines.append(f"Policy Findings: {report_data['policy_findings']}")
        lines.append(f"Credential Findings: {report_data['credential_findings']}")
        if report_data['weak_accounts'] > 0:
            lines.append(f"Weak Accounts: {report_data['weak_accounts']}")

        # Add category breakdown
        if report_data['policy_by_category']:
            lines.append("\nFindings by Category:")
            for category, count in report_data['policy_by_category'].items():
                lines.append(f"  {category.replace('_', ' ').title()}: {count}")

        # Add findings
        findings = report_data.get("findings", [])
        if findings:
            lines.append("\nFINDINGS:")
            lines.append("-" * 80)

            # Sort findings by severity
            severity_order = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "INFO": 4
            }
            sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "LOW"), 5))

            for i, finding in enumerate(sorted_findings, 1):
                lines.append(f"\n{i}. [{finding.get('severity', 'UNKNOWN')}] {finding.get('title', 'Unnamed Finding')}")
                lines.append(f"   ID: {finding.get('id', 'UNKNOWN')}")
                lines.append(f"   Category: {finding.get('category', 'unknown')}")
                lines.append(f"\n   Description: {finding.get('description', 'No description provided')}")

                # Add details
                if "details" in finding and finding["details"]:
                    lines.append("\n   Details:")
                    for key, value in finding["details"].items():
                        if isinstance(value, list):
                            lines.append(f"     {key.replace('_', ' ').title()}:")
                            for item in value:
                                lines.append(f"       - {item}")
                        else:
                            lines.append(f"     {key.replace('_', ' ').title()}: {value}")

                # Add remediation if available
                if "remediation" in finding and finding["remediation"]:
                    lines.append(f"\n   Remediation: {finding['remediation'].get('description', 'Not provided')}")

                lines.append("-" * 80)

        return "\n".join(lines)

    def _format_html_report(self, report_data: Dict[str, Any]) -> str:
        """
        Format report data as HTML.

        Args:
            report_data: Report data to format

        Returns:
            HTML report
        """
        html = []

        # Start HTML document
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append(f"<title>{report_data['tool']} - Password Assessment Report</title>")

        # Add CSS styling
        html.append("<style>")
        html.append("  body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }")
        html.append("  h1, h2, h3 { color: #333; }")
        html.append("  .header { border-bottom: 2px solid #0078d4; padding-bottom: 10px; }")
        html.append("  .summary { margin: 20px 0; background-color: #f5f5f5; padding: 15px; border-radius: 5px; }")
        html.append("  .summary-box { display: inline-block; margin-right: 20px; text-align: center; }")
        html.append("  .summary-count { font-size: 24px; font-weight: bold; }")
        html.append("  .finding { margin: 20px 0; padding: 15px; border-radius: 5px; border-left: 5px solid #ccc; }")
        html.append("  .critical { border-color: #d13438; background-color: rgba(209, 52, 56, 0.1); }")
        html.append("  .high { border-color: #ff8c00; background-color: rgba(255, 140, 0, 0.1); }")
        html.append("  .medium { border-color: #ffd700; background-color: rgba(255, 215, 0, 0.1); }")
        html.append("  .low { border-color: #107c10; background-color: rgba(16, 124, 16, 0.1); }")
        html.append("  .info { border-color: #0078d4; background-color: rgba(0, 120, 212, 0.1); }")
        html.append("  .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; }")
        html.append("  .critical-bg { background-color: #d13438; }")
        html.append("  .high-bg { background-color: #ff8c00; }")
        html.append("  .medium-bg { background-color: #ffd700; color: #333; }")
        html.append("  .low-bg { background-color: #107c10; }")
        html.append("  .info-bg { background-color: #0078d4; }")
        html.append("  .details { margin-top: 10px; }")
        html.append("  .details dt { font-weight: bold; margin-top: 8px; }")
        html.append("  .details dd { margin-left: 20px; }")
        html.append("</style>")
        html.append("</head>")
        html.append("<body>")

        # Header section
        html.append("<div class='header'>")
        html.append(f"<h1>{report_data['tool']} v{report_data['version']} - Password Assessment Report</h1>")
        html.append(f"<p>Target: <strong>{report_data['target']}</strong></p>")
        html.append(f"<p>Timestamp: {report_data['timestamp']}</p>")
        html.append("</div>")

        # Summary section
        html.append("<div class='summary'>")
        html.append("<h2>Summary</h2>")

        # Policy strength info
        html.append(f"<h3>Password Policy Strength: {report_data['policy_strength'].upper()}</h3>")
        html.append(f"<p>Policy Score: <strong>{report_data['policy_score']}/100</strong></p>")

        # Finding counts
        html.append("<div class='finding-counts'>")
        html.append("<div class='summary-box'>")
        html.append(f"<div class='summary-count'>{report_data['summary']['total_findings']}</div>")
        html.append("<div>Total Findings</div>")
        html.append("</div>")

        for severity, count in [
            ("critical", report_data['summary']['critical']),
            ("high", report_data['summary']['high']),
            ("medium", report_data['summary']['medium']),
            ("low", report_data['summary']['low']),
            ("info", report_data['summary']['info'])
        ]:
            html.append(f"<div class='summary-box'>")
            html.append(f"<div class='summary-count {severity}'>{count}</div>")
            html.append(f"<div>{severity.upper()}</div>")
            html.append("</div>")
        html.append("</div>")

        # Additional stats
        html.append("<div style='margin-top: 20px;'>")
        html.append(f"<p>Policy Findings: {report_data['policy_findings']}</p>")
        html.append(f"<p>Credential Findings: {report_data['credential_findings']}</p>")
        if report_data['weak_accounts'] > 0:
            html.append(f"<p>Weak Accounts: {report_data['weak_accounts']}</p>")
        html.append("</div>")

        # Category breakdown
        if report_data['policy_by_category']:
            html.append("<h3>Findings by Category</h3>")
            html.append("<ul>")
            for category, count in report_data['policy_by_category'].items():
                html.append(f"<li>{category.replace('_', ' ').title()}: {count}</li>")
            html.append("</ul>")

        html.append("</div>") # End summary

        # Findings section
        findings = report_data.get("findings", [])
        if findings:
            html.append("<h2>Findings</h2>")

            # Sort findings by severity
            severity_order = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "INFO": 4
            }
            sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "LOW"), 5))

            for finding in sorted_findings:
                severity = finding.get("severity", "UNKNOWN").lower()
                html.append(f"<div class='finding {severity}'>")

                # Finding header
                html.append("<div style='display: flex; justify-content: space-between;'>")
                html.append(f"<h3>{finding.get('title', 'Unnamed Finding')}</h3>")
                html.append(f"<span class='severity-badge {severity}-bg'>{finding.get('severity', 'UNKNOWN')}</span>")
                html.append("</div>")

                # Finding metadata
                html.append("<div>")
                html.append(f"<strong>ID:</strong> {finding.get('id', 'UNKNOWN')} | ")
                html.append(f"<strong>Category:</strong> {finding.get('category', 'unknown')}")
                html.append("</div>")

                # Finding description
                html.append(f"<p>{finding.get('description', 'No description provided')}</p>")

                # Finding details
                if "details" in finding and finding["details"]:
                    html.append("<div class='details'>")
                    html.append("<h4>Details</h4>")
                    html.append("<dl>")
                    for key, value in finding["details"].items():
                        html.append(f"<dt>{key.replace('_', ' ').title()}</dt>")
                        if isinstance(value, list):
                            html.append("<dd><ul>")
                            for item in value:
                                html.append(f"<li>{item}</li>")
                            html.append("</ul></dd>")
                        else:
                            html.append(f"<dd>{value}</dd>")
                    html.append("</dl>")
                    html.append("</div>")

                # Remediation
                if "remediation" in finding and finding["remediation"]:
                    html.append("<div class='details'>")
                    html.append("<h4>Remediation</h4>")
                    html.append(f"<p>{finding['remediation'].get('description', 'Not provided')}</p>")
                    html.append("</div>")

                html.append("</div>") # End finding

        # End HTML document
        html.append("</body>")
        html.append("</html>")

        return "\n".join(html)

    def _format_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """
        Format report data as Markdown.

        Args:
            report_data: Report data to format

        Returns:
            Markdown report
        """
        lines = []

        # Add header
        lines.append(f"# {report_data['tool']} v{report_data['version']} - Password Assessment Report")
        lines.append("")
        lines.append(f"**Target:** {report_data['target']}  ")
        lines.append(f"**Timestamp:** {report_data['timestamp']}")
        lines.append("")

        # Add summary
        lines.append("## Summary")
        lines.append("")
        summary = report_data["summary"]
        lines.append(f"**Total Findings:** {summary['total_findings']}")
        lines.append(f"- CRITICAL: {summary['critical']}")
        lines.append(f"- HIGH: {summary['high']}")
        lines.append(f"- MEDIUM: {summary['medium']}")
        lines.append(f"- LOW: {summary['low']}")
        lines.append(f"- INFO: {summary['info']}")
        lines.append("")

        # Add policy strength info
        lines.append(f"**Password Policy Strength:** {report_data['policy_strength'].upper()}  ")
        lines.append(f"**Policy Score:** {report_data['policy_score']}/100  ")
        lines.append(f"**Policy Findings:** {report_data['policy_findings']}  ")
        lines.append(f"**Credential Findings:** {report_data['credential_findings']}  ")
        if report_data['weak_accounts'] > 0:
            lines.append(f"**Weak Accounts:** {report_data['weak_accounts']}  ")
        lines.append("")

        # Add category breakdown
        if report_data['policy_by_category']:
            lines.append("### Findings by Category")
            lines.append("")
            for category, count in report_data['policy_by_category'].items():
                lines.append(f"- {category.replace('_', ' ').title()}: {count}")
            lines.append("")

        # Add findings
        findings = report_data.get("findings", [])
        if findings:
            lines.append("## Findings")
            lines.append("")

            # Sort findings by severity
            severity_order = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "INFO": 4
            }
            sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "LOW"), 5))

            for i, finding in enumerate(sorted_findings, 1):
                severity = finding.get("severity", "UNKNOWN")
                lines.append(f"### {i}. [{severity}] {finding.get('title', 'Unnamed Finding')}")
                lines.append("")
                lines.append(f"- **ID:** {finding.get('id', 'UNKNOWN')}")
                lines.append(f"- **Category:** {finding.get('category', 'unknown')}")
                lines.append("")
                lines.append(finding.get('description', 'No description provided'))
                lines.append("")

                # Add details
                if "details" in finding and finding["details"]:
                    lines.append("#### Details")
                    lines.append("")
                    for key, value in finding["details"].items():
                        if isinstance(value, list):
                            lines.append(f"**{key.replace('_', ' ').title()}:**")
                            for item in value:
                                lines.append(f"- {item}")
                        else:
                            lines.append(f"**{key.replace('_', ' ').title()}:** {value}")
                    lines.append("")

                # Add remediation if available
                if "remediation" in finding and finding["remediation"]:
                    lines.append("#### Remediation")
                    lines.append("")
                    lines.append(finding['remediation'].get('description', 'Not provided'))
                lines.append("")
                lines.append("---")
                lines.append("")

        return "\n".join(lines)

def main() -> int:
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Assess password policies and credentials",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Required arguments
    parser.add_argument("--target", required=True, help="Target authentication system to test")

    # Testing options
    parser.add_argument("--policy-only", action="store_true", help="Only test policy configuration, not actual credentials")
    parser.add_argument("--no-default-creds", action="store_false", dest="default_creds", help="Don't test for default credentials")
    parser.add_argument("--dictionary", dest="dictionary_path", help="Path to custom password dictionary")
    parser.add_argument("--no-storage-check", action="store_false", dest="check_storage", help="Skip password storage security checks")
    parser.add_argument("--no-policy-test", action="store_false", dest="policy_test", help="Skip password policy testing")
    parser.add_argument("--no-mfa-check", action="store_false", dest="check_mfa", help="Skip MFA implementation checks")
    parser.add_argument("--no-lockout-check", action="store_false", dest="check_lockout", help="Skip account lockout tests")

    # Lockout parameters
    parser.add_argument("--attempts", type=int, default=5, help="Number of attempts for lockout testing")
    parser.add_argument("--lockout-period", type=int, default=15, help="Expected lockout period in minutes")

    # Compliance and output options
    parser.add_argument("--compliance", dest="compliance_framework", choices=["pci-dss", "nist", "cis"], help="Compliance framework to check against")
    parser.add_argument("--output-format", default=DEFAULT_OUTPUT_FORMAT, choices=["standard", "json", "html", "text", "markdown", "md"], help="Output format for results")
    parser.add_argument("--output-file", help="Output file path")

    args = parser.parse_args()

    # Create target
    target = AssessmentTarget(target_id=args.target, target_type="authentication")

    # Create tester instance
    tester = PasswordStrengthTester(
        target=target,
        policy_only=args.policy_only,
        default_creds=args.default_creds,
        dictionary_path=args.dictionary_path,
        check_storage=args.check_storage,
        policy_test=args.policy_test,
        check_mfa=args.check_mfa,
        check_lockout=args.check_lockout,
        attempts=args.attempts,
        lockout_period=args.lockout_period,
        compliance_framework=args.compliance_framework,
        output_format=args.output_format,
        output_file=args.output_file
    )

    # Initialize the tester
    if not tester.initialize():
        print("Failed to initialize password strength tester", file=sys.stderr)
        return 1

    # Execute the assessment
    if not tester.execute():
        print("Assessment execution failed", file=sys.stderr)
        return 1

    # Get findings
    findings = tester.analyze_findings()

    # Generate report
    report = tester.get_report(args.output_format)

    # Output results
    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(report if isinstance(report, str) else json.dumps(report, indent=2, default=str))
        print(f"Results written to {args.output_file}")
    else:
        # Print to stdout
        if isinstance(report, str):
            print(report)
        else:
            print(json.dumps(report, indent=2, default=str))

    # Determine exit code based on findings
    has_critical = any(f.severity == FindingSeverity.CRITICAL for f in findings)
    has_high = any(f.severity == FindingSeverity.HIGH for f in findings)

    if has_critical:
        return 3  # Exit code 3 for critical issues
    elif has_high:
        return 2  # Exit code 2 for high issues
    elif findings:
        return 1  # Exit code 1 for any issues
    else:
        return 0  # Exit code 0 for no issues

if __name__ == "__main__":
    sys.exit(main())
