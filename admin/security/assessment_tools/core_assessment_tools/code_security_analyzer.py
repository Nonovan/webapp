#!/usr/bin/env python3
"""
Code Security Analyzer

This tool performs static analysis on application code to identify security vulnerabilities.
It detects common security issues, validates coding practices, and scans dependencies for known vulnerabilities.

Features:
- Static code analysis with security focus
- Secure coding practice validation
- Security vulnerability pattern detection
- Dependency scanning for known vulnerabilities
- Language-specific security rule engines
- Custom rule development framework
- SAST/SCA integration capabilities
- Secure code pattern recommendation
"""

import argparse
import json
import logging
import os
import re
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
TOOL_NAME = "Code Security Analyzer"
TOOL_VERSION = "1.0.0"
DEFAULT_OUTPUT_FORMAT = "standard"
DEFAULT_RULESET = "standard"
DEFAULT_LOG_DIR = "logs/code_security_analyzer"

# Language support
SUPPORTED_LANGUAGES = [
    "python", "java", "javascript", "typescript", "csharp", "go",
    "ruby", "php", "swift", "kotlin", "rust", "c", "cpp", "all"
]

# Vulnerability categories
VULN_CATEGORIES = {
    "injection": {"severity": FindingSeverity.HIGH, "impact": 0.8},
    "broken_auth": {"severity": FindingSeverity.HIGH, "impact": 0.8},
    "sensitive_data": {"severity": FindingSeverity.HIGH, "impact": 0.7},
    "xxe": {"severity": FindingSeverity.HIGH, "impact": 0.7},
    "broken_access": {"severity": FindingSeverity.HIGH, "impact": 0.8},
    "security_misconfig": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "xss": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "insecure_deserialization": {"severity": FindingSeverity.HIGH, "impact": 0.7},
    "vulnerable_components": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "insufficient_logging": {"severity": FindingSeverity.MEDIUM, "impact": 0.5},
    "api_security": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "hardcoded_secrets": {"severity": FindingSeverity.HIGH, "impact": 0.8},
    "crypto_issues": {"severity": FindingSeverity.HIGH, "impact": 0.7},
    "insecure_configuration": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
    "insecure_dependencies": {"severity": FindingSeverity.MEDIUM, "impact": 0.7},
    "insecure_communication": {"severity": FindingSeverity.MEDIUM, "impact": 0.6},
}


class CodeSecurityAnalyzer(AssessmentBase):
    """
    Main class for analyzing code security
    """

    def __init__(
        self,
        target: AssessmentTarget,
        language: str = "all",
        ruleset: str = DEFAULT_RULESET,
        scan_dependencies: bool = True,
        custom_rules_path: Optional[str] = None,
        ignore_paths: Optional[List[str]] = None,
        fail_level: str = "high",
        focus_areas: Optional[List[str]] = None,
        assessment_id: Optional[str] = None,
        output_format: str = DEFAULT_OUTPUT_FORMAT,
        output_file: Optional[str] = None,
        evidence_collection: bool = False,
        **kwargs
    ):
        """
        Initialize Code Security Analyzer.

        Args:
            target: Target to assess (path to code)
            language: Programming language to focus on
            ruleset: Security ruleset to apply
            scan_dependencies: Whether to include dependency scanning
            custom_rules_path: Path to custom rules file or directory
            ignore_paths: List of paths to ignore
            fail_level: Severity level to consider as failure
            focus_areas: List of specific security areas to focus on
            assessment_id: Unique assessment identifier
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
            compliance_framework=None,  # Set later if ruleset is a compliance framework
            evidence_collection=evidence_collection,
            non_invasive=True,
            **kwargs
        )

        self.language = language.lower()
        self.ruleset = ruleset
        self.scan_dependencies = scan_dependencies
        self.custom_rules_path = custom_rules_path
        self.ignore_paths = ignore_paths or []
        self.fail_level = fail_level.lower()
        self.focus_areas = focus_areas or []

        # Set compliance framework if ruleset is a compliance framework
        if self.ruleset in ["pci-dss", "hipaa", "gdpr", "owasp-asvs", "nist-800-53"]:
            self.compliance_framework = self.ruleset

        # Storage for analysis results
        self.security_issues = {}
        self.dependency_issues = {}
        self.rules_loaded = 0
        self.files_analyzed = 0
        self.lines_analyzed = 0

        self.logger.info(f"Code security analyzer initialized for target: {target.target_id}")
        self.logger.info(f"Language focus: {language}")
        self.logger.info(f"Using ruleset: {ruleset}")

        if self.focus_areas:
            self.logger.info(f"Focus areas: {', '.join(self.focus_areas)}")

        if self.custom_rules_path:
            self.logger.info(f"Using custom rules from: {self.custom_rules_path}")

    @secure_operation("assessment:execute")
    def initialize(self) -> bool:
        """
        Initialize the assessment by validating inputs and loading rules.

        Returns:
            bool: Whether initialization was successful
        """
        self.logger.info(f"Starting {TOOL_NAME} initialization...")

        try:
            # Create assessment evidence directory if needed
            if self.evidence_collection:
                self.evidence_paths.append(self._create_evidence_directory())

            # Check for required permissions to run this assessment
            if not verify_target_access(self.target, "code_analysis"):
                self.add_error(f"No permission to analyze code at {self.target.target_id}")
                return False

            # Validate language
            if self.language != "all" and self.language not in SUPPORTED_LANGUAGES:
                self.add_error(f"Unsupported language: {self.language}")
                return False

            # Validate target is a valid code repository or directory
            target_path = Path(self.target.target_id)
            if not target_path.exists():
                self.add_error(f"Target path does not exist: {self.target.target_id}")
                return False

            # Load security rules
            success = self._load_security_rules()
            if not success:
                return False

            # Load custom rules if specified
            if self.custom_rules_path:
                success = self._load_custom_rules()
                if not success:
                    self.add_warning(f"Failed to load custom rules from {self.custom_rules_path}")
                    # Continue anyway with default rules

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
        Execute the code security analysis.

        Returns:
            bool: Whether the assessment completed successfully
        """
        if self.status != AssessmentStatus.INITIALIZED:
            self.add_error("Cannot execute assessment: not properly initialized")
            return False

        try:
            self.status = AssessmentStatus.RUNNING
            self.start_time = datetime.now()
            self.logger.info(f"Starting code security analysis for {self.target.target_id}")

            # Collect files to analyze
            files_to_analyze = self._collect_files_to_analyze()
            if not files_to_analyze:
                self.add_warning("No files found to analyze")
                self.status = AssessmentStatus.COMPLETED
                self.end_time = datetime.now()
                return True

            # Analyze each file
            for file_path in files_to_analyze:
                success = self._analyze_file(file_path)
                if not success:
                    self.add_warning(f"Failed to analyze file: {file_path}")
                    # Continue with other files

            # Analyze dependencies if requested
            if self.scan_dependencies:
                self._analyze_dependencies()

            # Apply compliance-specific checks if a framework was specified
            if self.compliance_framework:
                self._apply_compliance_checks()

            self.status = AssessmentStatus.COMPLETED
            self.end_time = datetime.now()
            self.logger.info(f"Code security analysis completed successfully")

            return True

        except Exception as e:
            self.status = AssessmentStatus.FAILED
            self.logger.exception(f"Error during code security analysis: {str(e)}")
            self.add_error(f"Assessment failed with error: {str(e)}")
            return False

    def analyze_findings(self) -> List[Finding]:
        """
        Analyze assessment results to produce findings.

        Returns:
            List of findings from the assessment
        """
        findings = []

        # Process code security findings
        for category, issues in self.security_issues.items():
            if not issues:
                continue

            # Skip categories that are not in focus areas if focus areas are specified
            if self.focus_areas and category not in self.focus_areas:
                continue

            for issue in issues:
                severity = issue.get("severity", VULN_CATEGORIES.get(category, {}).get("severity", FindingSeverity.MEDIUM))

                # Create remediation guidance
                remediation = Remediation(
                    description=issue.get("remediation", "Review and fix the identified security issue."),
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
                    affected_resource=issue.get("file_path", self.target.target_id),
                    remediation=remediation,
                    evidence=self._collect_finding_evidence(issue) if self.evidence_collection else None,
                    references=issue.get("references", []),
                    cvss=self._calculate_cvss_vector(category, severity) if severity != FindingSeverity.INFO else None,
                    compliance_impacts=issue.get("compliance_impacts", []),
                    details={
                        "line": issue.get("line"),
                        "column": issue.get("column"),
                        "code_snippet": issue.get("code_snippet"),
                        "rule_id": issue.get("rule_id"),
                        "rule_name": issue.get("rule_name"),
                        "language": issue.get("language"),
                        "confidence": issue.get("confidence", "medium")
                    }
                )

                findings.append(finding)

        # Process dependency findings
        if self.scan_dependencies:
            for dep_name, dep_issues in self.dependency_issues.items():
                for issue in dep_issues:
                    severity = issue.get("severity", FindingSeverity.MEDIUM)

                    # Create remediation guidance
                    remediation = Remediation(
                        description=f"Update {dep_name} to a secure version.",
                        steps=[
                            f"Update {dep_name} from version {issue.get('current_version')} to {issue.get('recommended_version', 'latest secure version')}",
                            "Run comprehensive tests to ensure compatibility",
                            "Deploy the updated version"
                        ],
                        resources=[
                            issue.get("advisory_url", ""),
                            f"https://nvd.nist.gov/vuln/detail/{issue.get('cve_id')}" if issue.get("cve_id") else ""
                        ],
                        effort="medium",
                    )

                    # Create finding
                    finding = Finding(
                        title=f"Vulnerable dependency: {dep_name}",
                        description=issue.get("description", f"The dependency {dep_name} has known security vulnerabilities."),
                        severity=severity,
                        category="vulnerable_components",
                        affected_resource=f"{self.target.target_id}/dependencies/{dep_name}",
                        remediation=remediation,
                        evidence=None,  # No specific evidence for dependencies
                        references=issue.get("references", []),
                        cvss=issue.get("cvss_vector", ""),
                        compliance_impacts=issue.get("compliance_impacts", []),
                        details={
                            "dependency_name": dep_name,
                            "current_version": issue.get("current_version", "unknown"),
                            "vulnerable_versions": issue.get("vulnerable_versions", "all"),
                            "cve_id": issue.get("cve_id", ""),
                            "advisory_url": issue.get("advisory_url", ""),
                            "recommended_version": issue.get("recommended_version", "latest")
                        }
                    )

                    findings.append(finding)

        self.logger.info(f"Generated {len(findings)} findings from code security analysis")
        return findings

    def _create_evidence_directory(self) -> str:
        """
        Create directory for storing evidence.

        Returns:
            Path to the evidence directory
        """
        evidence_dir = os.path.join(
            "evidence",
            "code_security",
            os.path.basename(self.target.target_id),
            self.assessment_id,
            datetime.now().strftime("%Y%m%d_%H%M%S")
        )

        os.makedirs(evidence_dir, exist_ok=True)
        self.logger.info(f"Created evidence directory: {evidence_dir}")

        return evidence_dir

    def _load_security_rules(self) -> bool:
        """
        Load security rules based on selected ruleset.

        Returns:
            bool: Whether rules were loaded successfully
        """
        ruleset_map = {
            "standard": "standard_rules.json",
            "owasp-top-10": "owasp_top_10.json",
            "cwe-top-25": "cwe_top_25.json",
            "pci-dss": "pci_dss_rules.json",
            "hipaa": "hipaa_rules.json",
            "gdpr": "gdpr_rules.json",
            "owasp-asvs": "owasp_asvs.json",
            "nist-800-53": "nist_800_53.json"
        }

        if self.ruleset not in ruleset_map:
            self.add_error(f"Unknown ruleset: {self.ruleset}")
            return False

        ruleset_filename = ruleset_map[self.ruleset]
        rules_path = Path(parent_dir) / "config_files" / "custom_rules" / ruleset_filename

        try:
            # Check for ruleset existence
            if not rules_path.exists():
                # Try standard rules as fallback
                fallback_path = Path(parent_dir) / "config_files" / "custom_rules" / "standard_rules.json"
                if fallback_path.exists():
                    self.logger.warning(f"Ruleset {self.ruleset} not found, using standard rules")
                    rules_path = fallback_path
                else:
                    self.add_error(f"Security rules for '{self.ruleset}' not found")
                    return False

            # Load rules data
            with open(rules_path, 'r') as f:
                self.rules_data = json.load(f)

            # Count rules for each language
            language_count = {}
            for rule in self.rules_data.get("rules", []):
                lang = rule.get("language", "all")
                language_count[lang] = language_count.get(lang, 0) + 1

            self.rules_loaded = sum(language_count.values())
            self.logger.info(f"Loaded {self.rules_loaded} security rules from {rules_path}")

            for lang, count in language_count.items():
                if lang == "all" or (self.language == "all" or lang == self.language):
                    self.logger.info(f"  - {count} rules for {lang}")

            return True

        except json.JSONDecodeError as e:
            self.add_error(f"Invalid ruleset format: {str(e)}")
            self.logger.error(f"Failed to parse ruleset JSON: {str(e)}")
            return False

        except Exception as e:
            self.add_error(f"Failed to load security rules: {str(e)}")
            self.logger.error(f"Error loading rules: {str(e)}")
            return False

    def _load_custom_rules(self) -> bool:
        """
        Load custom security rules.

        Returns:
            bool: Whether custom rules were loaded successfully
        """
        try:
            # Validate path existence
            custom_path = Path(self.custom_rules_path)
            if not custom_path.exists():
                self.add_error(f"Custom rules path does not exist: {self.custom_rules_path}")
                return False

            # Load custom rules from file or directory
            if custom_path.is_file():
                with open(custom_path, 'r') as f:
                    custom_rules = json.load(f)

                    # Merge with existing rules
                    if "rules" in custom_rules:
                        new_rules = custom_rules["rules"]
                        self.rules_data["rules"].extend(new_rules)
                        self.logger.info(f"Loaded {len(new_rules)} custom rules from {custom_path}")
                        return True
                    else:
                        self.add_warning(f"No rules found in custom rules file: {custom_path}")
                        return False

            elif custom_path.is_dir():
                # Process all JSON files in directory
                rule_count = 0
                for file_path in custom_path.glob("*.json"):
                    with open(file_path, 'r') as f:
                        custom_rules = json.load(f)

                        if "rules" in custom_rules:
                            new_rules = custom_rules["rules"]
                            self.rules_data["rules"].extend(new_rules)
                            rule_count += len(new_rules)

                if rule_count > 0:
                    self.logger.info(f"Loaded {rule_count} custom rules from {custom_path}")
                    return True
                else:
                    self.add_warning(f"No rules found in custom rules directory: {custom_path}")
                    return False

            else:
                self.add_error(f"Custom rules path is neither a file nor directory: {custom_path}")
                return False

        except json.JSONDecodeError as e:
            self.add_error(f"Invalid custom rules format: {str(e)}")
            return False

        except Exception as e:
            self.add_error(f"Failed to load custom rules: {str(e)}")
            return False

    def _collect_files_to_analyze(self) -> List[str]:
        """
        Collect all files to be analyzed.

        Returns:
            List of file paths to analyze
        """
        target_path = Path(self.target.target_id)
        files_to_analyze = []

        # Define file extensions to analyze based on language
        extensions = self._get_extensions_for_language(self.language)

        # Function to check if a path should be ignored
        def should_ignore(path):
            # Convert to string for comparison
            path_str = str(path)

            # Check against ignore paths
            for ignore in self.ignore_paths:
                if ignore in path_str:
                    return True

            # Common dirs to ignore
            ignore_dirs = ['.git', 'node_modules', '__pycache__', 'venv', 'env', '.venv',
                          '.env', 'dist', 'build', 'target', 'out']
            for part in path.parts:
                if part in ignore_dirs:
                    return True

            return False

        # Collect files (recursively if target is a directory)
        if target_path.is_file():
            if not should_ignore(target_path) and self._is_supported_file(target_path, extensions):
                files_to_analyze.append(str(target_path))
        else:
            for root, dirs, files in os.walk(target_path):
                # Filter out ignored directories
                dirs[:] = [d for d in dirs if not should_ignore(Path(root) / d)]

                for file in files:
                    file_path = Path(root) / file
                    if not should_ignore(file_path) and self._is_supported_file(file_path, extensions):
                        files_to_analyze.append(str(file_path))

        self.logger.info(f"Found {len(files_to_analyze)} files to analyze")
        return files_to_analyze

    def _get_extensions_for_language(self, language: str) -> List[str]:
        """
        Get file extensions to analyze based on language.

        Args:
            language: Programming language

        Returns:
            List of file extensions
        """
        language_ext_map = {
            "python": ['.py'],
            "java": ['.java', '.jsp', '.jspx'],
            "javascript": ['.js', '.jsx', '.mjs'],
            "typescript": ['.ts', '.tsx'],
            "csharp": ['.cs', '.cshtml', '.razor'],
            "go": ['.go'],
            "ruby": ['.rb', '.erb'],
            "php": ['.php', '.phtml'],
            "swift": ['.swift'],
            "kotlin": ['.kt', '.kts'],
            "rust": ['.rs'],
            "c": ['.c', '.h'],
            "cpp": ['.cpp', '.cc', '.cxx', '.hpp', '.hxx', '.h']
        }

        if language == "all":
            # Combine all extensions
            all_extensions = []
            for exts in language_ext_map.values():
                all_extensions.extend(exts)
            return all_extensions
        else:
            return language_ext_map.get(language, [])

    def _is_supported_file(self, file_path: Path, extensions: List[str]) -> bool:
        """
        Check if the file is supported for analysis.

        Args:
            file_path: Path to file
            extensions: List of supported extensions

        Returns:
            Whether the file is supported
        """
        # Check extension
        if extensions and file_path.suffix not in extensions:
            return False

        # Skip very large files
        try:
            if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10 MB
                self.logger.warning(f"Skipping large file: {file_path}")
                return False
        except Exception:
            return False

        return True

    def _analyze_file(self, file_path: str) -> bool:
        """
        Analyze a single file for security issues.

        Args:
            file_path: Path to file

        Returns:
            Whether analysis was successful
        """
        try:
            self.logger.debug(f"Analyzing file: {file_path}")

            # Determine language from file extension
            language = self._determine_language(file_path)

            # Read file content
            with open(file_path, 'r', errors='replace') as f:
                content = f.read()
                lines = content.split('\n')
                self.files_analyzed += 1
                self.lines_analyzed += len(lines)

            # Apply security rules
            self._apply_security_rules(file_path, language, lines)

            # Look for hardcoded secrets
            self._check_for_hardcoded_secrets(file_path, language, lines)

            # Save file evidence if requested
            if self.evidence_collection:
                self._collect_file_evidence(file_path, language)

            return True

        except Exception as e:
            self.logger.warning(f"Error analyzing file {file_path}: {str(e)}")
            return False

    def _determine_language(self, file_path: str) -> str:
        """
        Determine language from file extension.

        Args:
            file_path: Path to file

        Returns:
            Language identifier
        """
        extension = os.path.splitext(file_path)[1].lower()

        extension_map = {
            '.py': 'python',
            '.java': 'java',
            '.jsp': 'java',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.cs': 'csharp',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.kts': 'kotlin',
            '.rs': 'rust',
            '.c': 'c',
            '.h': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.hpp': 'cpp'
        }

        return extension_map.get(extension, 'unknown')

    def _apply_security_rules(self, file_path: str, language: str, lines: List[str]) -> None:
        """
        Apply security rules to file content.

        Args:
            file_path: Path to file
            language: Language identifier
            lines: File content as lines
        """
        for rule in self.rules_data.get("rules", []):
            rule_language = rule.get("language", "all")

            # Skip rules for other languages
            if rule_language != "all" and rule_language != language:
                continue

            # Get rule metadata
            rule_id = rule.get("id", "unknown")
            rule_name = rule.get("name", "Unknown rule")
            rule_category = rule.get("category", "security_misconfig")
            rule_severity = rule.get("severity", "medium").upper()

            # Skip if not in focus areas
            if self.focus_areas and rule_category not in self.focus_areas:
                continue

            # Get patterns
            patterns = rule.get("patterns", [])
            negative_patterns = rule.get("negative_patterns", [])

            # Check each line for patterns
            for line_num, line in enumerate(lines, 1):
                # Skip if line is empty or comment
                if not line.strip() or self._is_comment_line(line, language):
                    continue

                # Check if line matches any pattern
                for pattern in patterns:
                    if pattern in line:
                        # Check if line also matches any negative pattern (false positive filter)
                        is_false_positive = False
                        for neg_pattern in negative_patterns:
                            if neg_pattern in line:
                                is_false_positive = True
                                break

                        if not is_false_positive:
                            # Extract code snippet
                            start = max(0, line_num - 2)
                            end = min(len(lines), line_num + 1)
                            code_snippet = "\n".join(lines[start:end])

                            # Add finding
                            issue = {
                                "title": rule_name,
                                "description": rule.get("description", "Security issue detected."),
                                "severity": FindingSeverity[rule_severity] if hasattr(FindingSeverity, rule_severity) else FindingSeverity.MEDIUM,
                                "file_path": file_path,
                                "line": line_num,
                                "column": line.find(pattern) + 1,
                                "code_snippet": code_snippet,
                                "rule_id": rule_id,
                                "rule_name": rule_name,
                                "language": language,
                                "pattern": pattern,
                                "confidence": rule.get("confidence", "medium"),
                                "remediation": rule.get("remediation", "Fix the identified security issue."),
                                "remediation_steps": rule.get("remediation_steps", []),
                                "references": rule.get("references", []),
                                "compliance_impacts": rule.get("compliance_impacts", [])
                            }

                            # Add to issues by category
                            if rule_category not in self.security_issues:
                                self.security_issues[rule_category] = []

                            self.security_issues[rule_category].append(issue)

                            # Log the finding
                            self.logger.info(f"Found {rule_severity} security issue in {file_path}:{line_num}: {rule_name}")

    def _is_comment_line(self, line: str, language: str) -> bool:
        """
        Check if line is a comment.

        Args:
            line: Line of code
            language: Language identifier

        Returns:
            Whether the line is a comment
        """
        line = line.strip()

        # Language-specific comment detection
        if language == "python":
            return line.startswith("#")
        elif language in ["javascript", "typescript", "java", "csharp", "cpp", "c", "go", "swift", "kotlin", "rust"]:
            return line.startswith("//") or line.startswith("/*")
        elif language == "ruby":
            return line.startswith("#")
        elif language == "php":
            return line.startswith("//") or line.startswith("#") or line.startswith("/*")

        # Default
        return False

    def _check_for_hardcoded_secrets(self, file_path: str, language: str, lines: List[str]) -> None:
        """
        Check for hardcoded secrets in file.

        Args:
            file_path: Path to file
            language: Language identifier
            lines: File content as lines
        """
        # Patterns for common hardcoded secrets
        secret_patterns = [
            (r"password\s*=\s*['\"](?!.*\$\{).*['\"]", "password assignment"),
            (r"api_?key\s*=\s*['\"].*['\"]", "API key"),
            (r"secret\s*=\s*['\"].*['\"]", "secret"),
            (r"token\s*=\s*['\"].*['\"]", "token"),
            (r"access_?key\s*=\s*['\"].*['\"]", "access key"),
            (r"credential\s*=\s*['\"].*['\"]", "credential"),
            (r"-----BEGIN PRIVATE KEY-----", "private key"),
            (r"-----BEGIN RSA PRIVATE KEY-----", "RSA private key"),
            (r"-----BEGIN OPENSSH PRIVATE KEY-----", "SSH private key"),
        ]

        # Check each line for secret patterns
        import re
        for line_num, line in enumerate(lines, 1):
            # Skip if line is empty or comment
            if not line.strip() or self._is_comment_line(line, language):
                continue

            for pattern, secret_type in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check for environment variables or config references
                    # These are generally safe practices
                    if re.search(r"process\.env|os\.environ|\$\{|%\(|config\.", line, re.IGNORECASE):
                        continue

                    # Extract code snippet
                    start = max(0, line_num - 1)
                    end = min(len(lines), line_num + 1)
                    code_snippet = "\n".join(lines[start:end])

                    # Add finding
                    issue = {
                        "title": f"Hardcoded {secret_type}",
                        "description": f"Hardcoded {secret_type} found in source code. Credentials should not be stored in source code.",
                        "severity": FindingSeverity.HIGH,
                        "file_path": file_path,
                        "line": line_num,
                        "column": 1,  # We don't know exact position
                        "code_snippet": code_snippet,
                        "rule_id": "HARDCODED_SECRET",
                        "rule_name": "Hardcoded Secret Detection",
                        "language": language,
                        "pattern": pattern,
                        "confidence": "high",
                        "remediation": "Move the secret to a secure configuration management system or environment variables.",
                        "remediation_steps": [
                            "Remove the hardcoded secret from source code",
                            "Use environment variables, secure vaults, or configuration services",
                            "Ensure the actual secret is not committed to version control",
                            "Consider rotating the compromised secret"
                        ],
                        "references": [
                            "https://owasp.org/www-community/vulnerabilities/Hardcoded_Credentials"
                        ],
                        "compliance_impacts": ["pci-dss", "hipaa", "gdpr", "nist-800-53"]
                    }

                    # Add to issues by category
                    category = "hardcoded_secrets"
                    if category not in self.security_issues:
                        self.security_issues[category] = []

                    self.security_issues[category].append(issue)

                    # Log the finding
                    self.logger.warning(f"Found hardcoded {secret_type} in {file_path}:{line_num}")

    def _analyze_dependencies(self) -> None:
        """
        Analyze dependencies for security vulnerabilities.
        """
        self.logger.info("Scanning dependencies for vulnerabilities")

        # Detect project type based on dependency files
        dependency_files = self._detect_dependency_files()
        if not dependency_files:
            self.logger.info("No dependency files found, skipping dependency scan")
            return

        for dep_file in dependency_files:
            self.logger.info(f"Analyzing dependencies in {dep_file}")

            # Parse dependencies based on file type
            if os.path.basename(dep_file) == "requirements.txt":
                self._analyze_python_dependencies(dep_file)
            elif os.path.basename(dep_file) in ["package.json", "package-lock.json"]:
                self._analyze_npm_dependencies(dep_file)
            elif os.path.basename(dep_file) == "pom.xml":
                self._analyze_maven_dependencies(dep_file)
            elif os.path.basename(dep_file) == "build.gradle":
                self._analyze_gradle_dependencies(dep_file)
            elif os.path.basename(dep_file) == "Gemfile" or os.path.basename(dep_file) == "Gemfile.lock":
                self._analyze_ruby_dependencies(dep_file)
            elif os.path.basename(dep_file) == "composer.json" or os.path.basename(dep_file) == "composer.lock":
                self._analyze_php_dependencies(dep_file)
            else:
                self.logger.info(f"Unsupported dependency file format: {dep_file}")

    def _detect_dependency_files(self) -> List[str]:
        """
        Detect dependency files in the project.

        Returns:
            List of dependency file paths
        """
        target_path = Path(self.target.target_id)
        dependency_files = []

        # Common dependency file patterns
        dependency_patterns = [
            "requirements.txt",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pom.xml",
            "build.gradle",
            "Gemfile",
            "Gemfile.lock",
            "composer.json",
            "composer.lock",
            "go.mod"
        ]

        # If target is a directory, search for dependency files
        if target_path.is_dir():
            for pattern in dependency_patterns:
                for path in target_path.glob(f"**/{pattern}"):
                    # Don't scan dependency files in node_modules, vendor, etc.
                    if not any(ignore_dir in str(path) for ignore_dir in ['node_modules', 'vendor', '.git', 'venv', 'env']):
                        dependency_files.append(str(path))

        return dependency_files

    def _analyze_python_dependencies(self, file_path: str) -> None:
        """
        Analyze Python dependencies in requirements.txt.

        Args:
            file_path: Path to requirements.txt
        """
        try:
            # Read requirements file
            with open(file_path, 'r') as f:
                requirements = f.readlines()

            # Parse dependencies
            for req in requirements:
                # Skip comments and empty lines
                req = req.strip()
                if not req or req.startswith('#'):
                    continue

                # Parse package name and version
                parts = req.split('==')
                if len(parts) == 2:
                    package_name = parts[0].strip()
                    version = parts[1].strip()
                else:
                    # Handle other formats like >=, <=, etc.
                    for op in ['>=', '<=', '>', '<', '~=', '!=']:
                        if op in req:
                            parts = req.split(op)
                            package_name = parts[0].strip()
                            version = parts[1].strip()
                            break
                    else:
                        # No version specified
                        package_name = req.split('[')[0].strip()  # Handle extras like package[extra]
                        version = "latest"

                # Check for known vulnerabilities
                # In a real implementation, this would query vulnerability databases or APIs
                self._check_dependency_vulnerability(package_name, version, "python")

        except Exception as e:
            self.logger.warning(f"Error analyzing Python dependencies: {str(e)}")

    def _analyze_npm_dependencies(self, file_path: str) -> None:
        """
        Analyze npm dependencies in package.json or package-lock.json.

        Args:
            file_path: Path to package.json or package-lock.json
        """
        try:
            # Read package file
            with open(file_path, 'r') as f:
                package_data = json.load(f)

            # Parse dependencies from different sections
            dependency_sections = ['dependencies', 'devDependencies']

            for section in dependency_sections:
                if section in package_data:
                    for package_name, version in package_data[section].items():
                        # Clean up version string
                        if isinstance(version, str):
                            # Remove version range operators
                            for op in ['^', '~', '>=', '<=', '>', '<']:
                                version = version.replace(op, '')
                            version = version.strip()
                        elif isinstance(version, dict) and 'version' in version:
                            # Handle package-lock.json format
                            version = version['version']
                        else:
                            version = "unknown"

                        # Check for known vulnerabilities
                        self._check_dependency_vulnerability(package_name, version, "javascript")

        except Exception as e:
            self.logger.warning(f"Error analyzing npm dependencies: {str(e)}")

    def _analyze_maven_dependencies(self, file_path: str) -> None:
        """
        Analyze Maven dependencies in pom.xml.

        Args:
            file_path: Path to pom.xml
        """
        # Simplified version - in a real implementation this would use a proper XML parser
        try:
            # Read POM file
            with open(file_path, 'r') as f:
                pom_content = f.read()

            # Simple regex-based extraction of dependencies
            import re

            # Find dependency elements
            dependency_pattern = re.compile(r'<dependency>.*?</dependency>', re.DOTALL)
            dependencies = dependency_pattern.findall(pom_content)

            for dep in dependencies:
                # Extract group ID, artifact ID and version
                group_id = re.search(r'<groupId>(.*?)</groupId>', dep)
                artifact_id = re.search(r'<artifactId>(.*?)</artifactId>', dep)
                version = re.search(r'<version>(.*?)</version>', dep)

                if group_id and artifact_id:
                    group_id = group_id.group(1).strip()
                    artifact_id = artifact_id.group(1).strip()
                    version_str = version.group(1).strip() if version else "latest"

                    # Check for known vulnerabilities
                    package_name = f"{group_id}:{artifact_id}"
                    self._check_dependency_vulnerability(package_name, version_str, "java")

        except Exception as e:
            self.logger.warning(f"Error analyzing Maven dependencies: {str(e)}")

    def _analyze_gradle_dependencies(self, file_path: str) -> None:
        """
        Analyze Gradle dependencies in build.gradle.

        Args:
            file_path: Path to build.gradle
        """
        # Simplified version - in a real implementation this would use a proper Gradle parser
        try:
            # Read build.gradle file
            with open(file_path, 'r') as f:
                gradle_content = f.read()

            # Simple regex-based extraction of dependencies
            import re

            # Find dependency declarations
            dependency_pattern = re.compile(r'(implementation|api|compile|runtime|testImplementation)\s+[\'"]([^:\'"]*)(?::([^:\'"]*))?(?::([^\'"]*))?(:[^\'"]*)?[\'"]')
            dependencies = dependency_pattern.findall(gradle_content)

            for dep_type, group_id, artifact_id, version, _ in dependencies:
                if group_id and artifact_id:
                    # Check for known vulnerabilities
                    package_name = f"{group_id}:{artifact_id}"
                    self._check_dependency_vulnerability(package_name, version or "latest", "java")

        except Exception as e:
            self.logger.warning(f"Error analyzing Gradle dependencies: {str(e)}")

    def _analyze_ruby_dependencies(self, file_path: str) -> None:
        """
        Analyze Ruby dependencies in Gemfile or Gemfile.lock.

        Args:
            file_path: Path to Gemfile or Gemfile.lock
        """
        try:
            # Read Gemfile
            with open(file_path, 'r') as f:
                gemfile_content = f.readlines()

            # Parse gem declarations from Gemfile
            if os.path.basename(file_path) == "Gemfile":
                for line in gemfile_content:
                    line = line.strip()
                    if line.startswith('gem '):
                        # Extract gem name and version
                        parts = line.split(',')
                        gem_name = parts[0].replace('gem', '').replace("'", '').replace('"', '').strip()

                        version = "latest"
                        for part in parts[1:]:
                            if "=>" in part or ">=" in part or "~>" in part:
                                version_match = re.search(r'[\'"]([^\'"]+)[\'"]', part)
                                if version_match:
                                    version = version_match.group(1)
                                    break

                        # Check for known vulnerabilities
                        self._check_dependency_vulnerability(gem_name, version, "ruby")

            # Parse from Gemfile.lock (more accurate)
            elif os.path.basename(file_path) == "Gemfile.lock":
                in_gems_section = False
                for line in gemfile_content:
                    line = line.strip()

                    if line == "GEM":
                        in_gems_section = True
                    elif line.startswith("  ") and in_gems_section:
                        # Extract gem name and version
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            gem_name = parts[0]
                            version = parts[1].replace('(', '').replace(')', '')

                            # Check for known vulnerabilities
                            self._check_dependency_vulnerability(gem_name, version, "ruby")
                    elif not line.startswith("  ") and in_gems_section:
                        in_gems_section = False

        except Exception as e:
            self.logger.warning(f"Error analyzing Ruby dependencies: {str(e)}")

    def _analyze_php_dependencies(self, file_path: str) -> None:
        """
        Analyze PHP dependencies in composer.json or composer.lock.

        Args:
            file_path: Path to composer.json or composer.lock
        """
        try:
            # Read composer file
            with open(file_path, 'r') as f:
                composer_data = json.load(f)

            # Parse from composer.json
            if os.path.basename(file_path) == "composer.json":
                for section in ['require', 'require-dev']:
                    if section in composer_data:
                        for package_name, version in composer_data[section].items():
                            # Clean up version string
                            version = version.replace('^', '').replace('~', '').strip()

                            # Check for known vulnerabilities
                            self._check_dependency_vulnerability(package_name, version, "php")

            # Parse from composer.lock (more accurate)
            elif os.path.basename(file_path) == "composer.lock":
                for section in ['packages', 'packages-dev']:
                    if section in composer_data:
                        for package in composer_data[section]:
                            if 'name' in package and 'version' in package:
                                # Check for known vulnerabilities
                                self._check_dependency_vulnerability(package['name'], package['version'], "php")

        except Exception as e:
            self.logger.warning(f"Error analyzing PHP dependencies: {str(e)}")

    def _check_dependency_vulnerability(self, package_name: str, version: str, ecosystem: str) -> None:
        """
        Check dependency for known vulnerabilities.

        In a real implementation, this would query vulnerability databases or APIs.
        For demonstration purposes, we're using a simplified approach with a few hardcoded examples.

        Args:
            package_name: Name of package
            version: Package version
            ecosystem: Package ecosystem (python, javascript, java, etc.)
        """
        # Known vulnerable packages (example)
        known_vulnerabilities = {
            "python": {
                "django": {
                    "affected_versions": ["<3.2.5", "<2.2.24"],
                    "cve_id": "CVE-2021-33203",
                    "description": "URL resolver vulnerability allowing attackers to bypass middleware protections",
                    "remediation": ">=3.2.5",
                },
                "requests": {
                    "affected_versions": ["<2.20.0"],
                    "cve_id": "CVE-2018-18074",
                    "description": "CRLF injection vulnerability",
                    "remediation": ">=2.20.0",
                }
            },
            "javascript": {
                "lodash": {
                    "affected_versions": ["<4.17.21"],
                    "cve_id": "CVE-2021-23337",
                    "description": "Command injection vulnerability in zipObjectDeep function",
                    "remediation": ">=4.17.21",
                },
                "axios": {
                    "affected_versions": ["<0.21.1"],
                    "cve_id": "CVE-2020-28168",
                    "description": "Server-side request forgery vulnerability",
                    "remediation": ">=0.21.1",
                }
            }
        }

        # Check if package is in known vulnerabilities list for its ecosystem
        if ecosystem in known_vulnerabilities and package_name in known_vulnerabilities[ecosystem]:
            vuln_info = known_vulnerabilities[ecosystem][package_name]

            # Simple version comparison (real implementation would use proper version comparison)
            is_vulnerable = False
            for affected_version_pattern in vuln_info["affected_versions"]:
                if affected_version_pattern.startswith("<"):
                    # Vulnerable if version is less than specified version
                    vulnerable_version = affected_version_pattern[1:]
                    if self._compare_versions(version, vulnerable_version) < 0:
                        is_vulnerable = True
                        break

            if is_vulnerable:
                # Add vulnerability finding
                if package_name not in self.dependency_issues:
                    self.dependency_issues[package_name] = []

                self.dependency_issues[package_name].append({
                    "current_version": version,
                    "vulnerable_versions": ", ".join(vuln_info["affected_versions"]),
                    "recommended_version": vuln_info.get("remediation", "latest"),
                    "cve_id": vuln_info.get("cve_id", ""),
                    "description": vuln_info.get("description", "Known security vulnerability"),
                    "severity": FindingSeverity.HIGH,
                    "ecosystem": ecosystem,
                    "references": [
                        f"https://nvd.nist.gov/vuln/detail/{vuln_info.get('cve_id')}" if vuln_info.get("cve_id") else ""
                    ],
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # Example vector
                })

                self.logger.warning(f"Found vulnerable dependency: {package_name} {version} ({vuln_info.get('cve_id', 'no CVE')})")

    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Simple version comparison.

        Args:
            version1: First version string
            version2: Second version string

        Returns:
            -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            # Convert version strings to lists of integers
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]

            # Pad with zeros to make equal length
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)

            # Compare parts
            for i in range(len(v1_parts)):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1

            return 0
        except:
            # If we can't parse the versions, just do string comparison
            if version1 < version2:
                return -1
            elif version1 > version2:
                return 1
            else:
                return 0

    def _apply_compliance_checks(self) -> None:
        """
        Apply additional compliance-specific checks.
        """
        self.logger.info(f"Applying {self.compliance_framework} compliance checks")

        # Special compliance-specific checks could be applied here
        # For now, we just add compliance information to findings

        # For findings that didn't have compliance impacts set by rules
        for category, issues in self.security_issues.items():
            for issue in issues:
                if not issue.get("compliance_impacts"):
                    issue["compliance_impacts"] = [self.compliance_framework]

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

        file_path = issue.get("file_path", "")
        if not file_path:
            return None

        # Create unique filename for evidence
        base_filename = os.path.basename(file_path)
        line_num = issue.get("line", 0)
        rule_id = issue.get("rule_id", "unknown")
        evidence_filename = f"{base_filename}_line{line_num}_{rule_id}.json"
        evidence_path = os.path.join(self.evidence_paths[0], evidence_filename)

        try:
            # Save issue details to evidence file
            with open(evidence_path, 'w') as f:
                # Create an evidence copy with code snippet
                evidence_data = {
                    "issue": issue,
                    "code_snippet": issue.get("code_snippet", ""),
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "rule_id": rule_id
                }
                json.dump(evidence_data, f, indent=2)

            # Return Evidence object
            return Evidence(
                path=evidence_path,
                description=f"Code security finding evidence for {issue.get('rule_name', 'unknown rule')}",
                source=file_path,
                type="code_security_finding",
                timestamp=datetime.now().isoformat(),
                hash_algorithm="SHA-256",
                hash_value=self._calculate_file_hash(evidence_path)
            )
        except Exception as e:
            self.logger.warning(f"Failed to save finding evidence: {str(e)}")
            return None

    def _collect_file_evidence(self, file_path: str, language: str) -> None:
        """
        Collect file evidence.

        Args:
            file_path: Path to file
            language: Language identifier
        """
        if not self.evidence_collection or not self.evidence_paths:
            return

        # Only collect evidence for files with findings
        file_has_issues = False
        for issues in self.security_issues.values():
            for issue in issues:
                if issue.get("file_path") == file_path:
                    file_has_issues = True
                    break
            if file_has_issues:
                break

        if not file_has_issues:
            return

        try:
            # Create sanitized filename for evidence
            safe_filename = os.path.basename(file_path).replace(" ", "_")
            evidence_path = os.path.join(self.evidence_paths[0], f"source_{safe_filename}")

            # Copy file to evidence directory
            import shutil
            shutil.copy2(file_path, evidence_path)

            # Add evidence
            evidence = Evidence(
                path=evidence_path,
                description=f"Source code file with security issues ({language})",
                source=file_path,
                type="source_code",
                timestamp=datetime.now().isoformat(),
                hash_algorithm="SHA-256",
                hash_value=self._calculate_file_hash(evidence_path)
            )

            self.add_evidence(evidence_path)
            self.logger.debug(f"Collected evidence for file: {file_path}")

        except Exception as e:
            self.logger.warning(f"Failed to collect file evidence: {str(e)}")

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
        if category == "injection":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # Remote code execution
            else:
                return "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"  # Less severe injection

        elif category == "broken_auth":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"  # Authentication bypass
            else:
                return "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"  # Less severe auth issues

        elif category == "sensitive_data":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # Data exposure
            else:
                return "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"  # Local data exposure

        elif category == "xss":
            if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"  # Stored XSS
            else:
                return "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"  # Reflected XSS

        elif category == "hardcoded_secrets":
            return "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"  # Local access, high confidentiality

        elif category == "crypto_issues":
            return "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # Network access, high complexity, high confidentiality

        elif category == "insecure_dependencies":
            return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # Use default values for known vulnerabilities

        # Default based on severity
        return vectors.get(severity, vectors[FindingSeverity.MEDIUM])


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} - Analyzes code for security vulnerabilities.")

    # Required parameters
    parser.add_argument("--target", required=True, help="Target code repository or path")

    # Analysis options
    parser.add_argument("--language", default="all", choices=SUPPORTED_LANGUAGES,
                       help="Programming language to focus on")
    parser.add_argument("--ruleset", default=DEFAULT_RULESET,
                       help="Security ruleset to apply (standard, owasp-top-10, cwe-top-25, pci-dss, etc.)")
    parser.add_argument("--scan-dependencies", action="store_true", default=True,
                       help="Include dependency scanning")
    parser.add_argument("--no-scan-dependencies", dest="scan_dependencies", action="store_false",
                       help="Skip dependency scanning")
    parser.add_argument("--custom-rules", dest="custom_rules_path",
                       help="Path to custom rules file or directory")
    parser.add_argument("--ignore-paths",
                       help="Comma-separated list of paths to ignore")
    parser.add_argument("--fail-level", default="high", choices=["critical", "high", "medium", "low", "info"],
                       help="Severity level to consider as failure")
    parser.add_argument("--focus-areas",
                       help="Comma-separated list of security areas to focus on")

    # Output options
    parser.add_argument("--output-format", default=DEFAULT_OUTPUT_FORMAT,
                       help="Output format (json, csv, html, etc.)")
    parser.add_argument("--output-file", help="Output file path")
    parser.add_argument("--evidence-collection", action="store_true",
                       help="Collect evidence for findings")
    parser.add_argument("--summary-only", action="store_true",
                       help="Show only summary information in output")

    # Additional options
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--quiet", action="store_true", help="Minimize console output")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} v{TOOL_VERSION}")

    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the code security analyzer.

    Returns:
        Exit code (0 for success, 1 for errors, 2 for critical findings)
    """
    # Parse command line arguments
    args = parse_arguments()

    # Configure logging based on verbosity
    log_level = logging.DEBUG if args.debug else logging.INFO
    if args.quiet:
        log_level = logging.WARNING

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger = logging.getLogger(TOOL_NAME)

    try:
        # Initialize assessment target
        target = AssessmentTarget(
            target_id=args.target,
            target_type="code_repository",
            hostname=os.uname().nodename
        )

        # Parse focus areas if provided
        focus_areas = []
        if args.focus_areas:
            focus_areas = [area.strip() for area in args.focus_areas.split(',')]

        # Parse ignore paths if provided
        ignore_paths = []
        if args.ignore_paths:
            ignore_paths = [path.strip() for path in args.ignore_paths.split(',')]

        # Create analyzer instance
        analyzer = CodeSecurityAnalyzer(
            target=target,
            language=args.language,
            ruleset=args.ruleset,
            scan_dependencies=args.scan_dependencies,
            custom_rules_path=args.custom_rules_path,
            ignore_paths=ignore_paths,
            fail_level=args.fail_level,
            focus_areas=focus_areas,
            output_format=args.output_format,
            output_file=args.output_file,
            evidence_collection=args.evidence_collection
        )

        # Initialize the analyzer
        if not analyzer.initialize():
            logger.error("Failed to initialize the analyzer")
            return 1

        # Execute the analysis
        if not analyzer.execute():
            logger.error("Analysis execution failed")
            return 1

        # Get findings
        findings = analyzer.analyze_findings()

        # Generate report
        report = analyzer.generate_report(findings)

        # Output results
        if args.output_file:
            with open(args.output_file, 'w') as f:
                if args.output_format.lower() == 'json':
                    json.dump(report, f, indent=2, default=str)
                else:
                    f.write(report)
            logger.info(f"Results written to {args.output_file}")
        else:
            # Print summary to console
            print_summary(findings, args.summary_only)

        # Determine exit code based on findings
        if has_critical_findings(findings, args.fail_level):
            logger.warning(f"Security issues found at or above {args.fail_level.upper()} severity")
            return 2

        logger.info("Analysis completed successfully")
        return 0

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        return 1

    except Exception as e:
        logger.exception(f"Unexpected error during analysis: {str(e)}")
        return 1


def print_summary(findings: List[Finding], summary_only: bool) -> None:
    """
    Print summary of findings to console.

    Args:
        findings: List of findings
        summary_only: Whether to show only summary
    """
    # Count findings by severity
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    category_counts = {}

    for finding in findings:
        severity = finding.severity.name
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        category = finding.category
        category_counts[category] = category_counts.get(category, 0) + 1

    # Print summary
    print("\n--- Code Security Analysis Summary ---")
    print(f"Total findings: {len(findings)}")
    print("\nFindings by Severity:")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"  {severity}: {count}")

    print("\nFindings by Category:")
    for category, count in category_counts.items():
        if count > 0:
            print(f"  {category.replace('_', ' ').title()}: {count}")

    # Print detailed findings if not summary only
    if not summary_only and findings:
        print("\n--- Detailed Findings ---")
        for i, finding in enumerate(findings, 1):
            print(f"\n{i}. {finding.title} ({finding.severity.name})")
            print(f"   Category: {finding.category}")
            print(f"   Resource: {finding.affected_resource}")
            if finding.details.get("line"):
                print(f"   Location: Line {finding.details.get('line')}")
            if finding.details.get("code_snippet"):
                print(f"   Code:\n{textwrap.indent(finding.details.get('code_snippet'), '      ')}")
            print(f"   Description: {finding.description}")


def has_critical_findings(findings: List[Finding], fail_level: str) -> bool:
    """
    Check if there are findings at or above the specified fail level.

    Args:
        findings: List of findings
        fail_level: Severity level to consider as failure

    Returns:
        Whether critical findings exist
    """
    severity_order = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }

    fail_level_value = severity_order.get(fail_level.lower(), 3)  # Default to high if invalid

    for finding in findings:
        finding_level = severity_order.get(finding.severity.name.lower(), 0)
        if finding_level >= fail_level_value:
            return True

    return False


if __name__ == "__main__":
    # Add missing import for textwrap
    import textwrap
    sys.exit(main())
