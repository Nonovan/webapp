#!/usr/bin/env python3
"""
Finding Classifier

This module provides functionality for classifying and prioritizing security findings based on
multiple factors including technical severity (CVSS), business impact, exploitability, affected
systems, and compliance requirements. It helps security teams prioritize remediation efforts by
considering both the technical aspects of vulnerabilities and their impact on business operations.

Features:
- CVSS score calculation and validation
- Business impact assessment based on system criticality and data sensitivity
- Compliance controls mapping and impact assessment
- Remediation priority calculation
- Risk level classification using configurable risk matrices
- Support for multiple vulnerability taxonomies
- Batch classification for multiple findings
- Customizable classification rules
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, Set

# Add parent directory to path to allow imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from core_assessment_tools.common import (
        setup_assessment_logging,
        validate_output_format,
        VALID_OUTPUT_FORMATS
    )
except ImportError:
    # Fallback if core tools not available
    def setup_assessment_logging(name):
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def validate_output_format(format_type):
        return format_type in ["json", "csv", "html", "markdown", "text"]

    VALID_OUTPUT_FORMATS = ["json", "csv", "html", "markdown", "text", "pdf", "xml"]

# Configure module logger
logger = setup_assessment_logging("finding_classifier")

# Constants
DEFAULT_CONFIG_DIR = os.path.join(parent_dir, "config_files")
RISK_MATRICES_DIR = os.path.join(DEFAULT_CONFIG_DIR, "risk_matrices")
BUSINESS_CONTEXT_DIR = os.path.join(DEFAULT_CONFIG_DIR, "business_context")
COMPLIANCE_MAPPINGS_DIR = os.path.join(DEFAULT_CONFIG_DIR, "compliance_mappings")

DEFAULT_RISK_MATRIX = "standard"
DEFAULT_TAXONOMY = "cvss"
DEFAULT_OUTPUT_FORMAT = "json"

# Risk levels
class RiskLevel(str, Enum):
    """Risk levels for classified findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# Remediation priority
class RemediationPriority(str, Enum):
    """Priority levels for remediation activities."""
    IMMEDIATE = "immediate"  # 24-48 hours
    URGENT = "urgent"        # 1 week
    HIGH = "high"            # 2 weeks
    MEDIUM = "medium"        # 30 days
    LOW = "low"              # 90 days
    PLANNED = "planned"      # Next release cycle

# Compliance impact levels
class ComplianceImpact(str, Enum):
    """Impact levels for compliance requirements."""
    SEVERE = "severe"        # Direct violation with penalties
    SIGNIFICANT = "significant"  # Major non-compliance issue
    MODERATE = "moderate"    # Notable compliance concern
    MINOR = "minor"          # Minor compliance consideration
    NONE = "none"            # No compliance impact

# Default CVSS vector components
DEFAULT_CVSS_COMPONENTS = {
    # Base score metrics
    "AV": "N",  # Attack Vector: Network
    "AC": "L",  # Attack Complexity: Low
    "PR": "N",  # Privileges Required: None
    "UI": "N",  # User Interaction: None
    "S": "U",   # Scope: Unchanged
    "C": "N",   # Confidentiality Impact: None
    "I": "N",   # Integrity Impact: None
    "A": "N",   # Availability Impact: None

    # Temporal score metrics (optional)
    "E": "X",   # Exploit Code Maturity: Not Defined
    "RL": "X",  # Remediation Level: Not Defined
    "RC": "X",  # Report Confidence: Not Defined

    # Environmental score metrics (optional)
    "CR": "X",  # Confidentiality Requirement: Not Defined
    "IR": "X",  # Integrity Requirement: Not Defined
    "AR": "X",  # Availability Requirement: Not Defined
    "MAV": "X", # Modified Attack Vector: Not Defined
    "MAC": "X", # Modified Attack Complexity: Not Defined
    "MPR": "X", # Modified Privileges Required: Not Defined
    "MUI": "X", # Modified User Interaction: Not Defined
    "MS": "X",  # Modified Scope: Not Defined
    "MC": "X",  # Modified Confidentiality Impact: Not Defined
    "MI": "X",  # Modified Integrity Impact: Not Defined
    "MA": "X",  # Modified Availability Impact: Not Defined
}

# Default risk matrix - maps CVSS score ranges to risk levels
DEFAULT_RISK_MATRIX = {
    "critical": {"min": 9.0, "max": 10.0},
    "high":     {"min": 7.0, "max": 8.9},
    "medium":   {"min": 4.0, "max": 6.9},
    "low":      {"min": 0.1, "max": 3.9},
    "info":     {"min": 0.0, "max": 0.0}
}

# Default compliance frameworks mapping
DEFAULT_COMPLIANCE_FRAMEWORKS = [
    "pci-dss", "hipaa", "gdpr", "nist-800-53", "iso-27001", "soc2"
]

class FindingClassifier:
    """
    Classifies and prioritizes security findings based on multiple factors.

    This class analyzes security findings and assigns risk levels, calculates
    business impact, determines remediation priorities, and identifies
    compliance impacts.
    """

    def __init__(self,
                risk_matrix: str = DEFAULT_RISK_MATRIX,
                taxonomy: str = DEFAULT_TAXONOMY,
                business_context_file: Optional[str] = None,
                compliance_mappings: Optional[List[str]] = None):
        """
        Initialize the finding classifier.

        Args:
            risk_matrix: Risk matrix to use for classification (filename or identifier)
            taxonomy: Vulnerability taxonomy to use (cvss, owasp, etc.)
            business_context_file: Optional file with business context information
            compliance_mappings: Optional list of compliance frameworks to consider
        """
        self.logger = logger
        self.taxonomy = taxonomy
        self.risk_matrix_name = risk_matrix
        self.business_context = {}
        self.compliance_mappings = {}

        # Load risk matrix
        self.risk_matrix = self._load_risk_matrix(risk_matrix)

        # Load business context if provided
        if business_context_file:
            self.business_context = self._load_business_context(business_context_file)

        # Load compliance mappings if provided
        if compliance_mappings:
            for framework in compliance_mappings:
                mapping = self._load_compliance_mapping(framework)
                if mapping:
                    self.compliance_mappings[framework] = mapping

        self.logger.info(f"Finding classifier initialized with risk matrix: {risk_matrix}, "
                       f"taxonomy: {taxonomy}")
        if self.business_context:
            self.logger.debug(f"Loaded business context with {len(self.business_context)} items")
        if self.compliance_mappings:
            self.logger.debug(f"Loaded compliance mappings: {', '.join(self.compliance_mappings.keys())}")

    def classify_finding(self, finding: Dict[str, Any],
                        environment: str = "production",
                        additional_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Classify a single finding based on its attributes.

        Args:
            finding: Finding details to classify
            environment: Environment context (production, staging, development)
            additional_context: Additional classification context

        Returns:
            Dictionary with classification results including risk level,
            business impact, remediation priority, and compliance impacts
        """
        self.logger.debug(f"Classifying finding: {finding.get('title', 'Untitled')}")

        # Ensure finding has key attributes
        if not self._validate_finding(finding):
            self.logger.warning("Finding validation failed, using default classification")
            return self._get_default_classification(finding)

        # Combine business context
        context = self._get_combined_context(additional_context)

        # Get base classification attributes from finding
        classification = self._extract_base_classification(finding)

        # Calculate or extract CVSS score
        classification["cvss_score"] = self._get_cvss_score(finding)
        classification["cvss_vector"] = self._get_cvss_vector(finding)

        # Determine risk level based on CVSS score and risk matrix
        classification["risk_level"] = self._determine_risk_level(classification["cvss_score"])

        # Calculate business impact
        business_impact = self._calculate_business_impact(finding, context, environment)
        classification["business_impact"] = business_impact

        # Determine remediation priority
        classification["remediation_priority"] = self._determine_remediation_priority(
            classification["risk_level"],
            business_impact,
            environment
        )

        # Identify compliance impacts
        classification["compliance_impact"] = self._identify_compliance_impacts(finding, context)

        # Add environmental factors
        classification["environment"] = environment

        # Apply any custom classification rules
        self._apply_custom_classification_rules(classification, finding, context)

        self.logger.debug(f"Classification completed: {classification['risk_level']} risk, "
                        f"{classification['remediation_priority']} priority")

        return classification

    def classify_findings_batch(self, findings: List[Dict[str, Any]],
                              environment: str = "production",
                              business_context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Classify multiple findings in a batch operation.

        Args:
            findings: List of findings to classify
            environment: Environment context
            business_context: Business context information

        Returns:
            List of classified findings with added classification data
        """
        self.logger.info(f"Batch classifying {len(findings)} findings")

        classified_findings = []

        for finding in findings:
            try:
                # Classify the finding
                classification = self.classify_finding(
                    finding,
                    environment=environment,
                    additional_context=business_context
                )

                # Merge classification with original finding
                classified_finding = finding.copy()
                classified_finding.update({
                    "classification": classification,
                    "risk_level": classification["risk_level"],
                    "business_impact": classification["business_impact"],
                    "remediation_priority": classification["remediation_priority"],
                    "compliance_impact": classification["compliance_impact"]
                })

                classified_findings.append(classified_finding)

            except Exception as e:
                self.logger.error(f"Error classifying finding: {e}")
                # Add the original finding with minimal classification
                classified_finding = finding.copy()
                classified_finding["classification"] = self._get_default_classification(finding)
                classified_finding["risk_level"] = classified_finding["classification"]["risk_level"]
                classified_findings.append(classified_finding)

        # Sort findings by priority (critical first)
        classified_findings = sorted(
            classified_findings,
            key=lambda x: self._get_sort_key(x),
            reverse=True
        )

        self.logger.info(f"Classified {len(classified_findings)} findings")
        return classified_findings

    def _load_risk_matrix(self, matrix_name: str) -> Dict[str, Dict[str, float]]:
        """
        Load risk matrix from configuration file or use default.

        Args:
            matrix_name: Name of risk matrix to load

        Returns:
            Risk matrix dictionary
        """
        if matrix_name == "standard":
            return DEFAULT_RISK_MATRIX

        # Try to load from file
        try:
            matrix_path = os.path.join(RISK_MATRICES_DIR, f"{matrix_name}.json")

            if not os.path.exists(matrix_path):
                self.logger.warning(f"Risk matrix not found: {matrix_path}")
                return DEFAULT_RISK_MATRIX

            with open(matrix_path, 'r') as f:
                matrix = json.load(f)

            self.logger.debug(f"Loaded risk matrix from {matrix_path}")
            return matrix

        except Exception as e:
            self.logger.error(f"Error loading risk matrix: {e}")
            return DEFAULT_RISK_MATRIX

    def _load_business_context(self, context_file: str) -> Dict[str, Any]:
        """
        Load business context from file.

        Args:
            context_file: Path to business context file

        Returns:
            Business context dictionary
        """
        try:
            context_path = context_file

            # Check if it's a relative path to config directory
            if not os.path.exists(context_path):
                alt_path = os.path.join(BUSINESS_CONTEXT_DIR, context_file)
                if os.path.exists(alt_path):
                    context_path = alt_path

            if not os.path.exists(context_path):
                self.logger.warning(f"Business context file not found: {context_file}")
                return {}

            with open(context_path, 'r') as f:
                context = json.load(f)

            self.logger.debug(f"Loaded business context from {context_path}")
            return context

        except Exception as e:
            self.logger.error(f"Error loading business context: {e}")
            return {}

    def _load_compliance_mapping(self, framework: str) -> Dict[str, Any]:
        """
        Load compliance controls mapping.

        Args:
            framework: Compliance framework identifier

        Returns:
            Compliance mapping dictionary
        """
        try:
            mapping_path = os.path.join(COMPLIANCE_MAPPINGS_DIR, f"{framework}.json")

            if not os.path.exists(mapping_path):
                self.logger.warning(f"Compliance mapping not found: {mapping_path}")
                return {}

            with open(mapping_path, 'r') as f:
                mapping = json.load(f)

            self.logger.debug(f"Loaded compliance mapping for {framework}")
            return mapping

        except Exception as e:
            self.logger.error(f"Error loading compliance mapping: {e}")
            return {}

    def _validate_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Validate finding has required attributes.

        Args:
            finding: Finding to validate

        Returns:
            True if finding has minimum required attributes
        """
        if not isinstance(finding, dict):
            return False

        # Check for required fields
        required_fields = ["title", "severity"]
        for field in required_fields:
            if field not in finding:
                return False

        return True

    def _extract_base_classification(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract base classification attributes from finding.

        Args:
            finding: Finding to extract from

        Returns:
            Dictionary with base classification attributes
        """
        return {
            "title": finding.get("title", "Untitled Finding"),
            "severity": finding.get("severity", "medium").lower(),
            "category": finding.get("category", "unknown"),
            "confidence": finding.get("confidence", "medium"),
            "affected_resource": finding.get("affected_resource", ""),
            "affected_systems": finding.get("affected_systems", []),
            "affected_data": finding.get("affected_data", "unknown"),
            "exploitability": finding.get("exploitability", "unknown"),
            "authentication_required": finding.get("authentication_required", True),
            "automated_exploitation": finding.get("automated_exploitation", False),
            "mitigation_available": finding.get("mitigation_available", True),
            "original_severity": finding.get("severity", "medium").lower()
        }

    def _get_cvss_score(self, finding: Dict[str, Any]) -> float:
        """
        Get CVSS score from finding or calculate if not present.

        Args:
            finding: Finding to extract from or calculate for

        Returns:
            CVSS score
        """
        # If CVSS score is explicitly provided
        if "cvss_score" in finding and isinstance(finding["cvss_score"], (int, float)):
            return float(finding["cvss_score"])

        # If CVSS vector is provided, calculate score
        if "cvss_vector" in finding:
            score = calculate_cvss_score(finding["cvss_vector"])
            if score is not None:
                return score

        # Calculate score based on finding attributes
        return self._calculate_cvss_score(finding)

    def _get_cvss_vector(self, finding: Dict[str, Any]) -> str:
        """
        Get CVSS vector from finding or generate if not present.

        Args:
            finding: Finding to extract from or generate for

        Returns:
            CVSS vector string
        """
        # If CVSS vector is explicitly provided
        if "cvss_vector" in finding and isinstance(finding["cvss_vector"], str):
            return finding["cvss_vector"]

        # Generate vector based on finding attributes
        return self._generate_cvss_vector(finding)

    def _calculate_cvss_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate CVSS score based on finding attributes.

        Args:
            finding: Finding to calculate score for

        Returns:
            Calculated CVSS score
        """
        # Generate CVSS vector first
        vector = self._generate_cvss_vector(finding)

        # Calculate score from vector
        score = calculate_cvss_score(vector)

        # Fallback to severity mapping if calculation fails
        if score is None:
            severity_map = {
                "critical": 9.5,
                "high": 7.5,
                "medium": 5.0,
                "low": 3.0,
                "info": 0.0
            }
            severity = finding.get("severity", "medium").lower()
            score = severity_map.get(severity, 5.0)

        return score

    def _generate_cvss_vector(self, finding: Dict[str, Any]) -> str:
        """
        Generate CVSS vector from finding attributes.

        Args:
            finding: Finding to generate vector for

        Returns:
            CVSS vector string
        """
        components = DEFAULT_CVSS_COMPONENTS.copy()

        # Map finding attributes to CVSS components

        # Attack Vector (AV)
        attack_vectors = {
            "remote": "N",        # Network
            "adjacent": "A",      # Adjacent
            "local": "L",         # Local
            "physical": "P"       # Physical
        }
        av_value = finding.get("attack_vector", "remote").lower()
        components["AV"] = attack_vectors.get(av_value, "N")

        # Attack Complexity (AC)
        if finding.get("complexity", "").lower() == "high":
            components["AC"] = "H"
        else:
            components["AC"] = "L"

        # Privileges Required (PR)
        if finding.get("authentication_required", True):
            if finding.get("privileged_access", False):
                components["PR"] = "H"  # High privileges
            else:
                components["PR"] = "L"  # Low privileges
        else:
            components["PR"] = "N"  # No privileges

        # User Interaction (UI)
        if finding.get("user_interaction", False):
            components["UI"] = "R"  # Required
        else:
            components["UI"] = "N"  # None

        # Scope (S)
        if finding.get("scope_change", False):
            components["S"] = "C"  # Changed
        else:
            components["S"] = "U"  # Unchanged

        # Impact metrics based on severity
        impact_map = {
            "critical": "H",  # High
            "high": "H",      # High
            "medium": "M",    # Medium
            "low": "L",       # Low
            "info": "N"       # None
        }
        severity = finding.get("severity", "medium").lower()
        impact = impact_map.get(severity, "M")

        # Specific impact overrides if available
        if "confidentiality_impact" in finding:
            conf_impact = finding["confidentiality_impact"].lower()
            components["C"] = impact_map.get(conf_impact, impact)
        else:
            components["C"] = impact

        if "integrity_impact" in finding:
            int_impact = finding["integrity_impact"].lower()
            components["I"] = impact_map.get(int_impact, impact)
        else:
            components["I"] = impact

        if "availability_impact" in finding:
            avail_impact = finding["availability_impact"].lower()
            components["A"] = impact_map.get(avail_impact, impact)
        else:
            components["A"] = impact

        # Build base vector string
        vector = f"CVSS:3.1/AV:{components['AV']}/AC:{components['AC']}/PR:{components['PR']}/" \
                f"UI:{components['UI']}/S:{components['S']}/C:{components['C']}/" \
                f"I:{components['I']}/A:{components['A']}"

        return vector

    def _determine_risk_level(self, cvss_score: float) -> str:
        """
        Determine risk level based on CVSS score and risk matrix.

        Args:
            cvss_score: CVSS score

        Returns:
            Risk level string
        """
        for level, range_data in self.risk_matrix.items():
            if range_data["min"] <= cvss_score <= range_data["max"]:
                return level

        # Default to medium if no match
        return "medium"

    def _calculate_business_impact(self, finding: Dict[str, Any],
                                 context: Dict[str, Any],
                                 environment: str) -> Dict[str, Any]:
        """
        Calculate business impact based on context and finding details.

        Args:
            finding: Finding details
            context: Business context
            environment: Environment (production, staging, development)

        Returns:
            Business impact assessment
        """
        # Initialize with default impact
        impact = {
            "level": "medium",
            "score": 50,
            "factors": []
        }

        # Environment factor
        env_multiplier = 1.0
        if environment == "production":
            env_multiplier = 1.0
            impact["factors"].append("Production environment")
        elif environment == "staging":
            env_multiplier = 0.7
            impact["factors"].append("Staging environment")
        else:  # development or other
            env_multiplier = 0.5
            impact["factors"].append("Development environment")

        # Check affected systems against critical systems list
        affected_systems = finding.get("affected_systems", [])
        if isinstance(affected_systems, str):
            affected_systems = [affected_systems]

        affected_resource = finding.get("affected_resource", "")
        if affected_resource:
            affected_systems.append(affected_resource)

        critical_systems = context.get("critical_systems", [])
        high_value_systems = context.get("high_value_systems", [])

        # Check for critical system impact
        critical_system_affected = False
        high_value_system_affected = False

        for system in affected_systems:
            if system in critical_systems:
                critical_system_affected = True
                impact["factors"].append(f"Critical system affected: {system}")

            elif system in high_value_systems:
                high_value_system_affected = True
                impact["factors"].append(f"High-value system affected: {system}")

        # Data sensitivity factor
        data_sensitivity = "standard"
        affected_data = finding.get("affected_data", "").lower()

        if affected_data in ["pii", "phi", "pci", "financial", "credentials"]:
            data_sensitivity = "sensitive"
            impact["factors"].append(f"Sensitive data affected: {affected_data}")
        elif affected_data in ["internal", "proprietary", "confidential"]:
            data_sensitivity = "confidential"
            impact["factors"].append(f"Confidential data affected: {affected_data}")

        # Calculate impact score based on factors
        base_score = 50  # Medium impact

        # Critical system factor
        if critical_system_affected:
            base_score += 30
        elif high_value_system_affected:
            base_score += 15

        # Data sensitivity factor
        if data_sensitivity == "sensitive":
            base_score += 20
        elif data_sensitivity == "confidential":
            base_score += 10

        # Apply environment multiplier
        impact_score = min(100, int(base_score * env_multiplier))

        # Determine impact level
        if impact_score >= 80:
            impact_level = "critical"
        elif impact_score >= 60:
            impact_level = "high"
        elif impact_score >= 40:
            impact_level = "medium"
        elif impact_score >= 20:
            impact_level = "low"
        else:
            impact_level = "minimal"

        impact["level"] = impact_level
        impact["score"] = impact_score

        return impact

    def _determine_remediation_priority(self, risk_level: str,
                                       business_impact: Dict[str, Any],
                                       environment: str) -> str:
        """
        Determine remediation priority based on risk level and business impact.

        Args:
            risk_level: Technical risk level
            business_impact: Business impact assessment
            environment: Environment context

        Returns:
            Remediation priority
        """
        # Only critical findings in production get immediate priority
        if risk_level == "critical" and environment == "production" and business_impact["level"] in ["critical", "high"]:
            return RemediationPriority.IMMEDIATE

        # Urgent priority for critical in non-prod or high in production with high impact
        if (risk_level == "critical" and environment != "production") or \
           (risk_level == "high" and environment == "production" and business_impact["level"] in ["critical", "high"]):
            return RemediationPriority.URGENT

        # High priority
        if (risk_level == "high" and (environment != "production" or business_impact["level"] not in ["critical", "high"])) or \
           (risk_level == "medium" and environment == "production" and business_impact["level"] in ["critical", "high"]):
            return RemediationPriority.HIGH

        # Medium priority
        if (risk_level == "medium" and (environment != "production" or business_impact["level"] not in ["critical", "high"])) or \
           (risk_level == "low" and environment == "production" and business_impact["level"] in ["critical", "high"]):
            return RemediationPriority.MEDIUM

        # Low priority
        if risk_level == "low" and (environment != "production" or business_impact["level"] not in ["critical", "high"]):
            return RemediationPriority.LOW

        # Default to planned
        return RemediationPriority.PLANNED

    def _identify_compliance_impacts(self, finding: Dict[str, Any],
                                  context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Identify compliance framework impacts based on finding.

        Args:
            finding: Finding to analyze
            context: Business context

        Returns:
            Compliance impact assessment
        """
        # Initialize result
        result = {
            "impact_level": ComplianceImpact.NONE,
            "impacted_frameworks": {},
            "details": []
        }

        # Extract relevant finding attributes
        finding_type = finding.get("type", "unknown").lower()
        category = finding.get("category", "unknown").lower()
        severity = finding.get("severity", "medium").lower()
        cwe_id = finding.get("cwe_id")
        affected_data = finding.get("affected_data", "").lower()

        # Check against compliance mappings
        impacted_controls = {}

        for framework, mapping in self.compliance_mappings.items():
            framework_impacts = map_to_compliance_requirements(
                finding=finding,
                framework=framework,
                mapping=mapping
            )

            if framework_impacts:
                impacted_controls[framework] = framework_impacts
                result["details"].append({
                    "framework": framework,
                    "controls": framework_impacts
                })

        # Determine overall impact level
        impact_level = ComplianceImpact.NONE

        # If sensitive data is affected, increase impact level
        if affected_data in ["pii", "phi", "pci", "financial", "credentials"]:
            if "pci" in affected_data and severity in ["critical", "high"]:
                impact_level = ComplianceImpact.SEVERE
            elif "phi" in affected_data and severity in ["critical", "high"]:
                impact_level = ComplianceImpact.SEVERE
            elif "pii" in affected_data and severity in ["critical", "high"]:
                impact_level = ComplianceImpact.SIGNIFICANT
            else:
                impact_level = ComplianceImpact.MODERATE

        # If authentication or encryption related, increase impact level
        if category in ["authentication", "authorization", "encryption"] and severity in ["critical", "high"]:
            impact_level = max(impact_level, ComplianceImpact.SIGNIFICANT)

        # If number of impacted frameworks is high, increase impact
        if len(impacted_controls) >= 3:
            impact_level = max(impact_level, ComplianceImpact.MODERATE)

        # If we have specific frameworks with multiple controls impacted
        for framework, controls in impacted_controls.items():
            if len(controls) >= 3:
                # Multiple controls in a single framework is significant
                impact_level = max(impact_level, ComplianceImpact.SIGNIFICANT)
            elif len(controls) > 0 and framework in ["pci-dss", "hipaa"] and severity in ["critical", "high"]:
                # High severity findings affecting regulated frameworks
                impact_level = max(impact_level, ComplianceImpact.SIGNIFICANT)

        result["impact_level"] = impact_level
        result["impacted_frameworks"] = impacted_controls

        return result

    def _apply_custom_classification_rules(self, classification: Dict[str, Any],
                                         finding: Dict[str, Any],
                                         context: Dict[str, Any]) -> None:
        """
        Apply custom classification rules based on specific finding types.

        Args:
            classification: Classification results to modify
            finding: Original finding data
            context: Business context information
        """
        # Extract key attributes for rule matching
        finding_type = finding.get("type", "").lower()
        category = finding.get("category", "").lower()
        resource_type = finding.get("resource_type", "").lower()

        # Rule: Critical authentication findings always get immediate priority
        if category == "authentication" and classification["risk_level"] == "critical":
            classification["remediation_priority"] = RemediationPriority.IMMEDIATE

        # Rule: Hardcoded credentials are always at least high risk
        if finding_type in ["hardcoded_credentials", "hardcoded_secret"] and classification["risk_level"] not in ["critical"]:
            classification["risk_level"] = "high"
            if classification["remediation_priority"] not in [RemediationPriority.IMMEDIATE, RemediationPriority.URGENT]:
                classification["remediation_priority"] = RemediationPriority.URGENT

        # Rule: Cross-site scripting findings affecting authentication raise priority
        if finding_type == "xss" and "authentication" in str(finding):
            if classification["risk_level"] == "medium":
                classification["risk_level"] = "high"
            if classification["remediation_priority"] not in [RemediationPriority.IMMEDIATE, RemediationPriority.URGENT]:
                classification["remediation_priority"] = RemediationPriority.HIGH

        # Rule: SQL injection is always at least high risk with urgent priority
        if finding_type == "sql_injection":
            if classification["risk_level"] not in ["critical"]:
                classification["risk_level"] = "high"
            if classification["remediation_priority"] not in [RemediationPriority.IMMEDIATE]:
                classification["remediation_priority"] = RemediationPriority.URGENT

        # Rule: Critical public-facing findings with exploits always get immediate priority
        if finding.get("public_facing", False) and finding.get("exploit_available", False) and classification["risk_level"] == "critical":
            classification["remediation_priority"] = RemediationPriority.IMMEDIATE

    def _get_default_classification(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get default classification for a finding when complete classification fails.

        Args:
            finding: Finding to get default classification for

        Returns:
            Default classification dictionary
        """
        # Map severity to risk level
        severity = finding.get("severity", "medium").lower()
        severity_to_risk = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info"
        }
        risk_level = severity_to_risk.get(severity, "medium")

        # Default classification
        return {
            "risk_level": risk_level,
            "cvss_score": self._map_severity_to_cvss(severity),
            "cvss_vector": "",
            "business_impact": {
                "level": "medium",
                "score": 50,
                "factors": []
            },
            "remediation_priority": self._map_severity_to_priority(severity),
            "compliance_impact": {
                "impact_level": ComplianceImpact.NONE,
                "impacted_frameworks": {},
                "details": []
            }
        }

    def _map_severity_to_cvss(self, severity: str) -> float:
        """Map severity string to CVSS score."""
        severity_map = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 0.0
        }
        return severity_map.get(severity.lower(), 5.0)

    def _map_severity_to_priority(self, severity: str) -> str:
        """Map severity string to remediation priority."""
        severity_map = {
            "critical": RemediationPriority.URGENT,
            "high": RemediationPriority.HIGH,
            "medium": RemediationPriority.MEDIUM,
            "low": RemediationPriority.LOW,
            "info": RemediationPriority.PLANNED
        }
        return severity_map.get(severity.lower(), RemediationPriority.MEDIUM)

    def _get_combined_context(self, additional_context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Combine loaded business context with additional context.

        Args:
            additional_context: Additional context to include

        Returns:
            Combined context dictionary
        """
        context = self.business_context.copy()

        if additional_context:
            # For list values, extend instead of replace
            for key, value in additional_context.items():
                if key in context and isinstance(context[key], list) and isinstance(value, list):
                    context[key].extend(value)
                else:
                    context[key] = value

        return context

    def _get_sort_key(self, finding: Dict[str, Any]) -> Tuple[int, int, int]:
        """
        Get sort key for findings based on risk level and priority.

        Args:
            finding: Finding to get sort key for

        Returns:
            Tuple of sort values (risk_value, priority_value, impact_value)
        """
        # Risk level mapping
        risk_values = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }

        # Priority mapping
        priority_values = {
            RemediationPriority.IMMEDIATE: 6,
            RemediationPriority.URGENT: 5,
            RemediationPriority.HIGH: 4,
            RemediationPriority.MEDIUM: 3,
            RemediationPriority.LOW: 2,
            RemediationPriority.PLANNED: 1
        }

        # Impact level mapping
        impact_values = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "minimal": 0
        }

        risk_level = finding.get("risk_level", "medium")
        priority = finding.get("remediation_priority", RemediationPriority.MEDIUM)

        business_impact = finding.get("business_impact", {}).get("level", "medium")

        return (
            risk_values.get(risk_level, 3),
            priority_values.get(priority, 3),
            impact_values.get(business_impact, 2)
        )


def classify_finding(finding: Dict[str, Any],
                   risk_matrix: str = DEFAULT_RISK_MATRIX,
                   taxonomy: str = DEFAULT_TAXONOMY,
                   business_context: Optional[Dict[str, Any]] = None,
                   environment: str = "production") -> Dict[str, Any]:
    """
    Classify a finding without creating a FindingClassifier instance.

    Args:
        finding: Finding to classify
        risk_matrix: Risk matrix to use
        taxonomy: Vulnerability taxonomy to use
        business_context: Business context information
        environment: Environment context

    Returns:
        Classification results
    """
    classifier = FindingClassifier(risk_matrix=risk_matrix, taxonomy=taxonomy)
    return classifier.classify_finding(finding, environment=environment, additional_context=business_context)


def classify_findings_batch(findings: List[Dict[str, Any]],
                          risk_matrix: str = DEFAULT_RISK_MATRIX,
                          taxonomy: str = DEFAULT_TAXONOMY,
                          business_context_file: Optional[str] = None,
                          environment: str = "production") -> List[Dict[str, Any]]:
    """
    Classify multiple findings without creating a FindingClassifier instance.

    Args:
        findings: Findings to classify
        risk_matrix: Risk matrix to use
        taxonomy: Vulnerability taxonomy to use
        business_context_file: Path to business context file
        environment: Environment context

    Returns:
        List of classified findings
    """
    classifier = FindingClassifier(
        risk_matrix=risk_matrix,
        taxonomy=taxonomy,
        business_context_file=business_context_file
    )
    return classifier.classify_findings_batch(findings, environment=environment)


def calculate_cvss_score(vector: str) -> Optional[float]:
    """
    Calculate CVSS score from vector string.

    This is a simplified CVSS calculation that provides an approximate score
    based on the CVSS 3.1 formula. For precise scores, consider using a dedicated
    CVSS calculator library.

    Args:
        vector: CVSS vector string

    Returns:
        CVSS score or None if calculation fails
    """
    try:
        # Extract components from vector
        components = {}

        # Handle "CVSS:" prefix if present
        if "CVSS:" in vector:
            vector = vector.split("/", 1)[1] if "/" in vector else vector

        # Parse vector components
        parts = vector.split("/")
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                components[key] = value

        # Calculate base score components
        # Attack Vector (AV)
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        av_score = av_values.get(components.get("AV", "N"), 0.85)

        # Attack Complexity (AC)
        ac_values = {"L": 0.77, "H": 0.44}
        ac_score = ac_values.get(components.get("AC", "L"), 0.77)

        # Privileges Required (PR)
        pr_values = {"N": 0.85, "L": 0.62, "H": 0.27}
        scope_changed = components.get("S", "U") == "C"
        if scope_changed:
            pr_values = {"N": 0.85, "L": 0.68, "H": 0.5}  # Adjusted for scope change
        pr_score = pr_values.get(components.get("PR", "N"), 0.85)

        # User Interaction (UI)
        ui_values = {"N": 0.85, "R": 0.62}
        ui_score = ui_values.get(components.get("UI", "N"), 0.85)

        # Impact Scores
        impact_values = {"N": 0, "L": 0.22, "M": 0.4, "H": 0.56}
        c_score = impact_values.get(components.get("C", "N"), 0)
        i_score = impact_values.get(components.get("I", "N"), 0)
        a_score = impact_values.get(components.get("A", "N"), 0)

        # Calculate Exploitability subscore
        exploitability = 8.22 * av_score * ac_score * pr_score * ui_score

        # Calculate Impact subscore
        iss_base = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))

        if scope_changed:
            impact = 7.52 * (iss_base - 0.029) - 3.25 * (iss_base - 0.02) ** 15
        else:
            impact = 6.42 * iss_base

        # Calculate base score
        if impact <= 0:
            base_score = 0
        else:
            if scope_changed:
                base_score = min(10, 1.08 * (impact + exploitability))
            else:
                base_score = min(10, impact + exploitability)

        # Round to 1 decimal place
        return round(base_score * 10) / 10

    except Exception as e:
        logger.error(f"Error calculating CVSS score: {e}")
        return None


def calculate_business_impact(finding: Dict[str, Any],
                            business_context: Optional[Dict[str, Any]] = None,
                            environment: str = "production") -> Dict[str, Any]:
    """
    Calculate business impact for a finding.

    Args:
        finding: Finding to calculate impact for
        business_context: Business context information
        environment: Environment context

    Returns:
        Business impact assessment
    """
    classifier = FindingClassifier()
    context = business_context or {}
    return classifier._calculate_business_impact(finding, context, environment)


def map_to_compliance_requirements(finding: Dict[str, Any],
                               framework: str,
                               mapping: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Map finding to compliance framework requirements.

    Args:
        finding: Finding to map
        framework: Compliance framework to map to
        mapping: Optional pre-loaded compliance mapping

    Returns:
        List of impacted compliance controls
    """
    impacted_controls = []

    # Use provided mapping or try to load it
    if not mapping:
        try:
            mapping_path = os.path.join(COMPLIANCE_MAPPINGS_DIR, f"{framework}.json")
            if os.path.exists(mapping_path):
                with open(mapping_path, 'r') as f:
                    mapping = json.load(f)
            else:
                # Return empty list if mapping not available
                return []
        except Exception as e:
            logger.error(f"Error loading compliance mapping: {e}")
            return []

    # Skip if no mapping available
    if not mapping or not isinstance(mapping, dict):
        return []

    # Extract key finding attributes for mapping
    finding_type = finding.get("type", "").lower()
    category = finding.get("category", "").lower()
    severity = finding.get("severity", "medium").lower()
    cwe_id = finding.get("cwe_id")

    # Check for direct CWE mappings
    if cwe_id and "cwe_mappings" in mapping:
        cwe_str = f"CWE-{cwe_id}" if isinstance(cwe_id, int) else str(cwe_id)

        if cwe_str in mapping["cwe_mappings"]:
            for control in mapping["cwe_mappings"][cwe_str]:
                impacted_controls.append({
                    "id": control["id"],
                    "name": control["name"],
                    "description": control.get("description", ""),
                    "impact_level": _get_compliance_impact_level(severity, control.get("criticality", "medium"))
                })

    # Check category mappings
    if category and "category_mappings" in mapping:
        if category in mapping["category_mappings"]:
            for control in mapping["category_mappings"][category]:
                # Avoid duplicates
                if not any(c["id"] == control["id"] for c in impacted_controls):
                    impacted_controls.append({
                        "id": control["id"],
                        "name": control["name"],
                        "description": control.get("description", ""),
                        "impact_level": _get_compliance_impact_level(severity, control.get("criticality", "medium"))
                    })

    # Check type mappings
    if finding_type and "type_mappings" in mapping:
        if finding_type in mapping["type_mappings"]:
            for control in mapping["type_mappings"][finding_type]:
                # Avoid duplicates
                if not any(c["id"] == control["id"] for c in impacted_controls):
                    impacted_controls.append({
                        "id": control["id"],
                        "name": control["name"],
                        "description": control.get("description", ""),
                        "impact_level": _get_compliance_impact_level(severity, control.get("criticality", "medium"))
                    })

    return impacted_controls


def _get_compliance_impact_level(finding_severity: str, control_criticality: str) -> str:
    """
    Determine compliance impact level based on finding severity and control criticality.

    Args:
        finding_severity: Finding severity level
        control_criticality: Compliance control criticality

    Returns:
        Impact level string
    """
    # Maps severity+criticality to impact level
    impact_matrix = {
        # High criticality controls
        ("critical", "high"): ComplianceImpact.SEVERE,
        ("high", "high"): ComplianceImpact.SIGNIFICANT,
        ("medium", "high"): ComplianceImpact.MODERATE,
        ("low", "high"): ComplianceImpact.MINOR,

        # Medium criticality controls
        ("critical", "medium"): ComplianceImpact.SIGNIFICANT,
        ("high", "medium"): ComplianceImpact.MODERATE,
        ("medium", "medium"): ComplianceImpact.MINOR,
        ("low", "medium"): ComplianceImpact.MINOR,

        # Low criticality controls
        ("critical", "low"): ComplianceImpact.MODERATE,
        ("high", "low"): ComplianceImpact.MINOR,
        ("medium", "low"): ComplianceImpact.MINOR,
        ("low", "low"): ComplianceImpact.NONE
    }

    key = (finding_severity.lower(), control_criticality.lower())
    return impact_matrix.get(key, ComplianceImpact.MINOR)


def load_findings_from_file(input_file: str) -> List[Dict[str, Any]]:
    """
    Load findings from a file.

    Args:
        input_file: Path to input file

    Returns:
        List of findings
    """
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)

        # Check if file contains findings directly or nested in a findings property
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
            return data["findings"]
        else:
            logger.error(f"Invalid findings format in {input_file}")
            return []
    except Exception as e:
        logger.error(f"Error loading findings: {e}")
        return []


def write_findings_to_file(findings: List[Dict[str, Any]], output_file: str,
                         format_type: str = "json") -> bool:
    """
    Write findings to a file.

    Args:
        findings: Findings to write
        output_file: Output file path
        format_type: Output format

    Returns:
        True if successful
    """
    try:
        # Create directories if needed
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

        if format_type == "json":
            with open(output_file, 'w') as f:
                json.dump({"findings": findings}, f, indent=2, default=str)
            return True

        elif format_type == "csv":
            import csv

            # Extract common fields for headers
            headers = set()
            for finding in findings:
                for key in finding.keys():
                    if isinstance(finding[key], (str, int, float, bool)) or finding[key] is None:
                        headers.add(key)

            headers = sorted(list(headers))

            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()

                for finding in findings:
                    # Extract only simple types that can go into CSV
                    row = {}
                    for key in headers:
                        value = finding.get(key)
                        if isinstance(value, (str, int, float, bool)) or value is None:
                            row[key] = value
                        else:
                            row[key] = str(value)
                    writer.writerow(row)

            return True
        else:
            logger.error(f"Unsupported output format: {format_type}")
            return False

    except Exception as e:
        logger.error(f"Error writing findings: {e}")
        return False


def get_parser() -> argparse.ArgumentParser:
    """
    Create command-line argument parser for the finding classifier.

    Returns:
        Argument parser
    """
    parser = argparse.ArgumentParser(
        description="Classify security findings based on risk level, business impact, "
                   "and compliance requirements."
    )
    parser.add_argument("--input", required=True, help="Input findings file")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--format", default="json", choices=VALID_OUTPUT_FORMATS,
                      help="Output format")
    parser.add_argument("--risk-matrix", default="standard",
                      help="Risk matrix to use")
    parser.add_argument("--taxonomy", default="cvss",
                      help="Vulnerability taxonomy to use")
    parser.add_argument("--context", help="Business context file")
    parser.add_argument("--environment", default="production",
                      choices=["production", "staging", "development"],
                      help="Environment context")
    parser.add_argument("--compliance", nargs="+",
                      help="Compliance frameworks to apply")
    parser.add_argument("--summary", action="store_true",
                      help="Print summary to console")

    return parser


def main() -> int:
    """
    Main entry point for the finding classifier.

    Returns:
        Exit code
    """
    parser = get_parser()
    args = parser.parse_args()

    try:
        # Load findings from input file
        findings = load_findings_from_file(args.input)
        if not findings:
            logger.error(f"No findings found in {args.input}")
            return 1

        logger.info(f"Loaded {len(findings)} findings from {args.input}")

        # Create classifier
        classifier = FindingClassifier(
            risk_matrix=args.risk_matrix,
            taxonomy=args.taxonomy,
            business_context_file=args.context,
            compliance_mappings=args.compliance
        )

        # Classify findings
        classified_findings = classifier.classify_findings_batch(
            findings,
            environment=args.environment
        )

        logger.info(f"Classified {len(classified_findings)} findings")

        # Output results
        if args.output:
            success = write_findings_to_file(
                classified_findings,
                args.output,
                args.format
            )

            if success:
                logger.info(f"Wrote classified findings to {args.output}")
            else:
                logger.error(f"Failed to write to {args.output}")
                return 1

        # Print summary if requested
        if args.summary or not args.output:
            risk_counts = {level: 0 for level in ["critical", "high", "medium", "low", "info"]}
            priority_counts = {priority: 0 for priority in [p.value for p in RemediationPriority]}

            for finding in classified_findings:
                risk_level = finding.get("risk_level", "medium")
                priority = finding.get("remediation_priority", RemediationPriority.MEDIUM)

                risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
                priority_counts[priority] = priority_counts.get(priority, 0) + 1

            print("\nClassification Summary:")
            print("======================\n")

            print("Risk Levels:")
            for level in ["critical", "high", "medium", "low", "info"]:
                if risk_counts[level] > 0:
                    print(f"  {level.capitalize()}: {risk_counts[level]}")

            print("\nRemediation Priorities:")
            priority_order = [
                RemediationPriority.IMMEDIATE, RemediationPriority.URGENT,
                RemediationPriority.HIGH, RemediationPriority.MEDIUM,
                RemediationPriority.LOW, RemediationPriority.PLANNED
            ]

            for priority in priority_order:
                if priority_counts[priority] > 0:
                    print(f"  {priority.capitalize()}: {priority_counts[priority]}")

            print(f"\nTotal: {len(classified_findings)} findings\n")

        return 0

    except Exception as e:
        logger.error(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
