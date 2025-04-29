"""
Base classes for security assessment tools.

This module provides the foundation for all security assessment tools in the Cloud Infrastructure Platform.
It defines abstract base classes that standardize the assessment workflow, result handling,
and common functionality across different assessment tools.
"""

import abc
import datetime
import json
import logging
import os
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .assessment_logging import setup_logging
from .data_types import AssessmentTarget, Finding, FindingSeverity


class AssessmentStatus(Enum):
    """Status of an assessment execution."""

    NOT_STARTED = "not_started"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class AssessmentBase(abc.ABC):
    """
    Abstract base class for all security assessment implementations.

    This class defines the standard interface and workflow for security assessment tools,
    providing common functionality for initialization, execution, result handling,
    and cleanup.
    """

    def __init__(
        self,
        name: str,
        target: AssessmentTarget,
        assessment_id: Optional[str] = None,
        output_format: str = "standard",
        output_file: Optional[str] = None,
        profile_name: str = "default",
        compliance_framework: Optional[str] = None,
        evidence_collection: bool = False,
        non_invasive: bool = True,
        **kwargs
    ):
        """
        Initialize the assessment base with common parameters.

        Args:
            name: Name of the assessment
            target: Target system or application to assess
            assessment_id: Unique identifier for this assessment, generated if not provided
            output_format: Format for assessment results (standard, json, csv, xml, detailed)
            output_file: Path to output file, if None results are returned but not written
            profile_name: Name of the assessment profile to use
            compliance_framework: Optional compliance framework to validate against
            evidence_collection: Whether to collect evidence during the assessment
            non_invasive: Whether to use non-invasive assessment methods
            **kwargs: Additional parameters specific to assessment types
        """
        self.name = name
        self.target = target
        self.assessment_id = assessment_id or f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"
        self.output_format = output_format
        self.output_file = output_file
        self.profile_name = profile_name
        self.compliance_framework = compliance_framework
        self.evidence_collection = evidence_collection
        self.non_invasive = non_invasive
        self.status = AssessmentStatus.NOT_STARTED
        self.start_time = None
        self.end_time = None
        self.findings = []
        self.errors = []
        self.warnings = []
        self.evidence_paths = []
        self.logger = setup_logging(f"{name.lower().replace(' ', '_')}")
        self.additional_params = kwargs

        # Initialize configuration
        self.config = self._load_configuration()

        self.logger.info(f"Initialized {name} assessment with ID: {self.assessment_id}")

    @abc.abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the assessment resources and connections.

        This method should be implemented to:
        - Load necessary assessment profiles
        - Establish connections to target systems
        - Validate assessment parameters
        - Verify permissions and accessibility
        - Initialize any assessment-specific resources

        Returns:
            True if initialization was successful, False otherwise
        """
        pass

    @abc.abstractmethod
    def run(self) -> bool:
        """
        Execute the assessment against the target.

        This method should be implemented to:
        - Perform the actual assessment steps
        - Collect findings and evidence
        - Process and analyze results
        - Document assessment details

        Returns:
            True if the assessment completed successfully, False otherwise
        """
        pass

    @abc.abstractmethod
    def analyze_findings(self) -> List[Finding]:
        """
        Analyze assessment results to produce findings.

        This method should be implemented to:
        - Process raw assessment data
        - Identify security issues and vulnerabilities
        - Classify and prioritize findings
        - Generate remediation recommendations

        Returns:
            List of findings from the assessment
        """
        pass

    def get_results(self) -> Dict[str, Any]:
        """
        Get the complete results of the assessment.

        Returns:
            A dictionary containing assessment results, metadata, findings, and evidence
        """
        self.logger.debug(f"Generating results for assessment {self.assessment_id}")

        results = {
            "assessment_id": self.assessment_id,
            "name": self.name,
            "target": self.target.to_dict(),
            "status": self.status.value,
            "profile_name": self.profile_name,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if
                               (self.start_time and self.end_time) else None,
            "findings": [finding.to_dict() for finding in self.findings],
            "findings_summary": self._summarize_findings(),
            "evidence_collected": self.evidence_paths if self.evidence_collection else [],
            "errors": self.errors,
            "warnings": self.warnings,
            "configuration": {
                "non_invasive": self.non_invasive,
                "evidence_collection": self.evidence_collection,
                "output_format": self.output_format,
                "compliance_framework": self.compliance_framework
            }
        }

        if self.output_file and self.output_format in ["json", "standard"]:
            self._write_results_to_file(results)

        return results

    def add_finding(self, finding: Finding) -> None:
        """
        Add a finding to the assessment results.

        Args:
            finding: The finding to add
        """
        self.logger.debug(f"Adding finding: {finding.title}")
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        """
        Add an error message to the assessment results.

        Args:
            error: The error message
        """
        self.logger.error(f"Assessment error: {error}")
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """
        Add a warning message to the assessment results.

        Args:
            warning: The warning message
        """
        self.logger.warning(f"Assessment warning: {warning}")
        self.warnings.append(warning)

    def add_evidence(self, evidence_path: str) -> None:
        """
        Add evidence path to the assessment results.

        Args:
            evidence_path: Path to evidence file or directory
        """
        if self.evidence_collection:
            self.logger.debug(f"Adding evidence: {evidence_path}")
            self.evidence_paths.append(evidence_path)

    def cleanup(self) -> None:
        """
        Clean up assessment resources.

        This method should be called after the assessment is complete,
        or when handling exceptions to ensure proper resource cleanup.
        """
        self.logger.info(f"Cleaning up resources for assessment {self.assessment_id}")
        # Base implementation - subclasses should override and extend

    def _load_configuration(self) -> Dict[str, Any]:
        """
        Load assessment configuration from the profile.

        Returns:
            Configuration dictionary for the assessment
        """
        try:
            self.logger.info(f"Loading configuration profile: {self.profile_name}")
            # In a real implementation, this would load from the config directory
            # Here we provide a minimal implementation

            config_path = self._get_config_path(f"{self.profile_name}")

            if not config_path.exists():
                self.logger.warning(f"Profile {self.profile_name} not found, using default")
                config_path = self._get_config_path("default")

            if not config_path.exists():
                self.logger.error("Default profile not found")
                self.add_error("Configuration profile not found")
                return {}

            with open(config_path, 'r') as f:
                config = json.load(f)
                self.logger.debug(f"Configuration loaded successfully: {config_path}")
                return config
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            self.add_error(f"Configuration error: {str(e)}")
            return {}

    def _get_config_path(self, profile_name: str) -> Path:
        """
        Get the path to a configuration profile.

        Args:
            profile_name: Name of the profile

        Returns:
            Path to the configuration file
        """
        base_dir = Path(__file__).parent.parent.parent
        config_dir = base_dir / "config_files" / "assessment_profiles"

        # Check if it's a compliance profile
        if self.compliance_framework:
            compliance_path = config_dir / "compliance" / f"{profile_name}.json"
            if compliance_path.exists():
                return compliance_path

        # Regular profile
        return config_dir / f"{profile_name}.json"

    def _write_results_to_file(self, results: Dict[str, Any]) -> None:
        """
        Write assessment results to a file.

        Args:
            results: Assessment results dictionary
        """
        try:
            output_file = self.output_file

            # If no output file specified, create one in the default location
            if not output_file:
                base_dir = Path(__file__).parent.parent.parent
                output_dir = base_dir / "results"
                output_dir.mkdir(exist_ok=True)
                output_file = str(output_dir / f"{self.assessment_id}_results.json")

            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)

            self.logger.info(f"Assessment results written to {output_file}")
        except Exception as e:
            self.logger.error(f"Error writing results to file: {str(e)}")
            self.add_error(f"Failed to write results: {str(e)}")

    def _summarize_findings(self) -> Dict[str, int]:
        """
        Generate a summary of findings by severity.

        Returns:
            Dictionary with count of findings by severity
        """
        summary = {severity.value: 0 for severity in FindingSeverity}

        for finding in self.findings:
            summary[finding.severity.value] += 1

        summary["total"] = len(self.findings)
        return summary

    def start(self) -> bool:
        """
        Start the assessment process.

        This method orchestrates the complete assessment workflow:
        1. Initialization
        2. Execution
        3. Analysis
        4. Results collection

        Returns:
            True if assessment completed successfully, False otherwise
        """
        try:
            self.logger.info(f"Starting assessment {self.assessment_id}")
            self.status = AssessmentStatus.INITIALIZING
            self.start_time = datetime.datetime.now()

            # Initialize the assessment
            if not self.initialize():
                self.status = AssessmentStatus.FAILED
                self.add_error("Assessment initialization failed")
                self.end_time = datetime.datetime.now()
                return False

            # Run the assessment
            self.status = AssessmentStatus.RUNNING
            if not self.run():
                self.status = AssessmentStatus.FAILED
                self.add_error("Assessment execution failed")
                self.end_time = datetime.datetime.now()
                return False

            # Analyze findings
            self.findings = self.analyze_findings()

            # Mark as complete
            self.status = AssessmentStatus.COMPLETED
            self.end_time = datetime.datetime.now()
            self.logger.info(f"Assessment {self.assessment_id} completed with {len(self.findings)} findings")
            return True

        except Exception as e:
            self.status = AssessmentStatus.FAILED
            self.logger.exception(f"Assessment failed with error: {str(e)}")
            self.add_error(f"Unhandled exception: {str(e)}")
            self.end_time = datetime.datetime.now()
            return False
        finally:
            # Ensure cleanup happens even if there's an exception
            self.cleanup()


class AssessmentPlugin(abc.ABC):
    """
    Base class for assessment plugins.

    Assessment plugins provide modular functionality for specific
    assessment tasks that can be used by assessment tools.
    """

    def __init__(self, name: str, description: str):
        """
        Initialize the assessment plugin.

        Args:
            name: Plugin name
            description: Plugin description
        """
        self.name = name
        self.description = description
        self.enabled = True
        self.logger = logging.getLogger(f"assessment_plugin.{name}")

    @abc.abstractmethod
    def check(self, target: AssessmentTarget, **kwargs) -> List[Finding]:
        """
        Execute the plugin check against a target.

        Args:
            target: Target to check
            **kwargs: Additional parameters

        Returns:
            List of findings from the check
        """
        pass

    def initialize(self, **kwargs) -> bool:
        """
        Initialize the plugin with specific parameters.

        Args:
            **kwargs: Plugin configuration parameters

        Returns:
            True if initialization successful, False otherwise
        """
        return True

    def cleanup(self) -> None:
        """Clean up plugin resources."""
        pass


class AssessmentException(Exception):
    """Base exception for assessment errors."""

    def __init__(self, message: str, assessment_id: Optional[str] = None):
        """
        Initialize an assessment exception.

        Args:
            message: Error message
            assessment_id: ID of the assessment where the error occurred
        """
        self.assessment_id = assessment_id
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.assessment_id:
            return f"Assessment {self.assessment_id}: {self.message}"
        return self.message


class AssessmentInitializationError(AssessmentException):
    """Exception raised when assessment initialization fails."""
    pass


class AssessmentExecutionError(AssessmentException):
    """Exception raised when assessment execution fails."""
    pass


class AssessmentConfigurationError(AssessmentException):
    """Exception raised when assessment configuration is invalid."""
    pass


class CVSSScoreCalculator:
    """
    Handles calculation of CVSS scores for security findings.

    This class implements the Common Vulnerability Scoring System (CVSS) methodology
    for consistent vulnerability severity assessment across all security tools.
    """

    def __init__(self):
        """Initialize the CVSS calculator."""
        self.logger = logging.getLogger("cvss_calculator")

    def calculate_base_score(self,
                             attack_vector: str,  # N(etwork), A(djacent), L(ocal), P(hysical)
                             attack_complexity: str,  # L(ow), H(igh)
                             privileges_required: str,  # N(one), L(ow), H(igh)
                             user_interaction: str,  # N(one), R(equired)
                             scope: str,  # U(nchanged), C(hanged)
                             confidentiality: str,  # N(one), L(ow), H(igh)
                             integrity: str,  # N(one), L(ow), H(igh)
                             availability: str  # N(one), L(ow), H(igh)
                             ) -> float:
        """
        Calculate the CVSS base score based on the core metrics.

        Args:
            attack_vector: The context by which vulnerability exploitation is possible
            attack_complexity: The conditions beyond the attacker's control required for exploitation
            privileges_required: Level of privileges required for exploitation
            user_interaction: Whether user interaction is required for exploitation
            scope: Whether the vulnerability impacts resources beyond the vulnerable component
            confidentiality: Impact to the confidentiality of information
            integrity: Impact to the integrity of information and system operations
            availability: Impact to the availability of the affected component

        Returns:
            The calculated CVSS base score (0.0-10.0)
        """
        # Implementation would calculate the score based on CVSS formula
        # This is a placeholder for the actual calculation
        self.logger.debug("Calculating CVSS base score")

        # Convert metrics to numeric values
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values = {"N": 0.85, "L": 0.62 if scope == "U" else 0.68, "H": 0.27 if scope == "U" else 0.5}
        ui_values = {"N": 0.85, "R": 0.62}
        c_values = {"N": 0, "L": 0.22, "H": 0.56}
        i_values = {"N": 0, "L": 0.22, "H": 0.56}
        a_values = {"N": 0, "L": 0.22, "H": 0.56}

        # Convert metrics to scores
        try:
            av_score = av_values[attack_vector]
            ac_score = ac_values[attack_complexity]
            pr_score = pr_values[privileges_required]
            ui_score = ui_values[user_interaction]
            c_score = c_values[confidentiality]
            i_score = i_values[integrity]
            a_score = a_values[availability]

            # Calculate exploitability
            exploitability = 8.22 * av_score * ac_score * pr_score * ui_score

            # Calculate impact
            impact_base = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))

            if scope == "U":
                impact = 6.42 * impact_base
                base_score = min(exploitability + impact, 10)
            else:  # scope == "C"
                impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02)**15
                base_score = min(1.08 * (exploitability + impact), 10)

            # Round to 1 decimal place
            base_score = round(base_score, 1)

            self.logger.debug(f"CVSS Base Score: {base_score}")
            return base_score

        except KeyError as e:
            self.logger.error(f"Invalid CVSS metric value: {e}")
            # Return safe default if error occurs
            return 0.0

    def calculate_temporal_score(self,
                                base_score: float,
                                exploit_code_maturity: str = "X",  # N(ot defined), U(nproven), P(roof-of-concept), F(unctional), H(igh)
                                remediation_level: str = "X",      # N(ot defined), O(fficial fix), T(emporary fix), W(orkaround), U(navailable)
                                report_confidence: str = "X"       # N(ot defined), U(nknown), R(easonable), C(onfirmed)
                                ) -> float:
        """
        Calculate the CVSS temporal score based on base score and temporal metrics.

        Args:
            base_score: The CVSS base score
            exploit_code_maturity: State of exploit techniques or code availability
            remediation_level: Available remediation status
            report_confidence: Confidence level in the existence of vulnerability

        Returns:
            The calculated CVSS temporal score (0.0-10.0)
        """
        # Implementation would calculate the temporal score

        # Convert metrics to numeric values
        ecm_values = {"X": 1.0, "N": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}
        rl_values = {"X": 1.0, "N": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
        rc_values = {"X": 1.0, "N": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}

        try:
            ecm_score = ecm_values[exploit_code_maturity]
            rl_score = rl_values[remediation_level]
            rc_score = rc_values[report_confidence]

            # Calculate temporal score
            temporal_score = base_score * ecm_score * rl_score * rc_score

            # Round to 1 decimal place
            temporal_score = round(temporal_score, 1)

            self.logger.debug(f"CVSS Temporal Score: {temporal_score}")
            return temporal_score

        except KeyError as e:
            self.logger.error(f"Invalid temporal metric value: {e}")
            return base_score

    def calculate_environmental_score(self,
                                     base_score: float,
                                     confidentiality_requirement: str = "X",  # N(ot defined), L(ow), M(edium), H(igh)
                                     integrity_requirement: str = "X",        # N(ot defined), L(ow), M(edium), H(igh)
                                     availability_requirement: str = "X"      # N(ot defined), L(ow), M(edium), H(igh)
                                     ) -> float:
        """
        Calculate the CVSS environmental score based on base score and environmental metrics.

        Args:
            base_score: The CVSS base score
            confidentiality_requirement: Importance of confidentiality to the target system
            integrity_requirement: Importance of integrity to the target system
            availability_requirement: Importance of availability to the target system

        Returns:
            The calculated CVSS environmental score (0.0-10.0)
        """
        # Implementation would calculate the environmental score
        # This is a simplified implementation

        # Convert metrics to numeric values
        cr_values = {"X": 1.0, "N": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
        ir_values = {"X": 1.0, "N": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
        ar_values = {"X": 1.0, "N": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}

        try:
            cr_score = cr_values[confidentiality_requirement]
            ir_score = ir_values[integrity_requirement]
            ar_score = ar_values[availability_requirement]

            # This is a simplified calculation
            modifier = (cr_score + ir_score + ar_score) / 3
            environmental_score = base_score * modifier

            # Cap at 10.0 and round to 1 decimal place
            environmental_score = min(round(environmental_score, 1), 10.0)

            self.logger.debug(f"CVSS Environmental Score: {environmental_score}")
            return environmental_score

        except KeyError as e:
            self.logger.error(f"Invalid environmental metric value: {e}")
            return base_score

    def get_severity_from_score(self, score: float) -> FindingSeverity:
        """
        Convert a CVSS score to a severity level.

        Args:
            score: The CVSS score (0.0-10.0)

        Returns:
            The corresponding FindingSeverity level
        """
        if score >= 9.0:
            return FindingSeverity.CRITICAL
        elif score >= 7.0:
            return FindingSeverity.HIGH
        elif score >= 4.0:
            return FindingSeverity.MEDIUM
        elif score > 0.0:
            return FindingSeverity.LOW
        else:
            return FindingSeverity.INFO
