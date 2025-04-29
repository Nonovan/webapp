"""
Core assessment engine functionality for security assessment tools.

This module implements the primary execution engine for security assessment operations,
providing standardized workflow, plugin management, resource control, and result
aggregation capabilities across different assessment tools.
"""

import datetime
import logging
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union, cast

from .assessment_base import (
    AssessmentBase,
    AssessmentPlugin,
    AssessmentStatus,
    AssessmentConfigurationError,
    AssessmentExecutionError,
    AssessmentInitializationError,
)
from .assessment_logging import setup_assessment_logging, log_assessment_event
from .data_types import (
    AssessmentResult,
    AssessmentTarget,
    Evidence,
    Finding,
    FindingSeverity,
    FindingStatus,
    RiskLevel,
)
from .error_handlers import (
    ErrorSeverity,
    ExponentialBackoff,
    handle_assessment_error,
    retry_operation,
    safe_execute,
    validate_assessment_preconditions,
    circuit_breaker,
    capture_assessment_exceptions,
)
from .evidence_collector import EvidenceCollector
from .permission_utils import check_assessment_permission, verify_target_access
from .result_formatter import ResultFormatter
from .validation import (
    validate_assessment_parameters,
    validate_target,
    validate_profile,
    validate_output_format,
    is_valid_ip_address,
)


logger = logging.getLogger(__name__)


class ProgressStatus(Enum):
    """Status of assessment progress."""

    NOT_STARTED = "not_started"
    INITIALIZING = "initializing"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class AssessmentProgress:
    """Progress information for an assessment."""

    status: ProgressStatus = ProgressStatus.NOT_STARTED
    percent_complete: float = 0.0
    current_operation: str = ""
    start_time: Optional[datetime.datetime] = None
    end_time: Optional[datetime.datetime] = None
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


class AssessmentEngine:
    """
    Core engine for executing security assessments.

    This class handles the complete assessment workflow including:
    - Resource allocation and cleanup
    - Plugin loading and execution
    - Evidence collection
    - Result aggregation
    - Progress tracking
    """

    def __init__(
        self,
        name: str,
        target: Union[AssessmentTarget, str],
        assessment_id: Optional[str] = None,
        profile_name: str = "default",
        output_format: str = "standard",
        output_file: Optional[str] = None,
        compliance_framework: Optional[str] = None,
        evidence_collection: bool = False,
        non_invasive: bool = True,
        parallel: bool = False,
        max_workers: int = 4,
        timeout: int = 3600,
        **kwargs
    ):
        """
        Initialize the assessment engine.

        Args:
            name: Name of the assessment
            target: Target system or application to assess (string ID or AssessmentTarget)
            assessment_id: Unique identifier for this assessment, generated if not provided
            profile_name: Name of the assessment profile to use
            output_format: Format for assessment results
            output_file: Path to output file, if None results are returned but not written
            compliance_framework: Optional compliance framework to validate against
            evidence_collection: Whether to collect evidence during the assessment
            non_invasive: Whether to use non-invasive assessment methods
            parallel: Whether to run plugins in parallel
            max_workers: Maximum number of parallel workers when parallel=True
            timeout: Timeout in seconds for the complete assessment
            **kwargs: Additional parameters specific to assessment types
        """
        # Convert string target to AssessmentTarget if needed
        if isinstance(target, str):
            target = AssessmentTarget(
                target_id=target,
                target_type="unknown",
                name=target
            )

        # Initialize basic properties
        self.name = name
        self.target = target
        self.assessment_id = assessment_id or f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"
        self.profile_name = profile_name
        self.output_format = validate_output_format(output_format)
        self.output_file = output_file
        self.compliance_framework = compliance_framework
        self.evidence_collection = evidence_collection
        self.non_invasive = non_invasive
        self.parallel = parallel
        self.max_workers = max_workers
        self.timeout = timeout
        self.additional_params = kwargs

        # Setup assessment-specific logger
        self.logger = setup_assessment_logging(
            f"assessment_engine.{name.lower().replace(' ', '_')}_{self.assessment_id}"
        )

        # Initialize state
        self.status = AssessmentStatus.NOT_STARTED
        self.progress = AssessmentProgress()
        self.start_time = None
        self.end_time = None
        self.plugins: List[AssessmentPlugin] = []
        self.findings: List[Finding] = []
        self.evidence_collector = None
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.evidence_paths: List[str] = []

        # Load configuration
        self.logger.info(f"Initializing assessment '{name}' with ID: {self.assessment_id}")
        self.config = self._load_configuration()

        # Initialize evidence collector if needed
        if self.evidence_collection:
            self.evidence_collector = EvidenceCollector(
                assessment_id=self.assessment_id,
                target_id=self.target.target_id,
                assessor=self.additional_params.get('assessor', 'security_assessment')
            )

    @property
    def duration(self) -> Optional[float]:
        """Get assessment duration in seconds if completed."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def is_completed(self) -> bool:
        """Check if assessment is completed."""
        return self.status == AssessmentStatus.COMPLETED

    @property
    def is_failed(self) -> bool:
        """Check if assessment failed."""
        return self.status == AssessmentStatus.FAILED

    @property
    def is_running(self) -> bool:
        """Check if assessment is currently running."""
        return self.status in [
            AssessmentStatus.INITIALIZING,
            AssessmentStatus.RUNNING
        ]

    def initialize(self) -> bool:
        """
        Initialize the assessment resources and connections.

        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            self.logger.info(f"Initializing assessment: {self.assessment_id}")
            self.status = AssessmentStatus.INITIALIZING
            self.progress.status = ProgressStatus.INITIALIZING
            self.progress.current_operation = "Initialization"
            self.start_time = datetime.datetime.now()
            self.progress.start_time = self.start_time

            # Verify permissions
            if not verify_target_access(self.target, "execute"):
                error_msg = f"Permission denied for target: {self.target.target_id}"
                self.add_error(error_msg)
                self.logger.error(error_msg)
                return False

            # Load and initialize plugins
            self._load_plugins()

            # Initialize plugins
            for plugin in self.plugins:
                try:
                    if not plugin.initialize(**self.additional_params):
                        self.add_error(f"Failed to initialize plugin: {plugin.name}")
                except Exception as e:
                    error_msg = f"Error initializing plugin {plugin.name}: {str(e)}"
                    self.add_error(error_msg)
                    self.logger.error(error_msg, exc_info=True)

            # Update progress
            self.progress.percent_complete = 10.0
            self.progress.message = "Initialization complete"

            return len(self.errors) == 0

        except Exception as e:
            error_msg = f"Assessment initialization failed: {str(e)}"
            self.add_error(error_msg)
            self.logger.error(error_msg, exc_info=True)
            return False

    def run(self) -> bool:
        """
        Execute the assessment against the target.

        Returns:
            True if assessment completed successfully, False otherwise
        """
        if self.status != AssessmentStatus.INITIALIZING:
            self.add_error("Cannot run assessment that hasn't been initialized")
            return False

        try:
            self.logger.info(f"Running assessment: {self.assessment_id}")
            self.status = AssessmentStatus.RUNNING
            self.progress.status = ProgressStatus.EXECUTING
            self.progress.current_operation = "Executing assessment plugins"

            # Run all plugins
            if self.parallel and len(self.plugins) > 1:
                self._run_plugins_parallel()
            else:
                self._run_plugins_sequential()

            # Update progress
            self.progress.percent_complete = 70.0
            self.progress.message = "Assessment execution complete"

            return len(self.errors) == 0

        except Exception as e:
            error_msg = f"Assessment execution failed: {str(e)}"
            self.add_error(error_msg)
            self.logger.error(error_msg, exc_info=True)
            return False

    def analyze_findings(self) -> List[Finding]:
        """
        Analyze assessment results to produce findings.

        Returns:
            List of findings from the assessment
        """
        try:
            self.logger.info(f"Analyzing findings for assessment: {self.assessment_id}")
            self.progress.status = ProgressStatus.ANALYZING
            self.progress.current_operation = "Analyzing findings"

            # Process and deduplicate findings
            processed_findings = self._process_findings()

            # Update progress
            self.progress.percent_complete = 90.0
            self.progress.message = "Finding analysis complete"

            return processed_findings

        except Exception as e:
            error_msg = f"Finding analysis failed: {str(e)}"
            self.add_error(error_msg)
            self.logger.error(error_msg, exc_info=True)
            return self.findings

    def get_results(self) -> AssessmentResult:
        """
        Get the complete results of the assessment.

        Returns:
            AssessmentResult containing all findings and metadata
        """
        try:
            self.logger.info(f"Generating results for assessment: {self.assessment_id}")
            self.progress.status = ProgressStatus.FINALIZING
            self.progress.current_operation = "Generating results"

            # Create assessment result
            result = AssessmentResult(
                assessment_id=self.assessment_id,
                name=self.name,
                target=self.target,
                findings=self.findings,
                start_time=self.start_time or datetime.datetime.now(),
                end_time=self.end_time or datetime.datetime.now(),
                status=self.status.value
            )

            # Add errors and warnings
            result.errors = self.errors
            result.warnings = self.warnings

            # Generate summary
            result.generate_summary()

            # If output file specified, save results
            if self.output_file:
                self._write_results_to_file(result)

            # Update progress
            self.progress.percent_complete = 100.0
            self.progress.message = "Assessment complete"
            self.progress.status = ProgressStatus.COMPLETED

            return result

        except Exception as e:
            error_msg = f"Error generating results: {str(e)}"
            self.add_error(error_msg)
            self.logger.error(error_msg, exc_info=True)

            # Return partial results
            return AssessmentResult(
                assessment_id=self.assessment_id,
                name=self.name,
                target=self.target,
                findings=self.findings,
                start_time=self.start_time or datetime.datetime.now(),
                end_time=self.end_time or datetime.datetime.now(),
                status=AssessmentStatus.FAILED.value,
                errors=self.errors,
                warnings=self.warnings
            )

    def add_finding(self, finding: Finding) -> None:
        """
        Add a finding to the assessment results.

        Args:
            finding: Finding to add
        """
        self.findings.append(finding)
        self.logger.info(f"Added finding: {finding.title} [{finding.severity.value}]")

    def add_error(self, error: str) -> None:
        """
        Add an error message to the assessment.

        Args:
            error: Error message to add
        """
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """
        Add a warning message to the assessment.

        Args:
            warning: Warning message to add
        """
        self.warnings.append(warning)

    def add_evidence(self, evidence_path: str) -> None:
        """
        Add evidence path to the assessment.

        Args:
            evidence_path: Path to evidence file
        """
        self.evidence_paths.append(evidence_path)
        self.logger.debug(f"Added evidence: {evidence_path}")

    def add_plugin(self, plugin: AssessmentPlugin) -> None:
        """
        Add an assessment plugin to the engine.

        Args:
            plugin: AssessmentPlugin to add
        """
        self.plugins.append(plugin)
        self.logger.debug(f"Added plugin: {plugin.name}")

    def get_progress(self) -> AssessmentProgress:
        """
        Get current progress information.

        Returns:
            AssessmentProgress object with current status
        """
        return self.progress

    def cleanup(self) -> None:
        """Clean up assessment resources."""
        try:
            self.logger.info(f"Cleaning up assessment: {self.assessment_id}")

            # Cleanup plugins
            for plugin in self.plugins:
                try:
                    plugin.cleanup()
                except Exception as e:
                    self.logger.warning(f"Error cleaning up plugin {plugin.name}: {str(e)}")

            # Finalize evidence collection if needed
            if self.evidence_collector:
                try:
                    evidence_report = self.evidence_collector.finalize()
                    self.logger.info(f"Evidence collection finalized: {len(evidence_report)} items collected")
                except Exception as e:
                    self.logger.error(f"Error finalizing evidence collection: {str(e)}")

        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}", exc_info=True)

    def start(self) -> AssessmentResult:
        """
        Start the complete assessment process.

        This method orchestrates the entire assessment workflow:
        1. Initialization
        2. Execution
        3. Finding analysis
        4. Result generation

        Returns:
            AssessmentResult containing complete assessment results
        """
        try:
            self.logger.info(f"Starting assessment: {self.assessment_id}")

            # Initialize
            if not self.initialize():
                self.status = AssessmentStatus.FAILED
                self.add_error("Assessment initialization failed")
                self.end_time = datetime.datetime.now()
                self.progress.end_time = self.end_time
                return self.get_results()

            # Run assessment
            if not self.run():
                self.status = AssessmentStatus.FAILED
                self.add_error("Assessment execution failed")
                self.end_time = datetime.datetime.now()
                self.progress.end_time = self.end_time
                return self.get_results()

            # Analyze findings
            self.findings = self.analyze_findings()

            # Mark as complete
            self.status = AssessmentStatus.COMPLETED
            self.end_time = datetime.datetime.now()
            self.progress.end_time = self.end_time
            self.logger.info(f"Assessment {self.assessment_id} completed with {len(self.findings)} findings")

            # Return results
            return self.get_results()

        except Exception as e:
            self.status = AssessmentStatus.FAILED
            self.logger.exception(f"Assessment failed with error: {str(e)}")
            self.add_error(f"Unhandled exception: {str(e)}")
            self.end_time = datetime.datetime.now()
            self.progress.end_time = self.end_time
            return self.get_results()

        finally:
            # Ensure cleanup happens even if there's an exception
            self.cleanup()

    def _load_configuration(self) -> Dict[str, Any]:
        """
        Load assessment configuration from the profile.

        Returns:
            Configuration dictionary for the assessment
        """
        try:
            self.logger.info(f"Loading configuration profile: {self.profile_name}")
            # In a real implementation, this would load from the config directory

            config_path = self._get_config_path(f"{self.profile_name}")

            if not config_path.exists():
                self.logger.warning(f"Profile {self.profile_name} not found, using default")
                config_path = self._get_config_path("default")

            if not config_path.exists():
                self.logger.error("Default profile not found")
                self.add_error("Configuration profile not found")
                return {}

            with open(config_path, 'r') as f:
                config = {}
                try:
                    import json
                    config = json.load(f)
                    self.logger.debug(f"Configuration loaded successfully: {config_path}")
                except json.JSONDecodeError as e:
                    self.add_error(f"Invalid configuration format: {str(e)}")
                    self.logger.error(f"Error parsing configuration: {str(e)}")

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
            Path to the profile configuration file
        """
        # Navigate up to the assessment_tools directory
        base_path = Path(__file__).parent.parent.parent

        # Path to assessment profiles
        config_path = base_path / "config_files" / "assessment_profiles"

        # Check if this is a compliance profile
        if "/" in profile_name or "\\" in profile_name:
            return config_path / profile_name / ".json"

        # Standard profile
        return config_path / f"{profile_name}.json"

    def _load_plugins(self) -> None:
        """
        Load assessment plugins based on configuration.
        """
        self.logger.info("Loading assessment plugins")

        # In a real implementation, this would dynamically load plugins
        # based on the assessment type and configuration

        # For now, we'll leave this as a placeholder
        # Actual implementations would load plugin classes based on:
        # 1. Assessment type
        # 2. Profile configuration
        # 3. Target type

        # Example placeholder for plugin discovery
        self.logger.debug("Plugin loading completed")

    def _run_plugins_sequential(self) -> None:
        """
        Run assessment plugins sequentially.
        """
        total_plugins = len(self.plugins)
        self.logger.info(f"Running {total_plugins} plugins sequentially")

        for i, plugin in enumerate(self.plugins):
            try:
                # Update progress
                plugin_name = plugin.name
                self.progress.current_operation = f"Running plugin: {plugin_name}"
                self.progress.percent_complete = 10 + (i / total_plugins * 60)
                self.logger.info(f"Running plugin {i+1}/{total_plugins}: {plugin_name}")

                # Execute plugin check
                findings = plugin.check(self.target, **self.additional_params)

                # Add findings from this plugin
                for finding in findings:
                    self.add_finding(finding)

                self.logger.info(f"Plugin {plugin_name} completed with {len(findings)} findings")

            except Exception as e:
                error_msg = f"Error running plugin {plugin.name}: {str(e)}"
                self.add_error(error_msg)
                self.logger.error(error_msg, exc_info=True)

    def _run_plugins_parallel(self) -> None:
        """
        Run assessment plugins in parallel.
        """
        total_plugins = len(self.plugins)
        self.logger.info(f"Running {total_plugins} plugins in parallel with {self.max_workers} workers")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Start all plugin tasks
            future_to_plugin = {
                executor.submit(self._run_plugin, plugin): plugin
                for plugin in self.plugins
            }

            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                try:
                    findings = future.result()
                    # Add findings
                    for finding in findings:
                        self.add_finding(finding)

                    completed += 1
                    self.progress.percent_complete = 10 + (completed / total_plugins * 60)
                    self.logger.info(f"Plugin {plugin.name} completed with {len(findings)} findings ({completed}/{total_plugins})")

                except Exception as e:
                    error_msg = f"Error running plugin {plugin.name}: {str(e)}"
                    self.add_error(error_msg)
                    self.logger.error(error_msg, exc_info=True)

                    completed += 1
                    self.progress.percent_complete = 10 + (completed / total_plugins * 60)

    def _run_plugin(self, plugin: AssessmentPlugin) -> List[Finding]:
        """
        Run a single plugin safely.

        Args:
            plugin: Plugin to run

        Returns:
            List of findings from the plugin
        """
        plugin_name = plugin.name
        try:
            self.logger.info(f"Running plugin: {plugin_name}")
            return plugin.check(self.target, **self.additional_params)
        except Exception as e:
            self.logger.error(f"Error in plugin {plugin_name}: {str(e)}", exc_info=True)
            return []  # Return empty list on error

    def _process_findings(self) -> List[Finding]:
        """
        Process and deduplicate findings.

        Returns:
            List of processed findings
        """
        if not self.findings:
            self.logger.info("No findings to process")
            return []

        self.logger.info(f"Processing {len(self.findings)} findings")

        # In a real implementation, this would:
        # 1. Deduplicate findings
        # 2. Merge related findings
        # 3. Validate finding details
        # 4. Apply any compliance mappings

        # For this implementation, we'll just do basic validation
        processed_findings = []
        finding_ids = set()

        for finding in self.findings:
            # Skip if no finding ID (shouldn't happen with proper dataclass validation)
            if not finding.finding_id:
                finding.finding_id = f"finding-{uuid.uuid4().hex[:8]}"

            # Skip duplicate IDs
            if finding.finding_id in finding_ids:
                self.logger.warning(f"Duplicate finding ID: {finding.finding_id} - skipping")
                continue

            finding_ids.add(finding.finding_id)

            # Validate and ensure required fields
            if not finding.title:
                finding.title = f"Untitled Finding {finding.finding_id}"

            if not finding.description:
                finding.description = "No description provided"

            if not finding.severity:
                finding.severity = FindingSeverity.MEDIUM

            if not finding.status:
                finding.status = FindingStatus.NEW

            # Add to processed findings
            processed_findings.append(finding)

        self.logger.info(f"Processed findings: {len(processed_findings)}")
        return processed_findings

    def _write_results_to_file(self, results: AssessmentResult) -> None:
        """
        Write assessment results to a file.

        Args:
            results: AssessmentResult to write
        """
        try:
            output_file = self.output_file

            # If no output file specified, create one in the default location
            if not output_file:
                base_dir = Path(__file__).parent.parent.parent
                output_dir = base_dir / "results"
                output_dir.mkdir(exist_ok=True)
                timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                output_file = str(output_dir / f"{self.assessment_id}_{timestamp}_results.json")

            # Convert results to the appropriate format
            formatter = ResultFormatter()
            formatted_results = formatter.format(
                results=results,
                format_type=self.output_format,
                include_evidence=self.evidence_collection
            )

            # Write to file
            formatter.write_to_file(
                content=formatted_results,
                output_path=output_file
            )

            self.logger.info(f"Assessment results written to {output_file}")

        except Exception as e:
            self.logger.error(f"Error writing results to file: {str(e)}", exc_info=True)
            self.add_error(f"Failed to write results: {str(e)}")


def run_assessment(
    name: str,
    target: Union[AssessmentTarget, str],
    **kwargs
) -> AssessmentResult:
    """
    Run a complete security assessment.

    This is a convenience function to create and run an assessment in one step.

    Args:
        name: Name of the assessment
        target: Target system or application to assess
        **kwargs: Additional parameters for AssessmentEngine

    Returns:
        AssessmentResult containing complete assessment results
    """
    engine = AssessmentEngine(name=name, target=target, **kwargs)
    return engine.start()
