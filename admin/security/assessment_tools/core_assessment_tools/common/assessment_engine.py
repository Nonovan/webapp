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

    def convert_format(self, content: str, input_format: str, output_format: str) -> str:
        """
        Convert content from one format to another using the ResultFormatter.

        Args:
            content: Content to convert
            input_format: Current format of content
            output_format: Desired output format

        Returns:
            Converted content
        """
        formatter = ResultFormatter()
        return formatter.convert_format(content, input_format, output_format)

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

    def generate_report(self, report_template: str = "standard",
                        compliance_mapping: Optional[str] = None) -> str:
        """
        Generate a formatted report of the assessment results.

        Args:
            report_template: Template to use for the report (standard, executive, detailed)
            compliance_mapping: Optional compliance framework to map findings against

        Returns:
            Path to the generated report file
        """
        try:
            from ..supporting_scripts.report_generator import ReportGenerator

            self.logger.info(f"Generating {report_template} report with compliance mapping: {compliance_mapping}")

            generator = ReportGenerator(
                assessment_id=self.assessment_id,
                target=self.target,
                assessor=self.additional_params.get('assessor', 'security_assessment')
            )

            # Add findings to the report
            for finding in self.findings:
                generator.add_finding(finding)

            # Add evidence if collected
            if self.evidence_collection and self.evidence_collector:
                evidence_report = self.evidence_collector.get_evidence_report()
                generator.add_evidence(evidence_report)

            # Generate the report
            report_path = generator.generate_report(
                format=self.output_format,
                template=report_template,
                compliance_framework=compliance_mapping,
                output_path=self.output_file
            )

            self.logger.info(f"Report generated successfully: {report_path}")
            return report_path

        except ImportError:
            self.logger.warning("Report generator not available, skipping report generation")
            self.add_warning("Report generation skipped: report_generator module not available")
            return ""
        except Exception as e:
            error_msg = f"Error generating report: {str(e)}"
            self.add_error(error_msg)
            self.logger.error(error_msg, exc_info=True)
            return ""

    def pause(self) -> bool:
        """
        Pause the currently running assessment.

        Returns:
            True if successfully paused, False otherwise
        """
        if not self.is_running:
            self.logger.warning("Cannot pause: Assessment is not running")
            return False

        try:
            self.logger.info(f"Pausing assessment: {self.assessment_id}")
            self.status = AssessmentStatus.PAUSED
            self.progress.status = ProgressStatus.PAUSED

            # Pause any active plugins
            for plugin in self.plugins:
                if hasattr(plugin, 'pause') and callable(getattr(plugin, 'pause')):
                    plugin.pause()

            self.logger.info("Assessment paused successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to pause assessment: {str(e)}", exc_info=True)
            return False

    def resume(self) -> bool:
        """
        Resume a paused assessment.

        Returns:
            True if successfully resumed, False otherwise
        """
        if self.status != AssessmentStatus.PAUSED:
            self.logger.warning("Cannot resume: Assessment is not paused")
            return False

        try:
            self.logger.info(f"Resuming assessment: {self.assessment_id}")
            self.status = AssessmentStatus.RUNNING
            self.progress.status = ProgressStatus.EXECUTING

            # Resume any paused plugins
            for plugin in self.plugins:
                if hasattr(plugin, 'resume') and callable(getattr(plugin, 'resume')):
                    plugin.resume()

            self.logger.info("Assessment resumed successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to resume assessment: {str(e)}", exc_info=True)
            return False

    def send_notification(self, event_type: str, message: str,
                          recipients: Optional[List[str]] = None) -> bool:
        """
        Send notifications about assessment events.

        Args:
            event_type: Type of event (start, complete, error, finding)
            message: Notification message
            recipients: List of recipient emails/channels, uses config if None

        Returns:
            True if notification sent successfully, False otherwise
        """
        try:
            if not self.config.get('notification', {}).get('enabled', False):
                self.logger.debug("Notifications disabled, skipping")
                return False

            # Get recipients from config if not provided
            if not recipients:
                recipients = self.config.get('notification', {}).get('recipients', [])

            # For critical-only setting, only send critical notifications
            if (self.config.get('notification', {}).get('critical_only', False) and
                event_type not in ['error', 'critical']):
                self.logger.debug(f"Skipping non-critical notification: {event_type}")
                return False

            self.logger.info(f"Sending {event_type} notification to {recipients}")

            # Implement notification sending logic (would integrate with notification services)
            # For demonstration, we'll just log it
            self.logger.info(f"NOTIFICATION [{event_type}]: {message} to {recipients}")

            return True
        except Exception as e:
            self.logger.error(f"Error sending notification: {str(e)}", exc_info=True)
            return False

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

    def discover_plugins(self) -> List[Type[AssessmentPlugin]]:
        """
        Discover available assessment plugins based on configuration.

        Returns:
            List of plugin classes that can be instantiated
        """
        try:
            self.logger.info("Discovering assessment plugins")
            discovered_plugins = []

            # Get plugin directories from configuration
            plugin_dirs = self.config.get('plugins', {}).get('directories', ['plugins'])
            plugin_types = self._get_required_plugin_types()

            # Base path for plugin discovery
            base_path = Path(__file__).parent.parent

            for plugin_dir in plugin_dirs:
                plugin_path = base_path / plugin_dir
                if not plugin_path.exists() or not plugin_path.is_dir():
                    self.logger.warning(f"Plugin directory not found: {plugin_path}")
                    continue

                # Import plugins dynamically
                sys.path.insert(0, str(plugin_path))
                try:
                    for file in plugin_path.glob("*.py"):
                        if file.name.startswith("_"):
                            continue

                        module_name = file.stem
                        try:
                            module = __import__(module_name)

                            # Find plugin classes in module
                            for attr_name in dir(module):
                                attr = getattr(module, attr_name)
                                if (isinstance(attr, type) and
                                    issubclass(attr, AssessmentPlugin) and
                                    attr != AssessmentPlugin and
                                    attr.plugin_type in plugin_types):
                                    discovered_plugins.append(attr)
                                    self.logger.debug(f"Discovered plugin: {attr_name}")
                        except (ImportError, AttributeError) as e:
                            self.logger.warning(f"Error importing plugin {module_name}: {e}")
                finally:
                    sys.path.pop(0)

            self.logger.info(f"Discovered {len(discovered_plugins)} plugins")
            return discovered_plugins

        except Exception as e:
            self.logger.error(f"Error discovering plugins: {str(e)}", exc_info=True)
            return []

    def _get_required_plugin_types(self) -> List[str]:
        """Get the required plugin types based on assessment configuration."""
        # Default to all plugin types if not specified
        plugin_types = ["vulnerability", "configuration", "access_control", "network"]

        # If compliance framework is specified, add compliance plugins
        if self.compliance_framework:
            plugin_types.append("compliance")

        # Override if explicitly set in config
        if self.config.get('plugins', {}).get('types'):
            plugin_types = self.config.get('plugins', {}).get('types')

        return plugin_types

    def _load_plugins(self) -> None:
        """
        Load assessment plugins based on configuration.
        """
        self.logger.info("Loading assessment plugins")

        # Discover available plugin classes
        plugin_classes = self.discover_plugins()

        # Instantiate and initialize plugins
        for plugin_class in plugin_classes:
            try:
                # Skip plugins that don't match current assessment parameters
                if (hasattr(plugin_class, 'is_applicable') and
                    not plugin_class.is_applicable(self.target, self.profile_name, self.compliance_framework)):
                    self.logger.debug(f"Skipping inapplicable plugin: {plugin_class.__name__}")
                    continue

                # Create plugin instance
                plugin = plugin_class(
                    assessment_id=self.assessment_id,
                    config=self.config,
                    non_invasive=self.non_invasive
                )

                # Add to plugins list
                self.add_plugin(plugin)
                self.logger.info(f"Loaded plugin: {plugin.name} ({plugin.version})")

            except Exception as e:
                self.logger.error(f"Error loading plugin {plugin_class.__name__}: {str(e)}", exc_info=True)

        self.logger.info(f"Loaded {len(self.plugins)} plugins")

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

    def create_remediation_items(self) -> List[str]:
        """
        Create remediation tracking items from assessment findings.

        Returns:
            List of remediation item IDs created
        """
        try:
            from ..supporting_scripts.remediation_tracker import RemediationTracker

            self.logger.info("Creating remediation items from findings")

            tracker = RemediationTracker()
            remediation_ids = []

            for finding in self.findings:
                # Skip informational findings for remediation tracking
                if finding.severity in [FindingSeverity.INFO, FindingSeverity.NONE]:
                    continue

                # Create remediation item
                remediation_id = tracker.create_item(
                    finding_id=finding.finding_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity.value,
                    target=self.target.target_id,
                    assessment_id=self.assessment_id,
                    due_date_days=self._get_sla_for_severity(finding.severity)
                )

                if remediation_id:
                    remediation_ids.append(remediation_id)

            self.logger.info(f"Created {len(remediation_ids)} remediation items")
            return remediation_ids

        except ImportError:
            self.logger.warning("Remediation tracker not available, skipping remediation creation")
            return []
        except Exception as e:
            self.logger.error(f"Error creating remediation items: {str(e)}", exc_info=True)
            return []

    def _get_sla_for_severity(self, severity: FindingSeverity) -> int:
        """Get SLA days based on finding severity."""
        sla_mapping = self.config.get('finding_classification', {})

        if severity == FindingSeverity.CRITICAL:
            return sla_mapping.get('critical', {}).get('remediation_sla_days', 7)
        elif severity == FindingSeverity.HIGH:
            return sla_mapping.get('high', {}).get('remediation_sla_days', 30)
        elif severity == FindingSeverity.MEDIUM:
            return sla_mapping.get('medium', {}).get('remediation_sla_days', 60)
        elif severity == FindingSeverity.LOW:
            return sla_mapping.get('low', {}).get('remediation_sla_days', 90)
        else:
            return 90  # Default SLA

    def save_state(self, state_file: Optional[str] = None) -> str:
        """
        Save the current assessment state to allow resumption.

        Args:
            state_file: Optional file path to save state, uses default if None

        Returns:
            Path to the state file
        """
        try:
            if not state_file:
                base_dir = Path(__file__).parent.parent.parent
                state_dir = base_dir / "state"
                state_dir.mkdir(exist_ok=True)
                state_file = str(state_dir / f"{self.assessment_id}_state.json")

            self.logger.info(f"Saving assessment state to {state_file}")

            # Prepare state dictionary
            state = {
                "assessment_id": self.assessment_id,
                "name": self.name,
                "target": self.target.to_dict(),
                "profile_name": self.profile_name,
                "status": self.status.value,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "output_format": self.output_format,
                "output_file": self.output_file,
                "compliance_framework": self.compliance_framework,
                "evidence_collection": self.evidence_collection,
                "non_invasive": self.non_invasive,
                "findings": [finding.to_dict() for finding in self.findings],
                "errors": self.errors,
                "warnings": self.warnings,
                "progress": {
                    "status": self.progress.status.value,
                    "percent_complete": self.progress.percent_complete,
                    "current_operation": self.progress.current_operation,
                    "message": self.progress.message
                }
            }

            # Write state to file
            import json
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)

            self.logger.info(f"Assessment state saved to {state_file}")
            return state_file

        except Exception as e:
            self.logger.error(f"Error saving assessment state: {str(e)}", exc_info=True)
            return ""

    @classmethod
    def load_state(cls, state_file: str) -> 'AssessmentEngine':
        """
        Load assessment state from a state file.

        Args:
            state_file: Path to the state file

        Returns:
            AssessmentEngine with restored state
        """
        logger = logging.getLogger(__name__)
        logger.info(f"Loading assessment state from {state_file}")

        try:
            import json
            with open(state_file, 'r') as f:
                state = json.load(f)

            # Create target
            target = AssessmentTarget(**state.get('target', {}))

            # Create engine instance
            engine = cls(
                name=state.get('name', 'Unknown'),
                target=target,
                assessment_id=state.get('assessment_id'),
                profile_name=state.get('profile_name', 'default'),
                output_format=state.get('output_format', 'standard'),
                output_file=state.get('output_file'),
                compliance_framework=state.get('compliance_framework'),
                evidence_collection=state.get('evidence_collection', False),
                non_invasive=state.get('non_invasive', True)
            )

            # Restore state
            engine.status = AssessmentStatus(state.get('status', 'not_started'))

            if state.get('start_time'):
                engine.start_time = datetime.datetime.fromisoformat(state['start_time'])
                engine.progress.start_time = engine.start_time

            if state.get('end_time'):
                engine.end_time = datetime.datetime.fromisoformat(state['end_time'])
                engine.progress.end_time = engine.end_time

            # Restore findings, errors and warnings
            for finding_data in state.get('findings', []):
                engine.findings.append(Finding.from_dict(finding_data))

            engine.errors = state.get('errors', [])
            engine.warnings = state.get('warnings', [])

            # Restore progress
            progress_data = state.get('progress', {})
            engine.progress.status = ProgressStatus(progress_data.get('status', 'not_started'))
            engine.progress.percent_complete = progress_data.get('percent_complete', 0.0)
            engine.progress.current_operation = progress_data.get('current_operation', '')
            engine.progress.message = progress_data.get('message', '')

            logger.info(f"Assessment state loaded successfully: {engine.assessment_id}")
            return engine

        except Exception as e:
            logger.error(f"Error loading assessment state: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to load assessment state: {str(e)}")


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
