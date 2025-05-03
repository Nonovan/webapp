#!/usr/bin/env python3
"""
Assessment Coordinator

This module provides functionality for coordinating and orchestrating multiple security
assessment tools into unified assessment workflows. It manages dependencies between
assessment components, tracks execution progress, consolidates findings, and produces
comprehensive reports.

Features:
- Assessment workflow orchestration
- Dependency management between assessment components
- Parallel execution optimization
- Progress monitoring and status reporting
- Consolidated result generation
- Notification integration
- Scheduling capabilities
- Error handling and recovery
"""

import datetime
import json
import logging
import os
import sys
import time
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable

# Add parent directory to path to allow imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from core_assessment_tools.common import (
        # Core types and tools
        setup_assessment_logging,
        AssessmentTarget,
        validate_target,

        # Result handling
        ResultFormatter,
        export_findings,
        generate_summary
    )
except ImportError as e:
    print(f"Error importing core assessment modules: {e}", file=sys.stderr)
    print("Please ensure that the core_assessment_tools package is properly installed.", file=sys.stderr)
    sys.exit(1)

# Import local modules
try:
    from . import assessment_utils
except ImportError:
    # For standalone testing
    import assessment_utils

# Initialize module logger
logger = setup_assessment_logging("assessment_coordinator")

# Component state enum
class ComponentState(str, Enum):
    """Status states for assessment components."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"

# Assessment state enum
class AssessmentState(str, Enum):
    """Overall status states for assessments."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"

class AssessmentCoordinator:
    """
    Coordinates multiple security assessment components into a unified workflow.

    This class manages dependencies between assessment components, tracks execution,
    consolidates findings, and produces comprehensive reports. It provides a high-level
    interface for orchestrating complex security assessments across multiple tools.
    """

    def __init__(
        self,
        assessment_id: Optional[str] = None,
        assessment_profile: str = "default",
        compliance_standard: Optional[str] = None,
        config_file: Optional[str] = None,
        evidence_collection: bool = True,
        output_dir: Optional[str] = None,
        parallel: bool = True,
        max_workers: int = 3,
        non_invasive: bool = True,
        timeout: int = 3600
    ):
        """
        Initialize the assessment coordinator.

        Args:
            assessment_id: Optional unique identifier for this assessment
            assessment_profile: Assessment profile to use
            compliance_standard: Optional compliance standard to check against
            config_file: Optional configuration file path
            evidence_collection: Whether to collect evidence
            output_dir: Directory to store assessment outputs
            parallel: Whether to run compatible components in parallel
            max_workers: Maximum number of parallel worker threads
            non_invasive: Whether to use non-invasive assessment methods
            timeout: Overall assessment timeout in seconds
        """
        # Core properties
        self.assessment_id = assessment_id or f"coord-{uuid.uuid4().hex[:8]}"
        self.assessment_profile = assessment_profile
        self.compliance_standard = compliance_standard
        self.evidence_collection = evidence_collection
        self.non_invasive = non_invasive
        self.start_time = None
        self.end_time = None

        # Execution settings
        self.parallel = parallel
        self.max_workers = max_workers
        self.timeout = timeout

        # Status and tracking
        self.state = AssessmentState.INITIALIZING
        self.percent_complete = 0.0
        self.errors: List[str] = []
        self.warnings: List[str] = []

        # Load configuration (if provided)
        self.config = {}
        if config_file:
            self.config = assessment_utils.load_config(config_file)

        # Set output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = Path(parent_dir) / "results" / f"{self.assessment_id}_{timestamp}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Component tracking
        self.components: Dict[str, Dict[str, Any]] = {}
        self.dependencies: Dict[str, List[str]] = {}
        self.component_execution_order: List[str] = []
        self.lock = threading.RLock()  # For thread safety with parallel execution

        # Notification settings
        self.notification_config: Dict[str, Any] = {
            "on_start": [],
            "on_complete": [],
            "on_error": [],
            "on_component_complete": []
        }

        logger.info(f"Assessment coordinator initialized with ID: {self.assessment_id}")
        logger.info(f"Assessment profile: {self.assessment_profile}, " +
                   f"Compliance standard: {self.compliance_standard or 'None'}")

    def add_component(
        self,
        component_type: str,
        target: Union[str, AssessmentTarget],
        component_id: Optional[str] = None,
        profile: Optional[str] = None,
        output_format: str = "json",
        parameters: Optional[Dict[str, Any]] = None,
        weight: int = 1
    ) -> str:
        """
        Add an assessment component to the workflow.

        Args:
            component_type: Type of assessment component
            target: Target to assess
            component_id: Optional unique identifier for the component
            profile: Optional component-specific profile
            output_format: Output format for component results
            parameters: Additional parameters for the component
            weight: Relative weight of this component in progress calculation

        Returns:
            Component identifier

        Raises:
            ValueError: If component_type is not valid or component already exists
        """
        if component_type not in assessment_utils.SUPPORTED_ASSESSMENT_TYPES:
            supported = ", ".join(assessment_utils.SUPPORTED_ASSESSMENT_TYPES)
            raise ValueError(f"Unsupported assessment type: {component_type}. Supported: {supported}")

        # Create component_id if not provided
        if component_id is None:
            component_id = f"{component_type}_{uuid.uuid4().hex[:6]}"

        # Check for duplicate
        if component_id in self.components:
            raise ValueError(f"Component with ID {component_id} already exists")

        # Validate and normalize target
        if isinstance(target, str):
            target_obj = assessment_utils.create_assessment_target(target)
        else:
            target_obj = target

        # Create component entry
        component = {
            "component_id": component_id,
            "component_type": component_type,
            "target": target_obj,
            "profile": profile or self.assessment_profile,
            "output_format": output_format,
            "output_file": str(self.output_dir / f"{component_id}_results.json"),
            "parameters": parameters or {},
            "weight": weight,
            "state": ComponentState.PENDING,
            "progress": 0.0,
            "start_time": None,
            "end_time": None,
            "findings": [],
            "errors": [],
            "warnings": []
        }

        with self.lock:
            # Add component to registry
            self.components[component_id] = component

            # Initialize empty dependency list
            self.dependencies[component_id] = []

        logger.info(f"Added component {component_id} ({component_type}) targeting {target_obj.target_id}")
        return component_id

    def add_dependency(self, component_id: str, depends_on: str) -> None:
        """
        Add a dependency relationship between components.

        Args:
            component_id: ID of the dependent component
            depends_on: ID of the component that must complete first

        Raises:
            ValueError: If either component doesn't exist or circular dependency detected
        """
        with self.lock:
            # Validate both components exist
            if component_id not in self.components:
                raise ValueError(f"Component {component_id} not found")

            if depends_on not in self.components:
                raise ValueError(f"Dependency component {depends_on} not found")

            # Add dependency
            if depends_on not in self.dependencies[component_id]:
                self.dependencies[component_id].append(depends_on)
                logger.info(f"Added dependency: {component_id} depends on {depends_on}")

            # Check for circular dependencies
            if self._has_circular_dependency(component_id, depends_on):
                self.dependencies[component_id].remove(depends_on)
                raise ValueError(f"Circular dependency detected between {component_id} and {depends_on}")

    def set_notification_config(self, config: Dict[str, Any]) -> None:
        """
        Configure assessment notifications.

        Args:
            config: Notification configuration dictionary with these optional keys:
                   - on_start: List of recipients for start notifications
                   - on_complete: List of recipients for completion notifications
                   - on_error: List of recipients for error notifications
                   - on_component_complete: List of recipients for component completions
                   - notification_provider: Notification service configuration
        """
        self.notification_config.update(config)
        logger.debug(f"Notification configuration updated")

    def execute(self) -> Dict[str, Any]:
        """
        Execute the assessment workflow.

        This method runs all components in dependency order, potentially in parallel
        where possible, and returns the consolidated results.

        Returns:
            Dictionary with assessment results

        Raises:
            RuntimeError: If the assessment cannot be executed
        """
        try:
            # First check if we have any components
            if not self.components:
                raise RuntimeError("Cannot execute assessment: No components defined")

            # Update state and timestamps
            self.state = AssessmentState.RUNNING
            self.start_time = datetime.datetime.now()
            self.percent_complete = 0.0

            # Send start notification
            self._send_notification("on_start", "Assessment started",
                f"Assessment {self.assessment_id} has started at {self.start_time.isoformat()}")

            logger.info(f"Starting assessment execution with {len(self.components)} components")

            # Calculate execution order considering dependencies
            self._calculate_execution_order()

            if self.parallel:
                # Execute components with parallel processing where possible
                self._execute_parallel()
            else:
                # Execute components sequentially
                self._execute_sequential()

            # Check overall status and compile results
            success = all(self.components[c_id]["state"] == ComponentState.COMPLETED
                          for c_id in self.components)

            self.state = AssessmentState.COMPLETED if success else AssessmentState.FAILED
            self.end_time = datetime.datetime.now()
            self.percent_complete = 100.0

            # Generate consolidated results
            results = self.get_results()

            # Write consolidated results
            output_file = str(self.output_dir / f"{self.assessment_id}_consolidated_results.json")
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)

            # Send completion notification
            notification_subject = "Assessment completed successfully" if success else "Assessment completed with issues"
            self._send_notification("on_complete", notification_subject,
                f"Assessment {self.assessment_id} has completed at {self.end_time.isoformat()}")

            duration = (self.end_time - self.start_time).total_seconds()
            logger.info(f"Assessment execution completed in {duration:.1f}s with status: {self.state}")

            return results

        except Exception as e:
            self.state = AssessmentState.FAILED
            self.end_time = datetime.datetime.now()
            error_msg = f"Assessment execution failed: {str(e)}"
            self.errors.append(error_msg)
            logger.exception(error_msg)

            # Send error notification
            self._send_notification("on_error", "Assessment failed",
                f"Assessment {self.assessment_id} has failed: {str(e)}")

            # Return partial results
            return self.get_results()

    def get_status(self) -> Dict[str, Any]:
        """
        Get current assessment status information.

        Returns:
            Dictionary with current status information
        """
        component_states = {c_id: {
            "state": self.components[c_id]["state"],
            "progress": self.components[c_id]["progress"]
        } for c_id in self.components}

        return {
            "assessment_id": self.assessment_id,
            "state": self.state,
            "percent_complete": self.percent_complete,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "component_count": len(self.components),
            "components": component_states,
            "errors_count": len(self.errors),
            "warnings_count": len(self.warnings)
        }

    def get_results(self) -> Dict[str, Any]:
        """
        Get consolidated assessment results.

        Returns:
            Dictionary with consolidated results
        """
        # Gather all findings from components
        all_findings = []
        consolidated_evidence = []
        component_summaries = {}

        for component_id, component in self.components.items():
            # Skip components that didn't complete
            if component["state"] != ComponentState.COMPLETED:
                continue

            # Add findings from this component
            all_findings.extend(component.get("findings", []))

            # Track evidence paths
            if "evidence_paths" in component:
                consolidated_evidence.extend(component["evidence_paths"])

            # Store component summary
            component_summaries[component_id] = {
                "component_type": component["component_type"],
                "target": component["target"].target_id,
                "state": component["state"],
                "start_time": component["start_time"],
                "end_time": component["end_time"],
                "finding_count": len(component.get("findings", [])),
                "errors": component.get("errors", []),
                "warnings": component.get("warnings", [])
            }

        # Count findings by severity
        severity_counts = {sev: 0 for sev in ["critical", "high", "medium", "low", "info"]}
        for finding in all_findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Build consolidated results
        results = {
            "assessment_id": self.assessment_id,
            "name": f"Coordinated Assessment {self.assessment_id}",
            "profile": self.assessment_profile,
            "compliance_standard": self.compliance_standard,
            "state": self.state,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": ((self.end_time - self.start_time).total_seconds()
                                if self.start_time and self.end_time else None),
            "components": component_summaries,
            "findings": all_findings,
            "finding_count": len(all_findings),
            "severity_counts": severity_counts,
            "evidence_collected": consolidated_evidence,
            "errors": self.errors,
            "warnings": self.warnings
        }

        return results

    def is_complete(self) -> bool:
        """
        Check if the assessment is complete.

        Returns:
            True if assessment is complete (regardless of success or failure)
        """
        return self.state in [AssessmentState.COMPLETED, AssessmentState.FAILED, AssessmentState.CANCELLED]

    def cancel(self) -> bool:
        """
        Cancel the assessment.

        Returns:
            True if cancellation was successful
        """
        if self.state not in [AssessmentState.RUNNING, AssessmentState.INITIALIZING]:
            return False

        logger.info(f"Cancelling assessment {self.assessment_id}")
        self.state = AssessmentState.CANCELLED
        self.end_time = datetime.datetime.now()

        # Cancel any running components
        for component_id, component in self.components.items():
            if component["state"] in [ComponentState.RUNNING, ComponentState.QUEUED]:
                component["state"] = ComponentState.CANCELLED

        return True

    def generate_consolidated_report(
        self,
        format_type: str = "pdf",
        output_file: Optional[str] = None,
        include_evidence: bool = True,
        template: str = "comprehensive"
    ) -> str:
        """
        Generate a consolidated report from all completed components.

        Args:
            format_type: Report format (pdf, html, etc.)
            output_file: Path to output file, or None to auto-generate
            include_evidence: Whether to include evidence details
            template: Report template name

        Returns:
            Path to the generated report

        Raises:
            ImportError: If report_generator is not available
            RuntimeError: If report generation fails
        """
        try:
            from . import report_generator
        except ImportError:
            raise ImportError("Cannot generate report: report_generator module not available")

        # Get consolidated results
        results = self.get_results()

        # Create temp file for consolidated results
        temp_file = str(self.output_dir / f"{self.assessment_id}_consolidated.json")
        with open(temp_file, 'w') as f:
            json.dump(results, f, indent=2)

        # Generate output file name if not provided
        if output_file is None:
            output_file = str(self.output_dir / f"{self.assessment_id}_report.{format_type}")

        # Generate report using the report generator
        try:
            report_generator.generate_report(
                assessment_id=self.assessment_id,
                input_file=temp_file,
                format=format_type,
                template=template,
                output=output_file,
                include_evidence=include_evidence,
                compliance_map=self.compliance_standard
            )

            logger.info(f"Generated consolidated report: {output_file}")
            return output_file

        except Exception as e:
            raise RuntimeError(f"Failed to generate report: {str(e)}")

    def _has_circular_dependency(self, from_comp: str, to_comp: str) -> bool:
        """Check if adding a dependency would create a circular reference."""
        if from_comp == to_comp:
            return True

        # Check if to_comp depends on from_comp (directly or indirectly)
        visited = set()

        def dfs(component):
            visited.add(component)
            for dependency in self.dependencies.get(component, []):
                if dependency == from_comp:
                    return True
                if dependency not in visited:
                    if dfs(dependency):
                        return True
            return False

        return dfs(to_comp)

    def _calculate_execution_order(self) -> None:
        """Calculate component execution order based on dependencies."""
        with self.lock:
            # Reset execution order
            self.component_execution_order = []

            # Track components that have been added to the execution order
            added = set()

            # Keep adding components until all are in the execution order
            while len(added) < len(self.components):
                # Find components with all dependencies satisfied
                for component_id in self.components:
                    if component_id in added:
                        continue

                    # Check if all dependencies are satisfied
                    dependencies_satisfied = all(dep in added for dep in self.dependencies[component_id])

                    if dependencies_satisfied:
                        self.component_execution_order.append(component_id)
                        added.add(component_id)

                # Check for deadlock
                if len(self.component_execution_order) == len(added) < len(self.components):
                    # Deadlock detected
                    remaining = [c for c in self.components if c not in added]
                    error_msg = f"Dependency deadlock detected for components: {', '.join(remaining)}"
                    logger.error(error_msg)
                    self.errors.append(error_msg)

                    # Add remaining components in any order to break deadlock
                    for component_id in remaining:
                        self.component_execution_order.append(component_id)
                        added.add(component_id)

                    # Mark deadlocked components as having errors
                    for component_id in remaining:
                        self.components[component_id]["errors"].append("Dependency deadlock detected")

                    break

            logger.info(f"Component execution order: {', '.join(self.component_execution_order)}")

    def _execute_component(self, component_id: str) -> bool:
        """Execute a single assessment component."""
        component = self.components[component_id]

        # Skip if already completed or failed
        if component["state"] in [ComponentState.COMPLETED, ComponentState.FAILED, ComponentState.CANCELLED]:
            return component["state"] == ComponentState.COMPLETED

        # Update state and timestamps
        with self.lock:
            component["state"] = ComponentState.RUNNING
            component["start_time"] = datetime.datetime.now()
            component["progress"] = 0.0

        # Log execution
        logger.info(f"Executing component {component_id} ({component['component_type']})")

        try:
            # Prepare arguments
            additional_args = []

            # Add compliance standard if specified
            if self.compliance_standard:
                additional_args.extend(["--compliance", self.compliance_standard])

            # Add evidence collection if enabled
            if self.evidence_collection:
                additional_args.append("--evidence")

            # Add component-specific parameters
            for param, value in component["parameters"].items():
                if value is True:  # Handle boolean flags
                    additional_args.append(f"--{param}")
                elif value is not False:  # Skip parameters with False value
                    additional_args.extend([f"--{param}", str(value)])

            # Execute the assessment tool
            results = assessment_utils.run_assessment_tool(
                assessment_type=component["component_type"],
                target=component["target"].target_id,
                profile=component["profile"],
                output_format=component["output_format"],
                output_file=component["output_file"],
                additional_args=additional_args
            )

            # Handle execution results
            if "error" in results:
                with self.lock:
                    component["state"] = ComponentState.FAILED
                    component["end_time"] = datetime.datetime.now()
                    component["errors"].append(results["error"])
                    component["progress"] = 100.0

                logger.error(f"Component {component_id} failed: {results['error']}")
                return False

            # Store results in component
            with self.lock:
                component["state"] = ComponentState.COMPLETED
                component["end_time"] = datetime.datetime.now()
                component["findings"] = results.get("findings", [])
                component["errors"] = results.get("errors", [])
                component["warnings"] = results.get("warnings", [])
                component["evidence_paths"] = results.get("evidence_collected", [])
                component["progress"] = 100.0

            # Send component completion notification
            self._send_notification(
                "on_component_complete",
                f"Component {component_id} completed",
                f"Assessment component {component_id} ({component['component_type']}) " +
                f"completed at {component['end_time'].isoformat()} with " +
                f"{len(component['findings'])} findings."
            )

            logger.info(f"Component {component_id} completed with {len(component['findings'])} findings")
            return True

        except Exception as e:
            with self.lock:
                component["state"] = ComponentState.FAILED
                component["end_time"] = datetime.datetime.now()
                error_msg = f"Component execution error: {str(e)}"
                component["errors"].append(error_msg)
                component["progress"] = 100.0

            logger.exception(f"Component {component_id} failed with exception: {str(e)}")
            return False

    def _execute_sequential(self) -> None:
        """Execute components sequentially in dependency order."""
        total_components = len(self.component_execution_order)
        completed = 0

        # Execute each component in order
        for component_id in self.component_execution_order:
            # Check if component's dependencies completed successfully
            deps_ok = True
            for dep_id in self.dependencies[component_id]:
                if self.components[dep_id]["state"] != ComponentState.COMPLETED:
                    deps_ok = False
                    error_msg = f"Skipping component {component_id}: " + \
                               f"Dependency {dep_id} did not complete successfully"
                    self.components[component_id]["state"] = ComponentState.SKIPPED
                    self.components[component_id]["errors"].append(error_msg)
                    logger.warning(error_msg)
                    break

            # Skip if dependencies failed
            if not deps_ok:
                completed += 1
                self._update_progress(completed, total_components)
                continue

            # Execute the component
            self._execute_component(component_id)
            completed += 1

            # Update overall progress
            self._update_progress(completed, total_components)

    def _execute_parallel(self) -> None:
        """Execute components in parallel when dependencies allow."""
        # Track completed components
        completed_components: Set[str] = set()
        failed_components: Set[str] = set()
        total_components = len(self.component_execution_order)

        # Group components by dependency levels
        dependency_levels = []

        # Calculate dependency levels
        remaining = set(self.components.keys())

        while remaining:
            # Find components that only depend on completed levels
            level_components = []

            for component_id in list(remaining):
                if all(dep in completed_components for dep in self.dependencies[component_id]):
                    level_components.append(component_id)
                    remaining.remove(component_id)

            # If no components can be added at this level, we have a deadlock
            if not level_components:
                error_msg = f"Dependency deadlock detected for components: {', '.join(remaining)}"
                logger.error(error_msg)
                self.errors.append(error_msg)

                # Add all remaining as a final level to break deadlock
                level_components = list(remaining)
                remaining.clear()

            dependency_levels.append(level_components)

        logger.info(f"Dependency levels: {len(dependency_levels)}")
        for i, level in enumerate(dependency_levels):
            logger.debug(f"Level {i}: {', '.join(level)}")

        # Execute components level by level
        for level_idx, level_components in enumerate(dependency_levels):
            logger.info(f"Executing level {level_idx} with {len(level_components)} components")

            # Skip components that depend on failed components
            for component_id in level_components[:]:
                if any(dep in failed_components for dep in self.dependencies[component_id]):
                    error_msg = f"Skipping component {component_id}: Dependency failure"
                    self.components[component_id]["state"] = ComponentState.SKIPPED
                    self.components[component_id]["errors"].append(error_msg)
                    level_components.remove(component_id)
                    completed_components.add(component_id)
                    logger.warning(error_msg)

            # Execute this level in parallel
            level_results = {}

            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(level_components))) as executor:
                # Submit all tasks
                future_to_component = {
                    executor.submit(self._execute_component, component_id): component_id
                    for component_id in level_components
                }

                # Process results as they complete
                for future in as_completed(future_to_component):
                    component_id = future_to_component[future]

                    try:
                        success = future.result()
                        level_results[component_id] = success
                        completed_components.add(component_id)

                        if not success:
                            failed_components.add(component_id)

                    except Exception as e:
                        level_results[component_id] = False
                        self.components[component_id]["state"] = ComponentState.FAILED
                        error_msg = f"Component execution failed with exception: {str(e)}"
                        self.components[component_id]["errors"].append(error_msg)
                        completed_components.add(component_id)
                        failed_components.add(component_id)
                        logger.exception(f"Component {component_id} execution error: {str(e)}")

            # Update progress after each level
            self._update_progress(len(completed_components), total_components)

            # Log level completion
            success_count = sum(1 for success in level_results.values() if success)
            logger.info(f"Completed level {level_idx}: {success_count}/{len(level_results)} succeeded")

    def _update_progress(self, completed: int, total: int) -> None:
        """Update the overall assessment progress."""
        self.percent_complete = (completed / total) * 100 if total > 0 else 0
        logger.debug(f"Assessment progress: {self.percent_complete:.1f}%")

    def _send_notification(self, event_type: str, subject: str, message: str) -> bool:
        """Send a notification for assessment events."""
        if event_type not in self.notification_config or not self.notification_config[event_type]:
            return False

        recipients = self.notification_config[event_type]
        provider = self.notification_config.get("notification_provider", {})

        # TODO: Implement actual notification delivery
        logger.info(f"Would send notification '{subject}' to {len(recipients)} recipients")
        return True


def run_coordinated_assessment(
    target: Union[str, AssessmentTarget],
    assessment_types: List[str],
    profile: str = "default",
    output_dir: Optional[str] = None,
    compliance_standard: Optional[str] = None,
    parallel: bool = True,
    evidence: bool = True,
    **kwargs
) -> Dict[str, Any]:
    """
    Run a coordinated assessment with multiple components.

    This is a convenience function that sets up and executes a standard
    multi-component assessment against a single target.

    Args:
        target: Target to assess
        assessment_types: List of assessment types to run
        profile: Assessment profile to use
        output_dir: Directory to store outputs
        compliance_standard: Optional compliance standard to check against
        parallel: Whether to run components in parallel
        evidence: Whether to collect evidence
        **kwargs: Additional parameters for the assessment coordinator

    Returns:
        Dictionary with assessment results

    Raises:
        ValueError: If inputs are invalid
    """
    # Validate assessment types
    for assessment_type in assessment_types:
        if assessment_type not in assessment_utils.SUPPORTED_ASSESSMENT_TYPES:
            supported = ", ".join(assessment_utils.SUPPORTED_ASSESSMENT_TYPES)
            raise ValueError(f"Unsupported assessment type: {assessment_type}. Supported: {supported}")

    # Create coordinator
    coordinator = AssessmentCoordinator(
        assessment_profile=profile,
        compliance_standard=compliance_standard,
        evidence_collection=evidence,
        output_dir=output_dir,
        parallel=parallel,
        **kwargs
    )

    # Add components in standard order
    component_ids = []
    for assessment_type in assessment_types:
        component_id = coordinator.add_component(
            component_type=assessment_type,
            target=target
        )
        component_ids.append(component_id)

    # Add standard dependencies
    # If vulnerability scanning is included, make it run first
    if "vulnerability" in assessment_types:
        vuln_idx = assessment_types.index("vulnerability")
        vuln_component_id = component_ids[vuln_idx]

        # Make other components depend on vulnerability scan
        for i, component_id in enumerate(component_ids):
            if i != vuln_idx:
                coordinator.add_dependency(component_id, vuln_component_id)

    # If configuration analysis is included, make access control depend on it
    if "configuration" in assessment_types and "access_control" in assessment_types:
        config_idx = assessment_types.index("configuration")
        access_idx = assessment_types.index("access_control")

        coordinator.add_dependency(
            component_ids[access_idx],
            component_ids[config_idx]
        )

    # Execute assessment
    return coordinator.execute()


def schedule_assessment(
    target: Union[str, AssessmentTarget],
    assessment_types: List[str],
    schedule_type: str = "once",
    schedule_params: Optional[Dict[str, Any]] = None,
    **kwargs
) -> str:
    """
    Schedule a coordinated assessment for future execution.

    Args:
        target: Target to assess
        assessment_types: List of assessment types to run
        schedule_type: Schedule type (once, daily, weekly, monthly)
        schedule_params: Parameters for scheduling
        **kwargs: Additional parameters for the assessment

    Returns:
        Scheduled assessment ID

    Raises:
        NotImplementedError: Currently a placeholder for future implementation
    """
    # This is a placeholder for future implementation of scheduling
    assessment_id = f"scheduled-{uuid.uuid4().hex[:8]}"

    logger.info(f"Would schedule assessment {assessment_id} of type {schedule_type}")
    logger.info(f"Target: {target}, Components: {', '.join(assessment_types)}")

    # TODO: Implement actual scheduling mechanism
    raise NotImplementedError("Assessment scheduling not yet implemented")


def get_assessment_status(assessment_id: str) -> Dict[str, Any]:
    """
    Get status of a running or completed assessment.

    Args:
        assessment_id: Assessment identifier

    Returns:
        Dictionary with assessment status

    Raises:
        NotImplementedError: Currently a placeholder for future implementation
    """
    # This is a placeholder for future implementation
    # TODO: Implement actual status tracking
    raise NotImplementedError("Assessment status tracking not yet implemented")


def generate_consolidated_report(
    assessment_id: str,
    format_type: str = "pdf",
    output_file: Optional[str] = None,
    **kwargs
) -> str:
    """
    Generate a report from a completed assessment.

    Args:
        assessment_id: Assessment identifier
        format_type: Report format (pdf, html, etc.)
        output_file: Path to output file
        **kwargs: Additional parameters for report generation

    Returns:
        Path to generated report file

    Raises:
        NotImplementedError: Currently a placeholder for future implementation
    """
    # This is a placeholder for future implementation
    # TODO: Implement report generation wrapper
    raise NotImplementedError("Standalone report generation not yet implemented")


def cancel_assessment(assessment_id: str) -> bool:
    """
    Cancel a running assessment.

    Args:
        assessment_id: Assessment identifier

    Returns:
        True if cancelled successfully

    Raises:
        NotImplementedError: Currently a placeholder for future implementation
    """
    # This is a placeholder for future implementation
    # TODO: Implement assessment cancellation
    raise NotImplementedError("Assessment cancellation not yet implemented")


def main():
    """Command line entry point for direct script execution."""
    import argparse

    parser = argparse.ArgumentParser(description="Security Assessment Coordinator")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Run assessment command
    run_cmd = subparsers.add_parser("run", help="Run a coordinated assessment")
    run_cmd.add_argument("--target", required=True, help="Target to assess")
    run_cmd.add_argument("--types", required=True, help="Assessment types (comma-separated)")
    run_cmd.add_argument("--profile", default="default", help="Assessment profile")
    run_cmd.add_argument("--compliance", help="Compliance standard")
    run_cmd.add_argument("--output-dir", help="Output directory")
    run_cmd.add_argument("--sequential", action="store_true", help="Run components sequentially")
    run_cmd.add_argument("--no-evidence", action="store_true", help="Disable evidence collection")

    # Status command
    status_cmd = subparsers.add_parser("status", help="Get assessment status")
    status_cmd.add_argument("--assessment-id", required=True, help="Assessment ID")

    # Cancel command
    cancel_cmd = subparsers.add_parser("cancel", help="Cancel assessment")
    cancel_cmd.add_argument("--assessment-id", required=True, help="Assessment ID")

    # Report command
    report_cmd = subparsers.add_parser("report", help="Generate consolidated report")
    report_cmd.add_argument("--assessment-id", required=True, help="Assessment ID")
    report_cmd.add_argument("--format", default="pdf", help="Report format")
    report_cmd.add_argument("--output", help="Output file path")
    report_cmd.add_argument("--template", default="comprehensive", help="Report template")
    report_cmd.add_argument("--no-evidence", action="store_true", help="Exclude evidence")

    args = parser.parse_args()

    if args.command == "run":
        assessment_types = [t.strip() for t in args.types.split(",")]
        results = run_coordinated_assessment(
            target=args.target,
            assessment_types=assessment_types,
            profile=args.profile,
            output_dir=args.output_dir,
            compliance_standard=args.compliance,
            parallel=not args.sequential,
            evidence=not args.no_evidence
        )
        print(f"Assessment completed with ID: {results['assessment_id']}")
        print(f"Total findings: {results['finding_count']}")
        print(f"Output directory: {args.output_dir or 'default'}")

    elif args.command == "status":
        try:
            status = get_assessment_status(args.assessment_id)
            print(f"Assessment {args.assessment_id} status: {status['state']}")
            print(f"Progress: {status['percent_complete']:.1f}%")
        except NotImplementedError:
            print("Assessment status tracking not yet implemented")

    elif args.command == "cancel":
        try:
            success = cancel_assessment(args.assessment_id)
            if success:
                print(f"Assessment {args.assessment_id} cancelled successfully")
            else:
                print(f"Failed to cancel assessment {args.assessment_id}")
        except NotImplementedError:
            print("Assessment cancellation not yet implemented")

    elif args.command == "report":
        try:
            report_file = generate_consolidated_report(
                assessment_id=args.assessment_id,
                format_type=args.format,
                output_file=args.output,
                template=args.template,
                include_evidence=not args.no_evidence
            )
            print(f"Report generated: {report_file}")
        except NotImplementedError:
            print("Standalone report generation not yet implemented")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
