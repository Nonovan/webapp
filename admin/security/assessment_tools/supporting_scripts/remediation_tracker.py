#!/usr/bin/env python3
"""
Remediation Tracker

This module provides functionality for tracking the remediation status of security findings,
monitoring SLAs, and generating reports on progress. It helps security teams and stakeholders
manage the remediation workflow from identification to verification, ensuring timely
resolution of security issues.

Features:
- Remediation task lifecycle management
- SLA monitoring and alerting
- Customizable remediation workflows
- Integration with ticketing systems
- Verification tracking and evidence collection
- Remediation metrics and reporting
- Historical trend analysis
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

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
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def validate_output_format(format_type):
        valid_formats = ["json", "csv", "html", "markdown", "text", "pdf", "xml"]
        return format_type in valid_formats

    VALID_OUTPUT_FORMATS = ["json", "csv", "html", "markdown", "text", "pdf", "xml"]

# Initialize logger
logger = setup_assessment_logging("remediation_tracker")

# Constants
DEFAULT_CONFIG_DIR = os.path.join(parent_dir, "config_files")
DEFAULT_DATA_DIR = os.path.join(parent_dir, "data", "remediation")
DEFAULT_TEMPLATES_DIR = os.path.join(current_dir, "templates")
DEFAULT_SLA_CONFIG = os.path.join(DEFAULT_CONFIG_DIR, "sla_config.json")
DEFAULT_TICKET_TEMPLATES = os.path.join(DEFAULT_CONFIG_DIR, "ticket_templates")
DEFAULT_NOTIFICATION_CONFIG = os.path.join(DEFAULT_CONFIG_DIR, "notification_config.json")

# Remediation status enum
class RemediationStatus(str, Enum):
    """Status values for remediation tasks."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    CLOSED = "closed"
    RISK_ACCEPTED = "risk_accepted"
    REJECTED = "rejected"
    DEFERRED = "deferred"

# Resolution types enum
class ResolutionType(str, Enum):
    """Resolution types for closed remediation tasks."""
    FIXED = "fixed"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    WONT_FIX = "wont_fix"
    DEFERRED = "deferred"
    NOT_REPRODUCIBLE = "not_reproducible"

# Severity levels for standardization
class Severity(str, Enum):
    """Standard severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# SLA timeframes in days by severity (default values, can be overridden)
DEFAULT_SLA_TIMEFRAMES = {
    Severity.CRITICAL: 7,    # 1 week
    Severity.HIGH: 30,       # 1 month
    Severity.MEDIUM: 60,     # 2 months
    Severity.LOW: 90,        # 3 months
    Severity.INFO: 180       # 6 months
}

# Ticketing system integrations
SUPPORTED_TICKET_SYSTEMS = ["jira", "servicenow", "azure_devops", "github"]

class RemediationTracker:
    """
    Track and manage the remediation of security findings.

    This class provides functionality for creating remediation tasks, tracking their status,
    monitoring SLAs, and generating reports on remediation progress.
    """

    def __init__(
        self,
        assessment_id: Optional[str] = None,
        data_dir: Optional[str] = None,
        sla_config: Optional[str] = None,
        integration: Optional[Dict[str, Any]] = None,
        notification_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the remediation tracker.

        Args:
            assessment_id: Optional ID of the assessment to track remediation for
            data_dir: Directory to store remediation data (default: uses DEFAULT_DATA_DIR)
            sla_config: Path to SLA configuration (default: uses DEFAULT_SLA_CONFIG)
            integration: Optional ticketing system integration configuration
            notification_config: Optional notification configuration
        """
        self.assessment_id = assessment_id or f"remediation-{uuid.uuid4().hex[:8]}"

        # Set data directory
        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = Path(DEFAULT_DATA_DIR)

        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load SLA configuration
        self.sla_config = self._load_sla_config(sla_config or DEFAULT_SLA_CONFIG)

        # Set up ticketing system integration
        self.integration = integration or {}

        # Set up notification config
        self.notification_config = notification_config or {}

        # Load existing tasks
        self.tasks_file = self.data_dir / f"{self.assessment_id}_tasks.json"
        self.tasks = self._load_tasks()

        # Initialize task history tracking
        self.history_file = self.data_dir / f"{self.assessment_id}_history.json"
        self._ensure_history_file()

        logger.info(f"Remediation tracker initialized for assessment: {self.assessment_id}")
        logger.debug(f"Loaded {len(self.tasks)} remediation tasks")

    def create_task(
        self,
        finding_id: str,
        title: str,
        description: str,
        severity: str,
        target: Optional[str] = None,
        owner: Optional[str] = None,
        due_date: Optional[str] = None,
        due_date_days: Optional[int] = None,
        ticket_id: Optional[str] = None,
        references: Optional[List[str]] = None,
        remediation: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new remediation task.

        Args:
            finding_id: Unique identifier for the finding
            title: Short title describing the issue
            description: Detailed description of the finding
            severity: Severity level (critical, high, medium, low, info)
            target: Optional affected target system
            owner: Optional owner assigned to the task
            due_date: Optional specific due date (format: YYYY-MM-DD)
            due_date_days: Optional days until due from creation (alternative to due_date)
            ticket_id: Optional external ticketing system ID
            references: Optional list of references (URLs, CVEs, etc.)
            remediation: Optional remediation guidance

        Returns:
            Task ID of the created task
        """
        # Validate severity
        normalized_severity = severity.lower()
        if normalized_severity not in [s.value for s in Severity]:
            normalized_severity = Severity.MEDIUM.value
            logger.warning(f"Invalid severity '{severity}' normalized to '{normalized_severity}'")

        # Generate a new task ID
        task_id = f"RT-{uuid.uuid4().hex[:8]}"

        # Calculate due date if not provided
        task_due_date = None
        if due_date:
            try:
                task_due_date = datetime.datetime.fromisoformat(due_date).isoformat()
            except ValueError:
                logger.warning(f"Invalid due date format: {due_date}, calculating based on SLA")
                task_due_date = self._calculate_due_date(normalized_severity, due_date_days)
        else:
            task_due_date = self._calculate_due_date(normalized_severity, due_date_days)

        # Create task object
        task = {
            "task_id": task_id,
            "finding_id": finding_id,
            "title": title,
            "description": description,
            "severity": normalized_severity,
            "status": RemediationStatus.OPEN.value,
            "creation_date": datetime.datetime.now().isoformat(),
            "due_date": task_due_date,
            "last_updated": datetime.datetime.now().isoformat(),
            "assessment_id": self.assessment_id
        }

        # Add optional fields
        if target:
            task["target"] = target
        if owner:
            task["owner"] = owner
        if ticket_id:
            task["ticket_id"] = ticket_id
        if references:
            task["references"] = references
        if remediation:
            task["remediation"] = remediation

        # Add task to collection and save
        self.tasks[task_id] = task
        self._save_tasks()

        # Add to history
        self._add_history_entry(task_id, "created", "Task created")

        # Create ticket if integration is configured
        if ticket_id is None and self.integration:
            self._create_ticket_for_task(task_id)

        logger.info(f"Created remediation task {task_id} for finding {finding_id}")
        return task_id

    def update_task_status(
        self,
        task_id: str,
        status: str,
        updated_by: Optional[str] = None,
        notes: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Update the status of a remediation task.

        Args:
            task_id: ID of the task to update
            status: New status for the task
            updated_by: Optional name/ID of the person making the update
            notes: Optional notes about the status change
            evidence: Optional evidence for the status change

        Returns:
            Updated task data dictionary

        Raises:
            ValueError: If task ID doesn't exist or status is invalid
        """
        # Check if task exists
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        # Validate status
        normalized_status = status.lower()
        if normalized_status not in [s.value for s in RemediationStatus]:
            valid_statuses = ", ".join([s.value for s in RemediationStatus])
            raise ValueError(f"Invalid status '{status}'. Valid values are: {valid_statuses}")

        # Get task
        task = self.tasks[task_id]

        # Track previous status for notifications
        previous_status = task.get("status")

        # Update task
        task["status"] = normalized_status
        task["last_updated"] = datetime.datetime.now().isoformat()

        # Handle specific status updates
        if normalized_status == RemediationStatus.IMPLEMENTED.value:
            task["implementation_date"] = datetime.datetime.now().isoformat()
        elif normalized_status == RemediationStatus.VERIFIED.value:
            task["verification_date"] = datetime.datetime.now().isoformat()
        elif normalized_status == RemediationStatus.CLOSED.value:
            task["closure_date"] = datetime.datetime.now().isoformat()

        # Add evidence if provided
        if evidence:
            task.setdefault("evidence", []).append({
                "timestamp": datetime.datetime.now().isoformat(),
                "type": "status_update",
                "data": evidence,
                "added_by": updated_by or "system"
            })

        # Add history entry
        history_note = notes or f"Status changed from {previous_status} to {normalized_status}"
        self._add_history_entry(
            task_id,
            "status_update",
            history_note,
            {"previous_status": previous_status, "new_status": normalized_status},
            updated_by
        )

        # Add notes if provided
        if notes:
            self.add_note(task_id, notes, updated_by)

        # Save changes
        self._save_tasks()

        # Update ticket if integration is configured
        if task.get("ticket_id") and self.integration:
            self._update_ticket_status(task_id)

        # Send notification if configured
        self._send_status_notification(task_id, previous_status, normalized_status)

        logger.info(f"Updated task {task_id} status to {normalized_status}")
        return task

    def verify_remediation(
        self,
        task_id: str,
        success: bool = True,
        verifier: Optional[str] = None,
        notes: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Verify the remediation of a task.

        Args:
            task_id: ID of the task to verify
            success: Whether verification was successful
            verifier: Optional name/ID of the person doing verification
            notes: Optional notes about the verification
            evidence: Optional evidence of verification

        Returns:
            Dictionary with verification result

        Raises:
            ValueError: If task ID doesn't exist
        """
        # Check if task exists
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        # Get task
        task = self.tasks[task_id]

        # Check if task is in the right state for verification
        if task.get("status") not in [RemediationStatus.IMPLEMENTED.value, RemediationStatus.IN_PROGRESS.value]:
            logger.warning(f"Task {task_id} is in {task.get('status')} status, not ideal for verification")

        # Update verification status
        if success:
            # Update task status
            task["status"] = RemediationStatus.VERIFIED.value
            task["verification_date"] = datetime.datetime.now().isoformat()
            task["verified_by"] = verifier or "unknown"

            verification_result = {
                "status": "verified",
                "task_id": task_id,
                "verification_date": task["verification_date"]
            }

            # Add history entry
            self._add_history_entry(
                task_id,
                "verification",
                notes or "Remediation verified successfully",
                {"result": "success"},
                verifier
            )
        else:
            # Mark as still in progress
            task["status"] = RemediationStatus.IN_PROGRESS.value

            verification_result = {
                "status": "failed",
                "task_id": task_id,
                "verification_date": datetime.datetime.now().isoformat()
            }

            # Add history entry
            self._add_history_entry(
                task_id,
                "verification",
                notes or "Remediation verification failed",
                {"result": "failure"},
                verifier
            )

        # Add notes if provided
        if notes:
            self.add_note(task_id, notes, verifier)

        # Add evidence if provided
        if evidence:
            task.setdefault("evidence", []).append({
                "timestamp": datetime.datetime.now().isoformat(),
                "type": "verification",
                "data": evidence,
                "added_by": verifier or "system"
            })
            verification_result["evidence_added"] = True

        # Save changes
        self._save_tasks()

        # Update ticket if integration is configured
        if task.get("ticket_id") and self.integration:
            self._update_ticket_status(task_id)

        logger.info(f"Verification of task {task_id} {'succeeded' if success else 'failed'}")
        return verification_result

    def close_task(
        self,
        task_id: str,
        resolution: str,
        closed_by: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Close a remediation task with a specified resolution.

        Args:
            task_id: ID of the task to close
            resolution: Resolution type
            closed_by: Optional name/ID of the person closing the task
            notes: Optional notes about the closure

        Returns:
            Closed task data

        Raises:
            ValueError: If task ID doesn't exist or resolution is invalid
        """
        # Check if task exists
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        # Validate resolution
        normalized_resolution = resolution.lower()
        if normalized_resolution not in [r.value for r in ResolutionType]:
            valid_resolutions = ", ".join([r.value for r in ResolutionType])
            raise ValueError(f"Invalid resolution '{resolution}'. Valid values are: {valid_resolutions}")

        # Get task
        task = self.tasks[task_id]

        # Update task
        task["status"] = RemediationStatus.CLOSED.value
        task["resolution"] = normalized_resolution
        task["closure_date"] = datetime.datetime.now().isoformat()
        task["closed_by"] = closed_by or "unknown"
        task["last_updated"] = datetime.datetime.now().isoformat()

        # Add notes if provided
        if notes:
            self.add_note(task_id, notes, closed_by)

        # Add history entry
        resolution_desc = f"Task closed with resolution: {normalized_resolution}"
        self._add_history_entry(
            task_id,
            "closure",
            notes or resolution_desc,
            {"resolution": normalized_resolution},
            closed_by
        )

        # Save changes
        self._save_tasks()

        # Update ticket if integration is configured
        if task.get("ticket_id") and self.integration:
            self._update_ticket_status(task_id)

        logger.info(f"Closed task {task_id} with resolution: {normalized_resolution}")
        return task

    def add_note(
        self,
        task_id: str,
        content: str,
        author: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Add a note to a remediation task.

        Args:
            task_id: ID of the task to add a note to
            content: Note content
            author: Optional name/ID of the note author

        Returns:
            Added note as a dictionary

        Raises:
            ValueError: If task ID doesn't exist
        """
        # Check if task exists
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        # Get task
        task = self.tasks[task_id]

        # Create note
        note = {
            "timestamp": datetime.datetime.now().isoformat(),
            "content": content,
            "author": author or "unknown"
        }

        # Add note to task
        task.setdefault("notes", []).append(note)
        task["last_updated"] = note["timestamp"]

        # Save changes
        self._save_tasks()

        logger.debug(f"Added note to task {task_id}")
        return note

    def add_evidence(
        self,
        task_id: str,
        evidence_data: Dict[str, Any],
        evidence_type: str = "general",
        added_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Add evidence to a remediation task.

        Args:
            task_id: ID of the task to add evidence to
            evidence_data: Evidence data dictionary
            evidence_type: Type of evidence (general, implementation, verification)
            added_by: Optional name/ID of the person adding evidence

        Returns:
            Added evidence as a dictionary

        Raises:
            ValueError: If task ID doesn't exist
        """
        # Check if task exists
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        # Get task
        task = self.tasks[task_id]

        # Create evidence entry
        evidence = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": evidence_type,
            "data": evidence_data,
            "added_by": added_by or "system"
        }

        # Add evidence to task
        task.setdefault("evidence", []).append(evidence)
        task["last_updated"] = evidence["timestamp"]

        # Save changes
        self._save_tasks()

        logger.debug(f"Added {evidence_type} evidence to task {task_id}")
        return evidence

    def assign_task(
        self,
        task_id: str,
        assignee: str,
        assigner: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Assign a task to a person or team.

        Args:
            task_id: ID of the task to assign
            assignee: Name/ID of the person or team to assign to
            assigner: Optional name/ID of the person making the assignment
            notes: Optional notes about the assignment

        Returns:
            Updated task data

        Raises:
            ValueError: If task ID doesn't exist
        """
        # Check if task exists
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        # Get task
        task = self.tasks[task_id]

        # Record previous owner for history
        previous_owner = task.get("owner")

        # Update owner
        task["owner"] = assignee
        task["last_updated"] = datetime.datetime.now().isoformat()

        # Add notes if provided
        if notes:
            self.add_note(task_id, notes, assigner)

        # Add history entry
        if previous_owner:
            history_note = f"Task reassigned from {previous_owner} to {assignee}"
        else:
            history_note = f"Task assigned to {assignee}"

        self._add_history_entry(
            task_id,
            "assignment",
            notes or history_note,
            {"previous_owner": previous_owner, "new_owner": assignee},
            assigner
        )

        # Save changes
        self._save_tasks()

        # Update ticket if integration is configured
        if task.get("ticket_id") and self.integration:
            self._update_ticket_assignment(task_id)

        logger.info(f"Assigned task {task_id} to {assignee}")
        return task

    def update_due_date(
        self,
        task_id: str,
        due_date: str,
        updated_by: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update the due date for a remediation task.

        Args:
            task_id: ID of the task to update
            due_date: New due date in ISO format (YYYY-MM-DD)
            updated_by: Optional name/ID of the person updating the due date
            reason: Optional reason for changing the due date

        Returns:
            Updated task data

        Raises:
            ValueError: If task ID doesn't exist or due date format is invalid
        """
        # Check if task exists
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        # Validate due date
        try:
            parsed_date = datetime.datetime.fromisoformat(due_date)
            formatted_date = parsed_date.isoformat()
        except ValueError:
            raise ValueError(f"Invalid due date format: {due_date}. Expected format: YYYY-MM-DD")

        # Get task
        task = self.tasks[task_id]

        # Record previous due date for history
        previous_due_date = task.get("due_date")

        # Update due date
        task["due_date"] = formatted_date
        task["last_updated"] = datetime.datetime.now().isoformat()

        # Add history entry
        history_note = f"Due date updated from {previous_due_date} to {formatted_date}"
        if reason:
            history_note += f": {reason}"

        self._add_history_entry(
            task_id,
            "due_date_change",
            history_note,
            {"previous_due_date": previous_due_date, "new_due_date": formatted_date},
            updated_by
        )

        # Save changes
        self._save_tasks()

        # Update ticket if integration is configured
        if task.get("ticket_id") and self.integration:
            self._update_ticket_due_date(task_id)

        logger.info(f"Updated due date for task {task_id} to {formatted_date}")
        return task

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get details for a specific task.

        Args:
            task_id: ID of the task to retrieve

        Returns:
            Task data dictionary or None if not found
        """
        return self.tasks.get(task_id)

    def get_tasks(
        self,
        status: Optional[Union[str, List[str]]] = None,
        severity: Optional[Union[str, List[str]]] = None,
        owner: Optional[str] = None,
        overdue: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """
        Get tasks filtered by various criteria.

        Args:
            status: Optional status or list of statuses to filter by
            severity: Optional severity or list of severities to filter by
            owner: Optional owner to filter by
            overdue: Optional filter for overdue tasks

        Returns:
            List of task dictionaries matching the filters
        """
        # Convert single values to lists
        status_filters = [status.lower()] if isinstance(status, str) else status
        severity_filters = [severity.lower()] if isinstance(severity, str) else severity

        # Start with all tasks
        filtered_tasks = list(self.tasks.values())

        # Apply filters
        if status_filters:
            filtered_tasks = [t for t in filtered_tasks if t.get("status") and t["status"].lower() in status_filters]

        if severity_filters:
            filtered_tasks = [t for t in filtered_tasks if t.get("severity") and t["severity"].lower() in severity_filters]

        if owner:
            filtered_tasks = [t for t in filtered_tasks if t.get("owner") == owner]

        if overdue is not None:
            now = datetime.datetime.now()
            if overdue:
                # Keep only overdue tasks
                filtered_tasks = [
                    t for t in filtered_tasks
                    if t.get("due_date") and datetime.datetime.fromisoformat(t["due_date"]) < now
                    and t.get("status") not in [RemediationStatus.CLOSED.value, RemediationStatus.VERIFIED.value]
                ]
            else:
                # Keep only non-overdue tasks
                filtered_tasks = [
                    t for t in filtered_tasks
                    if not t.get("due_date") or datetime.datetime.fromisoformat(t["due_date"]) >= now
                    or t.get("status") in [RemediationStatus.CLOSED.value, RemediationStatus.VERIFIED.value]
                ]

        # Sort by severity (critical first) then due date
        severity_order = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 1,
            Severity.MEDIUM.value: 2,
            Severity.LOW.value: 3,
            Severity.INFO.value: 4
        }

        def get_sort_key(task):
            severity = task.get("severity", Severity.MEDIUM.value).lower()
            severity_val = severity_order.get(severity, 99)

            due_date = task.get("due_date")
            if due_date:
                try:
                    due_date_obj = datetime.datetime.fromisoformat(due_date)
                    return (severity_val, due_date_obj)
                except (ValueError, TypeError):
                    pass

            # Default to far future for tasks without due date
            return (severity_val, datetime.datetime.max)

        filtered_tasks.sort(key=get_sort_key)

        return filtered_tasks

    def get_overdue_items(
        self,
        days_threshold: Optional[int] = None,
        notify: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get overdue remediation items.

        Args:
            days_threshold: Optional threshold for days overdue (None for all overdue)
            notify: Whether to send notifications for overdue items

        Returns:
            List of overdue task dictionaries
        """
        now = datetime.datetime.now()

        # Get tasks that are not closed and have a due date that has passed
        overdue_tasks = [
            t for t in self.tasks.values()
            if t.get("status") not in [RemediationStatus.CLOSED.value, RemediationStatus.VERIFIED.value]
            and t.get("due_date") and datetime.datetime.fromisoformat(t["due_date"]) < now
        ]

        # Apply days threshold filter if specified
        if days_threshold is not None:
            threshold_date = now - datetime.timedelta(days=days_threshold)
            overdue_tasks = [
                t for t in overdue_tasks
                if datetime.datetime.fromisoformat(t["due_date"]) <= threshold_date
            ]

        # Sort by most overdue (oldest due date) and severity
        overdue_tasks.sort(
            key=lambda t: (
                datetime.datetime.fromisoformat(t["due_date"]),
                # Critical items first in the severity sort
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(t.get("severity", "medium").lower(), 99)
            )
        )

        # Send notifications if requested
        if notify and overdue_tasks:
            self._send_overdue_notifications(overdue_tasks)

        return overdue_tasks

    def generate_status_report(
        self,
        output_format: str = "html",
        output_file: Optional[str] = None
    ) -> Union[str, Dict[str, Any]]:
        """
        Generate a status report for remediation tasks.

        Args:
            output_format: Format for the report (html, json, pdf, markdown, text)
            output_file: Optional path to save the report

        Returns:
            Generated report content or path to output file

        Raises:
            ValueError: If output format is invalid
        """
        # Validate output format
        if not validate_output_format(output_format):
            valid_formats = ", ".join(VALID_OUTPUT_FORMATS)
            raise ValueError(f"Invalid output format: {output_format}. Valid formats: {valid_formats}")

        # Generate report data
        report_data = self._generate_report_data()

        # Generate report in specified format
        if output_format == "json":
            report_content = json.dumps(report_data, indent=2)
        elif output_format == "html":
            report_content = self._generate_html_report(report_data)
        elif output_format == "pdf":
            # Generate HTML first, then convert to PDF
            html_content = self._generate_html_report(report_data)
            if output_file:
                return self._generate_pdf_report(report_data, output_file)
            else:
                # Can't return PDF content directly, fallback to HTML
                logger.warning("PDF output requires output_file parameter, falling back to HTML")
                report_content = html_content
        elif output_format == "markdown":
            report_content = self._generate_markdown_report(report_data)
        else:
            # Default to text
            report_content = self._generate_text_report(report_data)

        # Write to file if specified
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, 'w') as f:
                f.write(report_content)

            logger.info(f"Status report saved to {output_file}")
            return output_file
        else:
            return report_content

    def export_remediation_metrics(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export metrics about remediation activities.

        Args:
            start_date: Optional start date for the metrics period (ISO format)
            end_date: Optional end date for the metrics period (ISO format)
            output_file: Optional path to save the metrics JSON

        Returns:
            Dictionary with remediation metrics
        """
        # Parse date range if provided
        start = None
        end = datetime.datetime.now()

        if start_date:
            try:
                start = datetime.datetime.fromisoformat(start_date)
            except ValueError:
                logger.warning(f"Invalid start date format: {start_date}")

        if end_date:
            try:
                end = datetime.datetime.fromisoformat(end_date)
            except ValueError:
                logger.warning(f"Invalid end date format: {end_date}")

        # Calculate metrics
        metrics = self._calculate_metrics(True)

        # Filter history events by date range if specified
        if start or end:
            history = self._load_history()
            filtered_events = []

            for event in history:
                try:
                    event_time = datetime.datetime.fromisoformat(event.get("timestamp", ""))
                    if (start is None or event_time >= start) and event_time <= end:
                        filtered_events.append(event)
                except (ValueError, TypeError):
                    # Skip events with invalid timestamps
                    pass

            metrics["historical_events"] = filtered_events
            metrics["date_range"] = {
                "start": start.isoformat() if start else None,
                "end": end.isoformat()
            }

        # Write to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(metrics, f, indent=2)

            logger.info(f"Remediation metrics exported to {output_file}")

        return metrics

    def _load_tasks(self) -> Dict[str, Dict[str, Any]]:
        """Load tasks from the data file."""
        if not self.tasks_file.exists():
            return {}

        try:
            with open(self.tasks_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading tasks file: {e}")
            return {}

    def _save_tasks(self) -> bool:
        """Save tasks to the data file."""
        try:
            self.tasks_file.parent.mkdir(parents=True, exist_ok=True)

            with open(self.tasks_file, 'w') as f:
                json.dump(self.tasks, f, indent=2)

            return True
        except IOError as e:
            logger.error(f"Error saving tasks file: {e}")
            return False

    def _ensure_history_file(self) -> None:
        """Ensure history file exists."""
        if not self.history_file.exists():
            self.history_file.parent.mkdir(parents=True, exist_ok=True)

            with open(self.history_file, 'w') as f:
                json.dump([], f)

    def _load_history(self) -> List[Dict[str, Any]]:
        """Load task history from the history file."""
        if not self.history_file.exists():
            self._ensure_history_file()
            return []

        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading history file: {e}")
            return []

    def _add_history_entry(
        self,
        task_id: str,
        action: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        user: Optional[str] = None
    ) -> None:
        """Add an entry to the task history."""
        history = self._load_history()

        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "task_id": task_id,
            "action": action,
            "description": description,
            "user": user or "system"
        }

        if details:
            entry["details"] = details

        # Get task data to include in history
        task = self.tasks.get(task_id)
        if task:
            entry["task_snapshot"] = {
                "title": task.get("title"),
                "severity": task.get("severity"),
                "status": task.get("status"),
                "owner": task.get("owner"),
                "due_date": task.get("due_date")
            }

        history.append(entry)

        try:
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=2)
        except IOError as e:
            logger.error(f"Error saving history file: {e}")

    def _load_sla_config(self, config_path: str) -> Dict[str, Any]:
        """Load SLA configuration from file."""
        # Start with default SLAs
        sla_config = {
            "timeframes": {
                severity.value: days
                for severity, days in DEFAULT_SLA_TIMEFRAMES.items()
            },
            "notification": {
                "warning_threshold": 7,  # Days before due date
                "overdue_interval": 7,   # Days between overdue notifications
            }
        }

        # Try to load configuration file
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)

                # Merge configurations
                if "timeframes" in loaded_config:
                    sla_config["timeframes"].update(loaded_config["timeframes"])

                if "notification" in loaded_config:
                    sla_config["notification"].update(loaded_config["notification"])

                logger.debug(f"Loaded SLA configuration from {config_path}")
            else:
                logger.warning(f"SLA configuration file not found: {config_path}")

        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading SLA configuration: {e}")

        return sla_config

    def _calculate_due_date(self, severity: str, days_override: Optional[int] = None) -> str:
        """Calculate due date based on severity and SLA configuration."""
        if days_override is not None:
            days = days_override
        else:
            # Get SLA timeframe for severity
            days = self.sla_config["timeframes"].get(
                severity,
                DEFAULT_SLA_TIMEFRAMES.get(Severity.MEDIUM)
            )

        due_date = datetime.datetime.now() + datetime.timedelta(days=days)
        return due_date.isoformat()

    def _create_ticket_for_task(self, task_id: str) -> Optional[str]:
        """Create a ticket in the integrated ticketing system."""
        if not self.integration:
            return None

        task = self.tasks.get(task_id)
        if not task:
            return None

        # Placeholder for actual ticket creation implementation
        # In a real implementation, this would call the appropriate API
        logger.info(f"Would create ticket for task {task_id} in ticketing system")

        # Simulate successful ticket creation with a fake ID
        ticket_id = f"TICKET-{uuid.uuid4().hex[:6]}"

        # Update task with ticket ID
        task["ticket_id"] = ticket_id
        self._save_tasks()

        return ticket_id

    def _update_ticket_status(self, task_id: str) -> bool:
        """Update ticket status in the integrated ticketing system."""
        if not self.integration:
            return False

        task = self.tasks.get(task_id)
        if not task or not task.get("ticket_id"):
            return False

        # Placeholder for actual ticket update implementation
        logger.info(f"Would update ticket {task.get('ticket_id')} status for task {task_id}")

        return True

    def _update_ticket_assignment(self, task_id: str) -> bool:
        """Update ticket assignment in the integrated ticketing system."""
        if not self.integration:
            return False

        task = self.tasks.get(task_id)
        if not task or not task.get("ticket_id") or not task.get("owner"):
            return False

        # Placeholder for actual ticket assignment implementation
        logger.info(f"Would update ticket {task.get('ticket_id')} assignment to {task.get('owner')}")

        return True

    def _update_ticket_due_date(self, task_id: str) -> bool:
        """Update ticket due date in the integrated ticketing system."""
        if not self.integration:
            return False

        task = self.tasks.get(task_id)
        if not task or not task.get("ticket_id") or not task.get("due_date"):
            return False

        # Placeholder for actual ticket due date update implementation
        logger.info(f"Would update ticket {task.get('ticket_id')} due date to {task.get('due_date')}")

        return True

    def _send_status_notification(
        self,
        task_id: str,
        old_status: str,
        new_status: str
    ) -> bool:
        """Send notification for task status change."""
        if not self.notification_config or not self.tasks.get(task_id):
            return False

        # Placeholder for actual notification implementation
        logger.info(f"Would send notification for task {task_id} status change: {old_status} -> {new_status}")

        return True

    def _send_overdue_notifications(self, overdue_tasks: List[Dict[str, Any]]) -> bool:
        """Send notifications for overdue tasks."""
        if not self.notification_config or not overdue_tasks:
            return False

        # Placeholder for actual notification implementation
        logger.info(f"Would send notifications for {len(overdue_tasks)} overdue tasks")

        return True

    def _generate_report_data(self) -> Dict[str, Any]:
        """Generate data for status report."""
        # Get all tasks
        all_tasks = list(self.tasks.values())

        # Calculate summary statistics
        status_counts = {}
        for status in [s.value for s in RemediationStatus]:
            status_counts[status] = sum(1 for t in all_tasks if t.get("status") == status)

        severity_counts = {}
        for severity in [s.value for s in Severity]:
            severity_counts[severity] = sum(1 for t in all_tasks if t.get("severity") == severity)

        # Calculate open tasks by severity
        open_by_severity = {}
        for severity in [s.value for s in Severity]:
            open_by_severity[severity] = sum(
                1 for t in all_tasks
                if t.get("severity") == severity and t.get("status") not in [
                    RemediationStatus.CLOSED.value,
                    RemediationStatus.VERIFIED.value
                ]
            )

        # Calculate overdue tasks
        now = datetime.datetime.now()
        overdue_tasks = [
            t for t in all_tasks
            if t.get("status") not in [RemediationStatus.CLOSED.value, RemediationStatus.VERIFIED.value]
            and t.get("due_date") and datetime.datetime.fromisoformat(t["due_date"]) < now
        ]

        # Sort tasks by severity (critical first)
        tasks_by_severity = sorted(
            all_tasks,
            key=lambda t: {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4
            }.get(t.get("severity", "medium").lower(), 99)
        )

        # Build report data
        report_data = {
            "metadata": {
                "assessment_id": self.assessment_id,
                "generated_at": datetime.datetime.now().isoformat(),
                "total_tasks": len(all_tasks),
                "overdue_tasks": len(overdue_tasks)
            },
            "summary": {
                "status_counts": status_counts,
                "severity_counts": severity_counts,
                "open_by_severity": open_by_severity
            },
            "overdue_tasks": overdue_tasks,
            "tasks_by_severity": tasks_by_severity,
            "tasks_by_status": {
                status: [t for t in all_tasks if t.get("status") == status]
                for status in [s.value for s in RemediationStatus]
                if sum(1 for t in all_tasks if t.get("status") == status) > 0
            }
        }

        return report_data

    def _get_days_overdue(self, task: Dict[str, Any]) -> int:
        """Calculate days overdue for a task."""
        if not task.get("due_date"):
            return 0

        try:
            due_date = datetime.datetime.fromisoformat(task["due_date"])
            now = datetime.datetime.now()

            if now > due_date and task.get("status") not in [
                RemediationStatus.CLOSED.value,
                RemediationStatus.VERIFIED.value
            ]:
                return (now - due_date).days
        except (ValueError, TypeError):
            pass

        return 0

    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate an HTML report from the given data."""
        # Basic HTML structure
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remediation Status Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #2c3e50;
            border-bottom: 1px solid #bdc3c7;
            padding-bottom: 5px;
        }
        .metadata {
            margin-bottom: 20px;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        .summary-card {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 10px;
            min-width: 200px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .summary-card h3 {
            margin-top: 0;
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 5px;
        }
        .task-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .task-table th {
            background-color: #f8f9fa;
            text-align: left;
            padding: 8px;
            border-bottom: 2px solid #dee2e6;
        }
        .task-table td {
            padding: 8px;
            border-bottom: 1px solid #dee2e6;
        }
        .severity-critical {
            color: #721c24;
            background-color: #f8d7da;
        }
        .severity-high {
            color: #856404;
            background-color: #fff3cd;
        }
        .severity-medium {
            color: #0c5460;
            background-color: #d1ecf1;
        }
        .severity-low {
            color: #155724;
            background-color: #d4edda;
        }
        .progress-bar {
            background-color: #e9ecef;
            border-radius: 5px;
            height: 20px;
            overflow: hidden;
        }
        .progress {
            height: 100%;
            text-align: center;
            color: white;
            background-color: #007bff;
        }
        .overdue {
            font-weight: bold;
            color: #dc3545;
        }
        @media print {
            .no-print {
                display: none;
            }
        }
    </style>
</head>
<body>
    <h1>Remediation Status Report</h1>
    <div class="metadata">
        <p><strong>Generated:</strong> {generated_at}</p>
        <p><strong>Assessment ID:</strong> {assessment_id}</p>
    </div>
"""
        # Format date for report
        generated_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = html.format(generated_at=generated_at, assessment_id=self.assessment_id)

        # Summary section
        html += "<h2>Summary</h2>"
        html += '<div class="summary">'

        # Total tasks summary card
        html += """
        <div class="summary-card">
            <h3>Total Tasks</h3>
            <p style="font-size: 24px; text-align: center;">{total_tasks}</p>
        </div>
        """.format(total_tasks=report_data["metadata"]["total_tasks"])

        # Overdue tasks summary card
        html += """
        <div class="summary-card">
            <h3>Overdue Tasks</h3>
            <p style="font-size: 24px; text-align: center; color: {color};">{overdue_tasks}</p>
        </div>
        """.format(
            overdue_tasks=report_data["metadata"]["overdue_tasks"],
            color="#dc3545" if report_data["metadata"]["overdue_tasks"] > 0 else "#333"
        )

        # Status distribution card
        html += """
        <div class="summary-card">
            <h3>Status Distribution</h3>
            <table>
        """
        for status, count in report_data["summary"]["status_counts"].items():
            html += f"<tr><td>{status}:</td><td>{count}</td></tr>"
        html += "</table></div>"

        # Severity distribution card
        html += """
        <div class="summary-card">
            <h3>Severity Distribution</h3>
            <table>
        """
        for severity, count in report_data["summary"]["severity_counts"].items():
            html += f"<tr><td>{severity}:</td><td>{count}</td></tr>"
        html += "</table></div>"

        html += "</div>"  # End summary div

        # Overdue tasks section
        if report_data["overdue_tasks"]:
            html += "<h2>Overdue Tasks</h2>"
            html += """
            <table class="task-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Owner</th>
                        <th>Days Overdue</th>
                        <th>Due Date</th>
                    </tr>
                </thead>
                <tbody>
            """
            for task in report_data["overdue_tasks"]:
                days_overdue = self._get_days_overdue(task)
                severity = task.get("severity", "").lower()
                html += f"""
                    <tr class="severity-{severity}">
                        <td>{task.get("severity", "").upper()}</td>
                        <td>{task.get("title", "")}</td>
                        <td>{task.get("status", "")}</td>
                        <td>{task.get("owner", "Unassigned")}</td>
                        <td class="overdue">{days_overdue}</td>
                        <td>{task.get("due_date", "N/A")}</td>
                    </tr>
                """
            html += "</tbody></table>"

        # All tasks section
        html += "<h2>All Tasks</h2>"
        html += """
        <table class="task-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Status</th>
                    <th>Owner</th>
                    <th>Due Date</th>
                    <th>Days Overdue</th>
                </tr>
            </thead>
            <tbody>
        """

        for task in report_data["tasks_by_severity"]:
            days_overdue = self._get_days_overdue(task)
            severity = task.get("severity", "").lower()
            overdue_class = "overdue" if days_overdue > 0 else ""
            overdue_text = days_overdue if days_overdue > 0 else ""

            html += f"""
                <tr class="severity-{severity}">
                    <td>{task.get("severity", "").upper()}</td>
                    <td>{task.get("title", "")}</td>
                    <td>{task.get("status", "")}</td>
                    <td>{task.get("owner", "Unassigned")}</td>
                    <td>{task.get("due_date", "N/A")}</td>
                    <td class="{overdue_class}">{overdue_text}</td>
                </tr>
            """

        html += """
            </tbody>
        </table>
        """

        # Print button
        html += """
        <div class="no-print" style="text-align: center; margin: 30px 0;">
            <button onclick="window.print()" style="padding: 10px 20px; background-color: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer;">
                Print Report
            </button>
        </div>
        """

        # Footer
        html += """
        <div style="margin-top: 30px; text-align: center; color: #7f8c8d; font-size: 12px;">
            <p>Generated by Remediation Tracker | {timestamp}</p>
        </div>
        """.format(timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Close HTML
        html += """
    </body>
    </html>
        """

        return html

    def _generate_pdf_report(self, report_data: Dict[str, Any], output_file: str) -> str:
        """
        Generate a PDF report from the given data.

        Args:
            report_data: Dictionary with report data
            output_file: Path to save the PDF report

        Returns:
            Path to the generated PDF file
        """
        try:
            # First generate HTML report
            html_content = self._generate_html_report(report_data)

            # Try to use weasyprint if available
            try:
                from weasyprint import HTML
                HTML(string=html_content).write_pdf(output_file)
                logger.info(f"Generated PDF report: {output_file}")
                return output_file
            except ImportError:
                # Fall back to pdfkit if available
                try:
                    import pdfkit
                    pdfkit.from_string(html_content, output_file)
                    logger.info(f"Generated PDF report using pdfkit: {output_file}")
                    return output_file
                except ImportError:
                    logger.error("PDF generation requires weasyprint or pdfkit")
                    raise RuntimeError("PDF generation libraries not available")

        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise

    def _generate_text_report(self, report_data: Dict[str, Any]) -> str:
        """Generate a plain text report from the given data."""
        lines = []

        # Header
        lines.append("=" * 80)
        lines.append("REMEDIATION STATUS REPORT")
        lines.append("=" * 80)
        lines.append(f"Assessment ID: {self.assessment_id}")
        lines.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("-" * 80)

        # Summary
        lines.append("SUMMARY:")
        lines.append(f"Total Tasks: {report_data['metadata']['total_tasks']}")
        lines.append(f"Overdue Tasks: {report_data['metadata']['overdue_tasks']}")
        lines.append("")

        # Status distribution
        lines.append("Status Distribution:")
        for status, count in report_data["summary"]["status_counts"].items():
            lines.append(f"  {status}: {count}")

        lines.append("")

        # Severity distribution
        lines.append("Severity Distribution:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = report_data["summary"]["severity_counts"].get(severity, 0)
            lines.append(f"  {severity.upper()}: {count}")

        lines.append("-" * 80)

        # Overdue tasks
        if report_data["overdue_tasks"]:
            lines.append("OVERDUE TASKS:")
            for task in report_data["overdue_tasks"]:
                days_overdue = self._get_days_overdue(task)
                lines.append(f"[{task.get('severity', '').upper()}] {task.get('title', '')}")
                lines.append(f"  Status: {task.get('status', '')}")
                lines.append(f"  Owner: {task.get('owner', 'Unassigned')}")
                lines.append(f"  Days Overdue: {days_overdue}")
                lines.append(f"  Due Date: {task.get('due_date', 'N/A')}")
                lines.append("")

            lines.append("-" * 80)

        # All tasks
        lines.append("ALL TASKS:")
        for task in report_data["tasks_by_severity"]:
            days_overdue = self._get_days_overdue(task)
            overdue = f" (OVERDUE: {days_overdue} days)" if days_overdue > 0 else ""

            lines.append(f"[{task.get('severity', '').upper()}] {task.get('title', '')}")
            lines.append(f"  Status: {task.get('status', '')}")
            lines.append(f"  Owner: {task.get('owner', 'Unassigned')}")
            lines.append(f"  Due Date: {task.get('due_date', 'N/A')}{overdue}")
            lines.append("")

        # Footer
        lines.append("=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """Generate a Markdown report from the given data."""
        lines = []

        # Header
        lines.append("# Remediation Status Report")
        lines.append("")
        lines.append(f"**Assessment ID:** {self.assessment_id}  ")
        lines.append(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"**Total Tasks:** {report_data['metadata']['total_tasks']}  ")
        lines.append(f"**Overdue Tasks:** {report_data['metadata']['overdue_tasks']}  ")
        lines.append("")

        # Status distribution
        lines.append("### Status Distribution")
        lines.append("")
        for status, count in report_data["summary"]["status_counts"].items():
            lines.append(f"- **{status}:** {count}")
        lines.append("")

        # Severity distribution
        lines.append("### Severity Distribution")
        lines.append("")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = report_data["summary"]["severity_counts"].get(severity, 0)
            lines.append(f"- **{severity.upper()}:** {count}")
        lines.append("")

        # Overdue tasks
        if report_data["overdue_tasks"]:
            lines.append("## Overdue Tasks")
            lines.append("")
            lines.append("| Severity | Title | Status | Owner | Days Overdue | Due Date |")
            lines.append("|---------|-------|--------|-------|--------------|----------|")

            for task in report_data["overdue_tasks"]:
                days_overdue = self._get_days_overdue(task)
                severity = task.get("severity", "").upper()
                title = task.get("title", "").replace("|", "\\|")  # Escape pipe characters
                status = task.get("status", "").replace("|", "\\|")
                owner = task.get("owner", "Unassigned").replace("|", "\\|")
                due_date = task.get("due_date", "N/A")
                lines.append(f"| {severity} | {title} | {status} | {owner} | {days_overdue} | {due_date} |")

            lines.append("")

        # All tasks
        lines.append("## All Tasks")
        lines.append("")
        lines.append("| Severity | Title | Status | Owner | Due Date | Days Overdue |")
        lines.append("|---------|-------|--------|-------|----------|-------------|")

        for task in report_data["tasks_by_severity"]:
            days_overdue = self._get_days_overdue(task)
            severity = task.get("severity", "").upper()
            title = task.get("title", "").replace("|", "\\|")  # Escape pipe characters
            status = task.get("status", "").replace("|", "\\|")
            owner = task.get("owner", "Unassigned").replace("|", "\\|")
            due_date = task.get("due_date", "N/A")
            overdue_text = str(days_overdue) if days_overdue > 0 else ""

            lines.append(f"| {severity} | {title} | {status} | {owner} | {due_date} | {overdue_text} |")

        # Footer
        lines.append("")
        lines.append("---")
        lines.append(f"*Generated by Remediation Tracker on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(lines)

    def _calculate_metrics(self, include_historical: bool = False) -> Dict[str, Any]:
        """
        Calculate metrics about remediation progress.

        Args:
            include_historical: Whether to include historical metrics

        Returns:
            Dictionary with metrics
        """
        # Get all tasks
        all_tasks = list(self.tasks.values())

        # Basic metrics
        total_tasks = len(all_tasks)
        open_tasks = sum(1 for t in all_tasks if t.get("status") == RemediationStatus.OPEN.value)
        in_progress = sum(1 for t in all_tasks if t.get("status") == RemediationStatus.IN_PROGRESS.value)
        implemented = sum(1 for t in all_tasks if t.get("status") == RemediationStatus.IMPLEMENTED.value)
        verified = sum(1 for t in all_tasks if t.get("status") == RemediationStatus.VERIFIED.value)
        closed = sum(1 for t in all_tasks if t.get("status") == RemediationStatus.CLOSED.value)
        rejected = sum(1 for t in all_tasks if t.get("status") == RemediationStatus.REJECTED.value)
        risk_accepted = sum(1 for t in all_tasks if t.get("status") == RemediationStatus.RISK_ACCEPTED.value)

        # Calculate overdue tasks
        overdue_tasks = sum(1 for t in all_tasks if self.is_task_overdue(t))

        # Calculate average remediation time (in days)
        remediation_days = []
        for task in all_tasks:
            if task.get("creation_date") and task.get("verification_date"):
                try:
                    creation = datetime.datetime.fromisoformat(task["creation_date"])
                    verification = datetime.datetime.fromisoformat(task["verification_date"])
                    days = (verification - creation).days
                    remediation_days.append(days)
                except (ValueError, TypeError):
                    pass

        avg_remediation_time = sum(remediation_days) / len(remediation_days) if remediation_days else 0

        # Build metrics object
        metrics = {
            "summary": {
                "total_tasks": total_tasks,
                "open_tasks": open_tasks,
                "in_progress": in_progress,
                "implemented": implemented,
                "verified": verified,
                "closed": closed,
                "rejected": rejected,
                "risk_accepted": risk_accepted,
                "overdue_tasks": overdue_tasks,
                "avg_remediation_time": round(avg_remediation_time, 1)
            },
            "by_severity": {
                "critical": sum(1 for t in all_tasks if t.get("severity") == "critical"),
                "high": sum(1 for t in all_tasks if t.get("severity") == "high"),
                "medium": sum(1 for t in all_tasks if t.get("severity") == "medium"),
                "low": sum(1 for t in all_tasks if t.get("severity") == "low"),
                "info": sum(1 for t in all_tasks if t.get("severity") == "info")
            },
            "generated_at": datetime.datetime.now().isoformat()
        }

        # Add historical metrics if requested
        if include_historical:
            # This would be implemented based on your historical data storage approach
            # For example, you might retrieve snapshots from a database or previous reports
            metrics["historical"] = {
                "not_implemented": "Historical metrics functionality would go here"
            }

        return metrics

    def is_task_overdue(self, task: Dict[str, Any]) -> bool:
        """
        Check if a task is overdue.

        Args:
            task: Task dictionary to check

        Returns:
            Boolean indicating if the task is overdue
        """
        if not task.get("due_date"):
            return False

        try:
            due_date = datetime.datetime.fromisoformat(task["due_date"])
            now = datetime.datetime.now()

            return (now > due_date and task.get("status") not in [
                RemediationStatus.CLOSED.value,
                RemediationStatus.VERIFIED.value,
                RemediationStatus.RISK_ACCEPTED.value,
                RemediationStatus.REJECTED.value
            ])
        except (ValueError, TypeError):
            return False

        return False

    def get_severity_sort_key(self, severity: str) -> int:
        """
        Get a numeric value for sorting by severity.

        Args:
            severity: The severity string

        Returns:
            Integer value for sorting (higher is more severe)
        """
        severity_map = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0
        }

        return severity_map.get(severity.lower(), 0)

    def get_task_statistics(self, task_id: str) -> Dict[str, Any]:
        """
        Get detailed statistics for a specific task.

        Args:
            task_id: ID of the task to analyze

        Returns:
            Dictionary with task statistics

        Raises:
            ValueError: If task ID doesn't exist
        """
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        task = self.tasks[task_id]
        history = self._load_history()
        task_history = [event for event in history if event.get("task_id") == task_id]

        # Calculate statistics
        stats = {
            "task_id": task_id,
            "title": task.get("title"),
            "current_status": task.get("status"),
            "severity": task.get("severity"),
            "age_days": 0,
            "days_in_current_status": 0,
            "status_changes": len([e for e in task_history if e.get("action") == "status_update"]),
            "notes_count": len(task.get("notes", [])),
            "evidence_count": len(task.get("evidence", [])),
            "history_events": len(task_history),
            "is_overdue": self.is_task_overdue(task)
        }

        # Calculate age in days
        if task.get("creation_date"):
            try:
                creation = datetime.datetime.fromisoformat(task["creation_date"])
                now = datetime.datetime.now()
                stats["age_days"] = (now - creation).days
            except (ValueError, TypeError):
                pass

        # Calculate time in current status
        last_status_change = None
        for event in sorted(task_history, key=lambda e: e.get("timestamp", ""), reverse=True):
            if event.get("action") == "status_update" and event.get("details", {}).get("new_status") == task.get("status"):
                try:
                    last_status_change = datetime.datetime.fromisoformat(event["timestamp"])
                    now = datetime.datetime.now()
                    stats["days_in_current_status"] = (now - last_status_change).days
                    break
                except (ValueError, TypeError, KeyError):
                    pass

        return stats

    def generate_summary_report(self, output_format: str = "text") -> str:
        """
        Generate a brief summary report of remediation status.

        Args:
            output_format: Format for the summary (text or markdown)

        Returns:
            Summary report as a string
        """
        # Calculate basic metrics
        metrics = self._calculate_metrics()
        summary = metrics["summary"]
        by_severity = metrics["by_severity"]

        if output_format == "markdown":
            lines = [
                "# Remediation Summary",
                "",
                f"**Assessment ID:** {self.assessment_id}",
                f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "## Task Status",
                "",
                f"- **Total Tasks:** {summary['total_tasks']}",
                f"- **Open Tasks:** {summary['open_tasks']}",
                f"- **In Progress:** {summary['in_progress']}",
                f"- **Implemented:** {summary['implemented']}",
                f"- **Verified:** {summary['verified']}",
                f"- **Closed:** {summary['closed']}",
                f"- **Overdue:** {summary['overdue_tasks']}",
                "",
                "## Breakdown by Severity",
                "",
                f"- **Critical:** {by_severity['critical']}",
                f"- **High:** {by_severity['high']}",
                f"- **Medium:** {by_severity['medium']}",
                f"- **Low:** {by_severity['low']}",
                f"- **Info:** {by_severity['info']}",
                "",
                f"*Generated by Remediation Tracker on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
            ]
            return "\n".join(lines)
        else:
            lines = [
                "REMEDIATION SUMMARY",
                "=" * 80,
                f"Assessment ID: {self.assessment_id}",
                f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "TASK STATUS:",
                f"  Total Tasks: {summary['total_tasks']}",
                f"  Open Tasks: {summary['open_tasks']}",
                f"  In Progress: {summary['in_progress']}",
                f"  Implemented: {summary['implemented']}",
                f"  Verified: {summary['verified']}",
                f"  Closed: {summary['closed']}",
                f"  Overdue: {summary['overdue_tasks']}",
                "",
                "BREAKDOWN BY SEVERITY:",
                f"  Critical: {by_severity['critical']}",
                f"  High: {by_severity['high']}",
                f"  Medium: {by_severity['medium']}",
                f"  Low: {by_severity['low']}",
                f"  Info: {by_severity['info']}",
                "-" * 80
            ]
            return "\n".join(lines)


# Helper functions for module usage
def create_remediation_task(
    finding_id: str,
    title: str,
    description: str,
    severity: str,
    assessment_id: Optional[str] = None,
    **kwargs
) -> str:
    """
    Create a new remediation task.

    Args:
        finding_id: Unique identifier for the finding
        title: Short title describing the issue
        description: Detailed description of the finding
        severity: Severity level (critical, high, medium, low, info)
        assessment_id: Optional assessment ID
        **kwargs: Additional parameters for task creation

    Returns:
        Task ID of the created task
    """
    tracker = RemediationTracker(assessment_id=assessment_id)
    return tracker.create_task(
        finding_id=finding_id,
        title=title,
        description=description,
        severity=severity,
        **kwargs
    )

def update_task_status(
    task_id: str,
    status: str,
    assessment_id: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Update the status of a remediation task.

    Args:
        task_id: ID of the task to update
        status: New status for the task
        assessment_id: Optional assessment ID
        **kwargs: Additional parameters for status update

    Returns:
        Updated task data dictionary
    """
    tracker = RemediationTracker(assessment_id=assessment_id)
    return tracker.update_task_status(
        task_id=task_id,
        status=status,
        **kwargs
    )

def verify_remediation(
    task_id: str,
    success: bool = True,
    assessment_id: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Verify the remediation of a task.

    Args:
        task_id: ID of the task to verify
        success: Whether verification was successful
        assessment_id: Optional assessment ID
        **kwargs: Additional parameters for verification

    Returns:
        Dictionary with verification result
    """
    tracker = RemediationTracker(assessment_id=assessment_id)
    return tracker.verify_remediation(
        task_id=task_id,
        success=success,
        **kwargs
    )

def get_overdue_items(
    assessment_id: Optional[str] = None,
    days_threshold: Optional[int] = None,
    notify: bool = False
) -> List[Dict[str, Any]]:
    """
    Get overdue remediation items.

    Args:
        assessment_id: Optional assessment ID
        days_threshold: Optional threshold for days overdue
        notify: Whether to send notifications for overdue items

    Returns:
        List of overdue task dictionaries
    """
    tracker = RemediationTracker(assessment_id=assessment_id)
    return tracker.get_overdue_items(
        days_threshold=days_threshold,
        notify=notify
    )

def generate_status_report(
    assessment_id: Optional[str] = None,
    output_format: str = "html",
    output_file: Optional[str] = None
) -> Union[str, Dict[str, Any]]:
    """
    Generate a status report for remediation tasks.

    Args:
        assessment_id: Optional assessment ID
        output_format: Format for the report (html, json, pdf, markdown, text)
        output_file: Optional path to save the report

    Returns:
        Generated report content or path to output file
    """
    tracker = RemediationTracker(assessment_id=assessment_id)
    return tracker.generate_status_report(
        output_format=output_format,
        output_file=output_file
    )

def export_remediation_metrics(
    assessment_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Export metrics about remediation activities.

    Args:
        assessment_id: Optional assessment ID
        start_date: Optional start date for the metrics period (ISO format)
        end_date: Optional end date for the metrics period (ISO format)
        output_file: Optional path to save the metrics JSON

    Returns:
        Dictionary with remediation metrics
    """
    tracker = RemediationTracker(assessment_id=assessment_id)
    return tracker.export_remediation_metrics(
        start_date=start_date,
        end_date=end_date,
        output_file=output_file
    )

def main():
    """Command line interface for remediation tracker."""
    parser = argparse.ArgumentParser(description="Track and manage remediation of security findings")

    # Main subcommand structure
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create task command
    create_parser = subparsers.add_parser("create", help="Create a new remediation task")
    create_parser.add_argument("--finding-id", required=True, help="Finding identifier")
    create_parser.add_argument("--title", required=True, help="Task title")
    create_parser.add_argument("--description", required=True, help="Task description")
    create_parser.add_argument("--severity", required=True, choices=[s.value for s in Severity], help="Severity level")
    create_parser.add_argument("--target", help="Target system")
    create_parser.add_argument("--owner", help="Task owner")
    create_parser.add_argument("--due-date", help="Due date (YYYY-MM-DD)")
    create_parser.add_argument("--due-date-days", type=int, help="Days until due")
    create_parser.add_argument("--ticket-id", help="External ticketing system ID")

    # Update status command
    update_parser = subparsers.add_parser("update", help="Update task status")
    update_parser.add_argument("--task-id", required=True, help="Task identifier")
    update_parser.add_argument("--status", required=True, choices=[s.value for s in RemediationStatus], help="New status")
    update_parser.add_argument("--updated-by", help="Person making the update")
    update_parser.add_argument("--notes", help="Notes about the status change")

    # Verify remediation command
    verify_parser = subparsers.add_parser("verify", help="Verify remediation of a task")
    verify_parser.add_argument("--task-id", required=True, help="Task identifier")
    verify_parser.add_argument("--success", type=bool, default=True, help="Verification result")
    verify_parser.add_argument("--verifier", help="Person performing verification")
    verify_parser.add_argument("--notes", help="Notes about verification")

    # Get overdue items command
    overdue_parser = subparsers.add_parser("overdue", help="Get overdue remediation tasks")
    overdue_parser.add_argument("--days-threshold", type=int, help="Minimum days overdue")
    overdue_parser.add_argument("--notify", action="store_true", help="Send notifications for overdue tasks")
    overdue_parser.add_argument("--output", help="Output file for the list")
    overdue_parser.add_argument("--format", default="text", choices=VALID_OUTPUT_FORMATS, help="Output format")

    # Generate report command
    report_parser = subparsers.add_parser("report", help="Generate remediation status report")
    report_parser.add_argument("--output", help="Output file for the report")
    report_parser.add_argument("--format", default="html", choices=VALID_OUTPUT_FORMATS, help="Output format")

    # Export metrics command
    metrics_parser = subparsers.add_parser("metrics", help="Export remediation metrics")
    metrics_parser.add_argument("--start-date", help="Start date for metrics period (YYYY-MM-DD)")
    metrics_parser.add_argument("--end-date", help="End date for metrics period (YYYY-MM-DD)")
    metrics_parser.add_argument("--output", help="Output file for metrics")

    # Common arguments for all commands
    for subparser in [create_parser, update_parser, verify_parser, overdue_parser, report_parser, metrics_parser]:
        subparser.add_argument("--assessment-id", help="Assessment identifier")
        subparser.add_argument("--data-dir", help="Directory for remediation data")
        subparser.add_argument("--sla-config", help="Path to SLA configuration file")
        subparser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    # Parse arguments
    args = parser.parse_args()

    # Set up logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    # Initialize tracker
    tracker_kwargs = {
        "assessment_id": args.assessment_id,
        "data_dir": args.data_dir,
        "sla_config": args.sla_config if hasattr(args, "sla_config") else None
    }
    tracker = RemediationTracker(**{k: v for k, v in tracker_kwargs.items() if v is not None})

    # Execute command
    try:
        if args.command == "create":
            task_id = tracker.create_task(
                finding_id=args.finding_id,
                title=args.title,
                description=args.description,
                severity=args.severity,
                target=args.target,
                owner=args.owner,
                due_date=args.due_date,
                due_date_days=args.due_date_days,
                ticket_id=args.ticket_id
            )
            print(f"Created remediation task: {task_id}")

        elif args.command == "update":
            task = tracker.update_task_status(
                task_id=args.task_id,
                status=args.status,
                updated_by=args.updated_by,
                notes=args.notes
            )
            print(f"Updated task {args.task_id} status to {args.status}")

        elif args.command == "verify":
            result = tracker.verify_remediation(
                task_id=args.task_id,
                success=args.success,
                verifier=args.verifier,
                notes=args.notes
            )
            status = "successful" if args.success else "failed"
            print(f"Verification {status} for task {args.task_id}")

        elif args.command == "overdue":
            overdue_tasks = tracker.get_overdue_items(
                days_threshold=args.days_threshold,
                notify=args.notify
            )
            if not overdue_tasks:
                print("No overdue tasks found")
            else:
                print(f"Found {len(overdue_tasks)} overdue tasks:")
                for task in overdue_tasks:
                    days_overdue = tracker._get_days_overdue(task)
                    print(f"- [{task.get('severity', '').upper()}] {task.get('title')} (ID: {task.get('task_id')}, {days_overdue} days overdue)")

                if args.output:
                    if args.format == "json":
                        with open(args.output, 'w') as f:
                            json.dump(overdue_tasks, f, indent=2)
                    else:
                        # Simple text output
                        with open(args.output, 'w') as f:
                            for task in overdue_tasks:
                                days_overdue = tracker._get_days_overdue(task)
                                f.write(f"[{task.get('severity', '').upper()}] {task.get('title')}\n")
                                f.write(f"  Task ID: {task.get('task_id')}\n")
                                f.write(f"  Status: {task.get('status')}\n")
                                f.write(f"  Due Date: {task.get('due_date')}\n")
                                f.write(f"  Days Overdue: {days_overdue}\n\n")
                    print(f"Overdue tasks list saved to {args.output}")

        elif args.command == "report":
            result = tracker.generate_status_report(
                output_format=args.format,
                output_file=args.output
            )
            if args.output:
                print(f"Report generated and saved to {args.output}")
            else:
                print(result)

        elif args.command == "metrics":
            metrics = tracker.export_remediation_metrics(
                start_date=args.start_date,
                end_date=args.end_date,
                output_file=args.output
            )
            if args.output:
                print(f"Metrics exported to {args.output}")
            else:
                print(json.dumps(metrics, indent=2))

        else:
            parser.print_help()

    except Exception as e:
        logger.error(f"Error executing command: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
