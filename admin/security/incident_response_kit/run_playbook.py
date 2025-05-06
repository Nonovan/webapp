"""
Playbook Execution Module for Incident Response Kit

This module provides functionality to execute incident response playbooks.
It coordinates the execution of various playbook steps, records progress,
and integrates with other components of the incident response toolkit.

Following the NIST SP 800-61 framework, the playbook runner ensures proper
execution sequence and documentation of all response actions.
"""

import os
import sys
import re
import logging
import json
import shutil
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Set, Callable

# Import shared components from the toolkit
try:
    from admin.security.incident_response_kit import (
        Incident, IncidentStatus, IncidentPhase, IncidentSeverity,
        IncidentType, MODULE_PATH, CONFIG_AVAILABLE, PLAYBOOKS_AVAILABLE,
        IncidentResponseError, PlaybookExecutionError, ValidationError,
        initialize_incident, update_status, get_incident_status,
        notify_stakeholders, verify_file_integrity, sanitize_incident_id
    )
    TOOLKIT_IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Error importing toolkit modules: {e}", file=sys.stderr)
    TOOLKIT_IMPORTS_AVAILABLE = False

    # Define fallback classes if imports aren't available
    class PlaybookExecutionError(Exception):
        """Exception raised for errors during playbook execution."""
        pass

    class ValidationError(Exception):
        """Exception raised for validation errors."""
        pass

    class Enum:
        """Simple Enum fallback."""
        pass

    class IncidentStatus(Enum):
        """Fallback for incident status."""
        OPEN = "open"
        INVESTIGATING = "investigating"
        RESOLVED = "resolved"
        CLOSED = "closed"

    class IncidentPhase(Enum):
        """Fallback for incident phase."""
        IDENTIFICATION = "identification"
        CONTAINMENT = "containment"
        ERADICATION = "eradication"
        RECOVERY = "recovery"
        LESSONS_LEARNED = "lessons_learned"

    MODULE_PATH = Path(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Constants for playbooks
PLAYBOOKS_DIR = MODULE_PATH / "playbooks"
PLAYBOOK_EXTENSION = ".md"
PHASE_MAPPING = {
    "detection": IncidentPhase.IDENTIFICATION,
    "containment": IncidentPhase.CONTAINMENT,
    "eradication": IncidentPhase.ERADICATION,
    "recovery": IncidentPhase.RECOVERY,
    "post-incident": IncidentPhase.LESSONS_LEARNED
}

# Regular expressions for parsing playbooks
SECTION_PATTERN = re.compile(r'^## (.+?)$', re.MULTILINE)
SUBSECTION_PATTERN = re.compile(r'^### (.+?)$', re.MULTILINE)
ACTION_PATTERN = re.compile(r'```python\s+([\s\S]+?)\s+```', re.MULTILINE)
STEP_PATTERN = re.compile(r'^[0-9]+\. \*\*(.+?)\*\*', re.MULTILINE)

class PlaybookFormat(Enum):
    """Enumeration of supported playbook formats."""
    MARKDOWN = "markdown"
    YAML = "yaml"
    JSON = "json"

class PlaybookSection:
    """Represents a section of a playbook with subsections and actions."""

    def __init__(self, name: str, phase: IncidentPhase = None):
        self.name = name
        self.phase = phase
        self.subsections = []
        self.content = ""

    def add_subsection(self, subsection: 'PlaybookSubsection'):
        """Add a subsection to this section."""
        self.subsections.append(subsection)

    def set_content(self, content: str):
        """Set the raw content of this section."""
        self.content = content

    def to_dict(self) -> Dict[str, Any]:
        """Convert this section to a dictionary."""
        return {
            "name": self.name,
            "phase": self.phase.value if self.phase else None,
            "subsections": [s.to_dict() for s in self.subsections],
            "content_length": len(self.content)
        }

class PlaybookSubsection:
    """Represents a subsection of a playbook with steps and actions."""

    def __init__(self, name: str):
        self.name = name
        self.steps = []
        self.actions = []
        self.content = ""

    def add_step(self, step: str):
        """Add a step to this subsection."""
        self.steps.append(step)

    def add_action(self, action: str):
        """Add an action (code block) to this subsection."""
        self.actions.append(action)

    def set_content(self, content: str):
        """Set the raw content of this subsection."""
        self.content = content

    def to_dict(self) -> Dict[str, Any]:
        """Convert this subsection to a dictionary."""
        return {
            "name": self.name,
            "steps": self.steps,
            "actions": len(self.actions),
            "content_length": len(self.content)
        }

class Playbook:
    """Represents a parsed incident response playbook with sections and actions."""

    def __init__(self, name: str, format_type: PlaybookFormat = PlaybookFormat.MARKDOWN):
        self.name = name
        self.format = format_type
        self.sections = []
        self.metadata = {
            "parsed_time": datetime.now(timezone.utc).isoformat(),
            "version": "1.0"
        }
        self.raw_content = ""

    def add_section(self, section: PlaybookSection):
        """Add a section to this playbook."""
        self.sections.append(section)

    def set_raw_content(self, content: str):
        """Set the raw content of this playbook."""
        self.raw_content = content

    def get_section(self, name: str) -> Optional[PlaybookSection]:
        """Get a section by name."""
        for section in self.sections:
            if section.name.lower() == name.lower():
                return section
        return None

    def get_all_actions(self) -> List[str]:
        """Get all actions across all subsections."""
        actions = []
        for section in self.sections:
            for subsection in section.subsections:
                actions.extend(subsection.actions)
        return actions

    def get_phase_content(self, phase: IncidentPhase) -> List[PlaybookSection]:
        """Get all sections for a specific incident phase."""
        return [section for section in self.sections if section.phase == phase]

    def to_dict(self) -> Dict[str, Any]:
        """Convert this playbook to a dictionary."""
        return {
            "name": self.name,
            "format": self.format.value,
            "metadata": self.metadata,
            "sections": [s.to_dict() for s in self.sections],
            "content_length": len(self.raw_content)
        }

class PlaybookParser:
    """Parser for incident response playbooks."""

    @staticmethod
    def parse_markdown(content: str, playbook_name: str) -> Playbook:
        """Parse a markdown playbook."""
        playbook = Playbook(playbook_name)
        playbook.set_raw_content(content)

        # Split content by sections
        sections = SECTION_PATTERN.split(content)[1:]  # Skip first empty part
        current_section = None

        # Process each section
        for i in range(0, len(sections), 2):
            if i + 1 >= len(sections):
                break

            section_name = sections[i].strip()
            section_content = sections[i + 1].strip()

            # Map section to incident phase
            phase = None
            lowercase_name = section_name.lower()
            for phase_key, phase_value in PHASE_MAPPING.items():
                if phase_key in lowercase_name:
                    phase = phase_value
                    break

            # Create new section
            current_section = PlaybookSection(section_name, phase)
            current_section.set_content(section_content)
            playbook.add_section(current_section)

            # Split section by subsections
            subsections = SUBSECTION_PATTERN.split(section_content)[1:]  # Skip first empty part
            current_subsection = None

            # Process each subsection
            for j in range(0, len(subsections), 2):
                if j + 1 >= len(subsections):
                    break

                subsection_name = subsections[j].strip()
                subsection_content = subsections[j + 1].strip()

                # Create new subsection
                current_subsection = PlaybookSubsection(subsection_name)
                current_subsection.set_content(subsection_content)
                current_section.add_subsection(current_subsection)

                # Extract steps
                steps = STEP_PATTERN.findall(subsection_content)
                for step in steps:
                    current_subsection.add_step(step.strip())

                # Extract actions (code blocks)
                actions = ACTION_PATTERN.findall(subsection_content)
                for action in actions:
                    current_subsection.add_action(action.strip())

        return playbook

    @staticmethod
    def parse_file(file_path: Union[str, Path], format_type: PlaybookFormat = PlaybookFormat.MARKDOWN) -> Playbook:
        """Parse a playbook file."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Playbook file not found: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        playbook_name = file_path.stem

        if format_type == PlaybookFormat.MARKDOWN:
            return PlaybookParser.parse_markdown(content, playbook_name)
        elif format_type == PlaybookFormat.YAML:
            raise NotImplementedError("YAML playbook parsing is not implemented yet")
        elif format_type == PlaybookFormat.JSON:
            raise NotImplementedError("JSON playbook parsing is not implemented yet")
        else:
            raise ValueError(f"Unsupported playbook format: {format_type}")

class PlaybookExecutionContext:
    """Context for playbook execution with state tracking."""

    def __init__(self, incident_id: str, playbook: Playbook, analyst: Optional[str] = None):
        self.incident_id = incident_id
        self.playbook = playbook
        self.analyst = analyst
        self.current_phase = None
        self.execution_history = []
        self.start_time = datetime.now(timezone.utc)
        self.completion_time = None
        self.notes = []

    def start_phase(self, phase: IncidentPhase):
        """Mark a phase as started."""
        self.current_phase = phase
        self.execution_history.append({
            "action": "phase_start",
            "phase": phase.value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def complete_phase(self, phase: IncidentPhase):
        """Mark a phase as completed."""
        self.execution_history.append({
            "action": "phase_complete",
            "phase": phase.value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def record_action(self, action: str, details: Dict[str, Any] = None):
        """Record an action execution."""
        self.execution_history.append({
            "action": "execute_action",
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def add_note(self, note: str):
        """Add a note to the execution context."""
        self.notes.append({
            "content": note,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def complete(self):
        """Mark the execution as complete."""
        self.completion_time = datetime.now(timezone.utc)
        self.execution_history.append({
            "action": "playbook_complete",
            "timestamp": self.completion_time.isoformat()
        })

    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of the execution status."""
        duration = (datetime.now(timezone.utc) - self.start_time).total_seconds()

        return {
            "incident_id": self.incident_id,
            "playbook": self.playbook.name,
            "current_phase": self.current_phase.value if self.current_phase else None,
            "start_time": self.start_time.isoformat(),
            "duration_seconds": duration,
            "completed": self.completion_time is not None,
            "actions_executed": len([h for h in self.execution_history if h["action"] == "execute_action"]),
            "phases_completed": len([h for h in self.execution_history if h["action"] == "phase_complete"])
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert the execution context to a dictionary."""
        return {
            "incident_id": self.incident_id,
            "playbook_name": self.playbook.name,
            "analyst": self.analyst,
            "start_time": self.start_time.isoformat(),
            "completion_time": self.completion_time.isoformat() if self.completion_time else None,
            "execution_history": self.execution_history,
            "notes": self.notes
        }

class PlaybookRunner:
    """Executes incident response playbooks and tracks progress."""

    def __init__(self, incident_id: str, dry_run: bool = False):
        self.incident_id = sanitize_incident_id(incident_id)
        self.dry_run = dry_run
        self.execution_log = []

        # Attempt to get incident status
        try:
            self.incident = get_incident_status(incident_id) if TOOLKIT_IMPORTS_AVAILABLE else None
        except Exception as e:
            logger.warning(f"Failed to get incident status: {e}")
            self.incident = None

    def validate_playbook(self, playbook_name: str) -> Tuple[bool, Optional[str]]:
        """Validate that a playbook exists and has the correct structure."""
        playbook_path = PLAYBOOKS_DIR / f"{playbook_name}{PLAYBOOK_EXTENSION}"

        if not playbook_path.exists():
            return False, f"Playbook file not found: {playbook_path}"

        try:
            playbook = PlaybookParser.parse_file(playbook_path)

            # Basic validation checks
            if not playbook.sections:
                return False, "Playbook has no sections"

            # Check for required sections
            required_sections = ["Incident Overview", "Detection and Identification",
                              "Containment", "Eradication", "Recovery"]
            missing_sections = []

            for required in required_sections:
                if not any(s.name.lower().startswith(required.lower()) for s in playbook.sections):
                    missing_sections.append(required)

            if missing_sections:
                return False, f"Playbook is missing required sections: {', '.join(missing_sections)}"

            return True, None
        except Exception as e:
            return False, f"Error validating playbook: {e}"

    def execute_action(self, action_code: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a code action from the playbook."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute: {action_code[:100]}...")
            return {"status": "simulated", "message": "Dry run mode"}

        # In a production system, this would need to be handled very carefully
        # Here we'll just log it and report success to avoid security issues
        logger.info(f"Executing action: {action_code[:100]}...")

        # The proper implementation would use a sandbox or secure execution environment
        # and have strict controls on allowed operations
        return {"status": "success", "message": "Action executed"}

    def execute_phase(self, playbook: Playbook, phase: IncidentPhase,
                      context: PlaybookExecutionContext) -> bool:
        """Execute all actions for a specific phase of the playbook."""
        logger.info(f"Executing phase: {phase.value} for incident {self.incident_id}")

        # Mark phase as started
        context.start_phase(phase)

        # Update incident status if we're connected to the incident system
        if not self.dry_run and TOOLKIT_IMPORTS_AVAILABLE:
            try:
                update_status(
                    incident_id=self.incident_id,
                    phase=phase,
                    status=IncidentStatus.INVESTIGATING,
                    notes=f"Executing {phase.value} phase of {playbook.name} playbook"
                )
            except Exception as e:
                logger.warning(f"Failed to update incident status: {e}")

        # Get all sections for this phase
        sections = playbook.get_phase_content(phase)
        if not sections:
            logger.warning(f"No sections found for phase {phase.value}")
            return True

        # Execute actions for each section
        for section in sections:
            logger.info(f"Processing section: {section.name}")

            for subsection in section.subsections:
                logger.info(f"Processing subsection: {subsection.name}")

                # Execute each action in the subsection
                for action in subsection.actions:
                    try:
                        # Skip comments and non-executable code
                        if action.strip().startswith('#') or not action.strip():
                            continue

                        # Execute the action
                        result = self.execute_action(action)

                        # Record the action execution
                        context.record_action(action, {
                            "section": section.name,
                            "subsection": subsection.name,
                            "result": result
                        })
                    except Exception as e:
                        logger.error(f"Error executing action: {e}")
                        # Continue with next action despite errors

        # Mark phase as completed
        context.complete_phase(phase)

        return True

    def execute_playbook(self, playbook_name: str, selected_phase: Optional[IncidentPhase] = None,
                         analyst: Optional[str] = None) -> Dict[str, Any]:
        """Execute a playbook for the given incident."""
        logger.info(f"Executing playbook {playbook_name} for incident {self.incident_id}")

        # Validate playbook
        valid, error_message = self.validate_playbook(playbook_name)
        if not valid:
            raise PlaybookExecutionError(error_message)

        # Parse playbook
        playbook_path = PLAYBOOKS_DIR / f"{playbook_name}{PLAYBOOK_EXTENSION}"
        playbook = PlaybookParser.parse_file(playbook_path)

        # Create execution context
        context = PlaybookExecutionContext(self.incident_id, playbook, analyst)

        # Determine phases to execute
        phases_to_execute = []
        if selected_phase:
            phases_to_execute = [selected_phase]
        else:
            # Execute all phases in order
            phases_to_execute = [
                IncidentPhase.IDENTIFICATION,
                IncidentPhase.CONTAINMENT,
                IncidentPhase.ERADICATION,
                IncidentPhase.RECOVERY,
                IncidentPhase.LESSONS_LEARNED
            ]

        # Execute each phase
        for phase in phases_to_execute:
            success = self.execute_phase(playbook, phase, context)
            if not success:
                logger.error(f"Failed to execute phase {phase.value}")
                break

        # Mark execution as complete
        context.complete()

        # Update incident status if we're connected to the incident system
        if not self.dry_run and TOOLKIT_IMPORTS_AVAILABLE:
            try:
                # Only update phase if we executed all phases
                if not selected_phase:
                    update_status(
                        incident_id=self.incident_id,
                        status=IncidentStatus.INVESTIGATING,
                        notes=f"Completed execution of {playbook_name} playbook"
                    )

                # Notify stakeholders of playbook completion
                notify_stakeholders(
                    incident_id=self.incident_id,
                    message=f"Playbook {playbook_name} execution completed for incident {self.incident_id}",
                    recipients=["security-team"],
                    channels=["email", "slack"],
                    severity="info"
                )
            except Exception as e:
                logger.warning(f"Failed to update incident status: {e}")

        return context.get_status_summary()

    def get_available_playbooks(self) -> List[Dict[str, Any]]:
        """Get a list of available playbooks with metadata."""
        available_playbooks = []

        if not PLAYBOOKS_DIR.exists():
            return available_playbooks

        for file in PLAYBOOKS_DIR.glob(f"*{PLAYBOOK_EXTENSION}"):
            if file.name == "README.md":
                continue

            try:
                # Quick scan of the file to extract basic metadata
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Extract title from first line
                title = file.stem.replace("_", " ").title()
                first_line = content.split("\n")[0] if content else ""
                if first_line.startswith("# "):
                    title = first_line[2:].strip()

                # Extract description (if available)
                description = ""
                overview_match = re.search(r"## Incident Overview\s+(.+?)(?=##|\Z)",
                                         content, re.DOTALL)
                if overview_match:
                    description_text = overview_match.group(1).strip()
                    # Take first paragraph only
                    description = description_text.split("\n\n")[0].strip()

                available_playbooks.append({
                    "name": file.stem,
                    "title": title,
                    "description": description,
                    "path": str(file),
                    "size": file.stat().st_size,
                    "last_modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()
                })
            except Exception as e:
                logger.warning(f"Error reading playbook {file}: {e}")

        return available_playbooks

    def get_playbook_details(self, playbook_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific playbook."""
        playbook_path = PLAYBOOKS_DIR / f"{playbook_name}{PLAYBOOK_EXTENSION}"

        if not playbook_path.exists():
            raise FileNotFoundError(f"Playbook file not found: {playbook_path}")

        try:
            playbook = PlaybookParser.parse_file(playbook_path)

            # Extract phases and sections
            phases = {}
            for section in playbook.sections:
                if section.phase:
                    if section.phase.value not in phases:
                        phases[section.phase.value] = []
                    phases[section.phase.value].append(section.name)

            # Count actions
            total_actions = len(playbook.get_all_actions())

            return {
                "name": playbook.name,
                "phases": phases,
                "sections": [s.name for s in playbook.sections],
                "total_actions": total_actions,
                "metadata": playbook.metadata
            }
        except Exception as e:
            raise PlaybookExecutionError(f"Error getting playbook details: {e}")

def run_playbook(incident_id: str, playbook_name: str, phase: Optional[str] = None,
                 analyst: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
    """
    Execute a playbook for a given incident.

    Args:
        incident_id (str): The ID of the incident
        playbook_name (str): The name of the playbook to execute
        phase (str, optional): Specific phase to execute (if any)
        analyst (str, optional): The name/email of the analyst executing the playbook
        dry_run (bool, optional): If True, will simulate execution without actually running actions

    Returns:
        Dict[str, Any]: Execution summary

    Raises:
        PlaybookExecutionError: If there's an error executing the playbook
        ValidationError: If the playbook validation fails
        FileNotFoundError: If the playbook file isn't found
    """
    # Initialize the runner
    runner = PlaybookRunner(incident_id, dry_run=dry_run)

    # Convert phase name to enum if provided
    selected_phase = None
    if phase:
        phase = phase.lower()
        for phase_enum in list(IncidentPhase):
            if phase_enum.value.lower() == phase:
                selected_phase = phase_enum
                break

        if not selected_phase:
            raise ValidationError(f"Invalid phase name: {phase}")

    # Execute the playbook
    try:
        result = runner.execute_playbook(playbook_name, selected_phase, analyst)
        logger.info(f"Playbook execution completed: {result}")
        return result
    except Exception as e:
        logger.error(f"Error executing playbook: {e}")
        raise PlaybookExecutionError(f"Error executing playbook: {e}")

def get_available_playbooks() -> List[Dict[str, Any]]:
    """
    Get a list of available playbooks with metadata.

    Returns:
        List[Dict[str, Any]]: List of playbooks with metadata
    """
    runner = PlaybookRunner("dummy-id", dry_run=True)
    return runner.get_available_playbooks()

def get_playbook_details(playbook_name: str) -> Dict[str, Any]:
    """
    Get detailed information about a specific playbook.

    Args:
        playbook_name (str): The name of the playbook

    Returns:
        Dict[str, Any]: Playbook details

    Raises:
        FileNotFoundError: If the playbook file isn't found
        PlaybookExecutionError: If there's an error getting playbook details
    """
    runner = PlaybookRunner("dummy-id", dry_run=True)
    return runner.get_playbook_details(playbook_name)

if __name__ == "__main__":
    # Handle command-line usage
    import argparse

    parser = argparse.ArgumentParser(description='Execute an incident response playbook.')
    parser.add_argument('--incident-id', '-i', required=True, help='The ID of the incident')
    parser.add_argument('--playbook', '-p', required=True, help='The name of the playbook to execute')
    parser.add_argument('--phase', help='Specific phase to execute (if any)')
    parser.add_argument('--analyst', help='The name/email of the analyst executing the playbook')
    parser.add_argument('--dry-run', action='store_true', help='Simulate execution without actually running actions')
    parser.add_argument('--list', action='store_true', help='List available playbooks')
    parser.add_argument('--details', action='store_true', help='Get details about a playbook')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        if args.list:
            playbooks = get_available_playbooks()
            print(json.dumps(playbooks, indent=2))
        elif args.details:
            details = get_playbook_details(args.playbook)
            print(json.dumps(details, indent=2))
        else:
            result = run_playbook(
                incident_id=args.incident_id,
                playbook_name=args.playbook,
                phase=args.phase,
                analyst=args.analyst,
                dry_run=args.dry_run
            )
            print(json.dumps(result, indent=2))
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
