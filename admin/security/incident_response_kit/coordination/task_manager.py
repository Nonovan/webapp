"""
Incident Response Kit - Task Manager

This module provides functionality for creating, assigning, updating, and tracking
tasks related to security incidents. It helps incident responders organize
response activities, assign responsibilities, track progress, and maintain
accountability throughout the incident handling process.

The task manager follows the NIST SP 800-61 incident handling framework and integrates
with other components of the incident response toolkit.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Union, Set

# Determine project root and add to sys.path if necessary
try:
    # Assumes this script is in admin/security/incident_response_kit/coordination
    ADMIN_DIR = Path(__file__).resolve().parents[3]
    if str(ADMIN_DIR) not in sys.path:
        sys.path.insert(0, str(ADMIN_DIR))

    # Import constants and shared functions
    from admin.security.incident_response_kit import (
        IncidentStatus, IncidentPhase, response_config, sanitize_incident_id,
        CONFIG_AVAILABLE, MODULE_PATH
    )

    # Import coordination components
    from admin.security.incident_response_kit.coordination.status_tracker import (
        get_incident_status, STORAGE_DIR as INCIDENT_STORAGE_DIR
    )

    # Import core security utilities for audit logging if available
    try:
        from core.security.cs_audit import log_security_event
        AUDIT_AVAILABLE = True
    except ImportError:
        AUDIT_AVAILABLE = False

except ImportError as e:
    print(f"Error importing project modules: {e}", file=sys.stderr)
    print("Ensure the script is run from within the project structure or PYTHONPATH is set correctly.", file=sys.stderr)

    # Define fallback constants if import fails, allowing basic operation
    class IncidentStatus:
        OPEN = "open"
        INVESTIGATING = "investigating"
        CONTAINED = "contained"
        ERADICATED = "eradicated"
        RECOVERING = "recovering"
        RESOLVED = "resolved"
        CLOSED = "closed"
        MERGED = "merged"

    class IncidentPhase:
        IDENTIFICATION = "identification"
        CONTAINMENT = "containment"
        ERADICATION = "eradication"
        RECOVERY = "recovery"
        LESSONS_LEARNED = "lessons_learned"

    response_config = {}
    CONFIG_AVAILABLE = False
    MODULE_PATH = Path(__file__).resolve().parent
    INCIDENT_STORAGE_DIR = Path("/secure/incidents")
    AUDIT_AVAILABLE = False

    def sanitize_incident_id(incident_id):
        """Sanitize incident ID for safety."""
        import re
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', incident_id)

    def get_incident_status(incident_id):
        """Placeholder for get_incident_status when not available."""
        return None

# --- Task Manager Configuration ---

# Configure logging
logger = logging.getLogger(__name__)
LOG_LEVEL = response_config.get("logging", {}).get("level", "INFO").upper()
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)

# Task storage configuration
STORAGE_DIR = response_config.get("task_manager", {}).get("storage_dir")
if not STORAGE_DIR:
    # Default to a tasks directory next to incidents
    STORAGE_DIR = INCIDENT_STORAGE_DIR.parent / "tasks" if INCIDENT_STORAGE_DIR else Path("/secure/tasks")
STORAGE_DIR = Path(STORAGE_DIR)

# File and directory permissions
FILE_PERMISSIONS = 0o600  # Owner read/write only
DIR_PERMISSIONS = 0o700   # Owner read/write/execute only

# Task configuration
MAX_CACHE_DURATION = 300    # Cache task data for 5 minutes
LOCKFILE_TIMEOUT = 30       # Seconds to wait for a lockfile before giving up
MAX_HISTORY_ITEMS = 100     # Maximum number of history items to keep per task

# In-memory cache for task data to reduce disk I/O
TASK_CACHE = {}            # Cache of task data by incident ID
TASK_CACHE_TIMESTAMPS = {} # Timestamps when tasks were last loaded

# --- Task priority and status enums ---

class TaskPriority(str, Enum):
    """Task priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_string(cls, priority_str):
        """Convert string to priority enum value, with fallback to MEDIUM."""
        try:
            return cls(priority_str.lower())
        except (ValueError, AttributeError):
            return cls.MEDIUM

class TaskStatus(str, Enum):
    """Task status values."""
    NEW = "new"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

    @classmethod
    def from_string(cls, status_str):
        """Convert string to status enum value, with fallback to NEW."""
        try:
            return cls(status_str.lower())
        except (ValueError, AttributeError):
            return cls.NEW

# --- Custom Exceptions ---

class TaskManagementError(Exception):
    """Base exception for task management errors."""
    pass

class TaskNotFoundError(TaskManagementError):
    """Exception raised when a task is not found."""
    pass

class ValidationError(TaskManagementError):
    """Exception raised for validation errors."""
    pass

class LockAcquisitionError(TaskManagementError):
    """Exception raised when a lock cannot be acquired."""
    pass

# --- Helper Functions ---

def get_tasks_file_path(incident_id: str) -> Path:
    """Get the path to the tasks data file for an incident."""
    incident_id = sanitize_incident_id(incident_id)
    return STORAGE_DIR / f"{incident_id}_tasks.json"

def get_tasks_lock_path(incident_id: str) -> Path:
    """Get the path to the tasks lock file for an incident."""
    incident_id = sanitize_incident_id(incident_id)
    return STORAGE_DIR / f"{incident_id}_tasks.lock"

def acquire_lock(incident_id: str) -> bool:
    """
    Acquire a lock for the tasks file of a specific incident.

    Args:
        incident_id: The incident ID

    Returns:
        True if lock was acquired, False otherwise
    """
    lock_file = get_tasks_lock_path(incident_id)

    # Try to acquire the lock for a limited time
    start_time = time.time()
    while time.time() - start_time < LOCKFILE_TIMEOUT:
        try:
            # Create the lock file if it doesn't exist
            with open(lock_file, 'x') as f:
                f.write(f"{os.getpid()},{time.time()}")
            os.chmod(lock_file, FILE_PERMISSIONS)
            return True
        except FileExistsError:
            # Lock file exists, check if it's stale
            try:
                with open(lock_file, 'r') as f:
                    content = f.read().strip()

                if ',' in content:
                    pid_str, timestamp_str = content.split(',', 1)
                    try:
                        pid = int(pid_str)
                        timestamp = float(timestamp_str)

                        # Check if the lock is stale (process doesn't exist or timeout exceeded)
                        if time.time() - timestamp > LOCKFILE_TIMEOUT:
                            logger.warning(f"Removing stale lock file for incident {incident_id}")
                            os.unlink(lock_file)
                            continue
                    except (ValueError, ProcessLookupError):
                        # Invalid content, assume stale lock
                        logger.warning(f"Removing invalid lock file for incident {incident_id}")
                        os.unlink(lock_file)
                        continue
            except OSError:
                pass  # Ignore errors checking lock file

            # Wait a bit before retrying
            time.sleep(0.5)

    logger.error(f"Failed to acquire lock for incident {incident_id}")
    return False

def release_lock(incident_id: str) -> None:
    """
    Release the lock for the tasks file of a specific incident.

    Args:
        incident_id: The incident ID
    """
    lock_file = get_tasks_lock_path(incident_id)
    try:
        if os.path.exists(lock_file):
            os.unlink(lock_file)
    except OSError as e:
        logger.warning(f"Error releasing lock for incident {incident_id}: {e}")

def get_current_timestamp() -> str:
    """Get the current timestamp as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()

def get_user_identity() -> str:
    """Get the current user's identity."""
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", "unknown")

def load_tasks(incident_id: str, bypass_cache: bool = False) -> Dict[str, Any]:
    """
    Load tasks for a specific incident.

    Args:
        incident_id: The incident ID
        bypass_cache: Whether to bypass the cache

    Returns:
        Dictionary with task data
    """
    incident_id = sanitize_incident_id(incident_id)

    # Check cache first unless bypass_cache is True
    if not bypass_cache and incident_id in TASK_CACHE:
        # Check if cache is still valid
        if incident_id in TASK_CACHE_TIMESTAMPS:
            cache_time = TASK_CACHE_TIMESTAMPS[incident_id]
            if time.time() - cache_time < MAX_CACHE_DURATION:
                return TASK_CACHE[incident_id]

    # Load from file
    tasks_file = get_tasks_file_path(incident_id)

    if not tasks_file.exists():
        # Initialize empty task structure
        tasks_data = {
            "incident_id": incident_id,
            "tasks": [],
            "metadata": {
                "created_at": get_current_timestamp(),
                "updated_at": get_current_timestamp(),
                "created_by": get_user_identity()
            }
        }
    else:
        try:
            with open(tasks_file, 'r') as f:
                tasks_data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading tasks for incident {incident_id}: {e}")
            tasks_data = {
                "incident_id": incident_id,
                "tasks": [],
                "metadata": {
                    "created_at": get_current_timestamp(),
                    "updated_at": get_current_timestamp(),
                    "created_by": get_user_identity(),
                    "error": f"Error loading previous data: {str(e)}"
                }
            }

    # Update cache
    TASK_CACHE[incident_id] = tasks_data
    TASK_CACHE_TIMESTAMPS[incident_id] = time.time()

    return tasks_data

def save_tasks(incident_id: str, tasks_data: Dict[str, Any], verify: bool = True) -> bool:
    """
    Save tasks for a specific incident.

    Args:
        incident_id: The incident ID
        tasks_data: Task data to save
        verify: Whether to verify the saved file

    Returns:
        True if save was successful, False otherwise
    """
    incident_id = sanitize_incident_id(incident_id)
    tasks_file = get_tasks_file_path(incident_id)

    # Ensure directory exists
    tasks_file.parent.mkdir(parents=True, exist_ok=True)

    # Acquire lock
    if not acquire_lock(incident_id):
        logger.error(f"Failed to acquire lock for saving tasks: {incident_id}")
        return False

    try:
        # Update timestamp
        tasks_data["metadata"]["updated_at"] = get_current_timestamp()

        # Create temp file for atomic write
        temp_file = tasks_file.with_suffix('.tmp')

        with open(temp_file, 'w') as f:
            json.dump(tasks_data, f, indent=2)

        # Set secure permissions
        os.chmod(temp_file, FILE_PERMISSIONS)

        # Verify the file can be read correctly
        if verify:
            try:
                with open(temp_file, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Verification of temporary file failed: {e}")
                os.unlink(temp_file)
                return False

        # Replace the real file with the temporary one
        if os.path.exists(tasks_file):
            backup_path = tasks_file.with_suffix('.bak')
            os.replace(tasks_file, backup_path)

        os.replace(temp_file, tasks_file)

        # Update cache
        TASK_CACHE[incident_id] = tasks_data
        TASK_CACHE_TIMESTAMPS[incident_id] = time.time()

        # Audit the save operation if available
        if AUDIT_AVAILABLE and 'log_security_event' in globals():
            try:
                log_security_event(
                    event_type="task_data_updated",
                    description=f"Task data updated for incident {incident_id}",
                    severity="info",
                    user_id=get_user_identity(),
                    metadata={
                        "incident_id": incident_id,
                        "task_count": len(tasks_data.get("tasks", []))
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to audit task data update: {e}")

        return True
    except Exception as e:
        logger.error(f"Error saving tasks for incident {incident_id}: {e}")
        return False
    finally:
        # Always release the lock
        release_lock(incident_id)

def prune_history(task: Dict[str, Any], max_items: int = MAX_HISTORY_ITEMS) -> Dict[str, Any]:
    """
    Prune task history to prevent unlimited growth.

    Args:
        task: Task dictionary
        max_items: Maximum number of history items to keep

    Returns:
        Task with pruned history
    """
    if "history" in task and len(task["history"]) > max_items:
        task["history"] = sorted(
            task["history"],
            key=lambda h: h.get("timestamp", ""),
            reverse=True
        )[:max_items]

    return task

def validate_task_fields(task_data: Dict[str, Any]) -> None:
    """
    Validate task fields.

    Args:
        task_data: Task data to validate

    Raises:
        ValidationError: If validation fails
    """
    required_fields = ["title", "description"]
    for field in required_fields:
        if field not in task_data or not task_data[field]:
            raise ValidationError(f"Missing required field: {field}")

    # Validate priority if present
    if "priority" in task_data:
        try:
            TaskPriority.from_string(task_data["priority"])
        except ValueError:
            raise ValidationError(f"Invalid priority value: {task_data['priority']}")

    # Validate status if present
    if "status" in task_data:
        try:
            TaskStatus.from_string(task_data["status"])
        except ValueError:
            raise ValidationError(f"Invalid status value: {task_data['status']}")

    # Validate deadline if present
    if "deadline" in task_data and task_data["deadline"]:
        try:
            # Check if deadline is a valid ISO format date
            datetime.fromisoformat(task_data["deadline"])
        except ValueError:
            raise ValidationError(f"Invalid deadline format: {task_data['deadline']}, use ISO format")

# --- Core Task Management Functions ---

def create_task(
    incident_id: str,
    title: str,
    description: str,
    priority: str = TaskPriority.MEDIUM,
    status: str = TaskStatus.NEW,
    assign_to: Optional[Union[str, List[str]]] = None,
    deadline: Optional[str] = None,
    tags: Optional[List[str]] = None,
    parent_task_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    user: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a new task for an incident.

    Args:
        incident_id: The incident ID
        title: Task title
        description: Task description
        priority: Task priority (critical, high, medium, low)
        status: Task status
        assign_to: Person or people assigned to the task
        deadline: Task deadline as ISO timestamp
        tags: List of tags for categorizing the task
        parent_task_id: ID of parent task if this is a subtask
        metadata: Additional task metadata
        user: User creating the task

    Returns:
        Created task information

    Raises:
        ValidationError: If task validation fails
        TaskManagementError: If task creation fails
    """
    incident_id = sanitize_incident_id(incident_id)
    user = user or get_user_identity()

    # Verify incident exists
    incident_data = get_incident_status(incident_id)
    if not incident_data:
        raise TaskManagementError(f"Incident not found: {incident_id}")

    # Format assignees consistently
    if assign_to is None:
        assignees = []
    elif isinstance(assign_to, str):
        assignees = [assign_to]
    else:
        assignees = list(assign_to)

    # Format tags
    if tags is None:
        tags = []

    # Normalize priority and status
    normalized_priority = TaskPriority.from_string(priority).value
    normalized_status = TaskStatus.from_string(status).value

    # Create task object
    timestamp = get_current_timestamp()
    task_id = f"{incident_id}-T{int(time.time())}"

    task = {
        "task_id": task_id,
        "incident_id": incident_id,
        "title": title,
        "description": description,
        "priority": normalized_priority,
        "status": normalized_status,
        "assignees": assignees,
        "created_at": timestamp,
        "updated_at": timestamp,
        "created_by": user,
        "history": [{
            "timestamp": timestamp,
            "action": "created",
            "user": user,
            "details": {
                "priority": normalized_priority,
                "status": normalized_status
            }
        }]
    }

    # Add optional fields
    if deadline:
        try:
            # Validate and normalize deadline
            task["deadline"] = datetime.fromisoformat(deadline).isoformat()
        except ValueError:
            raise ValidationError(f"Invalid deadline format: {deadline}, use ISO format")

    if tags:
        task["tags"] = tags

    if parent_task_id:
        task["parent_task_id"] = parent_task_id

    if metadata:
        task["metadata"] = metadata

    # Load existing tasks
    tasks_data = load_tasks(incident_id)

    # Add new task
    tasks_data["tasks"].append(task)

    # Update metadata
    tasks_data["metadata"]["updated_at"] = timestamp
    tasks_data["metadata"]["updated_by"] = user

    # Save tasks
    if not save_tasks(incident_id, tasks_data):
        raise TaskManagementError(f"Failed to save task for incident: {incident_id}")

    # Audit task creation if available
    if AUDIT_AVAILABLE and 'log_security_event' in globals():
        try:
            log_security_event(
                event_type="task_created",
                description=f"Task created for incident {incident_id}: {title}",
                severity="info",
                user_id=user,
                metadata={
                    "incident_id": incident_id,
                    "task_id": task_id,
                    "priority": normalized_priority
                }
            )
        except Exception as e:
            logger.warning(f"Failed to audit task creation: {e}")

    logger.info(f"Task created: {task_id} for incident {incident_id}")
    return task

def assign_task(
    incident_id: str,
    task_id: str,
    assignees: Union[str, List[str]],
    user: Optional[str] = None,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Assign a task to one or more people.

    Args:
        incident_id: The incident ID
        task_id: Task ID
        assignees: Person or people to assign the task to
        user: User making the assignment
        notes: Optional notes about the assignment

    Returns:
        Updated task information

    Raises:
        TaskNotFoundError: If the task is not found
        TaskManagementError: If task assignment fails
    """
    incident_id = sanitize_incident_id(incident_id)
    user = user or get_user_identity()

    # Format assignees consistently
    if isinstance(assignees, str):
        assignee_list = [assignees]
    else:
        assignee_list = list(assignees)

    # Load existing tasks
    tasks_data = load_tasks(incident_id)

    # Find the task
    task = None
    for t in tasks_data.get("tasks", []):
        if t.get("task_id") == task_id:
            task = t
            break

    if not task:
        raise TaskNotFoundError(f"Task not found: {task_id}")

    # Get previous assignees for history
    previous_assignees = task.get("assignees", [])

    # Update task
    timestamp = get_current_timestamp()
    task["assignees"] = assignee_list
    task["updated_at"] = timestamp

    # Update status if needed
    if task.get("status") == TaskStatus.NEW.value:
        task["status"] = TaskStatus.ASSIGNED.value

    # Add history entry
    history_entry = {
        "timestamp": timestamp,
        "action": "assigned",
        "user": user,
        "details": {
            "previous_assignees": previous_assignees,
            "new_assignees": assignee_list
        }
    }

    if notes:
        history_entry["notes"] = notes

    if "history" not in task:
        task["history"] = []

    task["history"].append(history_entry)

    # Prune history
    task = prune_history(task)

    # Update tasks data metadata
    tasks_data["metadata"]["updated_at"] = timestamp
    tasks_data["metadata"]["updated_by"] = user

    # Save tasks
    if not save_tasks(incident_id, tasks_data):
        raise TaskManagementError(f"Failed to save task assignment for incident: {incident_id}")

    # Audit task assignment if available
    if AUDIT_AVAILABLE and 'log_security_event' in globals():
        try:
            log_security_event(
                event_type="task_assigned",
                description=f"Task {task_id} assigned to {', '.join(assignee_list)}",
                severity="info",
                user_id=user,
                metadata={
                    "incident_id": incident_id,
                    "task_id": task_id,
                    "assignees": assignee_list
                }
            )
        except Exception as e:
            logger.warning(f"Failed to audit task assignment: {e}")

    logger.info(f"Task {task_id} assigned to {', '.join(assignee_list)} for incident {incident_id}")
    return task

def update_task_status(
    incident_id: str,
    task_id: str,
    status: str,
    user: Optional[str] = None,
    notes: Optional[str] = None,
    progress: Optional[int] = None
) -> Dict[str, Any]:
    """
    Update the status of a task.

    Args:
        incident_id: The incident ID
        task_id: Task ID
        status: New task status
        user: User updating the status
        notes: Optional notes about the status update
        progress: Optional progress percentage (0-100)

    Returns:
        Updated task information

    Raises:
        TaskNotFoundError: If the task is not found
        ValidationError: If the status is invalid
        TaskManagementError: If task update fails
    """
    incident_id = sanitize_incident_id(incident_id)
    user = user or get_user_identity()

    # Validate and normalize status
    try:
        normalized_status = TaskStatus.from_string(status).value
    except ValueError:
        valid_statuses = [s.value for s in TaskStatus]
        raise ValidationError(f"Invalid status: {status}. Valid values are: {', '.join(valid_statuses)}")

    # Load existing tasks
    tasks_data = load_tasks(incident_id)

    # Find the task
    task = None
    for t in tasks_data.get("tasks", []):
        if t.get("task_id") == task_id:
            task = t
            break

    if not task:
        raise TaskNotFoundError(f"Task not found: {task_id}")

    # Get previous status for history
    previous_status = task.get("status")

    # Update task
    timestamp = get_current_timestamp()
    task["status"] = normalized_status
    task["updated_at"] = timestamp

    # Add completion timestamp if the task is being completed
    if normalized_status == TaskStatus.COMPLETED.value and previous_status != TaskStatus.COMPLETED.value:
        task["completed_at"] = timestamp
        task["completed_by"] = user

    # Update progress if provided
    if progress is not None:
        # Validate progress value
        if not isinstance(progress, int) or progress < 0 or progress > 100:
            raise ValidationError("Progress must be an integer between 0 and 100")
        task["progress"] = progress

    # Add history entry
    history_entry = {
        "timestamp": timestamp,
        "action": "status_update",
        "user": user,
        "details": {
            "previous_status": previous_status,
            "new_status": normalized_status
        }
    }

    if notes:
        history_entry["notes"] = notes

    if progress is not None:
        history_entry["details"]["progress"] = progress

    if "history" not in task:
        task["history"] = []

    task["history"].append(history_entry)

    # Prune history
    task = prune_history(task)

    # Update tasks data metadata
    tasks_data["metadata"]["updated_at"] = timestamp
    tasks_data["metadata"]["updated_by"] = user

    # Save tasks
    if not save_tasks(incident_id, tasks_data):
        raise TaskManagementError(f"Failed to save task status update for incident: {incident_id}")

    # Audit task status update if available
    if AUDIT_AVAILABLE and 'log_security_event' in globals():
        try:
            log_security_event(
                event_type="task_status_updated",
                description=f"Task {task_id} status updated from {previous_status} to {normalized_status}",
                severity="info",
                user_id=user,
                metadata={
                    "incident_id": incident_id,
                    "task_id": task_id,
                    "previous_status": previous_status,
                    "new_status": normalized_status
                }
            )
        except Exception as e:
            logger.warning(f"Failed to audit task status update: {e}")

    logger.info(f"Task {task_id} status updated to {normalized_status} for incident {incident_id}")
    return task

def get_task(
    incident_id: str,
    task_id: str
) -> Dict[str, Any]:
    """
    Get a specific task.

    Args:
        incident_id: The incident ID
        task_id: Task ID

    Returns:
        Task information

    Raises:
        TaskNotFoundError: If the task is not found
    """
    incident_id = sanitize_incident_id(incident_id)

    # Load tasks
    tasks_data = load_tasks(incident_id)

    # Find the task
    for task in tasks_data.get("tasks", []):
        if task.get("task_id") == task_id:
            return task

    raise TaskNotFoundError(f"Task not found: {task_id}")

def get_task_list(
    incident_id: str,
    status: Optional[Union[str, List[str]]] = None,
    priority: Optional[Union[str, List[str]]] = None,
    assignee: Optional[str] = None,
    tags: Optional[List[str]] = None,
    include_completed: bool = True,
    include_cancelled: bool = False
) -> List[Dict[str, Any]]:
    """
    Get a list of tasks for an incident with optional filtering.

    Args:
        incident_id: The incident ID
        status: Filter by status or list of statuses
        priority: Filter by priority or list of priorities
        assignee: Filter by assignee
        tags: Filter by tags (tasks must have all specified tags)
        include_completed: Whether to include completed tasks
        include_cancelled: Whether to include cancelled tasks

    Returns:
        List of tasks
    """
    incident_id = sanitize_incident_id(incident_id)

    # Load tasks
    tasks_data = load_tasks(incident_id)
    tasks = tasks_data.get("tasks", [])

    # Prepare filters
    if status is not None:
        if isinstance(status, str):
            status_filters = [status.lower()]
        else:
            status_filters = [s.lower() for s in status]
    else:
        status_filters = None

    if priority is not None:
        if isinstance(priority, str):
            priority_filters = [priority.lower()]
        else:
            priority_filters = [p.lower() for p in priority]
    else:
        priority_filters = None

    # Apply filters
    filtered_tasks = []

    for task in tasks:
        # Skip completed tasks if not included
        if not include_completed and task.get("status") == TaskStatus.COMPLETED.value:
            continue

        # Skip cancelled tasks if not included
        if not include_cancelled and task.get("status") == TaskStatus.CANCELLED.value:
            continue

        # Filter by status
        if status_filters and (not task.get("status") or task["status"].lower() not in status_filters):
            continue

        # Filter by priority
        if priority_filters and (not task.get("priority") or task["priority"].lower() not in priority_filters):
            continue

        # Filter by assignee
        if assignee and (not task.get("assignees") or assignee not in task["assignees"]):
            continue

        # Filter by tags (task must have all specified tags)
        if tags:
            task_tags = task.get("tags", [])
            if not all(tag in task_tags for tag in tags):
                continue

        filtered_tasks.append(task)

    # Sort by priority (critical first) then creation date
    priority_order = {
        TaskPriority.CRITICAL.value: 0,
        TaskPriority.HIGH.value: 1,
        TaskPriority.MEDIUM.value: 2,
        TaskPriority.LOW.value: 3
    }

    def get_sort_key(task):
        priority = task.get("priority", TaskPriority.MEDIUM.value).lower()
        priority_val = priority_order.get(priority, 99)
        created_at = task.get("created_at", "")
        return (priority_val, created_at)

    filtered_tasks.sort(key=get_sort_key)

    return filtered_tasks

def add_task_comment(
    incident_id: str,
    task_id: str,
    comment: str,
    user: Optional[str] = None
) -> Dict[str, Any]:
    """
    Add a comment to a task.

    Args:
        incident_id: The incident ID
        task_id: Task ID
        comment: Comment text
        user: User adding the comment

    Returns:
        Updated task information

    Raises:
        TaskNotFoundError: If the task is not found
        ValidationError: If the comment is empty
        TaskManagementError: If comment addition fails
    """
    incident_id = sanitize_incident_id(incident_id)
    user = user or get_user_identity()

    # Validate comment
    if not comment or not comment.strip():
        raise ValidationError("Comment cannot be empty")

    # Load existing tasks
    tasks_data = load_tasks(incident_id)

    # Find the task
    task = None
    for t in tasks_data.get("tasks", []):
        if t.get("task_id") == task_id:
            task = t
            break

    if not task:
        raise TaskNotFoundError(f"Task not found: {task_id}")

    # Update task
    timestamp = get_current_timestamp()

    # Initialize comments list if it doesn't exist
    if "comments" not in task:
        task["comments"] = []

    # Add comment
    comment_entry = {
        "timestamp": timestamp,
        "user": user,
        "text": comment
    }

    task["comments"].append(comment_entry)
    task["updated_at"] = timestamp

    # Add history entry
    if "history" not in task:
        task["history"] = []

    task["history"].append({
        "timestamp": timestamp,
        "action": "comment_added",
        "user": user,
        "details": {
            "comment_count": len(task["comments"])
        }
    })

    # Prune history
    task = prune_history(task)

    # Update tasks data metadata
    tasks_data["metadata"]["updated_at"] = timestamp
    tasks_data["metadata"]["updated_by"] = user

    # Save tasks
    if not save_tasks(incident_id, tasks_data):
        raise TaskManagementError(f"Failed to save task comment for incident: {incident_id}")

    logger.info(f"Comment added to task {task_id} for incident {incident_id}")
    return task

def delete_task(
    incident_id: str,
    task_id: str,
    user: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Delete a task.

    Args:
        incident_id: The incident ID
        task_id: Task ID
        user: User deleting the task
        reason: Reason for deletion

    Returns:
        Result information

    Raises:
        TaskNotFoundError: If the task is not found
        TaskManagementError: If task deletion fails
    """
    incident_id = sanitize_incident_id(incident_id)
    user = user or get_user_identity()

    # Load existing tasks
    tasks_data = load_tasks(incident_id)

    # Find the task
    task_index = None
    for i, task in enumerate(tasks_data.get("tasks", [])):
        if task.get("task_id") == task_id:
            task_index = i
            deleted_task = task.copy()  # Keep a copy for the result
            break

    if task_index is None:
        raise TaskNotFoundError(f"Task not found: {task_id}")

    # Update metadata
    timestamp = get_current_timestamp()
    tasks_data["metadata"]["updated_at"] = timestamp
    tasks_data["metadata"]["updated_by"] = user

    # Record deletion in metadata
    if "deletions" not in tasks_data["metadata"]:
        tasks_data["metadata"]["deletions"] = []

    tasks_data["metadata"]["deletions"].append({
        "timestamp": timestamp,
        "task_id": task_id,
        "user": user,
        "reason": reason or "No reason provided"
    })

    # Remove the task
    tasks_data["tasks"].pop(task_index)

    # Save tasks
    if not save_tasks(incident_id, tasks_data):
        raise TaskManagementError(f"Failed to delete task for incident: {incident_id}")

    # Audit task deletion if available
    if AUDIT_AVAILABLE and 'log_security_event' in globals():
        try:
            log_security_event(
                event_type="task_deleted",
                description=f"Task {task_id} deleted from incident {incident_id}",
                severity="warning",  # Deletion is a higher severity audit event
                user_id=user,
                metadata={
                    "incident_id": incident_id,
                    "task_id": task_id,
                    "reason": reason
                }
            )
        except Exception as e:
            logger.warning(f"Failed to audit task deletion: {e}")

    logger.info(f"Task {task_id} deleted from incident {incident_id}")

    return {
        "success": True,
        "task_id": task_id,
        "incident_id": incident_id,
        "timestamp": timestamp,
        "deleted_task": deleted_task
    }

def create_subtask(
    incident_id: str,
    parent_task_id: str,
    title: str,
    description: str,
    priority: str = TaskPriority.MEDIUM,
    status: str = TaskStatus.NEW,
    assign_to: Optional[Union[str, List[str]]] = None,
    deadline: Optional[str] = None,
    tags: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    user: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a subtask for an existing task.

    Args:
        incident_id: The incident ID
        parent_task_id: Parent task ID
        title: Subtask title
        description: Subtask description
        priority: Subtask priority
        status: Subtask status
        assign_to: Person or people assigned to the subtask
        deadline: Subtask deadline
        tags: List of tags for categorizing the subtask
        metadata: Additional subtask metadata
        user: User creating the subtask

    Returns:
        Created subtask information

    Raises:
        TaskNotFoundError: If the parent task is not found
        TaskManagementError: If subtask creation fails
    """
    incident_id = sanitize_incident_id(incident_id)

    # First check if the parent task exists
    try:
        parent_task = get_task(incident_id, parent_task_id)
    except TaskNotFoundError:
        raise TaskNotFoundError(f"Parent task not found: {parent_task_id}")

    # Create the subtask
    subtask = create_task(
        incident_id=incident_id,
        title=title,
        description=description,
        priority=priority,
        status=status,
        assign_to=assign_to,
        deadline=deadline,
        tags=tags,
        parent_task_id=parent_task_id,
        metadata=metadata,
        user=user
    )

    return subtask

def generate_tasks_report(
    incident_id: str,
    output_format: str = "text",
    include_history: bool = False,
    include_comments: bool = True
) -> str:
    """
    Generate a report of tasks for an incident.

    Args:
        incident_id: The incident ID
        output_format: Output format (text, markdown, json)
        include_history: Whether to include task history
        include_comments: Whether to include task comments

    Returns:
        Report in the requested format
    """
    incident_id = sanitize_incident_id(incident_id)

    # Load tasks
    tasks_data = load_tasks(incident_id)
    tasks = tasks_data.get("tasks", [])

    # Get incident data if available
    incident_data = get_incident_status(incident_id)
    incident_info = {
        "id": incident_id,
        "status": incident_data.get("status", "unknown") if incident_data else "unknown",
        "phase": incident_data.get("current_phase", "unknown") if incident_data else "unknown"
    }

    # Generate report based on format
    if output_format.lower() == "json":
        # Create a copy to avoid modifying the original data
        report_data = {
            "incident": incident_info,
            "tasks_count": len(tasks),
            "tasks_by_status": {},
            "tasks_by_priority": {},
            "tasks": []
        }

        # Count tasks by status and priority
        status_counts = {}
        priority_counts = {}

        for task in tasks:
            # Count by status
            status = task.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            # Count by priority
            priority = task.get("priority", "unknown")
            priority_counts[priority] = priority_counts.get(priority, 0) + 1

            # Add task to report
            task_copy = task.copy()

            # Exclude history and comments if not requested
            if not include_history and "history" in task_copy:
                del task_copy["history"]

            if not include_comments and "comments" in task_copy:
                del task_copy["comments"]

            report_data["tasks"].append(task_copy)

        report_data["tasks_by_status"] = status_counts
        report_data["tasks_by_priority"] = priority_counts

        return json.dumps(report_data, indent=2)

    elif output_format.lower() == "markdown":
        lines = [
            f"# Tasks Report for Incident {incident_id}",
            "",
            f"**Incident Status:** {incident_info['status']}",
            f"**Incident Phase:** {incident_info['phase']}",
            f"**Total Tasks:** {len(tasks)}",
            f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Task Summary",
            ""
        ]

        # Count tasks by status
        status_counts = {}
        for task in tasks:
            status = task.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        # Add status counts
        lines.append("### By Status")
        lines.append("")
        for status, count in status_counts.items():
            lines.append(f"- **{status.capitalize()}:** {count}")

        lines.append("")

        # Count tasks by priority
        priority_counts = {}
        for task in tasks:
            priority = task.get("priority", "unknown")
            priority_counts[priority] = priority_counts.get(priority, 0) + 1

        # Add priority counts
        lines.append("### By Priority")
        lines.append("")
        for priority, count in priority_counts.items():
            lines.append(f"- **{priority.capitalize()}:** {count}")

        lines.append("")
        lines.append("## Task List")
        lines.append("")

        # Sort tasks by priority and status
        sorted_tasks = sorted(tasks, key=lambda x: (
            priority_order.get(x.get("priority"), 99),
            x.get("status") != TaskStatus.COMPLETED.value,  # Incomplete tasks first
            x.get("created_at", "")
        ))

        # Add task details
        for task in sorted_tasks:
            task_id = task.get("task_id", "unknown")
            title = task.get("title", "")
            status = task.get("status", "unknown").capitalize()
            priority = task.get("priority", "unknown").capitalize()
            assignees = ", ".join(task.get("assignees", []))

            lines.append(f"### {title} ({task_id})")
            lines.append("")
            lines.append(f"**Status:** {status}")
            lines.append(f"**Priority:** {priority}")

            if assignees:
                lines.append(f"**Assigned to:** {assignees}")

            if task.get("deadline"):
                lines.append(f"**Deadline:** {task.get('deadline')}")

            lines.append("")
            lines.append(task.get("description", ""))
            lines.append("")

            # Add comments if included
            if include_comments and task.get("comments"):
                lines.append("#### Comments")
                lines.append("")

                for comment in task.get("comments", []):
                    comment_time = datetime.fromisoformat(comment.get("timestamp", "")).strftime("%Y-%m-%d %H:%M")
                    comment_user = comment.get("user", "unknown")
                    comment_text = comment.get("text", "")

                    lines.append(f"**{comment_user}** ({comment_time}):")
                    lines.append("")
                    lines.append(comment_text)
                    lines.append("")

            # Add history if included
            if include_history and task.get("history"):
                lines.append("#### History")
                lines.append("")

                for entry in sorted(task.get("history", []), key=lambda x: x.get("timestamp", "")):
                    entry_time = datetime.fromisoformat(entry.get("timestamp", "")).strftime("%Y-%m-%d %H:%M")
                    entry_user = entry.get("user", "unknown")
                    entry_action = entry.get("action", "unknown")

                    lines.append(f"- **{entry_time}** - {entry_user}: {entry_action}")

                lines.append("")

        return "\n".join(lines)

    else:  # Plain text
        lines = [
            f"TASKS REPORT FOR INCIDENT {incident_id}",
            f"=============================={'=' * len(incident_id)}",
            "",
            f"Incident Status: {incident_info['status']}",
            f"Incident Phase:  {incident_info['phase']}",
            f"Total Tasks:     {len(tasks)}",
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "TASK SUMMARY",
            "============",
            ""
        ]

        # Count tasks by status
        status_counts = {}
        for task in tasks:
            status = task.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        # Add status counts
        lines.append("By Status:")
        for status, count in status_counts.items():
            lines.append(f"  {status.capitalize()}: {count}")

        lines.append("")

        # Count tasks by priority
        priority_counts = {}
        for task in tasks:
            priority = task.get("priority", "unknown")
            priority_counts[priority] = priority_counts.get(priority, 0) + 1

        # Add priority counts
        lines.append("By Priority:")
        for priority, count in priority_counts.items():
            lines.append(f"  {priority.capitalize()}: {count}")

        lines.append("")
        lines.append("TASK LIST")
        lines.append("=========")

        # Sort tasks by priority and status
        priority_order = {
            TaskPriority.CRITICAL.value: 0,
            TaskPriority.HIGH.value: 1,
            TaskPriority.MEDIUM.value: 2,
            TaskPriority.LOW.value: 3
        }

        sorted_tasks = sorted(tasks, key=lambda x: (
            priority_order.get(x.get("priority"), 99),
            x.get("status") != TaskStatus.COMPLETED.value,  # Incomplete tasks first
            x.get("created_at", "")
        ))

        # Add task details
        for task in sorted_tasks:
            task_id = task.get("task_id", "unknown")
            title = task.get("title", "")
            status = task.get("status", "unknown").capitalize()
            priority = task.get("priority", "unknown").capitalize()
            assignees = ", ".join(task.get("assignees", []))

            lines.append("")
            lines.append(f"{title} ({task_id})")
            lines.append("-" * (len(title) + len(task_id) + 3))
            lines.append(f"Status:   {status}")
            lines.append(f"Priority: {priority}")

            if assignees:
                lines.append(f"Assigned: {assignees}")

            if task.get("deadline"):
                lines.append(f"Deadline: {task.get('deadline')}")

            lines.append("")
            lines.append(task.get("description", ""))

            # Add comments if included
            if include_comments and task.get("comments"):
                lines.append("")
                lines.append("Comments:")
                lines.append("---------")

                for comment in task.get("comments", []):
                    comment_time = datetime.fromisoformat(comment.get("timestamp", "")).strftime("%Y-%m-%d %H:%M")
                    comment_user = comment.get("user", "unknown")
                    comment_text = comment.get("text", "")

                    lines.append(f"{comment_user} ({comment_time}):")
                    lines.append(comment_text)
                    lines.append("")

            # Add history if included
            if include_history and task.get("history"):
                lines.append("")
                lines.append("History:")
                lines.append("--------")

                for entry in sorted(task.get("history", []), key=lambda x: x.get("timestamp", "")):
                    entry_time = datetime.fromisoformat(entry.get("timestamp", "")).strftime("%Y-%m-%d %H:%M")
                    entry_user = entry.get("user", "unknown")
                    entry_action = entry.get("action", "unknown")

                    lines.append(f"{entry_time} - {entry_user}: {entry_action}")

                lines.append("")

        return "\n".join(lines)

# --- CLI Interface ---

def main():
    """Command-line interface for task manager."""
    parser = argparse.ArgumentParser(description="Manage tasks for security incidents.")
    parser.add_argument("--incident-id", required=True, help="Incident ID to manage tasks for.")

    # Action subparsers
    subparsers = parser.add_subparsers(dest="action", help="Action to perform.")

    # Create task
    create_parser = subparsers.add_parser("create", help="Create a new task.")
    create_parser.add_argument("--title", required=True, help="Task title.")
    create_parser.add_argument("--description", required=True, help="Task description.")
    create_parser.add_argument("--priority", choices=[p.value for p in TaskPriority], default=TaskPriority.MEDIUM.value,
                              help="Task priority.")
    create_parser.add_argument("--assign-to", help="Comma-separated list of assignees.")
    create_parser.add_argument("--deadline", help="Task deadline in ISO format (YYYY-MM-DDTHH:MM:SS).")
    create_parser.add_argument("--tags", help="Comma-separated list of tags.")

    # Assign task
    assign_parser = subparsers.add_parser("assign", help="Assign a task.")
    assign_parser.add_argument("--task-id", required=True, help="Task ID to assign.")
    assign_parser.add_argument("--assign-to", required=True, help="Comma-separated list of assignees.")
    assign_parser.add_argument("--notes", help="Notes about the assignment.")

    # Update task status
    status_parser = subparsers.add_parser("status", help="Update task status.")
    status_parser.add_argument("--task-id", required=True, help="Task ID to update.")
    status_parser.add_argument("--status", required=True, choices=[s.value for s in TaskStatus], help="New task status.")
    status_parser.add_argument("--notes", help="Notes about the status update.")
    status_parser.add_argument("--progress", type=int, help="Progress percentage (0-100).")

    # List tasks
    list_parser = subparsers.add_parser("list", help="List tasks.")
    list_parser.add_argument("--status", help="Filter by comma-separated status values.")
    list_parser.add_argument("--priority", help="Filter by comma-separated priority values.")
    list_parser.add_argument("--assignee", help="Filter by assignee.")
    list_parser.add_argument("--tags", help="Filter by comma-separated tags.")
    list_parser.add_argument("--hide-completed", action="store_true", help="Hide completed tasks.")
    list_parser.add_argument("--include-cancelled", action="store_true", help="Include cancelled tasks.")
    list_parser.add_argument("--format", choices=["text", "markdown", "json"], default="text", help="Output format.")

    # Add comment
    comment_parser = subparsers.add_parser("comment", help="Add a comment to a task.")
    comment_parser.add_argument("--task-id", required=True, help="Task ID to comment on.")
    comment_parser.add_argument("--text", required=True, help="Comment text.")

    # Delete task
    delete_parser = subparsers.add_parser("delete", help="Delete a task.")
    delete_parser.add_argument("--task-id", required=True, help="Task ID to delete.")
    delete_parser.add_argument("--reason", help="Reason for deletion.")

    # Generate report
    report_parser = subparsers.add_parser("report", help="Generate a tasks report.")
    report_parser.add_argument("--format", choices=["text", "markdown", "json"], default="text", help="Output format.")
    report_parser.add_argument("--include-history", action="store_true", help="Include task history.")
    report_parser.add_argument("--hide-comments", action="store_true", help="Hide task comments.")
    report_parser.add_argument("--output", help="Output file path. If omitted, prints to stdout.")

    # User identification
    parser.add_argument("--user", help="User performing the action (defaults to current user).")

    args = parser.parse_args()

    try:
        # Ensure storage directory exists
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

        # Set appropriate directory permissions
        os.chmod(STORAGE_DIR, DIR_PERMISSIONS)

        # Get user
        user = args.user or get_user_identity()

        # Perform the requested action
        if args.action == "create":
            # Parse assign-to and tags if provided
            assignees = args.assign_to.split(",") if args.assign_to else []
            tags = args.tags.split(",") if args.tags else []

            task = create_task(
                incident_id=args.incident_id,
                title=args.title,
                description=args.description,
                priority=args.priority,
                assign_to=assignees,
                deadline=args.deadline,
                tags=tags,
                user=user
            )

            print(f"Task created with ID: {task['task_id']}")

        elif args.action == "assign":
            # Parse assign-to
            assignees = args.assign_to.split(",")

            task = assign_task(
                incident_id=args.incident_id,
                task_id=args.task_id,
                assignees=assignees,
                user=user,
                notes=args.notes
            )

            print(f"Task {task['task_id']} assigned to: {', '.join(task['assignees'])}")

        elif args.action == "status":
            task = update_task_status(
                incident_id=args.incident_id,
                task_id=args.task_id,
                status=args.status,
                user=user,
                notes=args.notes,
                progress=args.progress
            )

            print(f"Task {task['task_id']} status updated to: {task['status']}")

        elif args.action == "list":
            # Parse status, priority, and tags if provided
            status_filters = args.status.split(",") if args.status else None
            priority_filters = args.priority.split(",") if args.priority else None
            tag_filters = args.tags.split(",") if args.tags else None

            tasks = get_task_list(
                incident_id=args.incident_id,
                status=status_filters,
                priority=priority_filters,
                assignee=args.assignee,
                tags=tag_filters,
                include_completed=not args.hide_completed,
                include_cancelled=args.include_cancelled
            )

            if args.format == "json":
                print(json.dumps(tasks, indent=2))
            elif args.format == "markdown":
                print(f"# Tasks for Incident {args.incident_id}")
                print(f"\n**Total Tasks:** {len(tasks)}\n")

                for task in tasks:
                    print(f"## {task['title']} ({task['task_id']})")
                    print(f"**Status:** {task['status']}")
                    print(f"**Priority:** {task['priority']}")

                    if task.get("assignees"):
                        print(f"**Assigned to:** {', '.join(task['assignees'])}")

                    if task.get("deadline"):
                        print(f"**Deadline:** {task['deadline']}")

                    print(f"\n{task['description']}\n")
            else:
                print(f"Tasks for incident {args.incident_id}:")
                print(f"Total: {len(tasks)}")
                print("")

                for task in tasks:
                    assignees = ", ".join(task.get("assignees", []))
                    assignee_info = f" (Assigned: {assignees})" if assignees else ""
                    deadline_info = f" (Due: {task.get('deadline')})" if task.get("deadline") else ""

                    print(f"[{task['priority'].upper()}] [{task['status']}] {task['task_id']}: {task['title']}{assignee_info}{deadline_info}")

        elif args.action == "comment":
            task = add_task_comment(
                incident_id=args.incident_id,
                task_id=args.task_id,
                comment=args.text,
                user=user
            )

            print(f"Comment added to task {task['task_id']}")

        elif args.action == "delete":
            result = delete_task(
                incident_id=args.incident_id,
                task_id=args.task_id,
                user=user,
                reason=args.reason
            )

            print(f"Task {result['task_id']} deleted from incident {result['incident_id']}")

        elif args.action == "report":
            report = generate_tasks_report(
                incident_id=args.incident_id,
                output_format=args.format,
                include_history=args.include_history,
                include_comments=not args.hide_comments
            )

            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"Report written to {args.output}")
            else:
                print(report)
        else:
            parser.print_help()

    except TaskNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ValidationError as e:
        print(f"Validation error: {e}")
        sys.exit(1)
    except TaskManagementError as e:
        print(f"Task management error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        logger.exception(f"Unexpected error in task manager: {e}")
        sys.exit(1)

# Make the script executable
if __name__ == "__main__":
    main()
