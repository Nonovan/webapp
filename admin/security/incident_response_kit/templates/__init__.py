"""
Incident Response Documentation Templates

This module provides templates for standardized incident response documentation
and the necessary functionality for working with template variables.

Templates follow the NIST SP 800-61 framework for incident handling and provide
consistent documentation across different phases of the incident lifecycle.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Set

# Import core template functionality
from .template_variables import (
    # Enums
    TemplateType,
    VariableCategory,

    # Core variable dictionaries
    COMMON_VARIABLES,
    INCIDENT_REPORT_VARIABLES,
    TIMELINE_VARIABLES,
    CHAIN_OF_CUSTODY_VARIABLES,
    COMMUNICATION_VARIABLES,
    REMEDIATION_VARIABLES,
    TEMPLATE_VARIABLES,

    # Helper functions
    get_variable_categories,
    get_variables_by_category,
    get_variables_by_template
)

# Define module constants
TEMPLATE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_INCIDENT_TEMPLATE = "incident_report.md"
DEFAULT_TIMELINE_TEMPLATE = "incident_timeline.md"
DEFAULT_CHAIN_OF_CUSTODY_TEMPLATE = "chain_of_custody.md"
DEFAULT_COMMUNICATION_TEMPLATE = "communication_plan.md"
DEFAULT_EXECUTIVE_BRIEFING_TEMPLATE = "executive_briefing.md"
DEFAULT_REMEDIATION_TEMPLATE = "remediation_plan.md"

def get_available_templates() -> Dict[str, Path]:
    """
    Get a dictionary of available templates in the templates directory.

    Returns:
        Dict mapping template names to their Path objects
    """
    templates = {}
    for file_path in TEMPLATE_DIR.glob("*.md"):
        if file_path.is_file():
            templates[file_path.name] = file_path
    return templates

def get_template_path(template_name: str) -> Optional[Path]:
    """
    Get the full path to a specific template.

    Args:
        template_name: Name of the template file

    Returns:
        Path to the template if it exists, None otherwise
    """
    path = TEMPLATE_DIR / template_name
    return path if path.exists() else None

def render_template(template_name: str, variables: Dict[str, str]) -> Optional[str]:
    """
    Render a template with the provided variables.

    Args:
        template_name: Name of the template file
        variables: Dictionary of variables to substitute in the template

    Returns:
        The rendered template content, or None if the template doesn't exist
    """
    template_path = get_template_path(template_name)
    if not template_path:
        return None

    try:
        with open(template_path, 'r') as f:
            template_content = f.read()

        # Replace template variables
        for key, value in variables.items():
            template_content = template_content.replace(f"{{{{{key}}}}}", str(value))

        return template_content
    except Exception as e:
        print(f"Error rendering template {template_name}: {e}", file=sys.stderr)
        return None

def get_template_type(template_name: str) -> Optional[TemplateType]:
    """
    Determine the template type for a given template name.

    Args:
        template_name: Name of the template file

    Returns:
        TemplateType enum value if known, None otherwise
    """
    template_map = {
        "incident_report.md": TemplateType.INCIDENT_REPORT,
        "incident_timeline.md": TemplateType.INCIDENT_TIMELINE,
        "chain_of_custody.md": TemplateType.CHAIN_OF_CUSTODY,
        "communication_plan.md": TemplateType.COMMUNICATION_PLAN,
        "executive_briefing.md": TemplateType.EXECUTIVE_BRIEFING,
        "remediation_plan.md": TemplateType.REMEDIATION_PLAN
    }

    return template_map.get(template_name)

def get_template_variables(template_name: str) -> Dict[str, Dict[str, str]]:
    """
    Get all applicable variables for a specific template.

    Args:
        template_name: Name of the template file

    Returns:
        Dict of variables applicable to the template
    """
    template_type = get_template_type(template_name)
    if template_type:
        return get_variables_by_template(template_type)
    return COMMON_VARIABLES.copy()  # Default to common variables only

# Package exports
__all__ = [
    # Classes and enums
    'TemplateType',
    'VariableCategory',

    # Functions
    'get_variable_categories',
    'get_variables_by_category',
    'get_variables_by_template',
    'get_available_templates',
    'get_template_path',
    'render_template',
    'get_template_type',
    'get_template_variables',

    # Constants
    'TEMPLATE_DIR',
    'DEFAULT_INCIDENT_TEMPLATE',
    'DEFAULT_TIMELINE_TEMPLATE',
    'DEFAULT_CHAIN_OF_CUSTODY_TEMPLATE',
    'DEFAULT_COMMUNICATION_TEMPLATE',
    'DEFAULT_EXECUTIVE_BRIEFING_TEMPLATE',
    'DEFAULT_REMEDIATION_TEMPLATE',

    # Variable dictionaries
    'COMMON_VARIABLES',
    'INCIDENT_REPORT_VARIABLES',
    'TIMELINE_VARIABLES',
    'CHAIN_OF_CUSTODY_VARIABLES',
    'COMMUNICATION_VARIABLES',
    'REMEDIATION_VARIABLES',
    'TEMPLATE_VARIABLES'
]
