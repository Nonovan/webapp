"""
Supporting Scripts for Security Assessments

This package provides supporting scripts and utilities used across the security assessment tools
in the Cloud Infrastructure Platform. These scripts provide standardized functionality for report
generation, finding classification, evidence collection, remediation tracking, and assessment
coordination.

Components:
- assessment_utils: Shared utilities for configuration management, target discovery, and validation
- report_generator: Creates standardized security assessment reports from assessment results
- finding_classifier: Classifies and prioritizes security findings with business impact analysis
- remediation_tracker: Tracks remediation status with SLA monitoring and notification
- evidence_collector: Securely collects and stores assessment evidence with chain of custody
- assessment_coordinator: Coordinates multi-component security assessments

These scripts are designed to integrate with the core assessment tools and provide
consistent report formats, remediation workflows, and evidence management across
all security assessment activities.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

# Setup package logger with null handler to prevent no-handler warnings
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Package version
__version__ = '0.1.1'

# Add parent directory to path to allow imports from assessment_tools
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import availability flags
ASSESSMENT_UTILS_AVAILABLE = False
REPORT_GENERATOR_AVAILABLE = False
FINDING_CLASSIFIER_AVAILABLE = False
REMEDIATION_TRACKER_AVAILABLE = False
EVIDENCE_COLLECTOR_AVAILABLE = False
ASSESSMENT_COORDINATOR_AVAILABLE = False

# Try importing assessment_utils
try:
    from .assessment_utils import (
        load_config,
        get_config_path,
        get_available_profiles,
        validate_profile,
        get_targets_from_group,
        create_assessment_target,
        read_targets_from_file,
        format_findings_for_tickets,
        create_tickets,
        update_tickets,
        run_assessment_tool,
        validate_assessment_results,
        merge_assessment_results
    )
    ASSESSMENT_UTILS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"assessment_utils not fully available: {e}")

# Try importing report_generator
try:
    from .report_generator import (
        ReportGenerator,
        generate_report,
        generate_executive_summary,
        generate_technical_report,
        generate_compliance_report
    )
    REPORT_GENERATOR_AVAILABLE = True
except ImportError as e:
    logger.debug(f"report_generator not fully available: {e}")

# Try importing finding_classifier
try:
    from .finding_classifier import (
        FindingClassifier,
        classify_finding,
        classify_findings_batch,
        calculate_cvss_score,
        calculate_business_impact,
        map_to_compliance_requirements
    )
    FINDING_CLASSIFIER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"finding_classifier not fully available: {e}")

# Try importing remediation_tracker
try:
    from .remediation_tracker import (
        RemediationTracker,
        create_remediation_task,
        update_task_status,
        verify_remediation,
        get_overdue_items,
        generate_status_report,
        export_remediation_metrics
    )
    REMEDIATION_TRACKER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"remediation_tracker not fully available: {e}")

# Try importing assessment_coordinator
try:
    from .assessment_coordinator import (
        AssessmentCoordinator,
        run_coordinated_assessment,
        schedule_assessment,
        get_assessment_status,
        generate_consolidated_report,
        cancel_assessment
    )
    ASSESSMENT_COORDINATOR_AVAILABLE = True
except ImportError as e:
    logger.debug(f"assessment_coordinator not fully available: {e}")

def get_available_scripts() -> Dict[str, bool]:
    """
    Get a dictionary of available supporting scripts.

    Returns:
        Dictionary mapping script names to their availability status
    """
    return {
        'assessment_utils': ASSESSMENT_UTILS_AVAILABLE,
        'report_generator': REPORT_GENERATOR_AVAILABLE,
        'finding_classifier': FINDING_CLASSIFIER_AVAILABLE,
        'remediation_tracker': REMEDIATION_TRACKER_AVAILABLE,
        'assessment_coordinator': ASSESSMENT_COORDINATOR_AVAILABLE
    }

def initialize_supporting_scripts(config_path: Optional[str] = None) -> bool:
    """
    Initialize supporting scripts with optional configuration.

    Args:
        config_path: Optional path to configuration file

    Returns:
        True if initialization was successful
    """
    try:
        # Load configuration if path provided
        if config_path:
            if ASSESSMENT_UTILS_AVAILABLE:
                config = load_config(config_path)
                logger.info(f"Loaded supporting scripts configuration from {config_path}")
            else:
                logger.warning("Cannot load configuration: assessment_utils not available")
                return False

        # Log initialization status
        available_scripts = [name for name, available in get_available_scripts().items() if available]
        if available_scripts:
            logger.info(f"Supporting scripts initialized with: {', '.join(available_scripts)}")
        else:
            logger.warning("No supporting scripts available")

        return True

    except Exception as e:
        logger.error(f"Error initializing supporting scripts: {e}", exc_info=True)
        return False

# Define exports
__all__ = [
    # Version and utility functions
    '__version__',
    'get_available_scripts',
    'initialize_supporting_scripts'
]

# Add module exports based on availability
if ASSESSMENT_UTILS_AVAILABLE:
    __all__.extend([
        'load_config',
        'get_config_path',
        'get_available_profiles',
        'validate_profile',
        'get_targets_from_group',
        'create_assessment_target',
        'read_targets_from_file',
        'format_findings_for_tickets',
        'create_tickets',
        'update_tickets',
        'run_assessment_tool',
        'validate_assessment_results',
        'merge_assessment_results'
    ])

if REPORT_GENERATOR_AVAILABLE:
    __all__.extend([
        'ReportGenerator',
        'generate_report',
        'generate_executive_summary',
        'generate_technical_report',
        'generate_compliance_report'
    ])

if FINDING_CLASSIFIER_AVAILABLE:
    __all__.extend([
        'FindingClassifier',
        'classify_finding',
        'classify_findings_batch',
        'calculate_cvss_score',
        'calculate_business_impact',
        'map_to_compliance_requirements'
    ])

if REMEDIATION_TRACKER_AVAILABLE:
    __all__.extend([
        'RemediationTracker',
        'create_remediation_task',
        'update_task_status',
        'verify_remediation',
        'get_overdue_items',
        'generate_status_report',
        'export_remediation_metrics'
    ])

if ASSESSMENT_COORDINATOR_AVAILABLE:
    __all__.extend([
        'AssessmentCoordinator',
        'run_coordinated_assessment',
        'schedule_assessment',
        'get_assessment_status',
        'generate_consolidated_report',
        'cancel_assessment'
    ])

# Log initialization
active_scripts = [name for name, available in get_available_scripts().items() if available]
if active_scripts:
    logger.debug(f"Supporting scripts package initialized with: {', '.join(active_scripts)}")
else:
    logger.debug("Supporting scripts package initialized but no modules are available.")
