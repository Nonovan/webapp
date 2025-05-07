"""
Anomaly Detection System

This module provides a Python interface to the anomaly detection system
implemented in the anomaly_detector.sh script. It allows for programmatic
initialization, configuration, and execution of behavioral anomaly detection.

The system detects anomalies in user behavior, system metrics, and network traffic
based on predefined baselines and detection rules.
"""

import os
import sys
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple

# Import constants if available
try:
    from .monitoring_constants import DETECTION_SENSITIVITY, DEFAULT_DETECTION_THRESHOLDS
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False

# Configure module logger
logger = logging.getLogger(__name__)

# Constants
SCRIPT_PATH = Path(__file__).parent / "anomaly_detector.sh"
DEFAULT_CONFIG_DIR = Path(__file__).parent / "config"
DEFAULT_BASELINE_DIR = DEFAULT_CONFIG_DIR / "baseline"
DEFAULT_RULES_DIR = DEFAULT_CONFIG_DIR / "detection_rules"

def initialize_detection(baseline_path: Optional[str] = None) -> bool:
    """
    Initialize the anomaly detection system with an optional custom baseline.

    This function sets up the anomaly detection system by configuring the baseline,
    detection rules, and ensuring necessary directories exist. It serves as a
    Python wrapper around the anomaly_detector.sh script's initialization logic.

    Args:
        baseline_path: Optional path to a custom behavioral baseline file
                      If not provided, default baseline for the environment will be used

    Returns:
        bool: True if initialization was successful, False otherwise
    """
    try:
        logger.info("Initializing anomaly detection system")

        # Check if script exists
        if not SCRIPT_PATH.exists():
            logger.error(f"Anomaly detector script not found at: {SCRIPT_PATH}")
            return False

        # Ensure the script is executable
        try:
            SCRIPT_PATH.chmod(SCRIPT_PATH.stat().st_mode | 0o111)
        except Exception as e:
            logger.warning(f"Could not set script executable: {e}")

        # Build initialization command
        cmd = [str(SCRIPT_PATH), "--initialize-only"]

        # Add baseline path if provided
        if baseline_path:
            if not Path(baseline_path).exists():
                logger.error(f"Provided baseline file not found: {baseline_path}")
                return False
            cmd.extend(["--baseline", baseline_path])

        # Execute the script
        try:
            logger.debug(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if result.returncode != 0:
                logger.error(f"Initialization failed: {result.stderr.strip()}")
                return False

            logger.info("Anomaly detection system initialized successfully")
            return True

        except subprocess.SubprocessError as e:
            logger.error(f"Failed to execute anomaly detector script: {e}")
            return False

    except Exception as e:
        logger.error(f"Unexpected error initializing anomaly detection: {e}")
        return False

def detect_anomalies(
    scope: str = "all",
    sensitivity: str = "medium",
    timeframe: str = "24h",
    output_format: str = "json",
    output_file: Optional[str] = None
) -> Union[Dict[str, Any], bool]:
    """
    Run anomaly detection with the specified parameters.

    Args:
        scope: Detection scope ('user', 'system', 'network', 'all')
        sensitivity: Detection sensitivity ('low', 'medium', 'high')
        timeframe: Time window for analysis (e.g., '24h', '7d')
        output_format: Output format ('json', 'text', 'html')
        output_file: Optional path to write results

    Returns:
        Dict containing detection results, or False if detection failed
    """
    try:
        # Build command
        cmd = [str(SCRIPT_PATH)]
        cmd.extend(["--scope", scope])
        cmd.extend(["--sensitivity", sensitivity])
        cmd.extend(["--timeframe", timeframe])
        cmd.extend(["--output-format", output_format])

        if output_file:
            cmd.extend(["--report-file", output_file])

        # Execute the script
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            logger.error(f"Anomaly detection failed: {result.stderr.strip()}")
            return False

        # Parse output if in JSON format
        if output_format == "json" and not output_file:
            try:
                import json
                return json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON output: {e}")
                return False

        return True

    except Exception as e:
        logger.error(f"Error running anomaly detection: {e}")
        return False

def get_detection_sensitivity_thresholds() -> Dict[str, Dict[str, float]]:
    """
    Get the thresholds for different sensitivity levels.

    Returns:
        Dict with sensitivity levels and their thresholds
    """
    if CONSTANTS_AVAILABLE:
        # Use the thresholds from constants if available
        return {
            "numeric": DETECTION_SENSITIVITY.THRESHOLDS,
            "standard_deviations": DETECTION_SENSITIVITY.STD_DEVIATIONS,
            "multipliers": DETECTION_SENSITIVITY.MULTIPLIERS
        }
    else:
        # Default thresholds if constants are not available
        return {
            "numeric": {
                "low": 0.9,
                "medium": 0.75,
                "high": 0.6
            },
            "standard_deviations": {
                "low": 3.0,
                "medium": 2.5,
                "high": 2.0
            },
            "multipliers": {
                "low": 2.0,
                "medium": 1.5,
                "high": 1.2
            }
        }

__all__ = [
    # Public functions
    "initialize_detection",
    "detect_anomalies",
    "get_detection_sensitivity_thresholds",

    # Constants
    "SCRIPT_PATH",
    "DEFAULT_CONFIG_DIR",
    "DEFAULT_BASELINE_DIR",
    "DEFAULT_RULES_DIR",
]
