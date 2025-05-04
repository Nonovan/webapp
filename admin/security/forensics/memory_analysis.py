"""
Memory Analysis Module for Forensic Analysis Toolkit.

This module provides functionality for analyzing memory dumps and extracting
forensically relevant information to support incident investigations.

It leverages the static_analysis/memory_string_analyzer.py for string analysis
and can interface with external memory forensics tools like Volatility.
"""

import os
import json
import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
import sys
from typing import Dict, List, Any, Optional, Tuple, Union

# Configure logger
logger = logging.getLogger(__name__)

# Try to import core forensic utilities
try:
    from .utils.logging_utils import log_forensic_operation
    from .utils.file_utils import (
        verify_integrity, create_secure_temp_file, get_file_metadata,
        read_only_open, set_file_read_only
    )
    from .utils.validation_utils import validate_path
    from .utils.crypto import calculate_file_hash
    FORENSIC_UTILS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Forensic utilities not fully available: {e}")
    FORENSIC_UTILS_AVAILABLE = False

    # Define fallbacks
    def log_forensic_operation(operation: str, success: bool, details: Dict[str, Any] = None, level: int = logging.INFO):
        """Simple fallback for forensic logging."""
        msg = f"Forensic operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logger.log(level=level, msg=msg)

    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash using standard library."""
        import hashlib
        if not os.path.isfile(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.new(algorithm)
                for chunk in iter(lambda: f.read(65536), b''):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except (IOError, OSError) as e:
            logger.error(f"Error calculating file hash: {str(e)}")
            return None

# Try importing evidence tracking if available
try:
    from .utils.evidence_tracker import track_analysis
    EVIDENCE_TRACKING_AVAILABLE = True
except ImportError:
    EVIDENCE_TRACKING_AVAILABLE = False
    logger.debug("Evidence tracking not available")

# Try importing memory string analyzer
try:
    from .static_analysis.memory_string_analyzer import perform_analysis as analyze_memory_strings
    MEMORY_STRING_ANALYZER_AVAILABLE = True
except ImportError:
    logger.warning("Memory string analyzer not available, string analysis will be limited")
    MEMORY_STRING_ANALYZER_AVAILABLE = False

# Constants
DEFAULT_OUTPUT_FORMAT = "json"
VOLATILITY_TIMEOUT = 600  # Default timeout for Volatility commands (10 minutes)
DEFAULT_HASH_ALGORITHM = "sha256"

# Common Volatility plugins to run for basic analysis
BASIC_VOLATILITY_PLUGINS = [
    "pslist", "psscan", "netscan", "sockscan", "filescan", "cmdline", "hivelist"
]


def analyze_memory_dump(
        memory_dump_path: str,
        output_dir: Optional[str] = None,
        volatility_plugins: Optional[List[str]] = None,
        case_id: Optional[str] = None,
        analyst: Optional[str] = None,
        extract_strings: bool = True,
        hash_verify: bool = True,
        plugin_timeout: int = VOLATILITY_TIMEOUT) -> Dict[str, Any]:
    """
    Analyze memory dump file and extract forensically relevant information.

    Args:
        memory_dump_path: Path to the memory dump file
        output_dir: Directory to save analysis results
        volatility_plugins: List of Volatility plugins to run (defaults to basic set)
        case_id: Case identifier for evidence tracking
        analyst: Name of analyst performing analysis
        extract_strings: Whether to perform string analysis
        hash_verify: Whether to verify file integrity with hashing
        plugin_timeout: Timeout for individual plugin execution in seconds

    Returns:
        Dictionary containing analysis results and findings

    Raises:
        FileNotFoundError: If memory dump not found
        ValueError: If memory dump is not valid
    """
    # Validate memory dump path
    if not os.path.exists(memory_dump_path):
        raise FileNotFoundError(f"Memory dump not found: {memory_dump_path}")

    if not os.path.isfile(memory_dump_path):
        raise ValueError(f"Path is not a file: {memory_dump_path}")

    # Create output directory if specified and doesn't exist
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Created output directory: {output_dir}")

    # Set up operation details for logging
    operation_details = {
        "memory_dump": memory_dump_path,
        "output_dir": output_dir,
        "case_id": case_id,
        "analyst": analyst
    }

    log_forensic_operation("memory_analysis_start", True, operation_details)

    # Initialize results structure
    results = {
        "memory_dump": memory_dump_path,
        "analysis_timestamp": datetime.now().isoformat(),
        "analyst": analyst,
        "case_id": case_id,
        "file_metadata": {},
        "integrity_check": {},
        "string_analysis": {},
        "volatility_analysis": {},
        "errors": [],
        "warnings": []
    }

    # File metadata collection
    try:
        results["file_metadata"] = _collect_file_metadata(memory_dump_path)
    except Exception as e:
        error_msg = f"Error collecting file metadata: {str(e)}"
        logger.error(error_msg)
        results["errors"].append(error_msg)

    # File integrity verification
    if hash_verify:
        try:
            file_hash = calculate_file_hash(memory_dump_path, DEFAULT_HASH_ALGORITHM)
            results["integrity_check"] = {
                "algorithm": DEFAULT_HASH_ALGORITHM,
                "hash_value": file_hash,
                "verification_timestamp": datetime.now().isoformat()
            }
            logger.info(f"Calculated {DEFAULT_HASH_ALGORITHM} hash: {file_hash}")
        except Exception as e:
            error_msg = f"Error calculating file hash: {str(e)}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
            results["integrity_check"]["error"] = error_msg

    # String analysis
    if extract_strings and MEMORY_STRING_ANALYZER_AVAILABLE:
        logger.info("Performing memory string analysis")
        try:
            # Create argument object as expected by memory_string_analyzer
            from argparse import Namespace
            string_args = Namespace(
                file=memory_dump_path,
                input_type="dump",
                min_length=6,
                output_dir=output_dir,
                output_format="json",
                detect_credentials=True,
                detect_crypto=True,
                detect_commands=True,
                extract_ioc=True,
                full_analysis=True,
                detect_paths=True,
                ioc_type="all",
                pattern_match=None,
                group_by="type",
                read_only=True,
                include_metadata=True,
                case_id=case_id,
                analyst=analyst,
                filter_strings=None,
                string_encoding="utf-8",
                context_bytes=0,
                verbose=0,
                max_findings=1000
            )

            string_results = analyze_memory_strings(string_args)
            results["string_analysis"] = string_results

            # Save string analysis results if output_dir specified
            if output_dir:
                strings_output_path = os.path.join(
                    output_dir, f"memory_strings_{Path(memory_dump_path).stem}.json"
                )
                with open(strings_output_path, 'w') as f:
                    json.dump(string_results, f, indent=2)
                logger.info(f"String analysis results saved to: {strings_output_path}")

        except Exception as e:
            error_msg = f"Error during string analysis: {str(e)}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
            results["string_analysis"]["error"] = error_msg

    # Volatility analysis
    try:
        volatility_results = _run_volatility_analysis(
            memory_dump_path,
            output_dir,
            plugins=volatility_plugins or BASIC_VOLATILITY_PLUGINS,
            timeout=plugin_timeout
        )
        results["volatility_analysis"] = volatility_results
    except Exception as e:
        error_msg = f"Error during Volatility analysis: {str(e)}"
        logger.error(error_msg)
        results["errors"].append(error_msg)
        results["volatility_analysis"]["error"] = error_msg

    # Generate summary
    results["summary"] = _generate_analysis_summary(results)

    # Track analysis if evidence tracking is available
    if EVIDENCE_TRACKING_AVAILABLE and case_id:
        try:
            track_analysis(
                case_id=case_id,
                evidence_id=os.path.basename(memory_dump_path),
                analyst=analyst or "system",
                action="memory_analysis",
                purpose="Memory dump forensic analysis",
                details={
                    "tool": "memory_analysis",
                    "output_dir": output_dir,
                    "plugins_run": volatility_plugins or BASIC_VOLATILITY_PLUGINS,
                    "findings_count": len(results["string_analysis"].get("findings", [])),
                    "errors": len(results["errors"])
                }
            )
        except Exception as e:
            logger.warning(f"Failed to track analysis in evidence tracker: {str(e)}")

    # Save final results if output_dir specified
    if output_dir:
        try:
            output_path = os.path.join(
                output_dir, f"memory_analysis_{Path(memory_dump_path).stem}.json"
            )
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Memory analysis results saved to: {output_path}")

            # Try to set results file as read-only for evidence preservation
            if FORENSIC_UTILS_AVAILABLE:
                set_file_read_only(output_path)
        except Exception as e:
            logger.error(f"Error saving analysis results: {str(e)}")

    log_forensic_operation(
        "memory_analysis_complete",
        True,
        {
            **operation_details,
            "errors": len(results["errors"]),
            "findings_count": results["summary"].get("total_findings", 0)
        }
    )

    return results


def _collect_file_metadata(file_path: str) -> Dict[str, Any]:
    """
    Collect detailed metadata about a memory dump file.

    Args:
        file_path: Path to the memory dump file

    Returns:
        Dictionary containing file metadata
    """
    metadata = {
        "filename": os.path.basename(file_path),
        "path": os.path.abspath(file_path),
        "size_bytes": os.path.getsize(file_path),
        "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
        "last_accessed": datetime.fromtimestamp(os.path.getatime(file_path)).isoformat(),
        "permissions": oct(os.stat(file_path).st_mode & 0o777)
    }

    # Format size in human-readable form
    size_mb = metadata["size_bytes"] / (1024 * 1024)
    metadata["size_human"] = f"{size_mb:.2f} MB"

    # Try to determine memory image type based on file signatures
    file_sig = _get_file_signature(file_path)
    metadata["file_signature"] = file_sig

    # Try to detect format based on signature and extension
    extension = os.path.splitext(file_path)[1].lower()
    if extension in ['.raw', '.dump', '.mem', '.bin']:
        metadata["format"] = "Raw memory dump"
    elif extension == '.lime':
        metadata["format"] = "LiME format"
    elif extension in ['.vmem', '.vmsn']:
        metadata["format"] = "VMware memory dump"
    elif extension == '.hpak':
        metadata["format"] = "Hibernation file"
    elif extension == '.core' or '.core.' in file_path.lower():
        metadata["format"] = "Core dump"
    else:
        # Try signature-based detection
        if file_sig.startswith(b'PMEM'):
            metadata["format"] = "WinPmem format"
        elif file_sig.startswith(b'KDMP'):
            metadata["format"] = "Windows kernel dump"
        else:
            metadata["format"] = "Unknown memory format"

    return metadata


def _get_file_signature(file_path: str, bytes_count: int = 8) -> bytes:
    """
    Get the file signature (magic bytes) from a file.

    Args:
        file_path: Path to the file
        bytes_count: Number of bytes to read

    Returns:
        Bytes containing the file signature
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read(bytes_count)
    except Exception as e:
        logger.error(f"Error reading file signature: {str(e)}")
        return b''


def _run_volatility_analysis(
        memory_dump_path: str,
        output_dir: Optional[str],
        plugins: List[str],
        timeout: int = VOLATILITY_TIMEOUT) -> Dict[str, Any]:
    """
    Run Volatility plugins against a memory dump.

    Args:
        memory_dump_path: Path to the memory dump file
        output_dir: Directory to save plugin output
        plugins: List of Volatility plugins to run
        timeout: Timeout for each plugin execution in seconds

    Returns:
        Dictionary containing Volatility analysis results
    """
    results = {
        "plugins_run": [],
        "plugins_failed": [],
        "findings": {},
        "profile": None,
        "version": None
    }

    # Check if Volatility is installed
    vol_path = _find_volatility_path()
    if not vol_path:
        results["error"] = "Volatility not found in PATH"
        return results

    results["version"] = _get_volatility_version(vol_path)

    # Create a directory for Volatility output if needed
    vol_output_dir = output_dir
    if output_dir:
        vol_output_dir = os.path.join(output_dir, "volatility_output")
        os.makedirs(vol_output_dir, exist_ok=True)

    # Try to determine profile first
    profile = _determine_volatility_profile(vol_path, memory_dump_path, timeout)
    results["profile"] = profile

    # Run each plugin
    for plugin in plugins:
        plugin_result = _run_volatility_plugin(
            vol_path, memory_dump_path, plugin, profile, vol_output_dir, timeout
        )

        if plugin_result.get("success", False):
            results["plugins_run"].append(plugin)
            results["findings"][plugin] = plugin_result
        else:
            results["plugins_failed"].append(plugin)
            results["findings"][plugin] = plugin_result

    return results


def _find_volatility_path() -> Optional[str]:
    """Find the Volatility executable in PATH."""
    # Try different common names for Volatility
    for cmd in ["volatility3", "vol3", "vol.py", "volatility"]:
        try:
            path = subprocess.check_output(["which", cmd], text=True).strip()
            return path
        except (subprocess.SubprocessError, FileNotFoundError):
            continue

    return None


def _get_volatility_version(vol_path: str) -> str:
    """Get the Volatility version."""
    try:
        version_output = subprocess.check_output(
            [vol_path, "--version"],
            stderr=subprocess.STDOUT,
            text=True
        )
        return version_output.strip()
    except subprocess.SubprocessError:
        return "Unknown"


def _determine_volatility_profile(vol_path: str, memory_dump_path: str, timeout: int) -> Optional[str]:
    """
    Determine the appropriate Volatility profile for a memory dump.

    Returns:
        Profile name or None if can't be determined
    """
    # For Volatility 3, we use imageinfo
    try:
        cmd = [vol_path, "-f", memory_dump_path, "windows.info"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Try to parse the output to find suggested profile
        if "Suggested Profile(s)" in result.stdout:
            profile_line = [line for line in result.stdout.split('\n')
                          if "Suggested Profile(s)" in line]
            if profile_line:
                # Extract first suggested profile
                profile = profile_line[0].split(':')[1].strip().split(',')[0]
                return profile
        else:
            # Voltality 3 doesn't use profiles the same way
            return None

    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.warning(f"Failed to determine Volatility profile: {str(e)}")
        return None


def _run_volatility_plugin(
        vol_path: str, memory_dump_path: str, plugin: str,
        profile: Optional[str], output_dir: Optional[str], timeout: int) -> Dict[str, Any]:
    """
    Run a specific Volatility plugin against a memory dump.

    Returns:
        Dictionary with plugin results and metadata
    """
    result = {
        "plugin": plugin,
        "start_time": datetime.now().isoformat(),
        "success": False,
        "output": None,
        "error": None
    }

    try:
        cmd = [vol_path, "-f", memory_dump_path]

        # Add profile if available and using Volatility 2.x
        if profile and "vol3" not in vol_path and "volatility3" not in vol_path:
            cmd.extend(["--profile", profile])

        # Handle plugins differently based on Volatility version
        if "vol3" in vol_path or "volatility3" in vol_path:
            # Volatility 3 format
            plugin_parts = plugin.split(".")
            if len(plugin_parts) == 1:
                # Add default namespace for common plugins
                cmd.append(f"windows.{plugin}")
            else:
                cmd.append(plugin)
        else:
            # Volatility 2 format
            cmd.append(plugin)

        # Add output file if directory is specified
        output_file = None
        if output_dir:
            output_file = os.path.join(output_dir, f"{plugin.replace('.', '_')}.txt")
            # Only for Vol 2.x
            if "vol3" not in vol_path and "volatility3" not in vol_path:
                cmd.extend(["--output-file", output_file])

        # Run the plugin
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Save the output
        plugin_output = proc.stdout

        # For Vol 3.x, manually save output if output_dir is provided
        if output_file and ("vol3" in vol_path or "volatility3" in vol_path):
            with open(output_file, 'w') as f:
                f.write(plugin_output)

        # Check for errors in stderr
        if proc.stderr and len(proc.stderr.strip()) > 0:
            result["error"] = proc.stderr
            if "ERROR" in proc.stderr or proc.returncode != 0:
                result["success"] = False
            else:
                # Some normal messages go to stderr but aren't errors
                result["success"] = True
        else:
            result["success"] = True

        # Truncate output if too large
        if len(plugin_output) > 10000:
            result["output"] = plugin_output[:10000] + "... [truncated]"
            result["truncated"] = True
        else:
            result["output"] = plugin_output

        result["output_file"] = output_file
        result["end_time"] = datetime.now().isoformat()

    except subprocess.TimeoutExpired:
        result["error"] = f"Plugin execution timed out after {timeout} seconds"
        result["success"] = False
        logger.warning(f"Volatility plugin {plugin} timed out")

    except Exception as e:
        result["error"] = str(e)
        result["success"] = False
        logger.error(f"Error running Volatility plugin {plugin}: {str(e)}")

    return result


def _generate_analysis_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a summary of memory analysis findings.

    Args:
        results: Complete analysis results

    Returns:
        Dictionary with summary information
    """
    summary = {
        "memory_dump": os.path.basename(results.get("memory_dump", "")),
        "memory_size": results.get("file_metadata", {}).get("size_human", "Unknown"),
        "memory_format": results.get("file_metadata", {}).get("format", "Unknown"),
        "analysis_date": datetime.now().isoformat(),
        "total_findings": 0,
        "error_count": len(results.get("errors", [])),
        "plugins_run": len(results.get("volatility_analysis", {}).get("plugins_run", [])),
        "plugins_failed": len(results.get("volatility_analysis", {}).get("plugins_failed", [])),
        "risk_assessment": "Low"
    }

    # Count string findings
    string_findings = len(results.get("string_analysis", {}).get("findings", []))
    summary["string_findings"] = string_findings
    summary["total_findings"] += string_findings

    # Extract string analysis risk assessment if available
    string_risk = results.get("string_analysis", {}).get("summary", {}).get("risk_assessment", "")
    if string_risk:
        summary["string_risk_assessment"] = string_risk

    # Extract notable findings by type from string analysis
    finding_types = results.get("string_analysis", {}).get("summary", {}).get("findings_by_type", {})
    if finding_types:
        summary["notable_findings"] = {
            "credentials": finding_types.get("Potential Password", 0) +
                          finding_types.get("Potential API Key", 0) +
                          finding_types.get("Private Key Header", 0),
            "network_indicators": finding_types.get("IPv4", 0) +
                                 finding_types.get("Domain Name", 0) +
                                 finding_types.get("URL", 0),
            "commands": finding_types.get("Command Execution", 0) +
                       finding_types.get("PowerShell Encoded", 0)
        }

    # Determine overall risk level based on findings
    if summary.get("notable_findings", {}).get("credentials", 0) > 0:
        summary["risk_assessment"] = "High"
    elif summary.get("notable_findings", {}).get("commands", 0) > 0:
        summary["risk_assessment"] = "Medium"
    elif string_risk == "High":
        summary["risk_assessment"] = "High"
    elif string_risk == "Medium":
        summary["risk_assessment"] = "Medium"

    return summary


def generate_memory_analysis_report(
        analysis_results: Dict[str, Any],
        output_path: str,
        report_format: str = "md") -> bool:
    """
    Generate a standardized report from memory analysis results.

    Args:
        analysis_results: The analysis results from analyze_memory_dump
        output_path: Path to save the report
        report_format: Report format (md, html, json)

    Returns:
        Boolean indicating success
    """
    try:
        # Try to use the report builder if available
        try:
            from .utils.report_builder import generate_forensic_report
            return generate_forensic_report(
                template_name="memory_analysis_report.md",
                output_path=output_path,
                report_data=analysis_results,
                format=report_format,
                title="Memory Analysis Report",
                case_id=analysis_results.get("case_id"),
                analyst_name=analysis_results.get("analyst")
            )
        except ImportError:
            # Fall back to basic report generation
            if report_format == "json":
                with open(output_path, 'w') as f:
                    json.dump(analysis_results, f, indent=2)
                return True
            elif report_format == "md":
                return _generate_markdown_report(analysis_results, output_path)
            else:
                logger.error(f"Unsupported report format without report_builder: {report_format}")
                return False

    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return False


def _generate_markdown_report(analysis_results: Dict[str, Any], output_path: str) -> bool:
    """Generate a simple Markdown report from analysis results."""
    try:
        summary = analysis_results.get("summary", {})
        file_meta = analysis_results.get("file_metadata", {})

        with open(output_path, 'w') as f:
            f.write("# Memory Analysis Report\n\n")

            # Document metadata
            f.write(f"**Analyst:** {analysis_results.get('analyst', 'Unknown')}\n")
            f.write(f"**Date Created:** {datetime.now().isoformat()}\n")
            if analysis_results.get("case_id"):
                f.write(f"**Case ID:** {analysis_results.get('case_id')}\n")
            f.write("\n")

            # Source evidence information
            f.write("## Source Evidence Information\n\n")
            f.write(f"**Evidence Description:** Memory Dump Analysis\n")
            f.write(f"**Evidence Type:** Memory Dump\n")

            # Memory image properties
            f.write("## Memory Image Properties\n\n")
            f.write(f"**Image Format:** {file_meta.get('format', 'Unknown')}\n")
            f.write(f"**Image Size:** {file_meta.get('size_human', 'Unknown')}\n")

            # Memory image integrity
            f.write("### Memory Image Integrity Verification\n\n")
            integrity = analysis_results.get("integrity_check", {})
            f.write("| Hash Type | Value | Verification Date/Time |\n")
            f.write("|-----------|---------------|----------------------|\n")
            f.write(f"| {integrity.get('algorithm', 'SHA-256')} | {integrity.get('hash_value', 'N/A')} | {integrity.get('verification_timestamp', 'N/A')} |\n\n")

            # Analysis results summary
            f.write("## Analysis Summary\n\n")
            f.write(f"**Risk Assessment:** {summary.get('risk_assessment', 'Unknown')}\n")
            f.write(f"**Total Findings:** {summary.get('total_findings', 0)}\n")
            f.write(f"**String Findings:** {summary.get('string_findings', 0)}\n")
            f.write(f"**Plugins Run:** {summary.get('plugins_run', 0)}\n")
            f.write(f"**Plugins Failed:** {summary.get('plugins_failed', 0)}\n")
            f.write(f"**Errors:** {summary.get('error_count', 0)}\n\n")

            # Notable findings
            if summary.get("notable_findings"):
                f.write("### Notable Findings\n\n")
                f.write(f"- Credential indicators: {summary.get('notable_findings', {}).get('credentials', 0)}\n")
                f.write(f"- Network indicators: {summary.get('notable_findings', {}).get('network_indicators', 0)}\n")
                f.write(f"- Command execution indicators: {summary.get('notable_findings', {}).get('commands', 0)}\n\n")

            # String analysis
            f.write("## Memory Strings Analysis\n\n")
            if "string_analysis" in analysis_results:
                findings = analysis_results.get("string_analysis", {}).get("findings", [])
                if findings:
                    f.write("### Significant Strings\n\n")
                    f.write("| Type | Value | Offset |\n")
                    f.write("|------|-------|--------|\n")

                    # Limit to first 20 findings to keep report manageable
                    for finding in findings[:20]:
                        value = finding.get("value", "").replace("|", "\\|")[:50]  # Escape pipe chars and truncate
                        f.write(f"| {finding.get('type', 'Unknown')} | {value} | {finding.get('offset', 'N/A')} |\n")

                    if len(findings) > 20:
                        f.write(f"\n*...and {len(findings) - 20} more findings*\n")

            # Volatility findings
            f.write("\n## Volatility Analysis\n\n")
            vol_results = analysis_results.get("volatility_analysis", {})
            f.write(f"**Version:** {vol_results.get('version', 'Unknown')}\n")
            if vol_results.get("profile"):
                f.write(f"**Profile:** {vol_results.get('profile')}\n")

            # List plugins run
            f.write("\n### Plugins Run\n\n")
            for plugin in vol_results.get("plugins_run", []):
                f.write(f"- {plugin}\n")

            f.write("\n### Plugins Failed\n\n")
            for plugin in vol_results.get("plugins_failed", []):
                f.write(f"- {plugin}\n")

            # Document History
            f.write("\n## Document History\n\n")
            f.write("| Version | Date | Modified By | Description of Changes |\n")
            f.write("|---------|------|------------|------------------------|\n")
            f.write(f"| 1.0 | {datetime.now().isoformat()} | {analysis_results.get('analyst', 'N/A')} | Initial document creation |\n")

            return True
    except Exception as e:
        logger.error(f"Error generating Markdown report: {str(e)}")
        return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Memory dump analysis tool")
    parser.add_argument("--file", required=True, help="Memory dump file to analyze")
    parser.add_argument("--output-dir", help="Directory to save analysis results")
    parser.add_argument("--no-strings", action="store_true", help="Skip string analysis")
    parser.add_argument("--no-volatility", action="store_true", help="Skip Volatility analysis")
    parser.add_argument("--case-id", help="Case identifier for evidence tracking")
    parser.add_argument("--analyst", help="Name of analyst performing the analysis")
    parser.add_argument("--report", help="Generate analysis report to specified path")
    parser.add_argument("--report-format", choices=["md", "json", "html"], default="md",
                       help="Report format (requires --report)")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO,
                      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    try:
        plugins = None if args.no_volatility else BASIC_VOLATILITY_PLUGINS

        results = analyze_memory_dump(
            memory_dump_path=args.file,
            output_dir=args.output_dir,
            volatility_plugins=plugins,
            case_id=args.case_id,
            analyst=args.analyst,
            extract_strings=not args.no_strings,
        )

        if args.report:
            generate_memory_analysis_report(
                analysis_results=results,
                output_path=args.report,
                report_format=args.report_format
            )

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        sys.exit(1)
