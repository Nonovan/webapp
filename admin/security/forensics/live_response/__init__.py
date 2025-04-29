"""
Live Response Forensic Toolkit Package

This package provides tools for acquiring volatile data during security incident response
by capturing system memory, network state, process information, and other volatile artifacts
that would be lost after system shutdown. The tools follow forensic best practices for
evidence collection, ensuring data integrity through proper hashing, minimal system impact,
and complete chain of custody documentation.

The toolkit includes:
- Memory acquisition capabilities with multiple collection methods
- Volatile system state collection (processes, users, network connections)
- Network state documentation and packet capture
- Evidence packaging with integrity verification

Usage:
    Primary usage is through the command-line scripts. See USAGE.md for detailed instructions.
    The module can also be imported to use the underlying capabilities programmatically.

Example:
    # This shows how to access the module programmatically
    from admin.security.forensics.live_response import get_collector, LiveResponseConfig

    # Configure a volatile data collector
    config = LiveResponseConfig(
        output_dir="/secure/evidence/case-001/",
        case_id="CASE-2024-001",
        examiner="Jane Smith"
    )
    collector = get_collector("volatile_data", config)
    collector.collect(categories=["processes", "network", "users"])
"""

import os
import sys
import json
import logging
import subprocess
import shutil
from typing import Dict, Any, Optional, Union, Callable, List, Tuple, Set
from pathlib import Path
from datetime import datetime

# Version information
__version__ = "0.0.1"
__author__ = "Security Forensics Team"
__email__ = "security-forensics@example.com"
__status__ = "Production"

# Set up package logging
logger = logging.getLogger(__name__)

# Define module constants
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = SCRIPT_DIR
DEFAULT_CONFIG_PATH = MODULE_PATH / "config"
DEFAULT_TOOL_PATHS = MODULE_PATH / "tool_paths.json"

# Collection types supported by the module
COLLECTION_TYPES = {
    "memory": "memory_acquisition.sh",
    "volatile": "volatile_data.sh",
    "network": "network_state.sh",
}

# Artifact types and their expected file patterns
ARTIFACT_TYPES = {
    "process": ["processes/ps_*.txt", "processes/pstree.txt"],
    "network": ["network/ss_*.txt", "network/*_connections.txt"],
    "memory": ["*.raw", "*.lime", "*.dump", "*.mem"],
    "user": ["users/w.txt", "users/who.txt", "users/passwd.txt"],
    "service": ["services/systemctl_*.txt", "services/*_services.txt"],
    "module": ["modules/lsmod.txt", "modules/module_*.txt"],
    "startup": ["startup/enabled_units.txt", "startup/*cron*.txt"],
    "command_history": ["history/*_history.txt"],
    "open_files": ["open_files/lsof_*.txt"],
    "mounted_devices": ["mounted_devices/mount.txt", "mounted_devices/df_*.txt"],
    "firewall": ["firewall/iptables_*.txt", "firewall/firewalld_*.txt"],
    "logs": ["*_log.txt", "*_logs.txt", "*.log"]
}

# Define base exceptions for the module
class LiveResponseError(Exception):
    """Base exception for all live response errors"""
    pass

class ConfigurationError(LiveResponseError):
    """Error in configuration parameters"""
    pass

class CollectionError(LiveResponseError):
    """Error during evidence collection"""
    pass

class ValidationError(LiveResponseError):
    """Validation error for input parameters"""
    pass

class ArtifactParsingError(LiveResponseError):
    """Error parsing forensic artifacts"""
    pass

# Configuration class for live response operations
class LiveResponseConfig:
    """Configuration container for live response operations"""

    def __init__(self,
                 output_dir: str,
                 case_id: Optional[str] = None,
                 examiner: Optional[str] = None,
                 target: Optional[str] = None,
                 user: Optional[str] = None,
                 key: Optional[str] = None,
                 verbose: bool = False,
                 compression: bool = True,
                 verify: bool = True) -> None:
        """
        Initialize live response configuration.

        Args:
            output_dir: Directory to store collected evidence
            case_id: Case identifier for documentation
            examiner: Name of forensic examiner
            target: Remote host address if collecting remotely
            user: Username for remote authentication
            key: SSH key path for remote authentication
            verbose: Enable verbose output
            compression: Enable compression of collected data
            verify: Verify collected data integrity
        """
        self.output_dir = output_dir
        self.case_id = case_id
        self.examiner = examiner
        self.target = target
        self.user = user
        self.key = key
        self.verbose = verbose
        self.compression = compression
        self.verify = verify

        # Validate required parameters
        if not output_dir:
            raise ConfigurationError("Output directory must be specified")

    def to_args_list(self) -> List[str]:
        """
        Convert configuration to command line arguments list

        Returns:
            List of command-line argument strings
        """
        args = []

        # Add basic options
        args.extend(["--output", self.output_dir])

        # Add optional parameters if provided
        if self.case_id:
            args.extend(["--case-id", self.case_id])
        if self.examiner:
            args.extend(["--examiner", self.examiner])
        if self.target:
            args.extend(["--target", self.target])
        if self.user:
            args.extend(["--user", self.user])
        if self.key:
            args.extend(["--key", self.key])
        if self.verbose:
            args.append("--verbose")
        if self.compression:
            args.append("--compress")
        if self.verify:
            args.append("--verify")

        return args

# Base collector class
class BaseCollector:
    """Base class for evidence collectors"""

    def __init__(self, config: LiveResponseConfig):
        """
        Initialize the collector with configuration.

        Args:
            config: Live response configuration
        """
        self.config = config
        self.script_path = None

    def collect(self, **kwargs) -> Tuple[bool, str]:
        """
        Collect evidence.

        Args:
            **kwargs: Collection-specific arguments

        Returns:
            Tuple of (success, output_path)
        """
        raise NotImplementedError("Subclasses must implement collect()")

    def _execute_script(self, args: List[str]) -> Tuple[int, str, str]:
        """
        Execute a shell script with arguments.

        Args:
            args: Command-line arguments

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        if not self.script_path or not os.path.exists(self.script_path):
            raise CollectionError(f"Script not found: {self.script_path}")

        cmd = [self.script_path] + args
        logger.debug(f"Executing command: {' '.join(cmd)}")

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            return process.returncode, process.stdout, process.stderr
        except Exception as e:
            logger.error(f"Error executing script: {e}")
            return 1, "", str(e)

# Memory acquisition collector
class MemoryCollector(BaseCollector):
    """Collector for system memory acquisition"""

    def __init__(self, config: LiveResponseConfig):
        """Initialize memory acquisition collector"""
        super().__init__(config)
        self.script_path = str(MODULE_PATH / "memory_acquisition.sh")

    def collect(self,
               method: Optional[str] = None,
               analyze: bool = False,
               ioc_file: Optional[str] = None,
               **kwargs) -> Tuple[bool, str]:
        """
        Collect system memory.

        Args:
            method: Memory acquisition method
            analyze: Run Volatility analysis after acquisition
            ioc_file: Path to IoC file for analysis
            **kwargs: Additional arguments

        Returns:
            Tuple of (success, output_path)
        """
        args = self.config.to_args_list()

        # Add memory specific arguments
        if method:
            args.extend(["--method", method])
        if analyze:
            args.append("--analyze")
        if ioc_file:
            args.extend(["--ioc-file", ioc_file])

        # Add any additional keyword arguments as flags
        for key, value in kwargs.items():
            if value is True:
                args.append(f"--{key.replace('_', '-')}")
            elif value not in (None, False):
                args.extend([f"--{key.replace('_', '-')}", str(value)])

        # Execute the script
        returncode, stdout, stderr = self._execute_script(args)

        # Parse output path from stdout or use default
        output_path = self.config.output_dir
        memory_file_pattern = "Memory image saved to: "
        for line in stdout.splitlines():
            if memory_file_pattern in line:
                output_path = line.split(memory_file_pattern)[1].strip()
                break

        success = returncode == 0
        if not success:
            logger.error(f"Memory acquisition failed: {stderr}")

        return success, output_path

# Volatile data collector
class VolatileDataCollector(BaseCollector):
    """Collector for volatile system data"""

    def __init__(self, config: LiveResponseConfig):
        """Initialize volatile data collector"""
        super().__init__(config)
        self.script_path = str(MODULE_PATH / "volatile_data.sh")

    def collect(self,
               categories: Optional[List[str]] = None,
               minimal: bool = False,
               process_args: bool = False,
               process_env: bool = False,
               **kwargs) -> Tuple[bool, str]:
        """
        Collect volatile system data.

        Args:
            categories: List of data categories to collect
            minimal: Perform minimal collection (faster)
            process_args: Include process command line arguments
            process_env: Include process environment variables
            **kwargs: Additional arguments

        Returns:
            Tuple of (success, output_path)
        """
        args = self.config.to_args_list()

        # Add volatile data specific arguments
        if categories:
            args.extend(["--collect", ",".join(categories)])
        if minimal:
            args.append("--minimal")
        if process_args:
            args.append("--process-args")
        if process_env:
            args.append("--process-env")

        # Add any additional keyword arguments as flags
        for key, value in kwargs.items():
            if value is True:
                args.append(f"--{key.replace('_', '-')}")
            elif value not in (None, False):
                args.extend([f"--{key.replace('_', '-')}", str(value)])

        # Execute the script
        returncode, stdout, stderr = self._execute_script(args)

        success = returncode == 0
        if not success:
            logger.error(f"Volatile data collection failed: {stderr}")

        return success, self.config.output_dir

# Network state collector
class NetworkStateCollector(BaseCollector):
    """Collector for network state information"""

    def __init__(self, config: LiveResponseConfig):
        """Initialize network state collector"""
        super().__init__(config)
        self.script_path = str(MODULE_PATH / "network_state.sh")

    def collect(self,
               connections_type: str = "all",
               firewall: bool = False,
               packet_capture: bool = False,
               capture_duration: Optional[str] = None,
               capture_packets: Optional[int] = None,
               capture_filter: Optional[str] = None,
               **kwargs) -> Tuple[bool, str]:
        """
        Collect network state information.

        Args:
            connections_type: Type of connections to collect
            firewall: Collect firewall rules
            packet_capture: Capture network packets
            capture_duration: Duration for packet capture
            capture_packets: Number of packets to capture
            capture_filter: Packet capture filter expression
            **kwargs: Additional arguments

        Returns:
            Tuple of (success, output_path)
        """
        args = self.config.to_args_list()

        # Add network state specific arguments
        args.extend(["--connections", connections_type])
        if firewall:
            args.append("--firewall")
        if packet_capture:
            args.append("--packet-capture")
        if capture_duration:
            args.extend(["--duration", capture_duration])
        if capture_packets:
            args.extend(["--capture-packets", str(capture_packets)])
        if capture_filter:
            args.extend(["--filter", capture_filter])

        # Add any additional keyword arguments as flags
        for key, value in kwargs.items():
            if value is True:
                args.append(f"--{key.replace('_', '-')}")
            elif value not in (None, False):
                args.extend([f"--{key.replace('_', '-')}", str(value)])

        # Execute the script
        returncode, stdout, stderr = self._execute_script(args)

        success = returncode == 0
        if not success:
            logger.error(f"Network state collection failed: {stderr}")

        return success, self.config.output_dir

# Artifact Parser implementation
class ArtifactParser:
    """Parser for forensic artifacts collected during live response"""

    def __init__(self, evidence_dir: str):
        """
        Initialize the artifact parser.

        Args:
            evidence_dir: Directory containing collected evidence
        """
        self.evidence_dir = Path(evidence_dir)
        if not self.evidence_dir.exists():
            raise ArtifactParsingError(f"Evidence directory does not exist: {evidence_dir}")

        self.artifacts = {}
        self.metadata = {}
        self._load_metadata()

    def _load_metadata(self) -> None:
        """Load collection metadata if available"""
        metadata_paths = [
            self.evidence_dir / "collection_metadata.json",
            self.evidence_dir / "collection_summary.txt"
        ]

        for path in metadata_paths:
            if path.exists():
                try:
                    if path.suffix == ".json":
                        with open(path, 'r') as f:
                            self.metadata = json.load(f)
                    else:
                        # Basic extraction from text summary
                        with open(path, 'r') as f:
                            content = f.read()

                            # Parse metadata from summary format
                            if "Case ID:" in content:
                                self.metadata["case_id"] = content.split("Case ID:")[1].split("\n")[0].strip()
                            if "Collection Date:" in content:
                                self.metadata["timestamp"] = content.split("Collection Date:")[1].split("\n")[0].strip()
                            if "Host:" in content:
                                self.metadata["host"] = content.split("Host:")[1].split("\n")[0].strip()
                            if "Examiner:" in content:
                                self.metadata["examiner"] = content.split("Examiner:")[1].split("\n")[0].strip()
                    break
                except Exception as e:
                    logger.warning(f"Failed to parse metadata file {path}: {e}")

    def find_artifacts(self) -> Dict[str, List[Path]]:
        """
        Identify and categorize artifacts in the evidence directory.

        Returns:
            Dictionary mapping artifact types to file paths
        """
        result = {artifact_type: [] for artifact_type in ARTIFACT_TYPES}

        # Walk through evidence directory and identify artifact types
        for root, _, files in os.walk(self.evidence_dir):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(self.evidence_dir)

                for artifact_type, patterns in ARTIFACT_TYPES.items():
                    for pattern in patterns:
                        if any(rel_path.match(p) for p in [pattern, f"*/{pattern}"]):
                            result[artifact_type].append(file_path)
                            break

        # Save results
        self.artifacts = result
        return result

    def get_artifact_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of collected artifacts.

        Returns:
            Dictionary with artifact summary information
        """
        if not self.artifacts:
            self.find_artifacts()

        summary = {
            "metadata": self.metadata,
            "artifact_counts": {k: len(v) for k, v in self.artifacts.items()},
            "total_files": sum(len(v) for v in self.artifacts.values()),
            "total_size_bytes": sum(p.stat().st_size for type_files in self.artifacts.values() for p in type_files if p.exists()),
            "artifact_types": list(k for k, v in self.artifacts.items() if v),
            "timestamp": datetime.now().isoformat()
        }

        return summary

    def extract_processes(self) -> List[Dict[str, Any]]:
        """
        Extract process information from collected artifacts.

        Returns:
            List of dictionaries with process information
        """
        processes = []

        # Find process listing files
        process_files = self.artifacts.get("process", [])
        for file_path in process_files:
            if not file_path.name.startswith("ps_"):
                continue

            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        # Skip header lines
                        if line.startswith("USER") or not line.strip():
                            continue

                        # Parse ps output format
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            process = {
                                "user": parts[0],
                                "pid": int(parts[1]),
                                "cpu_pct": float(parts[2]),
                                "mem_pct": float(parts[3]),
                                "vsz": int(parts[4]),
                                "rss": int(parts[5]),
                                "tty": parts[6],
                                "stat": parts[7],
                                "start": parts[8],
                                "time": parts[9],
                                "command": parts[10].strip()
                            }
                            processes.append(process)
            except Exception as e:
                logger.warning(f"Failed to parse process file {file_path}: {e}")

        return processes

    def extract_network_connections(self) -> List[Dict[str, Any]]:
        """
        Extract network connection information from collected artifacts.

        Returns:
            List of dictionaries with network connection information
        """
        connections = []

        # Find network connection files
        network_files = self.artifacts.get("network", [])
        for file_path in network_files:
            if not any(x in file_path.name for x in ["ss_", "connections", "netstat"]):
                continue

            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        # Skip header lines
                        if any(h in line for h in ["State", "Proto", "Active"]) or not line.strip():
                            continue

                        # Parse based on file type
                        if "ss_" in file_path.name:
                            # SS output format
                            parts = line.split()
                            if len(parts) >= 5:
                                conn = {
                                    "state": parts[0],
                                    "recv_q": int(parts[1]) if parts[1].isdigit() else 0,
                                    "send_q": int(parts[2]) if parts[2].isdigit() else 0,
                                    "local_addr": parts[3],
                                    "remote_addr": parts[4],
                                    "process": parts[5] if len(parts) > 5 else None
                                }
                                connections.append(conn)
                        elif "netstat" in file_path.name:
                            # Netstat output format
                            parts = line.split()
                            if len(parts) >= 5:
                                conn = {
                                    "proto": parts[0],
                                    "recv_q": int(parts[1]) if parts[1].isdigit() else 0,
                                    "send_q": int(parts[2]) if parts[2].isdigit() else 0,
                                    "local_addr": parts[3],
                                    "remote_addr": parts[4],
                                    "state": parts[5] if len(parts) > 5 else None
                                }
                                connections.append(conn)
            except Exception as e:
                logger.warning(f"Failed to parse network file {file_path}: {e}")

        return connections

    def extract_users(self) -> List[Dict[str, Any]]:
        """
        Extract user information from collected artifacts.

        Returns:
            List of dictionaries with user information
        """
        users = []
        user_files = self.artifacts.get("user", [])

        for file_path in user_files:
            if "passwd" in file_path.name:
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            if not line.strip():
                                continue

                            # Parse passwd file format
                            parts = line.strip().split(':')
                            if len(parts) >= 7:
                                user = {
                                    "username": parts[0],
                                    "uid": int(parts[2]),
                                    "gid": int(parts[3]),
                                    "gecos": parts[4],
                                    "home": parts[5],
                                    "shell": parts[6]
                                }
                                users.append(user)
                except Exception as e:
                    logger.warning(f"Failed to parse passwd file {file_path}: {e}")

        return users

    def extract_artifacts_by_type(self, artifact_type: str) -> List[Dict[str, Any]]:
        """
        Extract information from artifacts of a specific type.

        Args:
            artifact_type: Type of artifact to extract information from

        Returns:
            List of dictionaries with extracted information
        """
        if artifact_type == "process":
            return self.extract_processes()
        elif artifact_type == "network":
            return self.extract_network_connections()
        elif artifact_type == "user":
            return self.extract_users()
        else:
            logger.warning(f"Extraction not implemented for artifact type: {artifact_type}")
            return []

    def search_artifacts(self, search_term: str) -> Dict[str, List[Path]]:
        """
        Search for a term across all artifacts.

        Args:
            search_term: Term to search for

        Returns:
            Dictionary mapping artifact types to matching file paths
        """
        if not self.artifacts:
            self.find_artifacts()

        results = {artifact_type: [] for artifact_type in ARTIFACT_TYPES}

        for artifact_type, files in self.artifacts.items():
            for file_path in files:
                try:
                    if file_path.suffix in ['.raw', '.lime', '.dump', '.mem']:
                        # Skip binary files
                        continue

                    with open(file_path, 'r', errors='ignore') as f:
                        if search_term in f.read():
                            results[artifact_type].append(file_path)
                except Exception as e:
                    logger.debug(f"Error searching file {file_path}: {e}")

        return results

# Validation Suite implementation
class ValidationSuite:
    """Suite for validating forensic artifacts and collection integrity"""

    def __init__(self, evidence_dir: str):
        """
        Initialize the validation suite.

        Args:
            evidence_dir: Directory containing collected evidence
        """
        self.evidence_dir = Path(evidence_dir)
        if not self.evidence_dir.exists():
            raise ValidationError(f"Evidence directory does not exist: {evidence_dir}")

        self.parser = ArtifactParser(evidence_dir)
        self.validation_results = {}

    def validate_collection_completeness(self) -> Dict[str, Any]:
        """
        Validate that all expected artifact types are present.

        Returns:
            Dictionary with validation results
        """
        if not self.parser.artifacts:
            self.parser.find_artifacts()

        result = {
            "passed": True,
            "missing_types": [],
            "present_types": [],
            "details": {}
        }

        for artifact_type, files in self.parser.artifacts.items():
            if not files:
                result["missing_types"].append(artifact_type)
                result["passed"] = False
            else:
                result["present_types"].append(artifact_type)
                result["details"][artifact_type] = {
                    "file_count": len(files),
                    "file_examples": [str(p.relative_to(self.evidence_dir)) for p in files[:3]]
                }

        return result

    def validate_metadata_consistency(self) -> Dict[str, Any]:
        """
        Validate that metadata is consistent across artifacts.

        Returns:
            Dictionary with validation results
        """
        result = {
            "passed": True,
            "inconsistencies": [],
            "details": {}
        }

        # Find all metadata files
        metadata_files = []
        for root, _, files in os.walk(self.evidence_dir):
            for file in files:
                if file.endswith("_metadata.json") or file.endswith("_summary.txt"):
                    metadata_files.append(Path(root) / file)

        # Extract and compare case_id and examiner information
        case_ids = set()
        examiners = set()
        timestamps = []

        for file_path in metadata_files:
            try:
                if file_path.suffix == ".json":
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if "case_id" in data:
                            case_ids.add(data["case_id"])
                        if "examiner_id" in data:
                            examiners.add(data["examiner_id"])
                        if "timestamp" in data:
                            timestamps.append(data["timestamp"])
                else:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if "Case ID:" in content:
                            case_id = content.split("Case ID:")[1].split("\n")[0].strip()
                            if case_id != "Not Specified" and case_id != "none":
                                case_ids.add(case_id)
                        if "Examiner:" in content:
                            examiner = content.split("Examiner:")[1].split("\n")[0].strip()
                            if examiner != "Not Specified" and examiner != "none":
                                examiners.add(examiner)
            except Exception as e:
                logger.debug(f"Error parsing metadata file {file_path}: {e}")

        # Check for inconsistencies
        if len(case_ids) > 1:
            result["passed"] = False
            result["inconsistencies"].append("Multiple case IDs found")

        if len(examiners) > 1:
            result["passed"] = False
            result["inconsistencies"].append("Multiple examiners found")

        # Add details
        result["details"] = {
            "case_ids": list(case_ids),
            "examiners": list(examiners),
            "metadata_files": [str(p.relative_to(self.evidence_dir)) for p in metadata_files]
        }

        return result

    def validate_collection_integrity(self) -> Dict[str, Any]:
        """
        Validate collection integrity using available checksums.

        Returns:
            Dictionary with validation results
        """
        result = {
            "passed": True,
            "verified_files": 0,
            "failed_files": 0,
            "missing_checksums": 0,
            "details": {
                "failures": [],
                "verified": []
            }
        }

        # Look for checksum files
        checksum_files = []
        for root, _, files in os.walk(self.evidence_dir):
            for file in files:
                if file.endswith(".sha256") or file.endswith(".md5"):
                    checksum_files.append(Path(root) / file)

        if not checksum_files:
            result["passed"] = False
            result["details"]["message"] = "No checksum files found"
            return result

        # Import hashlib here to avoid overhead if not needed
        import hashlib

        # Verify checksums
        for checksum_file in checksum_files:
            hash_type = "md5" if checksum_file.name.endswith(".md5") else "sha256"
            hash_function = hashlib.md5 if hash_type == "md5" else hashlib.sha256

            try:
                with open(checksum_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            # Handle standard checksum format: hash filename
                            expected_hash = parts[0]
                            filename = " ".join(parts[1:])

                            # Handle path prefixes in checksum files
                            if filename.startswith("*") or filename.startswith(" "):
                                filename = filename.lstrip("* ")

                            file_path = checksum_file.parent / filename
                            if not file_path.exists():
                                result["missing_checksums"] += 1
                                continue

                            # Calculate actual hash
                            h = hash_function()
                            with open(file_path, 'rb') as data_file:
                                for chunk in iter(lambda: data_file.read(4096), b''):
                                    h.update(chunk)
                            actual_hash = h.hexdigest()

                            if actual_hash.lower() == expected_hash.lower():
                                result["verified_files"] += 1
                                result["details"]["verified"].append(str(file_path.relative_to(self.evidence_dir)))
                            else:
                                result["failed_files"] += 1
                                result["passed"] = False
                                result["details"]["failures"].append({
                                    "file": str(file_path.relative_to(self.evidence_dir)),
                                    "expected": expected_hash,
                                    "actual": actual_hash
                                })
            except Exception as e:
                logger.warning(f"Error processing checksum file {checksum_file}: {e}")

        return result

    def run_all_validations(self) -> Dict[str, Any]:
        """
        Run all validation checks and return combined results.

        Returns:
            Dictionary with all validation results
        """
        completeness = self.validate_collection_completeness()
        metadata = self.validate_metadata_consistency()
        integrity = self.validate_collection_integrity()

        # Determine overall status
        overall_passed = completeness["passed"] and metadata["passed"] and integrity["passed"]

        result = {
            "passed": overall_passed,
            "timestamp": datetime.now().isoformat(),
            "evidence_dir": str(self.evidence_dir),
            "validations": {
                "completeness": completeness,
                "metadata": metadata,
                "integrity": integrity
            },
            "summary": {
                "artifact_types_found": len(completeness["present_types"]),
                "artifact_types_missing": len(completeness["missing_types"]),
                "files_verified": integrity["verified_files"],
                "verification_failures": integrity["failed_files"]
            }
        }

        self.validation_results = result
        return result

    def generate_validation_report(self, output_format: str = "json") -> str:
        """
        Generate a validation report in the specified format.

        Args:
            output_format: Format for report ('json', 'text')

        Returns:
            Report content as string
        """
        if not self.validation_results:
            self.run_all_validations()

        if output_format == "json":
            return json.dumps(self.validation_results, indent=2)
        else:
            # Generate text report
            report = []
            report.append("EVIDENCE VALIDATION REPORT")
            report.append("=======================")
            report.append(f"Evidence Directory: {self.evidence_dir}")
            report.append(f"Validation Time: {datetime.now().isoformat()}")
            report.append(f"Overall Status: {'PASSED' if self.validation_results['passed'] else 'FAILED'}")
            report.append("")

            # Completeness
            comp = self.validation_results["validations"]["completeness"]
            report.append("1. COLLECTION COMPLETENESS")
            report.append(f"   Status: {'PASSED' if comp['passed'] else 'FAILED'}")
            report.append(f"   Artifact Types Present: {', '.join(comp['present_types']) or 'None'}")
            report.append(f"   Artifact Types Missing: {', '.join(comp['missing_types']) or 'None'}")
            report.append("")

            # Metadata
            meta = self.validation_results["validations"]["metadata"]
            report.append("2. METADATA CONSISTENCY")
            report.append(f"   Status: {'PASSED' if meta['passed'] else 'FAILED'}")
            if meta["inconsistencies"]:
                report.append(f"   Inconsistencies: {', '.join(meta['inconsistencies'])}")
            case_ids = meta["details"].get("case_ids", [])
            report.append(f"   Case ID{'s' if len(case_ids) > 1 else ''}: {', '.join(case_ids) or 'None'}")
            report.append("")

            # Integrity
            intg = self.validation_results["validations"]["integrity"]
            report.append("3. INTEGRITY VERIFICATION")
            report.append(f"   Status: {'PASSED' if intg['passed'] else 'FAILED'}")
            report.append(f"   Files Verified: {intg['verified_files']}")
            report.append(f"   Verification Failures: {intg['failed_files']}")
            report.append(f"   Missing Checksums: {intg['missing_checksums']}")

            if intg['failed_files'] > 0:
                report.append("\n   Failed Files:")
                for failure in intg["details"]["failures"]:
                    report.append(f"   - {failure['file']}")

            return "\n".join(report)

# Factory function to get a collector by type
def get_collector(collector_type: str, config: LiveResponseConfig) -> BaseCollector:
    """
    Get a collector instance by type.

    Args:
        collector_type: Type of collector to create
        config: Live response configuration

    Returns:
        Collector instance

    Raises:
        ValueError: If collector type is not supported
    """
    collectors = {
        "memory": MemoryCollector,
        "volatile": VolatileDataCollector,
        "network": NetworkStateCollector,
    }

    collector_class = collectors.get(collector_type.lower())
    if not collector_class:
        raise ValueError(f"Unknown collector type: {collector_type}")

    return collector_class(config)

# Export public API
__all__ = [
    # Version information
    '__version__',
    '__author__',
    '__email__',

    # Classes
    'LiveResponseConfig',
    'BaseCollector',
    'MemoryCollector',
    'VolatileDataCollector',
    'NetworkStateCollector',
    'ArtifactParser',
    'ValidationSuite',

    # Functions
    'get_collector',

    # Exceptions
    'LiveResponseError',
    'ConfigurationError',
    'CollectionError',
    'ValidationError',
    'ArtifactParsingError',

    # Constants
    'COLLECTION_TYPES',
    'ARTIFACT_TYPES',
]
