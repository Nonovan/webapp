"""
YARA integration for static analysis in the Forensic Analysis Toolkit.

This module provides a simple interface for using YARA rules to scan files
for malware patterns, suspicious code, and other indicators of compromise.
It includes a scanner class that handles rule compilation, caching, and
security controls for safe scanning operations.
"""

import os
import logging
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any, Union, Optional, Set, Tuple

# Initialize module-level logger
logger = logging.getLogger(__name__)

# Try to import YARA
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    logger.warning("yara-python not installed, YARA scanning functionality will be limited")
    YARA_AVAILABLE = False

# Default constants
DEFAULT_RULES_PATH = Path(__file__).parent
DEFAULT_TIMEOUT = 60  # seconds
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB
MAX_MATCHES = 100  # Prevent too many matches
RULE_COMPILE_TIMEOUT = 30  # seconds for rule compilation

class YaraScanner:
    """
    Provides a secure interface for scanning files with YARA rules.

    This class handles rule compilation, caching, and security controls
    to ensure safe scanning operations for forensic analysis.
    """

    def __init__(self, rule_paths: Optional[List[str]] = None, default_timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize the YaraScanner with specified rule paths.

        Args:
            rule_paths: List of paths to YARA rules files or directories
            default_timeout: Default timeout for scanning operations in seconds

        Raises:
            ImportError: If yara-python is not installed
            ValueError: If rule paths are invalid
        """
        self.default_timeout = default_timeout
        self._compiled_rules = {}  # Cache for compiled rules
        self._rule_mtimes = {}  # Track file modification times
        self._compiled_rules_lock = False  # Simple locking mechanism

        # Check for YARA availability
        if not YARA_AVAILABLE:
            logger.error("Cannot initialize YaraScanner: yara-python not available")
            raise ImportError("yara-python is required for YaraScanner")

        # Set default rules path if none provided
        if rule_paths is None:
            self.rule_paths = [str(DEFAULT_RULES_PATH)]
            logger.debug(f"No rule paths provided, using default: {self.rule_paths}")
        else:
            self.rule_paths = rule_paths

        # Validate rule paths
        self._validate_rule_paths()

        # Initially compile rules if available
        if self.rule_paths:
            try:
                self._compile_rules(self.rule_paths)
                logger.debug(f"Initial compilation of YARA rules complete")
            except Exception as e:
                logger.warning(f"Failed to compile initial YARA rules: {e}")

    def _validate_rule_paths(self) -> bool:
        """
        Validate that specified rule paths exist and are accessible.

        Returns:
            True if all paths are valid, False otherwise

        Raises:
            ValueError: If any path does not exist or is inaccessible
        """
        invalid_paths = []

        for path in self.rule_paths:
            if not os.path.exists(path):
                invalid_paths.append(path)

        if invalid_paths:
            error_msg = f"Invalid YARA rule paths: {', '.join(invalid_paths)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        return True

    def _compile_rules(self, paths: List[str]) -> Optional[yara.Rules]:
        """
        Compile YARA rules from specified paths.

        Args:
            paths: List of file paths or directory paths containing YARA rules

        Returns:
            Compiled YARA rules object or None if compilation fails

        This method handles compiling both individual .yar files and directories
        containing multiple rule files.
        """
        if self._compiled_rules_lock:
            logger.warning("Rule compilation already in progress")
            return None

        self._compiled_rules_lock = True
        rules_key = tuple(sorted(paths))

        try:
            # Check if rules need to be recompiled
            if rules_key in self._compiled_rules:
                # Check if any rule files have been modified
                needs_recompile = False
                for path in paths:
                    if os.path.isfile(path) and path in self._rule_mtimes:
                        current_mtime = os.path.getmtime(path)
                        if current_mtime > self._rule_mtimes[path]:
                            needs_recompile = True
                            break

                if not needs_recompile:
                    return self._compiled_rules[rules_key]

            # Begin compilation process
            filepaths = {}
            namespaces = set()

            # Process each path
            for path in paths:
                if os.path.isfile(path) and path.lower().endswith(('.yar', '.yara')):
                    # Single file
                    namespace = os.path.splitext(os.path.basename(path))[0]
                    # Ensure unique namespace
                    if namespace in namespaces:
                        # Create a unique namespace if duplicate
                        count = 1
                        while f"{namespace}_{count}" in namespaces:
                            count += 1
                        namespace = f"{namespace}_{count}"

                    namespaces.add(namespace)
                    filepaths[namespace] = path
                    self._rule_mtimes[path] = os.path.getmtime(path)

                elif os.path.isdir(path):
                    # Directory - find all .yar and .yara files
                    for root, _, files in os.walk(path):
                        for file in files:
                            if file.lower().endswith(('.yar', '.yara')):
                                file_path = os.path.join(root, file)
                                namespace = os.path.splitext(file)[0]

                                # Ensure unique namespace
                                if namespace in namespaces:
                                    count = 1
                                    while f"{namespace}_{count}" in namespaces:
                                        count += 1
                                    namespace = f"{namespace}_{count}"

                                namespaces.add(namespace)
                                filepaths[namespace] = file_path
                                self._rule_mtimes[file_path] = os.path.getmtime(file_path)

            # If no valid rules found
            if not filepaths:
                logger.warning(f"No YARA rule files found in specified paths: {paths}")
                self._compiled_rules_lock = False
                return None

            # Compile rules with timeout protection
            logger.debug(f"Compiling {len(filepaths)} YARA rule files")
            compiled_rules = yara.compile(filepaths=filepaths)

            # Cache the compiled rules
            self._compiled_rules[rules_key] = compiled_rules

            logger.debug(f"YARA rules compiled successfully: {len(filepaths)} files")
            return compiled_rules

        except yara.Error as ye:
            logger.error(f"YARA compilation error: {ye}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error during YARA rule compilation: {e}")
            return None

        finally:
            self._compiled_rules_lock = False

    def scan_file(self, file_path: str, rules_path: Optional[Union[str, List[str]]] = None,
                  timeout: Optional[int] = None, max_file_size: int = MAX_FILE_SIZE) -> List[Any]:
        """
        Scan a file with YARA rules.

        Args:
            file_path: Path to the file to scan
            rules_path: Optional path(s) to specific rule files/directories
                       (if None, uses rules provided at initialization)
            timeout: Scanning timeout in seconds (overrides default_timeout)
            max_file_size: Maximum file size to scan in bytes

        Returns:
            List of YARA match objects (empty list if no matches or on error)
        """
        if not YARA_AVAILABLE:
            logger.error("YARA scanning not available - missing yara-python module")
            return []

        # Check file exists and is within size limit
        try:
            if not os.path.isfile(file_path):
                logger.error(f"Cannot scan non-existent file: {file_path}")
                return []

            file_size = os.path.getsize(file_path)
            if file_size > max_file_size:
                logger.error(f"File too large for YARA scanning: {file_path} ({file_size} bytes)")
                return []

            # Determine which rules to use
            paths_to_use = self.rule_paths
            if rules_path:
                if isinstance(rules_path, str):
                    paths_to_use = [rules_path]
                else:
                    paths_to_use = rules_path

                # Validate the rules paths
                for path in paths_to_use:
                    if not os.path.exists(path):
                        logger.error(f"YARA rules path does not exist: {path}")
                        return []

            # Compile or fetch rules
            compiled_rules = self._compile_rules(paths_to_use)
            if not compiled_rules:
                logger.error("Failed to compile YARA rules for scanning")
                return []

            # Set timeout
            scan_timeout = timeout if timeout is not None else self.default_timeout

            # Scan the file
            start_time = time.time()

            # Use a context manager to ensure the file is properly closed
            with open(file_path, 'rb') as f:
                matches = compiled_rules.match(data=f.read(), timeout=scan_timeout)

            # Log scan results
            scan_time = time.time() - start_time
            match_count = len(matches)

            if match_count > 0:
                logger.warning(f"YARA scan matched {match_count} rules in {file_path} ({scan_time:.2f}s)")
            else:
                logger.debug(f"YARA scan completed with no matches in {scan_time:.2f}s")

            return matches[:MAX_MATCHES] if matches else []

        except yara.TimeoutError:
            logger.error(f"YARA scan timed out after {timeout or self.default_timeout}s: {file_path}")
            return []

        except yara.Error as ye:
            logger.error(f"YARA error scanning {file_path}: {ye}")
            return []

        except Exception as e:
            logger.error(f"Error during YARA scan of {file_path}: {e}")
            return []

    def scan_data(self, data: bytes, rules_path: Optional[Union[str, List[str]]] = None,
                 timeout: Optional[int] = None) -> List[Any]:
        """
        Scan in-memory data with YARA rules.

        Args:
            data: Bytes to scan
            rules_path: Optional path(s) to specific rule files/directories
                      (if None, uses rules provided at initialization)
            timeout: Scanning timeout in seconds (overrides default_timeout)

        Returns:
            List of YARA match objects (empty list if no matches or on error)
        """
        if not YARA_AVAILABLE:
            logger.error("YARA scanning not available - missing yara-python module")
            return []

        # Check data size
        if len(data) > MAX_FILE_SIZE:
            logger.error(f"Data too large for YARA scanning: {len(data)} bytes")
            return []

        # Determine which rules to use
        paths_to_use = self.rule_paths
        if rules_path:
            if isinstance(rules_path, str):
                paths_to_use = [rules_path]
            else:
                paths_to_use = rules_path

            # Validate the rules paths
            for path in paths_to_use:
                if not os.path.exists(path):
                    logger.error(f"YARA rules path does not exist: {path}")
                    return []

        # Compile or fetch rules
        compiled_rules = self._compile_rules(paths_to_use)
        if not compiled_rules:
            logger.error("Failed to compile YARA rules for scanning")
            return []

        # Set timeout
        scan_timeout = timeout if timeout is not None else self.default_timeout

        try:
            # Scan the data
            start_time = time.time()
            matches = compiled_rules.match(data=data, timeout=scan_timeout)
            scan_time = time.time() - start_time

            # Log scan results
            match_count = len(matches)
            if match_count > 0:
                logger.warning(f"YARA scan matched {match_count} rules in memory data ({scan_time:.2f}s)")
            else:
                logger.debug(f"YARA scan completed with no matches in {scan_time:.2f}s")

            return matches[:MAX_MATCHES] if matches else []

        except yara.TimeoutError:
            logger.error(f"YARA scan of memory data timed out after {timeout or self.default_timeout}s")
            return []

        except yara.Error as ye:
            logger.error(f"YARA error scanning memory data: {ye}")
            return []

        except Exception as e:
            logger.error(f"Error during YARA scan of memory data: {e}")
            return []

    def reload_rules(self) -> bool:
        """
        Force recompilation of all rule paths.

        Returns:
            True if rules were successfully recompiled, False otherwise
        """
        try:
            # Clear the cache
            self._compiled_rules = {}
            self._rule_mtimes = {}

            # Recompile rules
            if self._compile_rules(self.rule_paths) is not None:
                logger.info("YARA rules successfully reloaded")
                return True
            else:
                logger.error("Failed to reload YARA rules")
                return False

        except Exception as e:
            logger.error(f"Error reloading YARA rules: {e}")
            return False

    def get_rule_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the currently loaded rules.

        Returns:
            Dictionary with rule statistics
        """
        stats = {
            "rule_paths": self.rule_paths.copy(),
            "rule_files": 0,
            "rule_count": 0,
            "namespaces": []
        }

        try:
            # Count rule files
            for path in self.rule_paths:
                if os.path.isfile(path) and path.lower().endswith(('.yar', '.yara')):
                    stats["rule_files"] += 1
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            if file.lower().endswith(('.yar', '.yara')):
                                stats["rule_files"] += 1

            # Get rule count if we have compiled rules
            if self._compiled_rules and list(self._compiled_rules.values()):
                for rules_object in self._compiled_rules.values():
                    if hasattr(rules_object, 'namespaces'):
                        stats["namespaces"].extend(rules_object.namespaces)

                    # Try to get rule count - this depends on yara-python implementation
                    # and might not work with all versions
                    try:
                        stats["rule_count"] = len(rules_object)
                    except (TypeError, AttributeError):
                        # If we can't get the count, use namespace count as a proxy
                        stats["rule_count"] = len(stats["namespaces"])

            return stats

        except Exception as e:
            logger.error(f"Error getting rule stats: {e}")
            return {
                "rule_paths": self.rule_paths.copy(),
                "error": str(e)
            }

# Export the public API
__all__ = ['YaraScanner', 'YARA_AVAILABLE']
