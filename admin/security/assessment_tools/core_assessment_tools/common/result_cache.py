"""
Result caching implementation for security assessment tools.

This module provides caching functionality for assessment results to improve
performance and enable offline access to previous results. It supports multiple
cache backends, expiration policies, and secure storage of assessment data.
"""

import datetime
import json
import logging
import os
import shutil
import tempfile
import time
from functools import wraps
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from .assessment_logging import get_assessment_logger
from .data_types import AssessmentResult
from .error_handlers import handle_assessment_error

# Initialize module logger
logger = get_assessment_logger("result_cache")

# Cache lock to prevent concurrent write access
_cache_lock = Lock()


class ResultCache:
    """
    Cache for assessment results.

    Provides a configurable caching system for assessment results with support for
    file-based and memory-based caches, data expiration, and secure storage.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        max_size: int = 500,  # Max number of cached items
        default_ttl: int = 86400,  # Default TTL in seconds (1 day)
        in_memory: bool = False  # Whether to use in-memory cache
    ):
        """
        Initialize the result cache.

        Args:
            cache_dir: Directory for cached results (if None, uses default location)
            max_size: Maximum number of cached results
            default_ttl: Default time-to-live in seconds
            in_memory: Whether to cache results in memory only
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.in_memory = in_memory
        self._memory_cache: Dict[str, Dict[str, Any]] = {}

        # Set up cache directory for file-based cache
        if not in_memory:
            if cache_dir:
                self.cache_dir = cache_dir
            else:
                # Default cache location under project directory
                project_root = Path(__file__).parent.parent.parent.parent
                self.cache_dir = project_root / "cache" / "assessment_results"

            # Create cache directory with secure permissions if it doesn't exist
            try:
                os.makedirs(self.cache_dir, mode=0o750, exist_ok=True)
                logger.info(f"Using cache directory: {self.cache_dir}")
            except OSError as e:
                logger.error(f"Failed to create cache directory: {e}")
                # Fall back to in-memory cache if filesystem access fails
                self.in_memory = True
                logger.info("Falling back to in-memory cache")

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get a cached result by key.

        Args:
            key: Cache key

        Returns:
            Cached assessment result or None if not found or expired
        """
        if self.in_memory:
            return self._get_from_memory(key)
        else:
            return self._get_from_file(key)

    def set(self, key: str, result: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """
        Store an assessment result in the cache.

        Args:
            key: Cache key
            result: Assessment result to cache
            ttl: Time-to-live in seconds (uses default if None)

        Returns:
            True if successful, False otherwise
        """
        if self.in_memory:
            return self._set_in_memory(key, result, ttl)
        else:
            return self._set_in_file(key, result, ttl)

    def delete(self, key: str) -> bool:
        """
        Delete a cached result.

        Args:
            key: Cache key to delete

        Returns:
            True if successful, False otherwise
        """
        if self.in_memory:
            return self._delete_from_memory(key)
        else:
            return self._delete_from_file(key)

    def clear(self) -> bool:
        """
        Clear all cached results.

        Returns:
            True if successful, False otherwise
        """
        if self.in_memory:
            return self._clear_memory()
        else:
            return self._clear_files()

    def get_keys(self, pattern: Optional[str] = None) -> List[str]:
        """
        Get all cached keys, optionally filtered by pattern.

        Args:
            pattern: Optional filter pattern (supports * wildcard)

        Returns:
            List of matching keys
        """
        if self.in_memory:
            return self._get_memory_keys(pattern)
        else:
            return self._get_file_keys(pattern)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        if self.in_memory:
            return self._get_memory_stats()
        else:
            return self._get_file_stats()

    def prune_expired(self) -> int:
        """
        Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        if self.in_memory:
            return self._prune_memory_expired()
        else:
            return self._prune_file_expired()

    def export_cache(self, output_path: Path) -> bool:
        """
        Export the entire cache to a file.

        Args:
            output_path: Path to save the export

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.in_memory:
                cache_data = {
                    "type": "memory",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "entries": self._memory_cache
                }
                with open(output_path, "w") as f:
                    json.dump(cache_data, f, indent=2)
                return True
            else:
                # Create a zip archive of the cache directory
                shutil.make_archive(
                    str(output_path).rstrip('.zip'),
                    'zip',
                    self.cache_dir
                )
                return True
        except Exception as e:
            logger.error(f"Failed to export cache: {e}")
            return False

    def import_cache(self, input_path: Path) -> bool:
        """
        Import a previously exported cache.

        Args:
            input_path: Path to the exported cache

        Returns:
            True if successful, False otherwise
        """
        try:
            if input_path.name.endswith(".json"):
                # Import JSON (memory cache)
                with open(input_path, "r") as f:
                    cache_data = json.load(f)

                if self.in_memory:
                    self._memory_cache = cache_data.get("entries", {})
                else:
                    # Convert to file cache
                    for key, entry in cache_data.get("entries", {}).items():
                        self._set_in_file(key, entry["data"], None)
                return True
            elif input_path.name.endswith(".zip"):
                # Import ZIP (file cache)
                if self.in_memory:
                    logger.error("Cannot import file cache to in-memory cache")
                    return False

                # Create temporary directory for extraction
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Extract ZIP archive
                    shutil.unpack_archive(input_path, temp_dir, 'zip')

                    # Copy files to cache directory
                    for src in Path(temp_dir).glob("*.json"):
                        dst = self.cache_dir / src.name
                        shutil.copy2(src, dst)

                return True
            else:
                logger.error(f"Unsupported cache import format: {input_path.suffix}")
                return False
        except Exception as e:
            logger.error(f"Failed to import cache: {e}")
            return False

    # --- In-memory cache implementation ---

    def _get_from_memory(self, key: str) -> Optional[Dict[str, Any]]:
        """Get a result from the in-memory cache."""
        if key not in self._memory_cache:
            return None

        cache_entry = self._memory_cache[key]

        # Check if entry has expired
        if "expires_at" in cache_entry and cache_entry["expires_at"] < time.time():
            # Expired entry
            self._delete_from_memory(key)
            return None

        return cache_entry["data"]

    def _set_in_memory(self, key: str, result: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Store a result in the in-memory cache."""
        try:
            ttl = ttl if ttl is not None else self.default_ttl
            expires_at = time.time() + ttl if ttl > 0 else None

            cache_entry = {
                "data": result,
                "created_at": time.time(),
                "expires_at": expires_at,
                "ttl": ttl
            }

            with _cache_lock:
                # Clean up if cache is full
                if len(self._memory_cache) >= self.max_size:
                    self._prune_memory_expired()

                    # If still full, remove oldest entry
                    if len(self._memory_cache) >= self.max_size:
                        oldest_key = min(
                            self._memory_cache.keys(),
                            key=lambda k: self._memory_cache[k]["created_at"]
                        )
                        del self._memory_cache[oldest_key]

                # Add the new entry
                self._memory_cache[key] = cache_entry

            return True
        except Exception as e:
            logger.error(f"Failed to set cache entry {key}: {e}")
            return False

    def _delete_from_memory(self, key: str) -> bool:
        """Delete a result from the in-memory cache."""
        try:
            with _cache_lock:
                if key in self._memory_cache:
                    del self._memory_cache[key]
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete cache entry {key}: {e}")
            return False

    def _clear_memory(self) -> bool:
        """Clear all entries from the in-memory cache."""
        try:
            with _cache_lock:
                self._memory_cache.clear()
            return True
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            return False

    def _get_memory_keys(self, pattern: Optional[str] = None) -> List[str]:
        """Get all keys from the in-memory cache."""
        if not pattern:
            return list(self._memory_cache.keys())

        # Simple wildcard pattern matching
        import fnmatch
        return [k for k in self._memory_cache.keys() if fnmatch.fnmatch(k, pattern)]

    def _get_memory_stats(self) -> Dict[str, Any]:
        """Get statistics for the in-memory cache."""
        total_size = len(self._memory_cache)

        # Count expired entries
        now = time.time()
        expired = sum(1 for entry in self._memory_cache.values()
                     if "expires_at" in entry and entry["expires_at"] < now)

        # Calculate average TTL
        ttls = [entry.get("ttl", self.default_ttl) for entry in self._memory_cache.values()]
        avg_ttl = sum(ttls) / max(len(ttls), 1)

        # Find oldest and newest entries
        oldest = min(
            (entry["created_at"] for entry in self._memory_cache.values()),
            default=None
        )
        newest = max(
            (entry["created_at"] for entry in self._memory_cache.values()),
            default=None
        )

        return {
            "type": "memory",
            "total_entries": total_size,
            "expired_entries": expired,
            "valid_entries": total_size - expired,
            "capacity": self.max_size,
            "usage_percent": (total_size / self.max_size) * 100 if self.max_size > 0 else 0,
            "avg_ttl_seconds": avg_ttl,
            "oldest_entry_timestamp": oldest,
            "newest_entry_timestamp": newest,
        }

    def _prune_memory_expired(self) -> int:
        """Remove expired entries from the in-memory cache."""
        try:
            now = time.time()
            expired_keys = [
                key for key, entry in self._memory_cache.items()
                if "expires_at" in entry and entry["expires_at"] < now
            ]

            with _cache_lock:
                for key in expired_keys:
                    del self._memory_cache[key]

            return len(expired_keys)
        except Exception as e:
            logger.error(f"Failed to prune expired cache entries: {e}")
            return 0

    # --- File-based cache implementation ---

    def _get_cache_path(self, key: str) -> Path:
        """Get the file path for a cache key."""
        # Sanitize the key to make it a valid filename
        safe_key = "".join(c if c.isalnum() else "_" for c in key)
        return self.cache_dir / f"{safe_key}.json"

    def _get_from_file(self, key: str) -> Optional[Dict[str, Any]]:
        """Get a result from the file-based cache."""
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, "r") as f:
                cache_entry = json.load(f)

            # Check if entry has expired
            if "expires_at" in cache_entry and cache_entry["expires_at"] < time.time():
                # Expired entry
                self._delete_from_file(key)
                return None

            return cache_entry["data"]
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to read cache file for {key}: {e}")
            return None

    def _set_in_file(self, key: str, result: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Store a result in the file-based cache."""
        try:
            ttl = ttl if ttl is not None else self.default_ttl
            expires_at = time.time() + ttl if ttl > 0 else None

            cache_entry = {
                "data": result,
                "created_at": time.time(),
                "expires_at": expires_at,
                "ttl": ttl
            }

            cache_path = self._get_cache_path(key)

            # Clean up if cache is full
            if len(list(self.cache_dir.glob("*.json"))) >= self.max_size:
                self._prune_file_expired()

                # If still full, remove oldest entry
                cache_files = list(self.cache_dir.glob("*.json"))
                if len(cache_files) >= self.max_size:
                    oldest_file = min(
                        cache_files,
                        key=lambda p: p.stat().st_mtime
                    )
                    oldest_file.unlink(missing_ok=True)

            # Use atomic write pattern for better reliability
            with _cache_lock:
                temp_file = cache_path.with_suffix(".tmp")
                with open(temp_file, "w") as f:
                    json.dump(cache_entry, f)

                # Set secure permissions
                os.chmod(temp_file, 0o640)

                # Rename to target file (atomic on most filesystems)
                temp_file.replace(cache_path)

            return True
        except Exception as e:
            logger.error(f"Failed to write cache file for {key}: {e}")
            return False

    def _delete_from_file(self, key: str) -> bool:
        """Delete a result from the file-based cache."""
        try:
            cache_path = self._get_cache_path(key)
            with _cache_lock:
                if cache_path.exists():
                    cache_path.unlink()
                    return True
            return False
        except OSError as e:
            logger.error(f"Failed to delete cache file for {key}: {e}")
            return False

    def _clear_files(self) -> bool:
        """Clear all entries from the file-based cache."""
        try:
            with _cache_lock:
                for cache_file in self.cache_dir.glob("*.json"):
                    cache_file.unlink()
            return True
        except OSError as e:
            logger.error(f"Failed to clear cache directory: {e}")
            return False

    def _get_file_keys(self, pattern: Optional[str] = None) -> List[str]:
        """Get all keys from the file-based cache."""
        try:
            if not pattern:
                # Get all JSON files in cache directory
                return [p.stem for p in self.cache_dir.glob("*.json")]
            else:
                # Apply wildcard pattern
                import fnmatch
                all_keys = [p.stem for p in self.cache_dir.glob("*.json")]
                return [k for k in all_keys if fnmatch.fnmatch(k, pattern)]
        except OSError as e:
            logger.error(f"Failed to list cache files: {e}")
            return []

    def _get_file_stats(self) -> Dict[str, Any]:
        """Get statistics for the file-based cache."""
        try:
            # Get all cache files
            cache_files = list(self.cache_dir.glob("*.json"))
            total_size = len(cache_files)

            # Count expired entries
            now = time.time()
            expired = 0
            ttls = []
            created_times = []

            for cache_file in cache_files:
                try:
                    with open(cache_file, "r") as f:
                        cache_entry = json.load(f)

                    if "expires_at" in cache_entry and cache_entry["expires_at"] < now:
                        expired += 1

                    if "ttl" in cache_entry:
                        ttls.append(cache_entry["ttl"])

                    if "created_at" in cache_entry:
                        created_times.append(cache_entry["created_at"])
                except (json.JSONDecodeError, OSError):
                    expired += 1  # Count corrupted files as expired

            # Calculate average TTL
            avg_ttl = sum(ttls) / max(len(ttls), 1)

            # Find oldest and newest entries
            oldest = min(created_times, default=None)
            newest = max(created_times, default=None)

            # Calculate total size in bytes
            size_bytes = sum(cache_file.stat().st_size for cache_file in cache_files)

            return {
                "type": "file",
                "total_entries": total_size,
                "expired_entries": expired,
                "valid_entries": total_size - expired,
                "capacity": self.max_size,
                "usage_percent": (total_size / self.max_size) * 100 if self.max_size > 0 else 0,
                "avg_ttl_seconds": avg_ttl,
                "oldest_entry_timestamp": oldest,
                "newest_entry_timestamp": newest,
                "total_size_bytes": size_bytes,
                "cache_directory": str(self.cache_dir)
            }
        except Exception as e:
            logger.error(f"Failed to get cache statistics: {e}")
            return {
                "type": "file",
                "error": str(e),
                "cache_directory": str(self.cache_dir)
            }

    def _prune_file_expired(self) -> int:
        """Remove expired entries from the file-based cache."""
        try:
            now = time.time()
            removed_count = 0

            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, "r") as f:
                        cache_entry = json.load(f)

                    if "expires_at" in cache_entry and cache_entry["expires_at"] < now:
                        with _cache_lock:
                            cache_file.unlink(missing_ok=True)
                            removed_count += 1
                except (json.JSONDecodeError, OSError):
                    # Remove corrupt files
                    with _cache_lock:
                        cache_file.unlink(missing_ok=True)
                        removed_count += 1

            return removed_count
        except Exception as e:
            logger.error(f"Failed to prune expired cache files: {e}")
            return 0


# Global instance for module-level functions
_default_cache: Optional[ResultCache] = None


def get_default_cache() -> ResultCache:
    """
    Get or create the default result cache.

    Returns:
        Default ResultCache instance
    """
    global _default_cache
    if _default_cache is None:
        # Create with default settings
        _default_cache = ResultCache()
    return _default_cache


def cache_result(ttl: Optional[int] = None, key_prefix: str = ""):
    """
    Decorator to cache function results.

    Args:
        ttl: Time-to-live in seconds (uses default if None)
        key_prefix: Prefix for cache keys

    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_default_cache()

            # Generate cache key from function name, args, and kwargs
            args_str = ",".join(str(arg) for arg in args)
            kwargs_str = ",".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
            cache_key = f"{key_prefix}{func.__name__}:{args_str}:{kwargs_str}"

            # Try to get from cache
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return cached_result

            # Cache miss, run function
            logger.debug(f"Cache miss for {cache_key}")
            result = func(*args, **kwargs)

            # Cache result
            cache.set(cache_key, result, ttl)

            return result
        return wrapper
    return decorator


def invalidate_cache_key(key: str) -> bool:
    """
    Invalidate a specific cache key.

    Args:
        key: Cache key to invalidate

    Returns:
        True if successful, False otherwise
    """
    cache = get_default_cache()
    return cache.delete(key)


def invalidate_cache_pattern(pattern: str) -> int:
    """
    Invalidate cache keys matching a pattern.

    Args:
        pattern: Pattern to match (with * as wildcard)

    Returns:
        Number of keys invalidated
    """
    cache = get_default_cache()
    keys = cache.get_keys(pattern)
    count = 0
    for key in keys:
        if cache.delete(key):
            count += 1
    return count


def clear_all_cache() -> bool:
    """
    Clear the entire cache.

    Returns:
        True if successful, False otherwise
    """
    cache = get_default_cache()
    return cache.clear()


def get_cached_assessment(assessment_id: str) -> Optional[AssessmentResult]:
    """
    Get a cached assessment result by ID.

    Args:
        assessment_id: Assessment ID

    Returns:
        AssessmentResult object or None if not found
    """
    from .result_formatter import ResultFormatter

    cache = get_default_cache()
    cached_data = cache.get(f"assessment:{assessment_id}")

    if not cached_data:
        return None

    # Convert back to AssessmentResult
    try:
        formatter = ResultFormatter()
        return formatter.json_to_assessment_result(cached_data)
    except Exception as e:
        logger.error(f"Failed to deserialize cached assessment {assessment_id}: {e}")
        return None


def cache_assessment_result(assessment_result: AssessmentResult, ttl: Optional[int] = None) -> bool:
    """
    Cache an assessment result.

    Args:
        assessment_result: AssessmentResult to cache
        ttl: Time-to-live in seconds (uses default if None)

    Returns:
        True if successful, False otherwise
    """
    from .result_formatter import ResultFormatter

    cache = get_default_cache()
    formatter = ResultFormatter()

    try:
        # Convert AssessmentResult to JSON-serializable dict
        result_dict = formatter.assessment_result_to_json(assessment_result)

        # Cache it
        return cache.set(f"assessment:{assessment_result.assessment_id}", result_dict, ttl)
    except Exception as e:
        logger.error(f"Failed to cache assessment result: {e}")
        return False


def get_cached_results_summary() -> Dict[str, Any]:
    """
    Get a summary of all cached assessment results.

    Returns:
        Summary information about cached assessments
    """
    cache = get_default_cache()
    assessment_keys = cache.get_keys("assessment:*")

    summary = {
        "total_cached_assessments": len(assessment_keys),
        "assessments": []
    }

    for key in assessment_keys:
        assessment_data = cache.get(key)
        if assessment_data:
            # Extract basic information without full details
            assessment_summary = {
                "assessment_id": assessment_data.get("assessment_id"),
                "name": assessment_data.get("name"),
                "status": assessment_data.get("status"),
                "start_time": assessment_data.get("start_time"),
                "end_time": assessment_data.get("end_time")
            }

            # Add findings summary if available
            findings_summary = assessment_data.get("findings_summary")
            if findings_summary:
                assessment_summary["findings_summary"] = findings_summary

            summary["assessments"].append(assessment_summary)

    return summary


def export_cache_to_file(output_path: Path) -> bool:
    """
    Export cache contents to a file.

    Args:
        output_path: Path to save the exported cache

    Returns:
        True if successful, False otherwise
    """
    cache = get_default_cache()
    return cache.export_cache(output_path)


def import_cache_from_file(input_path: Path) -> bool:
    """
    Import cache from a previously exported file.

    Args:
        input_path: Path to the exported cache file

    Returns:
        True if successful, False otherwise
    """
    cache = get_default_cache()
    return cache.import_cache(input_path)


def prune_expired_cache_entries() -> int:
    """
    Remove expired entries from cache.

    Returns:
        Number of entries removed
    """
    cache = get_default_cache()
    return cache.prune_expired()


def get_cache_stats() -> Dict[str, Any]:
    """
    Get cache statistics.

    Returns:
        Dictionary with cache statistics
    """
    cache = get_default_cache()
    return cache.get_stats()


def configure_cache(
    cache_dir: Optional[Path] = None,
    max_size: int = 500,
    default_ttl: int = 86400,
    in_memory: bool = False
) -> None:
    """
    Configure the default cache.

    Args:
        cache_dir: Directory for cached results
        max_size: Maximum number of cached results
        default_ttl: Default time-to-live in seconds
        in_memory: Whether to cache results in memory only
    """
    global _default_cache
    _default_cache = ResultCache(
        cache_dir=cache_dir,
        max_size=max_size,
        default_ttl=default_ttl,
        in_memory=in_memory
    )
    logger.info(f"Configured result cache (in_memory={in_memory}, max_size={max_size})")
