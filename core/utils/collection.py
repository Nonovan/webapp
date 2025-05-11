"""
Collection utility functions for Cloud Infrastructure Platform.

This module provides utility functions for working with collections such as:
- Dictionary operations
- List manipulations
- Set operations
- Nested data structure handling
- Collection transformations

These utilities simplify common operations on collections and ensure consistent
handling across the application.
"""

import functools
import itertools
import json
import re
import uuid
import base64
from datetime import date, datetime
from decimal import Decimal
from typing import (Any, Callable, Dict, Iterable, Iterator, List, Mapping,
                    MutableMapping, Optional, Sequence, Set, Tuple, TypeVar,
                    Union)

from core.utils.core_utils_constants import (ARRAY_INDEX_PATTERN,
                                             DEFAULT_BATCH_SIZE,
                                             DEFAULT_LIST_LIMIT,
                                             DEFAULT_RECURSION_LIMIT,
                                             MAX_DICT_DEPTH, MAX_PAGE_SIZE,
                                             DEFAULT_PAGE_SIZE,
                                             PATH_SEPARATOR,
                                             SAFE_JSON_SPECIAL_TYPES,
                                             UNLIMITED_DEPTH)


T = TypeVar('T')
K = TypeVar('K')
V = TypeVar('V')


def deep_get(dictionary: Dict, keys: Union[str, List], default: Any = None) -> Any:
    """
    Safely get a value from a nested dictionary using a dot notation path or key list.

    Args:
        dictionary: Dictionary to get value from
        keys: Key path as dot-separated string or list of keys
        default: Default value if key doesn't exist

    Returns:
        Value at key path or default if not found

    Example:
        deep_get(data, "user.profile.name", "Unknown")
        deep_get(data, ["user", "profile", "name"], "Unknown")
    """
    if not dictionary:
        return default

    # Convert dot notation to key list if needed
    if isinstance(keys, str):
        keys = keys.split(PATH_SEPARATOR)

    current = dictionary
    try:
        for key in keys:
            # Check for array index notation (e.g., "users[0]")
            array_match = ARRAY_INDEX_PATTERN.match(key) if isinstance(key, str) else None

            if array_match:
                # Handle array indexing
                base_key, index = array_match.groups()
                if base_key in current and isinstance(current[base_key], list):
                    try:
                        index = int(index)
                        if 0 <= index < len(current[base_key]):
                            current = current[base_key][index]
                        else:
                            return default
                    except (ValueError, TypeError):
                        return default
                else:
                    return default
            elif isinstance(current, dict):
                # Standard dictionary lookup
                current = current.get(key, default)
                # If we hit the default value, terminate early
                if current is default:
                    return default
            else:
                # If current is not a dict, we can't navigate further
                return default

        return current
    except (KeyError, TypeError, IndexError):
        return default


def deep_set(dictionary: Dict, keys: Union[str, List], value: Any) -> Dict:
    """
    Set a value in a nested dictionary using a dot notation path or key list.
    Creates intermediate dictionaries if needed.

    Args:
        dictionary: Dictionary to set value in
        keys: Key path as dot-separated string or list of keys
        value: Value to set

    Returns:
        Updated dictionary

    Example:
        deep_set(data, "user.profile.name", "John Doe")
        deep_set(data, ["user", "profile", "name"], "John Doe")
    """
    if not dictionary:
        dictionary = {}

    # Convert dot notation to key list if needed
    if isinstance(keys, str):
        keys = keys.split(PATH_SEPARATOR)

    current = dictionary
    # Navigate to the last dict in the path
    for key in keys[:-1]:
        # Check for array index notation (e.g., "users[0]")
        array_match = ARRAY_INDEX_PATTERN.match(key) if isinstance(key, str) else None

        if array_match:
            base_key, index = array_match.groups()
            index = int(index)

            # Ensure the base key exists and is a list
            if base_key not in current:
                current[base_key] = []
            elif not isinstance(current[base_key], list):
                current[base_key] = [current[base_key]]

            # Ensure the list is long enough
            while len(current[base_key]) <= index:
                current[base_key].append({})

            current = current[base_key][index]
        else:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]

    # Set the value at the final key
    last_key = keys[-1]

    # Check if the last key contains an array index
    array_match = ARRAY_INDEX_PATTERN.match(last_key) if isinstance(last_key, str) else None
    if array_match:
        base_key, index = array_match.groups()
        index = int(index)

        # Ensure the base key exists and is a list
        if base_key not in current:
            current[base_key] = []
        elif not isinstance(current[base_key], list):
            current[base_key] = [current[base_key]]

        # Ensure the list is long enough
        while len(current[base_key]) <= index:
            current[base_key].append(None)

        current[base_key][index] = value
    else:
        current[last_key] = value

    return dictionary


def deep_update(target: Dict, source: Dict, overwrite: bool = True) -> Dict:
    """
    Update a nested dictionary with another nested dictionary.

    Args:
        target: Dictionary to update
        source: Dictionary to update from
        overwrite: Whether to overwrite existing values

    Returns:
        Updated target dictionary
    """
    for key, value in source.items():
        if isinstance(value, dict) and key in target and isinstance(target[key], dict):
            # Recursively update nested dictionaries
            deep_update(target[key], value, overwrite)
        else:
            # Skip if key exists and not overwriting
            if not overwrite and key in target:
                continue
            target[key] = value

    return target


def deep_filter(data: Dict, filter_func: Callable[[str, Any], bool]) -> Dict:
    """
    Filter a nested dictionary recursively based on a filter function.

    Args:
        data: Dictionary to filter
        filter_func: Function(key, value) that returns True for items to keep

    Returns:
        Filtered dictionary
    """
    if not isinstance(data, dict):
        return data

    result = {}
    for key, value in data.items():
        if isinstance(value, dict):
            # Recursively filter nested dictionaries
            filtered_value = deep_filter(value, filter_func)
            if filtered_value and filter_func(key, filtered_value):
                result[key] = filtered_value
        elif filter_func(key, value):
            result[key] = value

    return result


def flatten_dict(dictionary: Dict, separator: str = PATH_SEPARATOR, prefix: str = '') -> Dict:
    """
    Flatten a nested dictionary into a single-level dictionary with custom key separator.

    Args:
        dictionary: Nested dictionary to flatten
        separator: String used to join keys
        prefix: Prefix for all keys

    Returns:
        Flattened dictionary

    Example:
        flatten_dict({'a': 1, 'b': {'c': 2, 'd': 3}})
        # Returns: {'a': 1, 'b.c': 2, 'b.d': 3}
    """
    items = []
    for key, value in dictionary.items():
        new_key = f"{prefix}{separator}{key}" if prefix else key
        if isinstance(value, dict):
            items.extend(flatten_dict(value, separator, new_key).items())
        else:
            items.append((new_key, value))

    return dict(items)


def unflatten_dict(dictionary: Dict, separator: str = PATH_SEPARATOR) -> Dict:
    """
    Convert a flattened dictionary with separated keys back to a nested dictionary.

    Args:
        dictionary: Flattened dictionary
        separator: String used to split keys

    Returns:
        Nested dictionary

    Example:
        unflatten_dict({'a': 1, 'b.c': 2, 'b.d': 3})
        # Returns: {'a': 1, 'b': {'c': 2, 'd': 3}}
    """
    result = {}
    for key, value in dictionary.items():
        parts = key.split(separator)

        current = result
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    return result


def group_by(items: List[T], key_func: Callable[[T], K]) -> Dict[K, List[T]]:
    """
    Group a list of items by a key function.

    Args:
        items: List of items to group
        key_func: Function that returns the key to group by

    Returns:
        Dictionary mapping keys to lists of items

    Example:
        group_by([1, 2, 3, 4, 5], lambda x: x % 2)
        # Returns: {0: [2, 4], 1: [1, 3, 5]}
    """
    result = {}
    for item in items:
        key = key_func(item)
        if key not in result:
            result[key] = []
        result[key].append(item)

    return result


def partition(items: List[T], predicate: Callable[[T], bool]) -> Tuple[List[T], List[T]]:
    """
    Split a list into two parts based on a predicate function.

    Args:
        items: List to partition
        predicate: Function that returns True for items in first partition

    Returns:
        Tuple of (matched_items, unmatched_items)

    Example:
        partition([1, 2, 3, 4, 5], lambda x: x > 3)
        # Returns: ([4, 5], [1, 2, 3])
    """
    matches = []
    non_matches = []

    for item in items:
        if predicate(item):
            matches.append(item)
        else:
            non_matches.append(item)

    return matches, non_matches


def chunks(lst: List[T], size: int) -> Iterator[List[T]]:
    """
    Yield successive chunks from a list.

    Args:
        lst: List to chunk
        size: Size of each chunk

    Yields:
        Chunks of the list

    Example:
        list(chunks([1, 2, 3, 4, 5, 6, 7], 3))
        # Returns: [[1, 2, 3], [4, 5, 6], [7]]
    """
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def chunk_list(lst: List[T], size: int = DEFAULT_BATCH_SIZE) -> List[List[T]]:
    """
    Split a list into chunks of specified size.

    This function divides a list into smaller sublists of the specified size.
    The last chunk may contain fewer items if the list length is not
    evenly divisible by the chunk size.

    Args:
        lst: List to chunk
        size: Size of each chunk (default: from constants)

    Returns:
        List of list chunks

    Raises:
        ValueError: If size is less than 1

    Example:
        >>> chunk_list([1, 2, 3, 4, 5, 6, 7], 3)
        [[1, 2, 3], [4, 5, 6], [7]]
    """
    if size < 1:
        raise ValueError("Chunk size must be at least 1")

    return [lst[i:i + size] for i in range(0, len(lst), size)]


def unique_items(items: List[T], key_func: Optional[Callable[[T], Any]] = None) -> List[T]:
    """
    Get unique items from a list, preserving order.

    Args:
        items: List of items
        key_func: Optional function to extract comparison key

    Returns:
        List of unique items

    Example:
        unique_items([1, 2, 3, 1, 2, 4, 5])
        # Returns: [1, 2, 3, 4, 5]

        unique_items([{'id': 1}, {'id': 2}, {'id': 1}], key_func=lambda x: x['id'])
        # Returns: [{'id': 1}, {'id': 2}]
    """
    if key_func is None:
        # Use items themselves as keys
        seen = set()
        return [x for x in items if not (x in seen or seen.add(x))]
    else:
        # Use key function for comparison
        seen = set()
        result = []
        for item in items:
            key = key_func(item)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result


def find_duplicates(items: List[T], key_func: Optional[Callable[[T], Any]] = None) -> Dict[Any, List[T]]:
    """
    Find duplicate items in a list, optionally using a key function.

    Identifies items that appear multiple times in a list and groups them by
    their value or by the result of applying the key function to each item.

    Args:
        items: List of items to check for duplicates
        key_func: Optional function to extract a comparison key from each item
            If None, the items themselves are used as keys

    Returns:
        Dictionary mapping keys to lists of duplicate items

    Example:
        >>> find_duplicates([1, 2, 3, 1, 4, 2])
        {1: [1, 1], 2: [2, 2]}

        >>> find_duplicates(
        ...     [{'id': 1, 'name': 'A'}, {'id': 2, 'name': 'B'}, {'id': 1, 'name': 'C'}],
        ...     key_func=lambda x: x['id']
        ... )
        {1: [{'id': 1, 'name': 'A'}, {'id': 1, 'name': 'C'}]}
    """
    # Track occurrences of each item or key
    occurrences: Dict[Any, List[T]] = {}
    result: Dict[Any, List[T]] = {}

    for item in items:
        key = key_func(item) if key_func else item

        if key not in occurrences:
            occurrences[key] = []

        occurrences[key].append(item)

        # If we've seen this key before and it's not yet in results,
        # add it to our results as a duplicate
        if len(occurrences[key]) == 2:
            result[key] = occurrences[key].copy()
        # If we've seen this key multiple times and it's already in results,
        # just append the new item
        elif len(occurrences[key]) > 2:
            result[key].append(item)

    return result


def unique_by(items: List[T], key_func: Callable[[T], Any]) -> List[T]:
    """
    Return a list of unique items based on a key function.

    Unlike the standard `set` operation which requires items to be hashable
    and eliminates duplicates based on the item itself, this function uses
    a key function to determine uniqueness. It preserves the original order
    and returns the first item found for each unique key.

    Args:
        items: List of items to filter
        key_func: Function to extract the comparison key from each item

    Returns:
        List of items with duplicates removed

    Example:
        >>> unique_by([
        ...     {'id': 1, 'name': 'Alice'},
        ...     {'id': 2, 'name': 'Bob'},
        ...     {'id': 1, 'name': 'Alice (dup)'}
        ... ], key_func=lambda x: x['id'])
        [{'id': 1, 'name': 'Alice'}, {'id': 2, 'name': 'Bob'}]
    """
    seen = set()
    result = []

    for item in items:
        key = key_func(item)
        if key not in seen:
            seen.add(key)
            result.append(item)

    return result


def find_first(items: Iterable[T], predicate: Callable[[T], bool], default: Optional[T] = None) -> Optional[T]:
    """
    Find the first item in a collection that matches a predicate.

    Args:
        items: Collection to search
        predicate: Function that returns True for a match
        default: Default value if no match is found

    Returns:
        First matching item or default

    Example:
        find_first([1, 2, 3, 4], lambda x: x > 2)
        # Returns: 3
    """
    return next((item for item in items if predicate(item)), default)


def detect_cycles(graph: Dict[T, List[T]], max_depth: int = DEFAULT_RECURSION_LIMIT) -> Optional[List[T]]:
    """
    Detect cycles in a directed graph represented as adjacency list.

    Args:
        graph: Dictionary mapping nodes to lists of adjacent nodes
        max_depth: Maximum recursion depth for cycle detection

    Returns:
        First cycle found as list of nodes, or None if no cycles

    Example:
        detect_cycles({'A': ['B'], 'B': ['C'], 'C': ['A']})
        # Returns: ['A', 'B', 'C', 'A']
    """
    visited = set()
    path = []
    path_set = set()
    depth_counter = 0

    def visit(node):
        nonlocal depth_counter

        depth_counter += 1
        if depth_counter > max_depth:
            raise RecursionError("Maximum recursion depth exceeded during cycle detection")

        if node in path_set:
            # Found a cycle - extract the cycle from the path
            cycle_start = path.index(node)
            return path[cycle_start:] + [node]

        if node in visited:
            return None

        visited.add(node)
        path.append(node)
        path_set.add(node)

        for neighbor in graph.get(node, []):
            cycle = visit(neighbor)
            if cycle:
                return cycle

        path.pop()
        path_set.remove(node)
        depth_counter -= 1
        return None

    # Check each unvisited node
    for node in graph:
        if node not in visited:
            depth_counter = 0
            try:
                cycle = visit(node)
                if cycle:
                    return cycle
            except RecursionError:
                # Reset and continue with next node if recursion limit reached
                path.clear()
                path_set.clear()
                continue

    return None


def merge_dicts(*dicts: Dict, deep: bool = False, overwrite: bool = True) -> Dict:
    """
    Merge multiple dictionaries.

    Args:
        *dicts: Dictionaries to merge
        deep: Whether to merge nested dictionaries (True) or just top level (False)
        overwrite: Whether later dictionaries should overwrite earlier ones

    Returns:
        Merged dictionary

    Example:
        >>> merge_dicts({'a': 1}, {'b': 2}, {'a': 3}, overwrite=True)
        {'a': 3, 'b': 2}

        >>> merge_dicts({'a': {'x': 1}}, {'a': {'y': 2}}, deep=True)
        {'a': {'x': 1, 'y': 2}}
    """
    if not dicts:
        return {}

    if len(dicts) == 1:
        return dicts[0].copy()

    result = {}

    if deep:
        # Use deep_update for recursive merging
        for d in dicts:
            deep_update(result, d, overwrite)
        return result
    else:
        # Simple top-level merge
        for d in dicts:
            if overwrite:
                result.update(d)
            else:
                for key, value in d.items():
                    if key not in result:
                        result[key] = value

        return result


def index_by(items: Iterable[T], key_func: Callable[[T], K]) -> Dict[K, T]:
    """
    Create a dictionary from a list of items, using a key function.

    Args:
        items: Items to index
        key_func: Function to extract key for each item

    Returns:
        Dictionary mapping keys to items

    Example:
        index_by([{'id': 1, 'name': 'Alice'}, {'id': 2, 'name': 'Bob'}], lambda x: x['id'])
        # Returns: {1: {'id': 1, 'name': 'Alice'}, 2: {'id': 2, 'name': 'Bob'}}
    """
    return {key_func(item): item for item in items}


def dict_transform(
    dictionary: Dict,
    transform_func: Callable[[str, Any], Optional[Tuple[str, Any]]],
    recursive: bool = True,
    max_depth: int = MAX_DICT_DEPTH
) -> Dict:
    """
    Transform a dictionary by applying a function to each key-value pair.

    Args:
        dictionary: Dictionary to transform
        transform_func: Function that takes (key, value) and returns new (key, value) or None to exclude
        recursive: Whether to recursively transform nested dictionaries
        max_depth: Maximum recursion depth to prevent stack overflow

    Returns:
        Transformed dictionary

    Example:
        dict_transform({'a': 1, 'b': 2}, lambda k, v: (k.upper(), v * 2))
        # Returns: {'A': 2, 'B': 4}
    """
    if max_depth <= 0:
        # Reached maximum recursion depth, return as-is
        return dictionary

    result = {}

    for key, value in dictionary.items():
        # Transform nested dictionaries if recursive
        if recursive and isinstance(value, dict) and max_depth > 0:
            transformed_value = dict_transform(value, transform_func, recursive, max_depth - 1)
        else:
            transformed_value = value

        # Apply transformation function
        transformation = transform_func(key, transformed_value)

        # Skip if transformation returns None
        if transformation is not None:
            new_key, new_value = transformation
            result[new_key] = new_value

    return result


def safe_json_serialize(obj: Any) -> Any:
    """
    Convert object to JSON-serializable format.

    Handles datetime objects, sets, and other common non-serializable types.
    This function is useful for preparing data for JSON serialization that may
    contain types not natively supported by the json module.

    Args:
        obj: Object to serialize

    Returns:
        JSON-serializable representation of the object
    """
    if obj is None:
        return None
    elif isinstance(obj, (str, int, float, bool)):
        return obj
    elif isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, uuid.UUID):
        return str(obj)
    elif isinstance(obj, (set, frozenset)):
        return list(obj)
    elif isinstance(obj, bytes):
        try:
            return obj.decode('utf-8')
        except UnicodeDecodeError:
            # If we can't decode as UTF-8, use base64
            return base64.b64encode(obj).decode('ascii')
    elif isinstance(obj, (list, tuple)):
        return [safe_json_serialize(item) for item in obj]
    elif isinstance(obj, dict):
        return {str(k): safe_json_serialize(v) for k, v in obj.items()}
    elif hasattr(obj, 'to_dict') and callable(getattr(obj, 'to_dict')):
        return safe_json_serialize(obj.to_dict())
    elif hasattr(obj, '__dict__'):
        # For custom objects, convert their __dict__ but skip the private attributes
        return safe_json_serialize({k: v for k, v in obj.__dict__.items()
                                  if not k.startswith('_')})
    else:
        # For everything else, convert to string
        obj_type = str(type(obj))
        if obj_type in SAFE_JSON_SPECIAL_TYPES:
            type_name = SAFE_JSON_SPECIAL_TYPES[obj_type]
            return f"<{type_name}:{str(obj)}>"
        return str(obj)


def filter_none(data: Dict) -> Dict:
    """
    Remove all key-value pairs where the value is None from a dictionary.

    Args:
        data: Dictionary to filter

    Returns:
        Dictionary with None values removed

    Example:
        >>> filter_none({'a': 1, 'b': None, 'c': 3})
        {'a': 1, 'c': 3}
    """
    if not isinstance(data, dict):
        return {}

    return {k: v for k, v in data.items() if v is not None}


def filter_empty(data: Dict) -> Dict:
    """
    Remove all key-value pairs where the value is empty (None, '', [], {}, ()).

    Args:
        data: Dictionary to filter

    Returns:
        Dictionary with empty values removed

    Example:
        >>> filter_empty({'a': 1, 'b': None, 'c': '', 'd': [], 'e': {}, 'f': ()})
        {'a': 1}
    """
    if not isinstance(data, dict):
        return {}

    def is_empty(value):
        if value is None:
            return True
        if isinstance(value, (str, list, dict, tuple, set)) and len(value) == 0:
            return True
        return False

    return {k: v for k, v in data.items() if not is_empty(v)}


def filter_dict_by_keys(data: Dict, keys: List[str], include: bool = True) -> Dict:
    """
    Filter a dictionary to include or exclude specific keys.

    Args:
        data: Dictionary to filter
        keys: List of keys to include or exclude
        include: If True, includes the keys; if False, excludes them

    Returns:
        Filtered dictionary

    Examples:
        >>> filter_dict_by_keys({'a': 1, 'b': 2, 'c': 3}, ['a', 'c'], include=True)
        {'a': 1, 'c': 3}
        >>> filter_dict_by_keys({'a': 1, 'b': 2, 'c': 3}, ['a', 'c'], include=False)
        {'b': 2}
    """
    if not isinstance(data, dict):
        return {}

    if include:
        return {k: v for k, v in data.items() if k in keys}
    else:
        return {k: v for k, v in data.items() if k not in keys}


def transform_keys(data: Dict, transform_func: Callable[[str], str], recursive: bool = True) -> Dict:
    """
    Transform all keys in a dictionary using a transformation function.

    Args:
        data: Dictionary whose keys should be transformed
        transform_func: Function that takes a key string and returns a new key string
        recursive: Whether to recursively transform keys in nested dictionaries

    Returns:
        Dictionary with transformed keys

    Example:
        >>> transform_keys({'first_name': 'John', 'last_name': 'Doe'},
        ...                lambda k: k.replace('_', '-'))
        {'first-name': 'John', 'last-name': 'Doe'}
    """
    if not isinstance(data, dict):
        return {}

    result = {}
    for key, value in data.items():
        new_key = transform_func(key)
        # Handle nested dictionaries
        if isinstance(value, dict) and recursive:
            result[new_key] = transform_keys(value, transform_func, recursive)
        else:
            result[new_key] = value

    return result


def transform_values(data: Dict, transform_func: Callable[[Any], Any], recursive: bool = True) -> Dict:
    """
    Transform all values in a dictionary using a transformation function.

    Args:
        data: Dictionary whose values should be transformed
        transform_func: Function that takes a value and returns a new value
        recursive: Whether to recursively transform values in nested dictionaries

    Returns:
        Dictionary with transformed values

    Example:
        >>> transform_values({'a': 1, 'b': 2, 'c': 3}, lambda x: x * 2)
        {'a': 2, 'b': 4, 'c': 6}
    """
    if not isinstance(data, dict):
        return {}

    result = {}
    for key, value in data.items():
        # Handle nested dictionaries
        if isinstance(value, dict) and recursive:
            result[key] = transform_values(value, transform_func, recursive)
        else:
            result[key] = transform_func(value)

    return result


def paginate(items: List[T], page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> Tuple[List[T], Dict[str, Any]]:
    """
    Paginate a list of items.

    Args:
        items: List of items to paginate
        page: Page number (1-based)
        page_size: Number of items per page (default from constants)

    Returns:
        Tuple of (paginated_items, pagination_info)

    Example:
        >>> items = list(range(100))
        >>> results, info = paginate(items, page=2, page_size=10)
        >>> len(results)
        10
        >>> results[0]
        10
        >>> info
        {'page': 2, 'page_size': 10, 'total_pages': 10, 'total_items': 100, 'has_next': True, 'has_prev': True}
    """
    # Validate input
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE
    if page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    # Calculate pagination
    total_items = len(items)
    total_pages = (total_items + page_size - 1) // page_size if total_items > 0 else 1
    page = min(page, total_pages)  # Ensure page isn't beyond the last page

    # Get paginated items
    start_idx = (page - 1) * page_size
    end_idx = min(start_idx + page_size, total_items)
    paginated_items = items[start_idx:end_idx]

    # Build pagination info
    pagination_info = {
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'total_items': total_items,
        'has_next': page < total_pages,
        'has_prev': page > 1
    }

    return paginated_items, pagination_info


def batch_process(items: List[T], func: Callable[[List[T]], Any], batch_size: int = DEFAULT_BATCH_SIZE) -> List[Any]:
    """
    Process a list in batches using a provided function.

    This function is useful for performing operations on large lists that
    should be broken up into smaller chunks, such as database operations.

    Args:
        items: List of items to process
        func: Function that takes a batch of items and processes them
        batch_size: Size of each batch

    Returns:
        List of results from each batch processing

    Example:
        >>> def process_batch(batch):
        ...     return [item * 2 for item in batch]
        >>> batch_process([1, 2, 3, 4, 5], process_batch, batch_size=2)
        [[2, 4], [6, 8], [10]]
    """
    if not items:
        return []

    results = []
    for batch in chunk_list(items, batch_size):
        result = func(batch)
        results.append(result)

    return results


def limit_list_length(items: List, max_length: int = DEFAULT_LIST_LIMIT) -> Tuple[List, bool]:
    """
    Limit a list to a maximum length, returning whether it was truncated.

    Args:
        items: List to limit
        max_length: Maximum allowed length

    Returns:
        Tuple of (limited_list, was_truncated)

    Example:
        >>> limit_list_length([1, 2, 3, 4, 5], 3)
        ([1, 2, 3], True)
        >>> limit_list_length([1, 2, 3], 5)
        ([1, 2, 3], False)
    """
    if not isinstance(items, list):
        return ([], False)

    if len(items) <= max_length:
        return (items, False)

    return (items[:max_length], True)


def walk_dict(
    data: Dict,
    visit_func: Callable[[str, Any, List[str]], None],
    path: Optional[List[str]] = None,
    max_depth: int = UNLIMITED_DEPTH
) -> None:
    """
    Walk through a nested dictionary, calling a visitor function for each value.

    Args:
        data: Dictionary to walk through
        visit_func: Function to call for each value with args (key, value, path)
        path: Current path in the dictionary (used in recursion)
        max_depth: Maximum recursion depth, -1 for unlimited

    Example:
        >>> def print_values(key, value, path):
        ...     print(f"{'.'.join(path)}: {value}")
        >>> data = {'a': 1, 'b': {'c': 2, 'd': 3}}
        >>> walk_dict(data, print_values)
        a: 1
        b.c: 2
        b.d: 3
    """
    if path is None:
        path = []

    # Check max depth
    if max_depth == 0:
        return

    for key, value in data.items():
        current_path = path + [key]
        visit_func(key, value, current_path)

        if isinstance(value, dict) and (max_depth == UNLIMITED_DEPTH or max_depth > 0):
            next_depth = max_depth - 1 if max_depth != UNLIMITED_DEPTH else UNLIMITED_DEPTH
            walk_dict(value, visit_func, current_path, next_depth)


def dict_to_json(data: Dict, indent: Optional[int] = None, sort_keys: bool = False) -> str:
    """
    Convert dictionary to JSON string, handling non-serializable types.

    Args:
        data: Dictionary to convert
        indent: Indentation level (None for compact)
        sort_keys: Whether to sort keys alphabetically

    Returns:
        JSON string representation of the dictionary

    Example:
        >>> dict_to_json({'a': 1, 'b': datetime(2022, 1, 1)})
        '{"a": 1, "b": "2022-01-01T00:00:00"}'
    """
    # Use the default encoder for JSON serializable types, and safe_json_serialize for others
    class CustomEncoder(json.JSONEncoder):
        def default(self, obj):
            return safe_json_serialize(obj)

    return json.dumps(data, indent=indent, sort_keys=sort_keys, cls=CustomEncoder)


# List of functions available when importing from this module
__all__ = [
    # Dictionary operations
    'deep_get',
    'deep_set',
    'deep_update',
    'deep_filter',
    'flatten_dict',
    'unflatten_dict',
    'merge_dicts',
    'dict_transform',
    'transform_keys',
    'transform_values',
    'filter_none',
    'filter_empty',
    'filter_dict_by_keys',
    'walk_dict',
    'dict_to_json',

    # List operations
    'group_by',
    'partition',
    'chunks',
    'chunk_list',
    'unique_items',
    'unique_by',
    'find_first',
    'find_duplicates',
    'paginate',
    'batch_process',
    'limit_list_length',

    # Graph operations
    'detect_cycles',

    # Advanced operations
    'index_by',
    'safe_json_serialize'
]
