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
from typing import Any, Dict, List, Optional, Set, Tuple, TypeVar, Union, Callable, Iterator, Iterable, Mapping, MutableMapping, Sequence


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
        keys = keys.split('.')

    current = dictionary
    try:
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key, default)
            else:
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
        keys = keys.split('.')

    current = dictionary
    # Navigate to the last dict in the path
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]

    # Set the value at the final key
    current[keys[-1]] = value

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


def flatten_dict(dictionary: Dict, separator: str = '.', prefix: str = '') -> Dict:
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


def unflatten_dict(dictionary: Dict, separator: str = '.') -> Dict:
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


def detect_cycles(graph: Dict[T, List[T]]) -> Optional[List[T]]:
    """
    Detect cycles in a directed graph represented as adjacency list.

    Args:
        graph: Dictionary mapping nodes to lists of adjacent nodes

    Returns:
        First cycle found as list of nodes, or None if no cycles

    Example:
        detect_cycles({'A': ['B'], 'B': ['C'], 'C': ['A']})
        # Returns: ['A', 'B', 'C', 'A']
    """
    visited = set()
    path = []
    path_set = set()

    def visit(node):
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
        return None

    # Check each unvisited node
    for node in graph:
        if node not in visited:
            cycle = visit(node)
            if cycle:
                return cycle

    return None


def merge_dicts(*dicts: Dict, overwrite: bool = True) -> Dict:
    """
    Merge multiple dictionaries.

    Args:
        *dicts: Dictionaries to merge
        overwrite: Whether later dictionaries should overwrite earlier ones

    Returns:
        Merged dictionary
    """
    result = {}
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
    recursive: bool = True
) -> Dict:
    """
    Transform a dictionary by applying a function to each key-value pair.

    Args:
        dictionary: Dictionary to transform
        transform_func: Function that takes (key, value) and returns new (key, value) or None to exclude
        recursive: Whether to recursively transform nested dictionaries

    Returns:
        Transformed dictionary

    Example:
        dict_transform({'a': 1, 'b': 2}, lambda k, v: (k.upper(), v * 2))
        # Returns: {'A': 2, 'B': 4}
    """
    result = {}

    for key, value in dictionary.items():
        # Transform nested dictionaries if recursive
        if recursive and isinstance(value, dict):
            transformed_value = dict_transform(value, transform_func, recursive)
        else:
            transformed_value = value

        # Apply transformation function
        transformation = transform_func(key, transformed_value)

        # Skip if transformation returns None
        if transformation is not None:
            new_key, new_value = transformation
            result[new_key] = new_value

    return result
