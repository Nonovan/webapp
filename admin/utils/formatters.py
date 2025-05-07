"""
Output formatting utilities for the administrative CLI.

This module provides functions to format command output in various formats
including text, JSON, CSV, and tables.
"""

import json
import logging
from typing import Any, Dict, List, Union

logger = logging.getLogger(__name__)

def format_output(data: Any, output_format: str = "text") -> str:
    """
    Format command output in the requested format.

    Args:
        data: Output data to format
        output_format: Format to use (text, json, csv, table)

    Returns:
        Formatted output string
    """
    if output_format == "json":
        return json.dumps(data, indent=2, default=str)

    elif output_format == "csv":
        if not isinstance(data, list) or not data:
            return "No data or invalid format for CSV output"

        import csv
        import io

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

        return output.getvalue()

    elif output_format == "table":
        if not isinstance(data, list) or not data:
            return "No data or invalid format for table output"

        # Simple ASCII table implementation
        columns = list(data[0].keys())
        col_widths = {col: len(col) for col in columns}

        # Find maximum width for each column
        for row in data:
            for col in columns:
                width = len(str(row.get(col, "")))
                col_widths[col] = max(col_widths[col], width)

        # Generate header
        header = " | ".join(col.ljust(col_widths[col]) for col in columns)
        separator = "-+-".join("-" * col_widths[col] for col in columns)

        # Generate rows
        rows = []
        for row in data:
            formatted_row = " | ".join(
                str(row.get(col, "")).ljust(col_widths[col]) for col in columns
            )
            rows.append(formatted_row)

        return "\n".join([header, separator] + rows)

    else:  # Default text format
        if isinstance(data, dict):
            return "\n".join(f"{k}: {v}" for k, v in data.items())
        elif isinstance(data, list):
            return "\n".join(str(item) for item in data)
        else:
            return str(data)


def mask_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mask sensitive data in command arguments for logging.

    Args:
        data: Command arguments dictionary

    Returns:
        Dictionary with sensitive values masked
    """
    if not isinstance(data, dict):
        return data

    sensitive_fields = [
        "password", "secret", "token", "key", "auth", "credential",
        "api_key", "private", "access_key", "secret_key"
    ]

    masked_data = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_fields):
            masked_data[key] = "******" if value else value
        elif isinstance(value, dict):
            masked_data[key] = mask_sensitive_data(value)
        elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
            masked_data[key] = [mask_sensitive_data(item) for item in value]
        else:
            masked_data[key] = value

    return masked_data
