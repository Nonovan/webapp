"""
Output formatting utilities for security assessment tools.

This module provides standalone formatting functions for converting assessment data
to various output formats (JSON, CSV, XML, HTML, Markdown). These functions are used
by the ResultFormatter class but can also be used independently for simpler formatting tasks.
"""

import csv
import io
import json
import datetime
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union
from xml.dom import minidom
from pathlib import Path

from .assessment_logging import get_assessment_logger

logger = get_assessment_logger("output_formatters")

def format_json_output(
    data: Dict[str, Any],
    indent: int = 2,
    sort_keys: bool = False
) -> str:
    """
    Format data as JSON.

    Args:
        data: Data to format
        indent: JSON indentation level
        sort_keys: Whether to sort keys

    Returns:
        JSON-formatted string
    """
    return json.dumps(data, indent=indent, sort_keys=sort_keys, default=str)


def format_csv_output(
    data: List[Dict[str, Any]],
    field_names: Optional[List[str]] = None,
    delimiter: str = ','
) -> str:
    """
    Format data as CSV.

    Args:
        data: List of dictionaries to format
        field_names: List of field names to include (defaults to all keys in first dict)
        delimiter: CSV delimiter character

    Returns:
        CSV-formatted string
    """
    if not data:
        return ""

    output = io.StringIO()

    # If field_names not specified, use keys from first item
    if not field_names and data:
        field_names = list(data[0].keys())

    writer = csv.DictWriter(
        output,
        fieldnames=field_names,
        delimiter=delimiter,
        extrasaction='ignore'
    )

    writer.writeheader()
    writer.writerows(data)

    return output.getvalue()


def format_xml_output(
    data: Dict[str, Any],
    root_element: str = "assessment_result",
    pretty_print: bool = True
) -> str:
    """
    Format data as XML.

    Args:
        data: Data to format
        root_element: Name for the XML root element
        pretty_print: Whether to format with indentation

    Returns:
        XML-formatted string
    """
    try:
        # Create root element and populate
        root = ET.Element(root_element)
        _convert_dict_to_xml(root, data)

        # Convert to string
        xml_str = ET.tostring(root, encoding='unicode')

        # Pretty print if requested
        if pretty_print:
            xml_str = minidom.parseString(xml_str).toprettyxml(indent="  ")

        return xml_str
    except Exception as e:
        logger.error(f"Error formatting XML: {str(e)}")
        return f"<error>Error formatting XML: {str(e)}</error>"


def format_html_output(
    data: Dict[str, Any],
    title: str = "Assessment Report",
    include_css: bool = True
) -> str:
    """
    Format data as HTML.

    Args:
        data: Data to format
        title: HTML document title
        include_css: Whether to include basic CSS styling

    Returns:
        HTML-formatted string
    """
    html = ["<!DOCTYPE html>", "<html>", "<head>"]
    html.append(f"  <title>{title}</title>")

    if include_css:
        html.append("  <style>")
        html.append("    body { font-family: Arial, sans-serif; margin: 20px; }")
        html.append("    h1 { color: #0066cc; }")
        html.append("    table { border-collapse: collapse; width: 100%; }")
        html.append("    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }")
        html.append("    th { background-color: #f2f2f2; }")
        html.append("    tr:nth-child(even) { background-color: #f2f2f2; }")
        html.append("    .critical { color: #721c24; background-color: #f8d7da; }")
        html.append("    .high { color: #856404; background-color: #fff3cd; }")
        html.append("    .medium { color: #0c5460; background-color: #d1ecf1; }")
        html.append("    .low { color: #155724; background-color: #d4edda; }")
        html.append("    .info { color: #383d41; background-color: #e2e3e5; }")
        html.append("    .section { margin-bottom: 30px; }")
        html.append("  </style>")

    html.append("</head>")
    html.append("<body>")

    # Convert data to HTML
    html.append(f"  <h1>{title}</h1>")

    _render_dict_as_html(data, html)

    html.append("</body>")
    html.append("</html>")

    return "\n".join(html)


def format_markdown_output(
    data: Dict[str, Any],
    title: str = "Assessment Report"
) -> str:
    """
    Format data as Markdown.

    Args:
        data: Data to format
        title: Markdown document title

    Returns:
        Markdown-formatted string
    """
    md = [f"# {title}", ""]

    # Render the data recursively
    _render_dict_as_markdown(data, md)

    return "\n".join(md)


def format_text_output(
    data: Dict[str, Any],
    title: str = "Assessment Report",
    width: int = 80
) -> str:
    """
    Format data as plain text.

    Args:
        data: Data to format
        title: Text report title
        width: Maximum line width

    Returns:
        Text-formatted string
    """
    text = []

    # Header with horizontal line
    text.append("=" * width)
    text.append(title.upper())
    text.append("=" * width)

    # Add timestamp
    text.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    text.append("")

    # Render the data recursively
    _render_dict_as_text(data, text, width)

    return "\n".join(text)


def write_to_file(content: str, output_path: Union[str, Path]) -> bool:
    """
    Write content to a file.

    Args:
        content: Formatted content to write
        output_path: Path to write the file to

    Returns:
        True if successful, False otherwise
    """
    try:
        output_path = Path(output_path)

        # Create directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"Content written to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Error writing content to {output_path}: {str(e)}")
        return False


# Helper functions
def _convert_dict_to_xml(parent: ET.Element, data_dict: Dict[str, Any]) -> None:
    """Convert a dictionary to XML elements."""
    for key, value in data_dict.items():
        # Create valid XML element name (remove spaces, non-alphanumeric chars)
        key = ''.join(c for c in key if c.isalnum() or c in '_-')
        key = key.lower()

        if key == '':
            key = 'item'

        # Handle different types
        if isinstance(value, dict):
            element = ET.SubElement(parent, key)
            _convert_dict_to_xml(element, value)
        elif isinstance(value, list):
            list_element = ET.SubElement(parent, key + '_list')
            for item in value:
                if isinstance(item, dict):
                    item_element = ET.SubElement(list_element, key)
                    _convert_dict_to_xml(item_element, item)
                else:
                    item_element = ET.SubElement(list_element, 'item')
                    item_element.text = str(item)
        else:
            element = ET.SubElement(parent, key)
            element.text = str(value)


def _render_dict_as_html(d: Dict[str, Any], html: List[str], level: int = 0) -> None:
    """Render a dictionary as HTML."""
    html.append("  <table>")

    for key, value in d.items():
        html.append("    <tr>")
        html.append(f"      <th>{key}</th>")

        # Handle different value types
        if isinstance(value, dict):
            html.append("      <td>")
            _render_dict_as_html(value, html, level + 1)
            html.append("      </td>")
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                # List of dictionaries
                html.append("      <td>")
                _render_list_of_dicts_as_html(value, html, level + 1)
                html.append("      </td>")
            else:
                # Simple list
                html.append(f"      <td>{', '.join(str(item) for item in value)}</td>")
        else:
            html.append(f"      <td>{value}</td>")

        html.append("    </tr>")

    html.append("  </table>")


def _render_list_of_dicts_as_html(items: List[Dict[str, Any]], html: List[str], level: int = 0) -> None:
    """Render a list of dictionaries as HTML tables."""
    for i, item in enumerate(items):
        if i > 0:
            html.append("  <hr>")
        _render_dict_as_html(item, html, level + 1)


def _render_dict_as_markdown(d: Dict[str, Any], md: List[str], level: int = 0) -> None:
    """Render a dictionary as Markdown."""
    for key, value in d.items():
        # Handle different value types
        if isinstance(value, dict):
            md.append(f"{'#' * (level + 2)} {key}")
            md.append("")
            _render_dict_as_markdown(value, md, level + 1)
        elif isinstance(value, list):
            md.append(f"{'#' * (level + 2)} {key}")
            md.append("")
            if value and isinstance(value[0], dict):
                # List of dictionaries
                _render_list_of_dicts_as_markdown(value, md, level + 1)
            else:
                # Simple list
                for item in value:
                    md.append(f"- {item}")
                md.append("")
        else:
            md.append(f"**{key}:** {value}  ")

    md.append("")


def _render_list_of_dicts_as_markdown(items: List[Dict[str, Any]], md: List[str], level: int = 0) -> None:
    """Render a list of dictionaries as Markdown."""
    for i, item in enumerate(items):
        md.append(f"### Item {i+1}")
        _render_dict_as_markdown(item, md, level + 1)
        md.append("---")
        md.append("")


def _render_dict_as_text(d: Dict[str, Any], text: List[str], width: int = 80, indent: int = 0) -> None:
    """Render a dictionary as plain text."""
    for key, value in d.items():
        indent_str = " " * indent

        if isinstance(value, dict):
            text.append(f"{indent_str}{key}:")
            _render_dict_as_text(value, text, width, indent + 2)
        elif isinstance(value, list):
            text.append(f"{indent_str}{key}:")
            if value and isinstance(value[0], dict):
                # List of dictionaries
                for i, item in enumerate(value):
                    text.append(f"{indent_str}  Item {i+1}:")
                    _render_dict_as_text(item, text, width, indent + 4)
            else:
                # Simple list
                for item in value:
                    text.append(f"{indent_str}  - {item}")
        else:
            # Simple key-value pair
            text.append(f"{indent_str}{key}: {value}")
