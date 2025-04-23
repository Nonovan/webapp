#!/usr/bin/env python3
"""
Template processor for documentation generation.

This script processes template files with variable substitution and
converts them to various output formats.

Usage:
    process_template.py TEMPLATE_FILE OUTPUT_FILE FORMAT TEMPLATE_DATA_JSON

Arguments:
    TEMPLATE_FILE      Path to the template file (.md.tmpl)
    OUTPUT_FILE        Path where the processed file should be written
    FORMAT             Output format (markdown, html, rst, pdf)
    TEMPLATE_DATA_JSON JSON string containing template variables
"""

import json
import re
import sys
import os
import subprocess
from datetime import datetime
from pathlib import Path


def process_template(template_file, output_file, format_type, template_data):
    """
    Process a template file with variable substitution.

    Args:
        template_file: Path to the template file
        output_file: Path where to write the processed output
        format_type: Output format (markdown, html, rst, pdf)
        template_data: JSON string or key=value data for variable substitution

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Load template data
        data = load_template_data(template_data)

        # Add standard variables
        data['generation_date'] = datetime.now().strftime('%Y-%m-%d')
        data['generation_time'] = datetime.now().strftime('%H:%M:%S')

        # Read the template
        with open(template_file, 'r') as f:
            template_content = f.read()

        # Replace variables
        processed_content = substitute_variables(template_content, data)

        # Write output based on format
        return write_output(processed_content, output_file, format_type)

    except Exception as e:
        print(f'Error processing template {template_file}: {e}', file=sys.stderr)
        return False


def load_template_data(template_data):
    """
    Load template data from JSON string or key=value pairs.

    Args:
        template_data: String containing template data

    Returns:
        dict: Template variables
    """
    data = {}

    # Try to parse as JSON
    try:
        data = json.loads(template_data)
    except json.JSONDecodeError:
        # If JSON parsing fails, try to parse it as a simple key=value format
        for line in template_data.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                data[key.strip()] = value.strip()

    return data


def substitute_variables(content, data):
    """
    Substitute {{variable}} placeholders in content with values from data.

    Args:
        content: Template content with placeholders
        data: Dictionary of variable values

    Returns:
        str: Content with variables substituted
    """
    def replace_var(match):
        var_name = match.group(1)
        if var_name in data:
            return str(data[var_name])
        return match.group(0)  # Keep the original if not found

    return re.sub(r'{{([a-zA-Z0-9_]+)}}', replace_var, content)


def write_output(content, output_file, format_type):
    """
    Write processed content to output file in the specified format.

    Args:
        content: Processed content to write
        output_file: Path where to write the output
        format_type: Output format (markdown, html, rst, pdf)

    Returns:
        bool: True if successful, False otherwise
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    if format_type == 'markdown':
        # For markdown, just write the processed file
        with open(output_file, 'w') as f:
            f.write(content)
        print(f'Generated markdown file: {output_file}')
        return True

    # Temporary file for pandoc conversion
    markdown_file = f"{output_file}.tmp"
    with open(markdown_file, 'w') as f:
        f.write(content)

    # Check if pandoc is available
    if not check_command('pandoc'):
        print(f"Warning: pandoc not found. Falling back to markdown output: {output_file}")
        os.rename(markdown_file, output_file)
        return True

    try:
        if format_type == 'html':
            # For HTML, use pandoc to convert
            run_command(['pandoc', markdown_file, '-o', f"{output_file}.html"])
            os.remove(markdown_file)
            print(f'Generated HTML file: {output_file}.html')

        elif format_type == 'pdf':
            # For PDF, use pandoc to convert
            run_command(['pandoc', markdown_file, '-o', f"{output_file}.pdf"])
            os.remove(markdown_file)
            print(f'Generated PDF file: {output_file}.pdf')

        elif format_type == 'rst':
            # For RST, use pandoc to convert
            run_command(['pandoc', markdown_file, '-f', 'markdown', '-t', 'rst', '-o', f"{output_file}.rst"])
            os.remove(markdown_file)
            print(f'Generated RST file: {output_file}.rst')

        else:
            # Default to markdown
            os.rename(markdown_file, output_file)
            print(f'Generated file: {output_file}')

        return True

    except subprocess.CalledProcessError as e:
        print(f"Error converting to {format_type}: {e}", file=sys.stderr)
        # Ensure we don't leave the temporary file
        if os.path.exists(markdown_file):
            os.rename(markdown_file, output_file)
        return False


def check_command(command):
    """Check if a command is available."""
    try:
        subprocess.run(['which', command],
                      stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE,
                      check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def run_command(cmd_list):
    """Run a command and raise exception on error."""
    subprocess.run(cmd_list, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(1)

    template_file = sys.argv[1]
    output_file = sys.argv[2]
    format_type = sys.argv[3]
    template_data = sys.argv[4]

    if process_template(template_file, output_file, format_type, template_data):
        sys.exit(0)
    else:
        sys.exit(1)
