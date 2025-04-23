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
import logging
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def process_template(
    template_file: str,
    output_file: str,
    format_type: str,
    template_data: str
) -> bool:
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
        # Validate inputs
        if not os.path.isfile(template_file):
            logger.error(f"Template file not found: {template_file}")
            return False

        if not os.path.exists(os.path.dirname(output_file)):
            try:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
            except OSError as e:
                logger.error(f"Could not create output directory: {e}")
                return False

        # Load template data
        data = load_template_data(template_data)

        # Add standard variables
        data['generation_date'] = datetime.now().strftime('%Y-%m-%d')
        data['generation_time'] = datetime.now().strftime('%H:%M:%S')
        data['generator'] = 'process_template.py'

        # Read the template
        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                template_content = f.read()
        except UnicodeDecodeError:
            logger.error(f"Template file encoding error: {template_file}")
            return False
        except IOError as e:
            logger.error(f"Error reading template file: {e}")
            return False

        # Replace variables
        processed_content = substitute_variables(template_content, data)

        # Write output based on format
        return write_output(processed_content, output_file, format_type)

    except Exception as e:
        logger.error(f"Error processing template {template_file}: {e}")
        return False


def load_template_data(template_data: str) -> Dict[str, Any]:
    """
    Load template data from JSON string or key=value pairs.

    Args:
        template_data: String containing template data

    Returns:
        dict: Template variables
    """
    data = {}

    if not template_data:
        logger.warning("Empty template data provided")
        return data

    # Try to parse as JSON
    try:
        data = json.loads(template_data)
        logger.debug(f"Successfully parsed JSON template data with {len(data)} variables")
        return data
    except json.JSONDecodeError:
        logger.debug("Not valid JSON, trying key=value format")
        # If JSON parsing fails, try to parse it as a simple key=value format
        for line in template_data.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                data[key.strip()] = value.strip()

    return data


def substitute_variables(content: str, data: Dict[str, Any]) -> str:
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
        logger.debug(f"Variable not found in template data: {var_name}")
        return match.group(0)  # Keep the original if not found

    # Check for any unmatched variables after substitution
    result = re.sub(r'{{([a-zA-Z0-9_]+)}}', replace_var, content)

    # Count remaining placeholders and warn if any
    remaining = len(re.findall(r'{{([a-zA-Z0-9_]+)}}', result))
    if remaining > 0:
        logger.warning(f"Template contains {remaining} unresolved variable placeholders")

    return result


def write_output(content: str, output_file: str, format_type: str) -> bool:
    """
    Write processed content to output file in the specified format.

    Args:
        content: Processed content to write
        output_file: Path where to write the output
        format_type: Output format (markdown, html, rst, pdf)

    Returns:
        bool: True if successful, False otherwise
    """
    # Normalize format type
    format_type = format_type.lower()

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

    if format_type == 'markdown' or format_type == 'md':
        # For markdown, just write the processed file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f'Generated markdown file: {output_file}')
            return True
        except IOError as e:
            logger.error(f"Error writing to {output_file}: {e}")
            return False

    # Create a temporary file for pandoc conversion
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False, encoding='utf-8') as temp:
            temp.write(content)
            markdown_file = temp.name
    except IOError as e:
        logger.error(f"Error creating temporary file: {e}")
        return False

    # Check if pandoc is available
    pandoc_available = check_command('pandoc')
    if not pandoc_available:
        logger.warning(f"Pandoc not found. Falling back to markdown output: {output_file}")
        try:
            # Copy temporary file to output file
            with open(markdown_file, 'r', encoding='utf-8') as src:
                with open(output_file, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
            os.unlink(markdown_file)
            return True
        except IOError as e:
            logger.error(f"Error writing to {output_file}: {e}")
            os.unlink(markdown_file)
            return False

    # Proceed with format conversion
    try:
        output_with_extension = output_file

        # Format-specific processing
        if format_type == 'html':
            output_with_extension = f"{os.path.splitext(output_file)[0]}.html"
            cmd = create_pandoc_command(markdown_file, output_with_extension, format_type)
            run_command(cmd)
            logger.info(f'Generated HTML file: {output_with_extension}')

        elif format_type == 'pdf':
            output_with_extension = f"{os.path.splitext(output_file)[0]}.pdf"
            cmd = create_pandoc_command(markdown_file, output_with_extension, format_type)
            run_command(cmd)
            logger.info(f'Generated PDF file: {output_with_extension}')

        elif format_type == 'rst':
            output_with_extension = f"{os.path.splitext(output_file)[0]}.rst"
            cmd = create_pandoc_command(markdown_file, output_with_extension, format_type)
            run_command(cmd)
            logger.info(f'Generated RST file: {output_with_extension}')

        else:
            # Default to markdown for unknown formats
            logger.warning(f"Unknown format: {format_type}, defaulting to markdown")
            with open(markdown_file, 'r', encoding='utf-8') as src:
                with open(output_file, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
            logger.info(f'Generated markdown file: {output_file}')

        # Clean up temporary file
        if os.path.exists(markdown_file):
            os.unlink(markdown_file)

        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Pandoc conversion error: {e}")
        # Ensure we don't leave the temporary file
        if os.path.exists(markdown_file):
            try:
                # Fall back to copying the markdown
                with open(markdown_file, 'r', encoding='utf-8') as src:
                    with open(output_file, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
                logger.warning(f"Conversion failed, saved markdown to: {output_file}")
                os.unlink(markdown_file)
            except IOError:
                os.unlink(markdown_file)
        return False
    except Exception as e:
        logger.error(f"Unexpected error during conversion: {e}")
        if os.path.exists(markdown_file):
            os.unlink(markdown_file)
        return False


def create_pandoc_command(input_file: str, output_file: str, format_type: str) -> List[str]:
    """
    Create pandoc command for the specified format.

    Args:
        input_file: Path to input markdown file
        output_file: Path to output file
        format_type: Output format type

    Returns:
        list: Command arguments for subprocess
    """
    if format_type == 'html':
        # For HTML, add CSS and metadata
        title = os.path.basename(output_file).split('.')[0].replace('_', ' ').title()
        cmd = [
            'pandoc',
            input_file,
            '--standalone',
            '--metadata', f'title={title}',
            '--metadata', 'lang=en',
            '--metadata', 'csp-nonce={{nonce}}',  # CSP nonce placeholder for security
            '-o', output_file
        ]

        # Add CSS if available
        css_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources', 'style.css')
        if os.path.exists(css_path):
            cmd.extend(['--css', css_path])

        return cmd

    elif format_type == 'pdf':
        # For PDF, ensure good formatting
        return [
            'pandoc',
            input_file,
            '--pdf-engine=xelatex',
            '--variable', 'geometry:margin=1in',
            '--variable', 'fontsize=11pt',
            '--toc',  # Table of contents
            '-o', output_file
        ]

    elif format_type == 'rst':
        # For RST, specific format options
        return [
            'pandoc',
            input_file,
            '-f', 'markdown',
            '-t', 'rst',
            '-o', output_file
        ]

    # Default command
    return ['pandoc', input_file, '-o', output_file]


def check_command(command: str) -> bool:
    """
    Check if a command is available on the system.

    Args:
        command: Command name to check

    Returns:
        bool: True if command is available, False otherwise
    """
    try:
        # Use different approach for Windows
        if os.name == 'nt':  # Windows
            result = subprocess.run(
                ['where', command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
        else:  # Unix/Linux/Mac
            result = subprocess.run(
                ['which', command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
        return result.returncode == 0
    except Exception:
        return False


def run_command(cmd_list: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """
    Run a command with proper error handling.

    Args:
        cmd_list: List of command arguments
        timeout: Timeout in seconds

    Returns:
        CompletedProcess: Result of subprocess.run

    Raises:
        subprocess.CalledProcessError: If command fails
        subprocess.TimeoutExpired: If command times out
    """
    logger.debug(f"Running command: {' '.join(cmd_list)}")
    result = subprocess.run(
        cmd_list,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        text=True
    )
    return result


def main() -> int:
    """
    Main entry point for script.

    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    if len(sys.argv) != 5:
        print(__doc__)
        return 1

    template_file = sys.argv[1]
    output_file = sys.argv[2]
    format_type = sys.argv[3]
    template_data = sys.argv[4]

    logger.info(f"Processing template {template_file} to {output_file} in {format_type} format")

    success = process_template(template_file, output_file, format_type, template_data)

    if success:
        logger.info("Template processing completed successfully")
        return 0
    else:
        logger.error("Template processing failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
