#!/usr/bin/env python3
"""
Template processor for documentation and configuration generation.

This script processes template files with variable substitution and
converts them to various output formats. It supports Markdown, HTML,
RST, and PDF output formats with robust error handling and validation.

Usage:
    process_template.py TEMPLATE_FILE OUTPUT_FILE FORMAT [TEMPLATE_DATA_JSON]

Arguments:
    TEMPLATE_FILE      Path to the template file (.md.tmpl, .html.tmpl, etc.)
    OUTPUT_FILE        Path where the processed file should be written
    FORMAT             Output format (markdown, html, rst, pdf)
    TEMPLATE_DATA_JSON Optional JSON string or file with template variables
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
from typing import Dict, Any, List, Optional, Union, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

__version__ = "0.1.1"
__author__ = "Cloud Infrastructure Platform Team"

# Constants for formats
SUPPORTED_FORMATS = ["markdown", "md", "html", "rst", "pdf", "docx", "plain"]

# Export the public API
__all__ = [
    'process_template',
    'load_template',
    'render_template',
    'save_output',
    'validate_template',
    'load_variables',
    'SUPPORTED_FORMATS'
]

def load_template(template_path: str) -> Tuple[bool, str, str]:
    """
    Load a template file from the filesystem.

    Args:
        template_path: Path to the template file

    Returns:
        Tuple of (success, content, error_message)
    """
    try:
        if not os.path.exists(template_path):
            return False, "", f"Template file not found: {template_path}"

        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return True, content, ""
    except UnicodeDecodeError:
        return False, "", f"Template file encoding error: {template_path}"
    except IOError as e:
        return False, "", f"Error reading template file: {e}"
    except Exception as e:
        return False, "", f"Unexpected error reading template: {e}"

def load_variables(data_source: str) -> Tuple[bool, Dict[str, Any], str]:
    """
    Load template variables from JSON string or file.

    Args:
        data_source: JSON string or path to JSON file

    Returns:
        Tuple of (success, variables_dict, error_message)
    """
    if not data_source:
        return True, {}, ""

    # Check if data_source is a file path
    if os.path.exists(data_source) and os.path.isfile(data_source):
        try:
            with open(data_source, 'r', encoding='utf-8') as f:
                data_str = f.read()
        except Exception as e:
            return False, {}, f"Error reading variables file: {e}"
    else:
        # Assume it's a JSON string
        data_str = data_source

    # Parse the JSON
    try:
        data = json.loads(data_str)

        # Add standard variables if not present
        if 'generation_date' not in data:
            data['generation_date'] = datetime.now().strftime('%Y-%m-%d')
        if 'generation_time' not in data:
            data['generation_time'] = datetime.now().strftime('%H:%M:%S')
        if 'generator' not in data:
            data['generator'] = 'process_template.py'

        return True, data, ""
    except json.JSONDecodeError as e:
        return False, {}, f"Invalid JSON format: {e}"
    except Exception as e:
        return False, {}, f"Error processing template data: {e}"

def validate_template(template_content: str) -> Tuple[bool, List[str]]:
    """
    Validate a template for correct syntax and required variables.

    Args:
        template_content: The template content to validate

    Returns:
        Tuple of (is_valid, list_of_error_messages)
    """
    errors = []

    # Check for unmatched variable brackets
    open_vars = len(re.findall(r'\{\{', template_content))
    close_vars = len(re.findall(r'\}\}', template_content))

    if open_vars != close_vars:
        errors.append(f"Unmatched variable delimiters: {open_vars} opening '{{{{' vs {close_vars} closing '}}}}'")

    # Check for invalid variable syntax
    invalid_vars = re.findall(r'\{\{[^}]*[<>&$|;].*?\}\}', template_content)
    for var in invalid_vars:
        errors.append(f"Potentially unsafe variable syntax: {var}")

    # Check for missing end tags in HTML templates
    if "<html" in template_content and "</html>" not in template_content:
        errors.append("HTML template missing </html> closing tag")
    if "<body" in template_content and "</body>" not in template_content:
        errors.append("HTML template missing </body> closing tag")

    is_valid = len(errors) == 0
    return is_valid, errors

def render_template(template_content: str, variables: Dict[str, Any]) -> str:
    """
    Replace template variables with their values.

    Args:
        template_content: Template content with {{variable}} placeholders
        variables: Dictionary of variable names and values

    Returns:
        Rendered template content
    """
    rendered = template_content

    # Replace each variable
    for key, value in variables.items():
        if not isinstance(value, str):
            if isinstance(value, (int, float, bool)):
                value = str(value)
            elif value is None:
                value = ""
            else:
                try:
                    value = json.dumps(value)
                except (TypeError, ValueError):
                    value = str(value)

        # Replace {{variable}} with value
        rendered = rendered.replace(f"{{{{{key}}}}}", value)

    # Check for unreplaced variables
    remaining_vars = re.findall(r'\{\{([^}]+)\}\}', rendered)
    for var in remaining_vars:
        logger.warning(f"Variable not replaced: {var}")

    return rendered

def save_output(content: str, output_path: str, format_type: str = "markdown") -> Tuple[bool, str]:
    """
    Save rendered content to file in the specified format.

    Args:
        content: Rendered content to save
        output_path: Path where to save the file
        format_type: Output format (markdown, html, rst, pdf, etc.)

    Returns:
        Tuple of (success, output_file_path or error_message)
    """
    # Normalize format type and ensure output directory exists
    format_type = format_type.lower()
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    if format_type in ["markdown", "md"]:
        # For markdown, just write the file
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True, output_path
        except Exception as e:
            return False, f"Error writing markdown file: {e}"

    # For other formats, we need to convert using pandoc
    # Create temporary markdown file
    markdown_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False, encoding='utf-8') as temp:
            temp.write(content)
            markdown_file = temp.name

        # Check for pandoc
        pandoc_available = _check_command('pandoc')
        if not pandoc_available:
            # Fall back to markdown if pandoc not available
            logger.warning("Pandoc not available, falling back to markdown format")
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            if markdown_file and os.path.exists(markdown_file):
                os.unlink(markdown_file)
            return True, output_path

        # Set output file with proper extension
        if format_type == "html":
            output_with_ext = f"{os.path.splitext(output_path)[0]}.html"
        elif format_type == "pdf":
            output_with_ext = f"{os.path.splitext(output_path)[0]}.pdf"
        elif format_type == "rst":
            output_with_ext = f"{os.path.splitext(output_path)[0]}.rst"
        elif format_type == "docx":
            output_with_ext = f"{os.path.splitext(output_path)[0]}.docx"
        elif format_type == "plain":
            output_with_ext = f"{os.path.splitext(output_path)[0]}.txt"
        else:
            # Default to markdown for unknown formats
            logger.warning(f"Unknown format: {format_type}, using markdown")
            output_with_ext = f"{os.path.splitext(output_path)[0]}.md"

        # Create pandoc command
        cmd = _create_pandoc_command(markdown_file, output_with_ext, format_type)

        # Execute conversion
        try:
            _run_command(cmd)
            logger.info(f"Generated {format_type} file: {output_with_ext}")

            # Clean up temp file
            if markdown_file and os.path.exists(markdown_file):
                os.unlink(markdown_file)

            return True, output_with_ext
        except Exception as e:
            # On error, try to save markdown as fallback
            logger.error(f"Pandoc conversion error: {e}")
            if os.path.exists(markdown_file):
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        with open(markdown_file, 'r', encoding='utf-8') as src:
                            f.write(src.read())
                    logger.warning(f"Saved markdown version as fallback to {output_path}")
                    return True, output_path
                except Exception as e2:
                    logger.error(f"Failed to write fallback markdown: {e2}")
            return False, f"Conversion error: {e}"
    except Exception as e:
        if markdown_file and os.path.exists(markdown_file):
            try:
                os.unlink(markdown_file)
            except:
                pass
        return False, f"Output processing error: {e}"

def process_template(template_path: str, output_path: str, format_type: str,
                    variables: Union[Dict[str, Any], str, None] = None) -> bool:
    """
    Process a template file with variable substitution and save to output.

    This is the main entry point function that ties together the template
    processing workflow.

    Args:
        template_path: Path to the template file
        output_path: Path where to save processed output
        format_type: Output format (markdown, html, rst, pdf, etc.)
        variables: Dictionary of variables or JSON string/file path

    Returns:
        bool: Success or failure
    """
    # Load template
    success, template_content, error = load_template(template_path)
    if not success:
        logger.error(f"Failed to load template: {error}")
        return False

    # Load variables
    if variables is None:
        variables_dict = {}
    elif isinstance(variables, dict):
        variables_dict = variables
    else:  # Assume string (JSON or file path)
        success, variables_dict, error = load_variables(variables)
        if not success:
            logger.error(f"Failed to load variables: {error}")
            return False

    # Add standard variables if not present
    if 'template_name' not in variables_dict:
        variables_dict['template_name'] = os.path.basename(template_path)
    if 'output_file' not in variables_dict:
        variables_dict['output_file'] = os.path.basename(output_path)

    # Validate template
    success, errors = validate_template(template_content)
    if not success:
        for error in errors:
            logger.error(f"Template validation error: {error}")
        logger.warning("Proceeding despite template validation errors")

    # Render template
    rendered_content = render_template(template_content, variables_dict)

    # Save output
    success, result = save_output(rendered_content, output_path, format_type)
    if success:
        logger.info(f"Successfully processed template {template_path} to {result}")
        return True
    else:
        logger.error(f"Failed to save output: {result}")
        return False

#
# Helper functions (private)
#

def _check_command(command: str) -> bool:
    """Check if a command is available on the system."""
    try:
        result = subprocess.run(
            ["which", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        return result.returncode == 0
    except Exception:
        return False

def _create_pandoc_command(input_file: str, output_file: str, format_type: str) -> List[str]:
    """Create a pandoc command for the specified conversion."""
    cmd = ['pandoc', input_file, '-o', output_file]

    # Format-specific options
    if format_type == 'html':
        cmd.extend([
            '--standalone',
            '--metadata', 'title=Generated Document',
            '--toc'
        ])

        # Try to find a CSS file in common locations
        css_locations = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'github.css'),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates', 'github.css'),
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'templates', 'github.css'),
        ]

        for css_path in css_locations:
            if os.path.exists(css_path):
                cmd.extend(['--css', css_path])
                break

    elif format_type == 'pdf':
        cmd.extend([
            '--pdf-engine=xelatex',
            '--variable', 'geometry:margin=1in',
            '--variable', 'fontsize=11pt',
            '--toc'
        ])

    elif format_type == 'rst':
        cmd.extend([
            '-f', 'markdown',
            '-t', 'rst'
        ])

    elif format_type == 'docx':
        cmd.extend([
            '--reference-doc=reference.docx'
        ])

    return cmd

def _run_command(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a subprocess command with proper error handling."""
    try:
        # Run the command with appropriate timeout
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=timeout
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(cmd)}")
        logger.error(f"Error output: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        raise

def main() -> int:
    """Main entry point for script."""
    if len(sys.argv) < 4:
        print(__doc__)
        return 1

    template_file = sys.argv[1]
    output_file = sys.argv[2]
    format_type = sys.argv[3]
    variables_data = sys.argv[4] if len(sys.argv) > 4 else None

    logger.info(f"Processing template {template_file} to {output_file} in {format_type} format")

    success = process_template(template_file, output_file, format_type, variables_data)

    if success:
        logger.info("Template processing completed successfully")
        return 0
    else:
        logger.error("Template processing failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
