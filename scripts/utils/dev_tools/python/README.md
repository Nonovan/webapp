# Python Developer Utilities

This directory contains Python utilities used by the Cloud Infrastructure Platform's development tools for file format conversion, documentation generation, and template processing.

## Overview

The Python utilities provide support for common development workflows including:

- Converting documents between different formats
- Generating CLI documentation from Python modules
- Processing templates with variable substitution

These utilities are designed to work within the larger development tools ecosystem and follow the platform's security and coding standards.

## Key Components

- **`convert_format.py`**: Document format conversion utilities
  - Converts files between formats using Pandoc
  - Handles Markdown, HTML, RST, PDF, and other formats
  - Includes backup functionality for safety
  - Provides recursive directory processing

- **`generate_cli_docs.py`**: CLI documentation generation
  - Extracts documentation from Python modules
  - Generates comprehensive Markdown documentation
  - Supports function and class documentation
  - Creates navigation indexes and reference pages
  - Handles private and deprecated components

- **`process_template.py`**: Template processing utilities
  - Processes template files with variable substitution
  - Supports multiple output formats
  - Validates templates for correct syntax
  - Implements secure variable handling
  - Supports environment variable expansion

## Directory Structure

```plaintext
scripts/utils/dev_tools/python/
├── README.md              # This documentation
├── __init__.py            # Package initialization and exports
├── convert_format.py      # Format conversion utilities
├── generate_cli_docs.py   # Documentation generation utilities
└── process_template.py    # Template processing utilities
```

## Usage

### Format Conversion

```python
from scripts.utils.dev_tools.python import convert_files, convert_file

# Convert a single file
result = convert_file(
    input_file="documentation.md",
    input_format="markdown",
    output_format="html"
)

# Convert multiple files in a directory
convert_files(
    directory="/path/to/docs",
    input_format="markdown",
    output_format="html",
    recursive=True
)
```

### CLI Documentation Generation

```python
from scripts.utils.dev_tools.python import generate_cli_docs

# Generate documentation for CLI modules
generate_cli_docs(
    cli_dir="/path/to/cli",
    output_dir="/path/to/docs",
    format_type="markdown",
    include_private=False,
    include_deprecated=False,
    project_root="/path/to/project"
)
```

### Template Processing

```python
from scripts.utils.dev_tools.python import process_template

# Process a template with variables
result = process_template(
    template_path="template.md.tmpl",
    output_path="output.md",
    format_type="markdown",
    variables={
        "title": "Project Documentation",
        "version": "1.0.0",
        "author": "Development Team"
    }
)
```

## Configuration

The utilities can be configured through their function parameters. Common configuration options include:

- **Format Types**: markdown, html, pdf, rst, docx
- **Logging Levels**: DEBUG, INFO, WARNING, ERROR
- **Path Settings**: Input/output directories and file paths
- **Templating Options**: Variable placeholders, output formats, environment variables

## Best Practices & Security

- Always validate template variables before processing
- Use secure file operations with proper permissions
- Create backups before modifying files
- Test template outputs in development before using in production
- Avoid processing untrusted templates
- Sanitize output filenames to prevent path traversal
- Use environment-specific configuration to separate sensitive data

## Common Features

All utility modules share these common features:

- **Comprehensive Logging**: Detailed logging with multiple levels
- **Error Handling**: Robust error detection and reporting
- **Format Detection**: Automatic file format detection
- **Input Validation**: Thorough validation of all inputs
- **Security Controls**: Path traversal prevention and safe defaults
- **Type Annotations**: Comprehensive type hints for better IDE support
- **Documentation**: Detailed docstrings and usage examples

## Related Documentation

- Development Workflow Guide
- Documentation Standards
- Template Development Guide
- Pandoc Integration Guide
- Development Tools Overview
