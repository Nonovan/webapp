#!/usr/bin/env python3
"""
CLI documentation generator.

This script generates documentation for CLI modules by:
1. Finding all Python files in the CLI directory
2. Extracting docstrings, functions, and classes
3. Generating markdown documentation
4. Creating index and reference documents

Usage:
    generate_cli_docs.py CLI_DIR OUTPUT_DIR FORMAT [INCLUDE_PRIVATE] [INCLUDE_DEPRECATED] [PROJECT_ROOT]

Arguments:
    CLI_DIR            Directory containing CLI Python modules
    OUTPUT_DIR         Directory where documentation will be written
    FORMAT             Output format (markdown, html, rst, pdf)
    INCLUDE_PRIVATE    Whether to include private members (true/false)
    INCLUDE_DEPRECATED Whether to include deprecated features (true/false)
    PROJECT_ROOT       Root directory of the project for imports
"""

import os
import sys
import importlib.util
import inspect
import re
import glob
from datetime import datetime
from pathlib import Path


def write_file(content, filename):
    """
    Write content to a file.

    Args:
        content: String content to write
        filename: Path to output file
    """
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        f.write(content)


def get_module_info(filename, module_name, include_private, include_deprecated):
    """
    Extract information from a Python module.

    Args:
        filename: Path to the Python file
        module_name: Fully qualified module name
        include_private: Whether to include private members
        include_deprecated: Whether to include deprecated features

    Returns:
        dict: Module information with docstring, functions and classes
    """
    try:
        # Import the module
        spec = importlib.util.spec_from_file_location(module_name, filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Extract docstring
        docstring = module.__doc__ or 'No description available.'

        # Get all functions and classes
        functions = []
        classes = []

        for name, obj in inspect.getmembers(module):
            # Skip private members unless requested
            if name.startswith('_') and not include_private:
                continue

            # Skip deprecated items unless requested
            doc = inspect.getdoc(obj) or ''
            if 'deprecated' in doc.lower() and not include_deprecated:
                continue

            if inspect.isfunction(obj):
                functions.append((name, obj))
            elif inspect.isclass(obj):
                classes.append((name, obj))

        return {
            'name': module_name,
            'docstring': docstring,
            'functions': functions,
            'classes': classes,
            'include_private': include_private
        }
    except Exception as e:
        print(f'Error importing {filename}: {e}', file=sys.stderr)
        return {
            'name': module_name,
            'docstring': f'Error importing module: {e}',
            'functions': [],
            'classes': []
        }


def format_docstring(doc):
    """
    Format a docstring for markdown output.

    Args:
        doc: Docstring to format

    Returns:
        str: Formatted docstring
    """
    if not doc:
        return 'No documentation available.'

    # Clean up docstring formatting
    lines = doc.split('\n')
    if len(lines) > 1:
        # Remove common leading whitespace
        leading_spaces = min((len(line) - len(line.lstrip())
                             for line in lines[1:] if line.strip()), default=0)
        result = lines[0] + '\n'
        result += '\n'.join(line[leading_spaces:] if line.strip() else line
                           for line in lines[1:])
        return result
    return doc


def generate_markdown_doc(module_info):
    """
    Generate markdown documentation from module information.

    Args:
        module_info: Dictionary containing module information

    Returns:
        str: Markdown documentation content
    """
    content = f'# {module_info["name"]}\n\n'
    content += format_docstring(module_info['docstring']) + '\n\n'

    if module_info['functions']:
        content += '## Functions\n\n'
        for name, func in module_info['functions']:
            content += f'### `{name}`\n\n'

            # Get signature
            try:
                signature = inspect.signature(func)
                content += f'```python\n{name}{signature}\n```\n\n'
            except (ValueError, TypeError):
                content += f'```python\n{name}(...)\n```\n\n'

            # Get docstring
            doc = inspect.getdoc(func) or 'No documentation available.'
            content += format_docstring(doc) + '\n\n'

    if module_info['classes']:
        content += '## Classes\n\n'
        for name, cls in module_info['classes']:
            content += f'### `{name}`\n\n'

            # Get docstring
            doc = inspect.getdoc(cls) or 'No documentation available.'
            content += format_docstring(doc) + '\n\n'

            # Get methods
            include_private = module_info.get('include_private', False)
            methods = [(n, m) for n, m in inspect.getmembers(cls, predicate=inspect.isfunction)
                      if not n.startswith('_') or include_private]

            if methods:
                content += '#### Methods\n\n'
                for method_name, method in methods:
                    content += f'##### `{method_name}`\n\n'

                    # Get signature
                    try:
                        signature = inspect.signature(method)
                        content += f'```python\n{method_name}{signature}\n```\n\n'
                    except (ValueError, TypeError):
                        content += f'```python\n{method_name}(...)\n```\n\n'

                    # Get docstring
                    method_doc = inspect.getdoc(method) or 'No documentation available.'
                    content += format_docstring(method_doc) + '\n\n'

    return content


def generate_cli_docs(cli_dir, output_dir, format_type, include_private, include_deprecated, project_root):
    """
    Generate CLI documentation.

    Args:
        cli_dir: Directory containing CLI Python modules
        output_dir: Directory where documentation will be written
        format_type: Output format (markdown, html, rst, pdf)
        include_private: Whether to include private members
        include_deprecated: Whether to include deprecated features
        project_root: Root directory of the project for imports

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Ensure Python can import from the project
        sys.path.insert(0, project_root)

        # Create index file
        index_content = '# CLI Documentation\n\n'
        index_content += f'Generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}\n\n'
        index_content += '## Available CLI Modules\n\n'

        # Create a README for the CLI documentation directory
        cli_readme = '# CLI Documentation\n\n'
        cli_readme += 'This directory contains documentation for the Cloud Infrastructure Platform CLI.\n\n'
        cli_readme += '## Directory Structure\n\n'

        # Find all Python files in the CLI directory
        python_files = glob.glob(os.path.join(cli_dir, '**', '*.py'), recursive=True)

        # Generate documentation for each file
        module_names = []
        for file_path in sorted(python_files):
            # Skip __init__.py files if not including private
            if os.path.basename(file_path) == '__init__.py' and not include_private:
                continue

            # Determine module name from file path
            rel_path = os.path.relpath(file_path, cli_dir)
            module_path = os.path.splitext(rel_path)[0]
            module_name = module_path.replace('/', '.')
            if module_name.endswith('.__init__'):
                module_name = module_name[:-9]

            # Skip test files
            if 'test' in module_name or 'example' in module_name:
                continue

            print(f'Processing CLI module: {module_name}')

            # Get module information
            module_info = get_module_info(file_path, module_name, include_private, include_deprecated)

            # Determine output path
            rel_dir = os.path.dirname(rel_path)
            output_subdir = os.path.join(output_dir, rel_dir)
            os.makedirs(output_subdir, exist_ok=True)

            output_filename = os.path.basename(file_path).replace('.py', '.md')
            output_path = os.path.join(output_subdir, output_filename)

            # Generate documentation
            doc_content = generate_markdown_doc(module_info)
            write_file(doc_content, output_path)

            # Add to index
            doc_path = os.path.join(rel_dir, output_filename)
            index_content += f'- [{module_name}]({doc_path})\n'
            module_names.append(module_name)

            # Add to README
            cli_readme += f'- **{os.path.basename(file_path)}** - {module_info["docstring"].split("\n")[0]}\n'

        # Write index file
        write_file(index_content, os.path.join(output_dir, 'index.md'))

        # Write README file
        write_file(cli_readme, os.path.join(output_dir, 'README.md'))

        # Generate a combined CLI reference document
        generate_cli_reference(module_names, output_dir, project_root)

        return True
    except Exception as e:
        print(f"Error generating CLI documentation: {e}", file=sys.stderr)
        return False


def generate_cli_reference(module_names, output_dir, project_root):
    """
    Generate a comprehensive CLI reference document.

    Args:
        module_names: List of module names to include in the reference
        output_dir: Directory where to write the reference document
        project_root: Root directory of the project for imports
    """
    reference_content = '# CLI Reference\n\n'
    reference_content += f'Generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}\n\n'
    reference_content += '## Overview\n\n'
    reference_content += 'This document provides a complete reference for all CLI commands.\n\n'
    reference_content += '## Available Commands\n\n'

    # Try to import the CLI module to get command information
    try:
        sys.path.insert(0, project_root)

        # Try different possible CLI modules
        cli_module = None
        for cli_module_name in ['cli', 'cli.main', 'cli.commands']:
            try:
                cli_module = __import__(cli_module_name, fromlist=[''])
                break
            except ImportError:
                continue

        # If we found a CLI module, try to extract commands
        if cli_module:
            # Look for a function that might be the command registrar
            commands = []

            for attr_name in ['get_commands', 'commands', 'cli', 'app', 'main']:
                if hasattr(cli_module, attr_name):
                    attr = getattr(cli_module, attr_name)

                    # Check if it's a function that might register commands
                    if callable(attr) and attr_name in ['get_commands', 'cli', 'main']:
                        try:
                            result = attr()
                            if isinstance(result, dict):
                                commands = result.items()
                                break
                        except Exception:
                            pass

                    # Check if it's a dictionary of commands
                    elif isinstance(attr, dict):
                        commands = attr.items()
                        break

                    # Check if it's a Click command group
                    elif hasattr(attr, 'commands') and isinstance(attr.commands, dict):
                        commands = attr.commands.items()
                        break

            # Add commands to reference
            if commands:
                for name, cmd in commands:
                    reference_content += f'### `{name}`\n\n'

                    if hasattr(cmd, '__doc__') and cmd.__doc__:
                        reference_content += format_docstring(cmd.__doc__) + '\n\n'
                    else:
                        reference_content += 'No description available.\n\n'

                    # Try to get options
                    options = []
                    if hasattr(cmd, 'params'):
                        options = cmd.params

                    if options:
                        reference_content += '#### Options\n\n'
                        for opt in options:
                            opt_names = ', '.join(f'`{o}`' for o in opt.opts)
                            reference_content += f'- {opt_names}: {opt.help or "No help available."}\n'
                        reference_content += '\n'
            else:
                reference_content += 'Command information could not be automatically extracted.\n\n'
                reference_content += 'Please refer to individual module documentation for details.\n\n'

    except Exception as e:
        reference_content += f'Error extracting CLI commands: {e}\n\n'
        reference_content += 'Please refer to individual module documentation for details.\n\n'

    # Add module summary
    reference_content += '## Module Summary\n\n'
    for module_name in sorted(module_names):
        reference_content += f'- `{module_name}`\n'

    # Write reference file
    write_file(reference_content, os.path.join(output_dir, 'cli_reference.md'))


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    cli_dir = sys.argv[1]
    output_dir = sys.argv[2]
    format_type = sys.argv[3]
    include_private = sys.argv[4].lower() == "true" if len(sys.argv) > 4 else False
    include_deprecated = sys.argv[5].lower() == "true" if len(sys.argv) > 5 else False
    project_root = sys.argv[6] if len(sys.argv) > 6 else os.path.dirname(os.path.dirname(cli_dir))

    if generate_cli_docs(cli_dir, output_dir, format_type, include_private, include_deprecated, project_root):
        print(f"Generated CLI documentation in {format_type} format")
        sys.exit(0)
    else:
        sys.exit(1)
