#!/usr/bin/env python3
"""
Document format converter.

This script converts documents between formats using pandoc.
It supports recursive processing of directories and handles
clean removal of original files after conversion.

Usage:
    convert_format.py DIRECTORY INPUT_FORMAT OUTPUT_FORMAT [RECURSIVE]

Arguments:
    DIRECTORY        Directory containing files to convert
    INPUT_FORMAT     Input format (markdown, html, rst, etc.)
    OUTPUT_FORMAT    Output format (markdown, html, rst, pdf, etc.)
    RECURSIVE        Whether to process subdirectories (true/false)
"""

import os
import sys
import glob
import subprocess
from pathlib import Path


def convert_files(directory, input_format, output_format, recursive=True):
    """
    Convert all files in a directory from one format to another.

    Args:
        directory: Directory containing files to convert
        input_format: Input file format (e.g., 'markdown')
        output_format: Output file format (e.g., 'html')
        recursive: Whether to process subdirectories

    Returns:
        bool: True if all conversions successful, False otherwise
    """
    if not os.path.isdir(directory):
        print(f"Error: Directory not found: {directory}")
        return False

    # Check if pandoc is installed
    if not check_pandoc():
        print("Error: pandoc is not installed")
        return False

    # Find all input files
    files = find_files(directory, input_format, recursive)

    if not files:
        print(f"No {input_format} files found in {directory}")
        return True

    # Process each file
    success = True
    for input_file in files:
        if not convert_file(input_file, input_format, output_format):
            success = False

    return success


def check_pandoc():
    """
    Check if pandoc is installed.

    Returns:
        bool: True if pandoc is available, False otherwise
    """
    try:
        subprocess.run(['which', 'pandoc'],
                      stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE,
                      check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def find_files(directory, ext, recursive=True):
    """
    Find files with a specific extension in a directory.

    Args:
        directory: Directory to search in
        ext: File extension to look for (without the dot)
        recursive: Whether to search in subdirectories

    Returns:
        list: List of file paths matching the extension
    """
    pattern = '**/*.' + ext if recursive else '*.' + ext
    return glob.glob(os.path.join(directory, pattern), recursive=recursive)


def convert_file(input_file, input_format, output_format):
    """
    Convert a single file from one format to another using pandoc.

    Args:
        input_file: Path to input file
        input_format: Input file format
        output_format: Output file format

    Returns:
        bool: True if conversion successful, False otherwise
    """
    output_file = os.path.splitext(input_file)[0] + '.' + output_format
    print(f"Converting {input_file} to {output_file}")

    try:
        # Execute pandoc with appropriate options
        cmd = ['pandoc', input_file, '-f', input_format, '-t', output_format, '-o', output_file]

        # Add specific options for certain formats
        if output_format == 'pdf':
            # For PDF, ensure we have good formatting
            cmd.extend(['--pdf-engine=xelatex', '--variable', 'geometry:margin=1in'])
        elif output_format == 'html':
            # For HTML, add title and CSS
            title = os.path.basename(input_file).split('.')[0].replace('_', ' ').title()
            cmd.extend(['--standalone', '--metadata', f'title={title}'])

            # Add CSS if available
            css_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources', 'style.css')
            if os.path.exists(css_path):
                cmd.extend(['--css', css_path])

        # Run command
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )

        # On success, delete the original file
        os.unlink(input_file)
        return True

    except subprocess.CalledProcessError as e:
        print(f"Error converting {input_file}: {e.stderr}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error processing {input_file}: {e}", file=sys.stderr)
        return False


def main():
    """Main entry point for the script."""
    if len(sys.argv) < 4:
        print(__doc__)
        return 1

    directory = sys.argv[1]
    input_format = sys.argv[2]
    output_format = sys.argv[3]
    recursive = True if len(sys.argv) <= 4 or sys.argv[4].lower() == "true" else False

    # Add common format aliases
    format_aliases = {
        'md': 'markdown',
        'rst': 'rst',
        'htm': 'html',
        'html': 'html',
        'tex': 'latex',
        'pdf': 'pdf',
        'docx': 'docx',
        'odt': 'odt'
    }

    # Normalize formats
    input_format_norm = format_aliases.get(input_format.lower(), input_format.lower())
    output_format_norm = format_aliases.get(output_format.lower(), output_format.lower())

    print(f"Converting {input_format_norm} files to {output_format_norm} format in {directory}")
    print(f"Recursive mode: {'enabled' if recursive else 'disabled'}")

    if convert_files(directory, input_format_norm, output_format_norm, recursive):
        print("Conversion completed successfully")
        return 0
    else:
        print("Conversion failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
