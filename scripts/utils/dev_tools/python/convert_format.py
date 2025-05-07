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

import logging
import os
import sys
import glob
import subprocess
import tempfile
from pathlib import Path


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

__all__ = [
    'convert_files',
    'check_pandoc',
    'find_files',
    'secure_backup',
    'convert_file',
    'restore_from_backup'
]

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
        logger.error("Directory not found: %s", directory)
        return False

    # Check if pandoc is installed
    if not check_pandoc():
        logger.error("pandoc is not installed")
        return False

    # Find all input files
    files = find_files(directory, input_format, recursive)

    if not files:
        logger.info("No %s files found in %s", input_format, directory)
        return True

    # Process each file
    success = True
    total_files = len(files)
    logger.info("Found %d files to convert", total_files)

    for idx, input_file in enumerate(files, 1):
        logger.info("Processing file %d/%d: %s", idx, total_files, input_file)
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
        # Use a platform-independent way to check for pandoc
        result = subprocess.run(
            ['pandoc', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,  # Don't raise exception for non-zero exit codes
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
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
    # Normalize the extension (remove dot if present)
    ext = ext.lstrip('.')

    pattern = '**/*.' + ext if recursive else '*.' + ext
    files = glob.glob(os.path.join(directory, pattern), recursive=recursive)

    # Sort files for consistent processing order
    return sorted(files)


def secure_backup(file_path):
    """
    Create a backup of a file before modification.

    Args:
        file_path: Path to the file to back up

    Returns:
        str: Path to the backup file or None if backup failed
    """
    try:
        # Create a backup with timestamp
        backup_path = f"{file_path}.bak"
        with open(file_path, 'rb') as src, open(backup_path, 'wb') as dst:
            dst.write(src.read())
        return backup_path
    except Exception as e:
        logger.warning("Failed to create backup of %s: %s", file_path, e)
        return None


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
    logger.info("Converting %s to %s", input_file, output_file)

    # Create backup of original file
    backup_file = secure_backup(input_file)

    try:
        # Create a temporary output file for atomic write
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{output_format}") as temp_output:
            temp_output_path = temp_output.name

        # Prepare pandoc command
        cmd = ['pandoc', input_file, '-f', input_format, '-t', output_format, '-o', temp_output_path]

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

            # Add security headers
            cmd.extend(['--metadata', 'csp-nonce:{{nonce}}'])

        # Run command with timeout
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
            timeout=60  # Prevent hanging processes
        )

        # Move the temp file to the final location (atomic write)
        if os.path.exists(output_file):
            os.unlink(output_file)
        os.rename(temp_output_path, output_file)

        # Set appropriate permissions
        os.chmod(output_file, 0o644)  # rw-r--r--

        # On success, delete the original file
        os.unlink(input_file)

        # Remove backup if everything went well
        if backup_file and os.path.exists(backup_file):
            os.unlink(backup_file)

        logger.info("Conversion successful: %s", output_file)
        return True

    except subprocess.CalledProcessError as e:
        logger.error("Error converting %s: %s", input_file, e.stderr)
        restore_from_backup(input_file, backup_file)
        return False
    except subprocess.TimeoutExpired:
        logger.error("Conversion timeout for %s", input_file)
        restore_from_backup(input_file, backup_file)
        return False
    except Exception as e:
        logger.error("Error processing %s: %s", input_file, str(e))
        restore_from_backup(input_file, backup_file)
        return False
    finally:
        # Clean up temporary file if it still exists
        if 'temp_output_path' in locals() and os.path.exists(temp_output_path):
            try:
                os.unlink(temp_output_path)
            except:
                pass


def restore_from_backup(original_file, backup_file):
    """Restore file from backup if available"""
    if backup_file and os.path.exists(backup_file):
        try:
            # If the original was deleted in a failed conversion, restore it
            if not os.path.exists(original_file):
                with open(backup_file, 'rb') as src, open(original_file, 'wb') as dst:
                    dst.write(src.read())
                logger.info("Restored original file from backup: %s", original_file)
            return True
        except Exception as e:
            logger.error("Failed to restore backup: %s", str(e))
            return False
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
        'markdown': 'markdown',
        'rst': 'rst',
        'htm': 'html',
        'html': 'html',
        'tex': 'latex',
        'latex': 'latex',
        'pdf': 'pdf',
        'docx': 'docx',
        'odt': 'odt',
        'txt': 'plain',
        'plain': 'plain'
    }

    # Normalize formats
    input_format_norm = format_aliases.get(input_format.lower(), input_format.lower())
    output_format_norm = format_aliases.get(output_format.lower(), output_format.lower())

    logger.info("Converting %s files to %s format in %s",
                input_format_norm, output_format_norm, directory)
    logger.info("Recursive mode: %s", 'enabled' if recursive else 'disabled')

    if convert_files(directory, input_format_norm, output_format_norm, recursive):
        logger.info("Conversion completed successfully")
        return 0
    else:
        logger.error("Conversion failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
