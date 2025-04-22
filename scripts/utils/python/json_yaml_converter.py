#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# JSON-YAML Converter Utility for Cloud Infrastructure Platform
#
# This script provides functionality for converting between JSON and YAML formats.
# It supports file conversion, string conversion, validation, and schema validation.
# The utility can be used as both a command-line tool and as an imported module.
#
# Part of Cloud Infrastructure Platform
# -----------------------------------------------------------------------------

"""
JSON-YAML Converter Utility for Cloud Infrastructure Platform

This script provides functionality for converting between JSON and YAML formats.
It supports file conversion, string conversion, validation, and schema validation.
The utility can be used as both a command-line tool and as an imported module.

Features:
- Convert JSON files to YAML format
- Convert YAML files to JSON format
- Validate JSON/YAML against schema files
- Pretty-print and format JSON/YAML content
- Merge multiple JSON/YAML files
- Support for custom configuration and output formats

Usage:
    json_yaml_converter.py convert --input INPUT_FILE --output OUTPUT_FILE [options]
    json_yaml_converter.py validate --input INPUT_FILE [--schema SCHEMA_FILE] [options]
    json_yaml_converter.py merge --inputs INPUT_FILES --output OUTPUT_FILE [options]

Examples:
    json_yaml_converter.py convert --input config.json --output config.yaml
    json_yaml_converter.py validate --input config.yaml --schema schema.json
    json_yaml_converter.py merge --inputs config1.yaml config2.yaml --output merged.yaml
"""

import os
import sys
import json
import yaml
import logging
import argparse
import jsonschema
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, TextIO, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("json-yaml-converter")

# Script version
__version__ = "1.0.0"


class JSONYAMLConverter:
    """Main converter class for JSON and YAML conversion operations."""

    def __init__(self, indent: int = 2, allow_duplicate_keys: bool = False,
                 default_flow_style: bool = False, sort_keys: bool = False):
        """
        Initialize the converter with formatting options.

        Args:
            indent: Number of spaces for indentation (default: 2)
            allow_duplicate_keys: Whether to allow duplicate keys in YAML (default: False)
            default_flow_style: YAML flow style setting (default: False for block style)
            sort_keys: Whether to sort dictionary keys (default: False)
        """
        self.indent = indent
        self.allow_duplicate_keys = allow_duplicate_keys
        self.default_flow_style = default_flow_style
        self.sort_keys = sort_keys

        # Configure YAML loader and dumper
        self._setup_yaml_handlers()

    def _setup_yaml_handlers(self):
        """Configure YAML loader and dumper with custom options."""
        # Use SafeLoader for security (prevents code execution)
        self.yaml_loader = yaml.SafeLoader

        # Configure dumper to use block style by default
        self.yaml_dumper = yaml.SafeDumper

        # Set default flow style for the YAML dumper
        yaml.SafeDumper.default_flow_style = self.default_flow_style

        # This helps prevent YAML anchors and references for repeated content
        # which can make the YAML output more readable
        def represent_none(self, _):
            return self.represent_scalar('tag:yaml.org,2002:null', 'null')

        yaml.SafeDumper.add_representer(type(None), represent_none)

    def json_to_yaml(self, data: Union[str, Dict, List, TextIO]) -> str:
        """
        Convert JSON data to YAML format.

        Args:
            data: JSON string, dictionary, list, or file object

        Returns:
            YAML formatted string

        Raises:
            ValueError: If JSON parsing fails
        """
        # Parse JSON if it's a string or file object
        if isinstance(data, str):
            try:
                parsed_data = json.loads(data)
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON: %s", e)
                raise ValueError(f"Invalid JSON format: {e}") from e
        elif hasattr(data, 'read'):  # File-like object
            try:
                parsed_data = json.load(data)
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON from file: %s", e)
                raise ValueError(f"Invalid JSON format: {e}") from e
        else:
            # Assume it's already a parsed dictionary or list
            parsed_data = data

        # Convert to YAML
        try:
            yaml_str = yaml.dump(
                parsed_data,
                Dumper=self.yaml_dumper,
                indent=self.indent,
                sort_keys=self.sort_keys
            )
            return yaml_str
        except yaml.YAMLError as e:
            logger.error("Failed to convert to YAML: %s", e)
            raise ValueError(f"Failed to convert to YAML: {e}") from e

    def yaml_to_json(self, data: Union[str, Dict, List, TextIO],
                     pretty: bool = True) -> str:
        """
        Convert YAML data to JSON format.

        Args:
            data: YAML string, dictionary, list, or file object
            pretty: Whether to format the JSON output (default: True)

        Returns:
            JSON formatted string

        Raises:
            ValueError: If YAML parsing fails
        """
        # Parse YAML if it's a string or file object
        if isinstance(data, str):
            try:
                parsed_data = yaml.load(data, Loader=self.yaml_loader)
            except yaml.YAMLError as e:
                logger.error("Failed to parse YAML: %s", e)
                raise ValueError(f"Invalid YAML format: {e}") from e
        elif hasattr(data, 'read'):  # File-like object
            try:
                parsed_data = yaml.load(data, Loader=self.yaml_loader)
            except yaml.YAMLError as e:
                logger.error("Failed to parse YAML from file: %s", e)
                raise ValueError(f"Invalid YAML format: {e}") from e
        else:
            # Assume it's already a parsed dictionary or list
            parsed_data = data

        # Convert to JSON
        try:
            indent = self.indent if pretty else None
            return json.dumps(
                parsed_data,
                indent=indent,
                sort_keys=self.sort_keys
            )
        except (TypeError, OverflowError) as e:
            logger.error("Failed to convert to JSON: %s", e)
            raise ValueError(f"Failed to convert to JSON: {e}") from e

    def json_to_yaml_file(self, input_file: str, output_file: str) -> bool:
        """
        Convert a JSON file to YAML format and save to output file.

        Args:
            input_file: Path to the input JSON file
            output_file: Path to the output YAML file

        Returns:
            True on success, False on failure

        Raises:
            FileNotFoundError: If input file doesn't exist
            PermissionError: If output file can't be written
        """
        logger.debug("Converting JSON file %s to YAML file %s", input_file, output_file)

        try:
            with open(input_file, 'r') as f:
                json_data = json.load(f)

            yaml_str = self.json_to_yaml(json_data)

            # Ensure output directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, 'w') as f:
                f.write(yaml_str)

            logger.info("Successfully converted %s to %s", input_file, output_file)
            return True

        except FileNotFoundError:
            logger.error("Input file not found: %s", input_file)
            raise
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in %s: %s", input_file, e)
            return False
        except PermissionError as e:
            logger.error("Permission error writing to %s: %s", output_file, e)
            raise
        except Exception as e:
            logger.error("Failed to convert %s to YAML: %s", input_file, e)
            return False

    def yaml_to_json_file(self, input_file: str, output_file: str,
                          pretty: bool = True) -> bool:
        """
        Convert a YAML file to JSON format and save to output file.

        Args:
            input_file: Path to the input YAML file
            output_file: Path to the output JSON file
            pretty: Whether to format the JSON output (default: True)

        Returns:
            True on success, False on failure

        Raises:
            FileNotFoundError: If input file doesn't exist
            PermissionError: If output file can't be written
        """
        logger.debug("Converting YAML file %s to JSON file %s", input_file, output_file)

        try:
            with open(input_file, 'r') as f:
                yaml_data = yaml.load(f, Loader=self.yaml_loader)

            # Ensure output directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            indent = self.indent if pretty else None
            with open(output_file, 'w') as f:
                json.dump(yaml_data, f, indent=indent, sort_keys=self.sort_keys)

            logger.info("Successfully converted %s to %s", input_file, output_file)
            return True

        except FileNotFoundError:
            logger.error("Input file not found: %s", input_file)
            raise
        except yaml.YAMLError as e:
            logger.error("Invalid YAML in %s: %s", input_file, e)
            return False
        except PermissionError as e:
            logger.error("Permission error writing to %s: %s", output_file, e)
            raise
        except Exception as e:
            logger.error("Failed to convert %s to JSON: %s", input_file, e)
            return False

    def validate_json(self, json_data: Union[str, Dict, List, TextIO],
                     schema: Optional[Union[str, Dict]] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate JSON data, optionally against a schema.

        Args:
            json_data: JSON string, dictionary, list, or file object
            schema: Optional JSON schema for validation

        Returns:
            Tuple of (is_valid, error_message)

        Raises:
            ValueError: If schema is invalid
        """
        # Parse JSON if it's a string or file object
        if isinstance(json_data, str):
            try:
                parsed_data = json.loads(json_data)
            except json.JSONDecodeError as e:
                return False, f"Invalid JSON format: {e}"
        elif hasattr(json_data, 'read'):  # File-like object
            try:
                parsed_data = json.load(json_data)
            except json.JSONDecodeError as e:
                return False, f"Invalid JSON format: {e}"
        else:
            # Assume it's already a parsed dictionary or list
            parsed_data = json_data

        # If no schema provided, just validate syntax (already done at this point)
        if not schema:
            return True, None

        # Parse schema if it's a string or file object
        if isinstance(schema, str):
            try:
                schema_data = json.loads(schema)
            except json.JSONDecodeError as e:
                logger.error("Invalid JSON schema: %s", e)
                raise ValueError(f"Invalid JSON schema: {e}") from e
        elif hasattr(schema, 'read'):  # File-like object
            try:
                schema_data = json.load(schema)
            except json.JSONDecodeError as e:
                logger.error("Invalid JSON schema from file: %s", e)
                raise ValueError(f"Invalid JSON schema: {e}") from e
        else:
            # Assume it's already a parsed dictionary
            schema_data = schema

        # Validate against schema
        try:
            jsonschema.validate(parsed_data, schema_data)
            return True, None
        except jsonschema.exceptions.ValidationError as e:
            return False, f"Schema validation error: {e.message}"
        except jsonschema.exceptions.SchemaError as e:
            logger.error("Invalid schema: %s", e)
            raise ValueError(f"Invalid JSON schema: {e}") from e

    def validate_yaml(self, yaml_data: Union[str, Dict, List, TextIO],
                     schema: Optional[Union[str, Dict]] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate YAML data, optionally against a JSON schema.

        Args:
            yaml_data: YAML string, dictionary, list, or file object
            schema: Optional JSON schema for validation

        Returns:
            Tuple of (is_valid, error_message)

        Raises:
            ValueError: If schema is invalid
        """
        # Parse YAML if it's a string or file object
        if isinstance(yaml_data, str):
            try:
                parsed_data = yaml.load(yaml_data, Loader=self.yaml_loader)
            except yaml.YAMLError as e:
                return False, f"Invalid YAML format: {e}"
        elif hasattr(yaml_data, 'read'):  # File-like object
            try:
                parsed_data = yaml.load(yaml_data, Loader=self.yaml_loader)
            except yaml.YAMLError as e:
                return False, f"Invalid YAML format: {e}"
        else:
            # Assume it's already a parsed dictionary or list
            parsed_data = yaml_data

        # If no schema provided, just validate syntax (already done at this point)
        if not schema:
            return True, None

        # For schema validation, convert to JSON validation
        return self.validate_json(parsed_data, schema)

    def merge_yaml_files(self, input_files: List[str], output_file: str) -> bool:
        """
        Merge multiple YAML files into a single output file.

        Args:
            input_files: List of input YAML file paths
            output_file: Path to the output merged YAML file

        Returns:
            True on success, False on failure

        Raises:
            FileNotFoundError: If any input file doesn't exist
            PermissionError: If output file can't be written
        """
        logger.debug("Merging YAML files: %s -> %s", ', '.join(input_files), output_file)

        merged_data = {}

        for file_path in input_files:
            try:
                with open(file_path, 'r') as f:
                    data = yaml.load(f, Loader=self.yaml_loader)

                if not isinstance(data, dict):
                    logger.warning("Skipping %s: not a dictionary (found %s)",
                                   file_path, type(data).__name__)
                    continue

                # Deep merge dictionaries
                self._deep_merge(merged_data, data)

            except FileNotFoundError:
                logger.error("Input file not found: %s", file_path)
                raise
            except yaml.YAMLError as e:
                logger.error("Invalid YAML in %s: %s", file_path, e)
                return False

        # Ensure output directory exists
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write merged data to output file
        try:
            with open(output_file, 'w') as f:
                yaml.dump(merged_data, f, Dumper=self.yaml_dumper,
                          indent=self.indent, sort_keys=self.sort_keys)

            logger.info("Successfully merged %d files into %s", len(input_files), output_file)
            return True

        except PermissionError as e:
            logger.error("Permission error writing to %s: %s", output_file, e)
            raise
        except Exception as e:
            logger.error("Failed to write merged YAML: %s", e)
            return False

    def merge_json_files(self, input_files: List[str], output_file: str,
                        pretty: bool = True) -> bool:
        """
        Merge multiple JSON files into a single output file.

        Args:
            input_files: List of input JSON file paths
            output_file: Path to the output merged JSON file
            pretty: Whether to format the JSON output (default: True)

        Returns:
            True on success, False on failure

        Raises:
            FileNotFoundError: If any input file doesn't exist
            PermissionError: If output file can't be written
        """
        logger.debug("Merging JSON files: %s -> %s", ', '.join(input_files), output_file)

        merged_data = {}

        for file_path in input_files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)

                if not isinstance(data, dict):
                    logger.warning("Skipping %s: not a dictionary (found %s)",
                                   file_path, type(data).__name__)
                    continue

                # Deep merge dictionaries
                self._deep_merge(merged_data, data)

            except FileNotFoundError:
                logger.error("Input file not found: %s", file_path)
                raise
            except json.JSONDecodeError as e:
                logger.error("Invalid JSON in %s: %s", file_path, e)
                return False

        # Ensure output directory exists
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write merged data to output file
        try:
            indent = self.indent if pretty else None
            with open(output_file, 'w') as f:
                json.dump(merged_data, f, indent=indent, sort_keys=self.sort_keys)

            logger.info("Successfully merged %d files into %s", len(input_files), output_file)
            return True

        except PermissionError as e:
            logger.error("Permission error writing to %s: %s", output_file, e)
            raise
        except Exception as e:
            logger.error("Failed to write merged JSON: %s", e)
            return False

    def _deep_merge(self, target: Dict, source: Dict) -> Dict:
        """
        Deep merge two dictionaries, recursively updating nested dicts.

        Args:
            target: The target dictionary to update
            source: The source dictionary with values to merge

        Returns:
            The updated target dictionary
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                # Recursively update nested dictionaries
                self._deep_merge(target[key], value)
            elif key in target and isinstance(target[key], list) and isinstance(value, list):
                # For lists, append items from source to target
                target[key].extend(value)
            else:
                # Otherwise, just update the value
                target[key] = value

        return target

    @staticmethod
    def detect_format(file_path: str) -> str:
        """
        Detect whether a file is JSON or YAML based on content and extension.

        Args:
            file_path: Path to the file

        Returns:
            String 'json', 'yaml', or 'unknown'
        """
        # First check file extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ('.json', '.jsn'):
            return 'json'
        elif ext in ('.yaml', '.yml'):
            return 'yaml'

        # If extension is ambiguous, try to parse the file
        try:
            with open(file_path, 'r') as f:
                first_non_whitespace = ''
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        first_non_whitespace = stripped
                        break

                # JSON typically starts with { or [
                if first_non_whitespace.startswith('{') or first_non_whitespace.startswith('['):
                    # Try to parse as JSON to confirm
                    f.seek(0)
                    try:
                        json.loads(f.read())
                        return 'json'
                    except json.JSONDecodeError:
                        pass

                # YAML often has key: value pairs or document start indicators
                if ':' in first_non_whitespace or first_non_whitespace == '---':
                    # Try to parse as YAML to confirm
                    f.seek(0)
                    try:
                        yaml.safe_load(f)
                        return 'yaml'
                    except yaml.YAMLError:
                        pass

        except Exception as e:
            logger.debug("Error analyzing file %s: %s", file_path, e)

        return 'unknown'


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="JSON/YAML Converter for Cloud Infrastructure Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Add version info
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')

    # Add verbosity options
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help="Increase verbosity (can be used multiple times)")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="Suppress informational output")

    # Create subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Convert command
    convert_parser = subparsers.add_parser('convert', help='Convert between JSON and YAML')
    convert_parser.add_argument('--input', '-i', required=True, help='Input file path')
    convert_parser.add_argument('--output', '-o', required=True, help='Output file path')
    convert_parser.add_argument('--format', '-f', choices=['json', 'yaml', 'auto'],
                           default='auto', help='Output format (default: auto-detect from extension)')
    convert_parser.add_argument('--indent', type=int, default=2,
                           help='Indentation level (default: 2)')
    convert_parser.add_argument('--sort-keys', action='store_true',
                           help='Sort dictionary keys')
    convert_parser.add_argument('--compact', action='store_true',
                           help='Output compact format without indentation')

    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate JSON or YAML')
    validate_parser.add_argument('--input', '-i', required=True, help='Input file to validate')
    validate_parser.add_argument('--schema', '-s', help='Optional schema file for validation')
    validate_parser.add_argument('--format', '-f', choices=['json', 'yaml', 'auto'],
                             default='auto', help='Input format (default: auto-detect)')

    # Merge command
    merge_parser = subparsers.add_parser('merge', help='Merge multiple JSON or YAML files')
    merge_parser.add_argument('--inputs', '-i', required=True, nargs='+',
                          help='Input files to merge')
    merge_parser.add_argument('--output', '-o', required=True, help='Output file path')
    merge_parser.add_argument('--format', '-f', choices=['json', 'yaml', 'auto'],
                          default='auto', help='Output format (default: auto-detect from extension)')
    merge_parser.add_argument('--indent', type=int, default=2,
                          help='Indentation level (default: 2)')
    merge_parser.add_argument('--sort-keys', action='store_true',
                          help='Sort dictionary keys')
    merge_parser.add_argument('--compact', action='store_true',
                          help='Output compact format without indentation')

    return parser.parse_args()


def configure_logging(args: argparse.Namespace) -> None:
    """Configure logging based on command line arguments."""
    if args.quiet:
        logger.setLevel(logging.WARNING)
    elif args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.INFO)


def get_output_format(input_file: str, output_file: str, format_arg: str) -> str:
    """
    Determine the output format based on arguments and file extensions.

    Args:
        input_file: Input file path
        output_file: Output file path
        format_arg: Format argument from command line

    Returns:
        'json' or 'yaml'
    """
    if format_arg != 'auto':
        return format_arg

    # Try to determine from output file extension
    output_ext = os.path.splitext(output_file)[1].lower()
    if output_ext in ('.json', '.jsn'):
        return 'json'
    elif output_ext in ('.yaml', '.yml'):
        return 'yaml'

    # If output extension is ambiguous, check input extension
    input_ext = os.path.splitext(input_file)[1].lower()
    if input_ext in ('.json', '.jsn'):
        return 'yaml'  # Convert from JSON to YAML
    elif input_ext in ('.yaml', '.yml'):
        return 'json'  # Convert from YAML to JSON

    # If all else fails, default to JSON
    logger.warning("Could not determine output format, defaulting to JSON")
    return 'json'


def main() -> int:
    """
    Main entry point for the script.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    args = parse_arguments()

    # Handle case when no command is provided
    if not args.command:
        logger.error("No command specified. Use --help to see available commands.")
        return 1

    configure_logging(args)

    # Create converter with options
    indent = 0 if getattr(args, 'compact', False) else getattr(args, 'indent', 2)
    converter = JSONYAMLConverter(
        indent=indent,
        sort_keys=getattr(args, 'sort_keys', False)
    )

    try:
        if args.command == 'convert':
            # Determine output format
            output_format = get_output_format(args.input, args.output, args.format)

            # Detect input format
            input_format = converter.detect_format(args.input)
            if input_format == 'unknown':
                logger.error("Could not determine format of input file: %s", args.input)
                return 1

            # Perform conversion
            if input_format == 'json' and output_format == 'yaml':
                success = converter.json_to_yaml_file(args.input, args.output)
            elif input_format == 'yaml' and output_format == 'json':
                success = converter.yaml_to_json_file(args.input, args.output, not args.compact)
            elif input_format == output_format:
                logger.warning("Input and output formats are both %s. Just copying.", input_format)

                # Ensure output directory exists
                output_path = Path(args.output)
                output_path.parent.mkdir(parents=True, exist_ok=True)

                with open(args.input, 'r') as in_file, open(args.output, 'w') as out_file:
                    out_file.write(in_file.read())
                success = True
            else:
                logger.error("Unsupported conversion: %s to %s", input_format, output_format)
                return 1

            return 0 if success else 1

        elif args.command == 'validate':
            # Determine input format
            input_format = args.format
            if input_format == 'auto':
                input_format = converter.detect_format(args.input)
                if input_format == 'unknown':
                    logger.error("Could not determine format of input file: %s", args.input)
                    return 1

            schema_data = None
            if args.schema:
                # Read schema file
                try:
                    with open(args.schema, 'r') as f:
                        schema_data = json.load(f)
                except FileNotFoundError:
                    logger.error("Schema file not found: %s", args.schema)
                    return 1
                except json.JSONDecodeError as e:
                    logger.error("Invalid JSON schema: %s", e)
                    return 1

            # Validate file
            try:
                with open(args.input, 'r') as f:
                    if input_format == 'json':
                        is_valid, error = converter.validate_json(f, schema_data)
                    elif input_format == 'yaml':
                        is_valid, error = converter.validate_yaml(f, schema_data)
                    else:
                        logger.error("Unsupported format: %s", input_format)
                        return 1
            except FileNotFoundError:
                logger.error("Input file not found: %s", args.input)
                return 1

            if is_valid:
                logger.info("Validation successful: %s", args.input)
                return 0
            else:
                logger.error("Validation failed: %s", error)
                return 1

        elif args.command == 'merge':
            # Determine output format
            output_format = args.format
            if output_format == 'auto':
                output_ext = os.path.splitext(args.output)[1].lower()
                if output_ext in ('.json', '.jsn'):
                    output_format = 'json'
                elif output_ext in ('.yaml', '.yml'):
                    output_format = 'yaml'
                else:
                    logger.error("Could not determine format from output file extension: %s", args.output)
                    return 1

            # Perform merge
            if output_format == 'json':
                success = converter.merge_json_files(args.inputs, args.output, not args.compact)
            elif output_format == 'yaml':
                success = converter.merge_yaml_files(args.inputs, args.output)
            else:
                logger.error("Unsupported output format: %s", output_format)
                return 1

            return 0 if success else 1

        else:
            logger.error("Unknown command: %s", args.command)
            return 1

    except Exception as e:
        logger.error("Error: %s", e)
        if logger.level <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
