#!/usr/bin/env python3
"""
INI Configuration Validator

Validates INI configuration files against schema definitions.
This tool ensures configuration files meet the required standards
and conform to the expected structure defined in schema files.
"""
import sys
import os
import json
import configparser
import logging
from typing import Dict, Any, List, Tuple, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ini-validator')


def load_ini_schema(schema_file: str) -> Dict[str, Any]:
    """
    Load and parse an INI schema file.
    
    Args:
        schema_file: Path to the JSON schema file
        
    Returns:
        Dictionary containing the schema definition
        
    Raises:
        FileNotFoundError: If the schema file doesn't exist
        json.JSONDecodeError: If the schema file isn't valid JSON
    """
    try:
        with open(schema_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Schema file not found: {schema_file}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in schema file: {e}")
        raise


def validate_ini_file(config_file: str, schema_file: str) -> Tuple[bool, List[str]]:
    """
    Validate an INI file against a schema.
    
    Args:
        config_file: Path to the INI file to validate
        schema_file: Path to the schema file (JSON format)
    
    Returns:
        Tuple of (is_valid, error_messages)
    """
    try:
        # Load schema
        schema = load_ini_schema(schema_file)
        
        # Parse INI file
        config = configparser.ConfigParser()
        config.read(config_file)
        
        errors = []
        warnings = []
        
        # Check required sections
        for section in schema.get('required_sections', []):
            if section not in config:
                errors.append(f"Missing required section: {section}")
        
        # Check section properties
        for section, properties in schema.get('sections', {}).items():
            if section not in config:
                if properties.get('required', False):
                    errors.append(f"Required section missing: {section}")
                continue
                
            # Check required properties in section
            for prop, rules in properties.get('properties', {}).items():
                if rules.get('required', False) and prop not in config[section]:
                    errors.append(f"Required property '{prop}' missing in section '{section}'")
                    continue
                    
                if prop in config[section]:
                    value = config[section][prop]
                    
                    # Check value type
                    if 'type' in rules:
                        try:
                            validate_type(value, rules['type'], section, prop, errors)
                        except ValueError as e:
                            errors.append(str(e))
                    
                    # Check enum values
                    if 'enum' in rules and value not in rules['enum']:
                        errors.append(f"Property '{prop}' in section '{section}' must be one of: {', '.join(rules['enum'])}")
                    
                    # Check minimum/maximum values for numeric types
                    try:
                        validate_range(value, rules, section, prop, errors)
                    except ValueError:
                        # Already handled in validate_type
                        pass
                    
                    # Check default value warning
                    if 'default' in rules and value == rules['default']:
                        warnings.append(f"Property '{prop}' in section '{section}' is using default value: {value}")
        
        # Log warnings but don't make them errors
        for warning in warnings:
            logger.warning(warning)
        
        # Return validation result
        is_valid = len(errors) == 0
        return is_valid, errors
        
    except Exception as e:
        return False, [f"Validation error: {str(e)}"]


def validate_type(value: str, expected_type: str, section: str, prop: str, errors: List[str]) -> None:
    """
    Validate if a value conforms to the expected type.
    
    Args:
        value: The string value from the config file
        expected_type: The expected type from the schema
        section: Section name for error reporting
        prop: Property name for error reporting
        errors: List to append errors to
    """
    if expected_type == "int":
        try:
            int(value)
        except ValueError:
            errors.append(f"Property '{prop}' in section '{section}' must be an integer")
    
    elif expected_type == "float":
        try:
            float(value)
        except ValueError:
            errors.append(f"Property '{prop}' in section '{section}' must be a float")
    
    elif expected_type == "boolean":
        if value.lower() not in ('true', 'false', '0', '1', 'yes', 'no', 'on', 'off'):
            errors.append(f"Property '{prop}' in section '{section}' must be a boolean")


def validate_range(value: str, rules: Dict[str, Any], section: str, prop: str, errors: List[str]) -> None:
    """
    Validate numeric range constraints for a value.
    
    Args:
        value: The string value from the config file
        rules: Rules dictionary from the schema
        section: Section name for error reporting
        prop: Property name for error reporting
        errors: List to append errors to
    """
    if rules.get('type') in ('int', 'float'):
        try:
            num_value = float(value) if rules['type'] == 'float' else int(value)
            
            if 'minimum' in rules and num_value < rules['minimum']:
                errors.append(f"Property '{prop}' in section '{section}' must be >= {rules['minimum']}")
            
            if 'maximum' in rules and num_value > rules['maximum']:
                errors.append(f"Property '{prop}' in section '{section}' must be <= {rules['maximum']}")
        except ValueError:
            # Type validation already caught this error
            pass


def validate_string_length(value: str, rules: Dict[str, Any], section: str, prop: str, errors: List[str]) -> None:
    """
    Validate string length constraints.
    
    Args:
        value: The string value from the config file
        rules: Rules dictionary from the schema
        section: Section name for error reporting
        prop: Property name for error reporting
        errors: List to append errors to
    """
    if rules.get('type') == 'string':
        if 'minLength' in rules and len(value) < rules['minLength']:
            errors.append(f"Property '{prop}' in section '{section}' must be at least {rules['minLength']} characters long")
        
        if 'maxLength' in rules and len(value) > rules['maxLength']:
            errors.append(f"Property '{prop}' in section '{section}' must be at most {rules['maxLength']} characters long")


def main() -> int:
    """
    Main entry point for CLI usage.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ini_file> <schema_file>")
        return 1
        
    config_file = sys.argv[1]
    schema_file = sys.argv[2]
    
    if not os.path.isfile(config_file):
        print(f"Error: Config file {config_file} not found")
        return 1
        
    if not os.path.isfile(schema_file):
        print(f"Error: Schema file {schema_file} not found")
        return 1
    
    is_valid, errors = validate_ini_file(config_file, schema_file)
    
    if is_valid:
        print(f"INI file {os.path.basename(config_file)} is valid")
        return 0
    else:
        print(f"INI file {os.path.basename(config_file)} is invalid:")
        for error in errors:
            print(f"  - {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
