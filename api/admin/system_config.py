"""
System configuration management for the Administrative API.

This module provides utility functions for managing system configuration settings
through the administrative API. It handles retrieving, updating, and validating
configuration values stored in the database via the SystemConfig model.

Functions include:
- Retrieving individual and grouped configuration values
- Setting and validating configuration values
- Importing and exporting configurations
- Validation of configuration keys and values
"""

import json
import logging
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from models.security.system_config import SystemConfig
from extensions import db
from core.security.cs_audit import log_security_event

# Initialize logger
logger = logging.getLogger(__name__)

# Constants
SENSITIVE_KEYS = {'password', 'secret', 'key', 'token', 'credential', 'api_key'}


def get_config_value(key: str, mask_sensitive: bool = True) -> Optional[str]:
    """
    Get a configuration value by key.

    Args:
        key (str): The configuration key
        mask_sensitive (bool): If True, mask sensitive values

    Returns:
        Optional[str]: The configuration value or None if not found
    """
    try:
        config = SystemConfig.query.filter_by(key=key).first()
        if not config:
            return None

        value = config.decoded_value

        # Mask sensitive values if needed
        if mask_sensitive and any(sensitive_key in key.lower() for sensitive_key in SENSITIVE_KEYS):
            return "********" if value else None

        return value
    except Exception as e:
        logger.error(f"Error retrieving config value for {key}: {e}")
        return None


def set_config_value(key: str, value: str, description: Optional[str] = None,
                    category: Optional[str] = None, updated_by: Optional[int] = None) -> Dict[str, Any]:
    """
    Set or update a configuration value.

    Args:
        key (str): The configuration key
        value (str): The new value
        description (str, optional): Description for the config
        category (str, optional): Category for the config
        updated_by (int, optional): User ID who made the update

    Returns:
        Dict[str, Any]: The updated configuration as a dictionary

    Raises:
        ValueError: If validation fails
    """
    try:
        # Check if config already exists
        config = SystemConfig.query.filter_by(key=key).first()

        if config:
            # Update existing config
            original_value = config.value

            if description is not None:
                config.description = description

            if category is not None:
                # Ensure category is valid
                if category not in SystemConfig.CATEGORIES:
                    raise ValueError(f"Invalid category: {category}")
                config.category = category

            # Update the value and perform validation
            if not config.update_value(value, user_id=updated_by):
                raise ValueError(f"Failed to update configuration value for {key}")

            config.updated_at = datetime.now()
            db.session.commit()

        else:
            # Create new config
            if category is None:
                category = SystemConfig.CATEGORY_GENERAL

            # Ensure category is valid
            if category not in SystemConfig.CATEGORIES:
                raise ValueError(f"Invalid category: {category}")

            config = SystemConfig(
                key=key,
                value=value,
                description=description or f"Configuration setting: {key}",
                category=category
            )

            # Check if validation rules apply
            if hasattr(config, 'validation_rules') and config.validation_rules:
                is_valid, error = config.validate_value(value)
                if not is_valid:
                    raise ValueError(f"Invalid value: {error}")

            db.session.add(config)
            db.session.commit()

        # Return the updated config
        return {
            'key': config.key,
            'value': get_config_value(key),  # Use getter to apply masking if needed
            'description': config.description,
            'category': config.category,
            'updated_at': config.updated_at.isoformat() if config.updated_at else None
        }

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error in set_config_value: {e}")
        raise ValueError(f"Database error: {str(e)}")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in set_config_value: {e}")
        raise ValueError(str(e))


def get_all_configs(category: Optional[str] = None,
                    mask_sensitive: bool = True) -> List[Dict[str, Any]]:
    """
    Get all configuration settings, optionally filtered by category.

    Args:
        category (str, optional): Filter by category
        mask_sensitive (bool): If True, mask sensitive values

    Returns:
        List[Dict[str, Any]]: List of configuration dictionaries
    """
    try:
        query = SystemConfig.query

        if category:
            if category not in SystemConfig.CATEGORIES:
                raise ValueError(f"Invalid category: {category}")
            query = query.filter_by(category=category)

        configs = query.all()
        result = []

        for config in configs:
            value = config.decoded_value

            # Mask sensitive values
            if mask_sensitive and any(sensitive_key in config.key.lower() for sensitive_key in SENSITIVE_KEYS):
                value = "********" if value else None

            result.append({
                'key': config.key,
                'value': value,
                'description': config.description,
                'category': config.category,
                'created_at': config.created_at.isoformat() if config.created_at else None,
                'updated_at': config.updated_at.isoformat() if config.updated_at else None
            })

        return result

    except Exception as e:
        logger.error(f"Error in get_all_configs: {e}")
        raise ValueError(f"Failed to retrieve configurations: {str(e)}")


def validate_config_key(key: str) -> bool:
    """
    Validate if a configuration key is allowed to be modified.

    This function prevents modification of critical system settings
    that should not be changed at runtime.

    Args:
        key (str): Configuration key to validate

    Returns:
        bool: True if the key can be modified, False otherwise
    """
    # List of protected keys that should not be modified directly
    protected_keys = {
        'maintenance_mode',  # This should only be changed through maintenance API
        'system_version',    # Should be set by deployment process
        'database_schema_version', # Should be set by migration system
        'encryption_key',    # Should never be modified directly
        'file_integrity_baseline' # Should only be updated through file integrity system
    }

    return key not in protected_keys


def export_configuration(format_type: str = 'json',
                         category: Optional[str] = None,
                         include_sensitive: bool = False) -> Union[Dict[str, Any], str]:
    """
    Export system configuration in the specified format.

    Args:
        format_type (str): Export format ('json' or 'yaml')
        category (str, optional): Filter by category
        include_sensitive (bool): Whether to include sensitive values

    Returns:
        Union[Dict[str, Any], str]: Exported configuration as dictionary or YAML string

    Raises:
        ValueError: If export fails or format is invalid
    """
    if format_type not in ['json', 'yaml']:
        raise ValueError("Invalid format. Must be 'json' or 'yaml'")

    try:
        # Get configurations
        configs = get_all_configs(category=category, mask_sensitive=not include_sensitive)

        export_data = {
            "version": current_app.config.get('VERSION', '1.0.0'),
            "timestamp": datetime.now().isoformat(),
            "environment": current_app.config.get('ENVIRONMENT', 'production'),
            "config_count": len(configs),
            "configs": configs
        }

        if format_type == 'json':
            return export_data
        else:  # yaml
            try:
                return yaml.dump(export_data, default_flow_style=False)
            except Exception as e:
                raise ValueError(f"YAML serialization failed: {str(e)}")

    except Exception as e:
        logger.error(f"Error exporting configuration: {e}")
        raise ValueError(f"Failed to export configuration: {str(e)}")


def import_configuration(config_data: Union[Dict[str, Any], str],
                         format_type: str = 'json',
                         overwrite: bool = False,
                         imported_by: Optional[int] = None) -> Dict[str, Any]:
    """
    Import system configuration from the specified format.

    Args:
        config_data: Configuration data as dictionary or string
        format_type (str): Import format ('json' or 'yaml')
        overwrite (bool): Whether to overwrite existing values
        imported_by (int, optional): User ID who performed the import

    Returns:
        Dict[str, Any]: Import results with success and error counts

    Raises:
        ValueError: If import fails or format is invalid
    """
    if format_type not in ['json', 'yaml']:
        raise ValueError("Invalid format. Must be 'json' or 'yaml'")

    try:
        # Parse input data if needed
        if format_type == 'yaml' and isinstance(config_data, str):
            try:
                parsed_data = yaml.safe_load(config_data)
            except Exception as e:
                raise ValueError(f"Invalid YAML: {str(e)}")
        elif format_type == 'json' and isinstance(config_data, str):
            try:
                parsed_data = json.loads(config_data)
            except Exception as e:
                raise ValueError(f"Invalid JSON: {str(e)}")
        else:
            parsed_data = config_data

        # Validate structure
        if not isinstance(parsed_data, dict) or 'configs' not in parsed_data:
            raise ValueError("Invalid configuration format. Must contain 'configs' key.")

        configs = parsed_data['configs']
        if not isinstance(configs, list):
            raise ValueError("Invalid 'configs' format. Must be a list of configuration objects.")

        # Process configurations
        results = {
            "imported": [],
            "errors": []
        }

        for config in configs:
            # Validate each config item
            if not isinstance(config, dict) or 'key' not in config or 'value' not in config:
                results["errors"].append({
                    "error": "Invalid config format",
                    "detail": "Config must have 'key' and 'value' properties",
                    "config": config
                })
                continue

            key = config['key']
            value = config['value']
            description = config.get('description')
            category = config.get('category', SystemConfig.CATEGORY_GENERAL)

            # Check if key is valid
            if not validate_config_key(key):
                results["errors"].append({
                    "key": key,
                    "error": "Protected configuration key",
                    "detail": "This configuration cannot be modified through import"
                })
                continue

            # Check if config already exists
            existing = SystemConfig.query.filter_by(key=key).first()
            if existing and not overwrite:
                results["errors"].append({
                    "key": key,
                    "error": "Configuration already exists",
                    "detail": "Set overwrite=true to update existing configurations"
                })
                continue

            try:
                # Update or create configuration
                set_config_value(
                    key=key,
                    value=value,
                    description=description,
                    category=category,
                    updated_by=imported_by
                )

                results["imported"].append({
                    "key": key,
                    "category": category
                })

            except ValueError as e:
                results["errors"].append({
                    "key": key,
                    "error": "Validation error",
                    "detail": str(e)
                })

        # Log the import
        log_security_event(
            event_type="config_import",
            description=f"Configuration import: {len(results['imported'])} imported, {len(results['errors'])} failed",
            severity="high" if len(results['imported']) > 0 else "medium",
            user_id=imported_by,
            details={
                "successful_imports": len(results["imported"]),
                "failed_imports": len(results["errors"])
            }
        )

        return results

    except Exception as e:
        logger.error(f"Error importing configuration: {e}")
        raise ValueError(f"Failed to import configuration: {str(e)}")
