"""
Secure Credential Handling Utilities for Administrative Tools.

This module provides functions for securely retrieving and managing sensitive
credentials (API keys, passwords, tokens) needed by administrative scripts
and tools. It integrates with various potential backend secret stores like
HashiCorp Vault, environment variables, or system keyrings, prioritizing
security best practices.
"""

import os
import logging
import json
import time
import datetime
import hashlib
from typing import Optional, List, Dict, Any, Generator, Callable, Tuple, Union
from contextlib import contextmanager
from pathlib import Path

# Attempt to import Vault client
try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False

# Attempt to import keyring
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

# Internal imports
try:
    from core.loggings import get_logger
    logger = get_logger(__name__)
except ImportError:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core logging module not found, using basic logging.")

try:
    from admin.utils.audit_utils import log_admin_action
except ImportError:
    logger.warning("Admin audit logging utility not found. Audit logs will be skipped.")
    def log_admin_action(*args, **kwargs) -> None:
        pass

try:
    from admin.utils.error_handling import AdminConfigurationError, AdminResourceNotFoundError, AdminError
except ImportError:
    logger.warning("Admin error handling utilities not found. Using generic exceptions.")
    class AdminError(Exception):
        """Base class for administrative errors."""
        pass

    class AdminConfigurationError(AdminError):
        """Error related to administrative configuration."""
        pass

    class AdminResourceNotFoundError(AdminError):
        """Error when a required resource is not found."""
        def __init__(self, resource_type: str, resource_id: str, *args, **kwargs):
            self.resource_type = resource_type
            self.resource_id = resource_id
            message = f"{resource_type} not found: {resource_id}"
            super().__init__(message, *args, **kwargs)

# --- Configuration ---

# Order of preference for credential sources
DEFAULT_SOURCE_PREFERENCE: List[str] = ['vault', 'env', 'keyring', 'file']

# Environment variable prefix for credentials
ENV_CRED_PREFIX: str = "CP_ADMIN_CRED_"

# Vault configuration
VAULT_ADDR: Optional[str] = os.environ.get("VAULT_ADDR")
VAULT_TOKEN: Optional[str] = os.environ.get("VAULT_TOKEN")
VAULT_ROLE_ID: Optional[str] = os.environ.get("VAULT_ROLE_ID")
VAULT_SECRET_ID: Optional[str] = os.environ.get("VAULT_SECRET_ID")
VAULT_K8S_ROLE: Optional[str] = os.environ.get("VAULT_K8S_ROLE")
VAULT_K8S_MOUNT_PATH: Optional[str] = os.environ.get("VAULT_K8S_MOUNT_PATH", "kubernetes")
VAULT_BASE_PATH: str = os.environ.get("VAULT_ADMIN_BASE_PATH", "secret/cloud-platform/admin")

# Keyring service name
KEYRING_SERVICE_NAME: str = "cloud_platform_admin"

# Credential cache settings
CACHE_CREDENTIALS = os.environ.get("CACHE_ADMIN_CREDENTIALS", "false").lower() == "true"
CREDENTIAL_CACHE: Dict[str, Dict[str, Any]] = {}
DEFAULT_CACHE_TTL = 300  # Default cache TTL in seconds

# --- Helper Functions ---

def _get_vault_client() -> Optional['hvac.Client']:
    """
    Creates and authenticates a HashiCorp Vault client.

    Attempts authentication using several methods in order of preference:
    1. VAULT_TOKEN environment variable
    2. AppRole authentication with VAULT_ROLE_ID and VAULT_SECRET_ID
    3. Kubernetes authentication using service account token
    4. Existing authentication from .vault-token file

    Returns:
        Optional[hvac.Client]: Authenticated client or None if failed
    """
    if not HVAC_AVAILABLE:
        logger.warning("HashiCorp Vault client library not available")
        return None

    if not VAULT_ADDR:
        logger.debug("VAULT_ADDR not set, skipping Vault credential source")
        return None

    try:
        # Initialize client
        client = hvac.Client(url=VAULT_ADDR)

        # 1. Try token authentication first
        if VAULT_TOKEN:
            client.token = VAULT_TOKEN
            if client.is_authenticated():
                logger.debug("Authenticated to Vault using VAULT_TOKEN")
                return client
            else:
                logger.warning("VAULT_TOKEN is invalid")

        # 2. Try AppRole authentication
        if VAULT_ROLE_ID and VAULT_SECRET_ID:
            try:
                client.auth.approle.login(
                    role_id=VAULT_ROLE_ID,
                    secret_id=VAULT_SECRET_ID
                )
                if client.is_authenticated():
                    logger.debug("Authenticated to Vault using AppRole")
                    return client
                else:
                    logger.warning("Vault AppRole authentication failed")
            except Exception as e:
                logger.warning(f"Vault AppRole authentication error: {e}")

        # 3. Try Kubernetes authentication
        if VAULT_K8S_ROLE:
            k8s_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            if os.path.exists(k8s_token_path):
                try:
                    with open(k8s_token_path, 'r') as f:
                        jwt = f.read()

                    client.auth.kubernetes.login(
                        role=VAULT_K8S_ROLE,
                        jwt=jwt,
                        mount_point=VAULT_K8S_MOUNT_PATH
                    )
                    if client.is_authenticated():
                        logger.debug("Authenticated to Vault using Kubernetes Auth")
                        return client
                    else:
                        logger.warning("Vault Kubernetes authentication failed")
                except Exception as e:
                    logger.warning(f"Vault Kubernetes authentication error: {e}")
            else:
                logger.debug(f"Kubernetes service account token not found at {k8s_token_path}")

        # 4. Check if already authenticated (e.g., via CLI)
        if client.is_authenticated():
            logger.debug("Using existing Vault authentication")
            return client

    except Exception as e:
        logger.error(f"Vault authentication failed: {str(e)}")

    logger.warning("All Vault authentication methods failed")
    return None


def _get_from_vault(key: str, environment: Optional[str] = None) -> Optional[str]:
    """
    Retrieves a credential from HashiCorp Vault.

    Args:
        key: The key to look up in Vault
        environment: Optional environment name for path construction

    Returns:
        Credential value or None if not found or unavailable
    """
    if not HVAC_AVAILABLE:
        logger.debug("HashiCorp Vault client library not available")
        return None

    client = _get_vault_client()
    if not client:
        logger.debug("Could not obtain authenticated Vault client")
        return None

    # Construct path based on environment
    if environment:
        secret_path = f"{VAULT_BASE_PATH}/{environment}"
        alt_path = f"{VAULT_BASE_PATH}/environments/{environment}"
    else:
        secret_path = VAULT_BASE_PATH
        alt_path = None

    try:
        # Try to get the secret from Vault
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=secret_path,
                mount_point='secret'
            )
            value = response['data']['data'].get(key)
            if value is not None:
                logger.debug(f"Retrieved secret '{key}' from Vault at path '{secret_path}'")
                return value
        except hvac.exceptions.InvalidPath:
            logger.debug(f"Secret not found at path '{secret_path}'")

        # Try alternate path if available
        if alt_path:
            try:
                response = client.secrets.kv.v2.read_secret_version(
                    path=alt_path,
                    mount_point='secret'
                )
                value = response['data']['data'].get(key)
                if value is not None:
                    logger.debug(f"Retrieved secret '{key}' from Vault at alternate path '{alt_path}'")
                    return value
            except hvac.exceptions.InvalidPath:
                logger.debug(f"Secret not found at alternate path '{alt_path}'")

    except Exception as e:
        logger.error(f"Error retrieving secret '{key}' from Vault: {str(e)}")

    return None


def _get_from_env(key: str) -> Optional[str]:
    """
    Retrieves a credential from environment variables.

    Args:
        key: The key to look up in environment variables

    Returns:
        Credential value or None if not found
    """
    # Convert to uppercase and add prefix
    env_var_name = f"{ENV_CRED_PREFIX}{key.upper()}"
    value = os.environ.get(env_var_name)

    if value is not None:
        logger.debug(f"Retrieved credential '{key}' from environment variable")
        return value

    logger.debug(f"Credential '{key}' not found in environment variables")
    return None


def _get_from_keyring(key: str) -> Optional[str]:
    """
    Retrieves a credential from the system keyring.

    Args:
        key: The key to look up in the system keyring

    Returns:
        Credential value or None if not found or keyring unavailable
    """
    if not KEYRING_AVAILABLE:
        logger.debug("keyring library not available")
        return None

    try:
        value = keyring.get_password(KEYRING_SERVICE_NAME, key)
        if value is not None:
            logger.debug(f"Retrieved credential '{key}' from system keyring")
            return value

        logger.debug(f"Credential '{key}' not found in system keyring")
        return None
    except Exception as e:
        logger.error(f"Error accessing system keyring for '{key}': {str(e)}")
        return None


def _get_from_file(key: str, environment: Optional[str] = None) -> Optional[str]:
    """
    Retrieves a credential from credential files (last resort).

    Args:
        key: The key to look up in credential files
        environment: Optional environment name for namespacing

    Returns:
        Credential value or None if not found
    """
    # Determine base directory for credential files
    creds_dir = os.environ.get("CP_ADMIN_CREDS_DIR", "/etc/cloud-platform/admin/secrets")

    # First try environment-specific file if environment is provided
    if environment:
        env_file = os.path.join(creds_dir, f"{environment}.json")
        try:
            if os.path.exists(env_file):
                with open(env_file, 'r') as f:
                    creds_data = json.load(f)
                    if key in creds_data:
                        logger.debug(f"Retrieved credential '{key}' from file '{env_file}'")
                        return creds_data[key]
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Error reading environment credentials file '{env_file}': {str(e)}")

    # Then try default credentials file
    default_file = os.path.join(creds_dir, "credentials.json")
    try:
        if os.path.exists(default_file):
            with open(default_file, 'r') as f:
                creds_data = json.load(f)
                if key in creds_data:
                    logger.debug(f"Retrieved credential '{key}' from file '{default_file}'")
                    return creds_data[key]
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error reading default credentials file '{default_file}': {str(e)}")

    logger.debug(f"Credential '{key}' not found in credential files")
    return None


# --- Public Functions ---

def get_credential(
    key: str,
    environment: Optional[str] = None,
    source_preference: Optional[List[str]] = None,
    log_access: bool = True
) -> str:
    """
    Retrieves a credential securely from configured sources.

    Searches for the credential in the specified order of preference.

    Args:
        key: The name/key of the credential to retrieve
        environment: The target environment (e.g., 'production', 'staging').
                    Used for namespacing in some sources like Vault or files.
        source_preference: A list defining the order to check sources
                          (e.g., ['vault', 'env']). Defaults to
                          DEFAULT_SOURCE_PREFERENCE.
        log_access: Whether to log an audit event upon successful retrieval.

    Returns:
        The credential value as a string

    Raises:
        AdminResourceNotFoundError: If credential cannot be found in any source
        AdminConfigurationError: If a configured source is unavailable
    """
    if source_preference is None:
        source_preference = DEFAULT_SOURCE_PREFERENCE

    # Check cache first if caching is enabled
    cache_key = f"{key}:{environment or 'default'}"
    if CACHE_CREDENTIALS and cache_key in CREDENTIAL_CACHE:
        cache_entry = CREDENTIAL_CACHE[cache_key]
        if cache_entry['expires'] > time.time():
            logger.debug(f"Using cached credential '{key}'")
            return cache_entry['value']
        else:
            # Remove expired cache entry
            del CREDENTIAL_CACHE[cache_key]

    logger.info(f"Retrieving credential '{key}' for environment '{environment or 'default'}'")

    retrieval_methods = {
        'vault': lambda: _get_from_vault(key, environment),
        'env': lambda: _get_from_env(key),
        'keyring': lambda: _get_from_keyring(key),
        'file': lambda: _get_from_file(key, environment),
    }

    for source in source_preference:
        if source not in retrieval_methods:
            logger.warning(f"Unknown credential source '{source}', skipping")
            continue

        try:
            value = retrieval_methods[source]()
            if value is not None:
                # Log the successful retrieval
                if log_access:
                    log_admin_action(
                        action="credential.access",
                        status="success",
                        details={
                            "credential_key": key,
                            "source": source,
                            "environment": environment or 'default'
                        }
                    )

                # Cache the credential if caching is enabled
                if CACHE_CREDENTIALS:
                    CREDENTIAL_CACHE[cache_key] = {
                        'value': value,
                        'expires': time.time() + DEFAULT_CACHE_TTL
                    }

                return str(value)
        except Exception as e:
            logger.error(f"Error accessing credential source '{source}': {str(e)}")

    # If we get here, the credential wasn't found
    log_admin_action(
        action="credential.access",
        status="failure",
        details={
            "credential_key": key,
            "environment": environment or 'default',
            "reason": "Not found in any source",
            "sources_checked": source_preference
        }
    )
    raise AdminResourceNotFoundError("Credential", key)


@contextmanager
def secure_credential(
    key: str,
    environment: Optional[str] = None,
    source_preference: Optional[List[str]] = None,
    log_access: bool = True
) -> Generator[str, None, None]:
    """
    Context manager for secure credential handling.

    Retrieves a credential securely using get_credential() and attempts
    to clean up the credential from memory when the context exits.

    Args:
        key: The name/key of the credential to retrieve
        environment: The target environment
        source_preference: A list defining the order to check sources
        log_access: Whether to log an audit event for access

    Yields:
        The credential value

    Raises:
        AdminResourceNotFoundError: If credential cannot be found
        AdminConfigurationError: If a configured source is unavailable

    Example:
        with secure_credential('database_password', 'production') as password:
            db = connect_to_database(user='admin', password=password)
            # Password will be attempted to be cleared after context exits
    """
    value = None
    try:
        value = get_credential(key, environment, source_preference, log_access)
        yield value
    finally:
        # Attempt to clear the credential from memory
        if value is not None:
            # 1. Overwrite the string with dummy data
            try:
                placeholder = '*' * len(value)
                value = placeholder
            except Exception:
                pass

            # 2. Delete the reference to trigger garbage collection
            del value


def store_credential(
    key: str,
    value: str,
    environment: Optional[str] = None,
    target: str = 'keyring',
    expires_in: Optional[int] = None
) -> bool:
    """
    Stores a credential in the specified credential storage.

    Warning: This should only be used for development or temporary credentials.
    Production credentials should be managed through proper secret management.

    Args:
        key: The name/key to store the credential under
        value: The credential value to store
        environment: Optional environment name for namespacing
        target: Where to store the credential ('keyring', 'vault', or 'file')
        expires_in: Optional expiration time in seconds

    Returns:
        True if stored successfully, False otherwise

    Raises:
        AdminConfigurationError: If target storage is unavailable
        ValueError: If an unsupported target is specified
    """
    if target == 'keyring':
        if not KEYRING_AVAILABLE:
            raise AdminConfigurationError("Keyring storage unavailable, missing keyring package")

        try:
            keyring.set_password(KEYRING_SERVICE_NAME, key, value)
            logger.info(f"Stored credential '{key}' in system keyring")

            # Log audit event for credential storage
            log_admin_action(
                action="credential.store",
                status="success",
                details={
                    "credential_key": key,
                    "target": target,
                    "environment": environment or 'default',
                    "expiration": expires_in
                }
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store credential in keyring: {str(e)}")
            return False

    elif target == 'vault':
        if not HVAC_AVAILABLE:
            raise AdminConfigurationError("Vault storage unavailable, missing hvac package")

        client = _get_vault_client()
        if not client:
            raise AdminConfigurationError("Failed to connect to Vault")

        try:
            # Construct path based on environment
            if environment:
                secret_path = f"{VAULT_BASE_PATH}/{environment}"
            else:
                secret_path = VAULT_BASE_PATH

            # First read existing secrets to avoid overwriting
            try:
                response = client.secrets.kv.v2.read_secret_version(
                    path=secret_path,
                    mount_point='secret'
                )
                data = response['data']['data']
            except hvac.exceptions.InvalidPath:
                data = {}
            except Exception as e:
                logger.warning(f"Error reading existing secrets: {e}")
                data = {}

            # Add new credential
            data[key] = value

            # Create or update the secret
            client.secrets.kv.v2.create_or_update_secret(
                path=secret_path,
                mount_point='secret',
                secret=data
            )

            logger.info(f"Stored credential '{key}' in Vault at path '{secret_path}'")

            # Log audit event
            log_admin_action(
                action="credential.store",
                status="success",
                details={
                    "credential_key": key,
                    "target": target,
                    "vault_path": secret_path,
                    "environment": environment or 'default',
                    "expiration": expires_in
                }
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store credential in Vault: {str(e)}")
            return False

    elif target == 'file':
        # Only allow file storage in development environments for safety
        if environment and environment.lower() not in ['dev', 'development', 'local', 'test']:
            logger.error(f"File storage only allowed in development environments, not '{environment}'")
            return False

        creds_dir = os.environ.get("CP_ADMIN_CREDS_DIR", "/etc/cloud-platform/admin/secrets")
        if environment:
            # Ensure environment directory exists
            env_dir = os.path.join(creds_dir, environment)
            os.makedirs(env_dir, exist_ok=True)
            filepath = os.path.join(env_dir, "credentials.json")
        else:
            filepath = os.path.join(creds_dir, "credentials.json")

        # Create or update the credentials file
        try:
            data = {}
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    data = json.load(f)

            data[key] = value

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

            # Set secure permissions
            os.chmod(filepath, 0o600)
            logger.info(f"Stored credential '{key}' in file: {filepath}")

            # Log audit event
            log_admin_action(
                action="credential.store",
                status="success",
                details={
                    "credential_key": key,
                    "target": target,
                    "file": filepath,
                    "environment": environment or 'default',
                    "expiration": expires_in
                }
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store credential in file: {str(e)}")
            return False
    else:
        raise ValueError(f"Unsupported credential storage target: {target}")


def delete_credential(
    key: str,
    environment: Optional[str] = None,
    target: Optional[str] = None
) -> bool:
    """
    Deletes a credential from the specified storage.

    Args:
        key: The name/key of the credential to delete
        environment: Optional environment name for namespacing
        target: Where to delete the credential from (None to try all)

    Returns:
        True if deleted successfully, False otherwise
    """
    targets_to_try = [target] if target else ['vault', 'keyring', 'file']
    success = False

    for t in targets_to_try:
        if t == 'keyring' and KEYRING_AVAILABLE:
            try:
                keyring.delete_password(KEYRING_SERVICE_NAME, key)
                logger.info(f"Deleted credential '{key}' from system keyring")
                success = True
            except Exception as e:
                logger.debug(f"Failed to delete credential from keyring: {str(e)}")

        elif t == 'vault' and HVAC_AVAILABLE:
            client = _get_vault_client()
            if client:
                try:
                    # Construct path based on environment
                    if environment:
                        secret_path = f"{VAULT_BASE_PATH}/{environment}"
                    else:
                        secret_path = VAULT_BASE_PATH

                    # First read existing secrets
                    try:
                        response = client.secrets.kv.v2.read_secret_version(
                            path=secret_path,
                            mount_point='secret'
                        )
                        data = response['data']['data']
                    except hvac.exceptions.InvalidPath:
                        logger.debug(f"Secret path '{secret_path}' not found in Vault")
                        continue

                    # Remove the credential if it exists
                    if key in data:
                        del data[key]

                        # Update the secret
                        client.secrets.kv.v2.create_or_update_secret(
                            path=secret_path,
                            mount_point='secret',
                            secret=data
                        )

                        logger.info(f"Deleted credential '{key}' from Vault at path '{secret_path}'")
                        success = True
                except Exception as e:
                    logger.debug(f"Failed to delete credential from Vault: {str(e)}")

        elif t == 'file':
            creds_dir = os.environ.get("CP_ADMIN_CREDS_DIR", "/etc/cloud-platform/admin/secrets")

            # Determine file path based on environment
            if environment:
                filepath = os.path.join(creds_dir, environment, "credentials.json")
            else:
                filepath = os.path.join(creds_dir, "credentials.json")

            try:
                if os.path.exists(filepath):
                    with open(filepath, 'r') as f:
                        data = json.load(f)

                    if key in data:
                        del data[key]

                        with open(filepath, 'w') as f:
                            json.dump(data, f, indent=2)

                        logger.info(f"Deleted credential '{key}' from file {filepath}")
                        success = True
            except Exception as e:
                logger.debug(f"Failed to delete credential from file: {str(e)}")

    # Log the action
    log_admin_action(
        action="credential.delete",
        status="success" if success else "failure",
        details={
            "credential_key": key,
            "environment": environment or 'default',
            "targets": targets_to_try
        }
    )

    # Clear from cache if present
    if CACHE_CREDENTIALS:
        cache_key = f"{key}:{environment or 'default'}"
        if cache_key in CREDENTIAL_CACHE:
            del CREDENTIAL_CACHE[cache_key]

    return success


def rotate_credential(
    key: str,
    generator: Callable[[], str],
    environment: Optional[str] = None,
    target: str = 'vault',
    deprecation_period: Optional[int] = None
) -> Dict[str, Any]:
    """
    Rotates a credential by generating a new one and storing it.

    Args:
        key: The name/key of the credential to rotate
        generator: A function that generates the new credential value
        environment: Optional environment name for namespacing
        target: Where to store the new credential
        deprecation_period: Optional period in seconds before the old
                           credential becomes invalid

    Returns:
        Dict with new_value and old_value if successful

    Raises:
        AdminConfigurationError: If target storage is unavailable
    """
    # Generate timestamp for versioning
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

    # Create key for old credential
    old_key = f"{key}_old_{timestamp}"

    try:
        # Try to get the old credential
        try:
            old_value = get_credential(key, environment, log_access=False)
            has_old = True
        except AdminResourceNotFoundError:
            old_value = None
            has_old = False

        # Generate new credential
        new_value = generator()

        # Store the new credential
        if not store_credential(key, new_value, environment, target):
            raise AdminConfigurationError(f"Failed to store new credential '{key}'")

        # Store the old credential with timestamp if it existed
        if has_old:
            if not store_credential(old_key, old_value, environment, target,
                                   expires_in=deprecation_period):
                logger.warning(f"Failed to store old credential '{old_key}'")

        # Log the rotation
        log_admin_action(
            action="credential.rotate",
            status="success",
            details={
                "credential_key": key,
                "old_credential_key": old_key if has_old else None,
                "environment": environment or 'default',
                "target": target,
                "deprecation_period": deprecation_period
            }
        )

        return {
            "key": key,
            "new_value": new_value,
            "old_value": old_value,
            "old_key": old_key if has_old else None,
            "timestamp": timestamp,
            "environment": environment,
            "deprecation_period": deprecation_period
        }

    except Exception as e:
        # Log the failure
        log_admin_action(
            action="credential.rotate",
            status="failure",
            details={
                "credential_key": key,
                "environment": environment or 'default',
                "error": str(e)
            }
        )
        raise


# Additional utility functions

def list_credentials(environment: Optional[str] = None) -> Dict[str, List[str]]:
    """
    List available credentials by source.

    This function doesn't return the actual credential values,
    only the keys that are available.

    Args:
        environment: Optional environment name for namespacing

    Returns:
        Dict mapping sources to lists of available credential keys
    """
    result = {
        'vault': [],
        'keyring': [],
        'env': [],
        'file': []
    }

    # Check environment variables
    for env_var in os.environ:
        if env_var.startswith(ENV_CRED_PREFIX):
            key = env_var[len(ENV_CRED_PREFIX):].lower()
            result['env'].append(key)

    # Check keyring if available
    if KEYRING_AVAILABLE:
        # Note: There's no standard way to list all keys in a keyring
        # This is inherently limited by the keyring backends
        pass

    # Check file
    creds_dir = os.environ.get("CP_ADMIN_CREDS_DIR", "/etc/cloud-platform/admin/secrets")
    if environment:
        filepath = os.path.join(creds_dir, f"{environment}.json")
    else:
        filepath = os.path.join(creds_dir, "credentials.json")

    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
                result['file'] = list(data.keys())
    except Exception as e:
        logger.debug(f"Failed to read credentials file: {str(e)}")

    # Check Vault if available
    if HVAC_AVAILABLE:
        client = _get_vault_client()
        if client:
            try:
                # Construct path based on environment
                if environment:
                    secret_path = f"{VAULT_BASE_PATH}/{environment}"
                else:
                    secret_path = VAULT_BASE_PATH

                response = client.secrets.kv.v2.read_secret_version(
                    path=secret_path,
                    mount_point='secret'
                )
                result['vault'] = list(response['data']['data'].keys())
            except Exception as e:
                logger.debug(f"Failed to read Vault secrets: {str(e)}")

    return result


def clear_credential_cache() -> int:
    """
    Clears the in-memory credential cache.

    Returns:
        Number of cache entries cleared
    """
    count = len(CREDENTIAL_CACHE)
    CREDENTIAL_CACHE.clear()
    logger.debug(f"Cleared {count} entries from credential cache")
    return count


if __name__ == "__main__":
    # Simple self-test
    print("Testing secure credential utilities...")

    # Test credential storage and retrieval
    test_key = "test_credential"
    test_value = f"test_value_{int(time.time())}"

    print(f"Storing test credential: {test_key}")
    success = False

    # Try to store in keyring first
    if KEYRING_AVAILABLE:
        success = store_credential(test_key, test_value, target='keyring')
        print(f"Store in keyring: {'Success' if success else 'Failed'}")
    else:
        print("Keyring not available")

    # Fall back to file storage
    if not success:
        success = store_credential(test_key, test_value, environment='dev', target='file')
        print(f"Store in file: {'Success' if success else 'Failed'}")

    # Retrieve the credential
    if success:
        try:
            retrieved = get_credential(test_key, environment='dev')
            print(f"Retrieved credential matches: {retrieved == test_value}")

            # Test secure context manager
            with secure_credential(test_key, environment='dev') as value:
                print(f"Secure context manager works: {value == test_value}")

            # Clean up
            delete_credential(test_key, environment='dev')
            print("Deleted test credential")

        except Exception as e:
            print(f"Error during retrieval: {e}")
    else:
        print("Skipping retrieval test")

    print("Self-test completed")
