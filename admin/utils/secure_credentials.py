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
from typing import Optional, List, Dict, Any, Generator, Callable
from contextlib import contextmanager
from admin.utils.error_handling import AdminConfigurationError, AdminResourceNotFoundError

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

# --- Helper Functions ---

def _get_vault_client() -> Optional['hvac.Client']:
    """
    Initializes and authenticates the Vault client.

    Returns:
        Authenticated hvac.Client or None if authentication failed
    """
    if not HVAC_AVAILABLE:
        logger.debug("hvac library not available, Vault client unavailable")
        return None

    if not VAULT_ADDR:
        logger.debug("VAULT_ADDR not configured, Vault client unavailable")
        return None

    client = hvac.Client(url=VAULT_ADDR)

    try:
        # Try various authentication methods in priority order

        # 1. Direct token authentication
        if VAULT_TOKEN:
            client.token = VAULT_TOKEN
            if client.is_authenticated():
                logger.debug("Authenticated to Vault using token")
                return client
            else:
                logger.warning("Provided VAULT_TOKEN is invalid or expired")

        # 2. AppRole authentication
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

        # 3. Kubernetes authentication
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
    Retrieves a secret from HashiCorp Vault.

    Args:
        key: The secret key to retrieve
        environment: Optional environment name for namespacing

    Returns:
        Secret value as string or None if not found or error occurred
    """
    client = _get_vault_client()
    if not client:
        return None

    # Build the path where the secret is stored
    if environment:
        secret_path = f"{VAULT_BASE_PATH}/{environment}/{key}"
        alt_path = f"{VAULT_BASE_PATH}/{key}"
    else:
        secret_path = f"{VAULT_BASE_PATH}/{key}"
        alt_path = None

    try:
        # Try to read the secret using KV v2 engine
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=secret_path,
                mount_point='secret'
            )
            # Extract the value - usually stored with the key name as the field
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
    if not source_preference:
        source_preference = DEFAULT_SOURCE_PREFERENCE

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
        target: Where to store the credential ('keyring' or 'file')
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
