#!/usr/bin/env python3
"""
Secure Communications Manager for Incident Response

This module provides tools to establish secure communication channels during security
incident response, ensuring confidential and authenticated communications between
responders, stakeholders, and affected systems.

Features:
- Encrypted communication channels for incident response team
- Secure file sharing for sensitive incident artifacts
- Ephemeral messaging with automatic expiration
- Verification of communication authenticity
- Multi-channel notification system with fallbacks
- Audit trail of all communications
"""

import argparse
import base64
import datetime
import getpass
import hashlib
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any

# Add parent directory to path if running as script
if __name__ == "__main__":
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

# Initialize module path and constants
MODULE_PATH = Path(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = MODULE_PATH / "config"
DEFAULT_CHANNEL_CONFIG = CONFIG_DIR / "secure_channels.json"
DEFAULT_KEY_DIR = MODULE_PATH / ".secure" / "keys"
KEY_FILE_PERMISSIONS = 0o600
LOG_FILE_PERMISSIONS = 0o600
DIR_PERMISSIONS = 0o700

# Import shared components from the toolkit
try:
    from admin.security.incident_response_kit import (
        response_config, tool_paths, CONFIG_AVAILABLE, MODULE_PATH,
        IncidentResponseError, sanitize_incident_id
    )
    from admin.security.incident_response_kit.coordination.notification_system import notify_stakeholders
    TOOLKIT_IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Error importing toolkit modules: {e}", file=sys.stderr)
    TOOLKIT_IMPORTS_AVAILABLE = False

    # Fallback definitions if imports aren't available
    class IncidentResponseError(Exception):
        """Base exception for all incident response errors."""
        pass

    def sanitize_incident_id(incident_id: str) -> str:
        """Sanitize incident ID for use in filenames."""
        return "".join(c for c in incident_id if c.isalnum() or c in "-_").strip()

    response_config = {}
    tool_paths = {}
    CONFIG_AVAILABLE = False

# Try to import security components from core module
try:
    from core.security.cs_crypto import (
        encrypt_sensitive_data, decrypt_sensitive_data,
        generate_secure_token, generate_hmac_token, verify_hmac_token
    )
    from core.security.cs_audit import log_security_event
    CORE_SECURITY_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Core security module not available: {e}", file=sys.stderr)
    CORE_SECURITY_AVAILABLE = False

# Exception classes
class CommunicationError(IncidentResponseError):
    """Error during secure communications."""
    pass

class ChannelError(CommunicationError):
    """Error with communication channel setup or operation."""
    pass

class EncryptionError(CommunicationError):
    """Error during encryption or decryption operations."""
    pass

class AuthenticationError(CommunicationError):
    """Authentication failure during communications."""
    pass

class ValidationError(CommunicationError):
    """Invalid input or configuration parameters."""
    pass

# Enums and constants
class ChannelType(str, Enum):
    """Communication channel types."""
    EMAIL = "email"
    CHAT = "chat"
    ENCRYPTED_FILE = "encrypted_file"
    MESSAGING = "messaging"
    API = "api"
    WEBHOOK = "webhook"
    CUSTOM = "custom"

class MessagePriority(str, Enum):
    """Message priority levels."""
    URGENT = "urgent"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class SecurityLevel(str, Enum):
    """Security level for communications."""
    CRITICAL = "critical"  # Most sensitive communications, maximum security
    HIGH = "high"          # Sensitive operational details
    MEDIUM = "medium"      # General incident information
    LOW = "low"            # Non-sensitive communications

@dataclass
class SecureMessage:
    """Represents an encrypted message with metadata."""
    content: str
    sender: str
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    message_id: str = field(default_factory=lambda: secrets.token_hex(8))
    priority: MessagePriority = MessagePriority.MEDIUM
    expires_at: Optional[str] = None
    signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return {
            "content": self.content,
            "sender": self.sender,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
            "priority": self.priority,
            "expires_at": self.expires_at,
            "signature": self.signature,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecureMessage':
        """Create message from dictionary."""
        return cls(
            content=data["content"],
            sender=data["sender"],
            timestamp=data.get("timestamp", datetime.datetime.now().isoformat()),
            message_id=data.get("message_id", secrets.token_hex(8)),
            priority=data.get("priority", MessagePriority.MEDIUM),
            expires_at=data.get("expires_at"),
            signature=data.get("signature"),
            metadata=data.get("metadata", {})
        )

class SecureComms:
    """
    Main class for managing secure communications during incident response.
    """

    def __init__(
        self,
        incident_id: Optional[str] = None,
        config_path: Optional[str] = None,
        key_dir: Optional[str] = None,
        log_level: int = logging.INFO,
        integrity_check: bool = True
    ):
        """
        Initialize secure communications manager.

        Args:
            incident_id: Optional incident ID to associate with communications
            config_path: Path to configuration file (defaults to standard location)
            key_dir: Directory for encryption keys (defaults to standard location)
            log_level: Logging level
            integrity_check: Whether to verify toolkit integrity on startup

        Raises:
            ChannelError: If initialization fails
        """
        self.incident_id = incident_id
        self.config_path = config_path or DEFAULT_CHANNEL_CONFIG
        self.key_dir = Path(key_dir) if key_dir else DEFAULT_KEY_DIR
        self.integrity_verified = False
        self.channels = {}

        # Set up logging
        self.logger = self._setup_logging(log_level)

        # Load configuration
        self.config = self._load_config()

        # Set up key directory
        self._setup_key_dir()

        # Verify integrity if requested
        if integrity_check:
            self.verify_integrity()

    def verify_integrity(self) -> bool:
        """
        Verify the integrity of the toolkit components.

        Returns:
            bool: True if integrity check passed, False otherwise
        """
        self.logger.info("Verifying toolkit integrity...")

        try:
            # Define paths to critical files
            critical_files = [
                MODULE_PATH / "secure_comms.py",
                MODULE_PATH / "coordination" / "notification_system.py",
                MODULE_PATH / "config" / "response_config.json"
            ]

            # Try to import file integrity from forensic_tools if available
            try:
                sys.path.insert(0, str(MODULE_PATH))
                from forensic_tools.file_integrity import verify_file_integrity

                for file_path in critical_files:
                    if file_path.exists():
                        if not verify_file_integrity(file_path):
                            self.logger.error(f"Integrity check failed for {file_path}")
                            return False

                self.integrity_verified = True
                self.logger.info("Toolkit integrity verification successful")
                return True
            except ImportError:
                self.logger.warning("Could not import file_integrity module for verification")

                # Fallback to simple existence check if verification module not available
                for file_path in critical_files:
                    if not file_path.exists():
                        self.logger.warning(f"Critical file missing: {file_path}")

                self.logger.info("Basic file existence check completed")
                self.integrity_verified = True
                return True

        except Exception as e:
            self.logger.error(f"Error during integrity verification: {e}")
            return False

    def setup_channel(self, channel_type: Union[str, ChannelType], config: Dict[str, Any]) -> bool:
        """
        Configure a secure communication channel.

        Args:
            channel_type: Type of communication channel
            config: Channel configuration parameters

        Returns:
            bool: True if successful, False otherwise

        Raises:
            ChannelError: If channel setup fails
        """
        try:
            if isinstance(channel_type, str):
                channel_type = ChannelType(channel_type)

            # Validate configuration
            required_keys = self._get_required_keys(channel_type)
            missing_keys = [key for key in required_keys if key not in config]
            if missing_keys:
                raise ValidationError(f"Missing required configuration keys: {', '.join(missing_keys)}")

            # Store channel configuration
            self.channels[channel_type.value] = {
                "type": channel_type.value,
                "config": config,
                "enabled": True,
                "last_tested": None,
                "test_result": None
            }

            self.logger.info(f"Channel {channel_type.value} configured successfully")
            return True

        except Exception as e:
            self.logger.error(f"Error setting up channel {channel_type}: {str(e)}")
            raise ChannelError(f"Failed to set up {channel_type} channel: {str(e)}")

    def send_message(
        self,
        recipients: List[str],
        content: str,
        priority: Union[str, MessagePriority] = MessagePriority.MEDIUM,
        channel_type: Optional[Union[str, ChannelType]] = None,
        security_level: Union[str, SecurityLevel] = SecurityLevel.MEDIUM,
        expires_in: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Send a secure message to recipients.

        Args:
            recipients: List of recipient identifiers (emails, usernames, etc.)
            content: Message content
            priority: Message priority
            channel_type: Specific channel to use (auto-select if None)
            security_level: Security level for the message
            expires_in: Message expiry in seconds
            metadata: Additional message metadata

        Returns:
            Dict containing message ID and delivery status

        Raises:
            ChannelError: If message delivery fails
        """
        if isinstance(priority, str):
            priority = MessagePriority(priority)

        if isinstance(security_level, str):
            security_level = SecurityLevel(security_level)

        if channel_type and isinstance(channel_type, str):
            channel_type = ChannelType(channel_type)

        sender = getpass.getuser()  # Default to current system user
        message_id = secrets.token_hex(8)
        timestamp = datetime.datetime.now().isoformat()

        # Set expiry if provided
        expires_at = None
        if expires_in:
            expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=expires_in)
            expires_at = expiry_time.isoformat()

        # Prepare message
        message = SecureMessage(
            content=content,
            sender=sender,
            timestamp=timestamp,
            message_id=message_id,
            priority=priority,
            expires_at=expires_at,
            metadata=metadata or {}
        )

        # Sign message if possible
        if CORE_SECURITY_AVAILABLE:
            try:
                message_str = json.dumps(message.to_dict(), sort_keys=True)
                message.signature = generate_hmac_token(
                    key=self._get_signing_key(),
                    message=message_str
                )
            except Exception as e:
                self.logger.warning(f"Unable to sign message: {e}")

        # Select channel if not specified
        if not channel_type:
            channel_type = self._select_channel(security_level, priority)

        # Ensure the channel is configured
        if channel_type.value not in self.channels:
            raise ChannelError(f"Channel {channel_type.value} is not configured")

        # Encrypt sensitive content if possible
        if security_level in (SecurityLevel.CRITICAL, SecurityLevel.HIGH):
            try:
                if CORE_SECURITY_AVAILABLE:
                    message.content = encrypt_sensitive_data(content)
                else:
                    # Basic encryption fallback
                    self.logger.warning("Using basic encryption as core security is unavailable")
                    key = self._derive_encryption_key()
                    message.content = self._encrypt_content(content, key)
            except Exception as e:
                raise EncryptionError(f"Failed to encrypt message: {e}")

        # Send the message
        result = {
            "message_id": message_id,
            "timestamp": timestamp,
            "recipients": recipients,
            "status": "sent",
            "channel": channel_type.value
        }

        try:
            # Use toolkit notification system if available
            if TOOLKIT_IMPORTS_AVAILABLE:
                status = self._send_via_notification_system(recipients, message, channel_type, security_level)
            else:
                # Fallback to direct channel sending
                status = self._send_via_channel(recipients, message, channel_type)

            result["delivery_status"] = status

            # Log the activity
            self._log_communication_event(
                event_type="message_sent",
                description=f"Message sent via {channel_type.value}",
                recipients=recipients,
                message_id=message_id,
                priority=priority.value,
                security_level=security_level.value
            )

            return result

        except Exception as e:
            self.logger.error(f"Failed to send message: {e}")
            result["status"] = "failed"
            result["error"] = str(e)
            raise ChannelError(f"Failed to send message: {e}")

    def create_secure_room(
        self,
        name: str,
        members: List[str],
        description: Optional[str] = None,
        expires_in: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Create a secure communication room for team collaboration.

        Args:
            name: Room name
            members: Initial room members
            description: Room description
            expires_in: Room lifetime in seconds

        Returns:
            Dict containing room details

        Raises:
            ChannelError: If room creation fails
        """
        room_id = f"room-{secrets.token_hex(4)}"

        # Set expiry if provided
        expires_at = None
        if expires_in:
            expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=expires_in)
            expires_at = expiry_time.isoformat()

        # Generate access token
        access_token = generate_secure_token() if CORE_SECURITY_AVAILABLE else secrets.token_urlsafe(32)

        room_data = {
            "room_id": room_id,
            "name": name,
            "description": description,
            "created_at": datetime.datetime.now().isoformat(),
            "expires_at": expires_at,
            "members": members,
            "access_token": access_token,
            "created_by": getpass.getuser()
        }

        # Store room configuration
        rooms_dir = self.key_dir / "rooms"
        rooms_dir.mkdir(mode=DIR_PERMISSIONS, exist_ok=True)

        room_file = rooms_dir / f"{room_id}.json"
        with open(room_file, "w") as f:
            json.dump(room_data, f, indent=2)

        os.chmod(room_file, KEY_FILE_PERMISSIONS)

        # Log room creation
        self._log_communication_event(
            event_type="room_created",
            description=f"Secure room '{name}' created",
            room_id=room_id,
            members=members
        )

        # Notify members if possible
        try:
            notification = (
                f"You have been added to secure communication room: {name}\n"
                f"Room ID: {room_id}\n"
            )

            self.send_message(
                recipients=members,
                content=notification,
                priority=MessagePriority.HIGH,
                security_level=SecurityLevel.HIGH,
                metadata={"room_id": room_id}
            )
        except Exception as e:
            self.logger.warning(f"Failed to notify members about room creation: {e}")

        return {
            "room_id": room_id,
            "name": name,
            "access_token": access_token,
            "created_at": room_data["created_at"],
            "expires_at": expires_at,
            "members": members
        }

    def encrypt_file(
        self,
        file_path: str,
        recipients: Optional[List[str]] = None,
        output_path: Optional[str] = None,
        delete_original: bool = False
    ) -> Dict[str, Any]:
        """
        Encrypt a file for secure sharing.

        Args:
            file_path: Path to file for encryption
            recipients: List of recipients who can decrypt
            output_path: Path for encrypted output (default: add .enc)
            delete_original: Whether to delete the original file

        Returns:
            Dict with encryption details

        Raises:
            EncryptionError: If encryption fails
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise EncryptionError(f"File not found: {file_path}")

            # Generate output path if not specified
            if not output_path:
                output_path = f"{file_path}.enc"

            # Use core encryption if available
            if CORE_SECURITY_AVAILABLE:
                with open(file_path, "rb") as f:
                    content = f.read()

                # Encrypt file content
                encrypted_data = encrypt_sensitive_data(content.decode('latin1'))

                with open(output_path, "w") as f:
                    f.write(encrypted_data)

                # Set secure permissions
                os.chmod(output_path, KEY_FILE_PERMISSIONS)

            else:
                # Fallback to OpenSSL if available
                self.logger.warning("Using OpenSSL for encryption as core security is unavailable")
                key = self._derive_encryption_key()
                key_hex = key.hex()

                # Save temporary key file
                temp_key_file = self.key_dir / f"temp_key_{secrets.token_hex(4)}"
                with open(temp_key_file, "w") as f:
                    f.write(key_hex)
                os.chmod(temp_key_file, KEY_FILE_PERMISSIONS)

                try:
                    # Use OpenSSL for encryption
                    import subprocess
                    cmd = [
                        "openssl", "enc", "-aes-256-cbc", "-salt",
                        "-in", str(file_path),
                        "-out", output_path,
                        "-pass", f"file:{temp_key_file}"
                    ]

                    result = subprocess.run(cmd, check=True, capture_output=True)

                    # Store key for recipients
                    if recipients:
                        self._store_file_key(Path(output_path), key_hex, recipients)

                finally:
                    # Always remove temp key file
                    if temp_key_file.exists():
                        os.unlink(temp_key_file)

            # Calculate hash of encrypted file
            file_hash = self._calculate_file_hash(output_path)

            # Delete original if requested
            if delete_original:
                os.unlink(file_path)

            # Log the encryption
            self._log_communication_event(
                event_type="file_encrypted",
                description=f"File encrypted: {file_path.name}",
                file_path=str(file_path),
                output_path=output_path,
                recipients=recipients or []
            )

            return {
                "original_file": str(file_path),
                "encrypted_file": output_path,
                "hash": file_hash,
                "timestamp": datetime.datetime.now().isoformat(),
                "recipients": recipients or []
            }

        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt file: {e}")

    def decrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        delete_encrypted: bool = False
    ) -> Dict[str, Any]:
        """
        Decrypt a previously encrypted file.

        Args:
            file_path: Path to encrypted file
            output_path: Path for decrypted output
            delete_encrypted: Whether to delete the encrypted file

        Returns:
            Dict with decryption details

        Raises:
            EncryptionError: If decryption fails
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise EncryptionError(f"Encrypted file not found: {file_path}")

            # Generate output path if not specified
            if not output_path:
                if str(file_path).endswith(".enc"):
                    output_path = str(file_path)[:-4]
                else:
                    output_path = f"{file_path}.dec"

            # Use core decryption if available
            if CORE_SECURITY_AVAILABLE:
                with open(file_path, "r") as f:
                    encrypted_data = f.read()

                # Decrypt file content
                decrypted_data = decrypt_sensitive_data(encrypted_data)

                with open(output_path, "wb") as f:
                    f.write(decrypted_data.encode('latin1'))

            else:
                # Check if we have stored key for this file
                key = self._retrieve_file_key(file_path)

                if not key:
                    raise EncryptionError("Decryption key not found for file")

                # Save temporary key file
                temp_key_file = self.key_dir / f"temp_key_{secrets.token_hex(4)}"
                with open(temp_key_file, "w") as f:
                    f.write(key)
                os.chmod(temp_key_file, KEY_FILE_PERMISSIONS)

                try:
                    # Use OpenSSL for decryption
                    import subprocess
                    cmd = [
                        "openssl", "enc", "-d", "-aes-256-cbc",
                        "-in", str(file_path),
                        "-out", output_path,
                        "-pass", f"file:{temp_key_file}"
                    ]

                    result = subprocess.run(cmd, check=True, capture_output=True)
                finally:
                    # Always remove temp key file
                    if temp_key_file.exists():
                        os.unlink(temp_key_file)

            # Calculate hash of decrypted file
            file_hash = self._calculate_file_hash(output_path)

            # Delete encrypted file if requested
            if delete_encrypted:
                os.unlink(file_path)

            # Log the decryption
            self._log_communication_event(
                event_type="file_decrypted",
                description=f"File decrypted: {file_path.name}",
                file_path=str(file_path),
                output_path=output_path
            )

            return {
                "encrypted_file": str(file_path),
                "decrypted_file": output_path,
                "hash": file_hash,
                "timestamp": datetime.datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt file: {e}")

    def test_channels(self) -> Dict[str, Dict[str, Any]]:
        """
        Test all configured communication channels.

        Returns:
            Dict mapping channel types to test results
        """
        results = {}

        for channel_type, channel_config in self.channels.items():
            if not channel_config.get("enabled", True):
                results[channel_type] = {"status": "skipped", "reason": "Channel disabled"}
                continue

            try:
                self.logger.info(f"Testing channel: {channel_type}")
                # Test message content
                test_message = (
                    f"This is an automated test message from the incident response toolkit. "
                    f"Timestamp: {datetime.datetime.now().isoformat()}"
                )

                # Test recipients from config or use fallback
                test_recipients = channel_config.get("config", {}).get("test_recipients", ["test@example.com"])

                # Create test message but don't actually send
                message = SecureMessage(
                    content=test_message,
                    sender=getpass.getuser(),
                    priority=MessagePriority.LOW
                )

                # Run connection test
                connection_ok = self._test_channel_connection(
                    channel_type=ChannelType(channel_type),
                    config=channel_config["config"]
                )

                if connection_ok:
                    results[channel_type] = {
                        "status": "success",
                        "timestamp": datetime.datetime.now().isoformat()
                    }

                    # Update channel status
                    self.channels[channel_type]["last_tested"] = datetime.datetime.now().isoformat()
                    self.channels[channel_type]["test_result"] = True

                else:
                    results[channel_type] = {
                        "status": "failure",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "reason": "Connection test failed"
                    }

                    # Update channel status
                    self.channels[channel_type]["last_tested"] = datetime.datetime.now().isoformat()
                    self.channels[channel_type]["test_result"] = False

            except Exception as e:
                self.logger.error(f"Channel test failed for {channel_type}: {e}")
                results[channel_type] = {
                    "status": "error",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "error": str(e)
                }

                # Update channel status
                self.channels[channel_type]["last_tested"] = datetime.datetime.now().isoformat()
                self.channels[channel_type]["test_result"] = False

        return results

    def _setup_logging(self, log_level: int) -> logging.Logger:
        """Setup module logging."""
        logger = logging.getLogger("secure_comms")
        logger.setLevel(log_level)

        # Reset handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Add file handler if incident ID is provided
        if self.incident_id:
            log_dir = Path(MODULE_PATH) / "logs"
            log_dir.mkdir(mode=DIR_PERMISSIONS, exist_ok=True)

            incident_id_safe = sanitize_incident_id(self.incident_id)
            log_file = log_dir / f"comms_{incident_id_safe}.log"

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

            # Set secure permissions on log file
            os.chmod(log_file, LOG_FILE_PERMISSIONS)

        return logger

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        config = {}

        # First load built-in defaults
        try:
            config_path = Path(self.config_path)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)
                self.logger.debug(f"Loaded configuration from {config_path}")
        except Exception as e:
            self.logger.warning(f"Unable to load configuration: {e}")

        # Then merge with toolkit config
        if CONFIG_AVAILABLE:
            comm_config = response_config.get("secure_communications", {})
            config = {**config, **comm_config}

        return config

    def _setup_key_dir(self) -> None:
        """Setup the key directory."""
        try:
            # Create key directory if it doesn't exist
            self.key_dir.mkdir(parents=True, exist_ok=True)

            # Set secure permissions
            os.chmod(self.key_dir, DIR_PERMISSIONS)

            # Create necessary subdirectories
            (self.key_dir / "rooms").mkdir(mode=DIR_PERMISSIONS, exist_ok=True)
            (self.key_dir / "files").mkdir(mode=DIR_PERMISSIONS, exist_ok=True)

            # Create master key if it doesn't exist
            master_key_path = self.key_dir / "master.key"
            if not master_key_path.exists():
                with open(master_key_path, "w") as f:
                    # Generate random key
                    key = secrets.token_hex(32)
                    f.write(key)

                # Set secure permissions
                os.chmod(master_key_path, KEY_FILE_PERMISSIONS)

        except Exception as e:
            self.logger.error(f"Failed to setup key directory: {e}")
            raise ChannelError(f"Key directory setup failed: {e}")

    def _get_required_keys(self, channel_type: ChannelType) -> List[str]:
        """Get required configuration keys for a channel type."""
        common_keys = ["name", "enabled"]

        channel_specific = {
            ChannelType.EMAIL: ["smtp_server", "smtp_port", "username", "password", "from_address"],
            ChannelType.CHAT: ["api_url", "token"],
            ChannelType.MESSAGING: ["service_type", "credentials"],
            ChannelType.API: ["endpoint", "auth_token", "content_type"],
            ChannelType.WEBHOOK: ["url", "secret"],
            ChannelType.ENCRYPTED_FILE: ["output_dir"],
            ChannelType.CUSTOM: ["handler_module", "handler_class"]
        }

        return common_keys + channel_specific.get(channel_type, [])

    def _select_channel(
        self,
        security_level: SecurityLevel,
        priority: MessagePriority
    ) -> ChannelType:
        """Select appropriate communication channel based on parameters."""
        # Default channel preferences based on security level and priority
        preferences = {
            SecurityLevel.CRITICAL: [ChannelType.ENCRYPTED_FILE, ChannelType.CHAT, ChannelType.EMAIL],
            SecurityLevel.HIGH: [ChannelType.CHAT, ChannelType.EMAIL, ChannelType.MESSAGING],
            SecurityLevel.MEDIUM: [ChannelType.EMAIL, ChannelType.MESSAGING, ChannelType.CHAT],
            SecurityLevel.LOW: [ChannelType.EMAIL, ChannelType.WEBHOOK, ChannelType.API]
        }

        # Get preferences for this security level
        channel_preferences = preferences.get(security_level, [ChannelType.EMAIL])

        # Adjust for urgent priority
        if priority == MessagePriority.URGENT:
            if ChannelType.MESSAGING.value in self.channels:
                return ChannelType.MESSAGING

        # Check if preferred channels are available
        for channel in channel_preferences:
            if channel.value in self.channels and self.channels[channel.value].get("enabled", True):
                return channel

        # Fallback to any available channel
        for channel_type, channel_config in self.channels.items():
            if channel_config.get("enabled", True):
                return ChannelType(channel_type)

        # No channels available
        raise ChannelError("No communication channels available")

    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from master key."""
        try:
            # Read master key
            master_key_path = self.key_dir / "master.key"
            if not master_key_path.exists():
                raise EncryptionError("Master key not found")

            with open(master_key_path, "r") as f:
                master_key = f.read().strip()

            # Derive key with incident-specific salt if available
            salt = b'secure_comms_salt'
            if self.incident_id:
                salt = f"incident:{self.incident_id}".encode()

            # Use PBKDF2 to derive a key
            dk = hashlib.pbkdf2_hmac(
                'sha256',
                master_key.encode(),
                salt,
                iterations=100000
            )

            return dk

        except Exception as e:
            self.logger.error(f"Failed to derive encryption key: {e}")
            raise EncryptionError(f"Key derivation failed: {e}")

    def _encrypt_content(self, content: str, key: bytes) -> str:
        """Basic encryption implementation for fallback."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import os

            # Generate a random 16-byte IV
            iv = os.urandom(16)

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv),
                backend=default_backend()
            )

            encryptor = cipher.encryptor()

            # Encrypt data
            data = content.encode('utf-8')
            ciphertext = encryptor.update(data) + encryptor.finalize()

            # Combine IV and ciphertext
            result = iv + ciphertext

            # Return as hex
            return result.hex()

        except ImportError:
            self.logger.error("Required cryptography module not available")
            raise EncryptionError("Required encryption libraries not available")
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise EncryptionError(f"Content encryption failed: {e}")

    def _decrypt_content(self, encrypted: str, key: bytes) -> str:
        """Basic decryption implementation for fallback."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend

            # Convert from hex to binary
            data = bytes.fromhex(encrypted)

            # Extract IV (first 16 bytes)
            iv = data[:16]
            ciphertext = data[16:]

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv),
                backend=default_backend()
            )

            decryptor = cipher.decryptor()

            # Decrypt data
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            # Return as string
            return decrypted.decode('utf-8')

        except ImportError:
            self.logger.error("Required cryptography module not available")
            raise EncryptionError("Required decryption libraries not available")
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            raise EncryptionError(f"Content decryption failed: {e}")

    def _get_signing_key(self) -> str:
        """Get key for message signing."""
        if CORE_SECURITY_AVAILABLE:
            # Use secure random token
            return generate_secure_token()

        # Fallback to master key
        try:
            master_key_path = self.key_dir / "master.key"
            if master_key_path.exists():
                with open(master_key_path, "r") as f:
                    return f.read().strip()
        except Exception:
            pass

        # Last resort
        return secrets.token_hex(32)

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        try:
            hash_obj = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read in chunks for large files
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
            return ""

    def _store_file_key(self, file_path: Path, key: str, recipients: List[str]) -> None:
        """Store encryption key for a file."""
        file_keys_dir = self.key_dir / "files"
        file_hash = self._calculate_file_hash(str(file_path))

        key_data = {
            "file_path": str(file_path),
            "file_hash": file_hash,
            "encryption_key": key,
            "recipients": recipients,
            "created_at": datetime.datetime.now().isoformat(),
            "created_by": getpass.getuser()
        }

        # Store key data
        key_file = file_keys_dir / f"{file_path.name}.key"
        with open(key_file, "w") as f:
            json.dump(key_data, f, indent=2)

        # Set secure permissions
        os.chmod(key_file, KEY_FILE_PERMISSIONS)

    def _retrieve_file_key(self, file_path: Path) -> Optional[str]:
        """Retrieve encryption key for a file."""
        file_keys_dir = self.key_dir / "files"
        key_file = file_keys_dir / f"{file_path.name}.key"

        try:
            if key_file.exists():
                with open(key_file, "r") as f:
                    key_data = json.load(f)

                # Verify file path or hash
                file_hash = self._calculate_file_hash(str(file_path))
                if (key_data.get("file_path") == str(file_path) or
                    key_data.get("file_hash") == file_hash):
                    return key_data.get("encryption_key")
        except Exception as e:
            self.logger.error(f"Failed to retrieve file key: {e}")

        return None

    def _send_via_notification_system(
        self,
        recipients: List[str],
        message: SecureMessage,
        channel_type: ChannelType,
        security_level: SecurityLevel
    ) -> Dict[str, Any]:
        """Send message using the toolkit notification system."""
        if not TOOLKIT_IMPORTS_AVAILABLE:
            raise ChannelError("Notification system not available")

        # Convert message to appropriate format
        subject = f"IR Communication: {message.priority.value.capitalize()}"

        # Add security classification if high or critical
        if security_level in (SecurityLevel.HIGH, SecurityLevel.CRITICAL):
            subject = f"[{security_level.value.upper()}] {subject}"

        # Use the notification system
        try:
            result = notify_stakeholders(
                recipients=recipients,
                subject=subject,
                message=message.content,
                priority=message.priority.value,
                sender=message.sender,
                method=channel_type.value,
                incident_id=self.incident_id,
                metadata=message.metadata
            )

            return {
                "status": "sent",
                "timestamp": datetime.datetime.now().isoformat(),
                "details": result
            }
        except Exception as e:
            self.logger.error(f"Failed to send via notification system: {e}")
            raise ChannelError(f"Notification system error: {e}")

    def _send_via_channel(
        self,
        recipients: List[str],
        message: SecureMessage,
        channel_type: ChannelType
    ) -> Dict[str, Any]:
        """Send message directly through the specified channel."""
        if channel_type.value not in self.channels:
            raise ChannelError(f"Channel {channel_type.value} not configured")

        channel_config = self.channels[channel_type.value]["config"]

        # Implement channel-specific sending methods
        if channel_type == ChannelType.EMAIL:
            return self._send_email(recipients, message, channel_config)
        elif channel_type == ChannelType.ENCRYPTED_FILE:
            return self._send_encrypted_file(recipients, message, channel_config)
        elif channel_type == ChannelType.CHAT:
            return self._send_chat(recipients, message, channel_config)
        elif channel_type == ChannelType.WEBHOOK:
            return self._send_webhook(recipients, message, channel_config)
        else:
            raise ChannelError(f"Sending via {channel_type.value} not implemented")

    def _send_email(
        self,
        recipients: List[str],
        message: SecureMessage,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send message via email."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            # Create email
            email = MIMEMultipart()
            email["From"] = config.get("from_address")
            email["To"] = ", ".join(recipients)

            # Set subject based on priority
            subject = f"IR Communication: {message.priority.value.capitalize()}"
            if message.metadata.get("incident_id"):
                subject = f"{subject} - Incident {message.metadata['incident_id']}"
            email["Subject"] = subject

            # Add message body
            email.attach(MIMEText(message.content))

            # Connect to SMTP server
            smtp_server = config.get("smtp_server")
            smtp_port = int(config.get("smtp_port", 25))
            use_ssl = config.get("use_ssl", False)

            if use_ssl:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port)

                # Start TLS if required
                if config.get("use_tls", False):
                    server.starttls()

            # Login if credentials provided
            username = config.get("username")
            password = config.get("password")
            if username and password:
                server.login(username, password)

            # Send email
            server.send_message(email)
            server.quit()

            return {
                "status": "sent",
                "timestamp": datetime.datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
            raise ChannelError(f"Email sending failed: {e}")

    def _send_chat(
        self,
        recipients: List[str],
        message: SecureMessage,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send message via chat platform."""
        try:
            import requests

            api_url = config.get("api_url")
            token = config.get("token")

            # Format message for chat platform
            payload = {
                "text": message.content,
                "recipients": recipients,
                "sender": message.sender,
                "message_id": message.message_id
            }

            # Add channel/room if specified
            if config.get("channel"):
                payload["channel"] = config["channel"]

            # Add priority indicator
            if message.priority in (MessagePriority.HIGH, MessagePriority.URGENT):
                payload["text"] = f"[{message.priority.value.upper()}] {payload['text']}"

            # Send message
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            response = requests.post(
                api_url,
                headers=headers,
                json=payload
            )

            response.raise_for_status()

            return {
                "status": "sent",
                "timestamp": datetime.datetime.now().isoformat(),
                "platform_response": response.json()
            }

        except Exception as e:
            self.logger.error(f"Failed to send chat message: {e}")
            raise ChannelError(f"Chat message sending failed: {e}")

    def _send_encrypted_file(
        self,
        recipients: List[str],
        message: SecureMessage,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Save message as encrypted file."""
        try:
            # Create output directory if it doesn't exist
            output_dir = Path(config.get("output_dir", self.key_dir / "messages"))
            output_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(output_dir, DIR_PERMISSIONS)

            # Generate filename based on timestamp and message ID
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{message.message_id}.enc"
            output_path = output_dir / filename

            # Convert message to JSON
            message_data = message.to_dict()
            message_data["recipients"] = recipients

            # Encrypt message data
            key = self._derive_encryption_key()
            message_json = json.dumps(message_data)
            encrypted_content = self._encrypt_content(message_json, key)

            # Write to file
            with open(output_path, "w") as f:
                f.write(encrypted_content)

            # Set secure permissions
            os.chmod(output_path, KEY_FILE_PERMISSIONS)

            # Store key for recipients
            self._store_file_key(output_path, key.hex(), recipients)

            return {
                "status": "saved",
                "timestamp": datetime.datetime.now().isoformat(),
                "file_path": str(output_path)
            }

        except Exception as e:
            self.logger.error(f"Failed to save encrypted message file: {e}")
            raise ChannelError(f"Encrypted file saving failed: {e}")

    def _send_webhook(
        self,
        recipients: List[str],
        message: SecureMessage,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send message via webhook."""
        try:
            import requests

            url = config.get("url")
            secret = config.get("secret")

            # Format message for webhook
            payload = {
                "message": message.content,
                "sender": message.sender,
                "message_id": message.message_id,
                "timestamp": message.timestamp,
                "priority": message.priority.value,
                "recipients": recipients
            }

            # Add incident ID if available
            if self.incident_id:
                payload["incident_id"] = self.incident_id

            # Add custom data from config
            if config.get("custom_data"):
                payload["custom_data"] = config["custom_data"]

            # Add signature if secret is available
            if secret:
                payload_str = json.dumps(payload, sort_keys=True)
                signature = hmac.new(
                    secret.encode(),
                    payload_str.encode(),
                    digestmod=hashlib.sha256
                ).hexdigest()

                headers = {
                    "Content-Type": "application/json",
                    "X-Signature": signature
                }
            else:
                headers = {
                    "Content-Type": "application/json"
                }

            # Send webhook request
            response = requests.post(
                url,
                headers=headers,
                json=payload
            )

            response.raise_for_status()

            return {
                "status": "sent",
                "timestamp": datetime.datetime.now().isoformat(),
                "webhook_response": response.status_code
            }

        except Exception as e:
            self.logger.error(f"Failed to send webhook: {e}")
            raise ChannelError(f"Webhook sending failed: {e}")

    def _test_channel_connection(self, channel_type: ChannelType, config: Dict[str, Any]) -> bool:
        """Test connection to a communication channel."""
        try:
            if channel_type == ChannelType.EMAIL:
                import smtplib

                smtp_server = config.get("smtp_server")
                smtp_port = int(config.get("smtp_port", 25))
                use_ssl = config.get("use_ssl", False)

                if use_ssl:
                    server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
                else:
                    server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)

                    # Start TLS if required
                    if config.get("use_tls", False):
                        server.starttls()

                # Test authentication if credentials provided
                username = config.get("username")
                password = config.get("password")
                if username and password:
                    server.login(username, password)

                server.quit()
                return True

            elif channel_type == ChannelType.CHAT or channel_type == ChannelType.WEBHOOK:
                import requests

                url = config.get("api_url") or config.get("url")
                if not url:
                    return False

                # Make a simple request to validate the URL exists
                response = requests.head(url, timeout=10)
                return response.status_code < 500  # Any response below 500 is considered success

            elif channel_type == ChannelType.ENCRYPTED_FILE:
                # Check if output directory exists and is writable
                output_dir = Path(config.get("output_dir", self.key_dir / "messages"))
                output_dir.mkdir(parents=True, exist_ok=True)

                # Try to write a test file
                test_file = output_dir / f"test_{secrets.token_hex(4)}.txt"
                test_file.write_text("Test file for encrypted file channel")
                test_file.unlink()

                return True

            # Default to success for other channels
            return True

        except Exception as e:
            self.logger.error(f"Channel connection test failed: {e}")
            return False

    def _log_communication_event(self, event_type: str, description: str, **details) -> None:
        """Log a communication event."""
        try:
            # Log to audit system if available
            if CORE_SECURITY_AVAILABLE:
                log_security_event(
                    event_type=f"comm_{event_type}",
                    description=description,
                    severity="info",
                    details={
                        "incident_id": self.incident_id,
                        **details
                    }
                )

            # Log to local logger
            self.logger.info(f"{description} ({event_type})")

        except Exception as e:
            self.logger.warning(f"Failed to log communication event: {e}")


def main() -> int:
    """
    Main function for command-line execution.

    Returns:
        int: Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(
        description="Secure Communications for Incident Response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Setup a secure communication channel:
    %(prog)s --setup-channel email --config smtp_server=mail.example.com,smtp_port=587,username=ir@example.com,password=secret

  Send a secure message:
    %(prog)s --send --recipients user@example.com --message "Security incident detected" --priority high

  Create a secure communication room:
    %(prog)s --create-room "IR Team" --members "user1@example.com,user2@example.com" --description "Incident response coordination"

  Encrypt a sensitive file:
    %(prog)s --encrypt-file sensitive_data.txt --recipients "user@example.com"

  Decrypt a protected file:
    %(prog)s --decrypt-file sensitive_data.txt.enc

  Test all configured communication channels:
    %(prog)s --test-channels
"""
    )

    # Common parameters
    parser.add_argument("--incident-id", help="Incident ID to associate with communications")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--key-dir", help="Directory for encryption keys")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    # Action groups
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--setup-channel", choices=[c.value for c in ChannelType],
                             help="Set up a communication channel")
    action_group.add_argument("--send", action="store_true", help="Send a secure message")
    action_group.add_argument("--create-room", metavar="NAME", help="Create a secure communication room")
    action_group.add_argument("--encrypt-file", metavar="FILE", help="Encrypt a file for secure sharing")
    action_group.add_argument("--decrypt-file", metavar="FILE", help="Decrypt a previously encrypted file")
    action_group.add_argument("--test-channels", action="store_true", help="Test all configured communication channels")

    # Channel setup parameters
    parser.add_argument("--channel-config", help="Channel configuration as key=value pairs")

    # Message parameters
    parser.add_argument("--recipients", help="Comma-separated list of message recipients")
    parser.add_argument("--message", help="Message content")
    parser.add_argument("--priority", choices=[p.value for p in MessagePriority],
                       default=MessagePriority.MEDIUM.value, help="Message priority")
    parser.add_argument("--channel", choices=[c.value for c in ChannelType],
                       help="Specific channel to use (auto-select if not specified)")
    parser.add_argument("--security-level", choices=[s.value for s in SecurityLevel],
                       default=SecurityLevel.MEDIUM.value, help="Security level for the message")
    parser.add_argument("--expires-in", type=int, help="Message expiry in seconds")

    # Room parameters
    parser.add_argument("--members", help="Comma-separated list of room members")
    parser.add_argument("--description", help="Room description")

    # File parameters
    parser.add_argument("--output", help="Output path for encrypted/decrypted file")
    parser.add_argument("--delete-original", action="store_true", help="Delete original file after operation")

    # Parse arguments
    args = parser.parse_args()

    # Set up logging level
    log_level = logging.DEBUG if args.verbose else logging.INFO

    try:
        # Create secure comms manager
        comms = SecureComms(
            incident_id=args.incident_id,
            config_path=args.config,
            key_dir=args.key_dir,
            log_level=log_level
        )

        # Handle actions
        if args.setup_channel:
            # Parse channel configuration
            if not args.channel_config:
                parser.error("--channel-config is required with --setup-channel")

            config = {}
            for item in args.channel_config.split(","):
                if "=" in item:
                    key, value = item.split("=", 1)
                    config[key.strip()] = value.strip()

            # Set up channel
            result = comms.setup_channel(args.setup_channel, config)
            if result:
                print(f"Channel {args.setup_channel} configured successfully")

        elif args.send:
            # Validate required parameters
            if not args.recipients:
                parser.error("--recipients is required with --send")
            if not args.message:
                parser.error("--message is required with --send")

            # Send message
            recipients = [r.strip() for r in args.recipients.split(",")]
            result = comms.send_message(
                recipients=recipients,
                content=args.message,
                priority=args.priority,
                channel_type=args.channel,
                security_level=args.security_level,
                expires_in=args.expires_in
            )

            print(f"Message sent with ID: {result['message_id']}")

        elif args.create_room:
            # Validate required parameters
            if not args.members:
                parser.error("--members is required with --create-room")

            # Create room
            members = [m.strip() for m in args.members.split(",")]
            result = comms.create_secure_room(
                name=args.create_room,
                members=members,
                description=args.description,
                expires_in=args.expires_in
            )

            print(f"Secure room created:")
            print(f"  Room ID: {result['room_id']}")
            print(f"  Access Token: {result['access_token']}")

        elif args.encrypt_file:
            # Get recipients if specified
            recipients = None
            if args.recipients:
                recipients = [r.strip() for r in args.recipients.split(",")]

            # Encrypt file
            result = comms.encrypt_file(
                file_path=args.encrypt_file,
                recipients=recipients,
                output_path=args.output,
                delete_original=args.delete_original
            )

            print(f"File encrypted successfully:")
            print(f"  Output: {result['encrypted_file']}")
            print(f"  SHA-256: {result['hash']}")

        elif args.decrypt_file:
            # Decrypt file
            result = comms.decrypt_file(
                file_path=args.decrypt_file,
                output_path=args.output,
                delete_encrypted=args.delete_original
            )

            print(f"File decrypted successfully:")
            print(f"  Output: {result['decrypted_file']}")
            print(f"  SHA-256: {result['hash']}")

        elif args.test_channels:
            # Test channels
            results = comms.test_channels()

            print("Channel Test Results:")
            for channel, result in results.items():
                status = result["status"].upper()
                timestamp = datetime.datetime.fromisoformat(result["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                details = ""

                if status == "FAILURE" or status == "ERROR":
                    details = f" - {result.get('reason') or result.get('error') or 'Unknown error'}"

                print(f"  {channel}: {status} ({timestamp}){details}")

        return 0

    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


# Module exports
__all__ = [
    # Classes
    'SecureComms',
    'SecureMessage',
    'ChannelType',
    'MessagePriority',
    'SecurityLevel',

    # Exceptions
    'CommunicationError',
    'ChannelError',
    'EncryptionError',
    'AuthenticationError',
    'ValidationError',
]


if __name__ == "__main__":
    sys.exit(main())
