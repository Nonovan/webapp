#!/usr/bin/env python3
# filepath: /admin/security/incident_response_kit/network_isolation.py
"""
Network Isolation Module for the Incident Response Toolkit

This module provides capabilities to isolate systems during incident response,
implementing various isolation strategies including firewall rules, network
interface configuration, and cloud provider security group modifications.

The module follows defense-in-depth principles and maintains detailed logs
of all isolation actions for chain of custody and recovery purposes.
"""

import os
import sys
import logging
import json
import subprocess
import time
import ipaddress
from typing import Dict, List, Optional, Union, Any, Tuple, Set
from pathlib import Path
from datetime import datetime, timedelta

# Setup module logging
logger = logging.getLogger(__name__)

# Define isolation methods
ISOLATION_METHOD_FIREWALL = "firewall"
ISOLATION_METHOD_INTERFACE = "interface"
ISOLATION_METHOD_ACL = "acl"
ISOLATION_METHOD_VLAN = "vlan"
ISOLATION_METHOD_CLOUD = "cloud"
ISOLATION_METHOD_SDN = "sdn"

# Define isolation levels
ISOLATION_LEVEL_NONE = "none"  # No isolation (monitoring only)
ISOLATION_LEVEL_MONITORING = "monitoring"  # Allow all but monitor
ISOLATION_LEVEL_PARTIAL = "partial"  # Block most, allow specific
ISOLATION_LEVEL_FORENSIC = "forensic"  # Block all except forensic access
ISOLATION_LEVEL_FULL = "full"  # Block all communications

# Import incident response toolkit constants if available
try:
    from . import (
        DEFAULT_EVIDENCE_DIR,
        DEFAULT_LOG_DIR,
        DEFAULT_TEMP_DIR,
        IsolationError,
        NOTIFICATION_ENABLED
    )
except ImportError:
    logger.warning("Could not import incident response constants, using defaults")
    DEFAULT_EVIDENCE_DIR = "/secure/evidence"
    DEFAULT_LOG_DIR = "/var/log"
    DEFAULT_TEMP_DIR = "/tmp/ir-toolkit"
    NOTIFICATION_ENABLED = False

    # Define exception class if not available from main package
    class IsolationError(Exception):
        """Error during system isolation"""
        pass

# Load configuration if available
ISOLATION_CONFIG_PATH = Path(os.path.dirname(os.path.abspath(__file__))) / "config" / "isolation_config.json"
try:
    if ISOLATION_CONFIG_PATH.exists():
        with open(ISOLATION_CONFIG_PATH, "r") as f:
            ISOLATION_CONFIG = json.load(f)
        logger.debug("Loaded isolation configuration")
    else:
        logger.warning(f"Isolation config not found at {ISOLATION_CONFIG_PATH}, using defaults")
        ISOLATION_CONFIG = {
            "default_method": ISOLATION_METHOD_FIREWALL,
            "default_level": ISOLATION_LEVEL_FORENSIC,
            "quarantine_vlan": 999,
            "forensic_vlan": 998,
            "default_duration": "24h",
            "always_allow_ips": ["10.0.0.10"]  # IR team management IP
        }
except Exception as e:
    logger.error(f"Error loading isolation config: {e}")
    ISOLATION_CONFIG = {
        "default_method": ISOLATION_METHOD_FIREWALL,
        "default_level": ISOLATION_LEVEL_FORENSIC,
        "quarantine_vlan": 999,
        "forensic_vlan": 998,
        "default_duration": "24h",
        "always_allow_ips": []
    }

# Try importing forensics network utilities if available
try:
    from admin.security.forensics.utils.network_utils import (
        normalize_ip_address,
        is_internal_ip,
        get_default_gateway
    )
    FORENSIC_NETWORK_UTILS_AVAILABLE = True
except ImportError:
    logger.debug("Forensics network utilities not available, using internal functions")
    FORENSIC_NETWORK_UTILS_AVAILABLE = False

    # Simple internal implementations of required functions
    def normalize_ip_address(ip: str) -> str:
        """Normalize an IP address to its canonical form."""
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return ip

    def is_internal_ip(ip: str) -> bool:
        """Check if an IP address is in private IP ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    def get_default_gateway() -> Optional[str]:
        """Get the default gateway IP address."""
        try:
            if sys.platform == "linux" or sys.platform == "linux2":
                output = subprocess.check_output("ip route | grep default", shell=True).decode()
                return output.split()[2]
            elif sys.platform == "darwin":
                output = subprocess.check_output("route -n get default | grep gateway", shell=True).decode()
                return output.split(":")[1].strip()
            else:
                return None
        except Exception:
            return None

# Isolation tracking state
_isolated_systems = {}
_isolation_logs = []

def parse_duration(duration_str: str) -> int:
    """
    Parse a duration string into seconds.

    Args:
        duration_str: Duration string (e.g., "1h", "30m", "1d", "60s")

    Returns:
        Duration in seconds
    """
    units = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400
    }

    if not duration_str:
        return 0

    # Check if it's already a numeric value
    if duration_str.isdigit():
        return int(duration_str)

    value = ""
    for char in duration_str:
        if char.isdigit() or char == '.':
            value += char
        else:
            unit = char.lower()
            break
    else:
        # No unit specified, assume seconds
        return int(value) if value.isdigit() else 0

    if not value or unit not in units:
        raise ValueError(f"Invalid duration format: {duration_str}")

    return int(float(value) * units[unit])

def log_isolation_action(target: str, action: str, method: str, level: str,
                         success: bool, details: Optional[Dict] = None) -> None:
    """
    Log an isolation action for audit purposes.

    Args:
        target: The target system being isolated
        action: The action taken (isolate, update, remove)
        method: The isolation method used
        level: The isolation level applied
        success: Whether the action was successful
        details: Additional details about the action
    """
    timestamp = datetime.utcnow().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "target": target,
        "action": action,
        "method": method,
        "level": level,
        "success": success
    }

    if details:
        log_entry["details"] = details

    _isolation_logs.append(log_entry)

    # Log to file if possible
    log_dir = Path(DEFAULT_LOG_DIR) / "incident_response"
    try:
        os.makedirs(log_dir, exist_ok=True)
        log_file = log_dir / "network_isolation.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        logger.warning(f"Failed to write isolation log to file: {e}")

    # Log to system logger
    log_msg = f"Network isolation: {action} {target} using {method} at {level} level"
    if success:
        logger.info(log_msg)
    else:
        logger.error(f"{log_msg} - FAILED")
        if details and "error" in details:
            logger.error(f"Error details: {details['error']}")

def get_isolation_method(method: Optional[str] = None) -> str:
    """
    Get the isolation method to use, applying defaults if necessary.

    Args:
        method: Requested isolation method or None for default

    Returns:
        Isolation method to use
    """
    if method:
        return method

    return ISOLATION_CONFIG.get("default_method", ISOLATION_METHOD_FIREWALL)

def get_isolation_level(level: Optional[str] = None) -> str:
    """
    Get the isolation level to use, applying defaults if necessary.

    Args:
        level: Requested isolation level or None for default

    Returns:
        Isolation level to use
    """
    if level:
        return level

    return ISOLATION_CONFIG.get("default_level", ISOLATION_LEVEL_FORENSIC)

def get_allowed_ips(allow_ips: Optional[List[str]] = None) -> List[str]:
    """
    Get the combined list of allowed IPs, including configured always-allowed IPs.

    Args:
        allow_ips: Additional IPs to allow

    Returns:
        Combined list of allowed IPs
    """
    default_allowed = ISOLATION_CONFIG.get("always_allow_ips", [])

    if not allow_ips:
        return default_allowed

    # Normalize IPs and combine lists
    combined = set(default_allowed)
    for ip in allow_ips:
        combined.add(normalize_ip_address(ip))

    return list(combined)

def _execute_iptables_isolation(target: str, allow_ips: List[str], level: str) -> Tuple[bool, str]:
    """
    Implement network isolation using iptables rules.

    Args:
        target: Target system to isolate
        allow_ips: IPs that should be allowed to communicate
        level: Isolation level

    Returns:
        Tuple of (success, message)
    """
    try:
        # Build iptables command to isolate the system
        # These commands would typically be executed on the target system
        # but we're just preparing them here as an example

        # Rules would be applied via SSH or agent on the target system
        commands = [
            # Flush the input chain to start fresh
            "iptables -F INPUT",
            # Allow loopback traffic
            "iptables -A INPUT -i lo -j ACCEPT",
            # Allow established connections
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        ]

        # Add rules for allowed IPs
        for ip in allow_ips:
            commands.append(f"iptables -A INPUT -s {ip} -j ACCEPT")

        # Add final default deny rule
        commands.append("iptables -P INPUT DROP")

        # If level is full, also block outbound traffic
        if level == ISOLATION_LEVEL_FULL:
            commands.extend([
                "iptables -F OUTPUT",
                # Allow loopback traffic for OUTPUT too
                "iptables -A OUTPUT -o lo -j ACCEPT",
                # Allow established connections
                "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                # Final default deny rule for OUTPUT
                "iptables -P OUTPUT DROP"
            ])

        # In a real implementation, these commands would be executed on the target
        # via SSH or an agent system

        # For example purposes, we'll just log what would be executed
        logger.info(f"Would execute on {target}:")
        for cmd in commands:
            logger.info(f"  {cmd}")

        # This would be replaced with actual command execution
        return True, "Isolation rules applied successfully"

    except Exception as e:
        return False, f"Failed to apply iptables isolation: {str(e)}"

def _execute_interface_isolation(target: str, level: str) -> Tuple[bool, str]:
    """
    Implement network isolation by configuring network interfaces.

    Args:
        target: Target system to isolate
        level: Isolation level

    Returns:
        Tuple of (success, message)
    """
    try:
        # Example implementation - in reality, this would execute commands
        # on the target system to modify interface configurations

        commands = []

        if level == ISOLATION_LEVEL_FULL:
            # Full isolation: bring down all non-loopback interfaces
            commands.append("for i in $(ip link show | grep -v lo: | grep -oE '^[0-9]+: [a-z0-9]+' | awk '{print $2}'); do ip link set $i down; done")
        elif level == ISOLATION_LEVEL_FORENSIC:
            # Forensic isolation: restrict interfaces to forensic VLAN
            vlan_id = ISOLATION_CONFIG.get("forensic_vlan", 998)
            commands.append(f"for i in $(ip link show | grep -v lo: | grep -oE '^[0-9]+: [a-z0-9]+' | awk '{print $2}'); do ip link set $i down; ip link add link $i name $i.{vlan_id} type vlan id {vlan_id}; ip link set $i up; ip link set $i.{vlan_id} up; done")
        else:
            # Partial isolation: remove default gateway
            commands.append("ip route del default")

        # In a real implementation, these commands would be executed on the target
        # For example purposes, we'll just log what would be executed
        logger.info(f"Would execute interface isolation on {target}:")
        for cmd in commands:
            logger.info(f"  {cmd}")

        return True, "Interface isolation applied successfully"

    except Exception as e:
        return False, f"Failed to apply interface isolation: {str(e)}"

def _execute_cloud_isolation(target: str, allow_ips: List[str], provider: str = "auto") -> Tuple[bool, str]:
    """
    Implement network isolation using cloud provider security groups.

    Args:
        target: Target system to isolate (instance ID)
        allow_ips: IPs that should be allowed to communicate
        provider: Cloud provider (aws, azure, gcp, or auto)

    Returns:
        Tuple of (success, message)
    """
    try:
        # Example implementation for cloud isolation
        # In reality, this would use the cloud provider's API

        if provider == "auto":
            # Try to detect the cloud provider
            # This is just a placeholder - real detection logic would be needed
            provider = "aws"

        commands = []

        if provider == "aws":
            # AWS implementation using security groups
            commands.extend([
                f"# Create isolation security group",
                f"aws ec2 create-security-group --group-name ir-isolation-{target} --description 'Incident Response Isolation'",
                f"# Remove instance from all security groups and add to isolation group",
                f"aws ec2 modify-instance-attribute --instance-id {target} --groups ir-isolation-{target}"
            ])

            # Add rules for allowed IPs
            for ip in allow_ips:
                commands.append(f"aws ec2 authorize-security-group-ingress --group-name ir-isolation-{target} --protocol tcp --port 22 --cidr {ip}/32")

        elif provider == "azure":
            # Azure implementation using NSGs
            commands.extend([
                f"# Create isolation NSG",
                f"az network nsg create -g ResourceGroupName -n ir-isolation-{target}",
                f"# Allow specific IPs",
                f"for ip in {' '.join(allow_ips)}; do az network nsg rule create -g ResourceGroupName --nsg-name ir-isolation-{target} --name allow-ssh --priority 100 --source-address-prefixes $ip --destination-port-ranges 22; done",
                f"# Apply NSG to NIC",
                f"az network nic update -g ResourceGroupName -n <NIC_NAME> --network-security-group ir-isolation-{target}"
            ])

        elif provider == "gcp":
            # GCP implementation using firewall rules
            commands.extend([
                f"# Create isolation firewall rule",
                f"gcloud compute firewall-rules create ir-isolation-{target} --target-tags=ir-isolation --action=deny --direction=INGRESS --rules=all",
                f"# Add exceptions for allowed IPs",
                f"for ip in {' '.join(allow_ips)}; do gcloud compute firewall-rules create ir-isolation-allow-$ip --target-tags=ir-isolation --action=allow --direction=INGRESS --rules=tcp:22 --source-ranges=$ip/32; done",
                f"# Apply tag to instance",
                f"gcloud compute instances add-tags {target} --tags ir-isolation"
            ])

        else:
            return False, f"Unsupported cloud provider: {provider}"

        # In a real implementation, these commands would be executed
        # For example purposes, we'll just log what would be executed
        logger.info(f"Would execute cloud isolation on {target} ({provider}):")
        for cmd in commands:
            logger.info(f"  {cmd}")

        return True, "Cloud isolation applied successfully"

    except Exception as e:
        return False, f"Failed to apply cloud isolation: {str(e)}"

def isolate_system(
    target: str,
    method: Optional[str] = None,
    level: Optional[str] = None,
    allow_ip: Optional[Union[str, List[str]]] = None,
    duration: Optional[str] = None,
    incident_id: Optional[str] = None,
    cloud_provider: Optional[str] = "auto",
    description: Optional[str] = None,
    update: bool = False,
    force: bool = False
) -> Dict[str, Any]:
    """
    Isolate a system from the network while maintaining specified access.

    Args:
        target: Target system to isolate (hostname, IP, or instance ID)
        method: Isolation method (firewall, interface, acl, vlan, cloud, sdn)
        level: Isolation level (none, monitoring, partial, forensic, full)
        allow_ip: IP address(es) that should still have access
        duration: Duration of isolation (e.g. "1h", "1d", "30m")
        incident_id: Associated incident ID
        cloud_provider: Cloud provider if using cloud method
        description: Description of why isolation was performed
        update: Whether to update an existing isolation
        force: Force isolation even if already isolated

    Returns:
        Dictionary with isolation status and details

    Raises:
        IsolationError: If isolation fails
    """
    # Normalize inputs
    target = normalize_ip_address(target) if target and '.' in target else target
    method = get_isolation_method(method)
    level = get_isolation_level(level)

    # Convert single IP to list
    if allow_ip and isinstance(allow_ip, str):
        allow_ip = [allow_ip]

    # Get all allowed IPs including defaults
    allowed_ips = get_allowed_ips(allow_ip)

    # Parse duration
    duration_seconds = 0
    if duration:
        try:
            duration_seconds = parse_duration(duration)
        except ValueError as e:
            raise IsolationError(f"Invalid duration format: {str(e)}")
    else:
        # Use default duration
        default_duration = ISOLATION_CONFIG.get("default_duration", "24h")
        duration_seconds = parse_duration(default_duration)

    # Check if system is already isolated
    if target in _isolated_systems and not update and not force:
        return {
            "success": False,
            "message": f"System {target} is already isolated. Use update=True to modify isolation.",
            "details": _isolated_systems[target]
        }

    # Execute isolation based on method
    success = False
    message = ""
    details = {}

    try:
        if method == ISOLATION_METHOD_FIREWALL:
            success, message = _execute_iptables_isolation(target, allowed_ips, level)
        elif method == ISOLATION_METHOD_INTERFACE:
            success, message = _execute_interface_isolation(target, level)
        elif method == ISOLATION_METHOD_CLOUD:
            success, message = _execute_cloud_isolation(target, allowed_ips, cloud_provider)
        elif method == ISOLATION_METHOD_ACL:
            # Example - would be implemented with appropriate network device access
            success, message = False, "ACL isolation not implemented in this version"
        elif method == ISOLATION_METHOD_VLAN:
            # Example - would be implemented with appropriate network device access
            success, message = False, "VLAN isolation not implemented in this version"
        elif method == ISOLATION_METHOD_SDN:
            # Example - would be implemented with appropriate SDN controller access
            success, message = False, "SDN isolation not implemented in this version"
        else:
            success, message = False, f"Unknown isolation method: {method}"

    except Exception as e:
        success = False
        message = f"Isolation failed: {str(e)}"

    # Prepare result details
    details = {
        "target": target,
        "method": method,
        "level": level,
        "allowed_ips": allowed_ips,
        "start_time": datetime.utcnow().isoformat(),
        "duration_seconds": duration_seconds,
        "expiry_time": (datetime.utcnow() + timedelta(seconds=duration_seconds)).isoformat(),
        "incident_id": incident_id,
        "description": description
    }

    if success:
        # Update isolation tracking state
        _isolated_systems[target] = details

    # Log the action
    action = "update" if update else "isolate"
    log_isolation_action(target, action, method, level, success, {
        "allowed_ips": allowed_ips,
        "duration": f"{duration_seconds}s",
        "incident_id": incident_id,
        "error": None if success else message
    })

    if not success:
        raise IsolationError(message)

    return {
        "success": success,
        "message": message,
        "details": details
    }

def remove_isolation(target: str, incident_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Remove isolation from a system.

    Args:
        target: Target system to remove isolation from
        incident_id: Associated incident ID for logging

    Returns:
        Dictionary with removal status and details
    """
    # Normalize target
    target = normalize_ip_address(target) if target and '.' in target else target

    # Check if system is isolated
    if target not in _isolated_systems:
        return {
            "success": False,
            "message": f"System {target} is not isolated"
        }

    isolation_details = _isolated_systems[target]
    method = isolation_details.get("method")
    level = isolation_details.get("level")

    # Execute isolation removal based on method
    success = False
    message = ""

    try:
        if method == ISOLATION_METHOD_FIREWALL:
            # Restore default accept policies and flush chains
            commands = [
                "iptables -P INPUT ACCEPT",
                "iptables -P OUTPUT ACCEPT",
                "iptables -F INPUT",
                "iptables -F OUTPUT"
            ]
            logger.info(f"Would execute on {target} to remove isolation:")
            for cmd in commands:
                logger.info(f"  {cmd}")
            success = True
            message = "Firewall isolation removed"

        elif method == ISOLATION_METHOD_INTERFACE:
            # Bring interfaces back up or reconfigure them
            commands = []

            if level == ISOLATION_LEVEL_FULL:
                # Bring all interfaces back up
                commands.append("for i in $(ip link show | grep -v lo: | grep -oE '^[0-9]+: [a-z0-9]+' | awk '{print $2}'); do ip link set $i up; done")
            elif level == ISOLATION_LEVEL_FORENSIC:
                # Remove VLAN interfaces and restore original interfaces
                vlan_id = ISOLATION_CONFIG.get("forensic_vlan", 998)
                commands.append(f"for i in $(ip link show | grep -v lo: | grep -oE '^[0-9]+: [a-z0-9]+' | awk '{print $2}'); do if [[ \"$i\" == *\".{vlan_id}\" ]]; then base_if=$(echo $i | cut -d'.' -f1); ip link del $i; ip link set $base_if up; fi; done")
            else:
                # Restore default gateway
                gateway = get_default_gateway()
                if gateway:
                    commands.append(f"ip route add default via {gateway}")

            logger.info(f"Would execute on {target} to remove interface isolation:")
            for cmd in commands:
                logger.info(f"  {cmd}")
            success = True
            message = "Interface isolation removed"

        elif method == ISOLATION_METHOD_CLOUD:
            # Example for AWS - would be replaced with actual API calls
            commands = [
                f"# Get current security groups",
                f"CURRENT_SG=$(aws ec2 describe-instances --instance-ids {target} --query 'Reservations[0].Instances[0].SecurityGroups[*].GroupId' --output text)",
                f"# Remove isolation security group",
                f"aws ec2 delete-security-group --group-name ir-isolation-{target}",
                f"# Restore original security groups",
                f"aws ec2 modify-instance-attribute --instance-id {target} --groups $CURRENT_SG"
            ]
            logger.info(f"Would execute to remove cloud isolation for {target}:")
            for cmd in commands:
                logger.info(f"  {cmd}")
            success = True
            message = "Cloud isolation removed"

        else:
            success = False
            message = f"Removal not implemented for isolation method: {method}"

    except Exception as e:
        success = False
        message = f"Failed to remove isolation: {str(e)}"

    # Log the action
    log_isolation_action(target, "remove", method, level, success, {
        "incident_id": incident_id,
        "error": None if success else message
    })

    if success:
        # Remove from tracking
        _isolated_systems.pop(target, None)

    return {
        "success": success,
        "message": message,
        "original_isolation": isolation_details
    }

def get_isolation_status(target: Optional[str] = None) -> Dict[str, Any]:
    """
    Get the isolation status of systems.

    Args:
        target: Target system to get status for, or None for all systems

    Returns:
        Dictionary with isolation status
    """
    if target:
        # Normalize target
        target = normalize_ip_address(target) if target and '.' in target else target

        if target in _isolated_systems:
            return {
                "isolated": True,
                "details": _isolated_systems[target]
            }
        else:
            return {
                "isolated": False
            }
    else:
        # Return all isolated systems
        return {
            "total_isolated": len(_isolated_systems),
            "systems": _isolated_systems
        }

def check_isolation_expiry():
    """
    Check for and remove expired isolations.

    Returns:
        Number of expired isolations removed
    """
    now = datetime.utcnow()
    expired = []

    for target, details in _isolated_systems.items():
        expiry_time_str = details.get("expiry_time")
        if not expiry_time_str:
            continue

        try:
            expiry_time = datetime.fromisoformat(expiry_time_str)
            if expiry_time < now:
                expired.append(target)
        except ValueError:
            logger.warning(f"Invalid expiry time format for {target}: {expiry_time_str}")

    # Remove expired isolations
    for target in expired:
        logger.info(f"Removing expired isolation for {target}")
        remove_isolation(target, incident_id=details.get("incident_id"))

    return len(expired)

def get_isolation_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Get the isolation action logs.

    Args:
        limit: Maximum number of logs to return

    Returns:
        List of log entries
    """
    # Return most recent logs first
    return sorted(_isolation_logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate a target specification.

    Args:
        target: Target system to validate

    Returns:
        Tuple of (valid, message)
    """
    if not target:
        return False, "Target must be specified"

    # IP address validation
    if '.' in target:
        try:
            ipaddress.ip_address(target)
            return True, "Valid IP address"
        except ValueError:
            pass

    # Hostname validation - basic check
    if target.islower() and '.' in target and target[0].isalpha():
        return True, "Valid hostname format"

    # Instance ID validation (cloud) - different formats depending on provider
    # AWS: i-0123456789abcdef0
    # Azure: vm12345
    # GCP: instance-1
    if target.startswith('i-') or target.startswith('vm') or target.startswith('instance-'):
        return True, "Valid instance ID format"

    return False, "Target format not recognized"

# Module initialization
def _initialize_module():
    """Initialize the network isolation module."""
    logger.info(f"Network isolation module initialized with {len(ISOLATION_CONFIG.get('always_allow_ips', []))} default allowed IPs")

    # Set up hook for checking expired isolations periodically
    # This would normally be done with a scheduler, but for simplicity
    # we'll just note that this should happen
    logger.debug("Expiry checks should be set up to run periodically")

# Run initialization when module is loaded
_initialize_module()

# Module exports
__all__ = [
    # Functions
    'isolate_system',
    'remove_isolation',
    'get_isolation_status',
    'get_isolation_logs',
    'validate_target',
    'check_isolation_expiry',

    # Constants
    'ISOLATION_METHOD_FIREWALL',
    'ISOLATION_METHOD_INTERFACE',
    'ISOLATION_METHOD_ACL',
    'ISOLATION_METHOD_VLAN',
    'ISOLATION_METHOD_CLOUD',
    'ISOLATION_METHOD_SDN',
    'ISOLATION_LEVEL_NONE',
    'ISOLATION_LEVEL_MONITORING',
    'ISOLATION_LEVEL_PARTIAL',
    'ISOLATION_LEVEL_FORENSIC',
    'ISOLATION_LEVEL_FULL'
]
