"""
Network Utilities for the Forensic Analysis Toolkit.

This module provides network-related utility functions useful during forensic
investigations. This includes IP address validation, DNS resolution, reverse
lookups, and potentially parsing network-related artifacts (though complex
parsing like PCAP analysis might reside in dedicated tools).

Functions aim to provide reliable network information retrieval while integrating
with forensic logging.
"""

import socket
import ipaddress
import logging
import re
import subprocess
from typing import List, Optional, Tuple, Union, Dict, Any

# Attempt to import forensic-specific logging and constants
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger.")
    # Fallback logging function
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None):
        level = logging.INFO if success else logging.ERROR
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

logger = logging.getLogger(__name__)

# Regex for MAC address validation (common formats)
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

# --- IP Address and DNS Functions ---

def is_valid_ip(ip_string: str) -> bool:
    """Checks if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def is_valid_mac(mac_string: str) -> bool:
    """Checks if a string is a valid MAC address (common formats)."""
    return MAC_REGEX.match(mac_string) is not None

def resolve_hostname(hostname: str) -> List[str]:
    """Resolves a hostname to a list of IP addresses (IPv4 and IPv6)."""
    ips: List[str] = []
    operation_details = {"hostname": hostname}
    try:
        # getaddrinfo returns a list of tuples: (family, type, proto, canonname, sockaddr)
        # sockaddr is (ip, port) for IPv4 and (ip, port, flowinfo, scopeid) for IPv6
        results = socket.getaddrinfo(hostname, None)
        ips = list(set(info[4][0] for info in results)) # Extract unique IPs
        log_forensic_operation("resolve_hostname", True, {**operation_details, "resolved_ips": ips})
        return ips
    except socket.gaierror as e:
        logger.warning("Failed to resolve hostname %s: %s", hostname, e)
        log_forensic_operation("resolve_hostname", False, {**operation_details, "error": str(e)})
        return []
    except Exception as e:
        logger.error("Unexpected error resolving hostname %s: %s", hostname, e)
        log_forensic_operation("resolve_hostname", False, {**operation_details, "error": str(e)})
        return []

def reverse_dns_lookup(ip_address: str) -> Optional[str]:
    """Performs a reverse DNS lookup for a given IP address."""
    operation_details = {"ip_address": ip_address}
    if not is_valid_ip(ip_address):
        logger.warning("Invalid IP address provided for reverse lookup: %s", ip_address)
        log_forensic_operation("reverse_dns_lookup", False, {**operation_details, "error": "Invalid IP format"})
        return None
    try:
        # gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        log_forensic_operation("reverse_dns_lookup", True, {**operation_details, "resolved_hostname": hostname})
        return hostname
    except socket.herror as e:
        logger.warning("Reverse DNS lookup failed for %s: %s", ip_address, e)
        log_forensic_operation("reverse_dns_lookup", False, {**operation_details, "error": str(e)})
        return None
    except Exception as e:
        logger.error("Unexpected error during reverse DNS lookup for %s: %s", ip_address, e)
        log_forensic_operation("reverse_dns_lookup", False, {**operation_details, "error": str(e)})
        return None

def get_local_ip_addresses(include_loopback: bool = False) -> List[str]:
    """Retrieves local IP addresses (IPv4) of the machine."""
    local_ips: List[str] = []
    try:
        # Get all address info for the local hostname
        hostname = socket.gethostname()
        addr_info = socket.getaddrinfo(hostname, None)

        for info in addr_info:
            family, _, _, _, sockaddr = info
            if family == socket.AF_INET: # Filter for IPv4
                ip = sockaddr[0]
                if ipaddress.ip_address(ip).is_loopback and not include_loopback:
                    continue
                if ip not in local_ips:
                    local_ips.append(ip)

        # Fallback if hostname resolution doesn't yield useful IPs
        if not local_ips or (len(local_ips) == 1 and ipaddress.ip_address(local_ips[0]).is_loopback and not include_loopback):
            # Try connecting to an external host to determine the primary outbound IP
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(0.1) # Avoid long waits
                    s.connect(("8.8.8.8", 80)) # Connect to Google DNS (doesn't send data)
                    ip = s.getsockname()[0]
                    if ip not in local_ips and (not ipaddress.ip_address(ip).is_loopback or include_loopback):
                         local_ips.append(ip)
            except Exception:
                 pass # Ignore errors in fallback

        log_forensic_operation("get_local_ips", True, {"local_ips": local_ips})
        return local_ips

    except Exception as e:
        logger.error("Failed to retrieve local IP addresses: %s", e)
        log_forensic_operation("get_local_ips", False, {"error": str(e)})
        return []


# --- Example Usage ---

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    print("--- Network Utilities Examples ---")

    # IP Validation
    print("\n--- IP Validation ---")
    valid_ipv4 = "192.168.1.1"
    valid_ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    invalid_ip = "not.an.ip"
    print(f"Is '{valid_ipv4}' valid IP? {is_valid_ip(valid_ipv4)}")
    print(f"Is '{valid_ipv6}' valid IP? {is_valid_ip(valid_ipv6)}")
    print(f"Is '{invalid_ip}' valid IP? {is_valid_ip(invalid_ip)}")

    # MAC Validation
    print("\n--- MAC Validation ---")
    valid_mac1 = "00:1A:2B:3C:4D:5E"
    valid_mac2 = "00-1a-2b-3c-4d-5e"
    invalid_mac = "00:1A:2B:3C:4D"
    print(f"Is '{valid_mac1}' valid MAC? {is_valid_mac(valid_mac1)}")
    print(f"Is '{valid_mac2}' valid MAC? {is_valid_mac(valid_mac2)}")
    print(f"Is '{invalid_mac}' valid MAC? {is_valid_mac(invalid_mac)}")

    # Hostname Resolution
    print("\n--- Hostname Resolution ---")
    hostname_to_resolve = "www.google.com"
    resolved_ips = resolve_hostname(hostname_to_resolve)
    if resolved_ips:
        print(f"IPs for '{hostname_to_resolve}': {resolved_ips}")
    else:
        print(f"Could not resolve '{hostname_to_resolve}'")

    hostname_fail = "invalid-domain-that-does-not-exist-kjhgf.com"
    resolve_hostname(hostname_fail) # Should log a warning

    # Reverse DNS Lookup
    print("\n--- Reverse DNS Lookup ---")
    ip_to_lookup = "8.8.8.8" # Google Public DNS
    resolved_hostname = reverse_dns_lookup(ip_to_lookup)
    if resolved_hostname:
        print(f"Hostname for '{ip_to_lookup}': {resolved_hostname}")
    else:
        print(f"Could not perform reverse lookup for '{ip_to_lookup}'")

    ip_fail = "192.0.2.1" # Test IP, likely no reverse record
    reverse_dns_lookup(ip_fail) # Should log a warning

    # Get Local IPs
    print("\n--- Get Local IPs ---")
    local_addresses = get_local_ip_addresses(include_loopback=True)
    print(f"Local IP Addresses (incl. loopback): {local_addresses}")
    local_addresses_no_loop = get_local_ip_addresses(include_loopback=False)
    print(f"Local IP Addresses (excl. loopback): {local_addresses_no_loop}")

    print("\n--- Network Utilities Examples Complete ---")
