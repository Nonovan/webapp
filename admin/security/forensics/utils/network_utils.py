"""
Network Utilities for the Forensic Analysis Toolkit.

This module provides network-related utility functions for forensic investigation,
including PCAP file analysis, network identifier extraction and normalization, and
traffic classification. These functions assist investigators in identifying network
indicators and correlating network activity with other forensic artifacts.

Functions are designed to preserve evidence integrity and maintain proper forensic
documentation through detailed logging of all operations.
"""

import ipaddress
import logging
import re
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any, BinaryIO

# Attempt to import forensic-specific logging and constants
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    FORENSIC_LOGGING_AVAILABLE = True
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger.")
    FORENSIC_LOGGING_AVAILABLE = False
    # Fallback logging function
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        msg = f"Forensic operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logging.log(level=level, msg=msg)

# Attempt to import forensic constants
try:
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_NETWORK_TIMEOUT,
        DEFAULT_PACKET_CAPTURE_SIZE
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    logging.warning("Forensic constants not found. Using default values.")
    CONSTANTS_AVAILABLE = False
    DEFAULT_NETWORK_TIMEOUT = 15
    DEFAULT_PACKET_CAPTURE_SIZE = 65535

logger = logging.getLogger(__name__)

# Try to import optional dependencies for PCAP parsing
try:
    import dpkt
    from dpkt.ethernet import Ethernet
    from dpkt.ip import IP
    from dpkt.tcp import TCP
    from dpkt.udp import UDP
    from dpkt.dns import DNS
    from dpkt.http import Request as HTTPRequest
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False
    logger.warning("dpkt package not available. PCAP parsing functionality will be limited.")

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy package not available. Advanced packet analysis will be limited.")

# Regular expressions for network identifiers
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
IPV4_REGEX = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
URL_REGEX = re.compile(r'^(https?|ftp)://[^\s/$.?#].[^\s]*$', re.IGNORECASE)

# IP classification constants
PRIVATE_IP_RANGES = [
    '10.0.0.0/8',        # RFC 1918 private network
    '172.16.0.0/12',     # RFC 1918 private network
    '192.168.0.0/16',    # RFC 1918 private network
    '127.0.0.0/8',       # Localhost
    '169.254.0.0/16',    # Link-local
    '224.0.0.0/4',       # Multicast
    '240.0.0.0/4'        # Reserved
]

# Convert to netmask objects for faster checking
PRIVATE_IP_NETWORKS = [ipaddress.ip_network(cidr) for cidr in PRIVATE_IP_RANGES]

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

def normalize_mac_address(mac: str) -> str:
    """
    Normalize MAC address to consistent format (lowercase, colon-separated).

    Args:
        mac: MAC address string in various formats (e.g., 00:1A:2B:3C:4D:5E or 00-1a-2b-3c-4d-5e)

    Returns:
        Normalized MAC address (e.g., 00:1a:2b:3c:4d:5e)
    """
    if not is_valid_mac(mac):
        raise ValueError(f"Invalid MAC address format: {mac}")

    # Remove separators and convert to lowercase
    mac_clean = mac.lower().replace('-', '').replace(':', '')

    # Format with colons
    return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))

def normalize_ip_address(ip: str) -> str:
    """
    Normalize IP address to standard representation.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        Normalized IP address string
    """
    if not is_valid_ip(ip):
        raise ValueError(f"Invalid IP address: {ip}")

    # Let ipaddress module handle the normalization
    return str(ipaddress.ip_address(ip))

def is_internal_ip(ip: str) -> bool:
    """
    Check if an IP address is internal (private, loopback, link-local, etc.).

    Args:
        ip: IP address to check

    Returns:
        True if the IP is internal/private, False if public
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Check IPv6 special cases
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_link_local or
                ip_obj.is_multicast or
                ip_obj.is_reserved or
                ip_obj.is_site_local
            )

        # For IPv4, check against known private networks
        for network in PRIVATE_IP_NETWORKS:
            if ip_obj in network:
                return True

        return False
    except ValueError:
        logger.warning(f"Invalid IP address for classification: {ip}")
        return False

def resolve_hostname(hostname: str) -> List[str]:
    """
    Resolve hostname to IP addresses with forensic logging.

    Args:
        hostname: Hostname to resolve

    Returns:
        List of resolved IP addresses
    """
    try:
        # Attempt to resolve the hostname
        addresses = socket.getaddrinfo(hostname, None)
        ips = list({addr[4][0] for addr in addresses})

        log_forensic_operation("resolve_hostname", True, {
            "hostname": hostname,
            "resolved_ips": ips
        })
        return ips
    except socket.gaierror as e:
        log_forensic_operation("resolve_hostname", False, {
            "hostname": hostname,
            "error": str(e)
        }, level=logging.WARNING)
        return []

def reverse_dns_lookup(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup with forensic logging.

    Args:
        ip: IP address to lookup

    Returns:
        Hostname if found, None otherwise
    """
    if not is_valid_ip(ip):
        log_forensic_operation("reverse_dns_lookup", False, {
            "ip": ip,
            "error": "Invalid IP address format"
        }, level=logging.WARNING)
        return None

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        log_forensic_operation("reverse_dns_lookup", True, {
            "ip": ip,
            "hostname": hostname
        })
        return hostname
    except (socket.herror, socket.gaierror) as e:
        log_forensic_operation("reverse_dns_lookup", False, {
            "ip": ip,
            "error": str(e)
        }, level=logging.DEBUG)
        return None

def get_local_ip_addresses(include_loopback: bool = False) -> List[str]:
    """
    Retrieves local IP addresses (IPv4) of the machine.

    Args:
        include_loopback: Whether to include loopback addresses (127.0.0.1)

    Returns:
        List of IP addresses
    """
    local_ips: List[str] = []
    try:
        # Get all address info for the local hostname
        hostname = socket.gethostname()
        addr_info = socket.getaddrinfo(hostname, None)

        for info in addr_info:
            family, _, _, _, sockaddr = info
            if family == socket.AF_INET:  # Filter for IPv4
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
                    s.settimeout(0.1)  # Avoid long waits
                    s.connect(("8.8.8.8", 80))  # Connect to Google DNS (doesn't send data)
                    ip = s.getsockname()[0]
                    if ip not in local_ips and (not ipaddress.ip_address(ip).is_loopback or include_loopback):
                         local_ips.append(ip)
            except Exception:
                 pass  # Ignore errors in fallback

        log_forensic_operation("get_local_ips", True, {"local_ips": local_ips})
        return local_ips

    except Exception as e:
        logger.error(f"Failed to retrieve local IP addresses: {e}")
        log_forensic_operation("get_local_ips", False, {"error": str(e)})
        return []

def parse_pcap_file(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Parse a PCAP file and extract packet information in a forensically sound manner.

    Args:
        pcap_path: Path to the PCAP file

    Returns:
        List of packet dictionaries containing metadata
    """
    if not DPKT_AVAILABLE and not SCAPY_AVAILABLE:
        log_forensic_operation("parse_pcap", False, {
            "pcap_path": pcap_path,
            "error": "Neither dpkt nor scapy are available for PCAP parsing"
        }, level=logging.ERROR)
        raise ImportError("PCAP parsing requires either 'dpkt' or 'scapy' package")

    packets = []
    operation_details = {
        "pcap_path": pcap_path,
        "parser": "dpkt" if DPKT_AVAILABLE else "scapy"
    }

    try:
        if DPKT_AVAILABLE:
            with open(pcap_path, 'rb') as f:
                try:
                    pcap_file = dpkt.pcap.Reader(f)
                    for ts, buf in pcap_file:
                        try:
                            packet_info = _parse_packet_dpkt(buf, ts)
                            if packet_info:
                                packets.append(packet_info)
                        except Exception as e:
                            logger.debug(f"Failed to parse individual packet: {e}")
                            continue
                except ValueError as e:
                    # Try pcapng format if regular pcap failed
                    f.seek(0)
                    try:
                        pcap_file = dpkt.pcapng.Reader(f)
                        for ts, buf in pcap_file:
                            try:
                                packet_info = _parse_packet_dpkt(buf, ts)
                                if packet_info:
                                    packets.append(packet_info)
                            except Exception as e:
                                logger.debug(f"Failed to parse individual packet: {e}")
                                continue
                    except Exception as inner_e:
                        raise ValueError(f"Not a valid pcap/pcapng file: {inner_e}")

        elif SCAPY_AVAILABLE:
            # Use scapy as fallback if dpkt isn't available
            operation_details["parser"] = "scapy"
            capture = scapy.rdpcap(pcap_path)

            for i, packet in enumerate(capture):
                try:
                    packet_info = _parse_packet_scapy(packet, i)
                    if packet_info:
                        packets.append(packet_info)
                except Exception as e:
                    logger.debug(f"Failed to parse individual packet with scapy: {e}")
                    continue

        operation_details["packet_count"] = len(packets)
        log_forensic_operation("parse_pcap", True, operation_details)
        return packets

    except Exception as e:
        operation_details["error"] = str(e)
        log_forensic_operation("parse_pcap", False, operation_details, level=logging.ERROR)
        logger.error(f"Failed to parse PCAP file {pcap_path}: {e}")
        return []

def _parse_packet_dpkt(buf: bytes, timestamp: float) -> Optional[Dict[str, Any]]:
    """
    Parse a single packet using dpkt.

    Args:
        buf: Raw packet buffer
        timestamp: Packet timestamp

    Returns:
        Dictionary with packet information or None if parsing failed
    """
    try:
        eth = Ethernet(buf)
        packet_time = datetime.fromtimestamp(timestamp)
        packet_info = {
            'timestamp': packet_time.isoformat(),
            'epoch_time': timestamp,
            'eth_type': eth.type,
            'size': len(buf)
        }

        # Extract MAC addresses if available
        packet_info['src_mac'] = ':'.join(f'{b:02x}' for b in eth.src)
        packet_info['dst_mac'] = ':'.join(f'{b:02x}' for b in eth.dst)

        # Handle IP packets
        if isinstance(eth.data, IP):
            ip = eth.data
            packet_info['proto'] = ip.p
            packet_info['src_ip'] = socket.inet_ntoa(ip.src)
            packet_info['dst_ip'] = socket.inet_ntoa(ip.dst)
            packet_info['ttl'] = ip.ttl

            # TCP Protocol
            if isinstance(ip.data, TCP):
                tcp = ip.data
                packet_info['src_port'] = tcp.sport
                packet_info['dst_port'] = tcp.dport
                packet_info['tcp_flags'] = {
                    'fin': bool(tcp.flags & dpkt.tcp.TH_FIN),
                    'syn': bool(tcp.flags & dpkt.tcp.TH_SYN),
                    'rst': bool(tcp.flags & dpkt.tcp.TH_RST),
                    'psh': bool(tcp.flags & dpkt.tcp.TH_PUSH),
                    'ack': bool(tcp.flags & dpkt.tcp.TH_ACK),
                    'urg': bool(tcp.flags & dpkt.tcp.TH_URG)
                }

                # HTTP Protocol Detection
                try:
                    if tcp.dport == 80 or tcp.sport == 80 or tcp.dport == 8080 or tcp.sport == 8080:
                        if len(tcp.data) > 0:
                            try:
                                http = dpkt.http.Request(tcp.data)
                                packet_info['http'] = {
                                    'method': http.method.decode('utf-8', errors='replace'),
                                    'uri': http.uri.decode('utf-8', errors='replace'),
                                    'version': http.version.decode('utf-8', errors='replace')
                                }

                                if http.method == b'GET' or http.method == b'POST':
                                    for header_name, header_value in http.headers.items():
                                        if header_name.lower() == b'host':
                                            packet_info['http']['host'] = header_value.decode('utf-8', errors='replace')
                                            break
                            except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
                                pass
                except Exception:
                    pass

            # UDP Protocol
            elif isinstance(ip.data, UDP):
                udp = ip.data
                packet_info['src_port'] = udp.sport
                packet_info['dst_port'] = udp.dport

                # DNS Protocol Detection
                try:
                    if udp.sport == 53 or udp.dport == 53:
                        try:
                            dns = DNS(udp.data)
                            packet_info['dns'] = {
                                'id': dns.id,
                                'opcode': dns.opcode,
                                'rcode': dns.rcode,
                                'query_count': len(dns.qd),
                                'answer_count': len(dns.an),
                                'is_response': bool(dns.op & dpkt.dns.DNS_QR)
                            }

                            # Extract DNS queries
                            if dns.qd:
                                packet_info['dns']['queries'] = []
                                for query in dns.qd:
                                    try:
                                        query_name = query.name.decode('utf-8', errors='replace')
                                        packet_info['dns']['queries'].append({
                                            'name': query_name,
                                            'type': query.type
                                        })
                                    except UnicodeDecodeError:
                                        pass
                        except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
                            pass
                except Exception:
                    pass

        return packet_info
    except Exception:
        return None

def _parse_packet_scapy(packet: Any, packet_index: int) -> Optional[Dict[str, Any]]:
    """
    Parse a single packet using scapy.

    Args:
        packet: Scapy packet object
        packet_index: Index of packet in capture

    Returns:
        Dictionary with packet information or None if parsing failed
    """
    try:
        packet_info = {
            'packet_index': packet_index,
            'timestamp': packet.time,
            'size': len(packet)
        }

        # Ethernet layer
        if packet.haslayer('Ether'):
            packet_info['src_mac'] = packet.getlayer('Ether').src
            packet_info['dst_mac'] = packet.getlayer('Ether').dst
            packet_info['eth_type'] = packet.getlayer('Ether').type

        # IP layer
        if packet.haslayer('IP'):
            ip = packet.getlayer('IP')
            packet_info['src_ip'] = ip.src
            packet_info['dst_ip'] = ip.dst
            packet_info['ttl'] = ip.ttl
            packet_info['proto'] = ip.proto

        # IPv6 layer
        elif packet.haslayer('IPv6'):
            ipv6 = packet.getlayer('IPv6')
            packet_info['src_ip'] = ipv6.src
            packet_info['dst_ip'] = ipv6.dst
            packet_info['proto'] = ipv6.nh

        # TCP layer
        if packet.haslayer('TCP'):
            tcp = packet.getlayer('TCP')
            packet_info['src_port'] = tcp.sport
            packet_info['dst_port'] = tcp.dport
            packet_info['tcp_flags'] = {
                'fin': tcp.flags.F,
                'syn': tcp.flags.S,
                'rst': tcp.flags.R,
                'psh': tcp.flags.P,
                'ack': tcp.flags.A,
                'urg': tcp.flags.U
            }

            # HTTP detection
            if tcp.sport == 80 or tcp.dport == 80 or tcp.sport == 8080 or tcp.dport == 8080:
                if packet.haslayer('Raw'):
                    raw_data = packet.getlayer('Raw').load
                    try:
                        if raw_data.startswith(b'GET ') or raw_data.startswith(b'POST '):
                            http_headers = raw_data.decode('utf-8', errors='replace').split('\r\n')
                            if http_headers and ' HTTP/' in http_headers[0]:
                                parts = http_headers[0].split(' ')
                                packet_info['http'] = {
                                    'method': parts[0],
                                    'uri': parts[1],
                                    'version': parts[2]
                                }

                                # Extract host from headers
                                for header in http_headers[1:]:
                                    if header.lower().startswith('host:'):
                                        packet_info['http']['host'] = header[5:].strip()
                                        break
                    except Exception:
                        pass

        # UDP layer
        elif packet.haslayer('UDP'):
            udp = packet.getlayer('UDP')
            packet_info['src_port'] = udp.sport
            packet_info['dst_port'] = udp.dport

            # DNS detection
            if udp.sport == 53 or udp.dport == 53:
                if packet.haslayer('DNS'):
                    dns = packet.getlayer('DNS')
                    packet_info['dns'] = {
                        'id': dns.id,
                        'is_response': dns.qr == 1,
                        'query_count': dns.qdcount,
                        'answer_count': dns.ancount
                    }

                    # Extract queries
                    if dns.qd:
                        packet_info['dns']['queries'] = []
                        for i in range(dns.qdcount):
                            try:
                                qname = dns.qd[i].qname.decode('utf-8', errors='replace')
                                if qname.endswith('.'):
                                    qname = qname[:-1]
                                packet_info['dns']['queries'].append({
                                    'name': qname,
                                    'type': dns.qd[i].qtype
                                })
                            except (IndexError, AttributeError, UnicodeDecodeError):
                                pass

        return packet_info
    except Exception:
        return None

def extract_ips_from_pcap(pcap_path: str, include_private: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract IP addresses from a PCAP file with associated metadata.

    Args:
        pcap_path: Path to the PCAP file
        include_private: Whether to include private/internal IP addresses

    Returns:
        Dictionary of IP addresses (source and destination) with associated packet info
    """
    ip_data = {
        'source_ips': {},
        'destination_ips': {}
    }

    operation_details = {
        'pcap_path': pcap_path,
        'include_private': include_private
    }

    try:
        packets = parse_pcap_file(pcap_path)
        src_ips = {}
        dst_ips = {}

        for packet in packets:
            if 'src_ip' in packet:
                src_ip = packet['src_ip']
                if include_private or not is_internal_ip(src_ip):
                    if src_ip not in src_ips:
                        src_ips[src_ip] = []

                    # Add packet info to the source IP
                    src_ips[src_ip].append({
                        'timestamp': packet.get('timestamp'),
                        'dst_ip': packet.get('dst_ip'),
                        'src_port': packet.get('src_port'),
                        'dst_port': packet.get('dst_port'),
                        'proto': packet.get('proto')
                    })

            if 'dst_ip' in packet:
                dst_ip = packet['dst_ip']
                if include_private or not is_internal_ip(dst_ip):
                    if dst_ip not in dst_ips:
                        dst_ips[dst_ip] = []

                    # Add packet info to the destination IP
                    dst_ips[dst_ip].append({
                        'timestamp': packet.get('timestamp'),
                        'src_ip': packet.get('src_ip'),
                        'src_port': packet.get('src_port'),
                        'dst_port': packet.get('dst_port'),
                        'proto': packet.get('proto')
                    })

        ip_data['source_ips'] = src_ips
        ip_data['destination_ips'] = dst_ips

        operation_details['src_ip_count'] = len(src_ips)
        operation_details['dst_ip_count'] = len(dst_ips)
        log_forensic_operation('extract_ips_from_pcap', True, operation_details)

        return ip_data

    except Exception as e:
        operation_details['error'] = str(e)
        log_forensic_operation('extract_ips_from_pcap', False, operation_details, level=logging.ERROR)
        logger.error(f"Failed to extract IPs from PCAP {pcap_path}: {e}")
        return ip_data

def extract_domains_from_pcap(pcap_path: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract domain names from a PCAP file, focusing on DNS queries and HTTP host headers.

    Args:
        pcap_path: Path to the PCAP file

    Returns:
        Dictionary with domain names and associated packet information
    """
    domains = {}
    operation_details = {'pcap_path': pcap_path}

    try:
        packets = parse_pcap_file(pcap_path)

        for packet in packets:
            # Extract domains from DNS queries
            if 'dns' in packet and 'queries' in packet['dns']:
                for query in packet['dns']['queries']:
                    domain = query.get('name', '').lower()
                    if domain and _is_valid_domain(domain):
                        if domain not in domains:
                            domains[domain] = []

                        domains[domain].append({
                            'timestamp': packet.get('timestamp'),
                            'src_ip': packet.get('src_ip'),
                            'dst_ip': packet.get('dst_ip'),
                            'query_type': query.get('type'),
                            'source': 'dns_query'
                        })

            # Extract domains from HTTP host headers
            if 'http' in packet and 'host' in packet['http']:
                domain = packet['http']['host'].lower()
                if domain and _is_valid_domain(domain):
                    if domain not in domains:
                        domains[domain] = []

                    domains[domain].append({
                        'timestamp': packet.get('timestamp'),
                        'src_ip': packet.get('src_ip'),
                        'dst_ip': packet.get('dst_ip'),
                        'http_method': packet['http'].get('method'),
                        'uri': packet['http'].get('uri'),
                        'source': 'http_host'
                    })

        operation_details['domain_count'] = len(domains)
        log_forensic_operation('extract_domains_from_pcap', True, operation_details)
        return domains

    except Exception as e:
        operation_details['error'] = str(e)
        log_forensic_operation('extract_domains_from_pcap', False, operation_details, level=logging.ERROR)
        logger.error(f"Failed to extract domains from PCAP {pcap_path}: {e}")
        return domains

def _is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    return DOMAIN_REGEX.match(domain) is not None

def classify_network_traffic(pcap_path: str) -> Dict[str, Any]:
    """
    Analyze and classify network traffic by protocol, port, and communication patterns.

    Args:
        pcap_path: Path to the PCAP file

    Returns:
        Classification results including protocol distribution, top talkers,
        external connections, and potential suspicious patterns
    """
    classification = {
        'protocol_distribution': {},
        'port_distribution': {
            'tcp': {},
            'udp': {}
        },
        'top_talkers': {},
        'external_connections': [],
        'suspicious_patterns': []
    }
    operation_details = {'pcap_path': pcap_path}

    try:
        packets = parse_pcap_file(pcap_path)
        ip_connections = {}  # For tracking unique connections

        for packet in packets:
            # Protocol distribution
            proto = packet.get('proto')
            if proto:
                proto_name = _get_protocol_name(proto)
                if proto_name not in classification['protocol_distribution']:
                    classification['protocol_distribution'][proto_name] = 0
                classification['protocol_distribution'][proto_name] += 1

            # Port distribution
            if 'src_port' in packet and 'dst_port' in packet:
                if proto == 6:  # TCP
                    tcp_port = packet['dst_port']
                    if tcp_port not in classification['port_distribution']['tcp']:
                        classification['port_distribution']['tcp'][tcp_port] = 0
                    classification['port_distribution']['tcp'][tcp_port] += 1
                elif proto == 17:  # UDP
                    udp_port = packet['dst_port']
                    if udp_port not in classification['port_distribution']['udp']:
                        classification['port_distribution']['udp'][udp_port] = 0
                    classification['port_distribution']['udp'][udp_port] += 1

            # Track unique connections and top talkers
            if 'src_ip' in packet and 'dst_ip' in packet:
                src_ip = packet['src_ip']
                dst_ip = packet['dst_ip']

                # Top talkers count
                if src_ip not in classification['top_talkers']:
                    classification['top_talkers'][src_ip] = {'packets_sent': 0, 'packets_received': 0}
                if dst_ip not in classification['top_talkers']:
                    classification['top_talkers'][dst_ip] = {'packets_sent': 0, 'packets_received': 0}

                classification['top_talkers'][src_ip]['packets_sent'] += 1
                classification['top_talkers'][dst_ip]['packets_received'] += 1

                # Track external connections
                if not is_internal_ip(dst_ip) and is_internal_ip(src_ip):
                    conn_key = f"{src_ip}:{packet.get('src_port', 0)}-{dst_ip}:{packet.get('dst_port', 0)}"
                    if conn_key not in ip_connections:
                        classification['external_connections'].append({
                            'internal_ip': src_ip,
                            'internal_port': packet.get('src_port'),
                            'external_ip': dst_ip,
                            'external_port': packet.get('dst_port'),
                            'protocol': proto_name,
                            'first_seen': packet.get('timestamp')
                        })
                        ip_connections[conn_key] = True

            # Check for suspicious patterns
            _check_suspicious_patterns(packet, classification['suspicious_patterns'])

        # Sort top talkers by total packets
        top_talkers_list = []
        for ip, counts in classification['top_talkers'].items():
            total = counts['packets_sent'] + counts['packets_received']
            top_talkers_list.append({
                'ip': ip,
                'packets_sent': counts['packets_sent'],
                'packets_received': counts['packets_received'],
                'total_packets': total
            })

        # Sort by total packets, descending
        top_talkers_list.sort(key=lambda x: x['total_packets'], reverse=True)
        classification['top_talkers'] = top_talkers_list[:10]  # Keep top 10

        operation_details['packet_count'] = len(packets)
        operation_details['connection_count'] = len(classification['external_connections'])
        operation_details['suspicious_count'] = len(classification['suspicious_patterns'])
        log_forensic_operation('classify_network_traffic', True, operation_details)

        return classification

    except Exception as e:
        operation_details['error'] = str(e)
        log_forensic_operation('classify_network_traffic', False, operation_details, level=logging.ERROR)
        logger.error(f"Failed to classify network traffic in PCAP {pcap_path}: {e}")
        return classification

def _get_protocol_name(proto_num: int) -> str:
    """Convert protocol number to protocol name."""
    protocols = {
        1: 'icmp',
        6: 'tcp',
        17: 'udp',
        47: 'gre',
        50: 'esp',
        51: 'ah',
        58: 'icmpv6',
        132: 'sctp'
    }
    return protocols.get(proto_num, f'proto_{proto_num}')

def _check_suspicious_patterns(packet: Dict[str, Any], suspicious_patterns: List[Dict[str, Any]]):
    """Check packet for suspicious network patterns."""
    # Check for uncommon ports that might indicate tunneling or C&C
    suspicious_ports = [22, 23, 1080, 4444, 5555, 8080, 31337]

    try:
        # Check for DNS tunneling indicators
        if 'dns' in packet and 'queries' in packet['dns']:
            for query in packet['dns']['queries']:
                domain = query.get('name', '')
                # Check for unusually long domain names which could indicate DNS tunneling
                if len(domain) > 50:
                    suspicious_patterns.append({
                        'type': 'possible_dns_tunneling',
                        'evidence': f"Unusually long DNS query: {domain}",
                        'timestamp': packet.get('timestamp'),
                        'src_ip': packet.get('src_ip'),
                        'dst_ip': packet.get('dst_ip')
                    })

        # Check for connections to unusual ports
        if 'dst_port' in packet and packet['dst_port'] in suspicious_ports:
            # Add context about what makes this port suspicious
            port_context = {
                22: "SSH (potential remote access)",
                23: "Telnet (insecure remote access)",
                1080: "SOCKS proxy (potential traffic tunneling)",
                4444: "Known backdoor/metasploit default port",
                5555: "Common reverse shell port",
                8080: "Alternative HTTP (potential proxy)",
                31337: "Elite backdoor/historical hacker port"
            }

            suspicious_patterns.append({
                'type': 'suspicious_port',
                'evidence': f"Connection to suspicious port {packet['dst_port']} ({port_context.get(packet['dst_port'], 'unknown reason')})",
                'timestamp': packet.get('timestamp'),
                'src_ip': packet.get('src_ip'),
                'dst_ip': packet.get('dst_ip'),
                'dst_port': packet['dst_port']
            })

        # Check for HTTP traffic with suspicious user agents or request patterns
        if 'http' in packet:
            # Check for unusual HTTP methods
            if packet['http'].get('method') not in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']:
                suspicious_patterns.append({
                    'type': 'unusual_http_method',
                    'evidence': f"Unusual HTTP method: {packet['http'].get('method')}",
                    'timestamp': packet.get('timestamp'),
                    'src_ip': packet.get('src_ip'),
                    'dst_ip': packet.get('dst_ip'),
                    'uri': packet['http'].get('uri')
                })

            # Check for potential command injection in URLs
            uri = packet['http'].get('uri', '')
            if any(cmd in uri.lower() for cmd in [';', '|', '&&', '`', 'cmd=', 'exec=', 'system(']):
                suspicious_patterns.append({
                    'type': 'potential_command_injection',
                    'evidence': f"Potential command injection in HTTP request: {uri}",
                    'timestamp': packet.get('timestamp'),
                    'src_ip': packet.get('src_ip'),
                    'dst_ip': packet.get('dst_ip'),
                    'uri': uri
                })

    except Exception as e:
        logger.debug(f"Error checking suspicious patterns: {e}")

def extract_http_requests(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Extract HTTP requests from PCAP file.

    Args:
        pcap_path: Path to the PCAP file

    Returns:
        List of HTTP requests with metadata
    """
    http_requests = []
    operation_details = {'pcap_path': pcap_path}

    try:
        packets = parse_pcap_file(pcap_path)

        for packet in packets:
            if 'http' not in packet:
                continue

            http_info = {
                'timestamp': packet.get('timestamp'),
                'src_ip': packet.get('src_ip'),
                'dst_ip': packet.get('dst_ip'),
                'src_port': packet.get('src_port'),
                'dst_port': packet.get('dst_port'),
                'method': packet['http'].get('method'),
                'uri': packet['http'].get('uri'),
                'version': packet['http'].get('version')
            }

            # Add host if available
            if 'host' in packet['http']:
                http_info['host'] = packet['http']['host']
                # Create full URL if possible
                if http_info['uri'].startswith('/'):
                    http_info['url'] = f"http://{packet['http']['host']}{http_info['uri']}"
                else:
                    http_info['url'] = f"http://{packet['http']['host']}/{http_info['uri']}"

            # Add headers if available
            if 'headers' in packet['http']:
                http_info['headers'] = packet['http']['headers']

            http_requests.append(http_info)

        operation_details['request_count'] = len(http_requests)
        log_forensic_operation('extract_http_requests', True, operation_details)
        return http_requests

    except Exception as e:
        operation_details['error'] = str(e)
        log_forensic_operation('extract_http_requests', False, operation_details, level=logging.ERROR)
        logger.error(f"Failed to extract HTTP requests from PCAP {pcap_path}: {e}")
        return http_requests

def reassemble_tcp_stream(pcap_path: str, src_ip: str, src_port: int,
                         dst_ip: str, dst_port: int) -> bytes:
    """
    Reassemble a TCP stream from a PCAP file.

    Args:
        pcap_path: Path to the PCAP file
        src_ip: Source IP address
        src_port: Source port
        dst_ip: Destination IP address
        dst_port: Destination port

    Returns:
        Reassembled stream data as bytes
    """
    operation_details = {
        'pcap_path': pcap_path,
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port
    }

    if not DPKT_AVAILABLE and not SCAPY_AVAILABLE:
        log_forensic_operation('reassemble_tcp_stream', False, {
            **operation_details,
            'error': 'Neither dpkt nor scapy are available for stream reassembly'
        }, level=logging.ERROR)
        raise ImportError("TCP stream reassembly requires either 'dpkt' or 'scapy' package")

    try:
        # Implement using dpkt if available (more efficient)
        if DPKT_AVAILABLE:
            # Track TCP sequences
            segments = {}
            stream_data = b''
            initial_sequence = None
            next_expected_seq = None

            with open(pcap_path, 'rb') as f:
                try:
                    pcap_reader = None
                    try:
                        pcap_reader = dpkt.pcap.Reader(f)
                    except ValueError:
                        # Try pcapng format if regular pcap failed
                        f.seek(0)
                        pcap_reader = dpkt.pcapng.Reader(f)

                    for ts, buf in pcap_reader:
                        try:
                            eth = dpkt.ethernet.Ethernet(buf)
                            if not isinstance(eth.data, dpkt.ip.IP):
                                continue

                            ip = eth.data
                            if not isinstance(ip.data, dpkt.tcp.TCP):
                                continue

                            tcp = ip.data

                            # Check if this packet belongs to our stream
                            packet_src_ip = socket.inet_ntoa(ip.src)
                            packet_dst_ip = socket.inet_ntoa(ip.dst)

                            stream_match = (
                                (packet_src_ip == src_ip and tcp.sport == src_port and
                                 packet_dst_ip == dst_ip and tcp.dport == dst_port) or
                                (packet_src_ip == dst_ip and tcp.sport == dst_port and
                                 packet_dst_ip == src_ip and tcp.dport == src_port)
                            )

                            if not stream_match:
                                continue

                            # Process the TCP segment
                            if len(tcp.data) > 0:
                                if initial_sequence is None:
                                    initial_sequence = tcp.seq
                                    next_expected_seq = initial_sequence + len(tcp.data)
                                    stream_data = tcp.data
                                else:
                                    segments[tcp.seq] = tcp.data

                        except Exception as e:
                            logger.debug(f"Error processing packet in stream reassembly: {e}")
                            continue

                    # Reassemble segments in order
                    if segments:
                        sorted_segments = sorted(segments.keys())
                        for seq in sorted_segments:
                            if seq == next_expected_seq:
                                stream_data += segments[seq]
                                next_expected_seq += len(segments[seq])
                            elif seq > next_expected_seq:
                                # Handle gap in sequence
                                stream_data += b'[GAP IN SEQUENCE]' + segments[seq]
                                next_expected_seq = seq + len(segments[seq])

                except Exception as e:
                    operation_details['error'] = f"Error reading PCAP: {str(e)}"
                    log_forensic_operation('reassemble_tcp_stream', False, operation_details, level=logging.ERROR)
                    return b''

            operation_details['stream_size'] = len(stream_data)
            log_forensic_operation('reassemble_tcp_stream', True, operation_details)
            return stream_data

        # Fallback to scapy if dpkt not available
        elif SCAPY_AVAILABLE:
            capture = scapy.rdpcap(pcap_path)
            stream_packets = []

            # Filter packets belonging to the specified stream
            for packet in capture:
                if packet.haslayer('IP') and packet.haslayer('TCP'):
                    ip = packet.getlayer('IP')
                    tcp = packet.getlayer('TCP')

                    # Check if packet belongs to our stream in either direction
                    if ((ip.src == src_ip and tcp.sport == src_port and
                         ip.dst == dst_ip and tcp.dport == dst_port) or
                        (ip.src == dst_ip and tcp.sport == dst_port and
                         ip.dst == src_ip and tcp.dport == src_port)):

                        # Keep packets with payload only
                        if packet.haslayer('Raw'):
                            stream_packets.append((tcp.seq, packet.getlayer('Raw').load))

            # Sort packets by sequence number
            stream_packets.sort(key=lambda x: x[0])

            # Reassemble the stream
            stream_data = b''.join(payload for _, payload in stream_packets)

            operation_details['stream_size'] = len(stream_data)
            log_forensic_operation('reassemble_tcp_stream', True, operation_details)
            return stream_data

    except Exception as e:
        operation_details['error'] = str(e)
        log_forensic_operation('reassemble_tcp_stream', False, operation_details, level=logging.ERROR)
        logger.error(f"Failed to reassemble TCP stream: {e}")
        return b''

def extract_dns_queries(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Extract DNS queries from a PCAP file.

    Args:
        pcap_path: Path to the PCAP file

    Returns:
        List of DNS query information
    """
    dns_queries = []
    operation_details = {'pcap_path': pcap_path}

    try:
        packets = parse_pcap_file(pcap_path)

        for packet in packets:
            if 'dns' not in packet or 'queries' not in packet['dns']:
                continue

            for query in packet['dns'].get('queries', []):
                dns_info = {
                    'timestamp': packet.get('timestamp'),
                    'src_ip': packet.get('src_ip'),
                    'dst_ip': packet.get('dst_ip'),
                    'query_name': query.get('name', ''),
                    'query_type': query.get('type'),
                    'is_response': packet['dns'].get('is_response', False)
                }

                dns_queries.append(dns_info)

        operation_details['query_count'] = len(dns_queries)
        log_forensic_operation('extract_dns_queries', True, operation_details)
        return dns_queries

    except Exception as e:
        operation_details['error'] = str(e)
        log_forensic_operation('extract_dns_queries', False, operation_details, level=logging.ERROR)
        logger.error(f"Failed to extract DNS queries from PCAP {pcap_path}: {e}")
        return dns_queries

# Self-test function for module validation
def _self_test():
    """Run self-tests to verify module functionality."""
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
    resolve_hostname(hostname_fail)  # Should log a warning

    # Reverse DNS Lookup
    print("\n--- Reverse DNS Lookup ---")
    ip_to_lookup = "8.8.8.8"  # Google Public DNS
    resolved_hostname = reverse_dns_lookup(ip_to_lookup)
    if resolved_hostname:
        print(f"Hostname for '{ip_to_lookup}': {resolved_hostname}")
    else:
        print(f"Could not perform reverse lookup for '{ip_to_lookup}'")

    ip_fail = "192.0.2.1"  # Test IP, likely no reverse record
    reverse_dns_lookup(ip_fail)  # Should log a warning

    # Get Local IPs
    print("\n--- Get Local IPs ---")
    local_addresses = get_local_ip_addresses(include_loopback=True)
    print(f"Local IP Addresses (incl. loopback): {local_addresses}")
    local_addresses_no_loop = get_local_ip_addresses(include_loopback=False)
    print(f"Local IP Addresses (excl. loopback): {local_addresses_no_loop}")

    # Internal IP detection
    print("\n--- Internal IP Detection ---")
    ips_to_test = ["192.168.1.1", "10.0.0.1", "172.16.0.5", "8.8.8.8", "1.1.1.1"]
    for ip in ips_to_test:
        print(f"IP {ip} is {'internal' if is_internal_ip(ip) else 'external'}")

    print("\n--- Network Utilities Examples Complete ---")

# Run self-test when module is executed directly
if __name__ == "__main__":
    _self_test()
