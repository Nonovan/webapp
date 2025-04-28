"""
Data Format Conversion Utilities for the Forensic Analysis Toolkit.

This module provides functions for converting data between various formats
commonly encountered during digital forensic investigations. This includes
encoding/decoding (Base64, Hex), timestamp format conversions, and basic
handling of structured data formats like JSON and CSV relevant to artifacts.

Functions prioritize clarity, error handling, and integration with forensic logging.
"""

import base64
import binascii
import codecs
import csv
import io
import json
import logging
import os
import re
import struct
import tempfile
import xml.dom.minidom
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, BinaryIO, TextIO

# Attempt to import forensic-specific logging and constants
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger.")
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None):
        level = logging.INFO if success else logging.ERROR
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

try:
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_TIMESTAMP_FORMAT,
        COMMON_TIMESTAMP_FORMATS,
        TEMP_DIR_FORENSICS,
    )
except ImportError:
    logging.warning("Forensic constants not found. Using default values.")
    FALLBACK_TIMESTAMP_FORMAT = "iso8601"  # Corresponds to datetime.isoformat()
    FALLBACK_COMMON_TIMESTAMP_FORMATS = [
        "%Y-%m-%dT%H:%M:%S.%fZ",         # ISO 8601 with microseconds
        "%Y-%m-%dT%H:%M:%SZ",            # ISO 8601
        "%Y-%m-%d %H:%M:%S.%f%z",        # ISO with space and timezone
        "%Y-%m-%d %H:%M:%S",             # Common YYYY-MM-DD HH:MM:SS
        "%d/%b/%Y:%H:%M:%S %z",          # Apache/nginx log format
        "%b %d %H:%M:%S",                # Syslog format
        "%m/%d/%Y %I:%M:%S %p",          # US format with AM/PM
    ]
    FALLBACK_TEMP_DIR = "/tmp/forensics"

    # Use fallback values
    DEFAULT_TIMESTAMP_FORMAT_FALLBACK = FALLBACK_TIMESTAMP_FORMAT
    resolved_common_timestamp_formats = COMMON_TIMESTAMP_FORMATS if 'COMMON_TIMESTAMP_FORMATS' in locals() else FALLBACK_COMMON_TIMESTAMP_FORMATS
    TEMP_DIR_FORENSICS = FALLBACK_TEMP_DIR

    # Ensure temp directory exists
    os.makedirs(TEMP_DIR_FORENSICS, exist_ok=True)

logger = logging.getLogger(__name__)

# --- Encoding/Decoding Functions ---

def bytes_to_base64(data: bytes) -> str:
    """Encodes bytes into a Base64 string."""
    try:
        encoded = base64.b64encode(data).decode('ascii')
        log_forensic_operation("encode_base64", True, {"input_len": len(data)})
        return encoded
    except Exception as e:
        logger.error("Failed to encode data to Base64: %s", e)
        log_forensic_operation("encode_base64", False, {"error": str(e)})
        raise ValueError(f"Base64 encoding failed: {e}") from e

def base64_to_bytes(encoded_data: str) -> bytes:
    """Decodes a Base64 string into bytes."""
    try:
        # Ensure padding is correct if needed
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)
        decoded = base64.b64decode(encoded_data, validate=True)
        log_forensic_operation("decode_base64", True, {"input_len": len(encoded_data)})
        return decoded
    except (binascii.Error, ValueError) as e:
        logger.error("Failed to decode Base64 data: %s", e)
        log_forensic_operation("decode_base64", False, {"error": str(e)})
        raise ValueError(f"Invalid Base64 data: {e}") from e
    except Exception as e:
        logger.error("An unexpected error occurred during Base64 decoding: %s", e)
        log_forensic_operation("decode_base64", False, {"error": str(e)})
        raise

def bytes_to_hex(data: bytes, separator: str = "") -> str:
    """Encodes bytes into a hexadecimal string."""
    try:
        encoded = data.hex(separator)
        log_forensic_operation("encode_hex", True, {"input_len": len(data)})
        return encoded
    except Exception as e:
        logger.error("Failed to encode data to Hex: %s", e)
        log_forensic_operation("encode_hex", False, {"error": str(e)})
        raise ValueError(f"Hex encoding failed: {e}") from e

def hex_to_bytes(hex_string: str) -> bytes:
    """Decodes a hexadecimal string into bytes."""
    try:
        # Remove common prefixes and separators if present
        hex_string = hex_string.replace("0x", "").replace(" ", "").replace("-", "").strip()
        if len(hex_string) % 2 != 0:
            hex_string = '0' + hex_string  # Pad if odd length

        decoded = bytes.fromhex(hex_string)
        log_forensic_operation("decode_hex", True, {"input_len": len(hex_string)})
        return decoded
    except ValueError as e:
        logger.error("Failed to decode Hex data: %s", e)
        log_forensic_operation("decode_hex", False, {"error": str(e)})
        raise ValueError(f"Invalid Hex data: {e}") from e
    except Exception as e:
        logger.error("An unexpected error occurred during Hex decoding: %s", e)
        log_forensic_operation("decode_hex", False, {"error": str(e)})
        raise

def decode_with_potential_encodings(data: bytes, encodings: List[str] = None) -> Optional[str]:
    """Attempts to decode bytes using a list of potential encodings."""
    if encodings is None:
        encodings = ['utf-8', 'latin-1', 'utf-16le', 'utf-16be', 'cp1252']

    for encoding in encodings:
        try:
            decoded_string = data.decode(encoding)
            log_forensic_operation("decode_bytes", True, {"encoding_used": encoding})
            return decoded_string
        except UnicodeDecodeError:
            continue  # Try next encoding
        except Exception as e:
            logger.warning("Unexpected error during decoding attempt with %s: %s", encoding, e)
            continue

    logger.warning("Failed to decode data using provided encodings.")
    log_forensic_operation("decode_bytes", False, {"error": "No suitable encoding found"})
    return None

def url_encode(data: str) -> str:
    """URL encodes a string."""
    try:
        import urllib.parse
        encoded = urllib.parse.quote(data)
        log_forensic_operation("url_encode", True, {"input_len": len(data)})
        return encoded
    except Exception as e:
        logger.error("Failed to URL encode data: %s", e)
        log_forensic_operation("url_encode", False, {"error": str(e)})
        raise ValueError(f"URL encoding failed: {e}") from e

def url_decode(encoded_data: str) -> str:
    """URL decodes a string."""
    try:
        import urllib.parse
        decoded = urllib.parse.unquote(encoded_data)
        log_forensic_operation("url_decode", True, {"input_len": len(encoded_data)})
        return decoded
    except Exception as e:
        logger.error("Failed to URL decode data: %s", e)
        log_forensic_operation("url_decode", False, {"error": str(e)})
        raise ValueError(f"URL decoding failed: {e}") from e

# --- Binary Data Processing ---

def extract_strings(data: bytes, min_length: int = 4, encoding: str = 'ascii') -> List[str]:
    """
    Extracts readable strings from binary data.

    Args:
        data: Binary data to search
        min_length: Minimum string length to extract
        encoding: Character encoding to use for extraction

    Returns:
        List of extracted strings
    """
    try:
        if encoding == 'ascii':
            pattern = b'[ -~]{%d,}' % min_length  # ASCII printable characters
        elif encoding == 'utf-8':
            # Simple approach - detect sequences that could be valid UTF-8
            data_str = data.decode('utf-8', errors='ignore')
            strings = re.findall(r'[\w\s\p{P}]{%d,}' % min_length, data_str)
            log_forensic_operation("extract_strings", True,
                                  {"encoding": encoding, "min_length": min_length, "strings_found": len(strings)})
            return strings
        else:
            logger.warning(f"Unsupported encoding for string extraction: {encoding}")
            log_forensic_operation("extract_strings", False, {"error": f"Unsupported encoding: {encoding}"})
            return []

        # For ASCII extraction
        strings = re.findall(pattern, data)
        decoded_strings = [s.decode(encoding, errors='replace') for s in strings]
        log_forensic_operation("extract_strings", True,
                              {"encoding": encoding, "min_length": min_length, "strings_found": len(decoded_strings)})
        return decoded_strings
    except Exception as e:
        logger.error("Failed to extract strings: %s", e)
        log_forensic_operation("extract_strings", False, {"error": str(e)})
        return []

def binary_to_hexdump(data: bytes, bytes_per_line: int = 16, show_ascii: bool = True) -> str:
    """
    Creates a hexdump representation of binary data.

    Args:
        data: Binary data to format
        bytes_per_line: Number of bytes to show per line
        show_ascii: Whether to include ASCII representation

    Returns:
        Formatted hexdump string
    """
    try:
        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i+bytes_per_line]
            # Format address
            addr = f"{i:08x}"

            # Format hex bytes
            hex_values = " ".join(f"{b:02x}" for b in chunk)
            # Pad for alignment if needed
            hex_values = hex_values.ljust(bytes_per_line * 3 - 1)

            if show_ascii:
                # Show ASCII representation (replace non-printable chars with dots)
                ascii_repr = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f"{addr}  {hex_values}  |{ascii_repr}|")
            else:
                lines.append(f"{addr}  {hex_values}")

        hexdump = "\n".join(lines)
        log_forensic_operation("binary_to_hexdump", True, {"bytes": len(data), "lines": len(lines)})
        return hexdump
    except Exception as e:
        logger.error("Failed to create hexdump: %s", e)
        log_forensic_operation("binary_to_hexdump", False, {"error": str(e)})
        raise ValueError(f"Hexdump creation failed: {e}") from e

# --- Timestamp Conversion Functions ---

# Windows FILETIME epoch (January 1, 1601 UTC)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Mac Absolute Time epoch (January 1, 2001 UTC)
_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

def filetime_to_datetime(filetime: int) -> datetime:
    """Converts a Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC) to a datetime object."""
    try:
        # Convert 100-nanosecond intervals to microseconds
        microseconds = filetime // 10
        dt = _FILETIME_EPOCH + timedelta(microseconds=microseconds)
        log_forensic_operation("convert_filetime_to_datetime", True, {"input": filetime})
        return dt
    except (TypeError, ValueError) as e:
        logger.error("Invalid FILETIME value for conversion: %s", filetime)
        log_forensic_operation("convert_filetime_to_datetime", False, {"input": filetime, "error": str(e)})
        raise ValueError(f"Invalid FILETIME value: {e}") from e

def epoch_to_datetime(epoch_seconds: Union[int, float]) -> datetime:
    """Converts a Unix epoch timestamp (seconds since 1970-01-01 UTC) to a datetime object."""
    try:
        dt = datetime.fromtimestamp(epoch_seconds, timezone.utc)
        log_forensic_operation("convert_epoch_to_datetime", True, {"input": epoch_seconds})
        return dt
    except (TypeError, ValueError, OSError) as e:  # OSError for out of range timestamps
        logger.error("Invalid epoch timestamp value for conversion: %s", epoch_seconds)
        log_forensic_operation("convert_epoch_to_datetime", False, {"input": epoch_seconds, "error": str(e)})
        raise ValueError(f"Invalid epoch timestamp: {e}") from e

def mac_absolute_time_to_datetime(timestamp: int) -> datetime:
    """Converts a Mac Absolute Time (seconds since 2001-01-01 UTC) to a datetime object."""
    try:
        dt = _MAC_EPOCH + timedelta(seconds=timestamp)
        log_forensic_operation("convert_mac_time_to_datetime", True, {"input": timestamp})
        return dt
    except (TypeError, ValueError) as e:
        logger.error("Invalid Mac Absolute Time value for conversion: %s", timestamp)
        log_forensic_operation("convert_mac_time_to_datetime", False, {"input": timestamp, "error": str(e)})
        raise ValueError(f"Invalid Mac Absolute Time value: {e}") from e

def format_datetime(dt: datetime, fmt: str = DEFAULT_TIMESTAMP_FORMAT) -> str:
    """Formats a datetime object into a string."""
    try:
        if fmt.lower() == "iso8601":
            # Ensure timezone info for ISO format consistency
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)  # Assume UTC if naive
            formatted = dt.isoformat()
        else:
            formatted = dt.strftime(fmt)
        log_forensic_operation("format_datetime", True, {"format": fmt})
        return formatted
    except (TypeError, ValueError) as e:
        logger.error("Failed to format datetime object: %s", e)
        log_forensic_operation("format_datetime", False, {"format": fmt, "error": str(e)})
        raise ValueError(f"Datetime formatting failed: {e}") from e

def parse_datetime_string(timestamp_str: str, formats: List[str] = None) -> Optional[datetime]:
    """
    Attempts to parse a datetime string using multiple formats.

    Args:
        timestamp_str: The timestamp string to parse
        formats: List of datetime format strings to try

    Returns:
        Parsed datetime object or None if parsing fails
    """
    if not formats:
        # Use common timestamp formats from constants or fallback
        formats = COMMON_TIMESTAMP_FORMATS

    for fmt in formats:
        try:
            parsed_dt = datetime.strptime(timestamp_str, fmt)

            # If no timezone info, assume UTC
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)

            log_forensic_operation("parse_datetime", True,
                                  {"input": timestamp_str, "format_used": fmt})
            return parsed_dt
        except ValueError:
            # Try next format
            continue

    logger.warning("Failed to parse datetime string: %s", timestamp_str)
    log_forensic_operation("parse_datetime", False,
                          {"input": timestamp_str, "error": "No matching format"})
    return None

def datetime_to_epoch(dt: datetime) -> float:
    """Converts a datetime object to a Unix epoch timestamp (seconds since 1970-01-01 UTC)."""
    try:
        # Ensure timezone info for consistent conversion
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)  # Assume UTC if naive
        epoch = dt.timestamp()
        log_forensic_operation("convert_datetime_to_epoch", True, {"datetime": dt.isoformat()})
        return epoch
    except (TypeError, ValueError, OSError) as e:
        logger.error("Failed to convert datetime to epoch: %s", e)
        log_forensic_operation("convert_datetime_to_epoch", False, {"error": str(e)})
        raise ValueError(f"Datetime to epoch conversion failed: {e}") from e

# --- Structured Data Conversion ---

def parse_json_string(json_string: str) -> Optional[Union[Dict, List]]:
    """Safely parses a JSON string into a Python dictionary or list."""
    try:
        data = json.loads(json_string)
        log_forensic_operation("parse_json", True)
        return data
    except json.JSONDecodeError as e:
        logger.error("Failed to parse JSON string: %s", e)
        log_forensic_operation("parse_json", False, {"error": str(e)})
        return None
    except Exception as e:
        logger.error("An unexpected error occurred during JSON parsing: %s", e)
        log_forensic_operation("parse_json", False, {"error": str(e)})
        return None

def dict_list_to_csv_string(data: List[Dict[str, Any]], headers: Optional[List[str]] = None) -> Optional[str]:
    """Converts a list of dictionaries to a CSV formatted string."""
    if not data:
        return ""
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        logger.error("Input must be a list of dictionaries for CSV conversion.")
        log_forensic_operation("dict_list_to_csv", False, {"error": "Invalid input type"})
        return None

    output = io.StringIO()
    try:
        if headers is None:
            # Use keys from the first dictionary as headers
            headers = list(data[0].keys())

        writer = csv.DictWriter(output, fieldnames=headers, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(data)

        csv_string = output.getvalue()
        log_forensic_operation("dict_list_to_csv", True, {"rows": len(data)})
        return csv_string
    except (IOError, csv.Error, KeyError) as e:  # KeyError if a dict misses a header
        logger.error("Failed to convert data to CSV string: %s", e)
        log_forensic_operation("dict_list_to_csv", False, {"error": str(e)})
        return None
    finally:
        output.close()

def csv_string_to_dict_list(csv_string: str, has_header: bool = True) -> Optional[List[Dict[str, Any]]]:
    """
    Converts a CSV string to a list of dictionaries.

    Args:
        csv_string: CSV formatted string
        has_header: Whether the CSV string includes a header row

    Returns:
        List of dictionaries where keys are column names, or None if conversion fails
    """
    if not csv_string:
        return []

    input_stream = io.StringIO(csv_string)
    try:
        csv_reader = csv.reader(input_stream)

        if has_header:
            headers = next(csv_reader)
            result = []
            for row in csv_reader:
                row_dict = {header: value for header, value in zip(headers, row)}
                result.append(row_dict)
        else:
            # If no header, use column positions as keys
            result = []
            for row in csv_reader:
                row_dict = {str(i): value for i, value in enumerate(row)}
                result.append(row_dict)

        log_forensic_operation("csv_to_dict_list", True, {"rows": len(result)})
        return result
    except csv.Error as e:
        logger.error("Failed to parse CSV string: %s", e)
        log_forensic_operation("csv_to_dict_list", False, {"error": str(e)})
        return None
    except Exception as e:
        logger.error("An unexpected error occurred during CSV parsing: %s", e)
        log_forensic_operation("csv_to_dict_list", False, {"error": str(e)})
        return None
    finally:
        input_stream.close()

def xml_to_dict(xml_string: str) -> Optional[Dict[str, Any]]:
    """
    Converts an XML string to a Python dictionary.

    Args:
        xml_string: XML formatted string

    Returns:
        Dictionary representation of the XML, or None if conversion fails
    """
    try:
        # Parse XML
        root = ET.fromstring(xml_string)
        result = _element_to_dict(root)
        log_forensic_operation("xml_to_dict", True)
        return result
    except ET.ParseError as e:
        logger.error("Failed to parse XML: %s", e)
        log_forensic_operation("xml_to_dict", False, {"error": str(e)})
        return None
    except Exception as e:
        logger.error("An unexpected error occurred during XML to dict conversion: %s", e)
        log_forensic_operation("xml_to_dict", False, {"error": str(e)})
        return None

def _element_to_dict(element: ET.Element) -> Dict[str, Any]:
    """Helper function to recursively convert XML elements to dictionaries."""
    result = {}

    # Add element attributes
    if element.attrib:
        result["@attributes"] = dict(element.attrib)

    # Process children
    for child in element:
        child_dict = _element_to_dict(child)

        # Handle duplicate tags by creating lists
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_dict)
        else:
            result[child.tag] = child_dict

    # Handle element text
    if element.text and element.text.strip():
        if not result:  # No children or attributes, just text
            result = element.text.strip()
        else:
            result["#text"] = element.text.strip()

    return result

def dict_to_xml(data: Dict[str, Any], root_name: str = "root") -> Optional[str]:
    """
    Converts a Python dictionary to an XML string.

    Args:
        data: Dictionary to convert
        root_name: Name of the root element

    Returns:
        XML formatted string, or None if conversion fails
    """
    try:
        root = ET.Element(root_name)
        _dict_to_element(root, data)

        # Convert to string with pretty formatting
        xml_bytes = ET.tostring(root, encoding='utf-8')
        dom = xml.dom.minidom.parseString(xml_bytes)
        pretty_xml = dom.toprettyxml(indent="  ")

        log_forensic_operation("dict_to_xml", True)
        return pretty_xml
    except Exception as e:
        logger.error("Failed to convert dictionary to XML: %s", e)
        log_forensic_operation("dict_to_xml", False, {"error": str(e)})
        return None

def _dict_to_element(parent: ET.Element, data: Dict[str, Any]) -> None:
    """Helper function to recursively convert dictionaries to XML elements."""
    if isinstance(data, dict):
        # Handle attributes
        if "@attributes" in data:
            for key, value in data["@attributes"].items():
                parent.set(key, str(value))
            data = {k: v for k, v in data.items() if k != "@attributes"}

        # Handle text content
        if "#text" in data:
            parent.text = str(data["#text"])
            data = {k: v for k, v in data.items() if k != "#text"}

        # Handle other elements
        for key, value in data.items():
            if isinstance(value, list):
                # For lists, create multiple elements with the same tag
                for item in value:
                    child = ET.SubElement(parent, key)
                    if isinstance(item, (dict, list)):
                        _dict_to_element(child, item)
                    else:
                        child.text = str(item)
            else:
                child = ET.SubElement(parent, key)
                if isinstance(value, (dict, list)):
                    _dict_to_element(child, value)
                else:
                    child.text = str(value)
    elif isinstance(data, list):
        # For direct list values
        for item in data:
            _dict_to_element(parent, item)
    else:
        # For direct scalar values
        parent.text = str(data)

# --- File Format Conversion ---

def convert_file_format(
    input_path: str,
    output_path: str,
    input_format: str = None,
    output_format: str = None,
    overwrite: bool = False
) -> bool:
    """
    Converts a file from one format to another.

    Args:
        input_path: Path to input file
        output_path: Path to output file
        input_format: Input file format (auto-detected if None)
        output_format: Output file format (detected from extension if None)
        overwrite: Whether to overwrite existing output file

    Returns:
        True if conversion was successful, False otherwise
    """
    operation_details = {
        "input_path": input_path,
        "output_path": output_path,
        "input_format": input_format,
        "output_format": output_format
    }

    if not os.path.exists(input_path):
        logger.error("Input file not found: %s", input_path)
        log_forensic_operation("convert_file_format", False,
                              {**operation_details, "error": "Input file not found"})
        return False

    if os.path.exists(output_path) and not overwrite:
        logger.error("Output file already exists: %s", output_path)
        log_forensic_operation("convert_file_format", False,
                              {**operation_details, "error": "Output file exists"})
        return False

    # Auto-detect formats if not specified
    if not input_format:
        input_format = detect_file_format(input_path)
        operation_details["input_format"] = input_format

    if not output_format:
        output_format = os.path.splitext(output_path)[1].lower().lstrip('.')
        if not output_format:
            logger.error("Could not determine output format from file extension")
            log_forensic_operation("convert_file_format", False,
                                  {**operation_details, "error": "Unknown output format"})
            return False
        operation_details["output_format"] = output_format

    # Check if formats are supported
    supported_conversions = {
        # Format pairs: (input_format, output_format)
        ("json", "csv"): _convert_json_to_csv,
        ("csv", "json"): _convert_csv_to_json,
        ("json", "xml"): _convert_json_to_xml,
        ("xml", "json"): _convert_xml_to_json,
        ("xml", "csv"): _convert_xml_to_csv,
        ("hex", "bin"): _convert_hex_to_bin,
        ("bin", "hex"): _convert_bin_to_hex,
        ("base64", "bin"): _convert_base64_to_bin,
        ("bin", "base64"): _convert_bin_to_base64,
    }

    format_pair = (input_format.lower(), output_format.lower())
    if format_pair not in supported_conversions:
        logger.error("Unsupported format conversion: %s to %s", input_format, output_format)
        log_forensic_operation("convert_file_format", False,
                              {**operation_details, "error": "Unsupported conversion"})
        return False

    # Create temp file for atomic writing
    with tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR_FORENSICS) as temp_file:
        temp_path = temp_file.name

    try:
        # Perform conversion
        conversion_func = supported_conversions[format_pair]
        success = conversion_func(input_path, temp_path)

        if not success:
            logger.error("Conversion failed: %s to %s", input_path, output_path)
            os.unlink(temp_path)
            log_forensic_operation("convert_file_format", False,
                                  {**operation_details, "error": "Conversion function failed"})
            return False

        # Move temp file to output path (atomic write)
        if os.path.exists(output_path):
            os.unlink(output_path)
        os.rename(temp_path, output_path)

        log_forensic_operation("convert_file_format", True, operation_details)
        return True

    except Exception as e:
        # Clean up temp file
        if os.path.exists(temp_path):
            os.unlink(temp_path)

        logger.error("Error during file conversion: %s", e)
        log_forensic_operation("convert_file_format", False,
                              {**operation_details, "error": str(e)})
        return False

def detect_file_format(file_path: str) -> str:
    """
    Attempts to detect the format of a file.

    Args:
        file_path: Path to the file

    Returns:
        String identifier of the file format
    """
    try:
        # Check extension first
        ext = os.path.splitext(file_path)[1].lower().lstrip('.')
        if ext in ('json', 'xml', 'csv', 'txt', 'html', 'bin', 'hex'):
            return ext

        # If no helpful extension, try to determine by content
        with open(file_path, 'rb') as f:
            header = f.read(16)  # Read first few bytes for detection

            # Look for common file signatures/magic numbers
            if header.startswith(b'\x89PNG'):
                return 'png'
            elif header.startswith(b'\xff\xd8\xff'):
                return 'jpg'
            elif header.startswith(b'%PDF'):
                return 'pdf'
            elif header.startswith(b'PK\x03\x04'):
                return 'zip'

            # Reset and try text-based detection
            f.seek(0)
            first_line = f.readline().strip()

            try:
                first_line_text = first_line.decode('utf-8', errors='ignore')

                if first_line_text.startswith('{') or first_line_text.startswith('['):
                    # Probably JSON
                    return 'json'
                elif first_line_text.startswith('<?xml') or first_line_text.startswith('<'):
                    # Probably XML
                    return 'xml'
                elif b',' in first_line and first_line.count(b',') >= 2:
                    # Might be CSV
                    return 'csv'

                # Check for hex dump format
                if re.match(r'^[0-9a-fA-F]{8}\s+(?:[0-9a-fA-F]{2}\s+)+', first_line_text):
                    return 'hex'

                # Check for Base64
                if re.match(r'^[A-Za-z0-9+/=]+$', first_line_text) and len(first_line_text) % 4 == 0:
                    return 'base64'

            except UnicodeDecodeError:
                # Not a text file
                return 'bin'

        # Default to binary if nothing else matches
        return 'bin'

    except Exception as e:
        logger.warning("Error detecting file format: %s", e)
        return 'unknown'

def _convert_json_to_csv(input_path: str, output_path: str) -> bool:
    """Converts a JSON file to CSV format."""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Handle case of either a list of dicts or a single dict
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            logger.error("JSON data must be a list of dictionaries or a single dictionary")
            return False

        # Convert to CSV string
        csv_data = dict_list_to_csv_string(data)
        if not csv_data:
            return False

        # Write to output file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(csv_data)

        return True
    except Exception as e:
        logger.error("Error converting JSON to CSV: %s", e)
        return False

def _convert_csv_to_json(input_path: str, output_path: str) -> bool:
    """Converts a CSV file to JSON format."""
    try:
        # Read CSV file
        with open(input_path, 'r', encoding='utf-8') as f:
            csv_data = f.read()

        # Convert to list of dicts
        data = csv_string_to_dict_list(csv_data)
        if data is None:
            return False

        # Write to JSON file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        return True
    except Exception as e:
        logger.error("Error converting CSV to JSON: %s", e)
        return False

def _convert_json_to_xml(input_path: str, output_path: str) -> bool:
    """Converts a JSON file to XML format."""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # For lists, wrap in a container element
        if isinstance(data, list):
            data = {"items": {"item": data}}

        # Convert to XML
        xml_data = dict_to_xml(data, "root")
        if not xml_data:
            return False

        # Write to output file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(xml_data)

        return True
    except Exception as e:
        logger.error("Error converting JSON to XML: %s", e)
        return False

def _convert_xml_to_json(input_path: str, output_path: str) -> bool:
    """Converts an XML file to JSON format."""
    try:
        # Read XML file
        with open(input_path, 'r', encoding='utf-8') as f:
            xml_data = f.read()

        # Convert to dict
        data = xml_to_dict(xml_data)
        if data is None:
            return False

        # Write to JSON file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        return True
    except Exception as e:
        logger.error("Error converting XML to JSON: %s", e)
        return False

def _convert_xml_to_csv(input_path: str, output_path: str) -> bool:
    """Converts an XML file to CSV format (via JSON as intermediate step)."""
    try:
        # First convert to JSON structure
        with tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR_FORENSICS, suffix='.json') as temp_file:
            temp_json_path = temp_file.name

        success = _convert_xml_to_json(input_path, temp_json_path)
        if not success:
            os.unlink(temp_json_path)
            return False

        # Then convert JSON to CSV
        success = _convert_json_to_csv(temp_json_path, output_path)
        os.unlink(temp_json_path)
        return success
    except Exception as e:
        logger.error("Error converting XML to CSV: %s", e)
        return False

def _convert_hex_to_bin(input_path: str, output_path: str) -> bool:
    """Converts a hexdump or hex string file to binary data."""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            hex_content = f.read()

        # Clean up the content (remove addresses, spaces, etc.)
        # Try to detect if it's a formatted hexdump vs a plain hex string
        if re.search(r'^\s*[0-9a-fA-F]{6,8}\s+', hex_content, re.MULTILINE):
            # Looks like a hexdump with addresses - extract just the hex bytes
            hex_pattern = re.compile(r'^\s*[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{2}\s*)+)', re.MULTILINE)
            matches = hex_pattern.findall(hex_content)
            if not matches:
                logger.error("Failed to parse hexdump format")
                return False
            hex_string = ''.join(matches).replace(' ', '')
        else:
            # Assume it's just a hex string - strip whitespace, etc.
            hex_string = ''.join(hex_content.split())

        # Convert to binary
        binary_data = bytes.fromhex(hex_string)

        # Write to output file
        with open(output_path, 'wb') as f:
            f.write(binary_data)

        return True
    except Exception as e:
        logger.error("Error converting hex to binary: %s", e)
        return False

def _convert_bin_to_hex(input_path: str, output_path: str) -> bool:
    """Converts a binary file to a hexdump format."""
    try:
        with open(input_path, 'rb') as f:
            binary_data = f.read()

        # Convert to hexdump
        hexdump = binary_to_hexdump(binary_data)

        # Write to output file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(hexdump)

        return True
    except Exception as e:
        logger.error("Error converting binary to hex: %s", e)
        return False

def _convert_base64_to_bin(input_path: str, output_path: str) -> bool:
    """Converts a Base64 encoded file to binary data."""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            base64_data = f.read().strip()

        # Clean up any whitespace, newlines, etc.
        base64_clean = ''.join(base64_data.split())

        # Decode
        binary_data = base64_to_bytes(base64_clean)

        # Write to output file
        with open(output_path, 'wb') as f:
            f.write(binary_data)

        return True
    except Exception as e:
        logger.error("Error converting Base64 to binary: %s", e)
        return False

def _convert_bin_to_base64(input_path: str, output_path: str) -> bool:
    """Converts a binary file to Base64 encoding."""
    try:
        with open(input_path, 'rb') as f:
            binary_data = f.read()

        # Encode as Base64
        base64_data = bytes_to_base64(binary_data)

        # Format with line breaks for readability
        formatted_base64 = '\n'.join(base64_data[i:i+76] for i in range(0, len(base64_data), 76))

        # Write to output file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(formatted_base64)

        return True
    except Exception as e:
        logger.error("Error converting binary to Base64: %s", e)
        return False

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # --- Encoding/Decoding Examples ---
    print("--- Encoding/Decoding ---")
    original_bytes = b"Forensic data sample!"
    print(f"Original Bytes: {original_bytes}")

    b64_encoded = bytes_to_base64(original_bytes)
    print(f"Base64 Encoded: {b64_encoded}")
    b64_decoded = base64_to_bytes(b64_encoded)
    print(f"Base64 Decoded: {b64_decoded}")
    print(f"Base64 Match: {original_bytes == b64_decoded}")

    hex_encoded = bytes_to_hex(original_bytes)
    print(f"Hex Encoded: {hex_encoded}")
    hex_decoded = hex_to_bytes(hex_encoded)
    print(f"Hex Decoded: {hex_decoded}")
    print(f"Hex Match: {original_bytes == hex_decoded}")

    url_enc = url_encode("Sample data with spaces & special chars!")
    print(f"URL Encoded: {url_enc}")
    url_dec = url_decode(url_enc)
    print(f"URL Decoded: {url_dec}")

    # --- Binary Data Processing ---
    print("\n--- Binary Data Processing ---")
    sample_binary = b"This is a binary sample with some numbers 12345 and special chars !@#$%^"
    strings = extract_strings(sample_binary, min_length=5)
    print(f"Extracted strings: {strings}")

    print("\nHexdump example:")
    hexdump = binary_to_hexdump(sample_binary[:32])
    print(hexdump)

    # --- Timestamp Examples ---
    print("\n--- Timestamps ---")
    epoch_ts = 1678886400  # March 15, 2023 12:00:00 PM UTC
    dt_from_epoch = epoch_to_datetime(epoch_ts)
    print(f"Epoch {epoch_ts} -> Datetime: {dt_from_epoch}")
    print(f"Formatted ISO: {format_datetime(dt_from_epoch)}")
    print(f"Formatted Custom: {format_datetime(dt_from_epoch, '%Y/%m/%d %H:%M')}")

    # Example FILETIME (approx March 15, 2023 12:00:00 PM UTC)
    filetime_ts = 133233168000000000
    dt_from_filetime = filetime_to_datetime(filetime_ts)
    print(f"FILETIME {filetime_ts} -> Datetime: {dt_from_filetime}")
    print(f"FILETIME matches Epoch DT: {dt_from_filetime == dt_from_epoch}")

    # Test timestamp string parsing
    print("\nTimestamp String Parsing:")
    test_timestamps = [
        "2023-03-15T12:00:00Z",
        "2023-03-15 12:00:00",
        "15/Mar/2023:12:00:00 +0000",
        "Mar 15 12:00:00"
    ]
    for ts in test_timestamps:
        parsed = parse_datetime_string(ts)
        print(f"String: {ts} -> Parsed: {parsed}")

    # Convert back to epoch
    if dt_from_epoch:
        epoch_from_dt = datetime_to_epoch(dt_from_epoch)
        print(f"Datetime to Epoch: {epoch_from_dt} (matches: {epoch_from_dt == epoch_ts})")

    # --- Structured Data Examples ---
    print("\n--- Structured Data ---")
    json_str = '{"event_id": 123, "user": "test", "action": "login", "timestamp": "2023-03-15T12:00:00Z"}'
    parsed_json = parse_json_string(json_str)
    print(f"Parsed JSON: {parsed_json}")

    list_of_dicts = [
        {"id": 1, "name": "file1.txt", "size": 1024},
        {"id": 2, "name": "image.jpg", "size": 20480},
        {"id": 3, "name": "report, final.docx", "size": 15360}  # Test comma in field
    ]
    csv_output = dict_list_to_csv_string(list_of_dicts)
    print(f"CSV Output:\n{csv_output}")

    if csv_output:
        back_to_dict = csv_string_to_dict_list(csv_output)
        print(f"Back to dictionaries: {back_to_dict}")

    # XML conversion example
    sample_dict = {
        "evidence": {
            "@attributes": {"id": "ev001", "source": "disk"},
            "file": [
                {"name": "document.txt", "size": "1024", "hash": "abc123"},
                {"name": "image.jpg", "size": "5120", "hash": "def456"}
            ],
            "metadata": {
                "collected_by": "Analyst",
                "timestamp": "2023-03-15T12:00:00Z"
            }
        }
    }
    xml_output = dict_to_xml(sample_dict, "forensic_data")
    print(f"\nXML Output:\n{xml_output[:400]}...")  # Show first part only for brevity

    if xml_output:
        dict_from_xml = xml_to_dict(xml_output)
        print(f"Back to dictionary (partial): {str(dict_from_xml)[:200]}...")

    # --- File Format Conversion Demo ---
    print("\n--- File Format Conversion ---")
    # Create test files
    test_dir = os.path.join(TEMP_DIR_FORENSICS, "format_test")
    os.makedirs(test_dir, exist_ok=True)

    # JSON test file
    json_file = os.path.join(test_dir, "test.json")
    with open(json_file, 'w') as f:
        json.dump(list_of_dicts, f)

    # Test format detection
    print(f"Detected format of {json_file}: {detect_file_format(json_file)}")

    # Convert JSON to CSV
    csv_file = os.path.join(test_dir, "test.csv")
    result = convert_file_format(json_file, csv_file, overwrite=True)
    print(f"JSON to CSV conversion: {'Success' if result else 'Failed'}")

    # Clean up test files
    try:
        import shutil
        shutil.rmtree(test_dir)
    except:
        pass
