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
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Union

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
    from admin.security.forensics.utils.forensic_constants import DEFAULT_TIMESTAMP_FORMAT
except ImportError:
    logging.warning("Forensic constants not found. Using default values.")
    FALLBACK_TIMESTAMP_FORMAT = "iso8601" # Corresponds to datetime.isoformat()

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
            hex_string = '0' + hex_string # Pad if odd length

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
            continue # Try next encoding
        except Exception as e:
            logger.warning("Unexpected error during decoding attempt with %s: %s", encoding, e)
            continue

    logger.warning("Failed to decode data using provided encodings.")
    log_forensic_operation("decode_bytes", False, {"error": "No suitable encoding found"})
    return None

# --- Timestamp Conversion Functions ---

# Windows FILETIME epoch (January 1, 1601 UTC)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

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
    except (TypeError, ValueError, OSError) as e: # OSError for out of range timestamps
        logger.error("Invalid epoch timestamp value for conversion: %s", epoch_seconds)
        log_forensic_operation("convert_epoch_to_datetime", False, {"input": epoch_seconds, "error": str(e)})
        raise ValueError(f"Invalid epoch timestamp: {e}") from e

def format_datetime(dt: datetime, fmt: str = DEFAULT_TIMESTAMP_FORMAT) -> str:
    """Formats a datetime object into a string."""
    try:
        if fmt.lower() == "iso8601":
            # Ensure timezone info for ISO format consistency
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc) # Assume UTC if naive
            formatted = dt.isoformat()
        else:
            formatted = dt.strftime(fmt)
        log_forensic_operation("format_datetime", True, {"format": fmt})
        return formatted
    except (TypeError, ValueError) as e:
        logger.error("Failed to format datetime object: %s", e)
        log_forensic_operation("format_datetime", False, {"format": fmt, "error": str(e)})
        raise ValueError(f"Datetime formatting failed: {e}") from e

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
    except (IOError, csv.Error, KeyError) as e: # KeyError if a dict misses a header
        logger.error("Failed to convert data to CSV string: %s", e)
        log_forensic_operation("dict_list_to_csv", False, {"error": str(e)})
        return None
    finally:
        output.close()

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

    # --- Timestamp Examples ---
    print("\n--- Timestamps ---")
    epoch_ts = 1678886400 # March 15, 2023 12:00:00 PM UTC
    dt_from_epoch = epoch_to_datetime(epoch_ts)
    print(f"Epoch {epoch_ts} -> Datetime: {dt_from_epoch}")
    print(f"Formatted ISO: {format_datetime(dt_from_epoch)}")
    print(f"Formatted Custom: {format_datetime(dt_from_epoch, '%Y/%m/%d %H:%M')}")

    # Example FILETIME (approx March 15, 2023 12:00:00 PM UTC)
    filetime_ts = 133233168000000000
    dt_from_filetime = filetime_to_datetime(filetime_ts)
    print(f"FILETIME {filetime_ts} -> Datetime: {dt_from_filetime}")
    print(f"FILETIME matches Epoch DT: {dt_from_filetime == dt_from_epoch}")

    # --- Structured Data Examples ---
    print("\n--- Structured Data ---")
    json_str = '{"event_id": 123, "user": "test", "action": "login", "timestamp": "2023-03-15T12:00:00Z"}'
    parsed_json = parse_json_string(json_str)
    print(f"Parsed JSON: {parsed_json}")

    list_of_dicts = [
        {"id": 1, "name": "file1.txt", "size": 1024},
        {"id": 2, "name": "image.jpg", "size": 20480},
        {"id": 3, "name": "report, final.docx", "size": 15360} # Test comma in field
    ]
    csv_output = dict_list_to_csv_string(list_of_dicts)
    print(f"CSV Output:\n{csv_output}")
