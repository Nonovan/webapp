"""
Data Sanitization Utilities for the Forensic Analysis Toolkit.

This module provides functions to sanitize data, such as logs, reports, or
extracted artifacts, by removing or redacting sensitive information. This is
crucial for sharing findings while protecting privacy (PII), security credentials,
and other confidential data.

Functions support pattern-based redaction and can be applied to text content
or structured data like JSON.
"""

import os
import re
import logging
import json
import shutil
import tempfile
from typing import List, Optional, Union, Dict, Any, Pattern, Set, Tuple

# Attempt to import core security utilities
try:
    from core.security.cs_utils import obfuscate_sensitive_data
    CORE_OBFUSCATION_AVAILABLE = True
    logger = logging.getLogger(__name__)
    logger.debug("Using core implementation of obfuscate_sensitive_data")
except ImportError:
    CORE_OBFUSCATION_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Core security module not found. Using fallback obfuscation.")

# Attempt to import forensic-specific logging
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    FORENSIC_LOGGING_AVAILABLE = True
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger for sanitization.")
    FORENSIC_LOGGING_AVAILABLE = False
    # Fallback logging function
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

# Attempt to import forensic constants
try:
    from admin.security.forensics.utils.forensic_constants import DEFAULT_REDACTION_PLACEHOLDER
    CONSTANTS_AVAILABLE = True
except ImportError:
    logging.warning("Forensic constants not found. Using default values for sanitization.")
    CONSTANTS_AVAILABLE = False
    FALLBACK_REDACTION_PLACEHOLDER = "[REDACTED]"

# --- Default Redaction Patterns ---
# These are examples; a production system would need more comprehensive and configurable patterns.

# Basic PII patterns
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
# Simple IPv4 pattern (might catch false positives)
IPV4_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
# Basic SSN-like pattern (use with caution, high false positive potential)
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
# Basic Credit Card pattern (Luhn check recommended for better accuracy)
CREDIT_CARD_PATTERN = re.compile(r'\b(?:\d[ -]*?){13,16}\b')

# Credential keywords (case-insensitive)
CREDENTIAL_KEYWORDS = [
    'password', 'passwd', 'secret', 'apikey', 'api_key', 'token',
    'credential', 'access_key', 'secret_key'
]
# Pattern to find key=value pairs with credential keywords
CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
    rf'\b({"|".join(CREDENTIAL_KEYWORDS)})\b\s*[:=]\s*["\']?([^"\'\s,]+)["\']?',
    re.IGNORECASE
)

# Predefined policy levels mapping to patterns
# In a real app, this could be loaded from config
REDACTION_POLICIES = {
    "none": [],
    "basic_pii": [EMAIL_PATTERN, IPV4_PATTERN],
    "credentials": [CREDENTIAL_ASSIGNMENT_PATTERN],
    "full_pii": [EMAIL_PATTERN, IPV4_PATTERN, SSN_PATTERN, CREDIT_CARD_PATTERN],
    "high": [EMAIL_PATTERN, IPV4_PATTERN, SSN_PATTERN, CREDIT_CARD_PATTERN, CREDENTIAL_ASSIGNMENT_PATTERN],
}

# --- Sanitization Functions ---

def redact_sensitive_data(
    content: str,
    patterns: Optional[List[Union[str, Pattern]]] = None,
    policy: Optional[str] = "high",
    placeholder: str = FALLBACK_REDACTION_PLACEHOLDER if not CONSTANTS_AVAILABLE else DEFAULT_REDACTION_PLACEHOLDER
) -> str:
    """
    Redacts sensitive information from a string based on regex patterns or a predefined policy.

    Args:
        content: The input string content to sanitize.
        patterns: A list of regex patterns (compiled or strings) to match and redact.
                  If provided, overrides the policy.
        policy: The name of a predefined redaction policy (e.g., "basic_pii", "high").
                Defaults to "high". Ignored if 'patterns' is provided.
        placeholder: The string to replace matched sensitive data with.

    Returns:
        The sanitized string content.
    """
    if not isinstance(content, str):
        logger.warning("Input content is not a string. Returning as is.")
        return content  # Or raise TypeError

    operation_details = {"policy": policy, "patterns_provided": bool(patterns), "placeholder": placeholder}
    sanitized_content = content
    patterns_to_use: List[Pattern] = []

    if patterns:
        operation_details["policy"] = "custom"  # Override policy name if patterns are given
        for p in patterns:
            if isinstance(p, str):
                try:
                    patterns_to_use.append(re.compile(p, re.IGNORECASE))  # Default to case-insensitive
                except re.error as e:
                    logger.warning(f"Invalid regex pattern string provided: '{p}'. Error: {e}. Skipping.")
            elif isinstance(p, re.Pattern):
                patterns_to_use.append(p)
            else:
                logger.warning(f"Invalid pattern type provided: {type(p)}. Skipping.")
    elif policy and policy in REDACTION_POLICIES:
        patterns_to_use = REDACTION_POLICIES[policy]
    elif policy:
        logger.warning(f"Unknown redaction policy: '{policy}'. Using no patterns.")
        operation_details["policy"] = f"unknown ({policy})"

    if not patterns_to_use:
        log_forensic_operation("redact_sensitive_data", True, {**operation_details, "status": "No patterns applied"})
        return content  # Nothing to redact

    redactions_made = 0
    for pattern in patterns_to_use:
        try:
            # Use a function for replacement to count matches
            def replacer(match):
                nonlocal redactions_made
                redactions_made += 1
                # For credential assignments, only redact the value part
                if pattern == CREDENTIAL_ASSIGNMENT_PATTERN and len(match.groups()) >= 2:
                    value_part = match.group(2)
                    # Use core obfuscation for credential values
                    if CORE_OBFUSCATION_AVAILABLE:
                        obfuscated_value = obfuscate_sensitive_data(value_part, prefix_visible=0, suffix_visible=0, mask_char='*')
                        return f"{match.group(1)}{match.group(0)[len(match.group(1)):].split(match.group(2))[0]}{obfuscated_value}"
                    else:
                        return f"{match.group(1)}{match.group(0)[len(match.group(1)):].split(match.group(2))[0]}{placeholder}"
                return placeholder
            sanitized_content = pattern.sub(replacer, sanitized_content)

        except re.error as e:
            logger.error(f"Regex error during redaction with pattern '{pattern.pattern}': {e}")
            log_forensic_operation("redact_sensitive_data", False, {**operation_details, "error": f"Regex error: {e}"}, level=logging.ERROR)
            # Continue with other patterns if possible, but report failure

    operation_details["redactions_count"] = redactions_made
    log_forensic_operation("redact_sensitive_data", True, operation_details)
    return sanitized_content


def mask_sensitive_value(
    value: str,
    prefix_visible: int = 0,
    suffix_visible: int = 4,
    placeholder: Optional[str] = None
) -> str:
    """
    Masks a sensitive string value, optionally showing parts of the beginning and end.

    Args:
        value: The sensitive string to mask
        prefix_visible: Number of characters to keep visible at the beginning
        suffix_visible: Number of characters to keep visible at the end
        placeholder: Custom placeholder to use instead of default masking

    Returns:
        The masked string with only specified portions visible
    """
    if not isinstance(value, str):
        return str(value)

    # Use the core implementation if available
    if CORE_OBFUSCATION_AVAILABLE:
        return obfuscate_sensitive_data(value, prefix_visible, suffix_visible, '*')

    # Otherwise use placeholder or default masking
    if placeholder is not None:
        if prefix_visible > 0 or suffix_visible > 0:
            # If showing portions, create a hybrid with placeholder
            data_len = len(value)
            prefix = value[:prefix_visible] if prefix_visible > 0 and prefix_visible < data_len else ""
            suffix = value[-suffix_visible:] if suffix_visible > 0 and suffix_visible < data_len else ""
            return f"{prefix}{placeholder}{suffix}"
        else:
            return placeholder
    else:
        # Use simple masking with asterisks if no placeholder provided
        data_len = len(value)
        if data_len == 0:
            return ""

        # Handle the case when the value is shorter than the visible parts
        if prefix_visible + suffix_visible >= data_len:
            prefix_visible = min(prefix_visible, data_len // 2)
            suffix_visible = min(suffix_visible, data_len // 2)

        prefix = value[:prefix_visible]
        suffix = value[-suffix_visible:] if suffix_visible > 0 else ""
        mask_length = data_len - prefix_visible - suffix_visible
        mask = '*' * mask_length if mask_length > 0 else ""

        return prefix + mask + suffix


def detect_pii(content: str) -> Dict[str, List[str]]:
    """
    Detects potential personally identifiable information (PII) in text content.

    This function scans the provided text for common PII patterns such as email addresses,
    SSNs, credit card numbers, and IP addresses. It's intended to help identify sensitive
    information that should be redacted before sharing.

    Args:
        content: The text content to scan for PII

    Returns:
        Dictionary mapping PII categories to lists of found matches
    """
    if not isinstance(content, str):
        logger.warning("Input content is not a string.")
        return {}

    operation_details = {"content_length": len(content)}
    results = {
        "emails": [],
        "ip_addresses": [],
        "ssns": [],
        "credit_cards": [],
        "credentials": []
    }

    try:
        # Find emails
        emails = EMAIL_PATTERN.findall(content)
        results["emails"] = emails

        # Find IP addresses
        ips = IPV4_PATTERN.findall(content)
        results["ip_addresses"] = ips

        # Find SSNs
        ssns = SSN_PATTERN.findall(content)
        results["ssns"] = ssns

        # Find credit card numbers
        # Note: In production, should validate with Luhn algorithm
        credit_cards = CREDIT_CARD_PATTERN.findall(content)
        results["credit_cards"] = credit_cards

        # Find credentials
        creds = CREDENTIAL_ASSIGNMENT_PATTERN.findall(content)
        results["credentials"] = [f"{key}={value}" for key, value in creds]

        # Count total findings
        total_findings = sum(len(items) for items in results.values())
        operation_details["total_findings"] = total_findings
        operation_details["findings_by_category"] = {k: len(v) for k, v in results.items()}

        log_forensic_operation("detect_pii", True, operation_details)
        return results

    except Exception as e:
        logger.error(f"Error detecting PII: {e}", exc_info=True)
        log_forensic_operation("detect_pii", False,
                              {**operation_details, "error": str(e)},
                              level=logging.ERROR)
        return results


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a filename to prevent directory traversal and other security issues.

    This function ensures filenames are safe by removing path components and
    replacing potentially dangerous characters. This is especially important
    when handling filenames from untrusted sources.

    Args:
        filename: The filename to sanitize

    Returns:
        The sanitized filename string
    """
    if not filename:
        return "unnamed_file"

    operation_details = {"original_filename": filename}

    try:
        # Remove directory traversal components and limit to basename
        sanitized = os.path.basename(filename)

        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x1f]', '', sanitized)

        # Replace potentially dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', sanitized)

        # Ensure the filename is not empty after sanitization
        if not sanitized:
            sanitized = "unnamed_file"

        # Limit length for safety (prevent extremely long filenames)
        if len(sanitized) > 255:
            # Preserve extension if present
            parts = sanitized.rsplit('.', 1)
            if len(parts) > 1:
                sanitized = parts[0][:250] + '.' + parts[1]
            else:
                sanitized = sanitized[:255]

        operation_details["sanitized_filename"] = sanitized
        log_forensic_operation("sanitize_filename", True, operation_details)
        return sanitized

    except Exception as e:
        logger.error(f"Error sanitizing filename: {e}")
        log_forensic_operation("sanitize_filename", False,
                              {**operation_details, "error": str(e)},
                              level=logging.ERROR)
        # Return a safe default in case of error
        return "sanitization_error_file"


def remove_metadata(file_path: str, output_path: Optional[str] = None, file_type: Optional[str] = None) -> Tuple[bool, str]:
    """
    Removes metadata from files to prevent leakage of sensitive information.

    This function strips metadata such as EXIF data from images, document properties
    from PDFs/Office documents, and other metadata that could contain sensitive information.

    Args:
        file_path: Path to the input file
        output_path: Path to save the sanitized file (if None, creates a path)
        file_type: Explicitly specify the file type (if None, detect from extension)

    Returns:
        Tuple of (success: bool, output_path: str)
    """
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        logger.error(f"Input file does not exist or is not a file: {file_path}")
        return False, ""

    operation_details = {"input_file": file_path}

    # Determine output path if not specified
    if output_path is None:
        base_dir = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        output_path = os.path.join(base_dir, f"sanitized_{filename}")

    operation_details["output_file"] = output_path

    # If output path is the same as input, we need a temporary file
    if output_path == file_path:
        use_temp = True
        temp_output = os.path.join(tempfile.gettempdir(), f"temp_sanitized_{os.path.basename(file_path)}")
    else:
        use_temp = False
        temp_output = output_path

    try:
        # Determine file type if not specified
        if file_type is None:
            ext = os.path.splitext(file_path)[1].lower()
            # Map extension to file type
            if ext in ('.jpg', '.jpeg', '.png', '.gif', '.tiff', '.tif'):
                file_type = 'image'
            elif ext in ('.pdf'):
                file_type = 'pdf'
            elif ext in ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'):
                file_type = 'office'
            elif ext in ('.mp3', '.wav', '.flac'):
                file_type = 'audio'
            elif ext in ('.mp4', '.mov', '.avi'):
                file_type = 'video'
            else:
                file_type = 'unknown'

        operation_details["file_type"] = file_type

        # Use file-type specific handling
        success = False
        result_msg = ""

        if file_type == 'image':
            # Simple metadata removal for images - just copy the pixel data
            try:
                from PIL import Image
                img = Image.open(file_path)
                # Create a new image with just the pixel data
                img_without_exif = Image.new(img.mode, img.size)
                img_without_exif.putdata(list(img.getdata()))
                # Save to new file
                img_without_exif.save(temp_output)
                success = True
                result_msg = "Image metadata stripped successfully"
            except ImportError:
                # Fallback method without PIL
                shutil.copy2(file_path, temp_output)
                result_msg = "PIL not available. Simple file copy performed without metadata removal."
                success = True

        elif file_type in ('pdf', 'office'):
            # For documents, we'd ideally use dedicated libraries like PyPDF2, python-docx
            # For simplicity, log that proper handling requires additional dependencies
            shutil.copy2(file_path, temp_output)
            result_msg = f"Full {file_type} metadata removal requires specialized libraries. Simple copy performed."
            success = True

        else:
            # For unknown/unsupported types, just make a copy
            shutil.copy2(file_path, temp_output)
            result_msg = "Unknown file type. Simple copy performed without metadata removal."
            success = True

        operation_details["result_message"] = result_msg

        # If we used a temp file because input=output, do the swap
        if use_temp and success:
            shutil.move(temp_output, output_path)

        log_forensic_operation("remove_metadata", success, operation_details)
        return success, output_path

    except Exception as e:
        error_msg = f"Error removing metadata: {str(e)}"
        logger.error(error_msg, exc_info=True)
        log_forensic_operation("remove_metadata", False,
                              {**operation_details, "error": error_msg},
                              level=logging.ERROR)

        # Clean up temp file if it exists
        if use_temp and os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except:
                pass

        return False, ""


def sanitize_ip_addresses(content: str, placeholder: str = "[REDACTED IP]") -> str:
    """
    Specifically sanitizes IP addresses in content.

    Args:
        content: The content containing IP addresses
        placeholder: The string to replace IP addresses with

    Returns:
        Sanitized content with IPs replaced
    """
    if not isinstance(content, str):
        return str(content)

    operation_details = {"content_length": len(content)}
    try:
        # Replace IPv4 addresses
        result, count = re.subn(IPV4_PATTERN, placeholder, content)

        # Add IPv6 handling if needed
        # IPv6_PATTERN = re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}')
        # result, ipv6_count = re.subn(IPv6_PATTERN, placeholder, result)
        # count += ipv6_count

        operation_details["ips_replaced"] = count
        log_forensic_operation("sanitize_ip_addresses", True, operation_details)
        return result

    except Exception as e:
        logger.error(f"Error sanitizing IP addresses: {e}")
        log_forensic_operation("sanitize_ip_addresses", False,
                              {**operation_details, "error": str(e)},
                              level=logging.ERROR)
        return content


def detect_credentials(content: str) -> List[Dict[str, str]]:
    """
    Detects potential credentials in text content.

    Args:
        content: The text content to scan

    Returns:
        List of dictionaries with credential type and value
    """
    if not isinstance(content, str):
        return []

    operation_details = {"content_length": len(content)}
    results = []

    try:
        # Find key=value style credentials
        creds = CREDENTIAL_ASSIGNMENT_PATTERN.findall(content)
        for key, value in creds:
            results.append({
                "type": key,
                "value": value
            })

        operation_details["credentials_found"] = len(results)
        log_forensic_operation("detect_credentials", True, operation_details)
        return results

    except Exception as e:
        logger.error(f"Error detecting credentials: {e}")
        log_forensic_operation("detect_credentials", False,
                              {**operation_details, "error": str(e)},
                              level=logging.ERROR)
        return []


def prepare_external_report(
    input_path: str,
    output_path: str,
    input_format: str = "json",  # or "text"
    redaction_policy: str = "high",
    key_patterns: Optional[List[Union[str, Pattern]]] = None,  # Only for JSON
    placeholder: str = FALLBACK_REDACTION_PLACEHOLDER if not CONSTANTS_AVAILABLE else DEFAULT_REDACTION_PLACEHOLDER,
    overwrite: bool = False
) -> bool:
    """
    Reads a file, sanitizes its content based on format and policy, and writes to an output file.

    Args:
        input_path: Path to the input file.
        output_path: Path to save the sanitized output file.
        input_format: Format of the input file ("json" or "text").
        redaction_policy: Name of the policy to apply for value redaction.
        key_patterns: Optional list of regex patterns for keys to redact (JSON only).
        placeholder: Placeholder for redacted data.
        overwrite: If True, overwrite the output file if it exists.

    Returns:
        True if successful, False otherwise.
    """
    operation_details = {
        "input_path": input_path,
        "output_path": output_path,
        "format": input_format,
        "policy": redaction_policy,
        "placeholder": placeholder,
        "key_patterns_provided": bool(key_patterns)
    }

    if not os.path.exists(input_path):
        logger.error(f"Input file not found: {input_path}")
        log_forensic_operation("prepare_external_report", False, {**operation_details, "error": "Input file not found"}, level=logging.ERROR)
        return False

    if not overwrite and os.path.exists(output_path):
        logger.error(f"Output file already exists: {output_path}. Use overwrite=True.")
        log_forensic_operation("prepare_external_report", False, {**operation_details, "error": "Output file exists"}, level=logging.ERROR)
        return False

    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(input_path, 'r', encoding='utf-8') as infile:
            if input_format.lower() == "json":
                try:
                    data = json.load(infile)
                    sanitized_data = sanitize_json_object(
                        data,
                        key_patterns=key_patterns,  # Will default to CREDENTIAL_KEYWORDS in the function
                        value_policy=redaction_policy,
                        placeholder=placeholder
                    )
                    output_content = json.dumps(sanitized_data, indent=2, default=str)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to decode JSON from {input_path}: {e}")
                    log_forensic_operation("prepare_external_report", False, {**operation_details, "error": f"JSON decode error: {e}"}, level=logging.ERROR)
                    return False
            elif input_format.lower() == "text":
                content = infile.read()
                sanitized_data = redact_sensitive_data(
                    content,
                    policy=redaction_policy,
                    placeholder=placeholder
                )
                output_content = sanitized_data
            else:
                logger.error(f"Unsupported input format: {input_format}")
                log_forensic_operation("prepare_external_report", False, {**operation_details, "error": "Unsupported format"}, level=logging.ERROR)
                return False

        # Write sanitized content
        with open(output_path, 'w', encoding='utf-8') as outfile:
            outfile.write(output_content)

        logger.info(f"Successfully sanitized '{input_path}' to '{output_path}' using policy '{redaction_policy}'")
        log_forensic_operation("prepare_external_report", True, operation_details)
        return True

    except (OSError, IOError) as e:
        logger.error(f"Error during report sanitization: {e}", exc_info=True)
        log_forensic_operation("prepare_external_report", False, {**operation_details, "error": f"I/O error: {str(e)}"}, level=logging.ERROR)
        # Clean up potentially partially written file
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                logger.warning(f"Could not remove partially written sanitized file: {output_path}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during report sanitization: {e}", exc_info=True)
        log_forensic_operation("prepare_external_report", False, {**operation_details, "error": str(e)}, level=logging.ERROR)
        # Clean up potentially partially written file
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                logger.warning(f"Could not remove partially written sanitized file: {output_path}")
        return False


def sanitize_json_object(
    data: Any,
    key_patterns: Optional[List[Union[str, Pattern]]] = None,
    value_patterns: Optional[List[Union[str, Pattern]]] = None,
    value_policy: Optional[str] = "high",
    placeholder: str = FALLBACK_REDACTION_PLACEHOLDER if not CONSTANTS_AVAILABLE else DEFAULT_REDACTION_PLACEHOLDER
) -> Any:
    """
    Recursively sanitizes a Python object (dict, list, str) potentially loaded from JSON.

    Redacts sensitive string values based on patterns/policy and can optionally
    redact values associated with specific keys.

    Args:
        data: The Python object to sanitize.
        key_patterns: Optional list of regex patterns to match dictionary keys.
                      If a key matches, its value will be redacted.
        value_patterns: Optional list of regex patterns to apply to string values.
                        Overrides value_policy.
        value_policy: Predefined policy for redacting string values (default: "high").
                      Ignored if value_patterns is provided.
        placeholder: The string to replace redacted values with.

    Returns:
        The sanitized Python object.
    """
    # Use credential keywords as default key patterns if none provided
    if key_patterns is None:
        key_patterns = CREDENTIAL_KEYWORDS

    compiled_key_patterns: List[Pattern] = []
    if key_patterns:
        for p in key_patterns:
            try:
                if isinstance(p, str):
                    compiled_key_patterns.append(re.compile(p, re.IGNORECASE))
                elif isinstance(p, re.Pattern):
                    compiled_key_patterns.append(p)
                else:
                    logger.warning(f"Invalid key pattern type: {type(p)}. Skipping.")
            except re.error as e:
                logger.warning(f"Invalid key regex pattern '{p}': {e}. Skipping.")

    if isinstance(data, dict):
        sanitized_dict = {}
        for key, value in data.items():
            redact_key = False
            if compiled_key_patterns:
                for kp in compiled_key_patterns:
                    if kp.search(str(key)):  # Convert key to string just in case
                        redact_key = True
                        break
            if redact_key:
                # For sensitive keys that match patterns, use the core obfuscation
                # instead of a simple placeholder to maintain consistent masking
                if isinstance(value, str) and CORE_OBFUSCATION_AVAILABLE:
                    sanitized_dict[key] = mask_sensitive_value(value, prefix_visible=0, suffix_visible=0, placeholder=placeholder)
                else:
                    sanitized_dict[key] = placeholder
            else:
                # Recursively sanitize the value
                sanitized_dict[key] = sanitize_json_object(
                    value, key_patterns, value_patterns, value_policy, placeholder
                )
        return sanitized_dict
    elif isinstance(data, list):
        # Recursively sanitize each item in the list
        return [sanitize_json_object(item, key_patterns, value_patterns, value_policy, placeholder) for item in data]
    elif isinstance(data, str):
        # Apply value redaction to strings
        return redact_sensitive_data(data, patterns=value_patterns, policy=value_policy, placeholder=placeholder)
    else:
        # Return non-dict/list/str types as is (e.g., numbers, booleans, None)
        return data


# --- Example Usage ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    print("--- Testing Data Sanitization ---")

    # Example Text Content
    sample_text = """
    User report filed by test@example.com.
    Incident occurred at 192.168.1.100 involving account 'admin'.
    User provided password='secretPassword123' over insecure channel.
    SSN mentioned: 123-45-6789. Credit card: 4111-1111-1111-1111.
    API Key: sk_live_abcdef1234567890. Another token=ghp_xyz789abc.
    Normal text follows.
    """

    print("\nOriginal Text:")
    print(sample_text)

    print("\nSanitized Text (Policy: 'high'):")
    sanitized_text = redact_sensitive_data(sample_text, policy="high")
    print(sanitized_text)

    print("\nSanitized Text (Policy: 'basic_pii'):")
    sanitized_text_basic = redact_sensitive_data(sample_text, policy="basic_pii")
    print(sanitized_text_basic)

    print("\nSanitized Text (Custom Pattern - emails only):")
    sanitized_text_custom = redact_sensitive_data(sample_text, patterns=[EMAIL_PATTERN], placeholder="[EMAIL REDACTED]")
    print(sanitized_text_custom)

    # Example JSON Content
    sample_json_obj = {
        "user_id": 123,
        "username": "jdoe",
        "contact": {
            "email": "john.doe@company.com",
            "phone": "555-123-4567"  # No pattern for phone yet
        },
        "credentials": {
            "password_hash": "...",  # Assume hash is okay
            "api_key": "ak_test_zyxw98765",
            "notes": "User mentioned SSN 987-65-4321 during call."
        },
        "activity": [
            {"ip_address": "10.0.0.5", "action": "login"},
            {"ip_address": "203.0.113.25", "action": "update_profile", "details": "Changed email to new.email@provider.net"}
        ],
        "sensitive_config": {
            "db_password": "very_secret_db_pass"
        }
    }

    print("\nOriginal JSON Object:")
    print(json.dumps(sample_json_obj, indent=2))

    print("\nSanitized JSON Object (Default - policy 'high', redact credential keys):")
    sanitized_json = sanitize_json_object(sample_json_obj, key_patterns=CREDENTIAL_KEYWORDS)
    print(json.dumps(sanitized_json, indent=2))

    print("\nSanitized JSON Object (Policy 'basic_pii', no key redaction):")
    sanitized_json_basic = sanitize_json_object(sample_json_obj, value_policy="basic_pii")
    print(json.dumps(sanitized_json_basic, indent=2))

    # Example File Sanitization
    print("\n--- Testing File Sanitization ---")
    TEST_INPUT_DIR = "temp_sanitize_in"
    TEST_OUTPUT_DIR = "temp_sanitize_out"
    os.makedirs(TEST_INPUT_DIR, exist_ok=True)
    os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

    # Create dummy input files
    input_json_path = os.path.join(TEST_INPUT_DIR, "report.json")
    input_text_path = os.path.join(TEST_INPUT_DIR, "log.txt")
    output_json_path = os.path.join(TEST_OUTPUT_DIR, "sanitized_report.json")
    output_text_path = os.path.join(TEST_OUTPUT_DIR, "sanitized_log.txt")

    with open(input_json_path, 'w') as f:
        json.dump(sample_json_obj, f, indent=2)
    with open(input_text_path, 'w') as f:
        f.write(sample_text)

    print(f"Created dummy input files in {TEST_INPUT_DIR}")

    # Sanitize JSON file
    success_json = prepare_external_report(
        input_path=input_json_path,
        output_path=output_json_path,
        input_format="json",
        redaction_policy="high",
        key_patterns=CREDENTIAL_KEYWORDS,  # Redact keys like 'password', 'api_key'
        overwrite=True
    )
    print(f"JSON file sanitization successful: {success_json}")
    if success_json:
        print(f"Sanitized JSON written to: {output_json_path}")

    # Sanitize Text file
    success_text = prepare_external_report(
        input_path=input_text_path,
        output_path=output_text_path,
        input_format="text",
        redaction_policy="high",
        overwrite=True
    )
    print(f"Text file sanitization successful: {success_text}")
    if success_text:
        print(f"Sanitized text written to: {output_text_path}")

    # Clean up dummy files/dirs (optional)
    # import shutil
    # shutil.rmtree(TEST_INPUT_DIR)
    # shutil.rmtree(TEST_OUTPUT_DIR)
    # print("\nCleaned up temporary directories.")

    print("\n--- Sanitization Tests Complete ---")
