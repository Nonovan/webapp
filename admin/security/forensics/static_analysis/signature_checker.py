"""
Signature Checker Tool for Forensic Static Analysis

This tool verifies file signatures, checks against known malware hash databases,
and performs YARA rule matching as part of the static analysis process within
the Cloud Infrastructure Platform's Forensic Analysis Toolkit.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, Any, List, Optional

# Attempt to import common forensic and static analysis utilities
try:
    # Common file operations and analysis
    from admin.security.forensics.static_analysis.common.file_utils import (
        safe_analyze_file,
        calculate_hash,
        save_analysis_report
    )
    # Signature database management
    from admin.security.forensics.static_analysis.common.signature_db import SignatureDBManager
    # YARA scanning capabilities
    from admin.security.forensics.static_analysis.common.yara_rules import YaraScanner
    # Core forensic logging
    from admin.security.forensics.utils.logging_utils import (
        setup_forensic_logger,
        log_forensic_operation
    )
    # Validation utilities
    from admin.security.forensics.utils.validation_utils import validate_path

    FORENSIC_CORE_AVAILABLE = True
    SIGNATURE_DB_AVAILABLE = True
    YARA_SCANNER_AVAILABLE = True

except ImportError as e:
    # Fallback if core forensic utilities are not available
    print(f"Warning: Critical forensic modules could not be imported: {e}. Functionality may be limited.")
    # Define dummy functions or basic fallbacks if necessary
    FORENSIC_CORE_AVAILABLE = False
    SIGNATURE_DB_AVAILABLE = False
    YARA_SCANNER_AVAILABLE = False

    # Basic logging setup if forensic logger fails
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('signature_checker_fallback')

    # Dummy log function
    def log_forensic_operation(operation: str, success: bool, details: Dict[str, Any], level=logging.INFO):
        logger.log(level, f"Operation '{operation}' {'succeeded' if success else 'failed'}. Details: {details}")

    # Dummy validation
    def validate_path(path_str: str, **kwargs) -> tuple[bool, str]:
        if not os.path.exists(path_str):
            return False, f"Path does not exist: {path_str}"
        if not os.path.isfile(path_str):
            return False, f"Path is not a file: {path_str}"
        return True, "Path is valid"

    # Dummy save function
    def save_analysis_report(data: Dict[str, Any], output_path: str, format: str = "json") -> bool:
        try:
            with open(output_path, 'w') as f:
                if format == 'json':
                    json.dump(data, f, indent=4)
                else: # Basic text fallback
                    for key, value in data.items():
                        f.write(f"{key}: {value}\n")
            logger.info(f"Fallback report saved to {output_path}")
            return True
        except Exception as ex:
            logger.error(f"Fallback save failed: {ex}")
            return False

    # Dummy hash function
    def calculate_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        import hashlib
        try:
            hasher = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as ex:
            logger.error(f"Fallback hash calculation failed: {ex}")
            return None

# Setup logger if core utils are available
if FORENSIC_CORE_AVAILABLE:
    setup_forensic_logger()
    logger = logging.getLogger('forensic_signature_checker')
else:
    # Use the fallback logger defined above
    pass


# --- Constants ---
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_OUTPUT_FORMATS = ["json", "text"]
DEFAULT_HASH_ALGORITHM = "sha256" # Align with common.hash_utils if possible


# --- Core Functions ---

def check_malware_signatures(file_path: str, db_manager: Optional[Any]) -> Dict[str, Any]:
    """
    Check the file's hash against known malware signature databases.
    """
    results = {"status": "skipped", "matches": []}
    if not SIGNATURE_DB_AVAILABLE or db_manager is None:
        results["status"] = "error"
        results["error_message"] = "SignatureDBManager not available."
        logger.warning("Malware signature check skipped: SignatureDBManager not available.")
        return results

    logger.info(f"Checking malware signatures for: {file_path}")
    try:
        # Calculate hash (use common util if available, else fallback)
        file_hash = calculate_hash(file_path, algorithm=DEFAULT_HASH_ALGORITHM)
        if not file_hash:
            results["status"] = "error"
            results["error_message"] = "Failed to calculate file hash."
            return results

        results["file_hash"] = file_hash
        matches = db_manager.check_malware_signatures(file_path=file_path, file_hash=file_hash)

        if matches:
            results["status"] = "detected"
            results["matches"] = [match.to_dict() for match in matches] # Assuming match object has to_dict()
            logger.warning(f"Malware signatures detected for {file_path}: {len(matches)} matches.")
        else:
            results["status"] = "clean"
            logger.info(f"No known malware signatures found for {file_path}.")

    except Exception as e:
        logger.error(f"Error checking malware signatures for {file_path}: {e}", exc_info=True)
        results["status"] = "error"
        results["error_message"] = str(e)

    return results

def scan_with_yara(file_path: str, yara_scanner: Optional[Any], rules_path: Optional[str]) -> Dict[str, Any]:
    """
    Scan the file using YARA rules.
    """
    results = {"status": "skipped", "matches": []}
    if not YARA_SCANNER_AVAILABLE or yara_scanner is None:
        results["status"] = "error"
        results["error_message"] = "YaraScanner not available."
        logger.warning("YARA scan skipped: YaraScanner not available.")
        return results

    if not rules_path:
        results["status"] = "skipped"
        results["error_message"] = "No YARA rules path provided."
        logger.info("YARA scan skipped: No rules path provided.")
        return results

    logger.info(f"Scanning {file_path} with YARA rules from: {rules_path}")
    try:
        # Load rules if not already loaded by the scanner instance
        # yara_scanner.load_rules(rules_path) # Assuming scanner has such a method

        matches = yara_scanner.scan_file(file_path, rules_path=rules_path) # Pass rules_path if needed

        if matches:
            results["status"] = "detected"
            # Format matches appropriately - depends on YaraScanner implementation
            results["matches"] = [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in matches]
            logger.warning(f"YARA rule matches found for {file_path}: {len(matches)} rules.")
        else:
            results["status"] = "clean"
            logger.info(f"No YARA rule matches found for {file_path}.")

    except Exception as e:
        logger.error(f"Error scanning {file_path} with YARA: {e}", exc_info=True)
        results["status"] = "error"
        results["error_message"] = str(e)

    return results

def verify_code_signature(file_path: str, db_manager: Optional[Any]) -> Dict[str, Any]:
    """
    Verify the digital code signing signature of the file.
    """
    results = {"status": "skipped", "details": {}}
    if not SIGNATURE_DB_AVAILABLE or db_manager is None:
        results["status"] = "error"
        results["error_message"] = "SignatureDBManager not available."
        logger.warning("Code signature verification skipped: SignatureDBManager not available.")
        return results

    logger.info(f"Verifying code signature for: {file_path}")
    try:
        # This relies heavily on the implementation of SignatureDBManager.verify_code_signature
        # It might need platform-specific tools or libraries (e.g., pefile, macholib, osslsigncode)
        verification_status = db_manager.verify_code_signature(file_path)

        if verification_status.verified:
            results["status"] = "verified"
            results["details"] = verification_status.to_dict() # Assuming status object has to_dict()
            logger.info(f"Code signature verified for {file_path}. Signer: {verification_status.signer_name}")
        elif verification_status.verification_attempted:
             results["status"] = "invalid"
             results["details"] = verification_status.to_dict()
             logger.warning(f"Invalid code signature for {file_path}. Reason: {verification_status.reason}")
        else:
             results["status"] = "not_signed_or_unsupported"
             results["details"] = {"message": "File is likely not signed or format is unsupported."}
             logger.info(f"No verifiable code signature found for {file_path}.")

    except Exception as e:
        logger.error(f"Error verifying code signature for {file_path}: {e}", exc_info=True)
        results["status"] = "error"
        results["error_message"] = str(e)

    return results


# --- Main Execution ---

def main() -> int:
    """Main function to parse arguments and orchestrate signature checks."""
    parser = argparse.ArgumentParser(
        description="Forensic Signature Checker: Verify file signatures, check malware DB, and run YARA scans."
    )
    parser.add_argument("--file", required=True, help="Path to the file to analyze.")
    parser.add_argument("--check-signatures", action="store_true", help="Check file hash against known malware databases.")
    parser.add_argument("--yara-rules", help="Path to a YARA rule file or directory.")
    parser.add_argument("--verify-signature", action="store_true", help="Verify the digital code signing signature (if applicable).")
    parser.add_argument("--output", help="Path to save the analysis report.")
    parser.add_argument("--output-format", choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT, help="Format for the output report.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--case-id", help="Case ID for forensic logging.")
    parser.add_argument("--analyst", help="Analyst name for forensic logging.")

    args = parser.parse_args()

    # Adjust logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Forensic operation logging context
    operation_details = {
        "tool": "signature_checker",
        "file_path": args.file,
        "checks_requested": {
            "malware_db": args.check_signatures,
            "yara": bool(args.yara_rules),
            "code_signing": args.verify_signature
        },
        "output_path": args.output,
        "output_format": args.output_format,
        "case_id": args.case_id,
        "analyst": args.analyst
    }
    log_forensic_operation("signature_check_start", True, operation_details, level=logging.INFO)

    # Validate input file path
    is_valid, validation_msg = validate_path(args.file, must_be_file=True, check_read=True)
    if not is_valid:
        logger.error(f"Input file validation failed: {validation_msg}")
        operation_details["error"] = validation_msg
        log_forensic_operation("signature_check_error", False, operation_details, level=logging.ERROR)
        return 1

    analysis_results: Dict[str, Any] = {
        "file_path": args.file,
        "analysis_summary": {},
    }

    # Initialize common components if available
    db_manager = None
    yara_scanner = None
    if SIGNATURE_DB_AVAILABLE:
        try:
            # Determine the root path for signature DBs, might need configuration
            # Example: Using a path relative to this script or an environment variable
            common_dir = os.path.dirname(os.path.abspath(__file__)) + "/common"
            db_root = os.path.join(common_dir, 'signature_db')
            logger.debug(f"Initializing SignatureDBManager with root: {db_root}")
            db_manager = SignatureDBManager(db_root=db_root)
        except Exception as e:
            logger.error(f"Failed to initialize SignatureDBManager: {e}", exc_info=True)
            SIGNATURE_DB_AVAILABLE = False # Disable checks relying on it
            analysis_results["initialization_error"] = f"SignatureDBManager failed: {e}"

    if YARA_SCANNER_AVAILABLE:
        try:
            logger.debug("Initializing YaraScanner.")
            yara_scanner = YaraScanner()
        except Exception as e:
            logger.error(f"Failed to initialize YaraScanner: {e}", exc_info=True)
            YARA_SCANNER_AVAILABLE = False # Disable checks relying on it
            analysis_results["initialization_error"] = f"YaraScanner failed: {e}"


    # --- Perform Requested Checks ---
    if args.check_signatures:
        analysis_results["malware_signature_check"] = check_malware_signatures(args.file, db_manager)

    if args.yara_rules:
        analysis_results["yara_scan"] = scan_with_yara(args.file, yara_scanner, args.yara_rules)

    if args.verify_signature:
        analysis_results["code_signature_verification"] = verify_code_signature(args.file, db_manager)

    # --- Generate Summary ---
    summary = {}
    if "malware_signature_check" in analysis_results:
        summary["malware_db_status"] = analysis_results["malware_signature_check"]["status"]
    if "yara_scan" in analysis_results:
        summary["yara_scan_status"] = analysis_results["yara_scan"]["status"]
    if "code_signature_verification" in analysis_results:
        summary["code_signing_status"] = analysis_results["code_signature_verification"]["status"]
    analysis_results["analysis_summary"] = summary

    # --- Save or Print Results ---
    report_saved = False
    if args.output:
        logger.info(f"Saving analysis results to: {args.output} in {args.output_format} format.")
        # Use the common save function if available
        report_saved = save_analysis_report(analysis_results, args.output, format=args.output_format)
        if not report_saved:
            logger.error(f"Failed to save report to {args.output}")
    else:
        # Print to stdout if no output file specified
        if args.output_format == 'json':
            print(json.dumps(analysis_results, indent=4))
        else: # Basic text output
            print("--- Signature Check Report ---")
            print(f"File: {analysis_results['file_path']}")
            print("\nSummary:")
            for key, value in analysis_results.get("analysis_summary", {}).items():
                print(f"  {key}: {value}")

            if "malware_signature_check" in analysis_results:
                print("\nMalware Signature Check:")
                print(f"  Status: {analysis_results['malware_signature_check']['status']}")
                if analysis_results['malware_signature_check'].get('matches'):
                    print(f"  Matches ({len(analysis_results['malware_signature_check']['matches'])}):")
                    for match in analysis_results['malware_signature_check']['matches'][:5]: # Show first 5
                        print(f"    - Name: {match.get('name', 'N/A')}, Source: {match.get('source', 'N/A')}")

            if "yara_scan" in analysis_results:
                print("\nYARA Scan:")
                print(f"  Status: {analysis_results['yara_scan']['status']}")
                if analysis_results['yara_scan'].get('matches'):
                    print(f"  Matches ({len(analysis_results['yara_scan']['matches'])}):")
                    for match in analysis_results['yara_scan']['matches'][:5]: # Show first 5
                        print(f"    - Rule: {match.get('rule', 'N/A')}, Tags: {match.get('tags', [])}")

            if "code_signature_verification" in analysis_results:
                print("\nCode Signature Verification:")
                print(f"  Status: {analysis_results['code_signature_verification']['status']}")
                details = analysis_results['code_signature_verification'].get('details', {})
                if details.get('signer_name'):
                    print(f"  Signer: {details['signer_name']}")
                if details.get('reason'):
                    print(f"  Reason: {details['reason']}")

            print("\n--- End of Report ---")


    # Final forensic log
    operation_details["summary"] = summary
    log_forensic_operation("signature_check_complete", True, operation_details, level=logging.INFO)

    # Determine exit code (0 for success, 1 for errors during analysis, 2 for detection if needed)
    exit_code = 0
    if any(v.get("status") == "error" for k, v in analysis_results.items() if isinstance(v, dict)):
        exit_code = 1
    # Optionally, exit with 2 if malware/YARA rules detected
    # elif any(v.get("status") == "detected" for k, v in analysis_results.items() if isinstance(v, dict)):
    #     exit_code = 2

    return exit_code

if __name__ == "__main__":
    sys.exit(main())
