"""
Chain of Custody Module for Forensic Analysis Toolkit.

This module provides functionality for maintaining the chain of custody for digital evidence
throughout its lifecycle, from acquisition through analysis and disposition. It ensures
proper documentation of all evidence handling to maintain integrity and admissibility
in legal proceedings.

Functions include:
- Creating and managing chain of custody records
- Tracking evidence transfers and access
- Validating evidence integrity through hashing
- Generating chain of custody reports in various formats
- Validating the completeness of chain of custody documentation
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

# Configure logging
logger = logging.getLogger(__name__)

try:
    # Import from forensics package
    from admin.security.forensics.utils.evidence_tracker import (
        register_evidence,
        track_access,
        track_analysis,
        get_chain_of_custody,
        update_evidence_details,
        get_evidence_details,
        transfer_evidence,
        verify_evidence_integrity,
        export_chain_of_custody
    )
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
    from admin.security.forensics.utils.crypto import calculate_file_hash, verify_file_hash
    from admin.security.forensics.utils.forensic_constants import (
        DEFAULT_HASH_ALGORITHM,
        DEFAULT_READ_ONLY_FILE_PERMS,
        EVIDENCE_METADATA_DIR
    )

    FORENSIC_UTILS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import one or more forensic utilities: {e}")
    FORENSIC_UTILS_AVAILABLE = False

    # Define fallback functions
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict[str, Any]] = None) -> None:
        """Basic logging function when forensic utilities are unavailable."""
        level = logging.INFO if success else logging.ERROR
        msg = f"Operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logger.log(level, msg)


class ChainOfCustody:
    """
    Manages chain of custody for digital evidence.

    This class provides methods for documenting evidence handling, transfers,
    access events, and integrity verification to maintain a proper chain of custody.
    """

    def __init__(self, case_id: str, analyst: str = None):
        """
        Initialize a Chain of Custody manager for a specific case.

        Args:
            case_id: Identifier for the case the evidence belongs to
            analyst: Name or ID of the analyst managing the evidence
        """
        self.case_id = case_id
        self.analyst = analyst or os.environ.get("USER", "unknown")
        log_forensic_operation("chain_of_custody_init", True, {
            "case_id": case_id,
            "analyst": self.analyst
        })

    def register_item(self,
                      file_path: str,
                      evidence_type: str,
                      description: str = None,
                      acquisition_method: str = "manual",
                      source_location: str = None) -> Dict[str, Any]:
        """
        Register a new evidence item and establish initial chain of custody.

        Args:
            file_path: Path to the evidence file
            evidence_type: Type of evidence (e.g., "memory_dump", "disk_image", "log_file")
            description: Optional description of the evidence
            acquisition_method: Method used to acquire the evidence
            source_location: Location where the evidence was acquired from

        Returns:
            Dictionary with registration details including evidence_id
        """
        if not FORENSIC_UTILS_AVAILABLE:
            raise RuntimeError("Forensic utilities not available")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        # Calculate hash for the evidence file
        file_hash = calculate_file_hash(file_path)

        # Register the evidence
        evidence_data = {
            "file_path": file_path,
            "evidence_type": evidence_type,
            "description": description or f"{evidence_type} from {source_location or 'unknown source'}",
            "acquisition_method": acquisition_method,
            "source_identifier": source_location,
            "acquisition_tool": "chain_of_custody.py",
            "analyst": self.analyst,
            "case_id": self.case_id,
            "hash_algorithm": DEFAULT_HASH_ALGORITHM,
            "hash_value": file_hash,
            "classification": "confidential"
        }

        result = register_evidence(**evidence_data)

        log_forensic_operation("register_evidence_item", result.get("success", False), {
            "evidence_id": result.get("evidence_id"),
            "case_id": self.case_id,
            "file": os.path.basename(file_path),
            "hash": file_hash
        })

        return result

    def record_access(self,
                      evidence_id: str,
                      purpose: str,
                      action: str = "access") -> bool:
        """
        Record an access to an evidence item in the chain of custody.

        Args:
            evidence_id: ID of the evidence being accessed
            purpose: Reason for accessing the evidence
            action: Type of access (e.g., "access", "view", "analyze", "copy")

        Returns:
            True if the access was recorded successfully, False otherwise
        """
        if not FORENSIC_UTILS_AVAILABLE:
            logger.error("Cannot record access: forensic utilities not available")
            return False

        return track_access(
            case_id=self.case_id,
            evidence_id=evidence_id,
            analyst=self.analyst,
            action=action,
            purpose=purpose,
            timestamp=datetime.now(timezone.utc)
        )

    def record_analysis(self,
                        evidence_id: str,
                        analysis_type: str,
                        findings: Dict[str, Any]) -> bool:
        """
        Record analysis performed on an evidence item.

        Args:
            evidence_id: ID of the evidence being analyzed
            analysis_type: Type of analysis performed
            findings: Summary of analysis findings

        Returns:
            True if the analysis was recorded successfully, False otherwise
        """
        if not FORENSIC_UTILS_AVAILABLE:
            logger.error("Cannot record analysis: forensic utilities not available")
            return False

        details = {
            "analysis_type": analysis_type,
            "findings_summary": findings.get("summary", "No summary provided"),
            "tools_used": findings.get("tools_used", [])
        }

        purpose = f"Perform {analysis_type} analysis"

        return track_analysis(
            case_id=self.case_id,
            evidence_id=evidence_id,
            analyst=self.analyst,
            action="analysis",
            purpose=purpose,
            details=details
        )

    def transfer_item(self,
                      evidence_id: str,
                      new_location: str,
                      reason: str,
                      verify_after: bool = True) -> bool:
        """
        Record the transfer of an evidence item to a new location.

        Args:
            evidence_id: ID of the evidence being transferred
            new_location: New location for the evidence
            reason: Reason for the transfer
            verify_after: Whether to verify evidence integrity after transfer

        Returns:
            True if the transfer was recorded successfully, False otherwise
        """
        if not FORENSIC_UTILS_AVAILABLE:
            logger.error("Cannot transfer evidence: forensic utilities not available")
            return False

        return transfer_evidence(
            case_id=self.case_id,
            evidence_id=evidence_id,
            analyst=self.analyst,
            new_location=new_location,
            transfer_reason=reason,
            verify_after_transfer=verify_after
        )

    def verify_integrity(self,
                         evidence_id: str,
                         file_path: Optional[str] = None) -> bool:
        """
        Verify the integrity of an evidence item.

        Args:
            evidence_id: ID of the evidence to verify
            file_path: Optional path to the file to verify (if different from registered path)

        Returns:
            True if integrity is verified, False otherwise
        """
        if not FORENSIC_UTILS_AVAILABLE:
            logger.error("Cannot verify evidence integrity: forensic utilities not available")
            return False

        return verify_evidence_integrity(
            case_id=self.case_id,
            evidence_id=evidence_id,
            analyst=self.analyst,
            file_path=file_path
        )

    def get_custody_history(self, evidence_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve the chain of custody history for an evidence item or entire case.

        Args:
            evidence_id: Optional ID of a specific evidence item

        Returns:
            List of chain of custody entries
        """
        if not FORENSIC_UTILS_AVAILABLE:
            logger.error("Cannot retrieve custody history: forensic utilities not available")
            return []

        return get_chain_of_custody(self.case_id, evidence_id)

    def export_history(self,
                       evidence_id: Optional[str] = None,
                       format_type: str = "pdf",
                       output_path: Optional[str] = None) -> Optional[str]:
        """
        Export the chain of custody history to a file.

        Args:
            evidence_id: Optional ID of a specific evidence item
            format_type: Output format (pdf, html, json, csv, text)
            output_path: Optional path to save the output file

        Returns:
            Path to the exported file, or None if export failed
        """
        if not FORENSIC_UTILS_AVAILABLE:
            logger.error("Cannot export custody history: forensic utilities not available")
            return None

        return export_chain_of_custody(
            case_id=self.case_id,
            evidence_id=evidence_id,
            output_path=output_path,
            format=format_type,
            include_signatures=True
        )

    def validate_custody_chain(self, evidence_id: str) -> Tuple[bool, List[str]]:
        """
        Validate the completeness and integrity of the chain of custody.

        Args:
            evidence_id: ID of the evidence to validate

        Returns:
            Tuple containing (is_valid, list_of_issues)
        """
        if not FORENSIC_UTILS_AVAILABLE:
            logger.error("Cannot validate custody chain: forensic utilities not available")
            return False, ["Forensic utilities not available"]

        # Get evidence details
        evidence = get_evidence_details(self.case_id, evidence_id)
        if not evidence:
            return False, ["Evidence not found"]

        # Get custody history
        custody_history = get_chain_of_custody(self.case_id, evidence_id)
        if not custody_history:
            return False, ["No custody history found"]

        issues = []

        # Check if there's an initial acquisition event
        acquisition_events = [
            entry for entry in custody_history
            if entry.get("action") in ["acquisition", "register", "collect"]
        ]
        if not acquisition_events:
            issues.append("No acquisition event found in custody chain")

        # Check for gaps in custody (time-ordered events)
        custody_history.sort(key=lambda x: x.get("timestamp", ""))
        previous_event = None
        for event in custody_history:
            if previous_event:
                # Check for missing information
                if not event.get("analyst"):
                    issues.append(f"Missing analyst in event at {event.get('timestamp')}")
                if not event.get("action"):
                    issues.append(f"Missing action in event at {event.get('timestamp')}")
                if not event.get("purpose"):
                    issues.append(f"Missing purpose in event at {event.get('timestamp')}")
            previous_event = event

        # Verify the latest integrity check
        integrity_checks = [
            entry for entry in custody_history
            if entry.get("action") in ["integrity_verification", "verify"]
        ]
        if integrity_checks:
            # Get the most recent integrity check
            latest_check = max(integrity_checks, key=lambda x: x.get("timestamp", ""))
            if latest_check.get("details", {}).get("verification_passed") is False:
                issues.append("Latest integrity check failed")
        else:
            issues.append("No integrity verification found in custody chain")

        is_valid = len(issues) == 0

        log_forensic_operation("validate_custody_chain", is_valid, {
            "evidence_id": evidence_id,
            "case_id": self.case_id,
            "issues": len(issues)
        })

        return is_valid, issues


def generate_custody_report(case_id: str, output_dir: str, format_type: str = "pdf") -> Dict[str, Any]:
    """
    Generate chain of custody reports for all evidence in a case.

    Args:
        case_id: ID of the case
        output_dir: Directory to save the output reports
        format_type: Format for output files (pdf, html, json, csv, text)

    Returns:
        Dictionary with result information
    """
    if not FORENSIC_UTILS_AVAILABLE:
        return {
            "success": False,
            "error": "Forensic utilities not available"
        }

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Get list of evidence for the case
    try:
        from admin.security.forensics.utils.evidence_tracker import list_evidence_by_case
        evidence_list = list_evidence_by_case(case_id)
    except (ImportError, AttributeError):
        return {
            "success": False,
            "error": "Unable to list evidence for case"
        }

    if not evidence_list:
        return {
            "success": False,
            "error": f"No evidence found for case {case_id}"
        }

    # Generate case-level report
    case_report_path = export_chain_of_custody(
        case_id=case_id,
        output_path=os.path.join(output_dir, f"chain_of_custody_{case_id}_complete.{format_type}"),
        format=format_type
    )

    # Generate reports for each evidence item
    evidence_reports = []
    for evidence in evidence_list:
        evidence_id = evidence.get("evidence_id")
        if not evidence_id:
            continue

        report_path = export_chain_of_custody(
            case_id=case_id,
            evidence_id=evidence_id,
            output_path=os.path.join(
                output_dir,
                f"chain_of_custody_{case_id}_{evidence_id}.{format_type}"
            ),
            format=format_type
        )

        if report_path:
            evidence_reports.append({
                "evidence_id": evidence_id,
                "description": evidence.get("description", "Unknown"),
                "report_path": report_path
            })

    log_forensic_operation("generate_custody_reports", True, {
        "case_id": case_id,
        "output_dir": output_dir,
        "format": format_type,
        "case_report": case_report_path is not None,
        "evidence_reports": len(evidence_reports)
    })

    return {
        "success": True,
        "case_id": case_id,
        "case_report_path": case_report_path,
        "evidence_reports": evidence_reports,
        "report_count": len(evidence_reports) + (1 if case_report_path else 0)
    }


def validate_case_chain_of_custody(case_id: str) -> Dict[str, Any]:
    """
    Validate the chain of custody for an entire case.

    Args:
        case_id: ID of the case to validate

    Returns:
        Dictionary with validation results
    """
    if not FORENSIC_UTILS_AVAILABLE:
        return {
            "success": False,
            "error": "Forensic utilities not available"
        }

    try:
        from admin.security.forensics.utils.evidence_tracker import list_evidence_by_case
        evidence_list = list_evidence_by_case(case_id)
    except (ImportError, AttributeError):
        return {
            "success": False,
            "error": "Unable to list evidence for case"
        }

    if not evidence_list:
        return {
            "success": False,
            "error": f"No evidence found for case {case_id}"
        }

    custody_manager = ChainOfCustody(case_id)
    validation_results = []

    for evidence in evidence_list:
        evidence_id = evidence.get("evidence_id")
        if not evidence_id:
            continue

        is_valid, issues = custody_manager.validate_custody_chain(evidence_id)

        validation_results.append({
            "evidence_id": evidence_id,
            "description": evidence.get("description", "Unknown"),
            "valid": is_valid,
            "issues": issues
        })

    # Count valid and invalid chains
    valid_count = sum(1 for result in validation_results if result["valid"])

    log_forensic_operation("validate_case_custody", True, {
        "case_id": case_id,
        "evidence_count": len(validation_results),
        "valid_count": valid_count,
        "invalid_count": len(validation_results) - valid_count
    })

    return {
        "success": True,
        "case_id": case_id,
        "evidence_count": len(validation_results),
        "valid_count": valid_count,
        "invalid_count": len(validation_results) - valid_count,
        "results": validation_results
    }


def main() -> int:
    """
    Main function for command line interface.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(
        description="Chain of Custody Management for Digital Evidence"
    )

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Register evidence command
    register_parser = subparsers.add_parser("register", help="Register new evidence and establish chain of custody")
    register_parser.add_argument("--file", required=True, help="Path to evidence file")
    register_parser.add_argument("--case-id", required=True, help="Case identifier")
    register_parser.add_argument("--type", required=True, help="Type of evidence")
    register_parser.add_argument("--description", help="Description of evidence")
    register_parser.add_argument("--source", help="Source location of evidence")
    register_parser.add_argument("--method", default="manual", help="Acquisition method")
    register_parser.add_argument("--analyst", help="Name of the analyst")

    # Record access command
    access_parser = subparsers.add_parser("access", help="Record access to evidence")
    access_parser.add_argument("--case-id", required=True, help="Case identifier")
    access_parser.add_argument("--evidence-id", required=True, help="Evidence identifier")
    access_parser.add_argument("--purpose", required=True, help="Purpose of access")
    access_parser.add_argument("--action", default="access", help="Type of access")
    access_parser.add_argument("--analyst", help="Name of the analyst")

    # Transfer evidence command
    transfer_parser = subparsers.add_parser("transfer", help="Record evidence transfer")
    transfer_parser.add_argument("--case-id", required=True, help="Case identifier")
    transfer_parser.add_argument("--evidence-id", required=True, help="Evidence identifier")
    transfer_parser.add_argument("--location", required=True, help="New location")
    transfer_parser.add_argument("--reason", required=True, help="Reason for transfer")
    transfer_parser.add_argument("--analyst", help="Name of the analyst")
    transfer_parser.add_argument("--verify", action="store_true", help="Verify integrity after transfer")

    # Verify integrity command
    verify_parser = subparsers.add_parser("verify", help="Verify evidence integrity")
    verify_parser.add_argument("--case-id", required=True, help="Case identifier")
    verify_parser.add_argument("--evidence-id", required=True, help="Evidence identifier")
    verify_parser.add_argument("--file", help="Path to evidence file (if different from registered)")
    verify_parser.add_argument("--analyst", help="Name of the analyst")

    # Export history command
    export_parser = subparsers.add_parser("export", help="Export chain of custody history")
    export_parser.add_argument("--case-id", required=True, help="Case identifier")
    export_parser.add_argument("--evidence-id", help="Evidence identifier (optional, exports entire case if omitted)")
    export_parser.add_argument("--format", default="pdf", choices=["pdf", "html", "json", "csv", "text"], help="Output format")
    export_parser.add_argument("--output", help="Output file path")

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate chain of custody completeness")
    validate_parser.add_argument("--case-id", required=True, help="Case identifier")
    validate_parser.add_argument("--evidence-id", help="Evidence identifier (optional, validates entire case if omitted)")

    # Generate report command
    report_parser = subparsers.add_parser("report", help="Generate custody reports for a case")
    report_parser.add_argument("--case-id", required=True, help="Case identifier")
    report_parser.add_argument("--output-dir", required=True, help="Output directory")
    report_parser.add_argument("--format", default="pdf", choices=["pdf", "html", "json", "csv", "text"], help="Output format")

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Check if forensic utilities are available
    if not FORENSIC_UTILS_AVAILABLE and args.command not in ["help"]:
        print("Error: Forensic utilities not available")
        return 1

    try:
        if args.command == "register":
            analyst = args.analyst or os.environ.get("USER", "unknown")
            custody_manager = ChainOfCustody(args.case_id, analyst)
            result = custody_manager.register_item(
                file_path=args.file,
                evidence_type=args.type,
                description=args.description,
                acquisition_method=args.method,
                source_location=args.source
            )

            if result and result.get("success"):
                print(f"Evidence registered successfully with ID: {result['evidence_id']}")
                return 0
            else:
                print(f"Failed to register evidence: {result.get('error', 'Unknown error')}")
                return 1

        elif args.command == "access":
            analyst = args.analyst or os.environ.get("USER", "unknown")
            custody_manager = ChainOfCustody(args.case_id, analyst)
            success = custody_manager.record_access(
                evidence_id=args.evidence_id,
                purpose=args.purpose,
                action=args.action
            )

            if success:
                print(f"Access recorded successfully for evidence: {args.evidence_id}")
                return 0
            else:
                print(f"Failed to record access for evidence: {args.evidence_id}")
                return 1

        elif args.command == "transfer":
            analyst = args.analyst or os.environ.get("USER", "unknown")
            custody_manager = ChainOfCustody(args.case_id, analyst)
            success = custody_manager.transfer_item(
                evidence_id=args.evidence_id,
                new_location=args.location,
                reason=args.reason,
                verify_after=args.verify
            )

            if success:
                print(f"Transfer recorded successfully for evidence: {args.evidence_id}")
                return 0
            else:
                print(f"Failed to record transfer for evidence: {args.evidence_id}")
                return 1

        elif args.command == "verify":
            analyst = args.analyst or os.environ.get("USER", "unknown")
            custody_manager = ChainOfCustody(args.case_id, analyst)
            success = custody_manager.verify_integrity(
                evidence_id=args.evidence_id,
                file_path=args.file
            )

            if success:
                print(f"Evidence integrity verified successfully: {args.evidence_id}")
                return 0
            else:
                print(f"Evidence integrity verification failed: {args.evidence_id}")
                return 1

        elif args.command == "export":
            custody_manager = ChainOfCustody(args.case_id)
            output_path = custody_manager.export_history(
                evidence_id=args.evidence_id,
                format_type=args.format,
                output_path=args.output
            )

            if output_path:
                print(f"Chain of custody exported successfully to: {output_path}")
                return 0
            else:
                print("Failed to export chain of custody")
                return 1

        elif args.command == "validate":
            if args.evidence_id:
                # Validate a single evidence item
                custody_manager = ChainOfCustody(args.case_id)
                valid, issues = custody_manager.validate_custody_chain(args.evidence_id)

                if valid:
                    print(f"Chain of custody is valid for evidence: {args.evidence_id}")
                    return 0
                else:
                    print(f"Chain of custody validation failed for evidence: {args.evidence_id}")
                    for issue in issues:
                        print(f"  - {issue}")
                    return 1
            else:
                # Validate all evidence in the case
                result = validate_case_chain_of_custody(args.case_id)

                if result.get("success"):
                    print(f"Case validation complete for {result['case_id']}")
                    print(f"  Total evidence items: {result['evidence_count']}")
                    print(f"  Valid chains: {result['valid_count']}")
                    print(f"  Invalid chains: {result['invalid_count']}")

                    if result["invalid_count"] > 0:
                        print("\nInvalid chains:")
                        for item in result["results"]:
                            if not item["valid"]:
                                print(f"  Evidence ID: {item['evidence_id']}")
                                for issue in item["issues"]:
                                    print(f"    - {issue}")
                        return 1
                    return 0
                else:
                    print(f"Case validation failed: {result.get('error', 'Unknown error')}")
                    return 1

        elif args.command == "report":
            result = generate_custody_report(args.case_id, args.output_dir, args.format)

            if result.get("success"):
                print(f"Generated {result['report_count']} custody reports for case {args.case_id}")
                if result.get("case_report_path"):
                    print(f"Case summary report: {result['case_report_path']}")
                return 0
            else:
                print(f"Failed to generate custody reports: {result.get('error', 'Unknown error')}")
                return 1

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
