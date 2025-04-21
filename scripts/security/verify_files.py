#!/usr/bin/env python3
"""
Verify file integrity and permissions for Cloud Infrastructure Platform

This script is designed to verify the integrity of critical files
as part of system health checks and disaster recovery processes.
It can compare current file hashes against stored references or
generate new reference files for future integrity checks.
"""
import json
import sys
import os
import argparse
import logging
import datetime
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

# Define critical file paths by environment
CRITICAL_FILES = {
    'common': [
        'app.py', 'config.py', 'core/security_utils.py', 'core/middleware.py',
        'core/config.py', 'core/auth.py', 'core/factory.py'
    ],
    'production': [
        'deployment/security/security_config.json',
        'deployment/environments/production.env'
    ],
    'staging': [
        'deployment/environments/staging.env'
    ],
    'development': [
        'deployment/environments/development.env'
    ]
}

# Define file sets by region for DR purposes
REGION_SPECIFIC_FILES = {
    'primary': [
        'deployment/infrastructure/primary_config.json'
    ],
    'secondary': [
        'deployment/infrastructure/secondary_config.json'
    ]
}

# Files with special permission requirements
CRITICAL_PERMISSION_FILES = {
    'deployment/environments/production.env': 0o600,  # Owner read/write only
    'deployment/security/security_config.json': 0o640,  # Owner read/write, group read
    'core/security_utils.py': 0o644  # Owner read/write, group/others read
}


def setup_logging(log_level: int = logging.INFO) -> logging.Logger:
    """
    Set up logging configuration.
    
    Args:
        log_level: The logging level to use
        
    Returns:
        Logger instance
    """
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger("file-verification")


def compute_file_hash(file_path: str) -> Optional[str]:
    """
    Compute SHA-256 hash of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Hex digest of the file hash or None if file not found
    """
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    except FileNotFoundError:
        return None
    except Exception as e:
        logging.error(f"Error computing hash for {file_path}: {e}")
        return None


def get_critical_file_hashes(base_path: str, file_list: List[str]) -> Dict[str, str]:
    """
    Get hashes for all critical files.
    
    Args:
        base_path: Base path for resolving relative paths
        file_list: List of file paths to hash
        
    Returns:
        Dictionary mapping file paths to their hashes
    """
    file_hashes = {}
    for file_path in file_list:
        full_path = os.path.join(base_path, file_path)
        file_hash = compute_file_hash(full_path)
        if file_hash:
            file_hashes[file_path] = file_hash
    
    return file_hashes


def detect_file_changes(current_hashes: Dict[str, str], 
                       reference_hashes: Dict[str, str]) -> Tuple[List[str], List[str], List[str]]:
    """
    Compare current file hashes with reference hashes.
    
    Args:
        current_hashes: Dictionary of current file hashes
        reference_hashes: Dictionary of reference file hashes
        
    Returns:
        Tuple containing lists of (modified files, missing files, new files)
    """
    modified_files = []
    missing_files = []
    new_files = []
    
    # Check for modified or missing files
    for file_path, ref_hash in reference_hashes.items():
        if file_path in current_hashes:
            if current_hashes[file_path] != ref_hash:
                modified_files.append(file_path)
        else:
            missing_files.append(file_path)
    
    # Check for new files
    for file_path in current_hashes:
        if file_path not in reference_hashes:
            new_files.append(file_path)
    
    return modified_files, missing_files, new_files


def verify_file_permissions(base_path: str, permission_files: Dict[str, int]) -> Dict[str, Dict]:
    """
    Verify permissions of critical files.
    
    Args:
        base_path: Base path for resolving relative paths
        permission_files: Dictionary mapping files to their expected permissions
        
    Returns:
        Dictionary mapping files to their permission status
    """
    permission_status = {}
    
    for file_path, expected_mode in permission_files.items():
        full_path = os.path.join(base_path, file_path)
        
        if not os.path.exists(full_path):
            permission_status[file_path] = {
                "exists": False,
                "status": "missing"
            }
            continue
            
        try:
            actual_mode = os.stat(full_path).st_mode & 0o777  # Get file permissions
            
            if actual_mode == expected_mode:
                status = "correct"
            else:
                status = "incorrect"
                
            permission_status[file_path] = {
                "exists": True,
                "expected": oct(expected_mode),
                "actual": oct(actual_mode),
                "status": status
            }
            
        except Exception as e:
            permission_status[file_path] = {
                "exists": True,
                "status": "error",
                "error": str(e)
            }
    
    return permission_status


def verify_files(environment: str = 'production', 
                region: Optional[str] = None, 
                reference_file: Optional[str] = None, 
                verbose: bool = False,
                check_permissions: bool = True) -> Tuple[bool, Dict]:
    """
    Verify the integrity of critical files based on environment and region.
    
    Args:
        environment: The environment to check (production, staging, development)
        region: The region to check (primary, secondary)
        reference_file: Path to reference hash file, or None to create new one
        verbose: Whether to output verbose information
        check_permissions: Whether to check file permissions
        
    Returns:
        Tuple of (success_flag, results_dict)
    """
    logger = logging.getLogger("file-verification")
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Determine files to check
    files_to_check = set(CRITICAL_FILES.get('common', []))
    files_to_check.update(CRITICAL_FILES.get(environment, []))
    
    if region and region in REGION_SPECIFIC_FILES:
        files_to_check.update(REGION_SPECIFIC_FILES[region])
    
    # Get current hashes
    current_hashes = get_critical_file_hashes(base_path, list(files_to_check))
    
    # Results dictionary
    results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "environment": environment,
        "region": region,
        "total_files": len(files_to_check),
        "found_files": len(current_hashes),
        "verification_status": "pending"
    }
    
    # Generate new reference file if none provided
    if not reference_file:
        output_file = f"file_integrity_{environment}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        reference_data = {
            "created_at": datetime.datetime.now().isoformat(),
            "environment": environment,
            "region": region,
            "file_hashes": current_hashes
        }
        
        with open(output_file, 'w') as f:
            json.dump(reference_data, f, indent=2)
        
        logger.info(f"Generated new reference file: {output_file}")
        results["verification_status"] = "reference_generated"
        results["reference_file"] = output_file
        return True, results
    
    # Compare with reference file
    try:
        with open(reference_file, 'r') as f:
            reference_data = json.load(f)
            reference_hashes = reference_data.get("file_hashes", {})
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error reading reference file: {e}")
        results["verification_status"] = "error"
        results["error"] = f"Failed to read reference file: {str(e)}"
        return False, results
    
    # Check file integrity
    modified_files, missing_files, new_files = detect_file_changes(current_hashes, reference_hashes)
    
    results["modified_files"] = modified_files
    results["missing_files"] = missing_files
    results["new_files"] = new_files
    
    # Calculate integrity score
    total_ref_files = len(reference_hashes)
    unchanged_files = total_ref_files - len(modified_files) - len(missing_files)
    if total_ref_files > 0:
        integrity_score = (unchanged_files / total_ref_files) * 100
    else:
        integrity_score = 0
        
    results["integrity_score"] = round(integrity_score, 2)
    
    # Check file permissions
    if check_permissions:
        permission_results = verify_file_permissions(base_path, CRITICAL_PERMISSION_FILES)
        results["permission_check"] = permission_results
        
        # Count incorrect permissions
        incorrect_permissions = sum(1 for info in permission_results.values() 
                                  if info.get("status") in ["incorrect", "error"])
        results["incorrect_permissions"] = incorrect_permissions
    
    # Determine verification status
    if not modified_files and not missing_files and (not check_permissions or incorrect_permissions == 0):
        results["verification_status"] = "success"
        logger.info("File integrity verification passed successfully.")
        return True, results
    else:
        issues = []
        if modified_files:
            issues.append(f"{len(modified_files)} modified")
        if missing_files:
            issues.append(f"{len(missing_files)} missing")
        if check_permissions and incorrect_permissions > 0:
            issues.append(f"{incorrect_permissions} permission issues")
            
        results["verification_status"] = "failed"
        results["issues_summary"] = ", ".join(issues)
        logger.warning(f"File integrity verification failed: {results['issues_summary']}")
        return False, results


def generate_report(results: Dict, output_format: str = 'text', output_file: Optional[str] = None) -> None:
    """
    Generate a report from the verification results.
    
    Args:
        results: Results dictionary from verify_files
        output_format: Format of the report (text, json, html)
        output_file: Path to output file or None for stdout
    """
    if output_format == 'json':
        report = json.dumps(results, indent=2)
    elif output_format == 'html':
        html_template = """<!DOCTYPE html>
<html>
<head>
<title>File Integrity Verification Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.success { color: green; }
.failure { color: red; }
.warning { color: orange; }
</style>
</head>
<body>
<h1>File Integrity Verification Report</h1>
<p><strong>Environment:</strong> {environment}</p>
<p><strong>Region:</strong> {region}</p>
<p><strong>Timestamp:</strong> {timestamp}</p>
<p><strong>Status:</strong> <span class="{status_class}">{verification_status}</span></p>
<p><strong>Integrity Score:</strong> {integrity_score}%</p>

<h2>Files Summary</h2>
<p>Total files checked: {total_files}</p>
<p>Files found: {found_files}</p>

{modified_section}
{missing_section}
{new_section}
{permissions_section}
</body>
</html>"""
        
        # Generate modified files section
        if results.get("modified_files"):
            modified_content = "<h2>Modified Files</h2><ul>"
            for file in results["modified_files"]:
                modified_content += f"<li>{file}</li>"
            modified_content += "</ul>"
        else:
            modified_content = ""
        
        # Generate missing files section
        if results.get("missing_files"):
            missing_content = "<h2>Missing Files</h2><ul>"
            for file in results["missing_files"]:
                missing_content += f"<li>{file}</li>"
            missing_content += "</ul>"
        else:
            missing_content = ""
        
        # Generate new files section
        if results.get("new_files"):
            new_content = "<h2>New Files</h2><ul>"
            for file in results["new_files"]:
                new_content += f"<li>{file}</li>"
            new_content += "</ul>"
        else:
            new_content = ""
        
        # Generate permissions section
        if "permission_check" in results:
            perm_content = "<h2>File Permissions</h2><table><tr><th>File</th><th>Status</th><th>Expected</th><th>Actual</th></tr>"
            for file, info in results["permission_check"].items():
                if info["status"] == "correct":
                    status_class = "success"
                    status = "Correct"
                elif info["status"] == "missing":
                    status_class = "warning"
                    status = "Missing"
                else:
                    status_class = "failure"
                    status = "Incorrect"
                    
                expected = info.get("expected", "N/A")
                actual = info.get("actual", "N/A")
                perm_content += f'<tr><td>{file}</td><td class="{status_class}">{status}</td><td>{expected}</td><td>{actual}</td></tr>'
            perm_content += "</table>"
        else:
            perm_content = ""
        
        # Determine status class
        if results["verification_status"] == "success":
            status_class = "success"
        elif results["verification_status"] == "reference_generated":
            status_class = "success"
        else:
            status_class = "failure"
            
        # Format the HTML template
        report = html_template.format(
            environment=results["environment"],
            region=results.get("region", "N/A"),
            timestamp=results["timestamp"],
            verification_status=results["verification_status"].replace("_", " ").title(),
            status_class=status_class,
            integrity_score=results.get("integrity_score", "N/A"),
            total_files=results["total_files"],
            found_files=results["found_files"],
            modified_section=modified_content,
            missing_section=missing_content,
            new_section=new_content,
            permissions_section=perm_content
        )
    else:  # text format
        report_lines = [
            "=== File Integrity Verification Report ===",
            f"Environment: {results['environment']}",
            f"Region: {results.get('region', 'N/A')}",
            f"Timestamp: {results['timestamp']}",
            f"Status: {results['verification_status']}",
            f"Integrity Score: {results.get('integrity_score', 'N/A')}%",
            f"Total files: {results['total_files']}",
            f"Files found: {results['found_files']}",
            ""
        ]
        
        if results.get("modified_files"):
            report_lines.append("Modified Files:")
            for file in results["modified_files"]:
                report_lines.append(f"  - {file}")
            report_lines.append("")
            
        if results.get("missing_files"):
            report_lines.append("Missing Files:")
            for file in results["missing_files"]:
                report_lines.append(f"  - {file}")
            report_lines.append("")
            
        if results.get("new_files"):
            report_lines.append("New Files:")
            for file in results["new_files"]:
                report_lines.append(f"  - {file}")
            report_lines.append("")
            
        if "permission_check" in results:
            report_lines.append("File Permissions:")
            for file, info in results["permission_check"].items():
                status = info["status"]
                if status == "missing":
                    report_lines.append(f"  - {file}: MISSING")
                elif status == "error":
                    report_lines.append(f"  - {file}: ERROR ({info.get('error', 'unknown error')})")
                else:
                    expected = info.get("expected", "N/A")
                    actual = info.get("actual", "N/A")
                    status_mark = "✓" if status == "correct" else "✗"
                    report_lines.append(f"  - {file}: {status_mark} Expected: {expected}, Actual: {actual}")
                    
        report = "\n".join(report_lines)
    
    # Output the report
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
        print(f"Report saved to {output_file}")
    else:
        print(report)


def main() -> int:
    """
    Main entry point for the script.
    
    Returns:
        Exit code: 0 for success, 1 for verification failure, 2 for script error
    """
    parser = argparse.ArgumentParser(description='Verify file integrity for the Cloud Infrastructure Platform.')
    parser.add_argument('--environment', '-e', choices=['production', 'staging', 'development'], 
                        default='production', help='Environment to check (default: production)')
    parser.add_argument('--region', '-r', choices=['primary', 'secondary'],
                        help='Region to check (optional)')
    parser.add_argument('--reference', '-f', 
                        help='Reference file containing file hashes. If not provided, a new one will be created.')
    parser.add_argument('--output', '-o',
                        help='Output file for the report. If not provided, output goes to stdout.')
    parser.add_argument('--format', choices=['text', 'json', 'html'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--no-permissions', action='store_true',
                        help="Skip file permission checks")
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress all output except errors and the final report')
    
    args = parser.parse_args()
    
    # Setup logging based on verbosity
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    
    logger = setup_logging(log_level)
    
    try:
        success, results = verify_files(
            environment=args.environment,
            region=args.region,
            reference_file=args.reference,
            verbose=args.verbose,
            check_permissions=not args.no_permissions
        )
        
        generate_report(results, args.format, args.output)
        
        if success:
            return 0
        else:
            return 1
            
    except Exception as e:
        logger.error(f"Error executing file verification: {e}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        return 2


if __name__ == "__main__":
    sys.exit(main())
