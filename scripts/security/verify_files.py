#!/usr/bin/env python3
"""
Verify file integrity and permissions for Cloud Infrastructure Platform

This script is designed to verify the integrity of critical files
as part of system health checks and disaster recovery processes.
"""
import json
import sys
import os
import argparse
import logging
import datetime
from core.utils import detect_file_changes, get_critical_file_hashes, setup_logging

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

def verify_files(environment='production', region=None, reference_file=None, verbose=False):
    """
    Verify the integrity of critical files based on environment and region
    
    Args:
        environment: The environment to check (production, staging, development)
        region: The region to check (primary, secondary)
        reference_file: Path to a reference hash file to compare against
        verbose: Whether to output detailed information
    
    Returns:
        tuple: (success, changes) where success is a boolean and changes is a dict
    """
    # Set up logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logger = setup_logging('file_verification', level=log_level)
    
    logger.info(f"Starting file verification for {environment} environment")
    if region:
        logger.info(f"Checking region-specific files for {region} region")
    
    # Get current directory and project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(os.path.dirname(script_dir))
    
    # Determine which files to check
    files_to_check = CRITICAL_FILES['common'].copy()
    
    # Add environment-specific files
    if environment in CRITICAL_FILES:
        files_to_check.extend(CRITICAL_FILES[environment])
    
    # Add region-specific files
    if region and region in REGION_SPECIFIC_FILES:
        files_to_check.extend(REGION_SPECIFIC_FILES[region])
    
    logger.debug(f"Verifying {len(files_to_check)} files")
    
    # Get file paths
    file_paths = [os.path.join(base_dir, f) for f in files_to_check]
    
    # Load reference hashes if provided
    if reference_file:
        try:
            with open(reference_file, 'r') as f:
                reference_hashes = json.load(f)
                logger.info(f"Loaded reference hashes from {reference_file}")
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load reference hashes: {str(e)}")
            return False, {"error": f"Failed to load reference hashes: {str(e)}"}
    else:
        # Generate new reference hashes
        logger.debug("Generating reference hashes")
        reference_hashes = get_critical_file_hashes(file_paths)
        
        # Save reference hashes for DR purposes
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        hash_file = f"/var/log/cloud-platform/file_hashes_{environment}_{timestamp}.json"
        os.makedirs(os.path.dirname(hash_file), exist_ok=True)
        
        try:
            with open(hash_file, 'w') as f:
                json.dump(reference_hashes, f, indent=2)
                logger.info(f"Saved reference hashes to {hash_file}")
        except IOError as e:
            logger.warning(f"Could not save reference hashes: {str(e)}")
    
    # Check for changes
    logger.debug("Detecting file changes")
    changes = detect_file_changes(base_dir, reference_hashes)
    
    # Save the verification results for DR audit trail
    if environment == 'production' or region is not None:
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = f"/var/log/cloud-platform/verification_{environment}_{region}_{timestamp}.json"
            with open(result_file, 'w') as f:
                json.dump({
                    'timestamp': timestamp,
                    'environment': environment,
                    'region': region,
                    'verified_files': len(files_to_check),
                    'changes': changes
                }, f, indent=2)
            logger.debug(f"Saved verification results to {result_file}")
        except IOError:
            logger.warning("Could not save verification results")
    
    # Log DR-specific event
    if region:
        try:
            with open("/var/log/cloud-platform/dr-events.log", "a") as f:
                status = "FAILURE" if changes else "SUCCESS"
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{timestamp},FILE_VERIFICATION,{environment},{region},{status}\n")
        except IOError:
            logger.warning("Could not write to DR events log")
    
    return not bool(changes), changes

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Verify file integrity')
    parser.add_argument('--environment', '-e', default='production',
                        choices=['production', 'staging', 'development'],
                        help='Environment to check')
    parser.add_argument('--region', '-r', choices=['primary', 'secondary'],
                        help='Region to check (for DR purposes)')
    parser.add_argument('--reference-file', '-f',
                        help='Path to reference hash file')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    args = parser.parse_args()
    
    success, changes = verify_files(
        environment=args.environment,
        region=args.region,
        reference_file=args.reference_file,
        verbose=args.verbose
    )
    
    if not success:
        print(f"❌ Found {len(changes)} file integrity issues:")
        print(json.dumps(changes, indent=2))
        sys.exit(1)
    else:
        print(f"✅ All files verified successfully in {args.environment} environment" + 
              (f" ({args.region} region)" if args.region else ""))
        sys.exit(0)

if __name__ == "__main__":
    main()
