#!/usr/bin/env python3
"""
Generate security keys for application configuration.

This script generates various cryptographic keys needed for secure application
operations, including Flask session keys, JWT tokens, and encryption keys.
Keys are output in a format suitable for environment files or configuration.

Usage:
    ./generate_security_keys.py [--output FILE] [--format FORMAT]

Options:
    --output FILE    Write keys to a file instead of stdout
    --format FORMAT  Output format: env (default), json, or yaml
"""
import os
import sys
import secrets
import base64
import argparse
import json
import yaml
from pathlib import Path
from typing import Dict, Any


def generate_keys() -> Dict[str, str]:
    """
    Generate cryptographic keys for application security.
    
    Returns:
        dict: Dictionary containing generated security keys
    """
    keys = {
        # Generate a secure key for Flask sessions
        "SECRET_KEY": secrets.token_hex(32),
        
        # Generate a JWT secret key
        "JWT_SECRET_KEY": secrets.token_hex(32),
        
        # Generate an encryption key for sensitive data
        "ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode('utf-8'),
        
        # Generate a key for API authentication
        "API_KEY": secrets.token_urlsafe(32),
        
        # Generate a key for cookie signing
        "COOKIE_SECRET": secrets.token_hex(24),
        
        # Generate an initialization vector for encryption
        "ENCRYPTION_IV": base64.b64encode(os.urandom(16)).decode('utf-8')
    }
    
    return keys


def format_as_env(keys: Dict[str, str]) -> str:
    """Format keys as environment variables."""
    return "\n".join([f"{key}={value}" for key, value in keys.items()])


def format_as_json(keys: Dict[str, str]) -> str:
    """Format keys as JSON."""
    return json.dumps(keys, indent=2)


def format_as_yaml(keys: Dict[str, str]) -> str:
    """Format keys as YAML."""
    return yaml.dump(keys, default_flow_style=False)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate security keys for application configuration"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: print to stdout)",
        type=str
    )
    parser.add_argument(
        "--format", "-f",
        choices=["env", "json", "yaml"],
        default="env",
        help="Output format (default: env)"
    )
    return parser.parse_args()


def main() -> int:
    """Execute the key generation script."""
    args = parse_arguments()
    
    try:
        # Generate the security keys
        keys = generate_keys()
        
        # Format the output according to the specified format
        if args.format == "json":
            output = format_as_json(keys)
        elif args.format == "yaml":
            output = format_as_yaml(keys)
        else:  # env format
            output = format_as_env(keys)
        
        # Write output to file or stdout
        if args.output:
            output_path = Path(args.output)
            
            # Create parent directories if they don't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write with restrictive permissions (600)
            with open(output_path, 'w') as f:
                f.write(output)
                
            # Set file permissions to be readable only by owner
            os.chmod(output_path, 0o600)
            
            print(f"Security keys written to {output_path} with restricted permissions", file=sys.stderr)
        else:
            print(output)
        
        return 0
    except Exception as e:
        print(f"Error generating security keys: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())