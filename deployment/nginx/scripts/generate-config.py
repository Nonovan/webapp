#!/usr/bin/env python3
"""
Generate NGINX configuration files from templates for Cloud Infrastructure Platform.

This script generates environment-specific NGINX configuration files using templates
in the templates directory and environment-specific settings.
"""

import os
import sys
import json
import argparse
import shutil
from datetime import datetime
import re
from pathlib import Path

# Default paths
DEFAULT_TEMPLATES_DIR = "../templates"
DEFAULT_OUTPUT_DIR = "../sites-available"
DEFAULT_CONFIG_DIR = "../../environments"
DEFAULT_INCLUDES_DIR = "../includes"

def setup_argparse():
    """Configure argument parser for the script."""
    parser = argparse.ArgumentParser(
        description="Generate NGINX configuration files from templates."
    )
    parser.add_argument(
        "--environment", "-e", 
        required=True,
        choices=["development", "staging", "production", "dr-recovery"],
        help="Environment to generate configuration for"
    )
    parser.add_argument(
        "--templates-dir", "-t",
        default=DEFAULT_TEMPLATES_DIR,
        help=f"Directory containing templates (default: {DEFAULT_TEMPLATES_DIR})"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for generated configs (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--config-dir", "-c",
        default=DEFAULT_CONFIG_DIR,
        help=f"Directory containing environment configs (default: {DEFAULT_CONFIG_DIR})"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force overwrite of existing files"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without writing files"
    )
    return parser.parse_args()

def load_environment_config(env_name, config_dir):
    """Load environment configuration from file."""
    config_file = os.path.join(config_dir, f"{env_name}.env")
    config = {}
    
    if os.path.exists(config_file):
        print(f"Loading environment configuration from {config_file}")
        with open(config_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    config[key] = value
    else:
        print(f"Warning: Environment file {config_file} not found")
        
    # Load JSON config files if they exist
    json_config_file = os.path.join(config_dir, f"{env_name}.json")
    if os.path.exists(json_config_file):
        print(f"Loading JSON configuration from {json_config_file}")
        with open(json_config_file, "r") as f:
            config.update(json.load(f))
            
    return config

def create_template_context(env_name, config):
    """Create a context dictionary for template rendering."""
    # Base context with defaults
    context = {
        "ENVIRONMENT": env_name,
        "APP_ROOT": config.get("APP_ROOT", "/var/www/cloud-platform"),
        "STATIC_PATH": config.get("STATIC_PATH", "/var/www/cloud-platform/static"),
        "API_UPSTREAM": config.get("API_UPSTREAM", "backend_api"),
        "API_VERSION": config.get("API_VERSION", "1.0"),
        "APP_VERSION": config.get("APP_VERSION", "1.0.0"),
        "DOMAIN_NAME": config.get("DOMAIN_NAME", f"cloud-platform-{env_name}.example.com"),
        "API_TIMEOUT": config.get("API_TIMEOUT", "60"),
        "API_CONNECT_TIMEOUT": config.get("API_CONNECT_TIMEOUT", "10"),
        "RATE_LIMIT_BURST": config.get("RATE_LIMIT_BURST", "20"),
        "RATE_LIMIT_MODE": config.get("RATE_LIMIT_MODE", "nodelay"),
        "AUTH_RATE_LIMIT_BURST": config.get("AUTH_RATE_LIMIT_BURST", "10"),
        "ICS_TIMEOUT": config.get("ICS_TIMEOUT", "300"),
        "STATIC_MAX_AGE": config.get("STATIC_MAX_AGE", "2592000"),
        "CACHE_CONTROL": config.get("CACHE_CONTROL", "public, max-age=86400"),
        "SSL_CERTIFICATE_PATH": config.get("SSL_CERTIFICATE_PATH", "/etc/ssl/certs/cloud-platform.crt"),
        "SSL_KEY_PATH": config.get("SSL_KEY_PATH", "/etc/ssl/private/cloud-platform.key"),
    }
    
    # Add ICS restricted IPs
    ics_ips = config.get("ICS_RESTRICTED_IPS", "10.100.0.0/16,192.168.10.0/24")
    context["ICS_RESTRICTED_IPS"] = [ip.strip() for ip in ics_ips.split(",")]
    
    # Environment-specific settings
    if env_name == "production":
        context["INTERNAL_HEALTH_CHECK"] = True
        context["CACHE_CONTROL"] = "public, max-age=86400"
    elif env_name == "staging":
        context["INTERNAL_HEALTH_CHECK"] = True
        context["CACHE_CONTROL"] = "public, max-age=3600"
    else:  # development or dr-recovery
        context["INTERNAL_HEALTH_CHECK"] = False
        context["CACHE_CONTROL"] = "no-cache, no-store, must-revalidate"
    
    return context

def render_template(template_path, context):
    """Render a template file with the provided context."""
    with open(template_path, 'r') as f:
        template_content = f.read()
    
    # Replace simple variables
    for key, value in context.items():
        if isinstance(value, (str, int, float)):
            template_content = template_content.replace(f"{{{{{key}}}}}", str(value))
    
    # Handle conditional blocks
    for key, value in context.items():
        if isinstance(value, bool):
            if value:
                # Remove the conditional tags for true conditions
                template_content = re.sub(
                    r'\{\{#' + key + r'\}\}(.*?)\{\{/' + key + r'\}\}',
                    r'\1',
                    template_content,
                    flags=re.DOTALL
                )
            else:
                # Remove the entire block for false conditions
                template_content = re.sub(
                    r'\{\{#' + key + r'\}\}(.*?)\{\{/' + key + r'\}\}',
                    '',
                    template_content,
                    flags=re.DOTALL
                )
    
    # Handle lists
    for key, value in context.items():
        if isinstance(value, list):
            list_pattern = r'\{\{#' + key + r'\}\}(.*?)\{\{\.}}'
            list_item_template = re.search(list_pattern, template_content)
            if list_item_template:
                item_template = list_item_template.group(1)
                rendered_items = []
                for item in value:
                    rendered_items.append(item_template.replace("{{.}}", str(item)))
                
                # Replace the entire list block with rendered items
                template_content = re.sub(
                    r'\{\{#' + key + r'\}\}.*?\{\{/' + key + r'\}\}',
                    ''.join(rendered_items),
                    template_content,
                    flags=re.DOTALL
                )
    
    return template_content

def process_templates(templates_dir, output_dir, context, force=False, dry_run=False):
    """Process all templates in the templates directory."""
    templates_dir = os.path.abspath(templates_dir)
    output_dir = os.path.abspath(output_dir)
    
    if not os.path.isdir(templates_dir):
        print(f"Error: Templates directory {templates_dir} not found")
        return False
    
    if not dry_run and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for template_file in os.listdir(templates_dir):
        if template_file.endswith('.template'):
            template_path = os.path.join(templates_dir, template_file)
            output_file = template_file.replace('.template', '')
            output_path = os.path.join(output_dir, output_file)
            
            if os.path.exists(output_path) and not force and not dry_run:
                print(f"Skipping {output_file} (already exists, use --force to overwrite)")
                continue
            
            print(f"Processing template: {template_file}")
            rendered_content = render_template(template_path, context)
            
            if dry_run:
                print(f"Would write to: {output_path}")
            else:
                with open(output_path, 'w') as f:
                    f.write(rendered_content)
                print(f"Generated: {output_path}")
    
    return True

def setup_includes(includes_dir, output_dir, dry_run=False):
    """Ensure all required include files are available."""
    includes_dir = os.path.abspath(includes_dir)
    output_dir = os.path.abspath(output_dir)
    
    if not os.path.isdir(includes_dir):
        print(f"Error: Includes directory {includes_dir} not found")
        return False
        
    # Create conf.d directory in output path if needed
    conf_d_dir = os.path.join(output_dir, "conf.d")
    if not dry_run and not os.path.exists(conf_d_dir):
        os.makedirs(conf_d_dir)
    
    return True

def main():
    """Main entry point for the script."""
    args = setup_argparse()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Resolve paths relative to the script
    templates_dir = os.path.join(script_dir, args.templates_dir)
    output_dir = os.path.join(script_dir, args.output_dir)
    config_dir = os.path.join(script_dir, args.config_dir)
    includes_dir = os.path.join(script_dir, DEFAULT_INCLUDES_DIR)
    
    print(f"Generating NGINX configuration for {args.environment} environment")
    
    # Load configuration
    config = load_environment_config(args.environment, config_dir)
    context = create_template_context(args.environment, config)
    
    if args.verbose:
        print("\nTemplate context:")
        for key, value in context.items():
            print(f"  {key}: {value}")
    
    # Add timestamp to the context
    context["GENERATED_TIMESTAMP"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    context["GENERATOR_SCRIPT"] = os.path.basename(__file__)
    
    # Process templates
    if not process_templates(templates_dir, output_dir, context, args.force, args.dry_run):
        print("Error processing templates")
        return 1
    
    # Ensure includes are set up
    if not setup_includes(includes_dir, output_dir, args.dry_run):
        print("Error setting up include files")
        return 1
    
    print("NGINX configuration generation complete")
    if not args.dry_run:
        print(f"Files generated in: {output_dir}")
    else:
        print("Dry run completed, no files were written")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
    