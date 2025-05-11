"""
Configuration management module for myproject.

This module defines configuration classes for different application environments,
extending the core configuration system with environment-specific settings.
It centralizes all configuration logic to ensure consistent settings across
the application and proper separation of concerns.

The module implements a hierarchical configuration approach:
1. Core base configuration from core.config.Config
2. Environment-specific overrides (development, production, testing, etc.)
3. Instance-specific settings loaded from environment variables

This structure ensures secure configuration handling, environment-specific
behavior, and flexible deployment options without hard-coding sensitive values.
"""

import os
import json
import click
import logging
from datetime import timedelta, datetime
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
from flask import current_app
from flask.cli import with_appcontext
from core.config import Config as CoreConfig

# Configure logger
logger = logging.getLogger(__name__)

class BaseConfig(CoreConfig):
    """
    Extended configuration with environment-specific settings.

    This class extends the core configuration with additional environment-specific
    settings and provides methods to load the appropriate configuration based on
    the current environment (development, production, testing, etc.).

    The class ensures that sensitive configuration values come from environment
    variables rather than being hard-coded, improving security and enabling
    different settings in different deployment environments.

    Attributes:
        Inherits all attributes from core.config.Config
    """

    @classmethod
    def load(cls, env='development'):
        """
        Load configuration with environment-specific overrides.

        This method retrieves the base configuration from the parent class and
        then applies environment-specific overrides based on the specified
        environment name. It provides a complete configuration dictionary
        suitable for the target environment.

        Args:
            env (str): Environment name to load configuration for
                       (development, production, testing, staging, ci)
                       Defaults to 'development'.

        Returns:
            dict: Complete configuration dictionary with environment-specific settings

        Example:
            # Load production configuration
            config = BaseConfig.load('production')
            app.config.update(config)
        """
        # Get base config
        base_configuration = super().load()

        # File integrity monitoring settings (common across environments)
        file_integrity_config = {
            'ENABLE_FILE_INTEGRITY_MONITORING': True,
            'FILE_HASH_ALGORITHM': 'sha256',
            'FILE_INTEGRITY_CHECK_INTERVAL': 3600,  # 1 hour
            'BASELINE_BACKUP_ENABLED': True,
            'BASELINE_PATH_TEMPLATE': 'instance/security/baseline_{environment}.json',
            'BASELINE_BACKUP_PATH_TEMPLATE': 'instance/security/baseline_backups/{timestamp}_{environment}.json',
            'BASELINE_UPDATE_MAX_FILES': 50,
            'BASELINE_UPDATE_CRITICAL_THRESHOLD': 5,
            'BASELINE_UPDATE_RETENTION': 5
        }

        # Add file integrity settings to base config
        base_configuration.update(file_integrity_config)

        # Add environment-specific overrides
        env_config = {
            'development': {
                'DEBUG': True,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': False,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DEV_DATABASE_URL'),
                # Development-specific file integrity settings
                'AUTO_UPDATE_BASELINE': True,  # Auto-update in development only
                'FILE_INTEGRITY_DEBUG': True,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': False,
                'CRITICAL_FILES_PATTERN': [
                    "*.py",                  # Python source files
                    "config/*.py",           # Configuration files
                    "config/*.ini",          # INI configuration files
                    "core/security/*.py"     # Core security components
                ]
            },
            'production': {
                'DEBUG': False,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': True,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL'),
                # Production-specific file integrity settings
                'AUTO_UPDATE_BASELINE': False,  # Disabled in production for security
                'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
                'CHECK_FILE_SIGNATURES': True,
                'CRITICAL_FILES_PATTERN': [
                    "*.py",                    # All Python files
                    "config/*.py",             # Configuration files
                    "config/*.ini",            # INI configuration files
                    "config/*.json",           # JSON configuration files
                    "core/security/*.py",      # Security components
                    "core/middleware.py",      # Security middleware
                    "app.py",                  # Main application entry point
                    "models/security/*.py",    # Security models
                    "services/security*.py",   # Security services
                    "api/security/*.py",       # Security API endpoints
                ]
            },
            'testing': {
                'DEBUG': False,
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'SESSION_COOKIE_SECURE': False,
                'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
                # Testing-specific file integrity settings
                'ENABLE_FILE_INTEGRITY_MONITORING': False,  # Disabled for faster tests
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_BACKUP_ENABLED': False,
                'FILE_HASH_ALGORITHM': 'sha256',
                'SMALL_FILE_THRESHOLD': 1024  # Smaller threshold for testing
            },
            'staging': {
                'DEBUG': False,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': True,
                'CACHE_TYPE': 'redis',
                'SQLALCHEMY_DATABASE_URI': os.getenv('STAGING_DATABASE_URL'),
                'CELERY_BROKER_URL': os.getenv('STAGING_REDIS_URL'),
                'SENTRY_ENVIRONMENT': 'staging',
                # Staging-specific file integrity settings
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
                'CRITICAL_FILES_PATTERN': [
                    "*.py",                    # All Python files
                    "config/*.py",             # Configuration files
                    "core/security/*.py",      # Security components
                    "app.py"                   # Main application entry point
                ]
            },
            'ci': {
                'DEBUG': False,
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'CACHE_TYPE': 'simple',
                'CELERY_ALWAYS_EAGER': True,
                'SQLALCHEMY_DATABASE_URI': 'postgresql://ci:ci@localhost/ci_test',
                # CI-specific file integrity settings
                'ENABLE_FILE_INTEGRITY_MONITORING': False,
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_BACKUP_ENABLED': False,
                'CI_SKIP_INTEGRITY_CHECK': True,
                'CRITICAL_FILES_PATTERN': [
                    "app.py",
                    "core/security/*.py",
                    "config/*.py"
                ]
            },
            'dr-recovery': {
                'DEBUG': False,
                'TESTING': False,
                'DR_MODE': True,
                'RECOVERY_MODE': True,
                'DR_ENHANCED_LOGGING': True,
                'DR_BASELINE_FROZEN': True,  # Prevent baseline changes during DR recovery
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
                'SESSION_COOKIE_SECURE': True,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DR_DATABASE_URL')
            }
        }

        # Update base config with environment settings
        base_configuration.update(env_config.get(env, env_config['development']))

        # Set up file baseline path
        if base_configuration.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            if 'FILE_BASELINE_PATH' not in base_configuration or not base_configuration['FILE_BASELINE_PATH']:
                baseline_path_template = base_configuration.get('BASELINE_PATH_TEMPLATE',
                                                             'instance/security/baseline_{environment}.json')
                base_configuration['FILE_BASELINE_PATH'] = baseline_path_template.format(environment=env)

        # Session security settings (override any environment-specific configurations)
        base_configuration.update({
            'SESSION_COOKIE_SECURE': True if env != 'development' and env != 'testing' else False,
            'SESSION_COOKIE_HTTPONLY': True,  # Prevent JavaScript access to cookies
            'SESSION_COOKIE_SAMESITE': 'Lax',  # Restrict cross-site requests
            'PERMANENT_SESSION_LIFETIME': timedelta(hours=1)  # Default session lifetime
        })

        return base_configuration

    @classmethod
    def update_file_integrity_baseline(
        cls,
        app=None,
        baseline_path: Optional[str] = None,
        updates: Optional[List[Dict[str, Any]]] = None,
        remove_missing: bool = False,
        auto_update_limit: int = 10
    ) -> Tuple[bool, str]:
        """
        Forward to the file integrity baseline update function in core config.

        This is a convenience method that delegates to the implementation in
        the core configuration package.

        Args:
            app: Flask application instance
            baseline_path: Path to the baseline file
            updates: List of dictionaries with file paths and their current hashes
            remove_missing: Whether to remove entries for files that no longer exist
            auto_update_limit: Maximum number of files to auto-update

        Returns:
            tuple: (success_bool, message_string)
        """
        from config import update_file_integrity_baseline as core_update
        return core_update(app, baseline_path, updates, remove_missing, auto_update_limit)

    @classmethod
    def calculate_file_hash(cls, file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash for a file using the specified algorithm.

        Args:
            file_path: Path to the file to hash
            algorithm: Hash algorithm to use ('sha256', 'sha384', 'sha512')

        Returns:
            str: Hexadecimal hash digest
        """
        try:
            # Try to use the hash function from core.security.cs_crypto
            from core.security.cs_crypto import compute_hash
            return compute_hash(file_path=file_path, algorithm=algorithm)
        except ImportError:
            # Fall back to a local implementation
            import hashlib
            hash_func = getattr(hashlib, algorithm)()

            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)

            return hash_func.hexdigest()

    @classmethod
    def register_cli_commands(cls, app):
        """
        Register CLI commands for file integrity baseline management.

        Args:
            app: Flask application instance
        """
        @app.cli.group()
        def integrity():
            """File integrity management commands."""
            pass

        @integrity.command('list-baseline')
        @click.option('--path', help='Path to the baseline file to inspect')
        @click.option('--filter', '-f', help='Filter files containing this string')
        @click.option('--format', type=click.Choice(['text', 'json']), default='text',
                      help='Output format (text or json)')
        @click.option('--sort', type=click.Choice(['path', 'hash']), default='path',
                      help='Sort by path or hash')
        @with_appcontext
        def list_baseline(path, filter, format, sort):
            """List the contents of the integrity baseline file."""
            # Get baseline path from config if not provided
            if not path:
                path = current_app.config.get('FILE_BASELINE_PATH')
                if not path:
                    click.echo("Error: No baseline path configured", err=True)
                    return 1

            # Check if baseline exists
            if not os.path.exists(path):
                click.echo(f"Error: Baseline file not found: {path}", err=True)
                return 1

            try:
                # Load baseline
                with open(path, 'r') as f:
                    baseline = json.load(f)

                # Count entries
                total_entries = len(baseline)

                # Filter if requested
                if filter:
                    baseline = {path: hash for path, hash in baseline.items() if filter in path}

                # Sort entries
                if sort == 'path':
                    sorted_entries = sorted(baseline.items())
                else:  # sort by hash
                    sorted_entries = sorted(baseline.items(), key=lambda x: x[1])

                # Output in requested format
                if format == 'json':
                    filtered_baseline = dict(sorted_entries)
                    click.echo(json.dumps(filtered_baseline, indent=2))
                else:
                    click.echo(f"Baseline file: {path}")
                    click.echo(f"Total entries: {total_entries}")
                    if filter:
                        click.echo(f"Filtered entries: {len(sorted_entries)} (filter: '{filter}')")

                    for path, hash in sorted_entries:
                        click.echo(f"{path}: {hash}")

                return 0
            except json.JSONDecodeError:
                click.echo(f"Error: Invalid baseline file format: {path}", err=True)
                return 1
            except Exception as e:
                click.echo(f"Error reading baseline file: {str(e)}", err=True)
                return 1

        @integrity.command('backup-baseline')
        @click.option('--path', help='Path to the baseline file to backup')
        @click.option('--backup-dir', help='Directory to store backup (defaults to baseline_backups)')
        @click.option('--comment', help='Optional comment to add to backup filename')
        @with_appcontext
        def backup_baseline(path, backup_dir, comment):
            """Create a backup of the current integrity baseline file."""
            # Get baseline path from config if not provided
            if not path:
                path = current_app.config.get('FILE_BASELINE_PATH')
                if not path:
                    click.echo("Error: No baseline path configured", err=True)
                    return 1

            # Check if baseline exists
            if not os.path.exists(path):
                click.echo(f"Error: Baseline file not found: {path}", err=True)
                return 1

            try:
                # Create backup filename with timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

                # Get backup directory
                if not backup_dir:
                    environment = current_app.config.get('ENVIRONMENT', 'development')
                    backup_path_template = current_app.config.get(
                        'BASELINE_BACKUP_PATH_TEMPLATE',
                        'instance/security/baseline_backups/{timestamp}_{environment}.json'
                    )
                    backup_path = backup_path_template.format(
                        timestamp=timestamp,
                        environment=environment
                    )

                    # Extract directory
                    backup_dir = os.path.dirname(backup_path)

                # Create backup directory if it doesn't exist
                os.makedirs(backup_dir, exist_ok=True)

                # Create backup filename
                backup_name = f"baseline_{timestamp}"
                if comment:
                    # Sanitize comment for use in filename
                    comment = ''.join(c if c.isalnum() or c in '_-' else '_' for c in comment)
                    backup_name += f"_{comment}"

                backup_path = os.path.join(backup_dir, f"{backup_name}.json")

                # Create backup
                with open(path, 'rb') as src, open(backup_path, 'wb') as dst:
                    dst.write(src.read())

                click.echo(click.style(f"✓ Baseline backup created: {backup_path}", fg='green'))
                return 0

            except Exception as e:
                click.echo(f"Error creating baseline backup: {str(e)}", err=True)
                return 1

        @integrity.command('verify')
        @click.option('--path', help='Path to the baseline file to verify against')
        @click.option('--report-only/--update', default=True,
                    help='Only report issues, do not update baseline')
        @click.option('--verbose', '-v', count=True,
                    help='Verbose output (use multiple times for more detail)')
        @with_appcontext
        def verify_integrity_baseline(path, report_only, verbose):
            """Verify file integrity against baseline."""
            from core.seeder import verify_baseline_integrity

            click.echo("Verifying file integrity against baseline...")

            result = verify_baseline_integrity(
                baseline_path=path,
                report_only=report_only,
                verbose=verbose > 0
            )

            if result.get('success', False):
                changes = result.get('changes', [])
                if not changes:
                    click.echo(click.style("✓ All files passed integrity check", fg='green'))
                    click.echo(f"  - Files checked: {result.get('files_checked', 0)}")
                else:
                    click.echo(click.style(f"✗ {len(changes)} integrity violations found!", fg='yellow'))

                    # Group changes by severity
                    by_severity = {}
                    for change in changes:
                        severity = change.get('severity', 'unknown')
                        by_severity.setdefault(severity, []).append(change)

                    # Display counts by severity
                    for severity in ['critical', 'high', 'medium', 'low']:
                        if severity in by_severity:
                            color = 'red' if severity == 'critical' else 'yellow'
                            click.echo(click.style(
                                f"  - {severity.upper()}: {len(by_severity[severity])} issues",
                                fg=color
                            ))

                    # Display critical and high severity issues
                    for severity in ['critical', 'high']:
                        if severity in by_severity:
                            click.echo(f"\n{severity.upper()} SEVERITY ISSUES:")
                            for change in by_severity[severity]:
                                status = change.get('status', 'unknown')
                                path = change.get('path', 'unknown')
                                click.echo(click.style(f"  • {status}: {path}", fg='red'))

                    # Display summary and baseline path
                    click.echo(f"\nSummary:")
                    click.echo(f"  - Files checked: {result.get('files_checked', 0)}")
                    click.echo(f"  - Issues found: {len(changes)}")

                    # Suggest action if in report-only mode
                    if report_only:
                        click.echo("\nTo update the baseline with these changes, run:")
                        click.echo(click.style("  flask integrity update-baseline --force", fg='blue'))

                return 0
            else:
                click.echo(click.style(f"✗ Verification failed: {result.get('error', 'Unknown error')}", fg='red'))
                return 1

        @integrity.command('compare-baselines')
        @click.argument('baseline1', type=click.Path(exists=True))
        @click.argument('baseline2', type=click.Path(exists=True))
        @click.option('--format', type=click.Choice(['text', 'json']), default='text',
                    help='Output format (text or json)')
        @with_appcontext
        def compare_baselines(baseline1, baseline2, format):
            """Compare two baseline files and show differences."""
            try:
                # Load baselines
                with open(baseline1, 'r') as f:
                    data1 = json.load(f)

                with open(baseline2, 'r') as f:
                    data2 = json.load(f)

                # Compare files
                only_in_1 = {path: hash for path, hash in data1.items() if path not in data2}
                only_in_2 = {path: hash for path, hash in data2.items() if path not in data1}

                # Find modified files (same path, different hash)
                modified = {}
                for path, hash1 in data1.items():
                    if path in data2 and data2[path] != hash1:
                        modified[path] = {
                            'baseline1': hash1,
                            'baseline2': data2[path]
                        }

                # Prepare results
                comparison = {
                    'baseline1': os.path.basename(baseline1),
                    'baseline2': os.path.basename(baseline2),
                    'only_in_baseline1': only_in_1,
                    'only_in_baseline2': only_in_2,
                    'modified': modified,
                    'summary': {
                        'baseline1_total': len(data1),
                        'baseline2_total': len(data2),
                        'only_in_baseline1': len(only_in_1),
                        'only_in_baseline2': len(only_in_2),
                        'modified': len(modified),
                        'identical': len([path for path, hash in data1.items()
                                        if path in data2 and data2[path] == hash])
                    }
                }

                # Output in requested format
                if format == 'json':
                    click.echo(json.dumps(comparison, indent=2))
                else:
                    click.echo(f"Comparing baselines:")
                    click.echo(f"  - Baseline 1: {baseline1} ({len(data1)} entries)")
                    click.echo(f"  - Baseline 2: {baseline2} ({len(data2)} entries)")

                    summary = comparison['summary']
                    click.echo("\nSummary:")
                    click.echo(f"  - Files only in baseline 1: {summary['only_in_baseline1']}")
                    click.echo(f"  - Files only in baseline 2: {summary['only_in_baseline2']}")
                    click.echo(f"  - Modified files: {summary['modified']}")
                    click.echo(f"  - Identical files: {summary['identical']}")

                    if only_in_1:
                        click.echo("\nFiles only in baseline 1:")
                        for path in sorted(only_in_1.keys()):
                            click.echo(f"  - {path}")

                    if only_in_2:
                        click.echo("\nFiles only in baseline 2:")
                        for path in sorted(only_in_2.keys()):
                            click.echo(f"  - {path}")

                    if modified:
                        click.echo("\nModified files:")
                        for path in sorted(modified.keys()):
                            click.echo(f"  - {path}")

                return 0

            except json.JSONDecodeError as e:
                click.echo(f"Error: Invalid JSON format in baseline file: {e}", err=True)
                return 1
            except Exception as e:
                click.echo(f"Error comparing baselines: {str(e)}", err=True)
                return 1

        @integrity.command('check-file')
        @click.argument('file_path', type=click.Path(exists=True))
        @click.option('--baseline', help='Path to the baseline file (uses configured path if not provided)')
        @click.option('--algorithm', type=click.Choice(['sha256', 'sha384', 'sha512', 'md5', 'sha1']),
                     default='sha256', help='Hash algorithm to use')
        @with_appcontext
        def check_file_integrity(file_path, baseline, algorithm):
            """Check if a specific file's hash matches the baseline."""
            # Get baseline path from config if not provided
            if not baseline:
                baseline = current_app.config.get('FILE_BASELINE_PATH')
                if not baseline:
                    click.echo("Error: No baseline path configured", err=True)
                    return 1

            # Check if baseline exists
            if not os.path.exists(baseline):
                click.echo(f"Error: Baseline file not found: {baseline}", err=True)
                return 1

            try:
                # Load baseline
                with open(baseline, 'r') as f:
                    baseline_data = json.load(f)

                # Get absolute path and then relative path for consistency
                abs_path = os.path.abspath(file_path)
                rel_path = os.path.relpath(abs_path, os.path.dirname(current_app.root_path))

                # Calculate current hash
                current_hash = cls.calculate_file_hash(file_path, algorithm)

                # Check if file exists in baseline
                if rel_path in baseline_data:
                    baseline_hash = baseline_data[rel_path]
                    if baseline_hash == current_hash:
                        click.echo(click.style("✓ File integrity verified", fg='green'))
                        click.echo(f"  - Path: {rel_path}")
                        click.echo(f"  - Hash: {current_hash}")
                        return 0
                    else:
                        click.echo(click.style("✗ File hash mismatch!", fg='red'))
                        click.echo(f"  - Path: {rel_path}")
                        click.echo(f"  - Current hash: {current_hash}")
                        click.echo(f"  - Baseline hash: {baseline_hash}")
                        return 1
                else:
                    click.echo(click.style("! File not in baseline", fg='yellow'))
                    click.echo(f"  - Path: {rel_path}")
                    click.echo(f"  - Current hash: {current_hash}")

                    # Show command to add file to baseline
                    click.echo("\nTo add this file to the baseline, run:")
                    click.echo(click.style(f"  flask integrity update-baseline --include '{os.path.basename(file_path)}'", fg='blue'))
                    return 1

            except json.JSONDecodeError:
                click.echo(f"Error: Invalid baseline file format: {baseline}", err=True)
                return 1
            except Exception as e:
                click.echo(f"Error checking file: {str(e)}", err=True)
                return 1

        # Log registration
        logger.debug("Registered file integrity CLI commands")


config = BaseConfig
"""
Configuration object for easy import.

This provides a convenient shorthand for importing the configuration class.

Example:
    from config import config
    app_config = config.load('production')
"""
