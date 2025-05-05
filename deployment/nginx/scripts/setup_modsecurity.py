"""
ModSecurity WAF setup utilities for Cloud Infrastructure Platform.

This module provides utilities for setting up, configuring, and managing
ModSecurity Web Application Firewall (WAF) for NGINX servers. It supports
installation of OWASP Core Rule Set (CRS), custom rule configuration,
and ModSecurity integration with NGINX.
"""

import os
import re
import shutil
import logging
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union, Callable

# Configure logger
logger = logging.getLogger(__name__)

# Constants
NGINX_ROOT = "/etc/nginx"
MODSEC_DIR = f"{NGINX_ROOT}/modsecurity"
MODSEC_RULES_DIR = f"{NGINX_ROOT}/modsecurity.d"
WAF_RULES_DIR = f"{MODSEC_RULES_DIR}/waf-rules"
CRS_DIR = f"{MODSEC_RULES_DIR}/coreruleset"
DEFAULT_CRS_VERSION = "3.3.5"
BACKUP_DIR = "/var/backups/nginx-modsec"
LOG_DIR = "/var/log/cloud-platform"


def check_modsec_installed() -> bool:
    """
    Check if ModSecurity module is installed in NGINX.

    Returns:
        bool: True if ModSecurity is installed, False otherwise
    """
    try:
        result = subprocess.run(
            ["nginx", "-V"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            universal_newlines=True
        )
        # Check both stdout and stderr as nginx -V outputs to stderr
        output = result.stdout + result.stderr
        return "ModSecurity" in output
    except Exception as e:
        logger.error(f"Failed to check ModSecurity installation: {e}")
        return False


def check_modsec_enabled() -> bool:
    """
    Check if ModSecurity is enabled in NGINX configuration.

    Returns:
        bool: True if ModSecurity is enabled, False otherwise
    """
    try:
        # Find all conf files in nginx directory
        config_files = []
        for root, _, files in os.walk(NGINX_ROOT):
            for file in files:
                if file.endswith('.conf'):
                    config_files.append(os.path.join(root, file))

        # Check for "modsecurity on" in these files
        for config_file in config_files:
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    if re.search(r'modsecurity\s+on', content):
                        return True
            except Exception:
                continue

        return False
    except Exception as e:
        logger.error(f"Failed to check if ModSecurity is enabled: {e}")
        return False


def backup_configs() -> Tuple[Optional[str], Optional[str]]:
    """
    Create backups of existing ModSecurity configurations.

    Returns:
        Tuple[Optional[str], Optional[str]]: Tuple containing paths to the
                                             backup files (config_backup, rules_backup)
    """
    try:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        modsec_backup = None
        rules_backup = None

        # Create backup directory if it doesn't exist
        os.makedirs(BACKUP_DIR, exist_ok=True)

        # Backup ModSecurity directory
        if os.path.isdir(MODSEC_DIR):
            modsec_backup = f"{BACKUP_DIR}/modsec-backup-{timestamp}.tar.gz"
            modsec_dir_name = os.path.basename(MODSEC_DIR)
            modsec_parent = os.path.dirname(MODSEC_DIR)

            subprocess.run(
                ["tar", "-czf", modsec_backup, "-C", modsec_parent, modsec_dir_name],
                check=True
            )
            logger.info(f"Created ModSecurity config backup at {modsec_backup}")

        # Backup rules directory
        if os.path.isdir(MODSEC_RULES_DIR):
            rules_backup = f"{BACKUP_DIR}/modsec-rules-{timestamp}.tar.gz"
            rules_dir_name = os.path.basename(MODSEC_RULES_DIR)
            rules_parent = os.path.dirname(MODSEC_RULES_DIR)

            subprocess.run(
                ["tar", "-czf", rules_backup, "-C", rules_parent, rules_dir_name],
                check=True
            )
            logger.info(f"Created ModSecurity rules backup at {rules_backup}")

        return modsec_backup, rules_backup

    except Exception as e:
        logger.error(f"Failed to create backups: {e}")
        return None, None


def install_owasp_crs(crs_version: str = DEFAULT_CRS_VERSION) -> bool:
    """
    Install OWASP ModSecurity Core Rule Set.

    Args:
        crs_version: Version of CRS to install

    Returns:
        bool: True if installation was successful, False otherwise
    """
    try:
        logger.info(f"Installing OWASP ModSecurity Core Rule Set {crs_version}")

        # Backup existing CRS
        if os.path.isdir(CRS_DIR):
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_file = f"{BACKUP_DIR}/crs-backup-{timestamp}.tar.gz"
            try:
                os.makedirs(os.path.dirname(backup_file), exist_ok=True)
                crs_dir_name = os.path.basename(CRS_DIR)
                crs_parent = os.path.dirname(CRS_DIR)

                subprocess.run(
                    ["tar", "-czf", backup_file, "-C", crs_parent, crs_dir_name],
                    check=True
                )
                logger.info(f"Created backup of existing CRS rules at {backup_file}")
            except Exception as e:
                logger.warning(f"Failed to backup existing CRS: {e}")

        # Create directories
        os.makedirs(MODSEC_RULES_DIR, exist_ok=True)

        # Create temp dir for downloading
        with tempfile.TemporaryDirectory() as temp_dir:
            # Download CRS
            crs_url = f"https://github.com/coreruleset/coreruleset/archive/v{crs_version}.zip"
            crs_zip = os.path.join(temp_dir, "crs.zip")

            logger.info(f"Downloading OWASP CRS from {crs_url}")
            subprocess.run(
                ["curl", "-s", "-L", crs_url, "-o", crs_zip],
                check=True
            )

            # Extract CRS
            logger.info("Extracting OWASP CRS")
            subprocess.run(
                ["unzip", "-q", crs_zip, "-d", temp_dir],
                check=True
            )

            # Remove existing CRS directory if it exists
            if os.path.isdir(CRS_DIR):
                shutil.rmtree(CRS_DIR)

            # Create CRS directory
            os.makedirs(CRS_DIR, exist_ok=True)

            # Copy extracted files to CRS directory
            extracted_dir = f"{temp_dir}/coreruleset-{crs_version}"
            for item in os.listdir(extracted_dir):
                source = os.path.join(extracted_dir, item)
                dest = os.path.join(CRS_DIR, item)
                if os.path.isdir(source):
                    shutil.copytree(source, dest)
                else:
                    shutil.copy2(source, dest)

        # Create CRS configuration from example
        crs_setup_example = os.path.join(CRS_DIR, "crs-setup.conf.example")
        crs_setup = os.path.join(CRS_DIR, "crs-setup.conf")

        if os.path.isfile(crs_setup_example):
            shutil.copy2(crs_setup_example, crs_setup)
            logger.info("Created CRS configuration from example")

        logger.info("OWASP CRS installation completed successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to install OWASP CRS: {e}")
        return False


def install_custom_waf_rules(project_root: Optional[str] = None) -> bool:
    """
    Install custom WAF rules for the platform.

    Args:
        project_root: Root directory of the project

    Returns:
        bool: True if installation was successful, False otherwise
    """
    try:
        logger.info("Installing custom WAF rules")

        # Create WAF rules directory if it doesn't exist
        os.makedirs(WAF_RULES_DIR, exist_ok=True)

        # Try to copy custom rules from project directory
        custom_rules_installed = False
        if project_root:
            custom_rules_src = os.path.join(project_root, "deployment/security/waf-rules")
            if os.path.isdir(custom_rules_src):
                logger.info(f"Copying custom WAF rules from {custom_rules_src}")

                # Copy all .conf files
                for item in os.listdir(custom_rules_src):
                    if item.endswith('.conf'):
                        source = os.path.join(custom_rules_src, item)
                        dest = os.path.join(WAF_RULES_DIR, item)
                        shutil.copy2(source, dest)
                        custom_rules_installed = True

        # If no custom rules found, create default ones
        if not custom_rules_installed:
            logger.warning("Custom WAF rules directory not found. Creating default rule files.")
            _create_default_rule_files()

        logger.info("Custom WAF rules installation completed")
        return True

    except Exception as e:
        logger.error(f"Failed to install custom WAF rules: {e}")
        return False


def _create_default_rule_files() -> None:
    """
    Create default WAF rule files if custom ones are not available.
    """
    # Default rule types to create
    rule_types = [
        "sensitive-data", "generic-attacks", "ip-reputation",
        "ics-protection", "command-injection", "request-limits",
        "api-protection"
    ]

    for rule_type in rule_types:
        rule_file = os.path.join(WAF_RULES_DIR, f"{rule_type}.conf")
        if not os.path.isfile(rule_file):
            logger.info(f"Creating default {rule_type}.conf")

            with open(rule_file, 'w') as f:
                f.write(f"# {rule_type} protection rules for Cloud Infrastructure Platform\n")
                f.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d')}\n\n")

                # Add specific content for certain rule types
                if rule_type == "api-protection":
                    f.write("""
# Block API access with suspicious query parameters
SecRule ARGS_NAMES "@rx (exec|system|eval|select|union|insert|update|delete)" \\
    "id:9000,phase:2,t:none,t:lowercase,log,deny,status:403,msg:'Suspicious API parameter detected'"

# JWT token validation (placeholder - specific rules depend on implementation)
SecRule REQUEST_HEADERS:Authorization "!@rx ^Bearer\\s+([a-zA-Z0-9\\._-]+)$" \\
    "id:9001,phase:1,t:none,log,deny,status:401,msg:'Invalid Authorization header format',chain"
SecRule REQUEST_URI "@rx ^/api/" ""
""")
                elif rule_type == "ics-protection":
                    f.write("""
# Block common ICS protocol keywords that shouldn't appear in web requests
SecRule ARGS|ARGS_NAMES|REQUEST_URI "@rx (modbus|bacnet|dnp3|ethernet/ip|profinet)" \\
    "id:9100,phase:2,t:none,t:lowercase,log,deny,status:403,msg:'Potential ICS protocol tampering'"

# Restricted access to ICS endpoints
SecRule REQUEST_URI "@beginsWith /api/ics/" \\
    "id:9101,phase:1,t:none,log,pass,id:'9101',msg:'ICS API access'"
""")
                else:
                    f.write("# This is a placeholder file. Add your custom rules below.\n")
                    f.write("# See ModSecurity documentation for rule syntax.\n")


def create_modsec_config(project_root: Optional[str] = None) -> bool:
    """
    Create main ModSecurity configuration.

    Args:
        project_root: Root directory of the project

    Returns:
        bool: True if configuration was created successfully, False otherwise
    """
    try:
        logger.info("Creating ModSecurity main configuration")

        # Create directories if they don't exist
        os.makedirs(MODSEC_DIR, exist_ok=True)
        os.makedirs(MODSEC_RULES_DIR, exist_ok=True)

        # Check if a custom config exists in the project
        modsec_conf_path = os.path.join(MODSEC_DIR, "modsecurity.conf")
        if project_root:
            modsec_conf_src = os.path.join(project_root, "deployment/security/modsecurity.conf")
            if os.path.isfile(modsec_conf_src):
                logger.info(f"Using ModSecurity configuration from {modsec_conf_src}")
                shutil.copy2(modsec_conf_src, modsec_conf_path)
                _create_rules_inclusion_file()
                _setup_logging_directory()
                return True

        # If no custom config, create a default one
        logger.info("Creating default ModSecurity configuration")
        with open(modsec_conf_path, 'w') as f:
            f.write(f"""# ModSecurity Configuration
# Generated on {datetime.now().strftime('%Y-%m-%d')} for Cloud Infrastructure Platform

# -- Rule engine initialization ----------------------------------------------

# Enable ModSecurity, attaching it to every transaction.
SecRuleEngine On

# -- Request body handling ---------------------------------------------------

# Allow ModSecurity to access request bodies.
SecRequestBodyAccess On

# Enable XML request body parser.
SecRule REQUEST_HEADERS:Content-Type "application/xml" \\
    "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

# Enable JSON request body parser.
SecRule REQUEST_HEADERS:Content-Type "application/json" \\
    "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# Maximum request body size we will accept for buffering
SecRequestBodyLimit 13107200

# Store up to 128 KB in memory
SecRequestBodyInMemoryLimit 131072

# -- Response body handling --------------------------------------------------

# Allow ModSecurity to access response bodies.
SecResponseBodyAccess On

# Which response MIME types do you want to inspect?
SecResponseBodyMimeType text/plain text/html application/json

# Buffer response bodies of up to 512 KB
SecResponseBodyLimit 524288

# -- Filesystem configuration ------------------------------------------------

# The location where ModSecurity stores temporary files.
SecTmpDir /tmp/

# The location where ModSecurity will keep its persistent data.
SecDataDir /tmp/

# -- Audit log configuration -------------------------------------------------

# Log everything we know about a transaction.
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"

# Log all transactions or just the ones that trigger a rule?
SecAuditLogParts ABIJDEFHZ

# Use a single file for logging. This is much easier to look at.
SecAuditLogType Serial
SecAuditLog /var/log/cloud-platform/modsec_audit.log

# -- Debug log configuration -------------------------------------------------

# The default debug log configuration is to duplicate error, warning and notices.
#SecDebugLog /var/log/cloud-platform/modsec_debug.log
#SecDebugLogLevel 3

# -- Rule set configuration --------------------------------------------------

# Include the OWASP ModSecurity Core Rule Set
Include {MODSEC_RULES_DIR}/modsecurity-rules.conf
""")

        # Create rules inclusion file
        _create_rules_inclusion_file()

        # Setup logging directory
        _setup_logging_directory()

        logger.info("ModSecurity configuration created successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to create ModSecurity configuration: {e}")
        return False


def _create_rules_inclusion_file() -> bool:
    """
    Create main rule inclusion file.

    Returns:
        bool: True if creation was successful, False otherwise
    """
    try:
        logger.info("Creating main rule inclusion file")

        rules_file = os.path.join(MODSEC_RULES_DIR, "modsecurity-rules.conf")
        with open(rules_file, 'w') as f:
            f.write(f"""# ModSecurity Rules Configuration
# Generated on {datetime.now().strftime('%Y-%m-%d')} for Cloud Infrastructure Platform

# Include the CRS setup configuration
Include {CRS_DIR}/crs-setup.conf

# Include CRS rules
Include {CRS_DIR}/rules/REQUEST-901-INITIALIZATION.conf
Include {CRS_DIR}/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf
Include {CRS_DIR}/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf
Include {CRS_DIR}/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
Include {CRS_DIR}/rules/REQUEST-910-IP-REPUTATION.conf
Include {CRS_DIR}/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
Include {CRS_DIR}/rules/REQUEST-912-DOS-PROTECTION.conf
Include {CRS_DIR}/rules/REQUEST-913-SCANNER-DETECTION.conf
Include {CRS_DIR}/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include {CRS_DIR}/rules/REQUEST-921-PROTOCOL-ATTACK.conf
Include {CRS_DIR}/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include {CRS_DIR}/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include {CRS_DIR}/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include {CRS_DIR}/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include {CRS_DIR}/rules/REQUEST-934-APPLICATION-ATTACK-NODEJS.conf
Include {CRS_DIR}/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include {CRS_DIR}/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include {CRS_DIR}/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include {CRS_DIR}/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf

# Include custom rules
Include {WAF_RULES_DIR}/*.conf

# Logging all matched rules
SecRule TX:MONITORING "@eq 1" \\
  "id:90001,phase:5,pass,log,msg:'ModSecurity: Alert - %{tx.msg}'"
""")
        return True
    except Exception as e:
        logger.error(f"Failed to create rules inclusion file: {e}")
        return False


def _setup_logging_directory() -> bool:
    """
    Set up logging directory for ModSecurity.

    Returns:
        bool: True if setup was successful, False otherwise
    """
    try:
        # Create log directory
        os.makedirs(LOG_DIR, exist_ok=True)

        # Create audit log file if it doesn't exist
        audit_log = f"{LOG_DIR}/modsec_audit.log"
        if not os.path.exists(audit_log):
            with open(audit_log, 'a'):
                pass

        # Set secure permissions
        os.chmod(audit_log, 0o640)

        return True
    except Exception as e:
        logger.error(f"Failed to set up logging directory: {e}")
        return False


def enable_modsecurity() -> bool:
    """
    Enable ModSecurity in NGINX.

    Returns:
        bool: True if ModSecurity was enabled successfully, False otherwise
    """
    try:
        logger.info("Enabling ModSecurity in NGINX")

        # Verify ModSecurity module is installed
        if not check_modsec_installed():
            logger.error("ModSecurity module is not installed in NGINX")
            logger.error("Please install NGINX with ModSecurity support first")
            logger.error("For Ubuntu: apt-get install nginx libnginx-mod-http-modsecurity")
            logger.error("For CentOS: yum install nginx-module-modsecurity")
            return False

        # Create ModSecurity include file for NGINX
        modsec_nginx_conf = os.path.join(NGINX_ROOT, "conf.d/modsecurity.conf")
        with open(modsec_nginx_conf, 'w') as f:
            f.write(f"""# ModSecurity configuration for NGINX
# Generated on {datetime.now().strftime('%Y-%m-%d')}

modsecurity on;
modsecurity_rules_file {MODSEC_DIR}/modsecurity.conf;

# Define environment variable for WAF status monitoring
modsecurity_status_variable $modsec_status;
""")

        # Enable ModSecurity in server blocks
        main_conf_files = [
            f"{NGINX_ROOT}/sites-available/cloud-platform.conf",
            f"{NGINX_ROOT}/sites-available/staging.conf",
            f"{NGINX_ROOT}/sites-available/development.conf"
        ]

        changes_made = False
        for conf_file in main_conf_files:
            if os.path.isfile(conf_file):
                logger.info(f"Checking ModSecurity in {conf_file}")

                # Read the file content
                with open(conf_file, 'r') as f:
                    content = f.read()

                # Check if modsecurity config already included
                if not re.search(r'include.*modsecurity\.conf', content):
                    logger.info(f"Enabling ModSecurity in {conf_file}")
                    # Insert the include directive after server { line
                    content = re.sub(
                        r'(server\s*{)',
                        r'\1\n    include conf.d/modsecurity.conf;',
                        content
                    )
                    changes_made = True

                # Make sure ModSecurity is on if it's explicitly set
                if re.search(r'modsecurity\s+off', content):
                    logger.info(f"Switching ModSecurity from off to on in {conf_file}")
                    content = re.sub(r'modsecurity\s+off', 'modsecurity on', content)
                    changes_made = True

                # Write the updated content back
                if changes_made:
                    with open(conf_file, 'w') as f:
                        f.write(content)

        if changes_made:
            logger.info("ModSecurity enabled in NGINX configurations")
        else:
            logger.info("No changes needed - ModSecurity appears to be already enabled")

        # Create status endpoint
        create_status_page()

        # Configure log rotation
        configure_logrotate()

        return True

    except Exception as e:
        logger.error(f"Failed to enable ModSecurity: {e}")
        return False


def disable_modsecurity() -> bool:
    """
    Disable ModSecurity in NGINX.

    Returns:
        bool: True if ModSecurity was disabled successfully, False otherwise
    """
    try:
        logger.info("Disabling ModSecurity in NGINX")

        # Set modsecurity off in the main config
        modsec_nginx_conf = os.path.join(NGINX_ROOT, "conf.d/modsecurity.conf")
        if os.path.isfile(modsec_nginx_conf):
            logger.info(f"Setting ModSecurity to off in {modsec_nginx_conf}")
            with open(modsec_nginx_conf, 'r') as f:
                content = f.read()

            content = re.sub(r'modsecurity\s+on', 'modsecurity off', content)

            with open(modsec_nginx_conf, 'w') as f:
                f.write(content)

        # Check for modsecurity settings in server blocks
        main_conf_files = [
            f"{NGINX_ROOT}/sites-available/cloud-platform.conf",
            f"{NGINX_ROOT}/sites-available/staging.conf",
            f"{NGINX_ROOT}/sites-available/development.conf"
        ]

        for conf_file in main_conf_files:
            if os.path.isfile(conf_file) and 'modsecurity on' in open(conf_file).read():
                logger.info(f"Setting ModSecurity to off in {conf_file}")
                with open(conf_file, 'r') as f:
                    content = f.read()

                content = re.sub(r'modsecurity\s+on', 'modsecurity off', content)

                with open(conf_file, 'w') as f:
                    f.write(content)

        logger.info("ModSecurity disabled in NGINX")
        return True

    except Exception as e:
        logger.error(f"Failed to disable ModSecurity: {e}")
        return False


def test_nginx_config() -> bool:
    """
    Test NGINX configuration.

    Returns:
        bool: True if the configuration is valid, False otherwise
    """
    try:
        logger.info("Testing NGINX configuration")
        result = subprocess.run(
            ["nginx", "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            universal_newlines=True
        )

        if result.returncode == 0:
            logger.info("NGINX configuration test passed")
            return True
        else:
            logger.error("NGINX configuration test failed")
            logger.error(result.stderr)
            return False
    except Exception as e:
        logger.error(f"Failed to test NGINX configuration: {e}")
        return False


def reload_nginx() -> bool:
    """
    Reload NGINX to apply configuration changes.

    Returns:
        bool: True if NGINX was reloaded successfully, False otherwise
    """
    try:
        logger.info("Reloading NGINX")
        result = subprocess.run(
            ["systemctl", "reload", "nginx"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            universal_newlines=True
        )

        if result.returncode == 0:
            logger.info("NGINX reloaded successfully")
            return True
        else:
            logger.error("Failed to reload NGINX")
            logger.error(result.stderr)
            return False
    except Exception as e:
        logger.error(f"Failed to reload NGINX: {e}")
        return False


def create_status_page() -> bool:
    """
    Create ModSecurity status endpoint for health checks.

    Returns:
        bool: True if status page was created successfully, False otherwise
    """
    try:
        logger.info("Creating ModSecurity status endpoint")

        status_conf = os.path.join(NGINX_ROOT, "conf.d/modsec-status.conf")
        with open(status_conf, 'w') as f:
            f.write(f"""# ModSecurity Status Endpoint
# Generated on {datetime.now().strftime('%Y-%m-%d')}

# Health check endpoint for WAF status
location = /health/waf {{
    allow 127.0.0.1;
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;

    # Return ModSecurity status
    return 200 "ModSecurity: $modsec_status";
    add_header Content-Type text/plain;
}}
""")

        logger.info("ModSecurity status endpoint created")
        return True
    except Exception as e:
        logger.error(f"Failed to create status page: {e}")
        return False


def configure_logrotate() -> bool:
    """
    Configure log rotation for ModSecurity logs.

    Returns:
        bool: True if log rotation was configured successfully, False otherwise
    """
    try:
        logger.info("Configuring log rotation for ModSecurity logs")

        logrotate_conf = "/etc/logrotate.d/modsecurity"
        with open(logrotate_conf, 'w') as f:
            f.write(f"""/var/log/cloud-platform/modsec_audit.log {{
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -s /run/nginx.pid ]; then
            kill -USR1 $(cat /run/nginx.pid)
        fi
    endscript
}}
""")

        logger.info("Log rotation configured for ModSecurity logs")
        return True
    except Exception as e:
        logger.error(f"Failed to configure log rotation: {e}")
        return False


def setup_modsecurity(
    enable: bool = False,
    disable: bool = False,
    update_rules: bool = False,
    crs_version: str = DEFAULT_CRS_VERSION,
    project_root: Optional[str] = None
) -> bool:
    """
    Setup ModSecurity WAF for NGINX.

    Args:
        enable: Enable ModSecurity
        disable: Disable ModSecurity
        update_rules: Update OWASP Core Rule Set and custom rules
        crs_version: Version of CRS to install
        project_root: Root directory of the project

    Returns:
        bool: True if setup was successful, False otherwise
    """
    try:
        logger.info("Starting ModSecurity WAF setup for Cloud Infrastructure Platform")

        # Create backup before making changes
        backup_configs()

        # Update rules if requested or as part of enabling
        if update_rules or (enable and not os.path.isdir(CRS_DIR)):
            install_owasp_crs(crs_version)
            install_custom_waf_rules(project_root)
            create_modsec_config(project_root)

        # Enable or disable ModSecurity
        if enable:
            # Make sure CRS is installed
            if not os.path.isdir(CRS_DIR):
                install_owasp_crs(crs_version)

            # Make sure WAF rules are installed
            if not os.path.isdir(WAF_RULES_DIR) or not os.listdir(WAF_RULES_DIR):
                install_custom_waf_rules(project_root)

            # Create main configuration if needed
            if not os.path.isfile(os.path.join(MODSEC_DIR, "modsecurity.conf")):
                create_modsec_config(project_root)

            enable_modsecurity()

        elif disable:
            disable_modsecurity()

        # Test and reload nginx
        if test_nginx_config():
            reload_nginx()

            # Final status check
            if enable:
                if check_modsec_enabled():
                    logger.info("ModSecurity is now enabled and active")
                else:
                    logger.warning("ModSecurity configuration is in place but may not be active")

                # Show next steps
                logger.info("Next Steps:")
                logger.info(f"1. Review and customize rules in {WAF_RULES_DIR}")
                logger.info("2. Monitor ModSecurity logs at /var/log/cloud-platform/modsec_audit.log")
                logger.info("3. Check WAF status at /health/waf endpoint from allowed IPs")

            elif disable:
                if not check_modsec_enabled():
                    logger.info("ModSecurity is now disabled")
                else:
                    logger.warning("ModSecurity may still be active in some configurations")

            logger.info("ModSecurity WAF setup completed successfully")
            return True
        else:
            logger.error("NGINX configuration test failed. Changes may not be applied.")
            return False

    except Exception as e:
        logger.error(f"Failed to setup ModSecurity: {e}")
        return False
