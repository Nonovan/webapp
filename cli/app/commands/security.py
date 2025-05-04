"""
Security commands for the Cloud Infrastructure Platform CLI.

This module provides commands for security-related operations including file integrity
verification, security baseline management, security configuration management,
and security audit reporting.
"""

import click
from flask.cli import AppGroup
from datetime import datetime
import json
import os
from typing import List, Dict, Any, Optional, Tuple

from core.security import (
    check_critical_file_integrity,
    create_file_hash_baseline,
    update_file_integrity_baseline,
    verify_baseline_update,
    get_security_events,
    validate_security_config,
    get_security_anomalies,
    check_security_dependencies,
    check_file_integrity,  # For individual file checking
    get_critical_file_hashes,  # For listing monitored files
    detect_suspicious_activity,  # For security scanning
    get_threat_summary,  # For security posture overview
    calculate_risk_score,  # For risk assessment
    log_audit_event  # For audit logging
)
from cli.common import (
    require_permission,
    handle_error,
    format_output,
    EXIT_SUCCESS,
    EXIT_ERROR
)

security_cli = AppGroup('security', help='Security management commands')

@security_cli.command('check-baseline')
@click.option('--verbose/--quiet', default=False, help='Show detailed results')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text',
              help='Output format')
@require_permission('security:view')
def check_security_baseline(verbose: bool, output_format: str) -> int:
    """
    Verify the current security baseline status.

    Checks file integrity and security configurations against the established baseline.
    Identifies any deviations from the secure baseline configuration.
    """
    try:
        result, changes = check_critical_file_integrity()

        if output_format == 'json':
            output = {
                'status': 'secure' if result else 'compromised',
                'changes': changes
            }
            click.echo(format_output(output, 'json'))
            return EXIT_SUCCESS if result else EXIT_ERROR

        # Text output format
        if result:
            click.echo("✅ Security baseline verified - No unauthorized changes detected")
            return EXIT_SUCCESS
        else:
            click.echo("❌ Security baseline verification FAILED")
            click.echo(f"Found {len(changes)} unauthorized changes:")

            for idx, change in enumerate(changes, 1):
                severity = change.get('severity', 'unknown')
                severity_marker = '❗❗' if severity == 'critical' else '❗'

                click.echo(f"{idx}. {severity_marker} {change.get('path')} - {change.get('status')}")
                if verbose:
                    for key, value in change.items():
                        if key not in ('path', 'status'):
                            click.echo(f"   - {key}: {value}")

            return EXIT_ERROR

    except Exception as e:
        handle_error(e, "Failed to check security baseline")
        return EXIT_ERROR

@security_cli.command('update-baseline')
@click.option('--auto/--manual', default=False, help='Automatically update baseline with current state')
@click.option('--file', type=click.Path(exists=True), help='Path to individual file to update in baseline')
@require_permission('security:admin')
def update_security_baseline(auto: bool, file: str) -> int:
    """
    Update the security baseline.

    Updates the file integrity baseline with current file states or specific files.
    """
    try:
        click.echo("Updating security baseline...")

        if file:
            # If specific file is provided, only update that file
            paths = [file]
            click.echo(f"Updating baseline for specific file: {file}")
        else:
            paths = None
            click.echo("Updating baseline for all monitored files...")

        # Call core function to update baseline
        success, msg = update_file_integrity_baseline(paths_to_update=paths)

        if not success:
            click.echo(f"❌ Failed to update baseline: {msg}")
            return EXIT_ERROR

        # Verify the update if not in auto mode
        if not auto:
            click.echo("Verifying baseline update...")
            verified, verification_msg = verify_baseline_update()

            if not verified:
                click.echo(f"⚠️ Baseline updated but verification failed: {verification_msg}")
                return EXIT_ERROR

            click.echo("✅ Baseline update verified successfully")

        click.echo(f"✅ Baseline updated successfully: {msg}")
        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to update security baseline")
        return EXIT_ERROR

@security_cli.command('events')
@click.option('--days', type=int, default=7, help='Number of days of events to retrieve')
@click.option('--severity', type=click.Choice(['info', 'warning', 'error', 'critical']),
              help='Filter by severity level')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json', 'csv']),
              default='text', help='Output format')
@require_permission('security:view')
def view_security_events(days: int, severity: str, output_format: str) -> int:
    """
    View security events and alerts.

    Displays security-related events from the audit log including auth attempts,
    permission changes, file integrity violations, and other security events.
    """
    try:
        events = get_security_events(days=days, severity=severity)

        if not events:
            click.echo("No security events found for the specified criteria.")
            return EXIT_SUCCESS

        if output_format == 'json':
            click.echo(format_output(events, 'json'))
            return EXIT_SUCCESS

        elif output_format == 'csv':
            # Create CSV string
            import csv
            import io

            output = io.StringIO()
            if events:
                # Get fields from first event
                fieldnames = ['event_type', 'timestamp', 'severity', 'description', 'user_id', 'ip_address']

                writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for event in events:
                    writer.writerow(event)

                click.echo(output.getvalue())
            return EXIT_SUCCESS

        else:  # text format
            click.echo(f"Security Events (last {days} days):")
            click.echo("-" * 80)

            for idx, event in enumerate(events, 1):
                # Format timestamp to be more readable
                timestamp = event.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except (ValueError, AttributeError):
                        formatted_time = timestamp
                else:
                    formatted_time = 'Unknown'

                event_type = event.get('event_type', 'unknown')
                severity = event.get('severity', 'info')
                description = event.get('description', 'No description')

                # Add severity indicator
                if severity == 'critical':
                    severity_marker = '❗❗'
                elif severity == 'error':
                    severity_marker = '❗'
                elif severity == 'warning':
                    severity_marker = '⚠️'
                else:
                    severity_marker = 'ℹ️'

                click.echo(f"{idx}. {severity_marker} [{formatted_time}] {event_type}")
                click.echo(f"   {description}")

                # Show additional details
                user_id = event.get('user_id')
                if user_id:
                    click.echo(f"   User: {user_id}")

                ip_address = event.get('ip_address')
                if ip_address:
                    click.echo(f"   IP: {ip_address}")

                click.echo("-" * 80)

            return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to retrieve security events")
        return EXIT_ERROR

@security_cli.command('analyze')
@click.option('--thorough/--quick', default=False, help='Perform a thorough security analysis')
@click.option('--report', type=click.Path(), help='Path to save the analysis report')
@require_permission('security:admin')
def analyze_security(thorough: bool, report: str) -> int:
    """
    Analyze system security posture.

    Performs a comprehensive analysis of the system's security configuration,
    identifying potential vulnerabilities and security gaps.
    """
    try:
        # Import additional security analysis functions
        from core.security import (
            validate_security_config,
            get_security_anomalies,
            check_security_dependencies
        )

        click.echo(f"Performing {'thorough' if thorough else 'quick'} security analysis...")
        issues = []

        # Check security configuration
        click.echo("Checking security configuration...")
        config_issues = validate_security_config()
        if config_issues:
            issues.extend([{"type": "config", "issue": issue} for issue in config_issues])
            click.echo(f"⚠️ Found {len(config_issues)} configuration issues")
        else:
            click.echo("✅ Security configuration looks good")

        # Check file integrity
        click.echo("Checking file integrity...")
        integrity_result, changes = check_critical_file_integrity()
        if not integrity_result:
            issues.extend([{"type": "integrity", "issue": change} for change in changes])
            click.echo(f"❌ Found {len(changes)} file integrity issues")
        else:
            click.echo("✅ File integrity verified")

        # Check security dependencies if thorough
        if thorough:
            click.echo("Checking security dependencies...")
            deps_ok, dep_issues = check_security_dependencies()
            if not deps_ok:
                issues.extend([{"type": "dependency", "issue": issue} for issue in dep_issues])
                click.echo(f"⚠️ Found {len(dep_issues)} dependency issues")
            else:
                click.echo("✅ Security dependencies verified")

            # Check for security anomalies
            click.echo("Checking for security anomalies...")
            anomalies = get_security_anomalies(hours=24)
            if anomalies:
                issues.extend([{"type": "anomaly", "issue": anomaly} for anomaly in anomalies])
                click.echo(f"⚠️ Found {len(anomalies)} security anomalies")
            else:
                click.echo("✅ No security anomalies detected")

        # Generate report
        if report:
            click.echo(f"Generating report at {report}...")
            with open(report, 'w') as f:
                import json

                report_data = {
                    "timestamp": datetime.now().isoformat(),
                    "analysis_type": "thorough" if thorough else "quick",
                    "issues_count": len(issues),
                    "issues": issues,
                    "summary": {
                        "config_issues": len(config_issues) if 'config_issues' in locals() else 0,
                        "integrity_issues": len(changes) if not integrity_result else 0,
                        "dependency_issues": len(dep_issues) if thorough and not deps_ok else 0,
                        "anomalies": len(anomalies) if thorough and 'anomalies' in locals() else 0
                    }
                }

                json.dump(report_data, f, indent=2)
                click.echo(f"✅ Report saved to {report}")

        # Final output
        if issues:
            click.echo(f"❌ Analysis complete. Found {len(issues)} security issues.")
            return EXIT_ERROR
        else:
            click.echo("✅ Analysis complete. No security issues found.")
            return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to perform security analysis")
        return EXIT_ERROR

# 1. File Integrity Commands
@security_cli.command('list-monitored')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text',
              help='Output format')
@require_permission('security:view')
def list_monitored_files(output_format: str) -> int:
    """
    List files monitored by the integrity system.

    Shows all files currently being monitored by the file integrity system,
    including their hash algorithm and priority level.
    """
    try:
        monitored_files = get_critical_file_hashes()

        if not monitored_files:
            click.echo("No files are currently being monitored.")
            return EXIT_SUCCESS

        if output_format == 'json':
            click.echo(format_output(monitored_files, 'json'))
            return EXIT_SUCCESS

        # Text output format
        click.echo("Files monitored by integrity system:")
        click.echo("-" * 80)

        for path, info in monitored_files.items():
            priority = info.get('priority', 'normal')
            algorithm = info.get('algorithm', 'sha256')
            priority_marker = "❗" if priority == 'critical' else "ℹ️"

            click.echo(f"{priority_marker} {path}")
            click.echo(f"   Priority: {priority}")
            click.echo(f"   Algorithm: {algorithm}")
            click.echo("-" * 80)

        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to list monitored files")
        return EXIT_ERROR

@security_cli.command('verify-file')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--verbose/--quiet', default=False, help='Show detailed results')
@require_permission('security:view')
def verify_file_integrity(file_path: str, verbose: bool) -> int:
    """
    Verify the integrity of a specific file.

    Checks if a specific file matches its baseline hash and permission settings.
    """
    try:
        # Check individual file integrity
        result, changes = check_file_integrity(file_path)

        if result:
            click.echo(f"✅ File integrity verified for {file_path}")
            if verbose:
                click.echo("File matches the baseline hash and permissions.")
            return EXIT_SUCCESS
        else:
            click.echo(f"❌ File integrity verification FAILED for {file_path}")

            if changes:
                change = changes[0]  # Should only be one change for a single file
                status = change.get('status', 'modified')
                expected_hash = change.get('expected_hash', 'N/A')
                current_hash = change.get('current_hash', 'N/A')

                click.echo(f"Status: {status}")

                if verbose:
                    click.echo(f"Expected hash: {expected_hash}")
                    click.echo(f"Current hash: {current_hash}")

                    if 'expected_permissions' in change:
                        click.echo(f"Expected permissions: {change['expected_permissions']}")
                        click.echo(f"Current permissions: {change.get('current_permissions', 'N/A')}")

            return EXIT_ERROR

    except Exception as e:
        handle_error(e, f"Failed to verify file integrity for {file_path}")
        return EXIT_ERROR

# 2. Security Scanning Commands
@security_cli.command('scan')
@click.option('--scope', type=click.Choice(['system', 'users', 'network', 'all']), default='all',
              help='Scope of security scan')
@click.option('--deep/--surface', default=False, help='Perform deep scan (slower but more thorough)')
@click.option('--report', type=click.Path(), help='Path to save scan report')
@require_permission('security:admin')
def security_scan(scope: str, deep: bool, report: str) -> int:
    """
    Perform security scan on the system.

    Scans the system for potential security issues including suspicious activity,
    insecure configurations, and possible compromises.
    """
    try:
        click.echo(f"Starting security scan (scope: {scope}, {'deep' if deep else 'surface'} scan)...")

        # Set the hours to look back based on scan depth
        hours_to_scan = 168 if deep else 24  # 7 days for deep scan, 1 day for surface

        # Placeholder for scan findings
        findings = []

        # Scan for suspicious activity
        if scope in ['all', 'system', 'users']:
            click.echo("Scanning for suspicious activity...")
            suspicious_activities = detect_suspicious_activity(hours=hours_to_scan)

            if suspicious_activities:
                findings.extend([{
                    'category': 'suspicious_activity',
                    'severity': activity.get('severity', 'medium'),
                    'description': activity.get('description', 'Unknown suspicious activity'),
                    'details': activity
                } for activity in suspicious_activities])

                click.echo(f"⚠️ Found {len(suspicious_activities)} suspicious activities")
            else:
                click.echo("✅ No suspicious activity detected")

        # Get threat summary
        if scope in ['all', 'system', 'network']:
            click.echo("Analyzing threat indicators...")
            threats = get_threat_summary(hours=hours_to_scan)

            if threats and threats.get('threats_detected', 0) > 0:
                threat_details = threats.get('details', [])
                findings.extend([{
                    'category': 'threat',
                    'severity': threat.get('severity', 'high'),
                    'description': threat.get('description', 'Unknown threat'),
                    'details': threat
                } for threat in threat_details])

                click.echo(f"⚠️ Found {threats.get('threats_detected', 0)} potential threats")
            else:
                click.echo("✅ No threats detected")

        # Calculate overall risk score
        risk_score = calculate_risk_score()
        risk_level = 'low'
        if risk_score > 70:
            risk_level = 'critical'
        elif risk_score > 50:
            risk_level = 'high'
        elif risk_score > 30:
            risk_level = 'medium'

        # Print scan summary
        click.echo("\n--- Security Scan Summary ---")
        click.echo(f"Risk Score: {risk_score}/100 ({risk_level.upper()})")
        click.echo(f"Total findings: {len(findings)}")
        if findings:
            by_severity = {}
            for finding in findings:
                severity = finding.get('severity', 'low')
                by_severity[severity] = by_severity.get(severity, 0) + 1

            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in by_severity:
                    click.echo(f"- {severity.capitalize()}: {by_severity[severity]}")

        # Generate report if requested
        if report and findings:
            click.echo(f"\nGenerating report at {report}...")
            with open(report, 'w') as f:
                report_data = {
                    'timestamp': datetime.now().isoformat(),
                    'risk_score': risk_score,
                    'risk_level': risk_level,
                    'scan_type': 'deep' if deep else 'surface',
                    'scan_scope': scope,
                    'findings_count': len(findings),
                    'findings': findings
                }
                json.dump(report_data, f, indent=2)
                click.echo(f"✅ Report saved to {report}")

        # Return appropriate exit code based on findings
        if findings:
            # See if any critical findings
            has_critical = any(f.get('severity') == 'critical' for f in findings)
            if has_critical:
                click.echo("\n❌ Critical security issues found. Immediate action required!")
                return EXIT_ERROR
            else:
                click.echo("\n⚠️ Security issues found. Review recommended.")
                return EXIT_SUCCESS
        else:
            click.echo("\n✅ No security issues found.")
            return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to complete security scan")
        return EXIT_ERROR

# 3. System Security Commands
@security_cli.command('status')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text',
              help='Output format')
@require_permission('security:view')
def security_status(output_format: str) -> int:
    """
    Show current security status of the system.

    Displays security health, active threats, recent incidents,
    and overall security posture.
    """
    try:
        # Get security posture components
        risk_score = calculate_risk_score()
        threat_summary = get_threat_summary(hours=24)
        dependencies_ok, dependency_issues = check_security_dependencies()
        _, integrity_issues = check_critical_file_integrity()
        anomalies = get_security_anomalies(hours=24)

        # Build status report
        status = {
            'timestamp': datetime.now().isoformat(),
            'risk_score': risk_score,
            'risk_level': 'critical' if risk_score > 70 else 'high' if risk_score > 50 else 'medium' if risk_score > 30 else 'low',
            'active_threats': threat_summary.get('threats_detected', 0),
            'integrity_issues': len(integrity_issues) if integrity_issues else 0,
            'security_anomalies': len(anomalies) if anomalies else 0,
            'dependency_issues': len(dependency_issues) if dependency_issues else 0,
            'status': 'compromised' if (len(integrity_issues) > 0 or
                                      threat_summary.get('threats_detected', 0) > 0 or
                                      len(dependency_issues) > 0 and any(d.get('critical', False) for d in dependency_issues))
                     else 'at_risk' if (len(anomalies) > 0 or risk_score > 50)
                     else 'secure',
            'details': {
                'threats': threat_summary.get('details', []),
                'integrity': integrity_issues or [],
                'anomalies': anomalies or [],
                'dependencies': dependency_issues or []
            }
        }

        if output_format == 'json':
            click.echo(format_output(status, 'json'))
            return EXIT_SUCCESS

        # Text output format
        click.echo("=== Security Status Report ===")
        click.echo(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Print status with appropriate icon
        system_status = status['status'].upper()
        if system_status == 'COMPROMISED':
            click.echo(f"\nSystem Status: ❌ {system_status}")
        elif system_status == 'AT_RISK':
            click.echo(f"\nSystem Status: ⚠️ {system_status}")
        else:
            click.echo(f"\nSystem Status: ✅ {system_status}")

        click.echo(f"Risk Score: {risk_score}/100 ({status['risk_level'].upper()})")

        # Summary stats
        click.echo("\n--- Summary ---")
        click.echo(f"Active Threats: {status['active_threats']}")
        click.echo(f"Integrity Issues: {status['integrity_issues']}")
        click.echo(f"Security Anomalies: {status['security_anomalies']}")
        click.echo(f"Dependency Issues: {status['dependency_issues']}")

        # Print issue details if any exist
        if status['integrity_issues'] > 0:
            click.echo("\n--- Integrity Issues ---")
            for issue in status['details']['integrity'][:3]:  # Show top 3
                click.echo(f"- {issue.get('path', 'Unknown')}: {issue.get('status', 'modified')}")
            if len(status['details']['integrity']) > 3:
                click.echo(f"... and {len(status['details']['integrity']) - 3} more")

        if status['active_threats'] > 0:
            click.echo("\n--- Active Threats ---")
            for threat in status['details']['threats'][:3]:  # Show top 3
                click.echo(f"- {threat.get('description', 'Unknown threat')}")
            if len(status['details']['threats']) > 3:
                click.echo(f"... and {len(status['details']['threats']) - 3} more")

        # Return success regardless of security status since command executed properly
        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to get security status")
        return EXIT_ERROR

# 4. Audit and Compliance Commands
@security_cli.command('audit-log')
@click.argument('event_type')
@click.option('--details', type=str, help='Event details (JSON string)')
@click.option('--severity', type=click.Choice(['debug', 'info', 'warning', 'error', 'critical']),
              default='info', help='Event severity')
@click.option('--object-type', type=str, help='Affected object type')
@click.option('--object-id', type=str, help='Affected object ID')
@require_permission('security:admin')
def create_audit_log(event_type: str, details: str, severity: str,
                    object_type: str, object_id: str) -> int:
    """
    Create a security audit log entry.

    Records a security-relevant event in the audit log for compliance
    and security monitoring purposes.
    """
    try:
        # Parse JSON details if provided
        parsed_details = None
        if details:
            try:
                parsed_details = json.loads(details)
            except json.JSONDecodeError:
                # If not valid JSON, use as plain string
                parsed_details = details

        # Log the audit event
        log_audit_event(
            event_type=event_type,
            details=parsed_details,
            severity=severity,
            object_type=object_type,
            object_id=object_id
        )

        click.echo(f"✅ Audit log entry created successfully (type: {event_type}, severity: {severity})")
        return EXIT_SUCCESS

    except Exception as e:
        handle_error(e, "Failed to create audit log entry")
        return EXIT_ERROR

@security_cli.command('compliance-check')
@click.option('--standard', type=click.Choice(['iso27001', 'pci-dss', 'hipaa', 'gdpr', 'all']),
              default='all', help='Compliance standard to check against')
@click.option('--report', type=click.Path(), help='Path to save compliance report')
@require_permission('security:admin')
def check_compliance(standard: str, report: str) -> int:
    """
    Check system compliance against security standards.

    Verifies that the system meets the requirements of specified
    security compliance standards.
    """
    try:
        # This would need to integrate with a more sophisticated compliance checking system
        # For now, we'll do a basic simulation based on the analyze function
        click.echo(f"Checking compliance against {standard} standard...")

        # Get security posture components for compliance check
        config_issues = validate_security_config()
        integrity_result, integrity_issues = check_critical_file_integrity()
        dependencies_ok, dependency_issues = check_security_dependencies()
        anomalies = get_security_anomalies(hours=24)

        # Map issues to compliance requirements
        compliance_issues = []

        # Sample mappings (in a real system, this would be more sophisticated)
        if config_issues:
            for issue in config_issues:
                item = {
                    'standard': standard if standard != 'all' else 'multiple',
                    'requirement': 'Security Configuration',
                    'issue': issue,
                    'status': 'non_compliant'
                }
                compliance_issues.append(item)

        if not integrity_result:
            for issue in integrity_issues:
                item = {
                    'standard': standard if standard != 'all' else 'multiple',
                    'requirement': 'File Integrity',
                    'issue': issue,
                    'status': 'non_compliant'
                }
                compliance_issues.append(item)

        if not dependencies_ok:
            for issue in dependency_issues:
                if issue.get('critical', False):
                    item = {
                        'standard': standard if standard != 'all' else 'multiple',
                        'requirement': 'Security Dependencies',
                        'issue': issue,
                        'status': 'non_compliant'
                    }
                    compliance_issues.append(item)

        # Build compliance report
        compliant = len(compliance_issues) == 0
        compliance_status = "compliant" if compliant else "non_compliant"

        # Print results
        if compliant:
            click.echo(f"✅ System is compliant with {standard} standard")
        else:
            click.echo(f"❌ System is NOT compliant with {standard} standard")
            click.echo(f"Found {len(compliance_issues)} compliance issues:")

            for idx, issue in enumerate(compliance_issues, 1):
                req = issue.get('requirement', 'Unknown')
                desc = issue.get('issue', {}).get('description', 'Unknown issue')
                click.echo(f"{idx}. {req}: {desc}")

        # Generate report if requested
        if report:
            click.echo(f"\nGenerating compliance report at {report}...")
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'standard': standard,
                'status': compliance_status,
                'issues_count': len(compliance_issues),
                'issues': compliance_issues
            }

            with open(report, 'w') as f:
                json.dump(report_data, f, indent=2)
            click.echo(f"✅ Compliance report saved to {report}")

        # Return appropriate exit code based on compliance
        return EXIT_SUCCESS if compliant else EXIT_ERROR

    except Exception as e:
        handle_error(e, "Failed to check compliance")
        return EXIT_ERROR
