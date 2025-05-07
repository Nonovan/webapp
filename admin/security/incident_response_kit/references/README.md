# Reference Materials for Incident Response

This directory contains reference materials, guides, and documentation to support incident response activities. These resources provide standardized information, guidelines, and checklists to ensure consistent and effective incident handling.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage Guidelines](#usage-guidelines)
- [API Reference](#api-reference)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The reference materials provide essential information and guidelines that support incident responders throughout the incident lifecycle. These resources follow the NIST SP 800-61 incident handling framework and align with the organization's security policies and regulatory requirements. They serve as authoritative sources of information during incident response activities, ensuring that responders have access to accurate information, proper procedures, and up-to-date contact information.

## Key Components

- **`contact_list.json`**: Emergency contact information
  - Incident response team contacts
  - Technical specialist contacts
  - Management escalation contacts
  - External support contacts
  - Regulatory authority contacts
  - Law enforcement contacts

- **`credential_compromise_remediation.md`**: Credential compromise guidance
  - Password reset procedures
  - Account recovery workflows
  - Multi-factor authentication implementation
  - Session invalidation techniques
  - Access review procedures
  - Service token rotation

- **`ddos_defense_architecture.md`**: DDoS defense reference
  - Defense architecture diagrams
  - Mitigation techniques
  - Traffic analysis procedures
  - Service provider coordination
  - Traffic filtering strategies
  - Post-attack recovery guidance

- **`evidence_collection_guide.md`**: Evidence handling procedures
  - Evidence identification guidelines
  - Collection methodologies
  - Chain of custody procedures
  - Storage requirements
  - Documentation standards
  - Legal considerations

- **`hr_coordination_guide.md`**: HR coordination guidance
  - Incident response roles for HR
  - Communication protocols
  - Employee privacy considerations
  - Investigation procedures
  - Administrative actions
  - Post-incident review process

- **`ioc_checklist.md`**: Indicators of compromise identification guide
  - Common IOC categories
  - Collection methodologies
  - Analysis techniques
  - Verification procedures
  - Sharing protocols
  - IOC management process

- **`privilege_escalation_techniques.md`**: Common privilege escalation methods
  - Known attack vectors
  - Detection techniques
  - MITRE ATT&CK mappings
  - Containment strategies
  - Permission validation procedures
  - Common vulnerability identifiers

- **`regulatory_requirements.md`**: Regulatory compliance guidance
  - Reporting timeframes by regulation
  - Required report contents
  - Notification templates
  - Compliance authority contacts
  - Documentation requirements
  - Legal obligations reference

- **`security_tools_reference.md`**: Security tools documentation
  - Core security tool configuration
  - Authentication and authorization tools
  - Encryption and cryptography tools
  - File integrity monitoring utilities
  - Session security mechanisms
  - Security header management

- **`severity_classification.md`**: Incident severity guidelines
  - Severity level definitions
  - Impact assessment criteria
  - Escalation thresholds
  - Response timeframes by severity
  - Resource allocation guidelines
  - Classification examples

- **`traffic_analysis_guide.md`**: Network traffic analysis guide
  - Traffic analysis methodologies
  - Visualization techniques
  - Attack pattern recognition
  - Anomaly detection strategies
  - Packet inspection guidelines
  - Traffic filtering implementations

- **`web_hardening.md`**: Web application hardening guide
  - Security headers implementation
  - Input validation strategies
  - Output encoding requirements
  - Authentication hardening
  - Session management security
  - Access control enhancements

- **`web_testing_methodology.md`**: Web security testing methodology
  - Testing procedures and checklists
  - API security assessment techniques
  - Authentication testing frameworks
  - Authorization testing strategies
  - Input validation testing
  - Output encoding verification

## Directory Structure

```plaintext
admin/security/incident_response_kit/references/
├── README.md                           # This documentation
├── contact_list.json                   # Emergency contacts information
├── credential_compromise_remediation.md # Credential compromise guidance
├── ddos_defense_architecture.md        # DDoS defense references
├── evidence_collection_guide.md        # Evidence collection procedures
├── hr_coordination_guide.md            # HR coordination procedures
├── insider_threat_indicators.md        # Insider threat detection guide
├── ioc_checklist.md                    # Indicators of compromise guide
├── permission_validation.md            # Permission validation procedures
├── privilege_escalation_detection.md   # Privilege escalation detection guide
├── privilege_escalation_techniques.md  # Privilege escalation vectors
├── regulatory_requirements.md          # Regulatory compliance guidance
├── security_tools_reference.md         # Security tools documentation
├── severity_classification.md          # Incident severity guidelines
├── traffic_analysis_guide.md           # Network traffic analysis guide
├── waf_rule_development.md             # WAF rule development guide
├── web_hardening.md                    # Web application hardening guide
└── web_testing_methodology.md          # Web security testing methodology
```

## Usage Guidelines

### Contact List

The contact list is maintained in JSON format for programmatic access and contains all emergency contacts needed during incident response:

```json
// Example contact_list.json structure
{
  "incident_response_team": [
    {
      "role": "Incident Response Coordinator",
      "primary": {
        "name": "Jane Smith",
        "email": "security-lead@example.com",
        "phone": "555-123-4567",
        "pager": "555-123-4567-911"
      },
      "secondary": {
        "name": "John Doe",
        "email": "security-backup@example.com",
        "phone": "555-123-4568",
        "pager": "555-123-4568-911"
      }
    }
  ],
  "external_resources": [
    {
      "organization": "Forensic Services Provider",
      "contact_name": "Forensic Team Lead",
      "phone": "555-987-6543",
      "email": "forensics@provider.com",
      "contract_id": "FS-2023-42",
      "availability": "24x7"
    }
  ],
  "regulatory_contacts": [
    // Regulatory authority contacts
  ],
  "law_enforcement": [
    // Law enforcement contacts
  ]
}
```

Access contact information programmatically:

```python
from admin.security.incident_response_kit import get_emergency_contact

# Get incident coordinator contact
coordinator = get_emergency_contact("incident_coordinator")
print(f"Contacting Incident Coordinator: {coordinator.name} at {coordinator.phone}")

# Alternatively, load the contact list directly
import json
with open('contact_list.json', 'r') as file:
    contacts = json.load(file)

# Get forensics provider contact
forensics = next((c for c in contacts['external_resources'] if c['organization'] == 'Forensic Services Provider'), None)
```

### Severity Classification

The severity classification guide helps determine the appropriate response level for incidents:

```bash
# Example of using the severity classification with the incident initialization script
../initialize.sh --incident-id IR-2023-042 \
    --severity high \
    --severity-guide references/severity_classification.md \
    --notify
```

Programmatic severity assessment:

```python
from admin.security.incident_response_kit import evaluate_incident_severity, IncidentSeverity

# Evaluate severity based on factors
severity = evaluate_incident_severity(
    data_sensitivity="confidential",
    system_criticality="high",
    affected_users=250,
    business_impact="moderate"
)

if severity >= IncidentSeverity.HIGH:
    # Implement high-severity response procedures
    notify_incident_management_team(severity=severity.name)
```

### Evidence Collection

The evidence collection guide provides standardized procedures:

```bash
# Reference the evidence collection guide during evidence acquisition
../collect_evidence.py --incident-id IR-2023-042 \
    --hostname compromised-host-01 \
    --follow-guide references/evidence_collection_guide.md \
    --output /secure/evidence/IR-2023-042
```

### DDoS Defense Reference

Access DDoS defense architecture and procedures:

```python
from admin.security.incident_response_kit import get_mitigation_strategy

# Get mitigation strategy for specific attack type
strategy = get_mitigation_strategy(
    attack_type="dns_amplification",
    traffic_volume="high",
    target_service="web_application"
)

print(f"Recommended filtering rules: {strategy.filtering_rules}")
print(f"Provider coordination steps: {strategy.provider_steps}")
```

### Privilege Escalation Reference

Access privilege escalation techniques for analysis:

```python
from admin.security.incident_response_kit import match_privilege_escalation_pattern

# Match observed behavior to known techniques
matches = match_privilege_escalation_pattern(
    observed_commands=["chmod u+s /bin/bash", "sudo -l"],
    file_modifications=["/etc/sudoers"],
    system_type="linux"
)

for technique in matches:
    print(f"Matched technique: {technique.name} - {technique.mitigation}")
```

### Regulatory Compliance

Evaluate regulatory notification requirements:

```python
from admin.security.incident_response_kit import (
    evaluate_notification_requirements,
    NOTIFICATION_TIMEFRAMES,
    REGULATORY_AUTHORITIES
)

# Evaluate notification requirements for an incident
requirements = evaluate_notification_requirements(
    incident_id="IR-2023-042",
    data_types=["pii", "financial"],
    affected_regions=["us", "eu"],
    severity="high",
    affected_records=5000,
    has_pii=True
)

# Calculate notification deadlines
from datetime import datetime
deadlines = calculate_notification_deadlines(
    discovery_time=datetime.now(),
    requirements=requirements,
    authorities=REGULATORY_AUTHORITIES
)

for authority, deadline in deadlines.items():
    print(f"Must notify {authority} by: {deadline}")
```

### HR Coordination for Security Incidents

Implement HR coordination processes for incidents involving employees:

```python
from admin.security.incident_response_kit.coordination import hr_coordination
from core.security import cs_authentication

# Set up joint HR and Security investigation
investigation = hr_coordination.setup_joint_investigation(
    incident_id="IR-2023-042",
    employee_id="E12345",
    hr_representative="hr-manager@example.com",
    security_lead="security-lead@example.com",
    investigation_type="insider_threat",
    privacy_level="confidential"
)

# Implement temporary measures
temporary_measure = hr_coordination.implement_temporary_measure(
    employee_id="E12345",
    measure_type="ACCESS_REDUCTION",
    justification="Suspicious system access patterns",
    duration_days=7,
    approver="security-director@example.com"
)

# Document investigation findings
findings = hr_coordination.document_investigation_findings(
    incident_id="IR-2023-042",
    employee_id="E12345",
    investigation_id=investigation["investigation_id"],
    findings_summary="Evidence of unauthorized data access",
    recommended_actions=["formal_warning", "additional_training"],
    evidence_references=["evidence/system_logs.txt", "evidence/access_records.pdf"]
)
```

### Web Application Security

Access web hardening and testing guidelines:

```python
from admin.security.incident_response_kit import web_security
from core.security import initialize_security_components, SecurityConfigType

# Get security headers configuration
security_headers = web_security.get_security_headers_config(
    application_type="web_application",
    threat_model="high_risk",
    include_reporting=True
)

# Apply hardening to authentication system
auth_hardening = web_security.harden_authentication(
    target="api_gateway",
    auth_config={
        "method": "OAUTH2",
        "mfa_required": True,
        "session_timeout": 30,
        "password_policy": "strict"
    },
    test_security=True
)

# Test API authorization controls
auth_test_results = web_security.test_authorization(
    target_url="https://api.example.com/v1",
    auth_config={
        "roles": ["admin", "user", "readonly"],
        "resources": ["/users", "/reports", "/settings"]
    },
    test_vertical_access=True,
    test_horizontal_access=True
)
```

## API Reference

### Core Reference Functions

- **`analyze_traffic_patterns(traffic_data, baseline_data, detection_sensitivity)`**: Analyze network traffic patterns for anomalies
- **`calculate_file_hash(file_path, algorithms, chunk_size)`**: Calculate file hash
- **`detect_file_changes(baseline_path, check_permissions, security_level, monitored_paths)`**: Detect file changes
- **`detect_privilege_escalation_attempt(command_log, file_access_log, network_connections)`**: Detect potential privilege escalation attempts
- **`evaluate_incident_severity(data_sensitivity, system_criticality, affected_users, business_impact)`**: Calculate incident severity based on factors
- **`generate_waf_rules(attack_patterns, protection_level, platform)`**: Generate WAF rules for specific attack patterns
- **`get_emergency_contact(role)`**: Retrieve contact information for a specific role
- **`get_evidence_collection_procedures(evidence_type, system_type)`**: Get detailed evidence collection procedures
- **`get_ioc_verification_steps(ioc_type)`**: Get steps to verify specific types of indicators of compromise
- **`get_mitigation_strategy(attack_type, traffic_volume, target_service)`**: Get DDoS mitigation strategy
- **`get_regulatory_requirements(data_types, regions, sectors)`**: Get regulatory requirements for specific data types in regions/sectors
- **`load_reference_document(document_name)`**: Load reference document content as structured data
- **`match_privilege_escalation_pattern(observed_commands, file_modifications, system_type)`**: Match observed behavior to known privilege escalation techniques

### HR Coordination Functions

- **`document_investigation_findings(incident_id, employee_id, investigation_id, findings_summary, recommended_actions, evidence_references)`**: Document investigation findings
- **`generate_hr_documentation(incident_id, document_type, employee_id, template)`**: Generate HR documentation
- **`implement_temporary_measure(employee_id, measure_type, justification, duration_days, approver)`**: Implement temporary measures for employee
- **`manage_employee_privacy(employee_id, data_accessed, justification, approver)`**: Manage employee privacy during investigation
- **`schedule_post_incident_review(incident_id, completion_date, security_lead, hr_representative)`**: Schedule post-incident review meeting
- **`setup_joint_investigation(incident_id, employee_id, hr_representative, security_lead, investigation_type, privacy_level)`**: Set up joint HR and Security investigation

### Regulatory Assessment Functions

- **`calculate_notification_deadlines(discovery_time, requirements, authorities, extensions)`**: Calculate notification deadlines
- **`determine_notification_content(authority, incident_data, metadata)`**: Determine required content for notifications
- **`document_notification_evidence(incident_id, recipient, method, timestamp, template_used, evidence_file)`**: Document notification activities
- **`evaluate_notification_requirements(incident_id, data_types, affected_regions, severity, affected_records, has_pii)`**: Evaluate notification requirements for an incident
- **`export_notification_evidence(incident_id, format, output_path)`**: Export notification evidence
- **`generate_notification_template(template_type, regulation, incident_data)`**: Generate notification templates
- **`get_notification_history(incident_id, include_drafts)`**: Get notification history
- **`get_regulatory_authorities(regions, data_types, industry)`**: Get list of relevant regulatory authorities

### Security Tool Functions

- **`apply_security_headers(response, policy, csp_nonce)`**: Apply security headers to response
- **`authenticate_user(credentials, method, mfa_required, context)`**: Authenticate user with various methods
- **`check_critical_file_integrity(paths, baseline_path, alert_on_changes)`**: Check file integrity
- **`check_permission(user_id, permission, resource_id, context)`**: Check specific permission
- **`create_file_hash_baseline(paths, output_path, metadata)`**: Create file integrity baseline
- **`decrypt_sensitive_data(encrypted_data, key_id, context, algorithm)`**: Decrypt sensitive data
- **`encrypt_sensitive_data(data, key_id, context, algorithm)`**: Encrypt sensitive data
- **`generate_csp_nonce(byte_length, return_type)`**: Generate CSP nonce
- **`generate_secure_token(token_type, length, include_timestamp, expiry)`**: Generate secure token
- **`get_security_config(component, environment, include_defaults)`**: Get security configuration
- **`hash_password(password, algorithm, pepper, iterations)`**: Hash password securely
- **`initialize_secure_session(user_id, role, ip_address, user_agent, permissions, remember_me, additional_context)`**: Initialize secure session
- **`initialize_security_components(custom_config, environment, validate_on_startup, setup_metrics)`**: Initialize core security components
- **`log_security_event(event_type, severity, details, source, user_id, request_id, correlation_id)`**: Log security event
- **`regenerate_session_safely(preserve_data, delete_old_session, validate_user, extend_timeout)`**: Regenerate session securely
- **`revoke_all_user_sessions(user_id, except_current, reason, notify_user)`**: Revoke all sessions for user
- **`setup_csp(policy_level, report_uri, allow_unsafe_inline, report_only)`**: Set up Content Security Policy
- **`validate_authentication(token, valid_types, validate_claims)`**: Validate authentication token
- **`validate_request_security(request, security_rules, block_suspicious)`**: Validate request security
- **`validate_security_config(config_path, environment, strict_mode)`**: Validate security configuration
- **`verify_authorization(user_id, resource, action, context)`**: Verify user authorization
- **`verify_password(password, stored_hash, pepper)`**: Verify password against hash

### Web Security Functions

- **`get_security_headers_config(application_type, threat_model, include_reporting)`**: Get security headers configuration
- **`harden_authentication(target, auth_config, test_security, backup_config)`**: Implement authentication hardening
- **`implement_access_controls(target, acl_config, test_restrictions)`**: Implement access controls
- **`secure_api_endpoints(target, api_security_config, test_security)`**: Secure API endpoints
- **`secure_dependencies(target, dependency_config, scan_dependencies, update_vulnerable)`**: Implement dependency security
- **`secure_session_management(target, session_config, generate_tests)`**: Implement session security
- **`test_access_control(target_url, auth_config, test_resources, output_file)`**: Test access control mechanisms
- **`test_api_security(target_url, api_config, test_cases, output_file)`**: Test API security
- **`test_authentication(target_url, auth_config, test_methods, output_file)`**: Test authentication mechanisms
- **`test_horizontal_access(target_url, auth_config, test_resources, output_file)`**: Test same-role access isolation
- **`test_input_validation(target_url, input_vectors, test_payloads, output_file)`**: Test input validation
- **`test_output_encoding(target_url, encoding_vectors, test_contexts, output_file)`**: Test output encoding
- **`test_vertical_access(target_url, auth_config, role_hierarchy, test_resources, output_file)`**: Test privilege escalation
- **`validate_input_handling(target, input_types, generate_tests)`**: Validate input handling implementation
- **`verify_output_encoding(target, encoding_config, test_escaping)`**: Verify output encoding implementation
- **`verify_security_headers(target_url, expected_headers, output_file)`**: Verify security headers
- **`verify_security_implementation(target_url, requirements, control_mapping, include_evidence, output_file)`**: Verify security implementation
- **`verify_tls_configuration(target, expected_config, output_file)`**: Verify TLS configuration

### Classes

- **`AccessControlConfig`**: Access control configuration
- **`APISecurityConfig`**: API security configuration
- **`AuthenticationConfig`**: Authentication configuration
- **`DependencyConfig`**: Dependency security configuration
- **`EmergencyContact`**: Contact information with notification capabilities
- **`EscalationTechnique`**: Privilege escalation technique with detection and mitigation info
- **`EvidenceCollectionProcedure`**: Detailed evidence collection steps with validation
- **`IncidentSeverityCalculator`**: Calculator for incident severity based on multiple factors
- **`InputValidationConfig`**: Input validation configuration
- **`MitigationStrategy`**: DDoS mitigation strategy with filtering rules and coordination steps
- **`NotificationEvidence`**: Evidence of notification activities
- **`NotificationRequirement`**: Requirement for incident notification
- **`OutputEncodingConfig`**: Output encoding configuration
- **`PrivilegeEscalationIndicator`**: Indicator of privilege escalation activity
- **`RegulatoryRequirement`**: Regulatory requirement with deadlines and notification templates
- **`SecurityControl`**: Security control implementation
- **`SecurityControlVerification`**: Verification of security control
- **`SecurityHeaderConfiguration`**: Security header configuration
- **`SecurityImplementationVerification`**: Security implementation verification
- **`SessionConfig`**: Session management configuration
- **`TestResult`**: Security test result
- **`TLSConfig`**: TLS configuration
- **`TrafficPattern`**: Network traffic pattern for analysis
- **`WAFRule`**: Web Application Firewall rule

### Constants

#### Core Constants

- **`ATTACK_VECTORS`**: Common attack vectors with identification patterns
- **`EVIDENCE_TYPES`**: Types of evidence with collection requirements
- **`IOC_TYPES`**: Types of indicators of compromise with detection methods
- **`PRIVILEGED_OPERATIONS`**: Operations requiring elevated privileges
- **`REGULATORY_FRAMEWORKS`**: List of supported regulatory frameworks
- **`SEVERITY_LEVELS`**: Defined severity levels with thresholds

#### HR Coordination Constants

- **`ADMINISTRATIVE_ACTION_TYPES`**: Types of administrative actions
- **`DOCUMENTATION_TYPES`**: Types of HR documentation
- **`EMPLOYEE_PRIVACY_LEVELS`**: Privacy levels for employee data
- **`INVESTIGATION_TYPES`**: Types of investigations
- **`TEMPORARY_MEASURE_TYPES`**: Types of temporary measures

#### Regulatory Constants

- **`BREACH_NOTIFICATION_THRESHOLDS`**: Thresholds that trigger notification requirements
- **`NOTIFICATION_TIMEFRAMES`**: Regulatory timeframes for notifications
- **`REGULATORY_AUTHORITIES`**: Regulatory authorities by jurisdiction
- **`REQUIRED_NOTIFICATION_CONTENT`**: Content requirements by regulation

#### Security Tool Constants

- **`AuthenticationSource`**: Authentication sources
- **`CircuitBreakerStatus`**: Circuit breaker status values
- **`CryptoAlgorithm`**: Cryptographic algorithms
- **`EventSeverity`**: Event severity levels
- **`FileIntegrityStatus`**: File integrity status values
- **`HashAlgorithm`**: Hash algorithms
- **`KeyType`**: Key types
- **`LogLevel`**: Log level constants
- **`SecurityEventType`**: Security event types
- **`TokenType`**: Token types
- **`ValidationResult`**: Validation result types

#### Web Security Constants

- **`AccessControlTestType`**: Access control testing types
- **`AccessControlType`**: Access control types
- **`AuthenticationTestType`**: Authentication testing types
- **`AuthMethod`**: Authentication methods
- **`CSPDirective`**: Content Security Policy directives
- **`InputValidationType`**: Input validation types
- **`OutputEncodingContext`**: Output encoding contexts
- **`SecurityHeaderType`**: Security header types
- **`ServerType`**: Web server types
- **`SessionAttribute`**: Session security attributes
- **`TLSVersion`**: TLS protocol versions

## Best Practices & Security

- **Regular Updates**: Update all reference materials quarterly or after significant changes
- **Version Control**: Maintain all reference documents in version control
- **Access Control**: Ensure appropriate access controls for sensitive contact information
- **Verification**: Regularly verify all contact information for accuracy
- **Encryption**: Store sensitive contact information in encrypted format
- **Offline Copies**: Maintain offline copies of critical reference materials
- **Review Process**: Establish formal review process for all reference materials
- **Distribution Control**: Control distribution of reference materials with sensitive information
- **Training**: Include reference materials in incident response training
- **Format Consistency**: Maintain consistent formatting across all reference materials
- **Automation Integration**: Ensure reference materials can be used by automated tools
- **Standardized Formats**: Use machine-readable formats where appropriate
- **Source Attribution**: Include sources and references for technical content
- **Tiered Access**: Implement role-based access to sensitive reference materials
- **Geographic Redundancy**: Maintain copies in multiple secure locations

## Common Features

All reference materials share these common features:

- **Version Information**: All documents include version number and last update date
- **Approval Status**: Documentation of approval status and approving authority
- **Review Schedule**: Clearly defined review and update schedule
- **Standardized Format**: Consistent formatting for easy navigation
- **Security Classification**: Clear marking of information sensitivity level
- **Cross-References**: Links to related documents and resources
- **Change Log**: Documentation of significant changes
- **Responsible Owner**: Clearly identified document owner
- **Legal Review**: Indication of legal review for applicable documents
- **Export Controls**: Notification of any applicable export control requirements
- **Machine-Readable Data**: Structured formats for automated processing
- **Periodic Validation**: Documentation of validation frequency and results
- **Threat Intelligence Links**: References to related threat intelligence
- **Execution Instructions**: Clear steps for implementing guidance
- **Risk Assessment**: Associated risk level for each documented technique

## Related Documentation

- Incident Response Kit Overview
- Incident Response Playbooks
- Documentation Templates
- Forensic Tools Documentation
- Recovery Tools
- Security Incident Response Plan
- Incident Response Procedures
- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- Chain of Custody Requirements
- Regulatory Compliance Overview
- DDoS Mitigation Strategies
- Privilege Escalation Response
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-53: Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- Core Security Module Documentation
- Security Log Analysis Guide
- Network Traffic Analysis Guide
- [EU Data Protection Board Guidance on Personal Data Breach Notification](https://edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-012021-examples-regarding-personal-data-breach_en)
