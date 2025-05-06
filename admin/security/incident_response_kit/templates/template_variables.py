"""
Template Variables for Incident Response Documentation

This module defines standardized variables used in incident response documentation templates.
It helps maintain consistency across templates and provides a central reference for all
variable names with descriptions of their intended use.

Variables are organized by template type and common usage patterns, following NIST SP 800-61
incident handling framework phases.
"""

import enum
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Union


class TemplateType(enum.Enum):
    """Defines the different template types."""
    INCIDENT_REPORT = "incident_report"
    INCIDENT_TIMELINE = "incident_timeline"
    CHAIN_OF_CUSTODY = "chain_of_custody"
    COMMUNICATION_PLAN = "communication_plan"
    EXECUTIVE_BRIEFING = "executive_briefing"
    REMEDIATION_PLAN = "remediation_plan"


class VariableCategory(enum.Enum):
    """Categories for template variables."""
    METADATA = "metadata"
    CLASSIFICATION = "classification"
    INCIDENT_DETAILS = "incident_details"
    IMPACT = "impact"
    TIMELINE = "timeline"
    TECHNICAL = "technical"
    EVIDENCE = "evidence"
    RESPONSE = "response"
    COMMUNICATION = "communication"
    REMEDIATION = "remediation"
    RECOMMENDATIONS = "recommendations"
    APPROVAL = "approval"


# Common variables used across multiple templates
COMMON_VARIABLES = {
    "CLASSIFICATION": {
        "description": "Security classification of the document",
        "example": "Confidential",
        "category": VariableCategory.CLASSIFICATION
    },
    "INCIDENT_ID": {
        "description": "Unique identifier for the incident",
        "example": "IR-2023-042",
        "category": VariableCategory.METADATA
    },
    "DATE": {
        "description": "Document creation date",
        "example": datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        "category": VariableCategory.METADATA
    },
    "LAST_UPDATED": {
        "description": "Last modification timestamp",
        "example": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        "category": VariableCategory.METADATA
    },
    "STATUS": {
        "description": "Current incident status",
        "example": "Investigating",
        "category": VariableCategory.INCIDENT_DETAILS
    },
    "LEAD_RESPONDER": {
        "description": "Name of lead incident responder",
        "example": "Jane Smith",
        "category": VariableCategory.METADATA
    },
    "INCIDENT_TYPE": {
        "description": "Type of security incident",
        "example": "Data Breach",
        "category": VariableCategory.INCIDENT_DETAILS
    },
    "SEVERITY": {
        "description": "Incident severity classification",
        "example": "High",
        "category": VariableCategory.INCIDENT_DETAILS
    },
    "PHASE": {
        "description": "Current incident response phase",
        "example": "Containment",
        "category": VariableCategory.INCIDENT_DETAILS
    },
    "DOCUMENT_OWNER": {
        "description": "Person responsible for maintaining the document",
        "example": "Security Incident Response Team",
        "category": VariableCategory.METADATA
    },
    "VERSION": {
        "description": "Document version number",
        "example": "1.2",
        "category": VariableCategory.METADATA
    },
    "MODIFICATION_DATE": {
        "description": "Date of document modification",
        "example": datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        "category": VariableCategory.METADATA
    },
    "MODIFIER_NAME": {
        "description": "Name of person who modified the document",
        "example": "John Doe",
        "category": VariableCategory.METADATA
    },
    "MODIFICATION_DESCRIPTION": {
        "description": "Description of changes made to document",
        "example": "Updated technical findings and added IOCs",
        "category": VariableCategory.METADATA
    },
}

# Variables specific to incident_report.md
INCIDENT_REPORT_VARIABLES = {
    "REPORT_VERSION": {
        "description": "Version number of the report",
        "example": "1.0",
        "category": VariableCategory.METADATA
    },
    "EXECUTIVE_SUMMARY": {
        "description": "Brief summary of the incident and key findings",
        "example": "On July 15, 2023, a ransomware attack was detected affecting 3 systems...",
        "category": VariableCategory.INCIDENT_DETAILS
    },
    "MITRE_TACTICS": {
        "description": "MITRE ATT&CK tactics identified in the incident",
        "example": "Initial Access, Execution, Persistence, Privilege Escalation",
        "category": VariableCategory.TECHNICAL
    },
    "MITRE_TECHNIQUES": {
        "description": "MITRE ATT&CK techniques identified in the incident",
        "example": "T1566.001 (Phishing), T1027 (Obfuscated Files), T1136 (Create Account)",
        "category": VariableCategory.TECHNICAL
    },
    "NUM_SYSTEMS_AFFECTED": {
        "description": "Number of systems affected by the incident",
        "example": "5",
        "category": VariableCategory.IMPACT
    },
    "DATA_IMPACT": {
        "description": "Impact on data confidentiality, integrity, availability",
        "example": "Unauthorized access to customer contact information",
        "category": VariableCategory.IMPACT
    },
    "OPERATIONAL_IMPACT": {
        "description": "Impact on business operations",
        "example": "Order processing system offline for 4 hours",
        "category": VariableCategory.IMPACT
    },
    "USER_IMPACT": {
        "description": "Impact on users or customers",
        "example": "250 users unable to access service for 2 hours",
        "category": VariableCategory.IMPACT
    },
    "FINANCIAL_IMPACT": {
        "description": "Financial impact of the incident",
        "example": "Estimated $25,000 in response costs and lost revenue",
        "category": VariableCategory.IMPACT
    },
    "REPUTATIONAL_IMPACT": {
        "description": "Impact on organization's reputation",
        "example": "Limited external visibility; contained before public disclosure",
        "category": VariableCategory.IMPACT
    },
    "DETECTION_DATETIME": {
        "description": "Date and time when incident was detected",
        "example": "2023-07-15T10:45:00Z",
        "category": VariableCategory.TIMELINE
    },
    "RESPONSE_DATETIME": {
        "description": "Date and time when response was initiated",
        "example": "2023-07-15T11:00:00Z",
        "category": VariableCategory.TIMELINE
    },
    "CONTAINMENT_DATETIME": {
        "description": "Date and time when containment was achieved",
        "example": "2023-07-15T14:30:00Z",
        "category": VariableCategory.TIMELINE
    },
    "RECOVERY_DATETIME": {
        "description": "Date and time when recovery was completed",
        "example": "2023-07-16T08:00:00Z",
        "category": VariableCategory.TIMELINE
    },
    "EVENT_DATETIME": {
        "description": "Date and time of a specific event",
        "example": "2023-07-15T10:45:00Z",
        "category": VariableCategory.TIMELINE
    },
    "EVENT_TYPE": {
        "description": "Type of timeline event",
        "example": "Detection",
        "category": VariableCategory.TIMELINE
    },
    "EVENT_DETAILS": {
        "description": "Details about the timeline event",
        "example": "Intrusion detection system alert triggered by anomalous outbound traffic",
        "category": VariableCategory.TIMELINE
    },
    "EVENT_SOURCE": {
        "description": "Source of information for the timeline event",
        "example": "Firewall logs",
        "category": VariableCategory.TIMELINE
    },
    "DISCOVERY_DATETIME": {
        "description": "Date and time when incident was discovered",
        "example": "2023-07-15T10:30:00Z",
        "category": VariableCategory.TIMELINE
    },
    "DISCOVERY_METHOD": {
        "description": "How the incident was discovered",
        "example": "Automated alert from SIEM system",
        "category": VariableCategory.TIMELINE
    },
    "DISCOVERED_BY": {
        "description": "Person or system that discovered the incident",
        "example": "Security Analyst (Jane Doe)",
        "category": VariableCategory.TIMELINE
    },
    "INITIAL_ALERT_ID": {
        "description": "ID of the initial alert or ticket",
        "example": "ALERT-4256",
        "category": VariableCategory.TIMELINE
    },
    "TIME_TO_DETECTION": {
        "description": "Time between incident start and detection",
        "example": "45 minutes",
        "category": VariableCategory.TIMELINE
    },
    "ACTION_DATETIME": {
        "description": "Date and time of a response action",
        "example": "2023-07-15T11:15:00Z",
        "category": VariableCategory.RESPONSE
    },
    "RESPONSE_ACTION": {
        "description": "Action taken in response to the incident",
        "example": "Isolated affected workstation from network",
        "category": VariableCategory.RESPONSE
    },
    "RESPONSE_BY": {
        "description": "Person who performed the response action",
        "example": "Network Engineer (Bob Johnson)",
        "category": VariableCategory.RESPONSE
    },
    "ACTION_OUTCOME": {
        "description": "Outcome of the response action",
        "example": "Successfully contained spread to other systems",
        "category": VariableCategory.RESPONSE
    },
    "SYSTEM_NAME": {
        "description": "Name of an affected system",
        "example": "WEBSERVER01",
        "category": VariableCategory.TECHNICAL
    },
    "SYSTEM_FUNCTION": {
        "description": "Function of the affected system",
        "example": "Production web application server",
        "category": VariableCategory.TECHNICAL
    },
    "SYSTEM_IDENTIFIER": {
        "description": "IP or hostname of the affected system",
        "example": "10.0.0.123 / webserver01.example.com",
        "category": VariableCategory.TECHNICAL
    },
    "SYSTEM_IMPACT": {
        "description": "Impact on the affected system",
        "example": "Compromise of service account credentials",
        "category": VariableCategory.IMPACT
    },
    "SYSTEM_STATUS": {
        "description": "Current status of the affected system",
        "example": "Offline for forensic analysis",
        "category": VariableCategory.TECHNICAL
    },
    "ATTACK_VECTOR_DESCRIPTION": {
        "description": "Description of how the attack was executed",
        "example": "Phishing email with malicious macro attachment",
        "category": VariableCategory.TECHNICAL
    },
    "INITIAL_ACCESS_METHOD": {
        "description": "Method used for initial access",
        "example": "Social engineering via targeted phishing email",
        "category": VariableCategory.TECHNICAL
    },
    "ATTACK_PROGRESSION": {
        "description": "How the attack progressed after initial access",
        "example": "Attacker executed malicious macro, established C2 connection, escalated privileges...",
        "category": VariableCategory.TECHNICAL
    },
    "PERSISTENCE_MECHANISMS": {
        "description": "Methods used by attacker to maintain access",
        "example": "Created scheduled task and backdoor service account",
        "category": VariableCategory.TECHNICAL
    },
    "IOC_TYPE": {
        "description": "Type of indicator of compromise",
        "example": "IP Address, File Hash, Domain",
        "category": VariableCategory.TECHNICAL
    },
    "IOC_VALUE": {
        "description": "Value of the indicator of compromise",
        "example": "192.168.1.100, 5f8ad35b212..., malicious-domain.com",
        "category": VariableCategory.TECHNICAL
    },
    "IOC_DESCRIPTION": {
        "description": "Description of the indicator of compromise",
        "example": "Command and control server",
        "category": VariableCategory.TECHNICAL
    },
    "IOC_LOCATION": {
        "description": "Where the IOC was detected",
        "example": "Firewall logs, Memory analysis",
        "category": VariableCategory.TECHNICAL
    },
    "VULNERABILITY_ID": {
        "description": "ID of exploited vulnerability",
        "example": "CVE-2023-12345",
        "category": VariableCategory.TECHNICAL
    },
    "VULNERABILITY_DESCRIPTION": {
        "description": "Description of the exploited vulnerability",
        "example": "Remote code execution in web application",
        "category": VariableCategory.TECHNICAL
    },
    "AFFECTED_COMPONENT": {
        "description": "Component affected by vulnerability",
        "example": "Content Management System v3.4.1",
        "category": VariableCategory.TECHNICAL
    },
    "EXPLOITABILITY": {
        "description": "Ease of exploiting the vulnerability",
        "example": "High - publicly available exploit code",
        "category": VariableCategory.TECHNICAL
    },
    "EVIDENCE_ID": {
        "description": "Unique ID for piece of evidence",
        "example": "EV-2023-042-001",
        "category": VariableCategory.EVIDENCE
    },
    "EVIDENCE_DESCRIPTION": {
        "description": "Description of collected evidence",
        "example": "Memory image of compromised workstation",
        "category": VariableCategory.EVIDENCE
    },
    "COLLECTION_DATE": {
        "description": "Date evidence was collected",
        "example": "2023-07-15",
        "category": VariableCategory.EVIDENCE
    },
    "COLLECTION_METHOD": {
        "description": "Method used to collect evidence",
        "example": "FTK Imager memory acquisition",
        "category": VariableCategory.EVIDENCE
    },
    "EVIDENCE_HASH": {
        "description": "Cryptographic hash of evidence file",
        "example": "5f8ad35b212e44b6979e8562e456c8s84d218afd22ccbc33e65efa9baa8d9a11",
        "category": VariableCategory.EVIDENCE
    },
    "FORENSIC_ANALYSIS_SUMMARY": {
        "description": "Summary of forensic analysis findings",
        "example": "Memory analysis revealed unauthorized PowerShell scripts...",
        "category": VariableCategory.TECHNICAL
    },
    "KEY_FINDING_1": {
        "description": "First key finding from investigation",
        "example": "Attacker used stolen credentials from previous phishing attack",
        "category": VariableCategory.TECHNICAL
    },
    "KEY_FINDING_2": {
        "description": "Second key finding from investigation",
        "example": "Lateral movement detected to 3 additional systems",
        "category": VariableCategory.TECHNICAL
    },
    "KEY_FINDING_3": {
        "description": "Third key finding from investigation",
        "example": "No evidence of data exfiltration was found",
        "category": VariableCategory.TECHNICAL
    },
    "ARTIFACT_NAME": {
        "description": "Name of forensic artifact",
        "example": "PowerShell History",
        "category": VariableCategory.EVIDENCE
    },
    "ARTIFACT_LOCATION": {
        "description": "Location where artifact was found",
        "example": "C:\\Users\\Administrator\\AppData\\...",
        "category": VariableCategory.EVIDENCE
    },
    "ANALYSIS_RESULTS": {
        "description": "Results of artifact analysis",
        "example": "PowerShell commands used to download malware payload",
        "category": VariableCategory.TECHNICAL
    },
    "ARTIFACT_SIGNIFICANCE": {
        "description": "Significance of the artifact to investigation",
        "example": "Demonstrates initial execution method",
        "category": VariableCategory.TECHNICAL
    },
    "ROOT_CAUSE_ANALYSIS": {
        "description": "Analysis of the incident's root cause",
        "example": "Outdated web application with unpatched vulnerability...",
        "category": VariableCategory.TECHNICAL
    },
    "ATTACK_ATTRIBUTION": {
        "description": "Attribution of attack if possible",
        "example": "Tactics consistent with APT group 'MeteorStrike'",
        "category": VariableCategory.TECHNICAL
    },
    "SCOPE_OF_COMPROMISE": {
        "description": "Extent of systems/data compromised",
        "example": "Limited to 3 workstations; no sensitive data access",
        "category": VariableCategory.IMPACT
    },
    "DATA_TYPE": {
        "description": "Type of data potentially exposed",
        "example": "Customer contact information",
        "category": VariableCategory.IMPACT
    },
    "DATA_AMOUNT": {
        "description": "Amount of data potentially exposed",
        "example": "Approximately 500 records",
        "category": VariableCategory.IMPACT
    },
    "DATA_SENSITIVITY": {
        "description": "Sensitivity classification of exposed data",
        "example": "Confidential - Business",
        "category": VariableCategory.IMPACT
    },
    "EXPOSURE_METHOD": {
        "description": "Method of data exposure",
        "example": "Database access via compromised credentials",
        "category": VariableCategory.TECHNICAL
    },
    "CONFIRMED_EXFILTRATION": {
        "description": "Whether data exfiltration is confirmed",
        "example": "No - no evidence of exfiltration found",
        "category": VariableCategory.IMPACT
    },
    "CONTAINMENT_MEASURE": {
        "description": "Measure taken to contain the incident",
        "example": "Network isolation of affected systems",
        "category": VariableCategory.RESPONSE
    },
    "IMPLEMENTATION_DATE": {
        "description": "Date containment measure was implemented",
        "example": "2023-07-15",
        "category": VariableCategory.RESPONSE
    },
    "IMPLEMENTED_BY": {
        "description": "Person who implemented containment measure",
        "example": "Network Security Team",
        "category": VariableCategory.RESPONSE
    },
    "EFFECTIVENESS": {
        "description": "Effectiveness of the containment measure",
        "example": "High - prevented further lateral movement",
        "category": VariableCategory.RESPONSE
    },
    "ERADICATION_STEP": {
        "description": "Step taken to eradicate the threat",
        "example": "Removal of malicious files and registry entries",
        "category": VariableCategory.RESPONSE
    },
    "COMPLETION_DATE": {
        "description": "Date step was completed",
        "example": "2023-07-16",
        "category": VariableCategory.RESPONSE
    },
    "PERFORMED_BY": {
        "description": "Person who performed the step",
        "example": "Incident Response Team",
        "category": VariableCategory.RESPONSE
    },
    "VERIFICATION_METHOD": {
        "description": "Method to verify step was successful",
        "example": "Follow-up scan and manual inspection",
        "category": VariableCategory.RESPONSE
    },
    "RECOVERY_ACTION": {
        "description": "Action taken to recover systems/data",
        "example": "Restore from clean backup",
        "category": VariableCategory.RESPONSE
    },
    "ACTION_DATE": {
        "description": "Date recovery action was performed",
        "example": "2023-07-16",
        "category": VariableCategory.RESPONSE
    },
    "ACTION_BY": {
        "description": "Person who performed recovery action",
        "example": "Infrastructure Team",
        "category": VariableCategory.RESPONSE
    },
    "ACTION_RESULTS": {
        "description": "Results of the recovery action",
        "example": "System successfully restored to operation",
        "category": VariableCategory.RESPONSE
    },
    "APPLICABLE_REGULATION_1": {
        "description": "First regulation applicable to incident",
        "example": "GDPR",
        "category": VariableCategory.COMMUNICATION
    },
    "APPLICABLE_REGULATION_2": {
        "description": "Second regulation applicable to incident",
        "example": "HIPAA",
        "category": VariableCategory.COMMUNICATION
    },
    "STAKEHOLDER": {
        "description": "Stakeholder requiring notification",
        "example": "Data Protection Authority",
        "category": VariableCategory.COMMUNICATION
    },
    "NOTIFICATION_REQUIREMENT": {
        "description": "Notification requirement details",
        "example": "Written notification within 72 hours",
        "category": VariableCategory.COMMUNICATION
    },
    "NOTIFICATION_DEADLINE": {
        "description": "Deadline for notification",
        "example": "2023-07-18 10:45 UTC",
        "category": VariableCategory.COMMUNICATION
    },
    "NOTIFICATION_STATUS": {
        "description": "Current notification status",
        "example": "Completed",
        "category": VariableCategory.COMMUNICATION
    },
    "NOTIFICATION_DATE": {
        "description": "Date notification was completed",
        "example": "2023-07-16",
        "category": VariableCategory.COMMUNICATION
    },
    "LESSONS_LEARNED": {
        "description": "Summary of lessons learned from incident",
        "example": "This incident highlighted several areas for improvement...",
        "category": VariableCategory.RECOMMENDATIONS
    },
    "WORKED_WELL_1": {
        "description": "First aspect that worked well",
        "example": "Rapid detection via enhanced monitoring",
        "category": VariableCategory.RECOMMENDATIONS
    },
    "WORKED_WELL_2": {
        "description": "Second aspect that worked well",
        "example": "Effective cross-team communication",
        "category": VariableCategory.RECOMMENDATIONS
    },
    "WORKED_WELL_3": {
        "description": "Third aspect that worked well",
        "example": "Playbook-driven containment procedures",
        "category": VariableCategory.RECOMMENDATIONS
    },
    "IMPROVEMENT_OPPORTUNITY_1": {
        "description": "First improvement opportunity",
        "example": "Enhance patch management process",
        "category": VariableCategory.RECOMMENDATIONS
    },
    "IMPROVEMENT_OPPORTUNITY_2": {
        "description": "Second improvement opportunity",
        "example": "Implement multi-factor authentication",
        "category": VariableCategory.RECOMMENDATIONS
    },
    "IMPROVEMENT_OPPORTUNITY_3": {
        "description": "Third improvement opportunity",
        "example": "Improve data backup verification",
        "category": VariableCategory.RECOMMENDATIONS
    },
    "DOCUMENT_TYPE": {
        "description": "Type of related document",
        "example": "Evidence Log",
        "category": VariableCategory.METADATA
    },
    "RELATED_DOCUMENT_ID": {
        "description": "ID of related document",
        "example": "EV-2023-042-LOG",
        "category": VariableCategory.METADATA
    },
    "DOCUMENT_NAME": {
        "description": "Name of related document",
        "example": "Network Traffic Analysis Report",
        "category": VariableCategory.METADATA
    },
    "DOCUMENT_LOCATION": {
        "description": "Location of related document",
        "example": "/secure/evidence/IR-2023-042/network_analysis.pdf",
        "category": VariableCategory.METADATA
    },
    "RELEVANCE": {
        "description": "Relevance of related document",
        "example": "Contains packet captures showing data access patterns",
        "category": VariableCategory.METADATA
    },
    "SECURITY_MANAGER": {
        "description": "Security manager name",
        "example": "Alice Williams",
        "category": VariableCategory.APPROVAL
    },
    "LEGAL_COUNSEL": {
        "description": "Legal counsel name",
        "example": "Robert Davis",
        "category": VariableCategory.APPROVAL
    },
    "EXECUTIVE_SPONSOR": {
        "description": "Executive sponsor name",
        "example": "Sarah Johnson",
        "category": VariableCategory.APPROVAL
    },
    "APPROVAL_STATUS": {
        "description": "Status of approval",
        "example": "Approved",
        "category": VariableCategory.APPROVAL
    },
    "APPROVAL_DATE": {
        "description": "Date of approval",
        "example": "2023-07-20",
        "category": VariableCategory.APPROVAL
    },
    "COMMENTS": {
        "description": "Comments on approval",
        "example": "Approved with minor revisions to communication plan",
        "category": VariableCategory.APPROVAL
    },
    "RECIPIENT_NAME": {
        "description": "Name of document recipient",
        "example": "John Smith",
        "category": VariableCategory.COMMUNICATION
    },
    "RECIPIENT_ROLE": {
        "description": "Role of document recipient",
        "example": "Chief Information Officer",
        "category": VariableCategory.COMMUNICATION
    },
    "RECIPIENT_ORG": {
        "description": "Organization of recipient",
        "example": "IT Department",
        "category": VariableCategory.COMMUNICATION
    },
    "DISTRIBUTION_DATE": {
        "description": "Date document was distributed",
        "example": "2023-07-21",
        "category": VariableCategory.COMMUNICATION
    },
}

# Variables specific to incident_timeline.md
TIMELINE_VARIABLES = {
    "DOCUMENT_VERSION": {
        "description": "Version number of the document",
        "example": "1.0",
        "category": VariableCategory.METADATA
    },
    "DETECTION_SOURCE": {
        "description": "Source of incident detection",
        "example": "SIEM Alert",
        "category": VariableCategory.TIMELINE
    },
    "DETECTION_ACTOR": {
        "description": "Entity that detected the incident",
        "example": "SOC Analyst",
        "category": VariableCategory.TIMELINE
    },
    "INITIAL_DETECTION_DESCRIPTION": {
        "description": "Description of how incident was initially detected",
        "example": "Intrusion detection system alerted on suspicious outbound traffic",
        "category": VariableCategory.TIMELINE
    },
    "INITIAL_ENTRY": {
        "description": "First entry in the timeline",
        "example": "2023-07-15T10:45:00Z - Alert triggered for unusual authentication pattern",
        "category": VariableCategory.TIMELINE
    },
    "TIMELINE_VISUALIZATION_LINK": {
        "description": "Link to visual timeline representation",
        "example": "/secure/evidence/IR-2023-042/timeline_visualization.html",
        "category": VariableCategory.TIMELINE
    },
    "INCIDENT_REPORT_LOCATION": {
        "description": "Location of related incident report",
        "example": "/secure/evidence/IR-2023-042/incident_report.pdf",
        "category": VariableCategory.METADATA
    },
    "EVIDENCE_INVENTORY_LOCATION": {
        "description": "Location of evidence inventory",
        "example": "/secure/evidence/IR-2023-042/evidence_inventory.xlsx",
        "category": VariableCategory.EVIDENCE
    },
    "TIMELINE_NOTES": {
        "description": "Additional notes about the timeline",
        "example": "Timeline reconstructed from multiple log sources with timestamps normalized to UTC",
        "category": VariableCategory.TIMELINE
    },
    "SIGNIFICANT_EVENT_1": {
        "description": "First significant event in timeline",
        "example": "Initial access via phishing email at 09:15 UTC",
        "category": VariableCategory.TIMELINE
    },
    "SIGNIFICANT_EVENT_2": {
        "description": "Second significant event in timeline",
        "example": "Lateral movement detected at 10:45 UTC",
        "category": VariableCategory.TIMELINE
    },
    "SIGNIFICANT_EVENT_3": {
        "description": "Third significant event in timeline",
        "example": "Data staging observed at 11:30 UTC",
        "category": VariableCategory.TIMELINE
    },
    "ATTACK_NARRATIVE": {
        "description": "Narrative description of attack based on timeline",
        "example": "The attack began with a targeted phishing email...",
        "category": VariableCategory.TECHNICAL
    },
    "RESPONSE_EFFECTIVENESS": {
        "description": "Analysis of response effectiveness",
        "example": "The incident response team effectively contained the threat within 45 minutes...",
        "category": VariableCategory.RESPONSE
    },
    "GAP_START": {
        "description": "Start time of a timeline gap",
        "example": "2023-07-15T12:00:00Z",
        "category": VariableCategory.TIMELINE
    },
    "GAP_END": {
        "description": "End time of a timeline gap",
        "example": "2023-07-15T13:15:00Z",
        "category": VariableCategory.TIMELINE
    },
    "GAP_DESCRIPTION": {
        "description": "Description of timeline gap",
        "example": "Missing log data during system reboot",
        "category": VariableCategory.TIMELINE
    },
    "GAP_EXPLANATION": {
        "description": "Explanation for timeline gap",
        "example": "Logging service was offline during recovery process",
        "category": VariableCategory.TIMELINE
    },
    "GAP_STATUS": {
        "description": "Status of gap investigation",
        "example": "Under investigation",
        "category": VariableCategory.TIMELINE
    },
}

# Variables specific to chain_of_custody.md
CHAIN_OF_CUSTODY_VARIABLES = {
    "EVIDENCE_ID": {
        "description": "Unique identifier for the evidence",
        "example": "EV-2023-042-001",
        "category": VariableCategory.EVIDENCE
    },
    "COLLECTION_DATETIME": {
        "description": "Date and time of evidence collection",
        "example": "2023-07-15T14:30:00Z",
        "category": VariableCategory.EVIDENCE
    },
    "COLLECTION_LOCATION": {
        "description": "Location where evidence was collected",
        "example": "Data Center, Rack B14, Server WEB01",
        "category": VariableCategory.EVIDENCE
    },
    "COLLECTOR_NAME": {
        "description": "Name of person who collected evidence",
        "example": "John Doe",
        "category": VariableCategory.EVIDENCE
    },
    "COLLECTION_TOOLS": {
        "description": "Tools used for evidence collection",
        "example": "FTK Imager 4.2.1, Write Blocker XYZ-123",
        "category": VariableCategory.EVIDENCE
    },
    "HASH_SHA256": {
        "description": "SHA-256 hash of evidence",
        "example": "5f8ad35b212e44b6979e8562e456c8a84d218afd22ccbc33e65efa9baa8d9a11",
        "category": VariableCategory.EVIDENCE
    },
    "HASH_MD5": {
        "description": "MD5 hash of evidence (optional)",
        "example": "d41d8cd98f00b204e9800998ecf8427e",
        "category": VariableCategory.EVIDENCE
    },
    "ORIGINAL_SOURCE": {
        "description": "Original source of evidence",
        "example": "Production Web Server Hard Drive",
        "category": VariableCategory.EVIDENCE
    },
    "STORAGE_LOCATION": {
        "description": "Location where evidence is stored",
        "example": "Digital Evidence Locker, Shelf 3, Box 42",
        "category": VariableCategory.EVIDENCE
    },
    "ACQUISITION_DATETIME": {
        "description": "Date and time of initial evidence acquisition",
        "example": "2023-07-15T14:30:00Z",
        "category": VariableCategory.EVIDENCE
    },
    "ACQUISITION_NOTES": {
        "description": "Notes about the evidence acquisition",
        "example": "System powered on during acquisition, RAM capture performed first",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_DATETIME": {
        "description": "Date and time of custody transfer",
        "example": "2023-07-16T09:00:00Z",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_ACTION": {
        "description": "Type of custody action",
        "example": "Transfer",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_FROM": {
        "description": "Person/location transferring from",
        "example": "John Doe (Incident Responder)",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_TO": {
        "description": "Person/location transferring to",
        "example": "Jane Smith (Forensic Analyst)",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_HANDLER": {
        "description": "Person handling the transfer",
        "example": "John Doe",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_PURPOSE": {
        "description": "Purpose of transfer or access",
        "example": "Forensic Analysis",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_VERIFICATION": {
        "description": "Method used to verify evidence integrity",
        "example": "SHA-256 hash verification",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_HASH": {
        "description": "Hash value during transfer",
        "example": "5f8ad35b212e44b6979e8562e456c8a84d218afd22ccbc33e65efa9baa8d9a11",
        "category": VariableCategory.EVIDENCE
    },
    "CUSTODY_NOTES": {
        "description": "Notes about the custody transfer",
        "example": "Evidence bagged and sealed with tamper-evident tape",
        "category": VariableCategory.EVIDENCE
    },
    "STORAGE_REQUIREMENT_1": {
        "description": "First storage requirement",
        "example": "Keep in climate-controlled environment (60-75°F)",
        "category": VariableCategory.EVIDENCE
    },
    "STORAGE_REQUIREMENT_2": {
        "description": "Second storage requirement",
        "example": "Protect from electromagnetic fields",
        "category": VariableCategory.EVIDENCE
    },
    "STORAGE_REQUIREMENT_3": {
        "description": "Third storage requirement",
        "example": "Store in anti-static packaging",
        "category": VariableCategory.EVIDENCE
    },
    "ACCESS_RESTRICTION_1": {
        "description": "First access restriction",
        "example": "Access limited to authorized forensic examiners",
        "category": VariableCategory.EVIDENCE
    },
    "ACCESS_RESTRICTION_2": {
        "description": "Second access restriction",
        "example": "Two-person integrity required for physical access",
        "category": VariableCategory.EVIDENCE
    },
    "ACCESS_RESTRICTION_3": {
        "description": "Third access restriction",
        "example": "All access must be logged in access control system",
        "category": VariableCategory.EVIDENCE
    },
    "VERIFICATION_TOOL_1": {
        "description": "First approved verification tool",
        "example": "OpenSSL 1.1.1k or later",
        "category": VariableCategory.EVIDENCE
    },
    "VERIFICATION_TOOL_2": {
        "description": "Second approved verification tool",
        "example": "HashMyFiles v2.36",
        "category": VariableCategory.EVIDENCE
    },
    "VERIFICATION_TOOL_3": {
        "description": "Third approved verification tool",
        "example": "FTK Imager 4.5",
        "category": VariableCategory.EVIDENCE
    },
    "RETENTION_PERIOD": {
        "description": "Evidence retention period",
        "example": "7 years",
        "category": VariableCategory.EVIDENCE
    },
    "RETENTION_REQUIREMENT": {
        "description": "Source of retention requirement",
        "example": "Legal Hold / Corporate Data Retention Policy",
        "category": VariableCategory.EVIDENCE
    },
    "DISPOSITION_DATE": {
        "description": "Date of evidence disposition",
        "example": "2030-07-15",
        "category": VariableCategory.EVIDENCE
    },
    "DISPOSITION_METHOD": {
        "description": "Method of evidence disposition",
        "example": "Secure Destruction - DoD 5220.22-M compliant wiping",
        "category": VariableCategory.EVIDENCE
    },
    "DISPOSITION_AUTHORITY": {
        "description": "Authority approving disposition",
        "example": "Legal Department / Head of Security",
        "category": VariableCategory.EVIDENCE
    },
    "VERIFICATION_DATETIME": {
        "description": "Date and time of evidence verification",
        "example": "2023-07-20T10:15:00Z",
        "category": VariableCategory.EVIDENCE
    },
    "VERIFIER_NAME": {
        "description": "Person who verified evidence integrity",
        "example": "Jane Smith",
        "category": VariableCategory.EVIDENCE
    },
    "VERIFICATION_RESULT": {
        "description": "Result of integrity verification",
        "example": "Passed - hash matches original",
        "category": VariableCategory.EVIDENCE
    },
    "VERIFICATION_NOTES": {
        "description": "Notes about the verification process",
        "example": "Verified using both SHA-256 and MD5 hashes",
        "category": VariableCategory.EVIDENCE
    },
    "RELATED_EVIDENCE_ID": {
        "description": "ID of related evidence item",
        "example": "EV-2023-042-002",
        "category": VariableCategory.EVIDENCE
    },
    "RELATIONSHIP_TYPE": {
        "description": "Type of relationship to other evidence",
        "example": "Extracted From / Parent-Child",
        "category": VariableCategory.EVIDENCE
    },
    "RELATIONSHIP_DESCRIPTION": {
        "description": "Description of evidence relationship",
        "example": "File extracted from disk image",
        "category": VariableCategory.EVIDENCE
    },
    "PREPARER_NAME": {
        "description": "Name of document preparer",
        "example": "John Doe",
        "category": VariableCategory.METADATA
    },
    "PREPARER_TITLE": {
        "description": "Title of document preparer",
        "example": "Incident Response Team Lead",
        "category": VariableCategory.METADATA
    },
    "PREPARATION_DATE": {
        "description": "Date document was prepared",
        "example": "2023-07-15",
        "category": VariableCategory.METADATA
    },
    "UPDATER_NAME": {
        "description": "Name of person who updated document",
        "example": "Jane Smith",
        "category": VariableCategory.METADATA
    },
    "CREATION_DATE": {
        "description": "Date document was created",
        "example": "2023-07-15",
        "category": VariableCategory.METADATA
    },
    "CREATOR_NAME": {
        "description": "Name of document creator",
        "example": "John Doe",
        "category": VariableCategory.METADATA
    },
}

# Variables specific to communication_plan.md
COMMUNICATION_VARIABLES = {
    "COMMUNICATION_OBJECTIVES": {
        "description": "Objectives for communication during the incident",
        "example": "Provide timely, accurate information to stakeholders while maintaining operational security...",
        "category": VariableCategory.COMMUNICATION
    },
    "STAKEHOLDER_NAME": {
        "description": "Name of stakeholder",
        "example": "IT Operations Team",
        "category": VariableCategory.COMMUNICATION
    },
    "STAKEHOLDER_ROLE": {
        "description": "Role or department of stakeholder",
        "example": "Infrastructure Management",
        "category": VariableCategory.COMMUNICATION
    },
    "COMMUNICATION_NEED": {
        "description": "Communication needs of stakeholder",
        "example": "Technical details of affected systems and workarounds",
        "category": VariableCategory.COMMUNICATION
    },
    "PRIORITY": {
        "description": "Priority level for stakeholder communication",
        "example": "High",
        "category": VariableCategory.COMMUNICATION
    },
    "POINT_OF_CONTACT": {
        "description": "Contact person for stakeholder group",
        "example": "John Smith, IT Director",
        "category": VariableCategory.COMMUNICATION
    },
    "RELATIONSHIP": {
        "description": "Relationship of external stakeholder",
        "example": "Cloud Service Provider",
        "category": VariableCategory.COMMUNICATION
    },
    "REGULATORY_BODY": {
        "description": "Name of regulatory body",
        "example": "Data Protection Authority",
        "category": VariableCategory.COMMUNICATION
    },
    "REQUIREMENT": {
        "description": "Regulatory notification requirement",
        "example": "Incident notification within 72 hours",
        "category": VariableCategory.COMMUNICATION
    },
    "DEADLINE": {
        "description": "Deadline for regulatory notification",
        "example": "2023-07-18 10:45 UTC",
        "category": VariableCategory.COMMUNICATION
    },
    "CHANNEL_NAME": {
        "description": "Name of communication channel",
        "example": "Email",
        "category": VariableCategory.COMMUNICATION
    },
    "USE_CASE": {
        "description": "Use case for communication channel",
        "example": "Status updates to internal teams",
        "category": VariableCategory.COMMUNICATION
    },
    "SECURITY_LEVEL": {
        "description": "Security level of communication channel",
        "example": "Encrypted / Confidential",
        "category": VariableCategory.COMMUNICATION
    },
    "RESPONSIBLE_PARTY": {
        "description": "Person responsible for communication channel",
        "example": "Communications Lead",
        "category": VariableCategory.COMMUNICATION
    },
    "AUTHORIZATION_PROCESS": {
        "description": "Process for authorizing communications",
        "example": "All external communications must be approved by the Legal team and Incident Commander",
        "category": VariableCategory.COMMUNICATION
    },
    "CLASSIFICATION_HANDLING": {
        "description": "Handling procedures for classified information",
        "example": "Confidential information must be encrypted and shared only via approved channels",
        "category": VariableCategory.COMMUNICATION
    },
    "INFORMATION_DISCLOSURE_GUIDELINES": {
        "description": "Guidelines for disclosing information",
        "example": "Only confirmed facts should be shared; speculation should be avoided",
        "category": VariableCategory.COMMUNICATION
    },
    "SECURE_TRANSMISSION_REQUIREMENTS": {
        "description": "Requirements for secure transmission",
        "example": "All documents must be password-protected and transmitted via encrypted channels",
        "category": VariableCategory.COMMUNICATION
    },
    "RECORD_KEEPING_REQUIREMENTS": {
        "description": "Requirements for communication records",
        "example": "All communications must be logged in the incident management system",
        "category": VariableCategory.COMMUNICATION
    },
    "INITIAL_NOTIFICATION_RECIPIENTS": {
        "description": "Recipients of initial notification",
        "example": "incident-response@example.com; security-team@example.com",
        "category": VariableCategory.COMMUNICATION
    },
    "INITIAL_FINDINGS": {
        "description": "Initial findings about the incident",
        "example": "Unauthorized access detected to the customer database",
        "category": VariableCategory.COMMUNICATION
    },
    "CURRENT_ACTIONS": {
        "description": "Current response actions being taken",
        "example": "Systems isolated, investigation in progress",
        "category": VariableCategory.COMMUNICATION
    },
    "NEXT_STEPS": {
        "description": "Next steps in incident response",
        "example": "Forensic analysis and containment verification",
        "category": VariableCategory.COMMUNICATION
    },
    "POC_NAME": {
        "description": "Name of point of contact",
        "example": "Jane Smith",
        "category": VariableCategory.COMMUNICATION
    },
    "POC_CONTACT": {
        "description": "Contact information for point of contact",
        "example": "jane.smith@example.com, +1-555-123-4567",
        "category": VariableCategory.COMMUNICATION
    },
    "EXECUTIVE_RECIPIENTS": {
        "description": "Recipients for executive updates",
        "example": "ceo@example.com; cio@example.com; ciso@example.com",
        "category": VariableCategory.COMMUNICATION
    },
    "BUSINESS_IMPACT": {
        "description": "Business impact of the incident",
        "example": "Order processing delayed by approximately 2 hours",
        "category": VariableCategory.COMMUNICATION
    },
    "CURRENT_SITUATION_SUMMARY": {
        "description": "Summary of current situation",
        "example": "The incident has been contained and affected systems are being restored",
        "category": VariableCategory.COMMUNICATION
    },
    "RESPONSE_ACTIONS_SUMMARY": {
        "description": "Summary of response actions taken",
        "example": "Malware quarantined, compromised accounts locked, systems isolated",
        "category": VariableCategory.COMMUNICATION
    },
    "RESOURCE_REQUIREMENTS": {
        "description": "Resources required for response",
        "example": "Additional forensic analysts needed for next 48 hours",
        "category": VariableCategory.COMMUNICATION
    },
    "EXECUTIVE_RECOMMENDATIONS": {
        "description": "Recommendations for executive action",
        "example": "Approve emergency firewall rule changes and overtime for response team",
        "category": VariableCategory.COMMUNICATION
    },
    "NEXT_UPDATE_TIME": {
        "description": "Time of next scheduled update",
        "example": "July 16, 2023 at 14:00 UTC",
        "category": VariableCategory.COMMUNICATION
    },
    "CUSTOMER_NOTIFICATION_SUBJECT": {
        "description": "Subject line for customer notification",
        "example": "Important Security Update",
        "category": VariableCategory.COMMUNICATION
    },
    "CUSTOMER_RECIPIENTS": {
        "description": "Recipients for customer notification",
        "example": "All affected customers",
        "category": VariableCategory.COMMUNICATION
    },
    "CUSTOMER_TYPE": {
        "description": "Type of customer being notified",
        "example": "Customer",
        "category": VariableCategory.COMMUNICATION
    },
    "AFFECTED_SERVICE_OR_DATA": {
        "description": "Service or data affected by incident",
        "example": "Cloud Storage Service",
        "category": VariableCategory.COMMUNICATION
    },
    "CUSTOMER_INCIDENT_DESCRIPTION": {
        "description": "Customer-facing incident description",
        "example": "On July 15, 2023, we detected unauthorized access to our user database",
        "category": VariableCategory.COMMUNICATION
    },
    "AFFECTED_INFORMATION": {
        "description": "Information affected by incident",
        "example": "Contact information including email addresses and phone numbers",
        "category": VariableCategory.COMMUNICATION
    },
    "COMPANY_ACTIONS": {
        "description": "Actions company is taking",
        "example": "We have secured our systems, reset all passwords, and engaged forensic experts",
        "category": VariableCategory.COMMUNICATION
    },
    "CUSTOMER_ACTIONS": {
        "description": "Recommended customer actions",
        "example": "Reset your password and enable two-factor authentication",
        "category": VariableCategory.COMMUNICATION
    },
    "ADDITIONAL_INFORMATION_SOURCES": {
        "description": "Sources for additional information",
        "example": "Visit our security update page at https://example.com/security",
        "category": VariableCategory.COMMUNICATION
    },
    "COMPANY_REPRESENTATIVE": {
        "description": "Name of company representative",
        "example": "Alex Johnson, Chief Security Officer",
        "category": VariableCategory.COMMUNICATION
    },
    "COMPANY_NAME": {
        "description": "Name of company",
        "example": "Example Corporation",
        "category": VariableCategory.COMMUNICATION
    },
    "REGULATORY_RECIPIENTS": {
        "description": "Recipients for regulatory notification",
        "example": "incidents@dataprotection.gov",
        "category": VariableCategory.COMMUNICATION
    },
    "REGULATION_REFERENCE": {
        "description": "Reference to applicable regulation",
        "example": "GDPR Article 33",
        "category": VariableCategory.COMMUNICATION
    },
    "ENTITY_NAME": {
        "description": "Legal name of reporting entity",
        "example": "Example Corporation Ltd.",
        "category": VariableCategory.COMMUNICATION
    },
    "ENTITY_ADDRESS": {
        "description": "Address of reporting entity",
        "example": "123 Main Street, Anytown, ST 12345",
        "category": VariableCategory.COMMUNICATION
    },
    "ENTITY_REGISTRATION_NUMBERS": {
        "description": "Registration numbers for entity",
        "example": "Company Registration: 12345678, Data Controller ID: DPC-987654",
        "category": VariableCategory.COMMUNICATION
    },
    "DISCOVERY_DATE": {
        "description": "Date incident was discovered",
        "example": "2023-07-15",
        "category": VariableCategory.TIMELINE
    },
    "INCIDENT_DATES": {
        "description": "Dates when incident occurred",
        "example": "2023-07-14 to 2023-07-15",
        "category": VariableCategory.TIMELINE
    },
    "REGULATORY_INCIDENT_DESCRIPTION": {
        "description": "Incident description for regulators",
        "example": "Unauthorized access to customer database via compromised credentials",
        "category": VariableCategory.COMMUNICATION
    },
    "AFFECTED_DATA_SYSTEMS": {
        "description": "Data and systems affected by incident",
        "example": "Customer database containing contact information for approximately 10,000 individuals",
        "category": VariableCategory.COMMUNICATION
    },
    "AFFECTED_COUNT": {
        "description": "Number of affected records or individuals",
        "example": "Approximately 10,000 individuals",
        "category": VariableCategory.COMMUNICATION
    },
    "NOTIFICATION_PLANS": {
        "description": "Plans for notifying affected individuals",
        "example": "Email notifications will be sent to all affected individuals within 7 days",
        "category": VariableCategory.COMMUNICATION
    },
    "REGULATORY_POC_NAME": {
        "description": "Name of regulatory point of contact",
        "example": "Jane Smith",
        "category": VariableCategory.COMMUNICATION
    },
    "REGULATORY_POC_TITLE": {
        "description": "Title of regulatory point of contact",
        "example": "Data Protection Officer",
        "category": VariableCategory.COMMUNICATION
    },
    "REGULATORY_POC_PHONE": {
        "description": "Phone number for regulatory point of contact",
        "example": "+1-555-123-4567",
        "category": VariableCategory.COMMUNICATION
    },
    "REGULATORY_POC_EMAIL": {
        "description": "Email for regulatory point of contact",
        "example": "dpo@example.com",
        "category": VariableCategory.COMMUNICATION
    },
    "REGULATION_NAME": {
        "description": "Name of applicable regulation",
        "example": "General Data Protection Regulation (GDPR)",
        "category": VariableCategory.COMMUNICATION
    },
    "MEDIA_HEADLINE": {
        "description": "Headline for media statement",
        "example": "Example Corporation Addresses Security Incident",
        "category": VariableCategory.COMMUNICATION
    },
    "ORGANIZATION_NAME": {
        "description": "Name of organization",
        "example": "Example Corporation",
        "category": VariableCategory.COMMUNICATION
    },
    "INCIDENT_TYPE_GENERAL": {
        "description": "General description of incident type",
        "example": "cybersecurity incident",
        "category": VariableCategory.COMMUNICATION
    },
    "DISCOVERY_DATE_PUBLIC": {
        "description": "Public-facing discovery date",
        "example": "July 15, 2023",
        "category": VariableCategory.COMMUNICATION
    },
    "MEDIA_INCIDENT_DESCRIPTION": {
        "description": "Media-ready incident description",
        "example": "Example Corporation detected unauthorized access to a system containing customer information.",
        "category": VariableCategory.COMMUNICATION
    },
    "EXECUTIVE_QUOTE": {
        "description": "Quote from executive",
        "example": "We take the security and privacy of our customers very seriously and are taking immediate steps to address this issue",
        "category": VariableCategory.COMMUNICATION
    },
    "EXECUTIVE_NAME": {
        "description": "Name of quoted executive",
        "example": "Jane Smith",
        "category": VariableCategory.COMMUNICATION
    },
    "EXECUTIVE_TITLE": {
        "description": "Title of quoted executive",
        "example": "Chief Information Security Officer",
        "category": VariableCategory.COMMUNICATION
    },
    "AFFECTED_PARTIES_STATEMENT": {
        "description": "Statement about affected parties",
        "example": "Example Corporation is in the process of notifying individuals whose information may have been affected.",
        "category": VariableCategory.COMMUNICATION
    },
    "CUSTOMER_GUIDANCE_BRIEF": {
        "description": "Brief guidance for customers",
        "example": "Customers are encouraged to reset their passwords and monitor their accounts for suspicious activity.",
        "category": VariableCategory.COMMUNICATION
    },
    "COOPERATING_ENTITIES": {
        "description": "Entities cooperating in investigation",
        "example": "law enforcement agencies and outside security experts",
        "category": VariableCategory.COMMUNICATION
    },
    "MEDIA_CONTACT_NAME": {
        "description": "Name of media contact",
        "example": "Sarah Johnson",
        "category": VariableCategory.COMMUNICATION
    },
    "MEDIA_CONTACT_TITLE": {
        "description": "Title of media contact",
        "example": "Director of Communications",
        "category": VariableCategory.COMMUNICATION
    },
    "MEDIA_CONTACT_EMAIL": {
        "description": "Email of media contact",
        "example": "press@example.com",
        "category": VariableCategory.COMMUNICATION
    },
    "MEDIA_CONTACT_PHONE": {
        "description": "Phone number of media contact",
        "example": "+1-555-987-6543",
        "category": VariableCategory.COMMUNICATION
    },
    "ORGANIZATION_BOILERPLATE": {
        "description": "Standard organization description",
        "example": "Example Corporation is a leading provider of cloud infrastructure services...",
        "category": VariableCategory.COMMUNICATION
    },
    "STATUS_UPDATE_RECIPIENTS": {
        "description": "Recipients for status updates",
        "example": "incident-response@example.com; executive-team@example.com",
        "category": VariableCategory.COMMUNICATION
    },
    "UPDATE_NUMBER": {
        "description": "Status update number",
        "example": "3",
        "category": VariableCategory.COMMUNICATION
    },
    "UPDATE_DATETIME": {
        "description": "Date and time of status update",
        "example": "2023-07-16 09:00 UTC",
        "category": VariableCategory.COMMUNICATION
    },
    "KEY_DEVELOPMENTS": {
        "description": "Key developments since last update",
        "example": "Malware analysis complete; identified as XYZ ransomware variant",
        "category": VariableCategory.COMMUNICATION
    },
    "CURRENT_ACTIVITIES": {
        "description": "Current response activities",
        "example": "System restoration in progress; affected databases being verified",
        "category": VariableCategory.COMMUNICATION
    },
    "PLANNED_STEPS": {
        "description": "Planned next steps",
        "example": "Deploy enhanced monitoring; conduct security awareness training",
        "category": VariableCategory.COMMUNICATION
    },
    "UPDATED_TIMELINE": {
        "description": "Updated incident timeline",
        "example": "Initial detection: 07:30, Containment: 09:45, Recovery started: 14:00",
        "category": VariableCategory.COMMUNICATION
    },
    "BLOCKERS": {
        "description": "Challenges or blockers to response",
        "example": "Waiting on third-party vendor for critical patch",
        "category": VariableCategory.COMMUNICATION
    },
    "RESOURCE_NEEDS": {
        "description": "Resource needs for incident response",
        "example": "Additional storage capacity needed for system backups",
        "category": VariableCategory.COMMUNICATION
    },
    "NEXT_UPDATE_EXPECTED": {
        "description": "When next update is expected",
        "example": "July 16, 2023 at 17:00 UTC",
        "category": VariableCategory.COMMUNICATION
    },
    "STAKEHOLDER_GROUP": {
        "description": "Group of stakeholders",
        "example": "Executive Leadership",
        "category": VariableCategory.COMMUNICATION
    },
    "COMMUNICATION_TYPE": {
        "description": "Type of communication",
        "example": "Status Update",
        "category": VariableCategory.COMMUNICATION
    },
    "FREQUENCY": {
        "description": "Frequency of communication",
        "example": "Every 4 hours",
        "category": VariableCategory.COMMUNICATION
    },
    "TIMING": {
        "description": "Timing of communication",
        "example": "Within 30 minutes of significant developments",
        "category": VariableCategory.COMMUNICATION
    },
    "CHANNEL": {
        "description": "Communication channel",
        "example": "Encrypted Email",
        "category": VariableCategory.COMMUNICATION
    },
    "COMMUNICATION_PRINCIPLE_1": {
        "description": "First communication principle",
        "example": "Be accurate and factual in all communications",
        "category": VariableCategory.COMMUNICATION
    },
    "COMMUNICATION_PRINCIPLE_2": {
        "description": "Second communication principle",
        "example": "Clearly distinguish between facts and assumptions",
        "category": VariableCategory.COMMUNICATION
    },
    "COMMUNICATION_PRINCIPLE_3": {
        "description": "Third communication principle",
        "example": "Communicate promptly while maintaining accuracy",
        "category": VariableCategory.COMMUNICATION
    },
    "COMMUNICATION_PRINCIPLE_4": {
        "description": "Fourth communication principle",
        "example": "Consider legal implications before sharing information",
        "category": VariableCategory.COMMUNICATION
    },
    "COMMUNICATION_PRINCIPLE_5": {
        "description": "Fifth communication principle",
        "example": "Tailor message to the audience's technical understanding",
        "category": VariableCategory.COMMUNICATION
    },
    "APPROVED_TERM": {
        "description": "Approved terminology for communications",
        "example": "Unauthorized Access",
        "category": VariableCategory.COMMUNICATION
    },
    "APPROVED_DESCRIPTION": {
        "description": "Approved description of term",
        "example": "Access to systems or data by an individual who does not have permission to do so",
        "category": VariableCategory.COMMUNICATION
    },
    "TERMS_TO_AVOID": {
        "description": "Terms to avoid in communications",
        "example": "Hack, Break-in, Attack (unless confirmed)",
        "category": VariableCategory.COMMUNICATION
    },
    "INITIAL_TALKING_POINT_1": {
        "description": "First initial phase talking point",
        "example": "We have identified a security incident and activated our incident response plan",
        "category": VariableCategory.COMMUNICATION
    },
    "INITIAL_TALKING_POINT_2": {
        "description": "Second initial phase talking point",
        "example": "Our security team is investigating to determine the scope and impact",
        "category": VariableCategory.COMMUNICATION
    },
    "INITIAL_TALKING_POINT_3": {
        "description": "Third initial phase talking point",
        "example": "We have implemented initial security measures to contain the incident",
        "category": VariableCategory.COMMUNICATION
    },
    "CONTAINMENT_TALKING_POINT_1": {
        "description": "First containment phase talking point",
        "example": "We have contained the incident and prevented further unauthorized access",
        "category": VariableCategory.COMMUNICATION
    },
    "CONTAINMENT_TALKING_POINT_2": {
        "description": "Second containment phase talking point",
        "example": "Our investigation is ongoing to understand the full scope of impact",
        "category": VariableCategory.COMMUNICATION
    },
    "CONTAINMENT_TALKING_POINT_3": {
        "description": "Third containment phase talking point",
        "example": "We are working to restore normal operations while maintaining security",
        "category": VariableCategory.COMMUNICATION
    },
    "RECOVERY_TALKING_POINT_1": {
        "description": "First recovery phase talking point",
        "example": "We have restored systems using secure backups and implemented additional safeguards",
        "category": VariableCategory.COMMUNICATION
    },
    "RECOVERY_TALKING_POINT_2": {
        "description": "Second recovery phase talking point",
        "example": "We have completed our investigation and understand the full scope of the incident",
        "category": VariableCategory.COMMUNICATION
    },
    "RECOVERY_TALKING_POINT_3": {
        "description": "Third recovery phase talking point",
        "example": "We are implementing additional security measures to prevent similar incidents",
        "category": VariableCategory.COMMUNICATION
    },
    "ANTICIPATED_QUESTION": {
        "description": "Anticipated question from stakeholders",
        "example": "Was any customer data compromised in this incident?",
        "category": VariableCategory.COMMUNICATION
    },
    "APPROVED_RESPONSE": {
        "description": "Approved response to question",
        "example": "Based on our investigation, we have no evidence that customer data was accessed or exfiltrated.",
        "category": VariableCategory.COMMUNICATION
    },
    "ESCALATION_TRIGGER": {
        "description": "Trigger for communication escalation",
        "example": "Detection of data exfiltration",
        "category": VariableCategory.COMMUNICATION
    },
    "ESCALATION_LEVEL": {
        "description": "Level of communication escalation",
        "example": "Level 2 - Executive and Legal",
        "category": VariableCategory.COMMUNICATION
    },
    "NOTIFICATION_STAKEHOLDERS": {
        "description": "Stakeholders to notify for escalation",
        "example": "CEO, CISO, General Counsel, PR Director",
        "category": VariableCategory.COMMUNICATION
    },
    "TIMEFRAME": {
        "description": "Timeframe for escalation",
        "example": "Within 30 minutes",
        "category": VariableCategory.COMMUNICATION
    },
    "UNPLANNED_SCENARIO": {
        "description": "Unexpected communication scenario",
        "example": "Media contacts employee directly for comment",
        "category": VariableCategory.COMMUNICATION
    },
    "RESPONSE_PROTOCOL": {
        "description": "Protocol for responding to unplanned scenario",
        "example": "Redirect all inquiries to Communications Lead; do not provide comments",
        "category": VariableCategory.COMMUNICATION
    },
    "AUTHORIZED_RESPONDERS": {
        "description": "Personnel authorized to respond to scenario",
        "example": "Communications Director, CISO, Legal Counsel",
        "category": VariableCategory.COMMUNICATION
    },
    "COMMUNICATIONS_LEAD": {
        "description": "Person leading communications efforts",
        "example": "Michael Johnson",
        "category": VariableCategory.COMMUNICATION
    },
    "FINAL_NOTIFICATION_CONTENT": {
        "description": "Content for final incident notification",
        "example": "The security incident reported on July 15 has been fully resolved...",
        "category": VariableCategory.COMMUNICATION
    },
    "LESSONS_LEARNED_COMMUNICATIONS": {
        "description": "Communication lessons learned from incident",
        "example": "Earlier involvement of legal team in drafting customer notifications",
        "category": VariableCategory.RECOMMENDATIONS
    },
    "COMMUNICATION_EFFECTIVENESS": {
        "description": "Assessment of communication effectiveness",
        "example": "Internal stakeholders were well-informed; external communications were timely",
        "category": VariableCategory.COMMUNICATION
    },
    "POST_INCIDENT_OUTREACH": {
        "description": "Follow-up communications after incident resolution",
        "example": "Customer webinar on enhanced security measures",
        "category": VariableCategory.COMMUNICATION
    }
}

# Variables for remediation_plan.md specific content
REMEDIATION_VARIABLES = {
    "PRIMARY_GOAL": {
        "description": "Primary remediation goal",
        "example": "Restore business operations within 24 hours",
        "category": VariableCategory.REMEDIATION
    },
    "SECONDARY_GOAL": {
        "description": "Secondary remediation goal",
        "example": "Implement enhanced security controls to prevent similar incidents",
        "category": VariableCategory.REMEDIATION
    },
    "TERTIARY_GOAL": {
        "description": "Tertiary remediation goal",
        "example": "Document lessons learned for future incident response improvement",
        "category": VariableCategory.REMEDIATION
    },
    "ACTION_NAME": {
        "description": "Name of remediation action",
        "example": "Reset all user credentials",
        "category": VariableCategory.REMEDIATION
    },
    "ACTION_DESCRIPTION": {
        "description": "Description of remediation action",
        "example": "Force password reset for all users and require MFA enrollment",
        "category": VariableCategory.REMEDIATION
    },
    "ASSIGNEE": {
        "description": "Person assigned to remediation action",
        "example": "Identity and Access Management Team",
        "category": VariableCategory.REMEDIATION
    },
    "DUE_DATE": {
        "description": "Due date for remediation action",
        "example": "2023-07-18",
        "category": VariableCategory.REMEDIATION
    },
    "SYSTEM_NAME": {
        "description": "Name of system requiring restoration",
        "example": "Customer Database",
        "category": VariableCategory.REMEDIATION
    },
    "PREREQUISITE_1": {
        "description": "First prerequisite for restoration",
        "example": "Verified clean backup available from July 14",
        "category": VariableCategory.REMEDIATION
    },
    "PREREQUISITE_2": {
        "description": "Second prerequisite for restoration",
        "example": "Network segmentation implemented",
        "category": VariableCategory.REMEDIATION
    },
    "RESTORATION_STEP_1": {
        "description": "First system restoration step",
        "example": "Restore database from last known good backup",
        "category": VariableCategory.REMEDIATION
    },
    "RESTORATION_STEP_2": {
        "description": "Second system restoration step",
        "example": "Apply all security patches to current version",
        "category": VariableCategory.REMEDIATION
    },
    "RESTORATION_STEP_3": {
        "description": "Third system restoration step",
        "example": "Perform security scan before returning to production",
        "category": VariableCategory.REMEDIATION
    },
    "VERIFICATION_METHOD": {
        "description": "Method to verify successful restoration",
        "example": "Execute test suite and verify data integrity",
        "category": VariableCategory.REMEDIATION
    },
    "ROLLBACK_PROCEDURE": {
        "description": "Procedure if restoration fails",
        "example": "Return to isolated system state and attempt alternative recovery method",
        "category": VariableCategory.REMEDIATION
    },
    "HARDENING_NAME": {
        "description": "Name of security hardening measure",
        "example": "Enhanced network segmentation",
        "category": VariableCategory.REMEDIATION
    },
    "HARDENING_DETAILS": {
        "description": "Implementation details for hardening measure",
        "example": "Implement zero-trust network architecture with microsegmentation",
        "category": VariableCategory.REMEDIATION
    },
    "TARGET_SYSTEMS": {
        "description": "Systems targeted for implementation",
        "example": "All production database servers",
        "category": VariableCategory.REMEDIATION
    },
    "REFERENCE_PROFILE": {
        "description": "Reference security profile or benchmark",
        "example": "CIS Benchmark Level 2",
        "category": VariableCategory.REMEDIATION
    },
    "MONITORING_NAME": {
        "description": "Name of monitoring enhancement",
        "example": "Advanced database activity monitoring",
        "category": VariableCategory.REMEDIATION
    },
    "MONITORING_DETAILS": {
        "description": "Implementation details for monitoring enhancement",
        "example": "Implement real-time monitoring of all privileged database commands",
        "category": VariableCategory.REMEDIATION
    },
    "ALERT_CRITERIA": {
        "description": "Criteria that will trigger alerts",
        "example": "Multiple failed login attempts, unusual data access patterns, off-hours activity",
        "category": VariableCategory.REMEDIATION
    },
    "ROLE": {
        "description": "Role required for remediation",
        "example": "Senior Network Security Engineer",
        "category": VariableCategory.REMEDIATION
    },
    "RESPONSIBILITIES": {
        "description": "Responsibilities of role",
        "example": "Firewall reconfiguration and network segmentation implementation",
        "category": VariableCategory.REMEDIATION
    },
    "RESOURCE_COUNT": {
        "description": "Number of resources needed",
        "example": "2",
        "category": VariableCategory.REMEDIATION
    },
    "TIME_COMMITMENT": {
        "description": "Time commitment for resources",
        "example": "Full-time for 3 days",
        "category": VariableCategory.REMEDIATION
    },
    "RESOURCE": {
        "description": "Resource needed for remediation",
        "example": "Temporary cloud server instances",
        "category": VariableCategory.REMEDIATION
    },
    "PURPOSE": {
        "description": "Purpose of resource",
        "example": "Testing environment for security patches",
        "category": VariableCategory.REMEDIATION
    },
    "AVAILABILITY": {
        "description": "Availability of resource",
        "example": "Immediately available",
        "category": VariableCategory.REMEDIATION
    },
    "CATEGORY": {
        "description": "Budget category",
        "example": "External Security Services",
        "category": VariableCategory.REMEDIATION
    },
    "BUDGET_ITEM": {
        "description": "Specific budget item",
        "example": "Forensic investigation support",
        "category": VariableCategory.REMEDIATION
    },
    "ESTIMATED_COST": {
        "description": "Estimated cost of item",
        "example": "$25,000",
        "category": VariableCategory.REMEDIATION
    },
    "MILESTONE_NAME": {
        "description": "Name of remediation milestone",
        "example": "Complete system restoration",
        "category": VariableCategory.REMEDIATION
    },
    "TARGET_DATE": {
        "description": "Target date for milestone",
        "example": "2023-07-18",
        "category": VariableCategory.REMEDIATION
    },
    "DEPENDENCIES": {
        "description": "Dependencies for milestone",
        "example": "Completion of forensic analysis, hardware availability",
        "category": VariableCategory.REMEDIATION
    },
    "OWNER": {
        "description": "Owner of milestone",
        "example": "IT Operations Manager",
        "category": VariableCategory.REMEDIATION
    },
    "SYSTEM": {
        "description": "System with scheduled maintenance",
        "example": "Authentication Server",
        "category": VariableCategory.REMEDIATION
    },
    "SCHEDULED_DOWNTIME": {
        "description": "Scheduled downtime for maintenance",
        "example": "2023-07-17 02:00-04:00 UTC",
        "category": VariableCategory.REMEDIATION
    },
    "DURATION": {
        "description": "Duration of maintenance window",
        "example": "2 hours",
        "category": VariableCategory.REMEDIATION
    },
    "APPROVER": {
        "description": "Person who approved maintenance",
        "example": "CIO",
        "category": VariableCategory.REMEDIATION
    },
    "RISK_DESCRIPTION": {
        "description": "Description of implementation risk",
        "example": "Potential service disruption during database migration",
        "category": VariableCategory.REMEDIATION
    },
    "IMPACT": {
        "description": "Impact of risk",
        "example": "High - Would affect all customers",
        "category": VariableCategory.REMEDIATION
    },
    "LIKELIHOOD": {
        "description": "Likelihood of risk occurring",
        "example": "Medium",
        "category": VariableCategory.REMEDIATION
    },
    "RISK_LEVEL": {
        "description": "Overall risk level",
        "example": "High",
        "category": VariableCategory.REMEDIATION
    },
    "MITIGATION_STRATEGY": {
        "description": "Strategy to mitigate risk",
        "example": "Perform migration in phases with rollback points",
        "category": VariableCategory.REMEDIATION
    },
    "SYSTEM_OWNER": {
        "description": "Owner of affected system",
        "example": "Database Administration Team",
        "category": VariableCategory.REMEDIATION
    }
}

# Combine all variables into a single dictionary
TEMPLATE_VARIABLES = {
    **COMMON_VARIABLES,
    **INCIDENT_REPORT_VARIABLES,
    **TIMELINE_VARIABLES,
    **CHAIN_OF_CUSTODY_VARIABLES,
    **COMMUNICATION_VARIABLES,
    **REMEDIATION_VARIABLES
}

def get_variable_categories():
    """Return all variable categories."""
    return [category for category in VariableCategory]

def get_variables_by_category(category: VariableCategory) -> Dict[str, Dict[str, str]]:
    """
    Return all variables for a specific category.

    Args:
        category: The variable category to filter by

    Returns:
        Dict of variables in the specified category
    """
    return {
        key: value for key, value in TEMPLATE_VARIABLES.items()
        if value.get("category") == category
    }

def get_variables_by_template(template_type: TemplateType) -> Dict[str, Dict[str, str]]:
    """
    Return all variables relevant to a specific template type.

    Args:
        template_type: The template type to get variables for

    Returns:
        Dict of variables for the specified template
    """
    variables = COMMON_VARIABLES.copy()

    if template_type == TemplateType.INCIDENT_REPORT:
        variables.update(INCIDENT_REPORT_VARIABLES)
    elif template_type == TemplateType.INCIDENT_TIMELINE:
        variables.update(TIMELINE_VARIABLES)
    elif template_type == TemplateType.CHAIN_OF_CUSTODY:
        variables.update(CHAIN_OF_CUSTODY_VARIABLES)
    elif template_type == TemplateType.COMMUNICATION_PLAN:
        variables.update(COMMUNICATION_VARIABLES)
    elif template_type == TemplateType.REMEDIATION_PLAN:
        variables.update(REMEDIATION_VARIABLES)

    return variables
