# Evidence Inventory

**Classification:** {{classification}}
**Case ID:** {{case_id}}
**Document ID:** INV-{{case_id}}
**Preparer:** {{analyst_name}}
**Date Created:** {{creation_date}}
**Last Updated:** {{last_updated}}

## Inventory Overview

This document provides a comprehensive inventory of all evidence items collected and preserved in relation to case {{case_id}}. All items listed are subject to proper chain of custody procedures and must be handled in accordance with digital evidence handling guidelines.

**Incident Type:** {{incident_type}}
**Investigation Period:** {{investigation_period}}
**Lead Investigator:** {{lead_investigator}}
**Evidence Storage Location:** {{primary_storage_location}}
**Retention Period:** {{retention_period}}

## Evidence Collection Summary

| Category | Item Count | Total Size | Description |
|----------|------------|------------|-------------|
| Memory Dumps | {{memory_count}} | {{memory_size}} | System memory acquisitions |
| Disk Images | {{disk_count}} | {{disk_size}} | Full and partial disk images |
| Network Captures | {{network_count}} | {{network_size}} | Network traffic recordings |
| Log Files | {{log_count}} | {{log_size}} | System and application logs |
| Document Files | {{document_count}} | {{document_size}} | Relevant documents and files |
| Other | {{other_count}} | {{other_size}} | Miscellaneous evidence items |
| **TOTAL** | {{total_count}} | {{total_size}} | All evidence items |

## Digital Evidence Items

### Memory Evidence

| Evidence ID | Acquisition Date | System/Source | Size | Hash (SHA-256) | Acquisition Method | Custodian | Notes |
|-------------|-----------------|---------------|------|----------------|-------------------|-----------|-------|
| {{evidence_id}} | {{acquisition_date}} | {{source_identifier}} | {{size}} | {{hash_value}} | {{acquisition_method}} | {{custodian}} | {{notes}} |
| | | | | | | | |
| | | | | | | | |

### Disk Images

| Evidence ID | Acquisition Date | System/Source | Size | Hash (SHA-256) | Acquisition Method | Custodian | Notes |
|-------------|-----------------|---------------|------|----------------|-------------------|-----------|-------|
| {{evidence_id}} | {{acquisition_date}} | {{source_identifier}} | {{size}} | {{hash_value}} | {{acquisition_method}} | {{custodian}} | {{notes}} |
| | | | | | | | |
| | | | | | | | |

### Network Captures

| Evidence ID | Acquisition Date | System/Source | Size | Hash (SHA-256) | Capture Duration | Custodian | Notes |
|-------------|-----------------|---------------|------|----------------|------------------|-----------|-------|
| {{evidence_id}} | {{acquisition_date}} | {{source_identifier}} | {{size}} | {{hash_value}} | {{capture_duration}} | {{custodian}} | {{notes}} |
| | | | | | | | |
| | | | | | | | |

### Log Files

| Evidence ID | Acquisition Date | System/Source | Size | Hash (SHA-256) | Log Time Range | Custodian | Notes |
|-------------|-----------------|---------------|------|----------------|----------------|-----------|-------|
| {{evidence_id}} | {{acquisition_date}} | {{source_identifier}} | {{size}} | {{hash_value}} | {{log_time_range}} | {{custodian}} | {{notes}} |
| | | | | | | | |
| | | | | | | | |

### Document Files

| Evidence ID | Acquisition Date | System/Source | Size | Hash (SHA-256) | File Type | Custodian | Notes |
|-------------|-----------------|---------------|------|----------------|-----------|-----------|-------|
| {{evidence_id}} | {{acquisition_date}} | {{source_identifier}} | {{size}} | {{hash_value}} | {{file_type}} | {{custodian}} | {{notes}} |
| | | | | | | | |
| | | | | | | | |

### Other Evidence

| Evidence ID | Acquisition Date | Description | Size | Hash (SHA-256) | Custodian | Notes |
|-------------|-----------------|-------------|------|----------------|-----------|-------|
| {{evidence_id}} | {{acquisition_date}} | {{description}} | {{size}} | {{hash_value}} | {{custodian}} | {{notes}} |
| | | | | | | |
| | | | | | | |

## Derivative Evidence

This section lists evidence items derived from original sources through processing, extraction, or analysis.

| Evidence ID | Parent Evidence ID | Creation Date | Description | Size | Hash (SHA-256) | Creator | Notes |
|-------------|-------------------|--------------|-------------|------|----------------|---------|-------|
| {{evidence_id}} | {{parent_evidence_id}} | {{creation_date}} | {{description}} | {{size}} | {{hash_value}} | {{creator}} | {{notes}} |
| | | | | | | | |
| | | | | | | | |

## Evidence Relationship Map

This section documents relationships between evidence items to establish context and connections.

| Primary Evidence ID | Related Evidence ID | Relationship Type | Description |
|--------------------|---------------------|------------------|-------------|
| {{primary_evidence_id}} | {{related_evidence_id}} | {{relationship_type}} | {{description}} |
| | | | |
| | | | |

## Physical Evidence

This section documents any physical evidence items associated with this investigation.

| Evidence ID | Description | Location | Condition | Chain of Custody Ref | Notes |
|------------|-------------|----------|-----------|---------------------|-------|
| {{evidence_id}} | {{description}} | {{location}} | {{condition}} | COC-{{case_id}}-{{evidence_id}} | {{notes}} |
| | | | | | |
| | | | | | |

## Evidence Storage Locations

| Storage ID | Location Type | Physical Location | Access Controls | Notes |
|-----------|--------------|-------------------|----------------|-------|
| {{storage_id}} | {{location_type}} | {{physical_location}} | {{access_controls}} | {{notes}} |
| | | | | |
| | | | | |

## Evidence Handling Notes

{{evidence_handling_notes}}

## Evidence Verification History

| Evidence ID | Verification Date | Verified By | Method | Result | Notes |
|------------|-----------------|------------|--------|--------|-------|
| {{evidence_id}} | {{verification_date}} | {{verifier}} | {{method}} | {{result}} | {{notes}} |
| | | | | | |
| | | | | | |

## Document Control

**Version:** {{document_version}}
**Last Updated:** {{last_updated}}
**Updated By:** {{updater_name}}
**Review Frequency:** Monthly or upon addition of new evidence

### Document History

| Version | Date | Modified By | Description of Changes |
|---------|------|------------|------------------------|
| 1.0 | {{creation_date}} | {{analyst_name}} | Initial document creation |
| {{version}} | {{modification_date}} | {{modifier_name}} | {{modification_description}} |

---

**Document Owner:** {{document_owner}}

This document must be maintained in accordance with evidence handling procedures and access restricted to authorized personnel only. All changes must be documented in the Document History section.

### Reference

NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
