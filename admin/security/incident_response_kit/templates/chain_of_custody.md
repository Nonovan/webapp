# Chain of Custody Documentation

**Classification:** {{CLASSIFICATION}}
**Incident ID:** {{INCIDENT_ID}}
**Document ID:** COC-{{INCIDENT_ID}}-{{DOCUMENT_VERSION}}
**Date Created:** {{DATE}}
**Last Updated:** {{LAST_UPDATED}}
**Document Status:** {{STATUS}}
**Prepared By:** {{CUSTODIAN_NAME}}

## Evidence Information

**Evidence ID:** {{EVIDENCE_ID}}
**Description:** {{EVIDENCE_DESCRIPTION}}
**Type:** {{EVIDENCE_TYPE}}
**Collection Date/Time:** {{COLLECTION_DATETIME}}
**Collection Location:** {{COLLECTION_LOCATION}}
**Collected By:** {{COLLECTOR_NAME}}
**Collection Method:** {{COLLECTION_METHOD}}
**Collection Tools:** {{COLLECTION_TOOLS}}

**Hash Values:**

- SHA-256: {{HASH_SHA256}}
- MD5: {{HASH_MD5}} _(optional)_

**Original Source:** {{ORIGINAL_SOURCE}}
**Initial Storage Location:** {{STORAGE_LOCATION}}

## Chain of Custody Log

This document records the complete chain of custody for the described evidence item. All individuals who handle, transfer, or access this evidence must record their actions below.

| Date/Time (UTC) | Action | From | To | Handled By | Purpose | Verification Method | Hash Value | Notes |
|-----------------|--------|------|-----|-----------|---------|---------------------|-----------|-------|
| {{ACQUISITION_DATETIME}} | Initial Acquisition | {{ORIGINAL_SOURCE}} | {{STORAGE_LOCATION}} | {{COLLECTOR_NAME}} | Evidence Collection | {{VERIFICATION_METHOD}} | {{HASH_SHA256}} | {{ACQUISITION_NOTES}} |
| {{CUSTODY_DATETIME}} | {{CUSTODY_ACTION}} | {{CUSTODY_FROM}} | {{CUSTODY_TO}} | {{CUSTODY_HANDLER}} | {{CUSTODY_PURPOSE}} | {{CUSTODY_VERIFICATION}} | {{CUSTODY_HASH}} | {{CUSTODY_NOTES}} |
| | | | | | | | | |
| | | | | | | | | |
| | | | | | | | | |

## Storage Requirements

**Storage Location:** {{STORAGE_LOCATION}}
**Storage Conditions:**

- {{STORAGE_REQUIREMENT_1}}
- {{STORAGE_REQUIREMENT_2}}
- {{STORAGE_REQUIREMENT_3}}

**Access Restrictions:**

- {{ACCESS_RESTRICTION_1}}
- {{ACCESS_RESTRICTION_2}}
- {{ACCESS_RESTRICTION_3}}

## Transfer Authorization

All transfers of this evidence must be authorized by one of the following:

- Incident Response Manager
- Lead Investigator
- Digital Forensics Team Lead
- Security Operations Manager
- Legal Counsel

## Verification Procedures

When verifying evidence integrity, use the following procedure:

1. Calculate SHA-256 hash of evidence using authorized tools
2. Compare calculated hash with the last recorded hash value
3. Document verification results in the custody record
4. Report any discrepancies immediately to the Incident Response Manager

**Authorized Verification Tools:**

- {{VERIFICATION_TOOL_1}}
- {{VERIFICATION_TOOL_2}}
- {{VERIFICATION_TOOL_3}}

## Evidence Disposition

**Retention Period:** {{RETENTION_PERIOD}}
**Retention Requirement Source:** {{RETENTION_REQUIREMENT}}
**Disposition Date:** {{DISPOSITION_DATE}}
**Disposition Method:** {{DISPOSITION_METHOD}}
**Disposition Authority:** {{DISPOSITION_AUTHORITY}}

## Integrity Verification History

| Date/Time (UTC) | Verified By | Verification Method | Result | Notes |
|-----------------|-------------|---------------------|--------|-------|
| {{VERIFICATION_DATETIME}} | {{VERIFIER_NAME}} | {{VERIFICATION_METHOD}} | {{VERIFICATION_RESULT}} | {{VERIFICATION_NOTES}} |
| | | | | |
| | | | | |

## Related Evidence

| Related Evidence ID | Relationship Type | Description |
|---------------------|-------------------|-------------|
| {{RELATED_EVIDENCE_ID}} | {{RELATIONSHIP_TYPE}} | {{RELATIONSHIP_DESCRIPTION}} |
| | | |
| | | |

## Authentication

I certify that the information provided in this chain of custody document is accurate and complete to the best of my knowledge. I understand that this document may be used in legal proceedings and that inaccurate information may constitute a violation of policy or law.

**Document Prepared By:** {{PREPARER_NAME}}
**Position/Title:** {{PREPARER_TITLE}}
**Date:** {{PREPARATION_DATE}}
**Signature:** ________________________

## Document Control

**Version:** {{DOCUMENT_VERSION}}
**Last Updated:** {{LAST_UPDATED}}
**Updated By:** {{UPDATER_NAME}}
**Review Frequency:** After each evidence transfer, access, or verification
**Document Owner:** Security Incident Response Team

### Document History

| Version | Date | Modified By | Description of Changes |
|---------|------|------------|------------------------|
| 1.0 | {{CREATION_DATE}} | {{CREATOR_NAME}} | Initial document creation |
| {{VERSION}} | {{MODIFICATION_DATE}} | {{MODIFIER_NAME}} | {{MODIFICATION_DESCRIPTION}} |

---

**SECURITY CLASSIFICATION:** {{CLASSIFICATION}}

This document must remain with the evidence at all times or be stored in the designated secure location. All access to this document must be logged. Unauthorized access or modification of this document is strictly prohibited.

### Reference

Based on NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
