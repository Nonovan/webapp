# Chain of Custody Form

**Classification:** {{classification}}
**Case ID:** {{case_id}}
**Evidence ID:** {{evidence_id}}
**Document ID:** COC-{{case_id}}-{{evidence_id}}

## Evidence Information

**Description:** {{evidence_description}}
**Type:** {{evidence_type}}
**Acquisition Date:** {{acquisition_date}}
**Source Location:** {{source_location}}

**Hash Values:**

- SHA-256: {{acquisition_hash}}
- MD5: {{acquisition_md5}} *(optional)*

## Custody Record

This document records the complete chain of custody for the described evidence item. All individuals who handle, transfer, or access this evidence must record their actions below.

| Date/Time (UTC) | Action | From | To | Performed By | Purpose | Verification Method | Hash Value | Notes |
|-----------------|--------|------|-----|-------------|---------|---------------------|-----------|-------|
| {{acquisition_date}} | Initial Acquisition | {{source_location}} | {{storage_location}} | {{collector_name}} | Evidence Collection | {{verification_method}} | {{acquisition_hash}} | {{acquisition_notes}} |
| | | | | | | | | |
| | | | | | | | | |
| | | | | | | | | |
| | | | | | | | | |

## Storage Conditions

**Default Storage Location:** {{storage_location}}
**Storage Requirements:**

- {{storage_requirements}}

**Access Restrictions:**

- {{access_restrictions}}

## Transfer Authorization

All transfers of this evidence must be authorized by one of the following:

- Case Lead Investigator
- Digital Forensic Team Lead
- Legal Counsel
- Security Operations Manager

## Verification Procedures

When verifying evidence integrity, use the following procedure:

1. Calculate SHA-256 hash of evidence using authorized tools
2. Compare calculated hash with the last recorded hash value
3. Document verification results in the custody record
4. Report any discrepancies immediately to the Case Lead Investigator

## Evidence Disposition

**Retention Period:** {{retention_period}}
**Disposition Method:** {{disposition_method}}
**Disposition Authority:** {{disposition_authority}}

## Authentication

I certify that the information provided in this chain of custody document is accurate and complete to the best of my knowledge.

**Form Prepared By:** {{preparer_name}}
**Position/Title:** {{preparer_title}}
**Date:** {{preparation_date}}
**Signature:** ________________________

## Document Control

**Version:** 1.0
**Last Updated:** {{preparation_date}}
**Review Frequency:** After each evidence transfer or access event
**Document Owner:** Security Incident Response Team

---

This document must remain with the evidence at all times or be stored in the designated secure location. All access to this document must be logged. Unauthorized access or modification of this document is strictly prohibited.

### Reference

NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
