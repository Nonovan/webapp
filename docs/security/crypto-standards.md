# Cryptographic Standards and Key Management

This document outlines the cryptographic standards and key management practices implemented across the Cloud Infrastructure Platform to ensure the confidentiality, integrity, and authenticity of data both at rest and in transit.

## Overview

The Cloud Infrastructure Platform employs industry-standard cryptographic algorithms, protocols, and key management practices to protect sensitive data. These standards align with NIST recommendations, ISO 27001 requirements, and other relevant compliance frameworks.

## Supported Cryptographic Algorithms

### Symmetric Encryption

| Algorithm | Key Length | Usage | Status |
|-----------|------------|-------|--------|
| AES-GCM | 256-bit | Data at rest, Secure communication | Approved |
| AES-CBC | 256-bit | Legacy systems only | Restricted |
| ChaCha20-Poly1305 | 256-bit | Alternative to AES-GCM for specific use cases | Approved |
| 3DES | Any | Legacy systems | Prohibited |
| RC4 | Any | Any usage | Prohibited |
| Blowfish | Any | Any usage | Prohibited |

### Asymmetric Encryption

| Algorithm | Key Length | Usage | Status |
|-----------|------------|-------|--------|
| RSA | 2048-bit minimum<br>4096-bit recommended | Key exchange, Digital signatures | Approved |
| ECDSA | P-256, P-384 | Digital signatures | Approved |
| ECDH | P-256, P-384 | Key exchange | Approved |
| Ed25519 | 256-bit | Digital signatures | Approved |
| X25519 | 256-bit | Key exchange | Approved |
| RSA | < 2048-bit | Any usage | Prohibited |
| DSA | Any | Any usage | Prohibited |

### Hash Functions

| Algorithm | Usage | Status |
|-----------|-------|--------|
| SHA-256 | General purpose hashing | Approved |
| SHA-384 | Critical systems hashing | Approved |
| SHA-512 | Critical systems hashing | Approved |
| HMAC-SHA-256 | Message authentication | Approved |
| HMAC-SHA-384 | Message authentication for critical systems | Approved |
| MD5 | Any usage | Prohibited |
| SHA-1 | Any usage | Prohibited |

### Key Derivation Functions

| Algorithm | Usage | Status |
|-----------|-------|--------|
| PBKDF2 | Password-based key derivation | Approved with min 310,000 iterations |
| Argon2id | Password hashing | Recommended |
| bcrypt | Password hashing | Approved |
| scrypt | Password hashing | Approved |
| HKDF | Key derivation from shared secrets | Approved |

## Transport Layer Security (TLS)

### TLS Protocol Versions

| Version | Status | Notes |
|---------|--------|-------|
| TLS 1.3 | Preferred | Use for all new implementations |
| TLS 1.2 | Approved | With approved cipher suites only |
| TLS 1.1 | Prohibited | Not to be used |
| TLS 1.0 | Prohibited | Not to be used |
| SSL (all versions) | Prohibited | Not to be used |

### Approved TLS Cipher Suites

#### TLS 1.3
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

#### TLS 1.2
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

### Deprecated TLS Cipher Suites

The following cipher suites must not be used:
- Any cipher suites using CBC mode
- Any cipher suites without Perfect Forward Secrecy (non-ECDHE/DHE)
- Any cipher suites using RC4, 3DES, or other weak ciphers
- Any cipher suites using SHA-1 or MD5

## Key Management

### Key Generation

- All cryptographic keys must be generated using approved cryptographically secure random number generators (CSPRNGs)
- Hardware security modules (HSMs) should be used for key generation where available
- Key generation must occur in a secure environment with appropriate access controls

### Key Storage

- Private keys must never be stored in plaintext
- Use dedicated key management services (KMS) provided by cloud providers where possible
- Hardware Security Modules (HSMs) should be used for storing critical keys
- Key material must be protected with appropriate access controls
- Keys must be stored separately from the data they protect

### Key Distribution

- Secure channels must be used for key distribution
- Keys must be encrypted during transmission
- Out-of-band verification should be used when distributing high-value keys
- Key exchange protocols must use Perfect Forward Secrecy

### Key Rotation

| Key Type | Rotation Frequency | Notes |
|----------|---------------------|-------|
| TLS Server Certificates | 1 year | Plus automated renewal before expiry |
| TLS Private Keys | 1 year | With certificate rotation |
| API Keys | 90 days | Automated rotation where possible |
| Data Encryption Keys (DEKs) | 1 year | Or upon security incident |
| Key Encryption Keys (KEKs) | 2 years | Or upon security incident |
| SSH Keys | 1 year | With proper key revocation |
| User Credentials | On-demand | Upon suspicion of compromise |
| JWT Signing Keys | 90 days | With proper key rotation procedures |

### Key Revocation

- Procedures must be in place for immediate key revocation in case of compromise
- Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP) must be properly configured
- Key revocation events must be logged and monitored
- Business continuity procedures must be in place to handle emergency key revocations

### Backup and Recovery

- Keys must be securely backed up to prevent loss
- Key recovery procedures must require multi-person authorization
- Backup copies of keys must have the same level of protection as production copies
- Key recovery events must be logged and audited

## Cryptography Implementation

### Secure Development Practices

- Use approved cryptographic libraries only (see below)
- Never implement custom cryptographic algorithms
- Follow secure coding practices when implementing cryptography
- Subject cryptographic implementations to regular security review and testing
- Apply the principle of least privilege to cryptographic operations

### Approved Cryptographic Libraries

| Language | Approved Libraries |
|----------|-------------------|
| Python | cryptography, pyca/cryptography, pynacl |
| JavaScript | Web Crypto API, Node.js crypto, subtle crypto |
| Java | Java Cryptography Architecture (JCA), Bouncy Castle |
| Go | golang.org/x/crypto, Go standard library crypto |
| .NET | .NET Core Cryptography, Bouncy Castle .NET |
| Rust | *ring*, RustCrypto, sodiumoxide |
| C/C++ | OpenSSL (1.1.1+), libsodium, Tink |

### Prohibited Practices

- Rolling custom cryptographic algorithms
- Using deprecated or broken algorithms (MD5, SHA-1, RC4, etc.)
- Hardcoding cryptographic keys in source code
- Storing unencrypted keys in configuration files
- Using default or predictable keys/passwords
- Using the same key for multiple purposes
- Using ECB mode for encryption
- Using non-authenticated encryption modes without additional integrity protection
- Disabling certificate validation in TLS connections

## Cryptographic Hardware

### Hardware Security Modules (HSMs)

- FIPS 140-2/140-3 Level 3 or higher HSMs should be used for critical applications
- HSMs must be properly configured according to vendor specifications and security best practices
- Multi-person access controls must be implemented for administrative HSM operations
- HSM operations must be logged and monitored

### Trusted Platform Modules (TPMs)

- TPMs should be used where available for secure key storage and platform integrity verification
- Boot attestation should be implemented using TPMs where possible
- TPM vendor security advisories must be monitored and updates applied

## Cloud Provider Cryptography Services

### AWS Key Management

- AWS KMS should be used for key management in AWS environments
- CMKs (Customer Master Keys) should be rotated annually
- Automatic key rotation should be enabled where supported
- AWS CloudHSM should be used for FIPS 140-2 Level 3 compliance requirements

### Google Cloud Platform

- Google Cloud KMS should be used for key management in GCP environments
- Cloud HSM should be used for FIPS 140-2 Level 3 compliance requirements
- Customer-managed encryption keys (CMEK) should be used for sensitive data

### Microsoft Azure

- Azure Key Vault should be used for key management in Azure environments
- Managed HSM should be used for FIPS 140-2 Level 3 compliance requirements
- Customer-managed keys should be used for sensitive data

## Compliance Requirements

The cryptographic standards defined in this document help maintain compliance with:

- ISO 27001 A.10 - Cryptography
- NIST SP 800-57 - Key Management Guidelines
- FIPS 140-2/140-3 - Security Requirements for Cryptographic Modules
- PCI DSS 4.0 Requirements 3.1-3.7, 4.1-4.2
- GDPR Article 32 - Security of processing
- SOC 2 Type II - Encryption control criteria
- HIPAA Security Rule - Technical safeguards

## Roles and Responsibilities

| Role | Responsibilities |
|------|------------------|
| CISO | Overall accountability for cryptographic standards |
| Security Architect | Defining and maintaining cryptographic standards |
| Infrastructure Security Manager | Implementation of cryptographic controls for infrastructure |
| Application Security Manager | Guidance on cryptographic implementation in applications |
| Cloud Security Engineer | Implementation of cryptographic controls in cloud environments |
| Developers | Proper implementation of cryptographic libraries |
| Security Audit Lead | Auditing compliance with cryptographic standards |

## Incident Response for Cryptographic Failures

In case of suspected cryptographic compromise:

1. **Identification**:
   - Identify affected systems and data
   - Determine the scope and nature of the compromise

2. **Containment**:
   - Revoke compromised keys immediately
   - Isolate affected systems if necessary

3. **Remediation**:
   - Generate new keys following secure procedures
   - Re-encrypt data with new keys
   - Update systems to use new cryptographic material

4. **Recovery**:
   - Deploy new keys and certificates
   - Verify proper implementation
   - Test functionality

5. **Post-Incident**:
   - Document lessons learned
   - Update cryptographic standards if necessary
   - Review key management procedures

## Audit and Verification

- Annual cryptographic implementation review
- Regular automated scanning for weak cryptographic implementations
- Penetration testing to include cryptographic assessment
- Code review processes to include cryptographic code evaluation
- Compliance verification against relevant standards

## Monitoring and Alerting

- Key usage and operations should be logged and monitored
- Suspicious cryptographic operations should trigger alerts
- Certificate expiration monitoring should be implemented
- Failed key operations should be logged and investigated
- HSM and KMS access should be monitored for unauthorized operations

## References

- [NIST SP 800-57 - Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-52 - Guidelines for TLS Implementations](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [NIST SP 800-175B - Guideline for Using Cryptographic Standards](https://csrc.nist.gov/publications/detail/sp/800-175b/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [NIST FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [Cloud Security Alliance - Cloud Key Management](https://cloudsecurityalliance.org/research/guidance/)

## Version History

| Version | Date | Description | Author |
|---------|------|-------------|--------|
| 1.0 | 2023-08-15 | Initial document | Security Architecture Team |
| 1.1 | 2023-11-10 | Updated TLS cipher suites | Cloud Security Engineer |
| 1.2 | 2024-01-30 | Added key rotation requirements | Security Architect |
| 1.3 | 2024-04-15 | Updated approved libraries | Application Security Manager |
| 1.4 | 2024-05-20 | Added cloud provider cryptography services and monitoring sections | Cloud Security Engineer |