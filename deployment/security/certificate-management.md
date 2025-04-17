# Certificate Management Procedures

This document outlines the procedures for managing SSL/TLS certificates within the Cloud Infrastructure Platform.

## Certificate Types and Usage

The platform uses several types of certificates for different purposes:

### Public-Facing SSL/TLS Certificates

* **Web Application Endpoints**
  * Customer-facing web interfaces
  * API endpoints
  * Admin interfaces

* **Requirements**
  * Issued by trusted public CA
  * Extended Validation (EV) for production
  * Organization Validation (OV) for staging
  * 2048-bit RSA or ECC P-256 keys
  * SHA-256 signature algorithm
  * Maximum 1-year validity

### Internal Service Certificates

* **Service-to-Service Communication**
  * Internal API calls
  * Microservice communication
  * Database connections

* **Requirements**
  * Internal CA-issued
  * 2048-bit RSA or ECC P-256 keys
  * SHA-256 signature algorithm
  * Maximum 2-year validity

### Certificate Authority (CA)

* **Internal CA**
  * Issues certificates for internal services
  * Not used for customer-facing services

* **Requirements**
  * 4096-bit RSA or ECC P-384 keys
  * SHA-256 signature algorithm
  * Offline root CA
  * Online intermediate CA
  * Maximum 10-year validity for root CA
  * Maximum 5-year validity for intermediate CA

## Certificate Lifecycle Management

### Acquisition

#### Public CA Certificates

1. **Planning**
   * Inventory domains requiring certificates
   * Choose appropriate certificate type
   * Select validation method

2. **CSR Generation**
   ```bash
   openssl req -new -newkey rsa:2048 -nodes -keyout example.key -out example.csr

```

1. **Validation**
    - DNS validation (preferred)
    - HTTP validation
    - Email validation
2. **Issuance**
    - Submit CSR to chosen CA
    - Complete validation requirements
    - Download certificate and chain

### Internal CA Certificates

1. **CSR Generation**
    
    ```bash
    openssl req -new -newkey rsa:2048 -nodes -keyout service.key -out service.csr
    
    ```
    
2. **Signing**
    
    ```bash
    openssl ca -in service.csr -out service.crt -config openssl.cnf
    
    ```
    

### Installation

1. **Web Servers**
    - Copy certificate, key, and chain to server
    - Update NGINX configuration
    - Validate configuration
    - Reload service
    
    ```bash
    sudo cp example.crt /etc/nginx/ssl/
    sudo cp example.key /etc/nginx/ssl/
    sudo cp chain.crt /etc/nginx/ssl/
    sudo nginx -t
    sudo systemctl reload nginx
    
    ```
    
2. **Application Services**
    - Copy certificate, key, and chain to service
    - Update service configuration
    - Restart service
    - Validate successful installation

### Monitoring

1. **Expiration Monitoring**
    - Automated monitoring of all certificates
    - Alerts at 90, 60, 30, 15, 7, 3, and 1 day before expiration
    - Daily summary report of certificate status
2. **Certificate Health Checks**
    - Weekly validation of certificate configuration
    - Cipher suite testing
    - Protocol validation
    - Chain validation
3. **SSL/TLS Quality Rating**
    - Monthly testing with SSL Labs
    - Minimum grade A requirement
    - Remediation of any issues found

### Renewal

1. **Renewal Schedule**
    - Public certificates: 30 days before expiration
    - Internal certificates: 60 days before expiration
2. **Automated Renewal**
    - Let's Encrypt certificates renewed automatically using Certbot
    - Run certificate renewal scripts using cron job
    
    ```bash
    0 3 * * * /opt/cloud-platform/deployment/security/certificate-renew.sh >> /var/log/cloud-platform/cert-renewal.log 2>&1
    
    ```
    
3. **Manual Renewal**
    - Follow same process as acquisition
    - Use same key or generate new key based on rotation policy

### Revocation

1. **Revocation Triggers**
    - Key compromise
    - Employee departure (for individually issued certificates)
    - Certificate replacement before expiration
    - Service decommissioning
2. **Revocation Process**
    - Request revocation from issuing CA
    - Update CRL and OCSP information
    - Remove certificate from all systems
    - Update certificate inventory

### Emergency Response

1. **Key Compromise**
    - Immediately revoke affected certificates
    - Generate new keys
    - Issue new certificates
    - Rotate affected certificates on all systems
    - Investigate cause and impact
    - Document incident and response
2. **CA Compromise**
    - Assess impact on all certificates
    - Prepare for mass certificate replacement
    - Follow certificate authority's instructions
    - Implement emergency certificate replacement

## Certificate Inventory Management

1. **Certificate Database**
    - Maintain inventory of all certificates
    - Record domains, services, expiration dates
    - Track responsible parties
    - Document renewal processes
2. **Automated Discovery**
    - Weekly scan of all systems for SSL/TLS certificates
    - Reconciliation with certificate inventory
    - Investigation of unauthorized certificates

## Tools and Automation

1. **Certificate Management Tools**
    - Certbot for Let's Encrypt automation
    - OpenSSL for certificate operations
    - Custom [certificate-renew.sh](http://certificate-renew.sh/) script for automation
    - Certificate monitoring integration with monitoring system
2. **Standard Commands**
    
    **Generate CSR and key:**
    
    ```bash
    openssl req -new -newkey rsa:2048 -nodes -keyout example.key -out example.csr -config csr.conf
    
    ```
    
    **Verify certificate:**
    
    ```bash
    openssl x509 -in example.crt -text -noout
    
    ```
    
    **Check certificate expiration:**
    
    ```bash
    openssl x509 -in example.crt -noout -enddate
    
    ```
    
    **Test SSL/TLS configuration:**
    
    ```bash
    openssl s_client -connect example.com:443 -tls1_2
    
    ```
    

## Best Practices

1. **Security Measures**
    - Private keys protected with strict permissions (0600)
    - Keys stored in secure locations
    - Keys never transmitted over unencrypted channels
    - Passphrase protection for sensitive keys
2. **Configuration Standards**
    - TLS 1.2/1.3 only
    - Strong cipher suites only
    - OCSP stapling enabled
    - HTTP Strict Transport Security (HSTS)
    - Certificate Transparency (CT) logging
3. **Documentation**
    - Document all certificate processes
    - Maintain certificate inventory
    - Record all certificate-related incidents
    - Document emergency procedures

## Compliance Requirements

- **PCI DSS**: Requires strong certificates and protocols
- **HIPAA**: Requires encryption of PHI in transit
- **SOC 2**: Requires proper certificate management controls
- **GDPR**: Requires appropriate technical measures for data protection

## Roles and Responsibilities

- **Security Team**: Certificate policy management and oversight
- **DevOps Team**: Certificate deployment and rotation
- **Development Team**: Certificate integration in applications
- **Monitoring Team**: Certificate expiration alerting

## Review and Improvement

- Quarterly review of certificate management processes
- Annual audit of all certificates and practices
- Continuous improvement based on industry standards