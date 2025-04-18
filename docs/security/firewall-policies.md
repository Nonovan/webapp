# Firewall Policies and Configuration

This document outlines the firewall policies and configuration standards for the Cloud Infrastructure Platform.

## Network Security Architecture

The Cloud Infrastructure Platform employs a multi-layered network security approach:

1. **Perimeter Layer**
   * External firewalls
   * DDoS protection services
   * Edge routers with ACLs

2. **DMZ Layer**
   * Web application firewalls (WAF)
   * Load balancers
   * Public-facing services

3. **Application Layer**
   * Internal firewalls
   * Application security groups
   * Micro-segmentation

4. **Database Layer**
   * Database firewalls
   * Data access controls
   * Encryption gateways

5. **Management Layer**
   * Bastion hosts
   * Jump servers
   * Administrative networks

## Firewall Policy Principles

### Core Principles

1. **Default Deny**
   * All traffic is denied by default
   * Explicit allow for required traffic only

2. **Least Privilege**
   * Allow only necessary access
   * Minimize scope of allowed communications

3. **Defense in Depth**
   * Multiple control points
   * Overlapping protection mechanisms
   * No single point of failure

4. **Zero Trust**
   * No implicit trust based on network location
   * All access requires authentication and authorization
   * Continuous verification

### Policy Enforcement Points

1. **Host Firewalls**
   * IPTables/NFTables rules on Linux hosts
   * Applied to all servers regardless of other protections

2. **Network Firewalls**
   * Hardware or virtual appliances
   * Cloud provider security groups
   * Software-defined networking controls

3. **Web Application Firewalls**
   * ModSecurity for HTTP/HTTPS traffic
   * API gateway protections
   * Layer 7 filtering

4. **Container Firewalls**
   * Pod security policies
   * Network policies
   * Service mesh controls

## Standard Firewall Rule Sets

### External Access Rules

| Source | Destination | Protocol | Port | Purpose | Environments |
|--------|------------|----------|------|---------|--------------|
| Any | Web Servers | TCP | 443 | HTTPS Access | All |
| Any | API Gateways | TCP | 443 | API Access | All |
| Authorized IPs | Management Hosts | TCP | 22 | SSH Access | All |
| CDN IPs | Web Servers | TCP | 443 | Content Delivery | Prod, Staging |
| Monitoring IPs | All Hosts | TCP | Various | Monitoring | All |

### Internal Network Rules

| Source | Destination | Protocol | Port | Purpose | Environments |
|--------|------------|----------|------|---------|--------------|
| Web Servers | App Servers | TCP | 8080-8090 | Application Traffic | All |
| App Servers | Database Servers | TCP | 5432 | PostgreSQL | All |
| App Servers | Cache Servers | TCP | 6379 | Redis | All |
| App Servers | Queue Servers | TCP | 5672 | RabbitMQ | All |
| Management Hosts | All Hosts | TCP | 22 | SSH Management | All |
| Monitoring Servers | All Hosts | TCP | 9100 | Node Exporter | All |
| Monitoring Servers | All Hosts | TCP | 9090 | Prometheus | All |

### Default Deny Rules

| Source | Destination | Protocol | Port | Action |
|--------|------------|----------|------|--------|
| Any | Any | Any | Any | DENY |

## Host Firewall Configuration

### IPTables Configuration

The host-based firewall is implemented using IPTables with the following structure:

1. **Default Policies**
   ```bash
   iptables -P INPUT DROP
   iptables -P FORWARD DROP
   iptables -P OUTPUT ACCEPT

```

1. **Allow Established Connections**
    
    ```bash
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    ```
    
2. **Allow Local Loopback**
    
    ```bash
    iptables -A INPUT -i lo -j ACCEPT
    
    ```
    
3. **Service-Specific Rules**
    
    ```bash
    # SSH access (restricted to management network)
    iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
    
    # Web traffic
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    ```
    
4. **Rate Limiting**
    
    ```bash
    # Rate limit SSH connections
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    
    ```
    
5. **Logging**
    
    ```bash
    # Log dropped packets
    iptables -A INPUT -j LOG --log-prefix "IPTABLES DROP: " --log-level 4
    
    ```
    

The complete IPTables configuration is applied by the [iptables-rules.sh](http://iptables-rules.sh/) script.

## Cloud Provider Firewall Configuration

### AWS Security Groups

Example AWS security group configuration:

```json
{
  "GroupName": "web-server-sg",
  "Description": "Security group for web servers",
  "Rules": [
    {
      "IpProtocol": "tcp",
      "FromPort": 443,
      "ToPort": 443,
      "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
      "Description": "HTTPS from anywhere"
    },
    {
      "IpProtocol": "tcp",
      "FromPort": 22,
      "ToPort": 22,
      "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
      "Description": "SSH from internal network"
    }
  ]
}

```

### Azure Network Security Groups

Example Azure NSG configuration:

```json
{
  "name": "web-server-nsg",
  "properties": {
    "securityRules": [
      {
        "name": "HTTPS",
        "properties": {
          "protocol": "TCP",
          "sourcePortRange": "*",
          "destinationPortRange": "443",
          "sourceAddressPrefix": "*",
          "destinationAddressPrefix": "*",
          "access": "Allow",
          "priority": 100,
          "direction": "Inbound"
        }
      },
      {
        "name": "SSH",
        "properties": {
          "protocol": "TCP",
          "sourcePortRange": "*",
          "destinationPortRange": "22",
          "sourceAddressPrefix": "10.0.0.0/8",
          "destinationAddressPrefix": "*",
          "access": "Allow",
          "priority": 110,
          "direction": "Inbound"
        }
      }
    ]
  }
}

```

### Google Cloud Firewall Rules

Example GCP firewall rules:

```yaml
- name: allow-https
  allowed:
  - IPProtocol: tcp
    ports:
    - '443'
  sourceRanges:
  - 0.0.0.0/0
  targetTags:
  - web-server

- name: allow-ssh-internal
  allowed:
  - IPProtocol: tcp
    ports:
    - '22'
  sourceRanges:
  - 10.0.0.0/8
  targetTags:
  - web-server

```

## Web Application Firewall (WAF) Policy

### ModSecurity Configuration

The platform uses ModSecurity with OWASP Core Rule Set (CRS) and custom rules:

1. **Base Configuration**
    - SecRuleEngine On
    - SecResponseBodyAccess On
    - SecRequestBodyLimit 10485760
2. **Rule Sets**
    - OWASP Core Rule Set (CRS) 3.3+
    - Custom platform-specific rules
    - IP reputation rules
3. **Protection Capabilities**
    - SQL Injection protection
    - Cross-Site Scripting (XSS) protection
    - Local/Remote File Inclusion protection
    - HTTP Protocol protection
    - Automated scanning detection
    - Rate limiting and anti-automation

### Custom WAF Rules

Example custom WAF rules for the platform:

```
# Block common attack patterns
SecRule REQUEST_URI "@rx (?:(?:\\.\\./)|(?:\\.\\.\\\\))" \\
    "id:10001,phase:1,t:none,t:urlDecodeUni,t:normalizePathWin,log,deny,status:403,msg:'Path Traversal Attack'"

# Block sensitive API access from unauthorized sources
SecRule REQUEST_URI "@beginsWith /api/admin/" \\
    "chain,id:10002,phase:1,t:none,log,deny,status:403"
SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8" \\
    "t:none"

# Rate limit login attempts
SecRule REQUEST_URI "@streq /api/auth/login" \\
    "id:10003,phase:1,t:none,nolog,pass,setvar:ip.login_attempt=+1,expirevar:ip.login_attempt=60"
SecRule IP:LOGIN_ATTEMPT "@gt 5" \\
    "id:10004,phase:1,t:none,log,deny,status:429,msg:'Login Rate Limit Exceeded'"

```

## Network Traffic Flow Controls

### Ingress Traffic Controls

1. **External Access Control**
    - TLS termination at edge
    - DDoS protection service
    - Geographic access restrictions
    - Rate limiting and throttling
2. **Request Filtering**
    - HTTP method restrictions
    - Content type validation
    - Request size limits
    - Input validation

### Egress Traffic Controls

1. **Data Loss Prevention**
    - Restricted outbound destinations
    - Content inspection
    - Data classification-based filtering
    - Encrypted tunnel requirements
2. **Malicious Communication Prevention**
    - Command and control blocking
    - DNS filtering
    - Proxy enforcement
    - TLS inspection where necessary

## Firewall Management and Operations

### Change Management

1. **Rule Change Process**
    - Request submission
    - Security review
    - Risk assessment
    - Approval workflow
    - Implementation
    - Verification
2. **Emergency Changes**
    - Expedited approval process
    - Post-implementation review
    - Documentation requirements
    - Change reversal procedure

### Monitoring and Auditing

1. **Rule Effectiveness Monitoring**
    - Traffic pattern analysis
    - Rule hit counts
    - False positive/negative monitoring
    - Performance impact assessment
2. **Compliance Auditing**
    - Quarterly rule review
    - Compliance validation
    - Unauthorized change detection
    - Configuration drift monitoring

### Firewall Logging and Analysis

1. **Log Collection**
    - Centralized logging
    - Log retention policy
    - Tamper-evident storage
2. **Security Analysis**
    - Alert generation
    - Correlation with other security events
    - Anomaly detection
    - Threat hunting

## Incident Response

### Firewall-Related Incidents

1. **Breach Detection**
    - Indicators of compromise
    - Unusual traffic patterns
    - Rule bypass detection
    - Multiple blocked attempts
2. **Response Actions**
    - Temporary blocking rules
    - Traffic diversion
    - Enhanced logging
    - Forensic capture

### Recovery Procedures

1. **Rule Restoration**
    - Known-good configuration recovery
    - Incremental rule deployment
    - Validation testing
    - Performance monitoring
2. **Post-Incident Analysis**
    - Root cause identification
    - Rule effectiveness assessment
    - Improvement recommendations
    - Documentation updates

## References

- [CIS Benchmarks for Firewalls](https://www.cisecurity.org/cis-benchmarks/)
- [NIST SP 800-41: Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)
- [OWASP WAF Configuration Guide](https://owasp.org/www-project-web-security-testing-guide/)