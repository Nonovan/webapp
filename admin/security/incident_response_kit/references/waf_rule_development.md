# WAF Rule Development Guide

## Contents

- [Overview](#overview)
- [WAF Rule Fundamentals](#waf-rule-fundamentals)
- [Rule Development Process](#rule-development-process)
- [Rule Types and Patterns](#rule-types-and-patterns)
- [Testing and Validation](#testing-and-validation)
- [Deployment Strategies](#deployment-strategies)
- [Implementation Reference](#implementation-reference)
- [Available Functions](#available-functions)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

This guide provides structured approaches for developing effective Web Application Firewall (WAF) rules during security incidents, particularly in response to web application attacks. It covers the entire rule development lifecycle from attack analysis to rule creation, testing, deployment, and maintenance.

WAF rules are a critical defense mechanism for protecting web applications and APIs from various attacks. By implementing properly crafted rules, security teams can block malicious traffic while minimizing disruption to legitimate users. This guide focuses on creating effective rules based on attack evidence collected during security incidents.

## WAF Rule Fundamentals

### Key Rule Components

1. **Rule Identifier**
   - Unique identifier for each rule
   - Versioning information
   - Category classification
   - Priority/severity indication
   - Origin tracking

2. **Match Conditions**
   - HTTP request components to inspect
   - Pattern matching expressions
   - Logical operators
   - Transformation functions
   - Variable selections

3. **Rule Actions**
   - Block request
   - Allow request
   - Log only (monitoring mode)
   - Rate limit
   - Challenge client
   - Custom response

4. **Metadata Elements**
   - Description of attack type
   - Creation information
   - References to CVEs or threats
   - Documentation links
   - Associated incident IDs

5. **Performance Considerations**
   - Execution phase specification
   - Rule chain positioning
   - Optimization parameters
   - Skip conditions
   - Resource utilization metrics

### Common WAF Variables

| Variable Category | Examples | Common Use Cases |
|------------------|----------|------------------|
| **Request Line** | REQUEST_METHOD, REQUEST_URI, QUERY_STRING | Method enforcement, path traversal, injection attacks |
| **Headers** | HTTP_USER_AGENT, HTTP_REFERER, HTTP_COOKIE | Bot detection, CSRF protection, session attacks |
| **Request Body** | REQUEST_BODY, XML, JSON | Command injection, XSS, SQLi in POST data |
| **File Upload** | FILES, FILES_NAMES, FILES_SIZES | Malicious file detection, file type enforcement |
| **Server Variables** | SERVER_NAME, REMOTE_ADDR | Access control, geo-blocking |
| **Combined** | ARGS, ARGS_NAMES, ARGS_POST | General parameter inspection across methods |

### Rule Phases

Modern WAF processing typically occurs across multiple phases:

1. **Connection Phase (1)**: Low-level connection handling
2. **Request Headers Phase (2)**: HTTP headers inspection
3. **Request Body Phase (3)**: POST data and file upload analysis
4. **Response Headers Phase (4)**: Server response header inspection
5. **Response Body Phase (5)**: Response content inspection

Most application attack rules operate in phases 2 and 3, while data leakage prevention rules typically use phases 4 and 5.

## Rule Development Process

### 1. Attack Analysis

1. **Evidence Collection**
   - Gather web server and application logs
   - Collect WAF alert data
   - Capture full HTTP requests if available
   - Examine application error logs
   - Document observed attack patterns

2. **Attack Characterization**
   - Identify targeted application component
   - Determine attack technique
   - Analyze request patterns
   - Identify distinguishing attack markers
   - Assess attack sophistication level

3. **Payload Extraction**
   - Isolate malicious payload components
   - Identify evasion techniques
   - Document encoding methods
   - Extract attack signatures
   - Create normalized attack samples

4. **Common Patterns Identification**
   - Group similar attack attempts
   - Identify recurring patterns
   - Determine attack tool signatures
   - Recognize automation indicators
   - Document pattern variations

### 2. Rule Creation

1. **Signature Development**
   - Define detection patterns
   - Select appropriate variables
   - Determine matching operators
   - Apply necessary transformations
   - Define logical rule chains

2. **Regular Expression Construction**
   - Start with exact match patterns
   - Develop generalized patterns
   - Test against attack samples
   - Include boundary assertions
   - Handle evasion techniques

3. **Evasion Protection**
   - Implement multiple encoding detections
   - Address case sensitivity issues
   - Handle null byte injections
   - Account for obfuscation techniques
   - Implement transformation functions

4. **Optimization Techniques**
   - Use anchored patterns when possible
   - Implement early termination conditions
   - Use negative lookups for performance
   - Avoid excessive backtracking
   - Minimize rule complexity

### 3. Rule Documentation

1. **Rule Header Documentation**
   - Provide clear rule title
   - Add detailed description
   - Include attack reference information
   - Document creation information
   - Add incident identifier when applicable

2. **Pattern Documentation**
   - Document regex pattern purpose
   - Explain complex pattern components
   - Document transformation rationale
   - Include pattern limitations
   - Document false positive potential

3. **Chain Documentation**
   - Document rule chain relationships
   - Explain chain logic
   - Document chain dependencies
   - Include phase information
   - Document expected execution flow

4. **Performance Notes**
   - Document performance implications
   - Include optimization notes
   - Document resource requirements
   - Include scaling considerations
   - Document expected traffic impact

## Rule Types and Patterns

### Request Method Protection

1. **Method Limitation Rules**
   - Restrict to specific HTTP methods
   - Block unauthorized methods
   - Enforce proper method for endpoints
   - Prevent method-based attacks
   - Example pattern: `^(?:GET|POST|PUT|DELETE)$`

2. **Method Implementation**

   ```plaintext
   # Restrict HTTP methods
   SecRule REQUEST_METHOD "!@rx ^(?:GET|POST|PUT|DELETE)$" \
       "id:10001,\
       phase:1,\
       t:none,\
       block,\
       msg:'HTTP method not allowed',\
       logdata:'%{REQUEST_METHOD}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-generic'"
   ```

### Path Traversal Protection

1. **Path Normalization Detection**
   - Identify directory traversal attempts
   - Detect path normalization sequences
   - Block access to sensitive directories
   - Prevent webroot escapes
   - Example pattern: `\.\.|%2e%2e|\/\/|\\\\|\/\.\/|\\\.\\`

2. **Implementation Example**

   ```plaintext
   # Path traversal detection
   SecRule REQUEST_URI|ARGS|ARGS_NAMES "@rx (?:\.\.|%2e%2e|\/\/|\\\\\\\\|\/%2e\/|\\\\%2e\\\\)" \
       "id:10002,\
       phase:1,\
       t:none,t:urlDecodeUni,t:lowercase,\
       block,\
       msg:'Path Traversal Attack',\
       logdata:'%{MATCHED_VAR}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-lfi'"
   ```

### SQL Injection Protection

1. **SQL Pattern Detection**
   - Identify SQL keywords and patterns
   - Detect comment-based injections
   - Block union-based attacks
   - Prevent boolean-based blind injections
   - Example pattern: `(?i:(?:select|union|insert|update|delete|drop)\b.*?\bfrom\b)`

2. **Implementation Example**

   ```plaintext
   # SQL injection pattern detection
   SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES "@rx (?i:(?:select|union|insert|update|delete|drop)\b.*?\bfrom\b)" \
       "id:10003,\
       phase:2,\
       t:none,t:urlDecodeUni,\
       block,\
       msg:'SQL Injection Attack',\
       logdata:'%{MATCHED_VAR}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-sqli'"
   ```

### Cross-Site Scripting Protection

1. **XSS Pattern Detection**
   - Identify script tag injections
   - Detect event handler injections
   - Block JavaScript protocol handlers
   - Prevent HTML attribute injections
   - Example pattern: `(?i:<script[\s\S]*?>|on\w+\s*=|javascript:)`

2. **Implementation Example**

   ```plaintext
   # XSS pattern detection
   SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES "@rx (?i:<script[\s\S]*?>|on\w+\s*=|javascript:)" \
       "id:10004,\
       phase:2,\
       t:none,t:urlDecodeUni,t:htmlEntityDecode,\
       block,\
       msg:'Cross-Site Scripting Attack',\
       logdata:'%{MATCHED_VAR}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-xss'"
   ```

### Command Injection Protection

1. **Command Pattern Detection**
   - Detect OS command patterns
   - Identify shell metacharacters
   - Block command chaining attempts
   - Prevent command substitution
   - Example pattern: `(?:;|\||&&|\$\(|\$\{|`|\\\\|<\(|>\(|\(\s*\))`

2. **Implementation Example**

   ```plaintext
   # Command injection detection
   SecRule ARGS|ARGS_NAMES "@rx (?:;|\||&&|\$\(|\$\{|`|\\\\|<\(|>\(|\(\s*\))" \
       "id:10005,\
       phase:2,\
       t:none,t:urlDecodeUni,\
       block,\
       msg:'Command Injection Attack',\
       logdata:'%{MATCHED_VAR}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-rce'"
   ```

### File Upload Protection

1. **Malicious File Detection**
   - Restrict allowed file types
   - Enforce filename patterns
   - Validate content-types
   - Check file content signatures
   - Example pattern: `(?i)\.(?:php|jsp|asp|aspx|exe|dll|bat|cmd|sh|ps1|pl)$`

2. **Implementation Example**

   ```plaintext
   # Malicious file upload detection
   SecRule FILES_NAMES "@rx (?i)\.(?:php|jsp|asp|aspx|exe|dll|bat|cmd|sh|ps1|pl)$" \
       "id:10006,\
       phase:2,\
       t:none,t:urlDecodeUni,t:lowercase,\
       block,\
       msg:'Malicious File Upload Attempt',\
       logdata:'%{MATCHED_VAR}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-file-upload'"
   ```

### Rate Limiting Rules

1. **Request Rate Limiting**
   - Limit requests by IP address
   - Implement endpoint-specific limits
   - Establish session-based quotas
   - Create burst tolerance thresholds
   - Use tracking collections

2. **Implementation Example**

   ```plaintext
   # Rate limiting for login endpoint
   SecRule REQUEST_URI "@beginsWith /api/login" \
       "id:10007,\
       phase:1,\
       t:none,\
       pass,\
       nolog,\
       setvar:'ip.login_attempt=+1',\
       expirevar:'ip.login_attempt=60'"

   SecRule IP:LOGIN_ATTEMPT "@gt 5" \
       "id:10008,\
       phase:1,\
       t:none,\
       block,\
       msg:'Excessive Login Attempts',\
       logdata:'%{REMOTE_ADDR} made %{IP.login_attempt} login attempts',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-bruteforce'"
   ```

## Testing and Validation

### Rule Testing Process

1. **Lab Testing**
   - Setup test environment
   - Create attack test cases
   - Develop legitimate traffic samples
   - Implement rule testing framework
   - Document test results

2. **False Positive Testing**
   - Test against legitimate traffic samples
   - Check application functionality
   - Validate form submissions
   - Test API endpoints
   - Document false positives

3. **False Negative Testing**
   - Test rule evasion techniques
   - Validate against obfuscated attacks
   - Test encoding variations
   - Implement boundary testing
   - Document detection gaps

4. **Performance Testing**
   - Measure rule execution time
   - Evaluate traffic throughput impact
   - Test under load conditions
   - Identify optimization opportunities
   - Document performance metrics

### Rule Validation Framework

1. **Test Case Development**
   - Create attack vectors test suite
   - Develop legitimate traffic samples
   - Document expected rule behavior
   - Include edge case scenarios
   - Implement regression tests

2. **Validation System Implementation**

   ```python
   from admin.security.incident_response_kit.recovery import security_controls

   # Validate WAF rule against test cases
   validation_result = security_controls.validate_waf_rule(
       rule_file="/secure/ir/IR-2023-042/custom_waf_rules.json",
       test_suite="/secure/ir/IR-2023-042/tests/xss_test_cases.json",
       fail_on_false_positives=True,
       performance_threshold_ms=5,
       output_report="/secure/ir/IR-2023-042/rule_validation_report.json"
   )

   # Check validation results
   if validation_result.passed:
       print(f"Rule validated successfully - Detection rate: {validation_result.detection_rate}%")
       print(f"False positive rate: {validation_result.false_positive_rate}%")
       print(f"Average performance: {validation_result.avg_performance_ms}ms per request")
   else:
       print(f"Rule validation failed: {validation_result.failure_reason}")
       for issue in validation_result.issues:
           print(f"- {issue.type}: {issue.description}")
   ```

3. **Detection Rate Metrics**
   - Calculate true positive rate
   - Measure false positive rate
   - Document detection accuracy
   - Compare rule versions
   - Track rule effectiveness

4. **Continuous Improvement**
   - Implement feedback loop process
   - Update rules based on validation
   - Refine patterns for accuracy
   - Document rule evolution
   - Maintain version history

## Deployment Strategies

### Graduated Deployment

1. **Monitoring Mode Deployment**
   - Deploy rules in detection-only mode
   - Log matched requests without blocking
   - Analyze detection accuracy
   - Monitor for false positives
   - Document traffic impact

2. **Staged Environment Progression**
   - Deploy to development environment
   - Progress to staging environment
   - Test in pre-production
   - Limited production deployment
   - Full production rollout

3. **Traffic Percentage Deployment**
   - Apply to percentage of traffic
   - Gradually increase coverage
   - Monitor application metrics
   - Control deployment scope
   - Document incremental results

4. **Rule Confidence Levels**
   - Implement confidence scoring
   - Deploy based on confidence
   - Adjust actions based on score
   - Monitor score effectiveness
   - Tune confidence thresholds

### Rules Management

1. **Rule Lifecycle Management**
   - Define rule stages (draft, testing, production, retired)
   - Implement version control
   - Document rule lifecycle
   - Set review schedules
   - Define rule expiration criteria

2. **Rule Set Organization**
   - Group rules by attack type
   - Establish priority hierarchy
   - Implement rule dependencies
   - Define execution order
   - Document rule relationships

3. **Rule Tuning Process**
   - Monitor rule effectiveness
   - Document false positives
   - Implement rule adjustments
   - Validate rule changes
   - Track tuning history

4. **Emergency Rule Management**
   - Define emergency deployment process
   - Implement rapid rollback capability
   - Document emergency procedures
   - Test emergency deployment
   - Maintain emergency templates

### Rule Deployment Example

```python
from admin.security.incident_response_kit.recovery import security_controls

# Deploy WAF rules with graduated approach
deployment_result = security_controls.deploy_waf_rules(
    rule_file="/secure/ir/IR-2023-042/custom_waf_rules.json",
    target_environment="production",
    deployment_strategy="graduated",
    deployment_parameters={
        "initial_mode": "detection_only",
        "monitoring_period": "4h",
        "traffic_percentage": 25,
        "auto_rollback_threshold": 0.5,  # 0.5% false positive rate for auto-rollback
        "progressive_stages": [
            {"duration": "2h", "mode": "detection_only", "traffic_percentage": 25},
            {"duration": "4h", "mode": "detection_only", "traffic_percentage": 50},
            {"duration": "6h", "mode": "detection_only", "traffic_percentage": 100},
            {"duration": "12h", "mode": "block", "traffic_percentage": 25},
            {"duration": "24h", "mode": "block", "traffic_percentage": 50},
            {"duration": "0", "mode": "block", "traffic_percentage": 100}
        ]
    },
    notification_channels=["slack", "email"],
    rollback_on_error=True,
    incident_id="IR-2023-042"
)

# Check deployment status
print(f"Deployment ID: {deployment_result.deployment_id}")
print(f"Deployment status: {deployment_result.status}")
print(f"Current stage: {deployment_result.current_stage}")
print(f"Next stage scheduled for: {deployment_result.next_stage_time}")
```

## Implementation Reference

### Rule Development Scripts

1. **Rule Generation Script**

   ```python
   from admin.security.incident_response_kit.recovery import security_controls
   from admin.security.incident_response_kit.incident_constants import RuleAction, RuleSeverity

   # Generate WAF rule from attack data
   new_rule = security_controls.generate_waf_rule(
       attack_data="/secure/evidence/IR-2023-042/attack_patterns.json",
       rule_template="xss_protection",
       rule_parameters={
           "id": "IR-2023-042-XSS-01",
           "description": "XSS attack pattern from incident IR-2023-042",
           "severity": RuleSeverity.CRITICAL,
           "action": RuleAction.BLOCK,
           "target_parameters": ["ARGS", "ARGS_NAMES", "REQUEST_COOKIES"],
           "transformations": ["URL_DECODE", "HTML_ENTITY_DECODE", "LOWERCASE"],
           "detect_evasion_techniques": True
       },
       output_file="/secure/ir/IR-2023-042/custom_waf_rules.json"
   )

   # Print rule details
   print(f"Generated rule ID: {new_rule.id}")
   print(f"Rule pattern: {new_rule.pattern}")
   print(f"Detection score: {new_rule.detection_score}")
   ```

2. **Rule Testing Script**

   ```python
   from admin.security.incident_response_kit.recovery import security_controls

   # Test WAF rule against captured attack traffic
   test_results = security_controls.test_waf_rule(
       rule_file="/secure/ir/IR-2023-042/custom_waf_rules.json",
       test_traffic="/secure/evidence/IR-2023-042/http_requests.pcap",
       legitimate_traffic="/secure/evidence/baseline_traffic.pcap",
       output_report="/secure/ir/IR-2023-042/rule_test_results.json"
   )

   # Analyze test results
   print(f"Rules tested: {len(test_results.rules_tested)}")
   print(f"Attack requests tested: {test_results.attack_requests}")
   print(f"Legitimate requests tested: {test_results.legitimate_requests}")
   print(f"Attack detection rate: {test_results.detection_rate}%")
   print(f"False positive rate: {test_results.false_positive_rate}%")
   print(f"Performance impact: {test_results.performance_impact_ms}ms per request")
   ```

3. **ModSecurity Rule Conversion**

   ```python
   from admin.security.incident_response_kit.recovery import security_controls

   # Convert JSON rule format to ModSecurity format
   modsec_rules = security_controls.convert_to_modsecurity(
       rule_file="/secure/ir/IR-2023-042/custom_waf_rules.json",
       output_file="/secure/ir/IR-2023-042/modsecurity_rules.conf",
       rule_format="v3",
       include_comments=True,
       include_performance_hints=True
   )

   print(f"Generated {len(modsec_rules.rules)} ModSecurity rules")
   print(f"Rules written to: {modsec_rules.output_file}")
   ```

4. **Rule Health Monitoring**

   ```python
   from admin.security.incident_response_kit.recovery import security_controls
   from datetime import datetime, timedelta

   # Monitor performance and effectiveness of deployed rules
   rule_health = security_controls.monitor_waf_rule_health(
       rule_ids=["IR-2023-042-XSS-01", "IR-2023-042-SQLI-01"],
       timeframe={
           "start": datetime.now() - timedelta(hours=24),
           "end": datetime.now()
       },
       metrics=["block_rate", "false_positive_rate", "performance_impact", "bypass_attempts"],
       alert_thresholds={
           "false_positive_rate": 0.5,  # Alert if false positive rate exceeds 0.5%
           "performance_impact_ms": 10,  # Alert if rule adds more than 10ms latency
           "bypass_attempts": 50         # Alert if more than 50 bypass attempts detected
       },
       output_report="/secure/ir/IR-2023-042/rule_health_report.json"
   )

   # Print health metrics
   for rule_id, metrics in rule_health.rule_metrics.items():
       print(f"Rule: {rule_id}")
       print(f"  Block rate: {metrics['block_rate']}%")
       print(f"  False positive rate: {metrics['false_positive_rate']}%")
       print(f"  Performance impact: {metrics['performance_impact']}ms")
       print(f"  Bypass attempts: {metrics['bypass_attempts']}")
       print(f"  Health score: {metrics['health_score']}/100")
   ```

### Rule Templates

1. **Basic Rule Template**

   ```json
   {
     "rule": {
       "id": "TEMPLATE-001",
       "description": "Basic rule template",
       "tags": ["template", "example"],
       "severity": "medium",
       "variables": ["ARGS", "ARGS_NAMES", "REQUEST_COOKIES"],
       "pattern": "(?i:example_pattern)",
       "transformations": ["URL_DECODE", "LOWERCASE"],
       "action": "block",
       "version": "1.0",
       "logic": "default"
     },
     "metadata": {
       "created_by": "incident_response_team",
       "created_date": "2023-07-15T10:00:00Z",
       "test_coverage": 100,
       "false_positive_rate": 0.0,
       "performance_impact": "low"
     }
   }
   ```

2. **XSS Rule Template**

   ```json
   {
     "rule": {
       "id": "XSS-TEMPLATE-001",
       "description": "Cross-site scripting protection template",
       "tags": ["xss", "injection", "template"],
       "severity": "critical",
       "variables": ["ARGS", "ARGS_NAMES", "REQUEST_COOKIES", "REQUEST_HEADERS"],
       "pattern": "(?i:<script[^>]*>|\\bon\\w+\\s*=|javascript:)",
       "transformations": ["URL_DECODE", "HTML_ENTITY_DECODE", "LOWERCASE"],
       "action": "block",
       "version": "1.0",
       "logic": "default"
     },
     "metadata": {
       "created_by": "security_team",
       "created_date": "2023-06-01T09:00:00Z",
       "test_coverage": 95,
       "false_positive_rate": 0.2,
       "performance_impact": "medium",
       "mitre_attack_id": "T1059.007"
     }
   }
   ```

3. **SQL Injection Rule Template**

   ```json
   {
     "rule": {
       "id": "SQLI-TEMPLATE-001",
       "description": "SQL injection protection template",
       "tags": ["sqli", "injection", "template"],
       "severity": "critical",
       "variables": ["ARGS", "ARGS_NAMES", "REQUEST_COOKIES"],
       "pattern": "(?i:(?:select|union|insert|delete|update|drop)\\b.*?\\bfrom\\b)",
       "transformations": ["URL_DECODE", "LOWERCASE", "REMOVE_COMMENTS"],
       "action": "block",
       "version": "1.0",
       "logic": "default"
     },
     "metadata": {
       "created_by": "security_team",
       "created_date": "2023-06-01T09:30:00Z",
       "test_coverage": 90,
       "false_positive_rate": 0.3,
       "performance_impact": "medium",
       "mitre_attack_id": "T1190"
     }
   }
   ```

### ModSecurity Rule Examples

1. **Basic ModSecurity Rule**

   ```plaintext
   # Basic protection rule
   SecRule ARGS|ARGS_NAMES "@rx (?i:malicious_pattern)" \
       "id:1001,\
       phase:2,\
       t:none,t:urlDecodeUni,t:lowercase,\
       block,\
       msg:'Malicious pattern detected',\
       logdata:'%{MATCHED_VAR}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-generic',\
       tag:'OWASP_CRS',\
       tag:'capec-152'"
   ```

2. **Rule Chain Example**

   ```plaintext
   # First rule in chain
   SecRule REQUEST_URI "@beginsWith /api/sensitive" \
       "id:2001,\
       phase:1,\
       t:none,\
       chain,\
       skip:1,\
       nolog,\
       tag:'application-multi'"

   # Second rule in chain
   SecRule &REQUEST_HEADERS:Authorization "@eq 0" \
       "t:none,\
       block,\
       msg:'Missing Authorization Header',\
       logdata:'%{MATCHED_VAR}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-generic'"
   ```

3. **Custom Response Rule**

   ```plaintext
   # Return custom response for detected attack
   SecRule ARGS|ARGS_NAMES "@rx (?i:attack_pattern)" \
       "id:3001,\
       phase:2,\
       t:none,t:urlDecodeUni,\
       block,\
       msg:'Attack pattern detected',\
       logdata:'%{MATCHED_VAR}',\
       severity:'CRITICAL',\
       tag:'application-multi',\
       tag:'attack-generic',\
       status:403,\
       set:ENV.attackinfo=%{MATCHED_VAR}"

   Header always set X-Attack-Info "%{ENV:attackinfo}" env=attackinfo
   ```

## Available Functions

### Security Controls Module

```python
from admin.security.incident_response_kit.recovery import security_controls
```

#### WAF Rule Management Functions

- **`generate_waf_rule()`** - Generate WAF rule from attack data
  - Parameters:
    - `attack_data`: Path to attack data file or dictionary with attack patterns
    - `rule_template`: Template to use (xss_protection, sqli_protection, etc.)
    - `rule_parameters`: Dictionary of rule parameters
    - `output_file`: Where to save the generated rule
  - Returns: Generated rule object

- **`test_waf_rule()`** - Test WAF rule against traffic samples
  - Parameters:
    - `rule_file`: Path to rule file
    - `test_traffic`: Path to test traffic capture
    - `legitimate_traffic`: Path to legitimate traffic capture
    - `output_report`: Where to save test report
  - Returns: Test results object with metrics

- **`validate_waf_rule()`** - Validate WAF rule against test cases
  - Parameters:
    - `rule_file`: Path to rule file
    - `test_suite`: Path to test suite file
    - `fail_on_false_positives`: Whether to fail if false positives occur
    - `performance_threshold_ms`: Maximum acceptable performance impact
    - `output_report`: Where to save validation report
  - Returns: Validation results object

- **`deploy_waf_rules()`** - Deploy WAF rules to production
  - Parameters:
    - `rule_file`: Path to rule file
    - `target_environment`: Target environment (development, staging, production)
    - `deployment_strategy`: Deployment strategy to use
    - `deployment_parameters`: Dictionary of deployment parameters
    - `notification_channels`: Notification channels for deployment events
    - `rollback_on_error`: Whether to automatically rollback on error
    - `incident_id`: Associated incident ID
  - Returns: Deployment result object

- **`convert_to_modsecurity()`** - Convert rule format to ModSecurity
  - Parameters:
    - `rule_file`: Path to rule file in JSON format
    - `output_file`: Where to save ModSecurity rules
    - `rule_format`: ModSecurity rule format version
    - `include_comments`: Whether to include detailed comments
    - `include_performance_hints`: Whether to include performance hints
  - Returns: Conversion result object

- **`monitor_waf_rule_health()`** - Monitor rule performance and effectiveness
  - Parameters:
    - `rule_ids`: List of rule IDs to monitor
    - `timeframe`: Timeframe for monitoring
    - `metrics`: List of metrics to monitor
    - `alert_thresholds`: Dictionary of alert thresholds
    - `output_report`: Where to save health report
  - Returns: Health metrics object

- **`update_waf_rules()`** - Update WAF rules on target system
  - Parameters:
    - `target`: Target system or application
    - `rules_file`: Path to rules file
    - `test_mode`: Whether to deploy in test mode
    - `incident_id`: Associated incident ID
  - Returns: Update result object

### Rule Constants and Enums

```python
from admin.security.incident_response_kit.incident_constants import (
    RuleAction, RuleSeverity, RuleLogic, RulePhase,
    RuleOperator, RuleFormat, DeploymentStrategy
)
```

- **`RuleAction`** - Actions for WAF rules
  - `PASS`: Allow request to proceed
  - `BLOCK`: Block the request
  - `LOG`: Log the request without blocking
  - `RATE_LIMIT`: Apply rate limiting
  - `CHALLENGE`: Present challenge to client

- **`RuleSeverity`** - Severity levels for WAF rules
  - `INFO`: Informational severity
  - `LOW`: Low severity
  - `MEDIUM`: Medium severity
  - `HIGH`: High severity
  - `CRITICAL`: Critical severity

- **`RuleLogic`** - Logic types for WAF rules
  - `DEFAULT`: Standard single rule logic
  - `CHAIN`: Chain multiple rules together
  - `NOT`: Negated condition
  - `AND`: Multiple conditions (all must match)
  - `OR`: Multiple conditions (any must match)

- **`RulePhase`** - Processing phases for WAF rules
  - `CONNECTION`: Connection handling phase
  - `REQUEST_HEADERS`: Request headers phase
  - `REQUEST_BODY`: Request body phase
  - `RESPONSE_HEADERS`: Response headers phase
  - `RESPONSE_BODY`: Response body phase
  - `LOGGING`: Logging phase

- **`RuleOperator`** - Operators for WAF rule conditions
  - `REGEX`: Regular expression match
  - `EQUALS`: Exact match
  - `CONTAINS`: Contains string
  - `STARTS_WITH`: Starts with string
  - `ENDS_WITH`: Ends with string
  - `GREATER_THAN`: Greater than value
  - `LESS_THAN`: Less than value
  - `WITHIN`: Within range

- **`RuleFormat`** - WAF rule format types
  - `MODSECURITY_V2`: ModSecurity version 2 format
  - `MODSECURITY_V3`: ModSecurity version 3 format
  - `NGINX_MODSECURITY`: NGINX ModSecurity format
  - `AWS_WAF`: AWS WAF format
  - `AZURE_WAF`: Azure WAF format
  - `CLOUDFLARE`: Cloudflare WAF format
  - `JSON`: Generic JSON format

- **`DeploymentStrategy`** - WAF rule deployment strategies
  - `IMMEDIATE`: Deploy immediately to all traffic
  - `DETECTION_ONLY`: Deploy in detection-only mode
  - `GRADUATED`: Gradually deploy with increasing scope
  - `PERCENTAGE`: Deploy to percentage of traffic
  - `STAGED`: Deploy across environments in stages
  - `CANARY`: Deploy to subset of servers first

## Best Practices & Security

- **Defense in Depth**: Do not rely on WAF rules as the only protection; implement multiple security layers
- **False Positive Management**: Start with detection-only mode to identify and correct false positives
- **Rule Specificity**: Create specific rules rather than overly broad patterns
- **Performance Considerations**: Test and optimize rules for performance impact
- **Rules Lifecycle**: Implement proper lifecycle management, including rule retirement
- **Regular Updates**: Review and update rules based on emerging threats
- **Testing Rigor**: Test rules thoroughly against both attack and legitimate traffic
- **Documentation**: Document rule purpose, pattern logic, and modification history
- **Rule Templating**: Use standardized templates for consistency and quality
- **Graduated Deployment**: Implement graduated deployment strategy for critical applications
- **Emergency Response**: Maintain emergency rule templates for rapid response
- **Data Protection**: Be careful not to log sensitive data in rule documentation or logs
- **Rule Change Control**: Implement formal change control process for production rules
- **Monitoring and Analytics**: Monitor rule effectiveness and performance
- **Correlation**: Correlate WAF events with other security monitoring data

## Related Documentation

- Web Application Attack Response Playbook - Response procedures for web application attacks
- Traffic Analysis Guide - Guide for analyzing network traffic patterns
- DDoS Defense Architecture - Reference for DDoS protection
- Evidence Collection Guide - Procedures for collecting evidence
- Web Application Hardening Guide - Web application security hardening
- [OWASP ModSecurity Core Rule Set Documentation](https://coreruleset.org/documentation/) - Reference for ModSecurity CRS
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Web application security testing
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual) - Official ModSecurity documentation
- [NIST SP 800-95: Guide to Secure Web Services](https://csrc.nist.gov/publications/detail/sp/800-95/final) - NIST guidance on web service security
- WAF Rule Testing Framework - Core security monitoring framework
