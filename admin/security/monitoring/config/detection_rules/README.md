# Detection Rules for Security Monitoring

This directory contains YAML-defined detection rules used by the security monitoring tools to identify potential security threats, attacks, and suspicious activities across the Cloud Infrastructure Platform.

## Contents

- Overview
- Key Components
- Directory Structure
- Rule Structure
- Usage
- Rule Development
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The detection rules define patterns, thresholds, and conditions that indicate potential security threats. These rules are consumed by the security monitoring tools (particularly `security_event_correlator.py` and `anomaly_detector.sh`) to analyze logs, metrics, and events for signs of malicious activity. The rules are organized by attack type to facilitate maintenance and are designed to minimize false positives while effectively detecting security threats.

## Key Components

- **Command Injection Rules**: Patterns detecting OS command injection attempts
  - Shell command injection signatures
  - Parameter manipulation patterns
  - Command chaining detection
  - Special character sequence identification
  - Suspicious command execution contexts

- **Data Exfiltration Rules**: Patterns indicating potential data theft
  - Unusual data transfer volume detection
  - Suspicious file access patterns
  - Abnormal API data retrieval
  - Database query volume anomalies
  - Sensitive data access monitoring

- **Lateral Movement Rules**: Detection of attacker movement between systems
  - Unusual cross-system authentication
  - Credential use across multiple systems
  - Network connection pattern analysis
  - Service account misuse detection
  - Administrative tool usage on multiple systems

- **Persistence Rules**: Detection of unauthorized persistence mechanisms
  - Startup modification detection
  - Scheduled task/cron job creation
  - Account manipulation
  - Configuration changes for auto-execution
  - Plugin/extension installation monitoring

- **Privilege Escalation Rules**: Detection of unauthorized privilege gain
  - Unexpected permission changes
  - Privilege elevation without approval
  - Exploitation of known vulnerabilities
  - Suspicious credential usage patterns
  - Access control bypass attempts

- **Suspicious Authentication Rules**: Unusual authentication patterns
  - Brute force attempt detection
  - Authentication from unusual locations
  - Off-hours authentication monitoring
  - Failed authentication spike detection
  - Session anomaly monitoring

## Directory Structure

```plaintext
admin/security/monitoring/config/detection_rules/
├── README.md                # This documentation
├── command_injection.yml    # Command injection detection rules
├── data_exfiltration.yml    # Data theft detection patterns
├── lateral_movement.yml     # Lateral movement detection rules
├── persistence.yml          # Persistence technique detection rules
├── privilege_esc.yml        # Privilege escalation detection rules
└── suspicious_auth.yml      # Suspicious authentication patterns
```

## Rule Structure

Each detection rule follows a consistent structure:

```yaml
rules:
  - id: RULE-ID-001
    name: "Human-readable rule name"
    description: "Detailed description of the suspicious activity"
    severity: high  # Options: critical, high, medium, low
    condition:
      event_type: "specific_event_type"  # Type of event to match
      properties:                         # Event properties to match
        property_name: "property_value"
        array_property:
          - "value1"
          - "value2"
      threshold:                          # Numerical thresholds
        count: 5
        timeframe: 300  # seconds
      not:                                # Exclusion conditions
        property_name: "excluded_value"
    tags:                                 # Categorization tags
      - "MITRE_TECHNIQUE_ID"
      - "category"
      - "subcategory"
    actions:                              # Actions to take on match
      - alert: "security_team"
      - log: "security_audit"
      - notify: "security_admin"
      - trigger_automation: "isolation_playbook"
    reference: "https://attack.mitre.org/techniques/TECHNIQUE_ID/"
    false_positives:                      # Known false positive scenarios
      - "Legitimate administrative activity"
      - "Specific application behavior"
    confidence: high  # Options: high, medium, low
```

## Usage

The detection rules are loaded by the security monitoring tools:

```python
import yaml
import os

def load_detection_rules(rule_category=None):
    """
    Load detection rules from YAML files.

    Args:
        rule_category (str, optional): Specific category to load (filename without .yml extension)

    Returns:
        dict: Loaded detection rules
    """
    rules_dir = os.path.dirname(os.path.abspath(__file__))
    loaded_rules = {}

    if rule_category:
        # Load specific rule category
        rule_file = os.path.join(rules_dir, f"{rule_category}.yml")
        if os.path.exists(rule_file):
            with open(rule_file, "r") as f:
                loaded_rules[rule_category] = yaml.safe_load(f)
    else:
        # Load all rule categories
        for filename in os.listdir(rules_dir):
            if filename.endswith(".yml") and not filename.startswith("_"):
                category = filename[:-4]  # Remove .yml extension
                rule_file = os.path.join(rules_dir, filename)
                with open(rule_file, "r") as f:
                    loaded_rules[category] = yaml.safe_load(f)

    return loaded_rules
```

The rules are applied to incoming events:

```python
def match_rules(event, rules):
    """
    Match an event against loaded detection rules.

    Args:
        event (dict): Event to evaluate
        rules (dict): Detection rules to match against

    Returns:
        list: List of matching rule IDs
    """
    matches = []

    for category, rule_set in rules.items():
        for rule in rule_set.get('rules', []):
            if evaluate_rule_condition(event, rule.get('condition', {})):
                matches.append({
                    'rule_id': rule.get('id'),
                    'name': rule.get('name'),
                    'severity': rule.get('severity', 'medium'),
                    'actions': rule.get('actions', [])
                })

    return matches
```

## Rule Development

When developing new detection rules:

1. **Research the Attack Pattern**
   - Understand the attack technique thoroughly
   - Identify key indicators and patterns
   - Reference MITRE ATT&CK framework when applicable
   - Consider multiple variations of the attack

2. **Define Clear Conditions**
   - Use specific event types and properties
   - Set appropriate thresholds based on environment baselines
   - Include context to reduce false positives
   - Consider legitimate activities that may trigger the rule

3. **Test Extensively**
   - Validate against both attack scenarios and normal activity
   - Tune thresholds to balance detection and false positives
   - Test across different environments (dev, staging, production)
   - Document any known false positive scenarios

4. **Document Properly**
   - Provide clear descriptions
   - Include reference links to attack techniques
   - Document false positive scenarios
   - Assign appropriate severity levels

## Best Practices & Security

- **Regular Updates**: Review and update detection rules quarterly or as needed
- **Environment-Specific Tuning**: Adjust thresholds based on environment characteristics
- **Version Control**: Track all rule changes in version control
- **Testing**: Test new rules thoroughly before deployment
- **Documentation**: Document the purpose and expected behavior of each rule
- **False Positive Management**: Document known false positive scenarios
- **MITRE Mapping**: Map rules to MITRE ATT&CK techniques when applicable
- **Response Actions**: Define appropriate response actions for each rule
- **Continuous Improvement**: Refine rules based on detection effectiveness
- **Confidence Levels**: Assign confidence levels to help prioritize alerts

## Common Features

Detection rules across categories share these common features:

- **Severity Classification**: Rules include severity ratings (critical, high, medium, low)
- **MITRE ATT&CK Mapping**: Rules reference relevant MITRE techniques
- **Customizable Thresholds**: Numerical thresholds can be adjusted per environment
- **Context Awareness**: Rules consider contextual information to reduce false positives
- **Response Actions**: Each rule specifies recommended response actions
- **False Positive Documentation**: Known false positive scenarios are documented
- **Confidence Levels**: Rules include confidence ratings to aid in prioritization
- **Reference Links**: External references for additional information
- **Descriptive Naming**: Clear, consistent naming conventions
- **Tagging System**: Tags for categorization and filtering

## Related Documentation

- Security Monitoring Overview
- Threat Intelligence Framework
- Security Event Correlation
- Anomaly Detection Configuration
- Security Monitoring Strategy
- Incident Response Procedures
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
