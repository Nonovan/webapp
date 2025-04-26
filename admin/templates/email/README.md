# Email Templates

This directory contains standardized email templates used throughout the Cloud Infrastructure Platform for administrative communications. These templates ensure consistent formatting, appropriate content, and proper handling of sensitive information in all administrative email communications.

## Contents

- Overview
- Key Templates
- Directory Structure
- Usage
- Template Variables
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The email templates provide standardized formats for administrative communications sent by the platform to users, administrators, and stakeholders. These templates ensure consistency in branding, formatting, and messaging while following best practices for email communications. They support notifications for account status changes, configuration modifications, maintenance events, security alerts, and system status updates.

## Key Templates

- **`account_status.html`**: Account status notification template
  - Account activation notifications
  - Account deactivation notices
  - Account suspension warnings
  - Password expiration reminders
  - Lockout notifications
  - Recovery procedure instructions

- **`config_change.html`**: Configuration change notification template
  - System configuration changes
  - Environment modification details
  - Policy updates
  - Service configuration modifications
  - Infrastructure changes
  - Configuration deployment confirmations

- **`maintenance.html`**: Maintenance announcement template
  - Planned maintenance notifications
  - Downtime announcements
  - Service interruption details
  - Maintenance completion notifications
  - Extended maintenance updates
  - Emergency maintenance alerts

- **`security_alert.html`**: Security alert notification template
  - Security incident notifications
  - Vulnerability disclosure messages
  - Security patch announcements
  - Suspicious activity alerts
  - Account compromise notifications
  - Security policy violation notices

- **`status_update.html`**: System status update template
  - Service status notifications
  - Incident progress updates
  - Resolution confirmations
  - Performance impact communications
  - Service degradation notices
  - Recovery status updates

- **`user_onboarding.html`**: User onboarding template
  - Welcome messages
  - Initial login instructions
  - Getting started guidance
  - Resource access information
  - Training resource links
  - Support contact information

## Directory Structure

```plaintext
admin/templates/email/
├── README.md           # This documentation
├── account_status.html # Account status notification template
├── config_change.html  # Configuration change notification template
├── maintenance.html    # Maintenance announcement template
├── security_alert.html # Security alert notification template
├── status_update.html  # System status update template
└── user_onboarding.html # User onboarding template
```

## Usage

The email templates are designed to be used with the platform's notification system:

```python
from jinja2 import Environment, FileSystemLoader
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_maintenance_notification(users, maintenance_info):
    """Send maintenance notification emails to affected users."""
    # Load the email template
    template_dir = os.path.join(os.path.dirname(__file__), 'admin/templates/email')
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template('maintenance.html')

    # Prepare email content with proper variables
    for user in users:
        # Render the template with user-specific and maintenance info
        html_content = template.render(
            user_name=user.full_name,
            maintenance_start=maintenance_info['start_time'],
            maintenance_end=maintenance_info['end_time'],
            affected_services=maintenance_info['services'],
            maintenance_reason=maintenance_info['reason'],
            alternative_access=maintenance_info.get('alternative_access'),
            contact_email=maintenance_info['contact_email'],
            environment_name=maintenance_info['environment']
        )

        # Create email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Scheduled Maintenance: {maintenance_info['environment']} - {maintenance_info['start_time']}"
        msg['From'] = "administrator@example.com"
        msg['To'] = user.email

        # Attach HTML content
        msg.attach(MIMEText(html_content, 'html'))

        # Send email (implementation depends on email sending service)
        send_email(msg)
```

## Template Variables

### Common Variables

- `{{application_name}}` - Platform/application name
- `{{contact_email}}` - Contact email for questions/issues
- `{{current_date}}` - Current date in appropriate format
- `{{environment}}` - Environment name (production, staging, development)
- `{{logo_url}}` - URL to the company/application logo
- `{{site_url}}` - Base URL for the application
- `{{support_url}}` - URL for the support portal
- `{{user_name}}` - Recipient's name

### Account Status Variables

- `{{account_expiry_date}}` - Account expiration date
- `{{account_status}}` - Current account status
- `{{last_login}}` - Last login date and time
- `{{lockout_reason}}` - Reason for account lockout
- `{{password_expiry_date}}` - Password expiration date
- `{{recovery_link}}` - Account recovery link

### Configuration Change Variables

- `{{approver}}` - Person who approved the change
- `{{change_description}}` - Description of the configuration change
- `{{change_id}}` - Change identifier
- `{{change_impact}}` - Impact level of the change
- `{{implementation_date}}` - When the change was implemented
- `{{modified_components}}` - List of modified components

### Maintenance Variables

- `{{affected_services}}` - Services affected by maintenance
- `{{alternative_access}}` - Alternative access methods during maintenance
- `{{downtime_expected}}` - Expected downtime duration
- `{{maintenance_end}}` - Maintenance end time
- `{{maintenance_reason}}` - Reason for maintenance
- `{{maintenance_start}}` - Maintenance start time

### Security Alert Variables

- `{{alert_severity}}` - Severity level of the security alert
- `{{detection_time}}` - When the security issue was detected
- `{{incident_details}}` - Details about the security incident
- `{{recommended_actions}}` - Recommended user actions
- `{{reference_id}}` - Security incident reference ID
- `{{security_contact}}` - Security team contact information

### Status Update Variables

- `{{affected_functionality}}` - Functionality affected by the incident
- `{{current_status}}` - Current system status
- `{{incident_description}}` - Description of the incident
- `{{incident_id}}` - Incident identifier
- `{{resolution_time}}` - Expected or actual resolution time
- `{{workarounds}}` - Available workarounds

## Customization Guidelines

When customizing email templates:

1. **Maintain Required Elements**
   - Keep the responsive email framework
   - Preserve header and footer sections
   - Maintain legal disclaimers and compliance information
   - Keep unsubscribe mechanisms for non-critical emails

2. **Follow Email Best Practices**
   - Use responsive design for mobile compatibility
   - Maintain appropriate text-to-image ratio
   - Keep critical information in text (not only in images)
   - Follow accessibility guidelines
   - Test with major email clients

3. **Maintain Brand Consistency**
   - Use approved colors and fonts
   - Include appropriate logos
   - Follow tone and voice guidelines
   - Apply consistent button styling
   - Use approved header/footer designs

4. **Test Before Deployment**
   - Verify HTML rendering in multiple email clients
   - Test responsiveness on mobile devices
   - Check for broken links and images
   - Validate variable substitution
   - Review for spelling and grammar issues

## Best Practices & Security

- **Accessibility**: Ensure templates meet WCAG 2.1 standards
- **Antiforensics Considerations**: Include anti-phishing guidance where appropriate
- **Authentication Links**: Set appropriate expiration times for authentication links
- **Client Compatibility**: Test templates with major email clients
- **Content Filtering**: Design to avoid common spam filters
- **Dark Mode Support**: Include styling for dark mode email clients
- **Link Security**: Use HTTPS for all links
- **Mobile Compatibility**: Ensure responsive design for mobile devices
- **Personalization**: Use appropriate level of personalization (name, role, etc.)
- **Phishing Protection**: Include guidance to identify legitimate emails
- **Privacy**: Follow data minimization principles in email content
- **Sensitivity Classification**: Include appropriate classification markings
- **Tracking Limitations**: Respect user privacy with email tracking
- **Transactional Clarity**: Clearly indicate which emails require action
- **Unsubscribe Options**: Include unsubscribe options for non-critical communications

## Common Features

All email templates include these common elements:

- **Brand Header**: Consistent platform branding and logo
- **Clear Subject Lines**: Standardized, descriptive subject line formats
- **Contact Information**: How to reach support or responsible teams
- **Footer Information**: Legal information, disclaimers, and privacy policy
- **HTML/Plain Text**: Both HTML and plain text versions of all emails
- **Mobile Responsiveness**: Responsive design for various screen sizes
- **Privacy Statement**: Link to the privacy policy
- **Responsive Layout**: Adaptable to different screen sizes
- **Security Indicators**: Anti-phishing indicators for official communications
- **Signature Block**: Standardized signature format
- **Timestamp**: When the email was generated
- **Unsubscribe Link**: Option to manage notification preferences (where applicable)

## Related Documentation

- Brand Guidelines
- Communication Standards
- Email Best Practices
- Email Notification System
- Notification Service API
- Security Communications Guide
- Template Development Guide
- User Notification Policies
