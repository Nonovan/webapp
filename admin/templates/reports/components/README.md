# Report Templates Components

This directory contains reusable components used to build standardized reports across the Cloud Infrastructure Platform. These components ensure consistent formatting, styling, and functionality for charts, findings, headers, footers, and risk visualizations.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage
- Customization Guidelines
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The report components directory contains modular HTML, CSS, and JavaScript elements that are included in various report templates. These components provide standardized formatting and functionality for common report elements such as charts, data visualizations, finding cards, headers, footers, and risk rating visualizations. By using these shared components, the platform maintains consistent presentation and behavior across different report types while simplifying maintenance and updates.

## Key Components

- **`chart_templates.html`**: Reusable data visualization components
  - Bar chart templates with consistent styling
  - Line chart components for trend data
  - Pie chart templates for distribution visualization
  - Radar chart templates for multi-metric comparison
  - Stacked area charts for time series data
  - Tooltip and interaction standardization

- **`finding_card.html`**: Finding presentation component
  - Expandable/collapsible finding details
  - Severity indicator formatting
  - Evidence presentation structure
  - Remediation suggestion formatting
  - CVSS score visualization
  - Validation status indicators

- **`header_footer.html`**: Standard header and footer
  - Classification banner formatting
  - Logo and branding placement
  - Report metadata presentation
  - Page numbering system
  - Document control information
  - Legal disclaimer formatting

- **`risk_rating.html`**: Risk rating visualization
  - Risk heatmap component
  - Severity color coding system
  - Risk trend indicators
  - Likelihood vs. impact matrix
  - Risk score calculation display
  - Comparative risk visualization

## Directory Structure

```plaintext
admin/templates/reports/components/
├── README.md                # This documentation
├── chart_templates.html     # Data visualization components
├── finding_card.html        # Finding presentation component
├── header_footer.html       # Standard header and footer
├── risk_rating.html         # Risk rating visualization
├── css/                     # Component-specific styling
│   ├── charts.css           # Chart styling
│   ├── findings.css         # Finding card styling
│   ├── layout.css           # Header and footer styling
│   └── risk.css             # Risk visualization styling
└── js/                      # Component JavaScript functionality
    ├── chart_behavior.js    # Chart interactivity
    ├── finding_behavior.js  # Finding card behaviors
    ├── print_helpers.js     # Print-specific functionality
    └── risk_calculator.js   # Risk calculation utilities
```

## Usage

The components are designed to be included in report templates using HTML includes or template engine mechanisms:

```html
<!-- Including chart templates in a report -->
<div class="report-metrics-section">
  <h2>Security Metrics Overview</h2>
  <div class="chart-container">
    <!-- Include the bar chart template -->
    {% include "admin/templates/reports/components/chart_templates.html" %}

    <!-- Configure the chart with specific data -->
    <script>
      renderBarChart({
        elementId: 'metrics-chart',
        data: securityMetricsData,
        labels: timeframeLabels,
        title: 'Security Findings by Month',
        color: '#3c78d8'
      });
    </script>
  </div>
</div>

<!-- Including a finding card for each finding -->
<div class="findings-section">
  <h2>Security Findings</h2>
  {% for finding in findings %}
    <div class="finding-wrapper">
      {% include "admin/templates/reports/components/finding_card.html" %}
    </div>
  {% endfor %}
</div>
```

For report generation scripts:

```python
def generate_assessment_report(assessment_data):
    """Generate an assessment report using standardized components."""
    # Set up the template environment
    template_env = Environment(loader=FileSystemLoader('admin/templates'))

    # Load the base report template
    base_template = template_env.get_template('reports/assessment_report.html')

    # Prepare context with necessary data
    context = {
        'title': assessment_data['title'],
        'date': assessment_data['date'],
        'findings': assessment_data['findings'],
        'metrics': assessment_data['metrics'],
        'risk_ratings': calculate_risk_ratings(assessment_data['findings']),
        'component_path': 'admin/templates/reports/components/'
    }

    # Render the template with components
    return base_template.render(context)
```

## Customization Guidelines

When customizing report components:

1. **Maintain Consistent Styling**
   - Follow the established color palette
   - Preserve accessibility features
   - Maintain responsive design elements
   - Use standardized fonts and sizes
   - Adhere to spacing and layout conventions

2. **Preserve Component Interfaces**
   - Maintain consistent data structures
   - Keep required attributes and elements
   - Preserve class and ID naming conventions
   - Ensure backward compatibility
   - Document any interface changes

3. **Follow JavaScript Patterns**
   - Use standardized error handling
   - Maintain event delegation patterns
   - Follow established initialization patterns
   - Preserve namespace conventions
   - Keep dependencies consistent

4. **Test Thoroughly**
   - Verify in multiple browsers
   - Test with different data scenarios
   - Check print layouts
   - Validate accessibility compliance
   - Test responsiveness on different devices

## Best Practices & Security

- **Accessibility**: Ensure all components meet WCAG 2.1 AA standards
- **Browser Compatibility**: Test components in all supported browsers
- **Content Sanitization**: Sanitize all dynamic content for XSS prevention
- **Data Handling**: Never embed sensitive data in component templates
- **Dependency Management**: Minimize external library dependencies
- **Error Handling**: Implement graceful fallbacks when components fail
- **Internationalization**: Support proper text direction and translations
- **Performance**: Optimize component rendering and interaction
- **Print Considerations**: Ensure all components print properly
- **Security Classification**: Properly display document classification markings
- **Separation of Concerns**: Keep styling separate from content and behavior

## Common Features

All report components include these common features:

- **Accessibility Support**: ARIA attributes and keyboard navigation
- **Branding Consistency**: Adherence to organizational style guide
- **Classification Handling**: Support for security classification markings
- **Dark Mode Support**: Automatic adaptation to system dark mode
- **Error States**: Consistent handling of missing or invalid data
- **Localization Support**: Text externalization for translation
- **Namespacing**: Consistent JavaScript namespace usage
- **Print Optimization**: Special styles for printed output
- **Responsive Design**: Adaptation to different screen sizes
- **Theme Compatibility**: Support for organization theme variations

## Related Documentation

- Assessment Report Templates
- Audit Report Templates
- Compliance Report Templates
- Executive Summary Templates
- Incident Report Templates
- Metrics Report Templates
- Report Generation API
- Report Style Guide
- Security Classification Guidelines
- Template Development Guide
