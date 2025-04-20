# Configuration file for the Sphinx documentation builder.
#
# This file contains configurations for Sphinx, which is used
# to generate the project documentation.
#
# For a full list of options see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys
from datetime import datetime

# -- Path setup --------------------------------------------------------------
# Add the project root directory to the Python path so Sphinx can find modules
sys.path.insert(0, os.path.abspath('..'))

# -- Project information -----------------------------------------------------
project = 'Cloud Infrastructure Platform'
copyright = f'{datetime.now().year}, Cloud Infrastructure Platform Team'
author = 'Cloud Infrastructure Platform Team'

# The full version, including alpha/beta/rc tags
release = '1.0.0'
version = '1.0'

# -- General configuration ---------------------------------------------------
# Add any Sphinx extension modules
extensions = [
    'sphinx.ext.autodoc',        # Include documentation from docstrings
    'sphinx.ext.viewcode',       # Add links to highlighted source code
    'sphinx.ext.napoleon',       # Support for NumPy and Google style docstrings
    'sphinx.ext.intersphinx',    # Link to other project's documentation
    'sphinx.ext.coverage',       # Checks for documentation coverage
    'sphinx.ext.autosummary',    # Generate autodoc summaries
    'sphinx.ext.githubpages',    # Generate .nojekyll file for GitHub Pages
    'sphinx.ext.todo',           # Support for todo items
    'myst_parser',               # Support for Markdown
    'sphinx_rtd_theme',          # Read the Docs theme
    'sphinx.ext.graphviz',       # Support for Graphviz diagrams
    'sphinx_autodoc_typehints',  # Support for typehints in documentation
]

# Add any paths that contain templates
templates_path = ['_templates']

# List of patterns to exclude from source files
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', 'venv', 'env', '.env', '.venv']

# The suffix(es) of source filenames
source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}

# The master toctree document
master_doc = 'index'

# -- Options for HTML output -------------------------------------------------
# The theme to use for HTML and HTML Help pages
html_theme = 'sphinx_rtd_theme'

# Theme options
html_theme_options = {
    'logo_only': False,
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': True,
    'navigation_depth': 4,
    'collapse_navigation': False,
    'sticky_navigation': True,
}

# Add any paths that contain custom static files
html_static_path = ['_static']

# Custom CSS files
html_css_files = [
    'css/custom.css',
]

# HTML title
html_title = f"Cloud Infrastructure Platform Documentation {version}"

# HTML logo
html_logo = "_static/logo.png"

# HTML favicon
html_favicon = "_static/favicon.ico"

# -- Options for autodoc extension -------------------------------------------
# Show both class docstring and __init__ docstring
autoclass_content = 'both'

# Order members by type
autodoc_member_order = 'groupwise'

# Default flags for autodoc directives
autodoc_default_options = {
    'members': True,
    'undoc-members': True,
    'show-inheritance': True,
    'private-members': False,
}

# -- Options for intersphinx extension ---------------------------------------
# Example configuration for intersphinx: refer to other projects
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'flask': ('https://flask.palletsprojects.com/en/2.3.x/', None),
    'sqlalchemy': ('https://docs.sqlalchemy.org/en/20/', None),
}

# -- Options for napoleon extension ------------------------------------------
# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_keyword = True
napoleon_custom_sections = None

# -- Options for myst_parser extension ---------------------------------------
# MyST parser settings
myst_enable_extensions = [
    'colon_fence',
    'deflist',
    'fieldlist',
    'substitution',
    'tasklist',
    'dollarmath',
    'amsmath',
]
myst_heading_anchors = 3

# -- Options for todo extension ----------------------------------------------
# If true, `todo` and `todoList` produce output
todo_include_todos = True

# -- Options for coverage extension ------------------------------------------
# Coverage settings
coverage_show_missing_items = True

# -- Options for graphviz extension ------------------------------------------
# Graphviz settings
graphviz_output_format = 'svg'

# Configure linkcheck builder
linkcheck_ignore = [
    r'http://localhost:\d+/',
    r'https://community\.cloud-platform\.example\.com',
    r'https://api\.cloud-platform\.example\.com',
]
linkcheck_timeout = 15
linkcheck_retries = 3
linkcheck_workers = 10

# Set up the API documentation
add_module_names = False

# Define the path to API modules for documentation
api_modules = [
    'api.auth',
    'api.cloud',
    'api.alerts',
    'api.webhooks',
    'api.newsletter',
    'core',
    'models',
]

# Generate man pages
man_pages = [
    ('index', 'cloud-infrastructure-platform', 'Cloud Infrastructure Platform Documentation',
     [author], 1)
]

# Configure epub output
epub_title = project
epub_author = author
epub_publisher = author
epub_copyright = copyright
epub_exclude_files = ['search.html']

# -- App setup hook ----------------------------------------------------------
def setup(app):
    """Set up Sphinx app with custom configurations."""
    # Add custom stylesheet
    app.add_css_file('css/custom.css')
    
    # Add custom JavaScript
    app.add_js_file('js/custom.js')
    
    # Add special configuration for production builds
    app.connect('builder-inited', on_builder_init)

def on_builder_init(app):
    """Run when the builder is initialized."""
    # Custom setup steps based on the builder
    if app.builder.name == 'html':
        # Add any HTML-specific setup
        pass
    elif app.builder.name == 'latex':
        # Add any LaTeX-specific setup
        pass
