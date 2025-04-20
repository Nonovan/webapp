/**
 * custom.js - Custom JavaScript for Cloud Infrastructure Platform Documentation
 * 
 * This file contains custom JavaScript functionality to enhance the 
 * documentation reading experience and provide interactive features.
 */

(function() {
  'use strict';

  // Execute when the DOM is fully loaded
  document.addEventListener('DOMContentLoaded', function() {
    setupDarkMode();
    addCopyButtons();
    enhanceCodeBlocks();
    setupVersionSelector();
    setupSearchHighlighting();
    setupExternalLinks();
    setupMobileNavigation();
    initializeExpandableContent();
    setupScrollSpy();
    monitorPageVisibility();
    addAccessibilityFeatures();
  });

  /**
   * Setup dark/light mode toggle
   */
  function setupDarkMode() {
    const darkModeToggle = document.createElement('button');
    darkModeToggle.className = 'theme-toggle';
    darkModeToggle.setAttribute('aria-label', 'Toggle dark/light mode');
    darkModeToggle.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>';
    
    // Insert button in the top navigation area
    const navbar = document.querySelector('.wy-nav-top');
    if (navbar) {
      navbar.appendChild(darkModeToggle);
    }
    
    // Also add the button to the sidebar
    const sidebar = document.querySelector('.wy-side-nav-search');
    if (sidebar) {
      const sidebarButton = darkModeToggle.cloneNode(true);
      sidebar.appendChild(sidebarButton);
      
      sidebarButton.addEventListener('click', toggleDarkMode);
    }
    
    darkModeToggle.addEventListener('click', toggleDarkMode);
    
    // Check for saved user preference
    function toggleDarkMode() {
      try {
        const currentTheme = localStorage.getItem('theme') || 'light';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        // Update icon visually
        const themeToggles = document.querySelectorAll('.theme-toggle');
        themeToggles.forEach(toggle => {
          toggle.classList.toggle('dark-mode');
        });
      } catch (e) {
        console.warn('Unable to save theme preference:', e);
      }
    }
    
    // Initialize theme based on saved preference or system default
    initializeTheme();
  }
  
  /**
   * Initialize theme based on saved preference or system default
   */
  function initializeTheme() {
    try {
      const savedTheme = localStorage.getItem('theme');
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const defaultTheme = savedTheme || (prefersDark ? 'dark' : 'light');
      
      document.documentElement.setAttribute('data-theme', defaultTheme);
      
      if (defaultTheme === 'dark') {
        const themeToggles = document.querySelectorAll('.theme-toggle');
        themeToggles.forEach(toggle => {
          toggle.classList.add('dark-mode');
        });
      }
    } catch (e) {
      console.warn('Unable to retrieve theme preference:', e);
    }
  }

  /**
   * Add copy buttons to code blocks
   */
  function addCopyButtons() {
    // Get all the code blocks
    const codeBlocks = document.querySelectorAll('div[class^="highlight-"]');
    
    codeBlocks.forEach(function(codeBlock) {
      // Create the copy button
      const button = document.createElement('button');
      button.className = 'copybutton';
      button.textContent = 'Copy';
      button.setAttribute('aria-label', 'Copy code to clipboard');
      
      // Add the button to the code block
      codeBlock.appendChild(button);
      
      // Add event listener
      button.addEventListener('click', function() {
        const code = codeBlock.querySelector('pre').textContent;
        
        navigator.clipboard.writeText(code).then(function() {
          // Visual feedback
          button.textContent = 'Copied!';
          button.classList.add('copied');
          
          // Reset after a short delay
          setTimeout(function() {
            button.textContent = 'Copy';
            button.classList.remove('copied');
          }, 2000);
        }).catch(function(error) {
          console.error('Could not copy code: ', error);
          button.textContent = 'Error';
          
          setTimeout(function() {
            button.textContent = 'Copy';
          }, 2000);
        });
      });
    });
  }

  /**
   * Enhance code blocks with line numbers and highlighting
   */
  function enhanceCodeBlocks() {
    const codeBlocks = document.querySelectorAll('div[class^="highlight-"] pre');
    
    codeBlocks.forEach(function(block, index) {
      // Add unique ID to each code block
      const blockId = 'code-block-' + index;
      block.id = blockId;
      
      // Add line numbers
      const lines = block.textContent.trim().split('\n');
      const lineNumbersDiv = document.createElement('div');
      lineNumbersDiv.className = 'line-numbers';
      
      for (let i = 1; i <= lines.length; i++) {
        const lineNumber = document.createElement('span');
        lineNumber.className = 'line-number';
        lineNumber.textContent = i;
        lineNumbersDiv.appendChild(lineNumber);
      }
      
      // Insert line numbers before the code block
      block.parentNode.insertBefore(lineNumbersDiv, block);
      
      // Add data-line-count attribute for CSS styling
      block.setAttribute('data-line-count', lines.length);
    });
  }

  /**
   * Setup version selector dropdown
   */
  function setupVersionSelector() {
    const versionContainer = document.querySelector('.rst-versions .rst-current-version');
    if (!versionContainer) return;
    
    // Create a full dropdown for versions
    const dropdown = document.createElement('div');
    dropdown.className = 'version-dropdown';
    dropdown.innerHTML = `
      <span class="version-dropdown-title">Version:</span>
      <select id="version-selector" aria-label="Select documentation version">
        <option value="latest" selected>latest (1.0.0)</option>
        <option value="stable">stable (0.9.0)</option>
        <option value="0.8.0">0.8.0</option>
        <option value="0.7.0">0.7.0</option>
      </select>
    `;
    
    versionContainer.appendChild(dropdown);
    
    // Handle version change
    document.getElementById('version-selector').addEventListener('change', function(e) {
      const version = e.target.value;
      // Redirect to the selected version
      if (version) {
        const currentPath = window.location.pathname;
        const basePath = currentPath.substring(0, currentPath.indexOf('/', 1));
        window.location.href = basePath + '/' + version + '/index.html';
      }
    });
  }

  /**
   * Highlight search terms in URL
   */
  function setupSearchHighlighting() {
    const params = new URLSearchParams(window.location.search);
    const highlight = params.get('highlight');
    
    if (highlight) {
      const terms = highlight.split(/\s+/);
      const contentElements = document.querySelectorAll('.document p, .document li, .document h1, .document h2, .document h3, .document h4, .document h5, .document h6, .document th, .document td');
      
      terms.forEach(function(term) {
        if (term.length < 3) return; // Skip short terms
        
        contentElements.forEach(function(el) {
          const regex = new RegExp('(' + term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
          if (el.innerHTML.match(regex)) {
            el.innerHTML = el.innerHTML.replace(regex, '<span class="highlighted">$1</span>');
          }
        });
      });
      
      // Scroll to the first highlighted element
      const firstHighlight = document.querySelector('.highlighted');
      if (firstHighlight) {
        setTimeout(function() {
          firstHighlight.scrollIntoView({behavior: 'smooth', block: 'center'});
        }, 500);
      }
    }
  }

  /**
   * Setup external links to open in new tabs
   */
  function setupExternalLinks() {
    const links = document.querySelectorAll('a[href^="http"]');
    
    links.forEach(function(link) {
      // Exclude links to the current domain
      if (!link.href.startsWith(window.location.origin)) {
        link.setAttribute('target', '_blank');
        link.setAttribute('rel', 'noopener noreferrer');
        
        // Add visual indicator for external links
        if (!link.querySelector('.external-link-icon')) {
          const externalIcon = document.createElement('span');
          externalIcon.className = 'external-link-icon';
          externalIcon.innerHTML = ' <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>';
          link.appendChild(externalIcon);
        }
      }
    });
  }

  /**
   * Improve mobile navigation experience
   */
  function setupMobileNavigation() {
    // Only run on mobile
    if (window.innerWidth > 768) return;
    
    // Add a button to show/hide the navigation
    const navToggle = document.createElement('button');
    navToggle.className = 'mobile-nav-toggle';
    navToggle.setAttribute('aria-label', 'Toggle navigation menu');
    navToggle.innerHTML = '<span></span><span></span><span></span>';
    
    const header = document.querySelector('.wy-nav-top');
    if (header) {
      header.appendChild(navToggle);
      
      navToggle.addEventListener('click', function() {
        document.querySelector('.wy-nav-side').classList.toggle('shown');
        navToggle.classList.toggle('active');
      });
    }
    
    // Close navigation when clicking a link
    const navLinks = document.querySelectorAll('.wy-menu-vertical a');
    navLinks.forEach(function(link) {
      link.addEventListener('click', function() {
        document.querySelector('.wy-nav-side').classList.remove('shown');
        navToggle.classList.remove('active');
      });
    });
  }

  /**
   * Setup expandable content sections
   */
  function initializeExpandableContent() {
    // Look for section headers that can be collapsed
    const expandableSections = document.querySelectorAll('.expand-section');
    
    expandableSections.forEach(function(section) {
      const heading = section.querySelector('h2, h3, h4, h5, h6');
      if (!heading) return;
      
      // Create toggle button
      const toggle = document.createElement('button');
      toggle.className = 'expand-toggle';
      toggle.innerHTML = '<span class="expand-icon"></span>';
      toggle.setAttribute('aria-expanded', 'true');
      toggle.setAttribute('aria-label', 'Toggle section visibility');
      
      // Add the toggle to the heading
      heading.prepend(toggle);
      
      // Get the content to collapse (everything after the heading until the next heading)
      const content = document.createElement('div');
      content.className = 'expand-content';
      
      let node = heading.nextSibling;
      const nodesToMove = [];
      
      while (node) {
        if (node.nodeType === 1 && /^h[2-6]$/i.test(node.tagName)) {
          break;
        }
        nodesToMove.push(node);
        node = node.nextSibling;
      }
      
      // Move nodes to the collapsible content div
      nodesToMove.forEach(function(nodeToMove) {
        content.appendChild(nodeToMove);
      });
      
      // Insert the collapsible content after the heading
      heading.parentNode.insertBefore(content, heading.nextSibling);
      
      // Set up toggle behavior
      toggle.addEventListener('click', function() {
        const isExpanded = toggle.getAttribute('aria-expanded') === 'true';
        toggle.setAttribute('aria-expanded', !isExpanded);
        content.classList.toggle('collapsed');
      });
    });
  }

  /**
   * Setup scroll spy to highlight the current section in the table of contents
   */
  function setupScrollSpy() {
    // Get all section headings
    const headings = document.querySelectorAll('h1[id], h2[id], h3[id], h4[id], h5[id], h6[id]');
    if (headings.length === 0) return;
    
    // Create an array of heading positions
    const headingPositions = [];
    headings.forEach(function(heading) {
      headingPositions.push({
        id: heading.id,
        top: heading.offsetTop - 100 // Offset for better UX
      });
    });
    
    // Update active TOC item on scroll
    window.addEventListener('scroll', function() {
      const scrollPosition = window.scrollY;
      
      // Find the current heading
      let currentHeadingId = headingPositions[0].id;
      for (let i = 0; i < headingPositions.length; i++) {
        if (scrollPosition >= headingPositions[i].top) {
          currentHeadingId = headingPositions[i].id;
        } else {
          break;
        }
      }
      
      // Remove active class from all TOC items
      document.querySelectorAll('.wy-menu-vertical .current').forEach(function(item) {
        item.classList.remove('toc-visible');
      });
      
      // Add active class to current TOC item
      const currentTocItem = document.querySelector(`.wy-menu-vertical a[href="#${currentHeadingId}"]`);
      if (currentTocItem) {
        currentTocItem.classList.add('toc-visible');
      }
    });
    
    // Trigger scroll event once to initialize
    window.dispatchEvent(new Event('scroll'));
  }

  /**
   * Monitor page visibility to resume where the user left off
   */
  function monitorPageVisibility() {
    // Save scroll position when user leaves the page
    document.addEventListener('visibilitychange', function() {
      if (document.visibilityState === 'hidden') {
        try {
          localStorage.setItem('scrollPosition', window.scrollY);
          localStorage.setItem('scrollPath', window.location.pathname);
        } catch (e) {
          console.warn('Unable to save scroll position:', e);
        }
      } else {
        // Restore position if returning to the same page
        try {
          const savedPath = localStorage.getItem('scrollPath');
          if (savedPath === window.location.pathname) {
            const savedPosition = parseInt(localStorage.getItem('scrollPosition'), 10) || 0;
            setTimeout(function() {
              window.scrollTo(0, savedPosition);
            }, 100);
          }
        } catch (e) {
          console.warn('Unable to retrieve scroll position:', e);
        }
      }
    });
  }

  /**
   * Add accessibility features
   */
  function addAccessibilityFeatures() {
    // Add skip to content link for keyboard navigation
    const skipLink = document.createElement('a');
    skipLink.href = '#main-content';
    skipLink.className = 'skip-to-content';
    skipLink.textContent = 'Skip to content';
    document.body.insertBefore(skipLink, document.body.firstChild);
    
    // Add ID to the main content for the skip link
    const mainContent = document.querySelector('.wy-nav-content');
    if (mainContent) {
      mainContent.id = 'main-content';
      mainContent.setAttribute('tabindex', '-1'); // Make it focusable
    }
    
    // Improve focus visibility
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Tab') {
        document.body.classList.add('keyboard-user');
      }
    });
    
    document.addEventListener('mousedown', function() {
      document.body.classList.remove('keyboard-user');
    });

    // Add role attributes to improve screen reader experience
    document.querySelector('.wy-nav-side').setAttribute('role', 'navigation');
    document.querySelector('.wy-nav-content').setAttribute('role', 'main');
    
    const footer = document.querySelector('footer');
    if (footer) {
      footer.setAttribute('role', 'contentinfo');
    }
  }
})();