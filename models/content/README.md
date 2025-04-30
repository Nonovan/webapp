# Content Management Models

This directory contains database models for the Cloud Infrastructure Platform's content management system, implementing a robust structure for organizing, publishing, and managing content across the platform.

## Contents

- [Overview](#overview)
- [Key Models](#key-models)
- [Directory Structure](#directory-structure)
- [Implementation Notes](#implementation-notes)
- [Features](#features)
- [Usage Examples](#usage-examples)
- [Security Considerations](#security-considerations)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

## Overview

The content management models provide a flexible and powerful foundation for creating, organizing, and publishing various types of content within the platform. These models support hierarchical organization, revision tracking, media management, and user interactions through a consistent API while ensuring proper security controls and audit capabilities.

## Key Models

1. **`Category`**: Hierarchical organization structure for content
   - Supports nested categories with unlimited depth
   - Includes slug generation for SEO-friendly URLs
   - Metadata for display order and visibility
   - Parent-child relationship navigation

2. **`Post`**: Core content item model
   - Rich content storage with HTML support
   - Comprehensive metadata (author, dates, status)
   - Publication workflow (draft, published, archived)
   - SEO attributes (meta description, keywords)
   - Versioning through ContentRevision integration

3. **`Tag`**: Flexible content classification
   - Cross-category tagging capabilities
   - Tag grouping for organization
   - Tag frequency tracking
   - Tag relationship management

4. **`Media`**: File attachments and uploads
   - Image, document, video, and other file type support
   - Metadata extraction and storage
   - File type validation and security scanning
   - Content delivery optimizations
   - Access control integration

5. **`PostMedia`**: Association between posts and media
   - Position and display context tracking
   - Caption and alt text for accessibility
   - Featured media designation
   - Gallery and inline media support

6. **`Comment`**: User feedback and interaction
   - Threaded comment support
   - Moderation workflow
   - Anti-spam integration
   - Author verification
   - Notification integration

7. **`ContentRevision`**: Version history tracking
   - Change tracking across revisions
   - Author and timestamp metadata
   - Rollback capabilities
   - Diff generation between versions
   - Automatic versioning

8. **`Menu`** and **`MenuItem`**: Navigation structure
   - Hierarchical menu organization
   - Link management to internal/external content
   - Position and display context
   - Conditional visibility rules

## Directory Structure

```plaintext
models/content/
├── __init__.py             # Package exports
├── category.py             # Category model for content organization
├── comment.py              # Comment model for user interactions
├── content_revision.py     # Content version history tracking
├── media.py                # Media file model
├── menu.py                 # Menu and MenuItem models for navigation
├── post.py                 # Post model for primary content
├── post_media.py           # Association between posts and media
├── README.md               # This documentation
└── tag.py                  # Tag model for content classification
```

## Implementation Notes

All content models inherit from the `BaseModel` class, providing:

- Common CRUD operations (save, update, delete)
- Timestamp tracking (created_at, updated_at)
- Audit logging for security-critical operations
- JSON serialization via `to_dict()`
- Consistent query methods and validation

Content models are designed with these principles:

- **Content separation**: Clear separation between content, metadata, and presentation
- **Reusable components**: Components like media can be attached to multiple content types
- **Workflow integration**: Publication state management built into core models
- **Security by design**: Access control integrated with the platform RBAC system
- **Audit capabilities**: Changes tracked and logged for compliance requirements

## Features

- **Hierarchical Organization**: Category nesting with traversal methods
- **Revision Tracking**: Full history of content changes
- **Workflow States**: Draft, published, scheduled, archived states
- **SEO Optimization**: Built-in slug generation and metadata
- **Media Management**: Structured attachment of files to content
- **User Interactions**: Comment threads with moderation
- **Menu Builder**: Tools for creating dynamic navigation
- **Security Integration**: Access control via RBAC system
- **Audit Logging**: Change tracking for compliance
- **Content Relationships**: Related content management
- **Content Scheduling**: Future publication capabilities
- **Flexible Classification**: Multi-dimensional tagging

## Usage Examples

### Creating and Publishing Content

```python
from models.content import Category, Post, Tag
from models.auth import User

# Create a category
tech_category = Category(
    name="Technology",
    description="Technology-related content",
    slug="technology"
)
tech_category.save()

# Get the author
author = User.query.filter_by(username="admin").first()

# Create a post
post = Post(
    title="Introduction to Cloud Security",
    content="<p>Cloud security is essential for...</p>",
    category_id=tech_category.id,
    author_id=author.id,
    status=Post.STATUS_DRAFT,
    meta_description="An overview of cloud security principles"
)
post.save()

# Add tags
cloud_tag = Tag.get_or_create("cloud")
security_tag = Tag.get_or_create("security")
post.add_tags([cloud_tag, security_tag])

# Publish the post
post.publish()
```

### Working with Media

```python
from models.content import Media, Post, PostMedia

# Create media
media = Media(
    filename="security_diagram.png",
    storage_path="uploads/2024/05/security_diagram.png",
    file_size=256000,
    mime_type="image/png",
    uploaded_by=current_user.id,
    title="Cloud Security Architecture Diagram",
    alt_text="Diagram showing cloud security components and their relationships"
)
media.save()

# Add media to a post
post = Post.query.filter_by(slug="introduction-to-cloud-security").first()
post_media = PostMedia(
    post_id=post.id,
    media_id=media.id,
    caption="Cloud Security Architecture Overview",
    position=PostMedia.POSITION_INLINE,
    display_order=1
)
post_media.save()

# Set as featured media
post_media.is_featured = True
post_media.save()
```

### Category Navigation

```python
from models.content import Category

# Get top-level categories
root_categories = Category.query.filter_by(parent_id=None).all()

# Get tree structure
for category in root_categories:
    print(f"Category: {category.name}")

    # Get subcategories
    for subcategory in category.children:
        print(f"  |- {subcategory.name}")

        # Get posts in subcategory
        posts = subcategory.posts.filter_by(status=Post.STATUS_PUBLISHED).all()
        for post in posts:
            print(f"    |- Post: {post.title}")
```

### Content Revisions

```python
from models.content import Post, ContentRevision

# Get a post
post = Post.query.filter_by(slug="introduction-to-cloud-security").first()

# Update content (automatically creates a revision)
original_content = post.content
post.content = post.content + "<p>Additional information about cloud security...</p>"
post.save()

# Get revision history
revisions = ContentRevision.get_revisions(
    content_type='post',
    content_id=post.id
)

# Compare with previous version
latest_revision = revisions[0]
previous_revision = revisions[1]
diff = ContentRevision.get_diff(previous_revision, latest_revision)

# Rollback to previous version if needed
post.rollback_to_revision(previous_revision.id)
```

### Menu Management

```python
from models.content import Menu, MenuItem, Category

# Create a main menu
main_menu = Menu(
    name="Main Navigation",
    slug="main-nav",
    description="Primary site navigation"
)
main_menu.save()

# Add items linking to categories
tech_category = Category.query.filter_by(slug="technology").first()
menu_item = MenuItem(
    menu_id=main_menu.id,
    title="Technology",
    content_type="category",
    content_id=tech_category.id,
    position=1
)
menu_item.save()

# Add external link
external_item = MenuItem(
    menu_id=main_menu.id,
    title="Documentation",
    url="https://docs.example.com",
    position=2,
    target="_blank"
)
external_item.save()

# Get menu structure
menu = Menu.get_by_slug("main-nav")
for item in menu.items:
    print(f"Menu item: {item.title}")
    for child in item.children:
        print(f"  |- {child.title}")
```

## Security Considerations

- **Access Control**: All content access is controlled through the RBAC system
- **Content Validation**: Rich text content is sanitized to prevent XSS
- **Media Security**: Uploaded files are scanned for malware and validated
- **Comment Protection**: Anti-spam measures prevent abuse of comment functionality
- **Version Control**: All changes are tracked for audit and compliance purposes
- **Sensitive Content**: Classification system for handling restricted content
- **Publication Workflow**: Approval processes for sensitive content areas

## Best Practices

- Always validate user input before storing in content fields
- Use the built-in sanitization functions for rich text
- Implement proper permission checks before content operations
- Follow naming conventions for consistency
- Set appropriate indexes for frequently queried fields
- Use the version history system to track important changes
- Implement workflow approval for sensitive content areas
- Always filter content by status when displaying to users
- Use proper content classification for access control

## Related Documentation

- Content API Reference
- Media Handling Guide
- RBAC Implementation Guide
- Content Workflow Guide
- API Content Endpoints
- Content Security Policy
