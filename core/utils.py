# core/utils.py

"""
Utility functions for the core module.
"""

import hashlib
import base64

def generate_sri_hash(file_path):
    """
    Generate a Subresource Integrity hash for a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        SRI hash string in the format "sha384-{hash}"
    """
    with open(file_path, 'rb') as f:
        file_contents = f.read()
        
    digest = hashlib.sha384(file_contents).digest()
    b64_digest = base64.b64encode(digest).decode('utf-8')
    return f"sha384-{b64_digest}"