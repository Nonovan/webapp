"""
Session extension module for API authentication.

This module provides functionality for managing and extending session lifetimes
in the application. It handles the validation, extension, and regeneration of
user sessions to maintain both security and user experience.

The primary goals are:
1. Ensure sessions expire after periods of inactivity for security
2. Allow active users to maintain their sessions without disruption
3. Implement security best practices like session regeneration

Classes:
    SessionManager: Handles all session lifetime management operations

Usage:
    To extend a session:
    
    ```
    manager = SessionManager()
    updated_session = manager.extend_session(session)
    ```
"""

import uuid
from datetime import datetime, timedelta
import random


class SessionManager:
    """
    Manages user session lifetimes and security.
    
    This class provides methods to validate, extend, and regenerate user sessions,
    implementing security best practices while maintaining a smooth user experience.
    
    Attributes:
        session_duration (timedelta): The amount of time a session should be extended
    """
    
    def __init__(self, session_duration_minutes=30):
        """
        Initialize a new SessionManager.
        
        Args:
            session_duration_minutes (int): Number of minutes to extend sessions by.
                                           Default is 30 minutes.
        """
        self.session_duration = timedelta(minutes=session_duration_minutes)

    def extend_session(self, session_data):
        """
        Extends the session expiration time.
        
        This method updates the expiration timestamp of a user session, effectively
        extending its lifetime. It validates that the session contains the required
        fields before proceeding.

        Args:
            session_data (dict): A dictionary containing session details, including 'expires_at'.

        Returns:
            dict: Updated session with extended expiration time.
            
        Raises:
            ValueError: If the session dictionary does not contain an 'expires_at' field.
        """
        if 'expires_at' not in session_data:
            raise ValueError("Session must contain an 'expires_at' field.")

        new_expiration = datetime.now() + self.session_duration
        session_data['expires_at'] = new_expiration.isoformat()
        
        # Randomly regenerate session ID to prevent session fixation
        if random.random() < 0.2:  # 20% chance
            self._regenerate_session_id(session_data)
            
        return session_data
        
    def _regenerate_session_id(self, session_data):
        """
        Regenerates the session ID to prevent session fixation attacks.
        
        This private method creates a new session ID while preserving all other
        session data. This helps protect against session fixation attacks where
        an attacker might force a user to use a known session ID.
        
        Args:
            session (dict): The session dictionary to update with a new ID.
            
        Returns:
            dict: The updated session dictionary with a new session ID.
        """
        
        # Generate a new session ID
        session_data['session_id'] = str(uuid.uuid4())
        
        # Update the regeneration timestamp
        session_data['regenerated_at'] = datetime.now().isoformat()
        
        return session_data
        
    def is_valid(self, session_data):
        """
        Validates whether a session is still active and not expired.
        
        Args:
            session_data (dict): The session dictionary to validate.
            
        Returns:
            bool: True if the session is valid, False otherwise.
        """
        if not session_data or 'expires_at' not in session_data:
            return False
            
        try:
            expiration = datetime.fromisoformat(session_data['expires_at'])
            return datetime.now() < expiration
        except (ValueError, TypeError):
            # Handle invalid date format
            return False


# Example usage
if __name__ == "__main__":
    # Example demonstrating how to use the SessionManager class.
    # This creates a sample session, extends it, and prints the result.
    session = {
        "user_id": 123,
        "expires_at": (datetime.now() + timedelta(minutes=30)).isoformat()
    }

    manager = SessionManager(session_duration_minutes=15)
    updated_session = manager.extend_session(session)
    print("Updated session:", updated_session)
    
    # Demonstrate validation
    valid = manager.is_valid(updated_session)
    print(f"Session valid: {valid}")