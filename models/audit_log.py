class AuditLog:
    """
    A class to represent an audit log entry.
    """

    def __init__(self, user_id, action, timestamp, details=None):
        """
        Initialize an AuditLog instance.

        :param user_id: ID of the user performing the action
        :param action: Description of the action performed
        :param timestamp: Timestamp of when the action occurred
        :param details: Optional additional details about the action
        """
        self.user_id = user_id
        self.action = action
        self.timestamp = timestamp
        self.details = details

    def to_dict(self):
        """
        Convert the audit log entry to a dictionary.

        :return: Dictionary representation of the audit log entry
        """
        return {
            "user_id": self.user_id,
            "action": self.action,
            "timestamp": self.timestamp,
            "details": self.details,
        }

    def __str__(self):
        """
        String representation of the audit log entry.

        :return: String describing the audit log entry
        """
        return f"AuditLog(user_id={self.user_id}, action={self.action}, timestamp={self.timestamp}, details={self.details})"