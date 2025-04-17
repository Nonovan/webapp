class UserActivity:
    """
    A class to represent user activity in the system.
    """

    def __init__(self, user_id, activity_type, timestamp):
        """
        Initialize a UserActivity instance.

        :param user_id: ID of the user performing the activity
        :param activity_type: Type of activity performed
        :param timestamp: Timestamp of the activity
        """
        self.user_id = user_id
        self.activity_type = activity_type
        self.timestamp = timestamp

    def __repr__(self):
        """
        Return a string representation of the UserActivity instance.
        """
        return f"UserActivity(user_id={self.user_id}, activity_type={self.activity_type}, timestamp={self.timestamp})"
    
    def update_last_active(self, new_timestamp):
        """
        Update the timestamp of the last activity.

        :param new_timestamp: New timestamp to update the activity
        """
        self.timestamp = new_timestamp