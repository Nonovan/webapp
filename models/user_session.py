class UserSession:
    def __init__(self, user_id, session_id, created_at, expires_at):
        """
        Initialize a UserSession instance.

        :param user_id: ID of the user
        :param session_id: Unique session identifier
        :param created_at: Timestamp when the session was created
        :param expires_at: Timestamp when the session expires
        """
        self.user_id = user_id
        self.session_id = session_id
        self.created_at = created_at
        self.expires_at = expires_at

    def is_active(self, current_time):
        """
        Check if the session is still active.

        :param current_time: Current timestamp
        :return: True if the session is active, False otherwise
        """
        return self.expires_at > current_time

    def extend_session(self, extension_time):
        """
        Extend the session expiration time.

        :param extension_time: Time in seconds to extend the session
        """
        self.expires_at += extension_time