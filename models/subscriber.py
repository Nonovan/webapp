from datetime import datetime
from typing import Optional
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base

# filepath: models/subscriber.py


Base = declarative_base()

class Subscriber(Base):
    """
    Subscriber model representing a subscriber entity in the system.

    Attributes:
        id (int): Primary key, unique identifier for the subscriber.
        email (str): Email address of the subscriber.
        name (str): Name of the subscriber.
        is_active (bool): Indicates if the subscriber is active.
        created_at (datetime): Timestamp when the subscriber was created.
        updated_at (datetime): Timestamp when the subscriber was last updated.
    """
    __tablename__ = 'subscribers'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, unique=True)
    name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, email: str, name: Optional[str] = None, is_active: bool = True):
        """
        Initialize a new Subscriber instance.

        Args:
            email (str): Email address of the subscriber.
            name (Optional[str]): Name of the subscriber. Defaults to None.
            is_active (bool): Indicates if the subscriber is active. Defaults to True.
        """
        self.email = email
        self.name = name
        self.is_active = is_active

    def __repr__(self) -> str:
        """
        String representation of the Subscriber instance.

        Returns:
            str: String representation of the subscriber.
        """
        return f"<Subscriber(id={self.id}, email='{self.email}', name='{self.name}', is_active={self.is_active})>"
