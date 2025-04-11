from datetime import datetime, timedelta
from typing import List
from flask import current_app
import click
from extensions import db
from models.user import User

def seed_database() -> bool:
    """Seed database with initial data.

    Returns:
        bool: True if seeding was successful, False if already seeded

    Raises:
        Exception: If seeding fails
    """
    try:
        # Check if already seeded
        if User.query.count() > 0:
            current_app.logger.info("Database already seeded. Skipping.")
            return False

        with click.progressbar(length=2, label='Seeding database') as bar_line:
            # Create admin user
            admin = User()
            admin.username = "admin"
            admin.email = "admin@example.com"
            admin.role = "admin"
            admin.status = "active"
            admin.created_at = datetime.utcnow()
            admin.set_password("AdminPass123!")
            db.session.add(admin)
            bar_line.update(1)

            # Create test users
            test_users: List[User] = []
            for i in range(1, 4):
                user = User()
                user.username = f"user{i}"
                user.email = f"user{i}@example.com"
                user.role = "user"
                user.status = "active"
                user.created_at = datetime.utcnow() - timedelta(days=i)
                user.set_password("UserPass123!")
                test_users.append(user)

            db.session.add_all(test_users)
            bar_line.update(1)

            # Commit changes
            db.session.commit()

            current_app.logger.info(f"Database seeded with {len(test_users) + 1} users")
            return True

    except Exception as e:
        current_app.logger.error(f"Database seeding failed: {e}")
        db.session.rollback()
        raise

if __name__ == "__main__":
    from app import create_app
    app = create_app()
    with app.app_context():
        seed_database()
