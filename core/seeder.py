from datetime import datetime, timedelta
import click
from flask import current_app
from models import db, User
from extensions import metrics

def seed_database():
    """Seeds the database with initial data."""
    try:
        # Check if already seeded
        if User.query.count() > 0:
            current_app.logger.info("Database already seeded. Skipping.")
            return False

        with click.progressbar(length=2, label='Seeding database') as bar:
            # Create admin user
            admin = User(
                username="admin",
                email="admin@example.com", 
                role="admin",
                status="active",
                created_at=datetime.utcnow()
            )
            admin.set_password("AdminPass123!")
            db.session.add(admin)
            bar.update(1)

            # Create test users
            test_users = [
                User(
                    username=f"user{i}",
                    email=f"user{i}@example.com",
                    role="user", 
                    status="active",
                    created_at=datetime.utcnow() - timedelta(days=i)
                ) for i in range(1, 4)
            ]
            for user in test_users:
                user.set_password("UserPass123!")
            db.session.add_all(test_users)
            bar.update(1)

            # Commit changes
            db.session.commit()

            # Log success
            current_app.logger.info(f"Database seeded with {len(test_users) + 1} users")
            metrics.increment('database_seed_success')
            return True

    except Exception as e:
        current_app.logger.error(f"Database seeding failed: {e}")
        metrics.increment('database_seed_error')
        db.session.rollback()
        raise

if __name__ == "__main__":
    from app import create_app
    app = create_app()
    with app.app_context():
        seed_database()
