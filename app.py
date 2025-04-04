import os
import logging
import uuid
from datetime import timedelta
from typing import Optional

from flask import Flask, render_template, request, session, redirect, flash, Blueprint, current_app, g
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from config import config
from models.user import User
from auth.utils import validate_input, login_required, require_role

# Load environment variables
load_dotenv()
required_env_vars = ['SECRET_KEY', 'DATABASE_URL']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Create blueprint
main = Blueprint('main', __name__)

# Request logging middleware
@main.before_request
def log_request_info():
    current_app.logger.info('Headers: %s', request.headers)
    current_app.logger.info('Body: %s', request.get_data())

@main.route("/About")
def about():
    return render_template('about.html')

@main.route('/cloud')
@login_required
@limiter.limit("30 per minute")
def cloud_services():
    users = User.query.with_entities(User.username).all()
    user_list = [user.username for user in users]
    return render_template('cloud.html', users=user_list)

# Error handlers
@main.app_errorhandler(404)
def not_found_error(error):
    current_app.logger.error(f'Page not found: {request.url}')
    return render_template('404.html'), 404

@main.app_errorhandler(500)
def internal_error(error):
    current_app.logger.error(f'Server Error: {error}')
    db.session.rollback()
    return render_template('500.html'), 500

@main.app_errorhandler(403)
def forbidden_error(error):
    current_app.logger.error(f'Forbidden access: {request.url}')
    return render_template('403.html'), 403

@main.route('/health')
def health_check():
    return {
        'status': 'healthy',
        'database': db.engine.execute('SELECT 1').scalar() == 1
    }

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

def validate_environment():
    required_vars = ['SECRET_KEY', 'DATABASE_URL']
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")
    
def setup_logging(app):
    formatter = logging.Formatter(
        '%(asctime)s [%(request_id)s] %(levelname)s: %(message)s'
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    app.logger.handlers = [handler]
    app.logger.setLevel(app.config['LOG_LEVEL'])

def create_app(config_name='default'):
    load_dotenv()
    validate_environment()
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    
    setup_logging(app)
    
    @app.before_request
    def before_request():
        g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        
    @app.after_request
    def add_security_headers(response):
        response.headers.update(app.config['SECURITY_HEADERS'])
        return response

    @app.route('/health')
    def health_check():
        return {
            'status': 'healthy',
            'version': app.config.get('VERSION', '1.0.0'),
            'database': db.engine.execute('SELECT 1').scalar() == 1
        }
    
    # Register blueprints
    from views.main import main_bp
    app.register_blueprint(main_bp)
    
    return app

def init_app():
    return create_app(os.getenv('FLASK_ENV', 'development'))

app = create_app()

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='approved')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)

def validate_input(text):
    return text and len(text.strip()) > 0 and len(text) < 100

def is_logged_in():
    return 'username' in session

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def validate_password(password):
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    if is_logged_in():
        return redirect('/ICS')
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if is_logged_in():
        return redirect('/')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            # Check if the username and password are valid
            if not validate_input(username) or not validate_input(password):
                flash('Invalid input.')
                return render_template('login.html'), 400

            if username and password:
                user = User.query.filter_by(username=username).first()
                if user and check_password_hash(user.password, password):
                    session.permanent = True
                    session['username'] = username
                    logging.info(f"Successful login for user: {username}")
                    return redirect('/ICS')

            logging.warning(f"Failed login attempt for user: {username}")
            flash("Invalid credentials.")
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash('An error occurred. Please try again.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
@limiter.limit("3 per hour")
def register_post():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    confirmation = request.form.get('confirmation', '').strip()
    
    if not validate_input(username) or not validate_input(password):
        flash('Invalid input.')
        return render_template('register.html'), 400
    
    if not username or not password:
        flash('Username and password are required.')
        return render_template('register.html')

    if password != confirmation:
        flash('Passwords do not match.')
        return render_template('register.html')
    
    if len(password) < 8:
        flash('Password must be at least 8 characters long.')
        return render_template('register.html')
        
    # Hash the password before storing
    # Example: hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    hashed_password = generate_password_hash(password)
    

    # Add the new user to the database
    try:
        # Check if the username already exists
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists.')
            return render_template('register.html')

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            status='approved'
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!')
        return redirect('/login')
    
    except Exception as e:
        logging.exception("Error during registration:") # Log the exception with traceback
        flash("An error occurred during registration.")
        return render_template('tryagain.html')


@app.route("/home")
def home():
    return render_template('home.html')


@app.route('/ICS')
@login_required
def icsdata():
    return render_template('ics.html')

if __name__ == '__main__':
    app = create_app()
    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')