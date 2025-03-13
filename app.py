import csv
import hashlib
import os
import logging
from datetime import timedelta
from flask import Flask, render_template, request, session, redirect, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://username:password@localhost:5432/yourdb'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='approved')

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


@app.route("/About")
def myabout():
    return render_template('about.html')


@app.route('/cloud')
@login_required
def cservices():
    # Get the list of users from the database
    users = User.query.with_entities(User.username).all()
    user_list = [user.username for user in users]
    return render_template('cloud.html', users=user_list)

@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
    return "Too many attempts. Please try again later.", 429

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
