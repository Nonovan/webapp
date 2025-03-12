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
    if not any(c.islower*() for c in password):
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
                # Example: user = db.get_user(username)
                # if user and check_password_hash(user.password, password):
                with open('users.csv', 'r', encoding='utf-8') as csvfile:
                    reader = csv.reader(csvfile, delimiter=',')
                    for row in reader:
                        if row[0] == username and check_password_hash(row[1], password):
                            session.permanent = True
                            session['username'] = username
                            logging.info(f"Succesful login for user: {username}")
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
        with open('users.csv', 'r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                if row[0] == username:
                    flash('Username already exists.')
                    return render_template('register.html')

        with open('users.csv', 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')

            # Write the new user to the file
            writer.writerow([username, hashed_password, 'approved'])

        flash('Registration successful!')
        return redirect('/login')
    
    except Exception as e:
        # Log the error for debugging purposes
        print(f"An error occurred: {e}")
        return render_template('tryagain.html', message="An error occurred during registration.")


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
    with open('users.csv', 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        users = []
        for row in reader:
            users.append(row[0])

    return render_template('cloud.html', users=users)

@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
    return "Too many attempts. Please try again later.", 429

# if __name__ == '__main__':
#    app.run(debug=True)
