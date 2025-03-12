import csv
import hashlib
import os
from datetime import timedelta
from flask import Flask, render_template, request, session, redirect, flash
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)   # Generate a random secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
csrf = CSRFProtect(app)

# Initiate a session
# session = {}

def is_logged_in():
    return 'username' in session

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    if is_logged_in():
        return redirect('/ICS')
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']

    # Check if the username and password are valid
    try:
        with open('users.csv', 'r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')

            for row in reader:
                
                if row[0] == username and check_password_hash(row[1], password):
                    session.permanent = True
                    session['username'] = username
                    return redirect('/ICS')

        flash('Invalid username or password.')
        return render_template('login.html')
    
    except FileNotFoundError:
        return render_template('tryagain.html', message="User database not found.")
    except Exception as e:
        # Log the error for debugging purposes
        print(f"An error occurred: {e}")
        return render_template('tryagain.html', message="An error occurred during login.")


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']
    confirmation = request.form['confirmation']
    
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
    #    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
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


# if __name__ == '__main__':
#    app.run(debug=True)
