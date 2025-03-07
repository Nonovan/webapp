import csv
import unittest
from flask import Flask, render_template, request, session, redirect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_secret_key'

# Initiate a session
session = {}

# session["username"] = "admin"
# session["password"] = "password"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    if 'username' in session:
        return redirect('/ICS')

    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']

    # Check if the username and password are valid
    with open('users.csv', 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        for row in reader:
            if row[0] == username and row[1] == password:
                session['username'] = username
                return redirect('/ICS')

    return render_template('tryagain.html', error='Invalid username or password')


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

    if password != confirmation:
        return render_template('tryagain.html', error='Passwords do not match')

    # Add the new user to the database
    with open('users.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')

        # Write the new user to the file
        writer.writerow([username, password, 'approved'])

    return redirect('/login')


@app.route("/home")
def home():
    # session["username"] = "admin"
    # session["password"] = "password"

    # return render_template('home.html')

    # if "username" in session:
    #     username = session["username"]
    #     return render_template('home.html')
    # else:
    #     return 'Please login first'

    return render_template('home.html')


@app.route("/ICS")
def icsdata():
    # Check if the user is logged in
    if 'username' not in session:
        return render_template('tryagain.html')

    return render_template('ics.html')


@app.route("/About")
def myabout():
    return render_template('about.html')


@app.route('/cloud')
def cservices():
    # Check if the user is logged in
    if 'username' not in session:
        return render_template('tryagain.html')

    # Get the list of users from the database
    with open('users.csv', 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        users = []
        for row in reader:
            users.append(row[0])

    return render_template('cloud.html', users=users)


if __name__ == '__main__':
    app.run(debug=True)
