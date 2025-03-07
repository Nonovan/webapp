import csv
import unittest
from flask import Flask, render_template, request, session

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    if 'username' in session:
        return redirect('/')

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
                return redirect('/')

    return render_template('login.html', error='Invalid username or password')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']
    confirmation = request.form['confirmation']

    if password != confirmation:
        return render_template('register.html', error='Passwords do not match')

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

    if "username" in session:
        username = session["username"]
        return render_template('home.html')
    else:
        return 'Please login first'


@app.route("/cloud")
def cservices():
    return render_template('cloud.html')


@app.route("/ICS")
def icsdata():
    return render_template('ics.html')


@app.route("/About")
def myabout():
    return render_template('about.html')


@app.route('/users')
def users():
    # Get the list of users from the database
    with open('users.csv', 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        users = []
        for row in reader:
            users.append(row[0])

    return render_template('users.html', users=users)


class AppTest(unittest.TestCase):
    def test_index(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Items', response.data)


    def test_login(self):
        response = self.client.post('/login', data={'username': 'admin', 'password': 'password'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, '/')

        with self.client.session_transaction() as sess:
            self.assertEqual(sess['username'], 'admin')


    def test_logout(self):
        self.client.post('/login', data={'username': 'admin', 'password': 'password'})
        response = self.client.get('/logout')
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, '/')

        with self.client.session_transaction() as sess:
            self.assertNotIn('username', sess)


    def test_register(self):
        response = self.client.post('/register', data={'username': 'new_user', 'password': 'password', 'confirmation': 'password'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, '/')

        # Check if the user was added to the database
        with open('users.csv', 'r') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')

            for row in reader:
                if row[0] == 'new_user':
                    break
            else:
                self.fail('New user was not added to the database')

        # Check if the user is logged in
        with self.client.session_transaction() as sess:
            self.assertEqual(sess['username'], 'new_user')

        # Check if the registration form is rendered correctly
        response = self.client.get('/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Username', response.data)
        self.assertIn('Password', response.data)
        self.assertIn('Confirmation', response.data)


    def test_users(self):
        response = self.client.get('/users')
        self.assertEqual(response.status_code, 200)
        self.assertIn('admin', response.data)

        # Check if the users are rendered in an enumerated list
        for i, user in enumerate(response.data.splitlines()):
            self.assertEqual(user, str(i) + '. ' + user)


if __name__ == '__main__':
    unittest.main()
