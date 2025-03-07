import csv
from flask import Flask, render_template, request, session

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'GET':
        return render_template('add.html')
    elif request.method == 'POST':
        name = request.form['name']
        description = request.form['description']

        # Open the flat file database
        with open('items.csv', 'a', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')

            # Write the new item to the file
            writer.writerow([name, description])

        return redirect('/')

@app.route('/items')
def items():
    # Open the flat file database
    with open('items.csv', 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        # Read the data from the file
        items = []
        for row in reader:
            items.append((row[0], row[1]))

    # Render the template
    return render_template('items.html', items=items)

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
                if row[2] == 'approved':
                    session['username'] = username
                    return redirect('/')
                else:
                    return render_template('login.html', error='Account not approved')

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

    # Check if the username is already taken
    with open('users.csv', 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        for row in reader:
            if row[0] == username:
                return render_template('register.html', error='Username already taken')

    # Add the new user to the flat file database
    with open('users.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')

        writer.writerow([username, password, 'approved'])

    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
