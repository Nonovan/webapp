import os
import json
from flask import Flask, render_template, request, session, redirect

app = Flask(__name__)
# app.config['SECRET_KEY'] = 'my_secret_key'

# Initiate a session
# session = {}

# session["username"] = "admin"
# session["password"] = "password"

# Create a file to store data
# data_file = open("data.json", "w")

# Add some sample data to the file
# data = [
#    {
#        "username": "admin",
#        "password": "password",
#        "grocery_list": ["apples", "oranges", "bananas"]
#    },
#    {
#        "username": "user",
#        "password": "password",
#        "grocery_list": ["milk", "bread", "eggs"]
#    }
# ]

# json.dump(data, data_file)

# Close the file
# data_file.close()

# Define the index route


@app.route("/myapp")
def index():
    return render_template('index.html')

# Define the home route


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

# Define the login


@app.route("/login")
def login():
    with open('data.json', 'r') as f:
        passwords = json.load(f)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in passwords and passwords[username] == password:
            session['username'] = username
            return redirect('home')
        else:
            return 'Invalid username or password'

    return render_template('login.html')

# Define the logout route


@app.route("/logout")
def logout():
    # Clear the session

    session.clear()
    return redirect('login')

# Define the register route


@app.route("/register")
def register():
    return render_template('register.html')

# Define various page routes


@app.route("/cloud")
def cservices():
    return render_template('cloud.html')


@app.route("/ICS")
def icsdata():
    return render_template('ics.html')


@app.route("/About")
def myabout():
    return render_template('about.html')

# Define the add item to grocery list route


@app.route("/add_item", methods=["POST"])
def add_item():
    item = request.form.get("item")

    if "username" in session:
        username = session["username"]

        with open("data.json", "r") as data_file:
            data = json.load(data_file)
            data[username]["grocery_list"].append(item)
            json.dump(data, data_file)
            data_file.close()

        return "Item added successfully"
    else:
        return "Please login first"

# Define the search item in grocery list route


@app.route("/search_item", methods=["POST"])
def search_item():
    item = request.form.get("item")

    if "username" in session:
        username = session["username"]

        with open("data.json", "r") as data_file:
            data = json.load(data_file)
            if item in data[username]["grocery_list"]:
                return "Item found"
            else:
                return "Item not found"
    else:
        return "Please login first"

# Define the list items in grocery list route


@app.route("/list_items", methods=["POST"])
def list_items():
    if "username" in session:
        username = session["username"]

        with open("data.json", "r") as data_file:
            data = json.load(data_file)
            items = data[username]["grocery_list"]

            table = []
            for item in items:
                row = []
                row.append(str(item))
                table.append(row)

            return json.dumps(table)
    else:
        return "Please login first"


# if __name__ == "__main__":
#     app.run(debug=True)
