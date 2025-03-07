import os
from flask import Flask, render_template, request

app = Flask(__name__)

# Create a file to store usernames and encrypted passwords
usernames_and_passwords = open("usernames_and_passwords.txt", "w")

# Add some sample data to the file
usernames_and_passwords.write("username1:password1\n")
usernames_and_passwords.write("username2:password2\n")

# Close the file
usernames_and_passwords.close()

# Create a file to store environmental data
environmental_data = open("environmental_data.txt", "w")

# Add some sample data to the file
environmental_data.write("temperature:25\n")
environmental_data.write("humidity:60\n")

# Close the file
environmental_data.close()

@app.route("/")
def index():
    # Get the username and password from the request
    username = request.args.get("username")
    password = request.args.get("password")

    # Check if the username and password are valid
    with open("usernames_and_passwords.txt", "r") as usernames_and_passwords_file:
        for line in usernames_and_passwords_file:
            username_and_password = line.strip()
            username, password_from_file = username_and_password.split(":")
            if username == username_and_password:
                if password == password_from_file:
                    return render_template("index.html", username=username)

    return render_template("index.html", username=None)

@app.route("/environmental_data")
def environmental_data():
    # Get the environmental data from the file
    with open("environmental_data.txt", "r") as environmental_data_file:
        for line in environmental_data_file:
            environmental_data = line.strip()
            key, value = environmental_data.split(":")
            return render_template("environmental_data.html", key=key, value=value)

if __name__ == "__main__":
    app.run(debug=True)
