import os
from flask import Flask, render_template, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from models.user import User
from models.environmental_data import EnvironmentalData

app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig')
db.init_app(app)

@app.route("/")
def index():
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        flash("Username and password are required", "error")
        return render_template("index.html", username=None)

    try:
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            return render_template("index.html", username=username)
        flash("Invalid credentials", "error")
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        flash("An error occurred", "error")

    return render_template("index.html", username=None)

@app.route("/environmental_data")
def environmental_data():
    try:
        data = EnvironmentalData.query.order_by(EnvironmentalData.timestamp.desc()).first()
        if data:
            return render_template("environmental_data.html", 
                                 temperature=data.temperature,
                                 humidity=data.humidity)
        return render_template("environmental_data.html", error="No data available")
    except Exception as e:
        app.logger.error(f"Error retrieving environmental data: {str(e)}")
        flash("Error retrieving data", "error")
        return render_template("environmental_data.html", error="Error retrieving data")

if __name__ == '__main__':
    app.run(debug=True)
