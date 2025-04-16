from flask import Flask, request, jsonify
import os

# subscribe.py


app = Flask(__name__)

@app.route('/newsletter/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400

    email = data['email']
    # Add logic to save the email to your database or mailing list
    # Simulating saving the email to a database or mailing list
    try:
        with open('/Users/ivans/Workspace/myproject/api/newsletter/subscribers.txt', 'a', encoding='utf-8') as file:
            file.write(f"{email}\n")
    except (IOError, OSError) as e:
        return jsonify({'error': f'Failed to save email: {str(e)}'}), 500
    return jsonify({'message': f'Successfully subscribed {email} to the newsletter!'}), 200

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)