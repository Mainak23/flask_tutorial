from flask import Flask, request, jsonify,abort,send_from_directory,abort, request,jsonify,url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token
from datetime import timedelta, datetime
import jwt
from werkzeug.utils import safe_join
from werkzeug.serving import make_server
import os

# Set up directories
directory_path = os.path.join(os.getcwd(), 'static_uploader')
DOWNLOAD_FOLDER = os.path.join(os.getcwd(), 'question_answer')

if not os.path.exists(directory_path):
    os.makedirs(directory_path)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure the SQLAlchemy database URI
app.config['SQLALCHEMY_BINDS'] = {
    'user_detail': f'sqlite:///{os.path.join(directory_path, "user_detail.db")}',
    'user_key': f'sqlite:///{os.path.join(directory_path, "user_key.db")}'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "werttryedfghbbfdetgffghjjuytrrterdfghhj#$"  # Change this to a secure key
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
db = SQLAlchemy(app)
jwt_manager = JWTManager(app)

class User(db.Model):
    __bind_key__ = 'user_detail'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Userkey(db.Model):
    __bind_key__ = 'user_key'
    id = db.Column(db.Integer, primary_key=True)
    jwt_token = db.Column(db.String(255), nullable=False) 
    time = db.Column(db.DateTime, nullable=False) 

# Create the databases and tables
"""with app.app_context():
    db.create_all()"""



@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # Check if username, password, and email are provided
    if not username or not password or not email:
        return jsonify({'error': 'Missing parameters'}), 400

    # Ensure the password is a string
    if not isinstance(password, str):
        return jsonify({'error': 'Password must be a string'}), 400

    # Check if the user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 400

    # Use a more secure hashing method
    try:
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    # Create a new user and save to the database
    new_user = User(username=username, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing parameters'}), 400

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        # Create JWT token with 24-hour expiration
        access_token = create_access_token(identity=username, expires_delta=timedelta(hours=24))
        new_user_key = Userkey(jwt_token=access_token, time=datetime.now())
        db.session.add(new_user_key)
        db.session.commit()
        return jsonify({'message': 'Login successful!', 'access_token': access_token}), 200
    elif user:
        return jsonify({'error': 'Invalid password'}), 401
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/<path:filename>', methods=['GET'])
def handle_request(filename):
    # Handle file download
    safe_path = safe_join(app.config['DOWNLOAD_FOLDER'], filename)
    
    try:
        if os.path.isfile(safe_path):
            return send_from_directory(
                app.config['DOWNLOAD_FOLDER'],
                filename,
                as_attachment=True
            )
        else:
            abort(404)  # File not found
    except OSError as e:
        # Handle OSError if something goes wrong with file access
        print(f"Error accessing file: {e}")
        abort(500)  # Internal Server Error


@app.route('/download/<path:filename>', methods=['GET'])
def download_files(filename):
    access_token = request.json.get('access_token')
    if not access_token:
        return jsonify({'error': 'Access token is required'}), 400
    try:
        # Decode the JWT token
        decoded_token = jwt.decode(access_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_identity = decoded_token.get("sub")
        
        # Check if the user exists in the database
        user = User.query.filter_by(username=user_identity).first()
        if user:
            download_url = url_for('handle_request', filename=filename, _external=True)
            return jsonify({'download_url': download_url})
        else:
            return jsonify({'error': 'User does not exist'}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500




if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)



