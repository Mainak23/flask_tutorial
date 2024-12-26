from flask import Flask, request, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta, datetime
import os
import jwt
import zipfile
import io

# Directory setup
directory_path = os.path.join(os.getcwd(), 'static_uploader')
UPLOAD_DIRECTORY = os.path.join(os.getcwd(), 'question_answer')

if not os.path.exists(directory_path):
    os.makedirs(directory_path)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure the SQLAlchemy database URI and binds
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///default.db'  # Default URI (for fallback)
app.config['SQLALCHEMY_BINDS'] = {
    'user_detail': f'sqlite:///{os.path.join(directory_path, "user_detail.db")}',
    'user_key': f'sqlite:///{os.path.join(directory_path, "user_key.db")}'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "werttryedfghbbfdetgffghjjuytrrterdfghhj#$"  # Change this to a secure key

db = SQLAlchemy(app)
jwt_manager = JWTManager(app)

class User(db.Model):
    __bind_key__ = 'user_detail'  # Use the 'user_detail' bind key
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Userkey(db.Model):
    __bind_key__ = 'user_key'  # Use the 'user_key' bind key
    id = db.Column(db.Integer, primary_key=True)
    jwt_token = db.Column(db.String(255), nullable=False)
    time = db.Column(db.DateTime, nullable=False)

with app.app_context():
    db.create_all()  # This will create all the tables

class Downloader:
    @staticmethod
    def download_all_files():
        try:
            # Create an in-memory bytes buffer
            zip_buffer = io.BytesIO()
            # Create a zip file in the bytes buffer
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                # Loop through all files in the directory
                for root, _, files in os.walk(UPLOAD_DIRECTORY):
                    for file in files:
                        file_path = os.path.join(root, file)
                        zip_file.write(file_path, os.path.relpath(file_path, UPLOAD_DIRECTORY))

            zip_buffer.seek(0)  # Seek to the beginning of the buffer
            return send_file(zip_buffer, as_attachment=True, download_name='all_files.zip', mimetype='application/zip')

        except Exception as e:
            abort(500, description=str(e))

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not username or not password or not email:
        return jsonify({'error': 'Missing parameters'}), 400
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
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
        access_token = create_access_token(identity=username, expires_delta=timedelta(hours=24))
        new_user_key = Userkey(jwt_token=access_token, time=datetime.now())
        db.session.add(new_user_key)
        db.session.commit()
        return jsonify({'message': 'Login successful!', 'access_token': access_token}), 200

    elif user:
        return jsonify({'error': 'Invalid password'}), 401
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/download', methods=['GET'])
def decode_token():
    access_token = request.args.get('access_token')
    ##http://127.0.0.1:5000/download?access_token=your_token_here
    if not access_token:
        return jsonify({'error': 'Access token is required'}), 400
    
    try:
        decoded_token = jwt.decode(access_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_identity = decoded_token["sub"]
        
        if User.query.filter_by(username=user_identity).first():
            return Downloader.download_all_files()
        else:
            return jsonify({'error': 'User not found'}), 404
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Welcome {current_user}! This is a protected route.'})

@app.route('/latest-entry', methods=['GET'])
def get_latest_entry():
    username = request.args.get('username')
    
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
    latest_entry = Userkey.query.filter_by(jwt_token=username).order_by(Userkey.time.desc()).first()

    if not latest_entry:
        return jsonify({'error': 'No entries found for this user'}), 404
    
    return jsonify({
        'id': latest_entry.id,
        'jwt_token': latest_entry.jwt_token,
        'time': latest_entry.time
    })

if __name__ == '__main__':
    app.run(debug=True)
