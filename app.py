from flask import Flask, request, jsonify
from security_utils import generate_random_password, encrypt_message, decrypt_message
from key_management import generate_and_store_key, retrieve_key
from functools import wraps
from auth import generate_token, verify_token
from loguru import logger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin

# Set up logging
logger.add("app.log", rotation="1 MB")

app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Initialiser SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security.db'
db = SQLAlchemy(app)

# Définir les modèles User et Role
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary='user_roles',
                            backref=db.backref('users', lazy='dynamic'))


class UserRoles(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))

# Créer les tables
with app.app_context():
    db.create_all()

# Configurer Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


@app.before_request
def log_request_info():
    logger.info(f"Request: {request.method} {request.url}")
    logger.info(f"Headers: {request.headers}")
    logger.info(f"Body: {request.get_data()}")


@app.after_request
def log_response_info(response):
    logger.info(f"Response: {response.status} {response.get_data()}")
    return response


@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Error: {str(e)}")
    response = {
        "error": str(e),
        "message": "An error occurred. Please try again later."
    }
    return jsonify(response), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "ratelimit exceeded",
        "message": "You have exceeded your request limit. Please try again later."
    }), 429


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            user_id = verify_token(token)
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/generate-password', methods=['GET'])
@token_required
@limiter.limit("10 per minute")
def generate_password():
    password = generate_random_password()
    return jsonify({'password': password})


@app.route('/encrypt-message', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def encrypt():
    data = request.json
    if not data or 'message' not in data:
        return jsonify({'error': 'Invalid input', 'message': 'Message is required.'}), 400
    message = data.get('message')
    try:
        key = retrieve_key()
        encrypted_message = encrypt_message(message, key)
        return jsonify({'encrypted_message': encrypted_message.decode()})
    except Exception as e:
        return handle_exception(e)


@app.route('/decrypt-message', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def decrypt():
    data = request.json
    if not data or 'encrypted_message' not in data:
        return jsonify({'error': 'Invalid input', 'message': 'Encrypted message is required.'}), 400
    encrypted_message = data.get('encrypted_message')
    try:
        key = retrieve_key()
        decrypted_message = decrypt_message(encrypted_message.encode(), key)
        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        return handle_exception(e)


if __name__ == '__main__':
    # Ensure a key is generated and stored before starting the server
    try:
        retrieve_key()
    except FileNotFoundError:
        generate_and_store_key()
    app.run(debug=True)
