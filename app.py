from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from flask_cors import CORS
from flask_migrate import Migrate
import os

app = Flask(_name_)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auction.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret_key')

db = SQLAlchemy(app)
migrate = Migrate(app, db)  
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

api = Api(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Seller(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(20), nullable=False)

    def __init__(self, username, email, password, phone):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.phone = phone

@app.before_request
def option_autoreply():
    if request.method == 'OPTIONS':
        resp = app.make_default_options_response()
        return resp

@app.route('/', methods=['OPTIONS'])
def handle_options():
    return jsonify({"message": "OK"}), 200

@app.route("/", methods=["GET", "POST"])
def hello_world():
    if request.method == "POST":
        # Handle POST request
        pass
    else:
        # Handle GET request
        return f"<p>Hello, World!</p>"

@app.route("/", methods=["GET"])
def hello_world_get():
    return f"<p>Hello, World!</p>"

@app.route("/", methods=["POST"])
def hello_world_post():
    # Handle POST request
    pass

class RegisterResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        phone_number = data.get('phone_number')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not all([username, email, phone_number, password, confirm_password]):
            return {'message': 'All fields are required'}, 400

        if password != confirm_password:
            return {'message': 'Passwords do not match'}, 400

        if User.query.filter_by(email=email).first():
            return {'message': 'Email already exists'}, 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, phone_number=phone_number, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User registered successfully'}, 201

class LoginResource(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return jsonify(access_token=access_token)
        else:
            return {'message': 'Invalid credentials'}, 401

class SellerRegister(Resource):
    def post(self):
        data = request.get_json()

        if not all(key in data for key in ('username', 'email', 'password', 'phone')):
            return {'message': 'Missing required fields'}, 400

        if Seller.query.filter_by(email=data['email']).first() or Seller.query.filter_by(username=data['username']).first():
            return {'message': 'User already exists'}, 400

        new_seller = Seller(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            phone=data['phone']
        )

        db.session.add(new_seller)
        db.session.commit()

        return {'message': 'Seller registered successfully'}, 201

class SellerLogin(Resource):
    def post(self):
        data = request.get_json()

        seller = Seller.query.filter_by(email=data['email']).first()

        if not seller or not bcrypt.check_password_hash(seller.password, data['password']):
            return {'message': 'Invalid credentials'}, 401

        return {'message': 'Logged in successfully'}, 200

api.add_resource(RegisterResource, '/register')
api.add_resource(LoginResource, '/login')
api.add_resource(SellerRegister, '/register/seller')
api.add_resource(SellerLogin, '/login/seller')

if __name__ == '_main_':
    app.run(debug=True)
