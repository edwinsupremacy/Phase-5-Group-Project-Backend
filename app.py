from flask import Flask, request, jsonify, make_response
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token
from flask_cors import CORS
from flask_migrate import Migrate
from datetime import timedelta
import os

app = Flask(__name__)

# Configure CORS
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auction.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret_key')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.before_request
def option_autoreply():
    if request.method == 'OPTIONS':
        resp = app.make_default_options_response()
        return resp

# Removed manual CORS header setting from after_request function

api = Api(app)

class User(db.Model):
    __tablename__ = 'users'
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

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class AdminRegister(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        username = args['username']
        password = args['password']

        existing_admin = Admin.query.filter_by(username=username).first()
        if existing_admin:
            return {'message': 'Admin already exists'}, 400

        new_admin = Admin(username=username)
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()

        return {'message': 'Admin registered successfully'}, 201

class AdminLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        username = args['username']
        password = args['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            access_token = create_access_token(identity=admin.id, expires_delta=timedelta(minutes=30))
            refresh_token = create_refresh_token(identity=admin.id)
            response = make_response({'access_token': access_token, 'refresh_token': refresh_token}, 200)
            return response
        response = make_response({'message': 'Invalid credentials'}, 401)
        return response

class AdminDelete(Resource):
    def delete(self, username):
        admin = Admin.query.filter_by(username=username).first()
        if admin:
            db.session.delete(admin)
            db.session.commit()
            return {'message': 'Admin deleted successfully'}, 200
        return {'message': 'Admin not found'}, 404

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    starting_price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)

class ItemList(Resource):
    def get(self):
        items = Item.query.all()
        return jsonify([{
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'starting_price': item.starting_price,
            'category': item.category,
            'image_url': item.image_url
        } for item in items])

    def post(self):
        data = request.get_json()
        new_item = Item(
            name=data['name'],
            description=data['description'],
            starting_price=data['starting_price'],
            category=data['category'],
            image_url=data['image_url']
        )
        db.session.add(new_item)
        db.session.commit()
        return jsonify({
            'id': new_item.id,
            'name': new_item.name,
            'description': new_item.description,
            'starting_price': new_item.starting_price,
            'category': new_item.category,
            'image_url': new_item.image_url
        })

class ItemResource(Resource):
    def get(self, item_id):
        item = Item.query.get_or_404(item_id)
        return jsonify({
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'starting_price': item.starting_price,
            'category': item.category,
            'image_url': item.image_url
        })

    def put(self, item_id):
        data = request.get_json()
        item = Item.query.get_or_404(item_id)
        item.name = data['name']
        item.description = data['description']
        item.starting_price = data['starting_price']
        item.category = data['category']
        item.image_url = data['image_url']
        db.session.commit()
        return jsonify({
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'starting_price': item.starting_price,
            'category': item.category,
            'image_url': item.image_url
        })

    def delete(self, item_id):
        item = Item.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item deleted'})

api.add_resource(RegisterResource, '/register')
api.add_resource(LoginResource, '/login')
api.add_resource(SellerRegister, '/register/seller')
api.add_resource(SellerLogin, '/login/seller')
api.add_resource(ItemList, '/items')
api.add_resource(ItemResource, '/items/<int:item_id>')
api.add_resource(AdminRegister, '/admin/register')
api.add_resource(AdminLogin, '/admin/login')
api.add_resource(AdminDelete, '/admin/<string:username>')

if __name__ == '__main__':
    app.run(debug=True)
