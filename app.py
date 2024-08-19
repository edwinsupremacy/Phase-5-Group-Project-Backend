from flask_restful import Api, Resource, reqparse
from flask import Flask, abort, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from requests.auth import HTTPBasicAuth
from flask_bcrypt import Bcrypt

from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token
from flask_cors import CORS
from flask_migrate import Migrate
import requests
from flask import abort
from flask_mail import Mail, Message
from datetime import timedelta
import random
import base64
import string
from flask_mail import Message
import datetime
from datetime import datetime
import logging
from flask_jwt_extended import get_jwt_identity, jwt_required
import os

bcrypt = Bcrypt()
app = Flask(__name__)
mail = Mail(app)
bcrypt = Bcrypt(app)

CORS(app, resources={r"/*": {"origins": "https://edwinsupremacy.github.io"}})


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auction.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret_key')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'vintageauction4@gmail.com'
app.config['MAIL_PASSWORD'] = 'cdud eapr jxqp iinw'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'vintageauction4@gmail.com'
mail = Mail(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.before_request
def option_autoreply():
    if request.method == 'OPTIONS':
        resp = app.make_default_options_response()
        return resp

api = Api(app)
def send_email(to, subject, body):
    msg = Message(subject, sender="vintageauction4@gmail.com", recipients=[to])
    msg.body = body
    mail.send(msg)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    verification_code = db.Column(db.String(5), nullable=True)

    def __init__(self, username, email, phone_number, password):
        self.username = username
        self.email = email
        self.phone_number = phone_number
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.verification_code = None  

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class UserListResource(Resource):
    def get(self):
        users = User.query.all()  
        users_list = [{'id': user.id, 'username': user.username, 'email': user.email} for user in users]  
        return jsonify(users_list)

class UserDeleteResource(Resource):
     def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        
        Bid.query.filter_by(user_id=user_id).delete()
        
        db.session.delete(user)
        db.session.commit()
        
        return {"message": "User and associated bids deleted successfully!"}, 200


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
        send_registration_email(email)

        return {'message': 'User registered successfully'}, 201

def send_registration_email(email):
    msg = Message('Registration Successful', recipients=[email])
    msg.body = 'Congratulations! You have successfully registered and welcome to vintage auctions'
    mail.send(msg)
class LoginResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True, help='email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        username_or_email = args['email']
        password = args['password']

        # Try to find the user by username or email
        user = User.query.filter( (User.email == username_or_email)).first()
        
        if user:
            print(f"Input password: {password}") 
            print(f"Stored password hash: {user.password}") 

            if bcrypt.check_password_hash(user.password, password):
                print("Password matched successfully")
                access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=30))
                refresh_token = create_refresh_token(identity=user.id)
                send_login_email(user.email)
                return {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'user_id': user.id
                }, 200
            else:
                print("Password did not match")
                return {'message': 'Invalid credentials'}, 401
        else:
            return {'message': 'User not found'}, 404

def send_login_email(email):
    msg = Message('Login Successful', recipients=[email])
    msg.body = 'You have successfully logged in.'
    mail.send(msg)
class Seller(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(20), nullable=False)

    def __init__(self, username, email, password, phone):
        self.username = username
        self.email = email
        self.password = password
        self.phone = phone
class SellerRegister(Resource):
    def post(self):
        data = request.get_json()

        if not all(key in data for key in ('username', 'email', 'password', 'phone')):
            return {'message': 'Missing required fields'}, 400

        if Seller.query.filter_by(email=data['email']).first() or Seller.query.filter_by(username=data['username']).first():
            return {'message': 'User already exists'}, 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        new_seller = Seller(
            username=data['username'],
            email=data['email'],
            password=hashed_password,
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
class SellerList(Resource):
    def get(self):
        sellers = Seller.query.all()
        sellers_data = [
            {
                'id': seller.id,
                'username': seller.username,
                'email': seller.email,
                'phone': seller.phone
            }
            for seller in sellers
        ]
        return {'sellers': sellers_data}, 200
class SellerDelete(Resource):
    def delete(self, seller_id):
        seller = Seller.query.get(seller_id)
        if not seller:
            return {'message': 'Seller not found'}, 404

        db.session.delete(seller)
        db.session.commit()
        return {'message': 'Seller deleted successfully'}, 200
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
    sub_category = db.Column(db.String(100), nullable=False)  
    image_url = db.Column(db.String(255), nullable=False)
    payments = db.relationship('Payment', backref='item', lazy=True)

class ItemList(Resource):
    def get(self):
        items = Item.query.all()
        return jsonify([{
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'starting_price': item.starting_price,
            'category': item.category,
            'sub_category': item.sub_category,  
            'image_url': item.image_url
        } for item in items])


def post(self):
    data = request.get_json()
    if not data.get('name') or not data.get('starting_price'):
        abort(400, description="Name and Starting Price are required.")

    new_item = Item(
        name=data['name'],
        description=data['description'],
        starting_price=data['starting_price'],
        category=data['category'],
        sub_category=data['sub_category'], 
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
        'sub_category': new_item.sub_category,
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
    
    item.name = data.get('name', item.name)
    item.description = data.get('description', item.description)
    item.starting_price = data.get('starting_price', item.starting_price)
    item.category = data.get('category', item.category)
    item.sub_category = data.get('sub_category', item.sub_category)
    item.image_url = data.get('image_url', item.image_url)

    db.session.commit()
    return jsonify({
        'id': item.id,
        'name': item.name,
        'description': item.description,
        'starting_price': item.starting_price,
        'category': item.category,
        'sub_category': item.sub_category,
        'image_url': item.image_url
    })

def delete(self, item_id):
        item = Item.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item deleted'}) 
class VerifyUserResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required=True, help="Email cannot be blank")
        parser.add_argument('phone_number', required=True, help="Phone number cannot be blank")
        args = parser.parse_args()

        user = User.query.filter_by(email=args['email'], phone_number=args['phone_number']).first()

        if user:
            verification_code = ''.join(random.choices(string.digits, k=5))
            user.verification_code = verification_code
            db.session.commit()
            send_verification_email(user.email, verification_code)

            return {'message': 'Verification code sent', 'user_id': user.id}, 200
        else:
            return {'message': 'User not found'}, 404

def send_verification_email(email, code):
    msg = Message('Password Reset Verification Code', recipients=[email])
    msg.body = f'Your password reset verification code is {code}.'
    mail.send(msg)
class ResetPasswordResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', required=True, help="User ID cannot be blank")
        parser.add_argument('new_password', required=True, help="New password cannot be blank")
        parser.add_argument('confirm_password', required=True, help="Confirm password cannot be blank")
        parser.add_argument('verification_code', required=True, help="Verification code cannot be blank")
        args = parser.parse_args()

        if args['new_password'] != args['confirm_password']:
            return {'message': 'Passwords do not match'}, 400

        user = User.query.get(args['user_id'])
        if user and user.verification_code == args['verification_code']:
            hashed_password = bcrypt.generate_password_hash(args['new_password']).decode('utf-8')
            print(f"Generated hashed password: {hashed_password}")  # Debugging statement
            user.password = hashed_password
            user.verification_code = None
            db.session.commit()
            send_reset_password_email(user.email)
            return {'message': 'Password updated successfully'}, 200
        else:
            return {'message': 'Invalid verification code or user not found'}, 404

def send_reset_password_email(email):
    msg = Message('Password Reset Successful', recipients=[email])
    msg.body = 'Your password has been successfully reset.'
    mail.send(msg)


class Bid(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='Pending', nullable=False)  # New status field

    item = db.relationship('Item', backref='bids')
    user = db.relationship('User', backref='bids')

class BidResource(Resource):
    def post(self):
        data = request.get_json()

        try:
            amount = float(data.get('amount'))
        except (TypeError, ValueError):
            return {'error': 'Invalid bid amount'}, 400

        item_id = data.get('item_id')
        user_id = data.get('user_id')

        if amount is None or item_id is None or user_id is None:
            return {'error': 'Bid amount, item ID, and user ID are required'}, 400

        if amount <= 0:
            return {'error': 'Bid amount must be greater than zero'}, 400

        item = Item.query.get(item_id)
        if not item:
            return {'error': 'Item not found'}, 404

        # Create a new bid
        new_bid = Bid(amount=amount, item_id=item_id, user_id=user_id)
        db.session.add(new_bid)
        db.session.commit()

        return {
            'message': 'Bid placed successfully',
            'bid': {
                'id': new_bid.id,
                'amount': new_bid.amount,
                'item_id': new_bid.item_id,
                'user_id': new_bid.user_id
            }
        }, 201
class BidActionResource(Resource):
    def put(self, bid_id):
        bid = Bid.query.get_or_404(bid_id)
        data = request.get_json()

        new_status = data.get('status')

        if new_status not in ['Accepted', 'Rejected']:
            return {'error': 'Invalid status'}, 400

        bid.status = new_status
        db.session.commit()

        return {'message': 'Bid status updated successfully'}, 200

class BidsResource(Resource):
    def get(self, item_id):
        item = Item.query.get_or_404(item_id)
        bids = Bid.query.filter_by(item_id=item.id).order_by(Bid.amount.desc()).all()
        bids_list = [{'id': bid.id, 'username': bid.user.username, 'amount': bid.amount, 'status': bid.status} for bid in bids]
        return {'bids': bids_list}, 200

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('amount', required=True, type=float, help="Amount is required")
        parser.add_argument('user_id', required=True, type=int, help="User ID is required")
        parser.add_argument('item_id', required=True, type=int, help="Item ID is required")
        args = parser.parse_args()

        user = User.query.get_or_404(args['user_id'])
        item = Item.query.get_or_404(args['item_id'])

        new_bid = Bid(amount=args['amount'], user_id=args['user_id'], item_id=args['item_id'])
        db.session.add(new_bid)
        db.session.commit()

        return {'message': 'Bid placed successfully'}, 201

class DeleteBidResource(Resource):
    def delete(self, bid_id):
        bid = Bid.query.get_or_404(bid_id)
        db.session.delete(bid)
        db.session.commit()
class UserBidsResource(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity() 
        
        bids = Bid.query.filter_by(user_id=user_id).order_by(Bid.amount.desc()).all()
        bids_list = [{'id': bid.id, 'item': bid.item.name, 'amount': bid.amount, 'status': bid.status} for bid in bids]
        
        return {'bids': bids_list}, 200
@app.route('/items/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    Bid.query.filter_by(item_id=item_id).delete()  # Delete all associated bids
    db.session.delete(item)
    db.session.commit()
    return '', 204
class LiveBidResource(Resource):
    def post(self, item_id):
        item = Item.query.get(item_id)
        if not item:
            return {'message': 'Item not found'}, 404
        item.live = True
        db.session.commit()
        return {'message': 'Live bid started for item {}'.format(item.name)}, 200

    def delete(self, item_id):
        item = Item.query.get(item_id)
        if not item:
            return {'message': 'Item not found'}, 404
        item.live = False
        db.session.commit()
        return {'message': 'Live bid ended for item {}'.format(item.name)}, 200

def send_login_email(email):
    msg = Message('Login Successful', recipients=[email])
    msg.body = 'You have successfully logged in.'
    mail.send(msg)

def send_reset_password_email(email):
    msg = Message('Password Reset Successful', recipients=[email])
    msg.body = 'Your password has been successfully reset.'
    mail.send(msg)
def send_login_email(email):
    try:
        msg = Message('Login Successful', recipients=[email])
        msg.body = 'You have successfully logged in.'
        mail.send(msg)
    except Exception as e:
        logging.error(f"Failed to send login email: {str(e)}")

def send_reset_password_email(email):
    try:
        msg = Message('Password Reset Successful', recipients=[email])
        msg.body = 'Your password has been successfully reset.'
        mail.send(msg)
    except Exception as e:
        logging.error(f"Failed to send reset password email: {str(e)}")

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reviewName = db.Column(db.String(80), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    reviewMessage = db.Column(db.Text, nullable=False)

    def __init__(self, reviewName, rating, reviewMessage):
        self.reviewName = reviewName
        self.rating = rating
        self.reviewMessage = reviewMessage

class ReviewResource(Resource):
    def post(self):
        data = request.get_json()
        new_review = Review(reviewName=data['reviewName'], rating=data['rating'], reviewMessage=data['reviewMessage'])
        db.session.add(new_review)
        db.session.commit()
        return {"message": "Review added successfully!"}, 201
    
    def get(self):
        reviews = Review.query.all()
        return [{'id': r.id, 'reviewName': r.reviewName, 'rating': r.rating, 'reviewMessage': r.reviewMessage} for r in reviews]

class DeleteReviewResource(Resource):
    def delete(self, review_id):
        review = Review.query.get_or_404(review_id)
        db.session.delete(review)
        db.session.commit()
        return {"message": "Review deleted successfully!"}, 204

def get_mpesa_access_token():
    consumer_key = '35KRcaSFHWxRKu3gLWgG3JgpAGUKA78rRA7BjeE2vN529tXJ'
    consumer_secret = 'xg4wAfPda9wGseSk5AN6yAoV6vAGNp4229esahXvARoxCRhXiCxxj33eR8q6eFp6'
    api_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'

    response = requests.get(api_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    token = response.json().get('access_token')
    return token

def get_mpesa_access_token():
    consumer_key = '35KRcaSFHWxRKu3gLWgG3JgpAGUKA78rRA7BjeE2vN529tXJ'
    consumer_secret = 'xg4wAfPda9wGseSk5AN6yAoV6vAGNp4229esahXvARoxCRhXiCxxj33eR8q6eFp6'
    api_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'

    response = requests.get(api_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    token = response.json().get('access_token')
    return token

def initiate_payment(phone_number, amount):
    try:
        access_token = get_mpesa_access_token()
        api_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
        headers = {'Authorization': f'Bearer {access_token}'}

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        short_code = '174379'
        passkey = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'
        password = base64.b64encode(f'{short_code}{passkey}{timestamp}'.encode()).decode()

        # Ensure the phone number is in the correct format
        phone_number = phone_number.strip()
        if not phone_number.startswith('254'):
            phone_number = '254' + phone_number[1:]

        payload = {
            'BusinessShortCode': short_code,
            'Password': password,
            'Timestamp': timestamp,
            'TransactionType': 'CustomerPayBillOnline',
            'Amount': amount,
            'PartyA': phone_number,
            'PartyB': '174379',
            'PhoneNumber': phone_number,
            'CallBackURL': 'https://phase-5-group-project-backend-1.onrender.com/callback',
            'AccountReference': phone_number,
            'TransactionDesc': 'Payment for event',
        }

        logging.info(f"Payload: {payload}")

        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info(f"Response: {response.json()}")
        if 'CheckoutRequestID' not in response.json():
            logging.error(f"MPesa API response missing 'CheckoutRequestID': {response.json()}")
            return {'error': 'Failed to initiate payment'}

        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error initiating payment: {e}")
        if e.response:
            logging.error(f"Response content: {e.response.content}")
        return {'error': 'Failed to initiate payment'}
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    transaction_id = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
class PayResource(Resource):
    def post(self):
        data = request.get_json()
        item_id = data.get('item_id')
        if not item_id:
               return {'message': 'item_id is required'}, 400

        amount = data.get('amount')
        phone_number = data.get('phone_number')
        transaction_id = data.get('transaction_id')
        status = data.get('status', 'Pending')
        user_id = data.get('user_id')
        new_payment = Payment(
            amount=amount,
            phone_number=phone_number,
            transaction_id=transaction_id,
            status=status,
            timestamp=datetime.utcnow(),
            user_id=user_id,
            item_id=item_id
        )

        db.session.add(new_payment)
        db.session.commit()

        return {'message': 'Payment created successfully'}, 201


class ItemPaymentsResource(Resource):
    def get(self, item_id):
        # Fetch all payments related to the specific item
        item = Item.query.get_or_404(item_id)
        payments = Payment.query.filter_by(item_id=item.id).all()
        
        return [{
            'id': payment.id,
            'amount': payment.amount,
            'phone_number': payment.phone_number,
            'transaction_id': payment.transaction_id,
            'status': payment.status,
            'timestamp': payment.timestamp
        } for payment in payments], 200


api.add_resource(PayResource, '/checkout/pay')
api.add_resource(ItemPaymentsResource, '/items/<int:item_id>/payments')
api.add_resource(RegisterResource, '/register')
api.add_resource(LoginResource, '/login')
api.add_resource(VerifyUserResource, '/verify-user')
api.add_resource(ResetPasswordResource, '/reset-password')
api.add_resource(SellerRegister, '/register/seller')
api.add_resource(SellerLogin, '/login/seller')
api.add_resource(AdminRegister, '/admin/register')
api.add_resource(AdminDelete, '/admin/<string:username>')
api.add_resource(AdminLogin, '/admin/login')
api.add_resource(ItemList, '/items')
api.add_resource(ItemResource, '/items/<int:item_id>')
api.add_resource(BidResource, '/bids')
api.add_resource(DeleteBidResource, '/bids/<int:bid_id>')
api.add_resource(UserListResource, '/users') 
api.add_resource(UserDeleteResource, '/users/delete/<int:user_id>')
api.add_resource(ReviewResource, '/reviews')
api.add_resource(DeleteReviewResource, '/reviews/<int:review_id>')
api.add_resource(SellerList, '/sellers')
api.add_resource(SellerDelete, '/sellers/delete/<int:seller_id>')
api.add_resource(BidsResource, '/items/<int:item_id>/bids')
api.add_resource(BidActionResource, '/bids/<int:bid_id>/action')
api.add_resource(UserBidsResource, '/user-bids')


if __name__ == '_main_':
    app.run(debug=True)