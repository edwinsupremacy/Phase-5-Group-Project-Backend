from flask import Blueprint, request, jsonify
from flask_restful import Api, Resource, reqparse
from app import db, bcrypt, mail
from models import User
from flask_mail import Message

user_bp = Blueprint('user', __name__)
api = Api(user_bp)

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
            send_login_email(user.email)  # Send login email
            return {
                'access_token': access_token,
                'user_id': user.id
            }
        else:
            return {'message': 'Invalid credentials'}, 401

def send_login_email(email):
    msg = Message('Login Successful', recipients=[email])
    msg.body = 'You have successfully logged in.'
    mail.send(msg)

class VerifyUserResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required=True, help="Email cannot be blank")
        parser.add_argument('phone_number', required=True, help="Phone number cannot be blank")
        args = parser.parse_args()

        user = User.query.filter_by(email=args['email'], phone_number=args['phone_number']).first()

        if user:
            return {'message': 'User verified', 'user_id': user.id}, 200
        else:
            return {'message': 'User not found'}, 404

class ResetPasswordResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', required=True, help="User ID cannot be blank")
        parser.add_argument('new_password', required=True, help="New password cannot be blank")
        parser.add_argument('confirm_password', required=True, help="Confirm password cannot be blank")
        args = parser.parse_args()

        if args['new_password'] != args['confirm_password']:
            return {'message': 'Passwords do not match'}, 400

        user = User.query.get(args['user_id'])
        if user:
            user.password = bcrypt.generate_password_hash(args['new_password']).decode('utf-8')
            db.session.commit()
            send_reset_password_email(user.email)  # Send reset password email
            return {'message': 'Password updated successfully'}, 200
        else:
            return {'message': 'User not found'}, 404

def send_reset_password_email(email):
    msg = Message('Password Reset Successful', recipients=[email])
    msg.body = 'Your password has been successfully reset.'
    mail.send(msg)

api.add_resource(RegisterResource, '/register')
api.add_resource(LoginResource, '/login')
api.add_resource(VerifyUserResource, '/verify-user')
api.add_resource(ResetPasswordResource, '/reset-password')
