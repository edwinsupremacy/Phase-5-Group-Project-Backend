from flask import Blueprint, make_response
from flask_restful import Api, Resource, reqparse
from app import db, bcrypt
from models import Admin

admin_bp = Blueprint('admin', __name__)
api = Api(admin_bp)

class RegisterAdminResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', required=True, help="Username cannot be blank")
        parser.add_argument('email', required=True, help="Email cannot be blank")
        parser.add_argument('password', required=True, help="Password cannot be blank")
        parser.add_argument('phone', required=True, help="Phone cannot be blank")
        args = parser.parse_args()

        if Admin.query.filter_by(email=args['email']).first():
            return make_response({'message': 'Email already exists'}, 400)

        new_admin = Admin(
            username=args['username'],
            email=args['email'],
            password_hash=bcrypt.generate_password_hash(args['password']).decode('utf-8')
        )
        db.session.add(new_admin)
        db.session.commit()

        return make_response({'message': 'Admin registered successfully'}, 201)

class LoginAdminResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', required=True, help="Username cannot be blank")
        parser.add_argument('password', required=True, help="Password cannot be blank")
        args = parser.parse_args()

        admin = Admin.query.filter_by(username=args['username']).first()

        if admin and admin.check_password(args['password']):
            return make_response({'message': 'Login successful'}, 200)
        else:
            return make_response({'message': 'Invalid username or password'}, 401)

api.add_resource(RegisterAdminResource, '/register')
api.add_resource(LoginAdminResource, '/login')
