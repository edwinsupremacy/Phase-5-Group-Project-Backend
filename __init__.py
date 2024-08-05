from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_mail import Mail
from flask_migrate import Migrate
from .config import Config


db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()
cors = CORS()
mail = Mail()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    cors.init_app(app, resources={r"/*": {"origins": "http://localhost:5173"}})
    mail.init_app(app)
    migrate.init_app(app, db)

    from resources.user import user_bp
    from resources.admin import admin_bp
    from resources.item import item_bp
    from resources.bid import bid_bp

    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(item_bp, url_prefix='/items')
    app.register_blueprint(bid_bp, url_prefix='/bids')

    return app
