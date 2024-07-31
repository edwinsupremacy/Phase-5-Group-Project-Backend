from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    _tablename_ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bids = db.relationship('Bid', backref='user', lazy=True)
    reviews = db.relationship('Review', backref='user', lazy=True)
    items = db.relationship('Item', backref='seller', lazy=True)
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    is_admin = db.Column(db.Boolean, default=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def _repr_(self):
        return '<Admin %r>' % self.username
class Item(db.Model):
    _tablename_ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.Text, nullable=True)
    starting_bid = db.Column(db.Numeric, nullable=False)
    current_bid = db.Column(db.Numeric, nullable=True)
    image_url = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    bids = db.relationship('Bid', backref='item', lazy=True)
    reviews = db.relationship('Review', backref='item', lazy=True)

class Bid(db.Model):
    _tablename_ = 'bids'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Numeric, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Transaction(db.Model):
    _tablename_ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Numeric, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)
    item = db.relationship('Item', backref='transactions')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref='transactions')
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.id'), nullable=False)
    payment = db.relationship('Payment', backref='transactions')

    @property
    def item_name(self):
        return self.item.name if self.item else 'Unknown'

    @property
    def payment_amount(self):
        return str(self.amount)