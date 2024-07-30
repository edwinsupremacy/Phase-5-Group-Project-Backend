from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from models import User, Bid, Review, Item, Admin, Category, Payment, Transaction

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auction.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)



@app.route('/')
def home():
    return 'Welcome to the Auction Platform!'

if __name__ == '__main__':
    app.run(debug=True)
