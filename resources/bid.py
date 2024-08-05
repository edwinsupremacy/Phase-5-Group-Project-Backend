from flask import Blueprint, request
from flask_restful import Api, Resource
from app import db
from models import Bid, Item, User

bid_bp = Blueprint('bid', __name__)
api = Api(bid_bp)

class BidResource(Resource):
    def post(self):
        data = request.get_json()
        item_id = data.get('item_id')
        user_id = data.get('user_id')
        amount = data.get('amount')

        item = Item.query.get(item_id)
        user = User.query.get(user_id)

        if not item or not user:
            return {'message': 'Item or User not found'}, 404

        new_bid = Bid(
            amount=amount,
            item_id=item_id,
            user_id=user_id
        )

        db.session.add(new_bid)
        db.session.commit()

        return {'message': 'Bid placed successfully'}, 201

    def get(self, bid_id):
        bid = Bid.query.get(bid_id)
        if not bid:
            return {'message': 'Bid not found'}, 404

        return {
            'id': bid.id,
            'amount': bid.amount,
            'item_id': bid.item_id,
            'user_id': bid.user_id,
            'item': {
                'name': bid.item.name,
                'description': bid.item.description,
                'starting_price': bid.item.starting_price,
                'category': bid.item.category,
                'image_url': bid.item.image_url
            },
            'user': {
                'username': bid.user.username,
                'email': bid.user.email,
                'phone_number': bid.user.phone_number
            }
        }

class BidListResource(Resource):
    def get(self):
        bids = Bid.query.all()
        return [{
            'id': bid.id,
            'amount': bid.amount,
            'item_id': bid.item_id,
            'user_id': bid.user_id
        } for bid in bids]

api.add_resource(BidListResource, '')
api.add_resource(BidResource, '/<int:bid_id>')
