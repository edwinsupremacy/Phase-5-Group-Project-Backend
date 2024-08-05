from flask import Blueprint, request
from flask_restful import Api, Resource
from app import db
from models import Item

item_bp = Blueprint('item', __name__)
api = Api(item_bp)

class ItemResource(Resource):
    def get(self, item_id):
        item = Item.query.get(item_id)
        if not item:
            return {'message': 'Item not found'}, 404

        return {
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'starting_price': item.starting_price,
            'category': item.category,
            'image_url': item.image_url
        }

    def put(self, item_id):
        item = Item.query.get(item_id)
        if not item:
            return {'message': 'Item not found'}, 404

        data = request.get_json()
        item.name = data.get('name', item.name)
        item.description = data.get('description', item.description)
        item.starting_price = data.get('starting_price', item.starting_price)
        item.category = data.get('category', item.category)
        item.image_url = data.get('image_url', item.image_url)

        db.session.commit()

        return {'message': 'Item updated successfully'}

    def delete(self, item_id):
        item = Item.query.get(item_id)
        if not item:
            return {'message': 'Item not found'}, 404

        db.session.delete(item)
        db.session.commit()

        return {'message': 'Item deleted successfully'}

class ItemListResource(Resource):
    def get(self):
        items = Item.query.all()
        return [{
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'starting_price': item.starting_price,
            'category': item.category,
            'image_url': item.image_url
        } for item in items]

    def post(self):
        data = request.get_json()
        new_item = Item(
            name=data.get('name'),
            description=data.get('description'),
            starting_price=data.get('starting_price'),
            category=data.get('category'),
            image_url=data.get('image_url')
        )
        db.session.add(new_item)
        db.session.commit()

        return {'message': 'Item created successfully'}, 201

api.add_resource(ItemListResource, '')
api.add_resource(ItemResource, '/<int:item_id>')
