import datetime
from db import db

class cart(db.Model):
    cart_id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.item_id"), nullable=False)
    item = db.relationship("items", backref=db.backref('cart', lazy=True))

    @classmethod
    def find_order(cls, cart_id):
        return cls.query.filter_by(cart_id=cart_id).first_or_404()

    @classmethod
    def delete_order(cls, delete_data):
        db.session.delete(delete_data)
        db.session.commit()

    @classmethod
    def adding_new(cls, order):
        db.session.add(order)
        db.session.commit()

    @classmethod
    def updating_order(cls):
        db.session.commit()


class items(db.Model):
    item_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(30), nullable=False)
    sub_category = db.Column(db.String(30), nullable=False)
    price = db.Column(db.Integer, nullable=False, default=0)
    description = db.Column(db.Text, nullable=False)

    @classmethod
    def find_item(cls, item_id):
        return cls.query.filter_by(item_id=item_id).first_or_404()

    @classmethod
    def find_by_name(cls, name):
        return cls.query.filter_by(name=name).all()

    @classmethod
    def find_by_category(cls, category):
        return cls.query.filter_by(category=category).all()

    @classmethod
    def delete_order(cls, delete_data):
        db.session.delete(delete_data)
        db.session.commit()

    @classmethod
    def adding_new(cls, item):  # have to create an instance of this item to be in a general context
        db.session.add(item)
        db.session.commit()

    @classmethod
    def updating_item(cls):
        db.session.commit()


class Users(db.Model):
    user_id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(30), nullable=False, unique=True)
    fullname = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)  # see if we can implement this to help with the user access

    @classmethod
    def find_user(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def All_users(cls,):
        return cls.query.order_by(cls.username).all()

    @classmethod
    def new_user(cls, new_data):
        db.session.add(new_data)
        db.session.commit()

    @classmethod
    def delete_User(cls, delete_data):
        db.session.delete(delete_data)
        db.session.commit()

    @classmethod
    def query_all_users(cls):
        return cls.query.filter_by(cls.username).all()


class Blacklist_Token(db.Model):
    token_id = db.Column(db.Integer, primary_key=True)
    token_identifier = db.Column(db.String(36), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)  # take note the table doesn't have to have the first letter in caps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now(datetime.timezone.utc))

    @classmethod
    def new_user(cls, new_token):
        db.session.add(new_token)
        db.session.commit()

    @classmethod
    def find_token(cls, token_identifier):
        return db.session.query(Blacklist_Token.token_id).filter_by(token_identifier=token_identifier).scalar()
