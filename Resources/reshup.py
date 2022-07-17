import datetime
from flask_restful import Resource, reqparse, fields, marshal_with
from common.model import cart, items, Users, Blacklist_Token
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import jwt_required, current_user, create_access_token, create_refresh_token, get_jwt_identity,  get_jwt, verify_jwt_in_request, get_current_user
from functools import wraps
from flask import jsonify

""" werkzeug.security.check_password_hash(pwhash, password)
          Check a password against a given salted and hashed password value(pwhash). In order to support unsalted legacy passwords this method supports plain text passwords, md5 and sha1 hashes (both salted and unsalted).
          Returns True if the password matched, False otherwise.
           werkzeug.security.generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
          Hash a password with the given method and salt with a string of the given length. The format of the string returned includes the method that was used so that check_password_hash() can check the hash."""
parser = reqparse.RequestParser()
parser.add_argument("name", type=str, required=True, help="This field can't be left Blank",)
parser.add_argument("item_id", type=int, required=True, help="This field can't be left Blank")
parser.add_argument("category", type=str, required=True, help="This field can't be left Blank")
parser.add_argument("sub_category", type=str, required=True, help="This field can't be left Blank")
parser.add_argument("price", type=int, required=True, help="This field can't be left Blank")
parser.add_argument("description", type=str, required=True, help="This field can't be left Blank")
# you can use the location arguments to change where the parser will look for arguments
cart_parser = reqparse.RequestParser()
cart_parser.add_argument("item_id", type=int, required=True, help="this field must be specified")
cart_parser.add_argument("cart_id", type=int, help="this field must be specified")

user_parser = reqparse.RequestParser()
user_parser.add_argument("user_id", type=str, help="This field can't be left Blank", required=False)
user_parser.add_argument("fullname", type=str, help="This field can't be left Blank", required=False)
user_parser.add_argument("username", type=str, help="This field can't be left Blank", required=True)
user_parser.add_argument("password", type=str, help="This field can't be left Blank", required=True)
user_parser.add_argument("admin", type=bool, help="This field can't be left Blank", required=False )


class Items(Resource):
    @jwt_required(optional=True)
    def post(self):
        req_data = parser.parse_args()
        item_data = {"name": req_data.get("name"),
                     "category": req_data.get("category"),
                     "sub_category": req_data.get("sub_category"),
                     "price": req_data.get("price"),
                     "description": req_data.get("description")
                     }
        new_item = items(**item_data)
        try:
            items.adding_new(new_item)
        except ValueError as exc:
            return {"error": "Failed"}, 400
        return {"message": "new item successfully added"}, 201


    @jwt_required(optional=True)
    def patch(self):
        req_data = parser.parse_args()  # this data is a dictionary
        update_id = req_data.get("item_id")  # fetch the data in id(because all items have uniques ID) from user input
        update_data = items.find_item(update_id)  # now you either have the item you want to query or you get a 404 error  THIS NEEDS TO BE LOOKED AT
        for key, value in req_data.items():
            setattr(update_data, key, value)  # fetches an attribute and changes the value
            items.updating_item()
        return {"message": "item successfully Updated"}, 201


    @jwt_required(optional=True)
    def delete(self):
        req_data = parser.parse_args()
        delete_id = req_data.get("item_id")  # fetch the data in id from user input
        delete_data = items.find_item(delete_id)
        items.delete_order(delete_data)
        return {"message": "item successfully deleted"}, 204


class Carts(Resource):
    @jwt_required()
    def post(self):
        orders_req = cart_parser.parse_args(strict=True)
        for order in orders_req:  # in cases of multiple orders to be added to cart!
            order_data = {"item_id": order.get("item_id")}
            new_order = cart(**order_data)
            cart.adding_new(new_order)
        return {"message": "new item successfully added to your cart!"}, 201

    @jwt_required()
    def patch(self):
        orders_req = cart_parser.parse_args(strict=True)
        order_id = orders_req.get("cart_id")
        update_data = cart.find_order(order_id)
        for key, value in orders_req.items():
            setattr(update_data, key, value)
            cart.updating_order()
        return {"message": "item successfully Updated"}, 201

    @jwt_required()
    def delete(self):
        orders_req = cart_parser.parse_args(strict=True)
        order_id = orders_req.get("cart_id")
        delete_ord = cart.find_order(order_id)
        cart.delete_order(delete_ord)
        return {"message": "item successfully been removed from your Cart!"}, 204

    @jwt_required(fresh=True)
    def get(self):
        order = cart.query.all()
        if not order:
            return {"message": "you do not have any item in your cart"}
        return jsonify(cart=cart.query.order_by(cart.id).all())  # Use the fields setting to manipulate this


class Login_Users(Resource):
    def post(self):
        data = user_parser.parse_args()
        data_username = Users.find_user(data.get("username"))  # find a way to Query the database better
        if not data_username:  # this returns the object of the class with the username, you can now query this object for the different attributes
            return {"error": "Invalid Username or Password!"}, 401
        if not check_password_hash(data_username.password, data.get("password")):
            return {"error": "Invalid Username or Password!"}, 401
        if not data_username.admin:
            access_token = create_access_token(identity=data_username.username, fresh=True, expires_delta=datetime.timedelta(minutes=15))
            refresh_token = create_refresh_token(data_username.username)
            return jsonify({
                "access_token": access_token,
                "refresh_token": refresh_token
            })
        access_token = create_access_token(identity=data_username.username,
                                           fresh=True,
                                           expires_delta=datetime.timedelta(minutes=15),
                                           additional_claims={"access": "admin"})
        refresh_token = create_refresh_token(identity=data_username.username)
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token
        })

    @jwt_required(fresh=True)
    def get(self):
        return jsonify({"welcome": current_user.username})  # trial an error scenario... should work


Users_fields = {
    "user_id": fields.Integer,
    "username": fields.String,
    "fullname": fields.String,
    "password": fields.String,
    "admin": fields.Boolean
}
def wrapper(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        if claims.get("access"):
            return func(*args, **kwargs)
        return {"error": "Admins Only route"}, 403
    return decorator


class Admins_Only(Resource):
    @wrapper
    @marshal_with(Users_fields, envelope="All_Users")
    def get(self):
        return Users.All_users()

    # TODO: add some routes to delete user, and grant user, admin function


class New_User(Resource):
    def post(self):
        data = user_parser.parse_args()
        new_User_data = Users.find_user(data.get("username"))
        if new_User_data:
            return {"message": "User %s already exists!" % data.get("username")}, 401
        new_data = {
            "user_id": data.get("user_id"),
            "username": data.get("username"),
            "fullname": data.get("fullname"),
            "password": generate_password_hash(data.get("password")),
            "admin": data.get("admin")
        }
        new_user = Users(**new_data)
        Users.new_user(new_user)
        return {"message": "account created"}, 201


response_field = {
    "item_code": fields.Integer(attribute="item_id"),
    "name": fields.String,
    "category": fields.String,
    "sub_category": fields.String,
    "price": fields.Integer,
    "description": fields.String
}
class home(Resource):
    @marshal_with(response_field)
    def get(self):
        return items.query.order_by(items.name).all()


class category(Resource):
    @marshal_with(response_field, envelope="Categories")
    def get(self, section):
        return items.find_by_category(section), 202


class item(Resource):
    @marshal_with(response_field, envelope="Items")
    def get(self, item):
        return items.find_by_name(item), 202


class Logout(Resource):
    @jwt_required()
    def delete(self):
        User_identity = get_jwt_identity()
        data_username = Users.find_user(User_identity)
        ID = data_username.user_id
        access = get_jwt()["jti"]
        time = datetime.datetime.now(datetime.timezone.utc)
        new_data = Blacklist_Token(token_identifier=access, created_at=time, user_id=ID)
        Blacklist_Token.new_user(new_data)  # this saves in the database as a blacklisted token issue is, it's not adding a user_id
        return {"message": "Logout Successful"}


class token_renewal(Resource):
    @jwt_required(refresh=True)
    def post(self):
        User_identity = get_jwt_identity()
        data_username = Users.find_user(User_identity)  # find a way to Query the database better
        if data_username.admin:
            access_token = create_access_token(identity=data_username.username,
                                               fresh=False,
                                               expires_delta=datetime.timedelta(minutes=15),
                                               additional_claims={"access": "admin"})
            return jsonify(access_token=access_token)
        access_token = create_access_token(identity=data_username.username,
                                           fresh=False,
                                           expires_delta=datetime.timedelta(minutes=15))
        return jsonify(access_token=access_token)