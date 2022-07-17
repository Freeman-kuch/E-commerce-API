import datetime, os
from flask import Flask
from Resources.reshup import Items, Carts, Login_Users, New_User, Logout, home, category, item, token_renewal, Admins_Only
from flask_restful import Api
from flask_jwt_extended import JWTManager
from common.model import Blacklist_Token

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQL_THINGY")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_SECRET_KEY"] = os.getenv("API_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=1)
jwt = JWTManager(app)
api = Api(app)

@app.before_first_request
def tables():
    db.create_all()

@jwt.token_in_blocklist_loader  # the error
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = Blacklist_Token.find_token(jti)
    return token is not None



api.add_resource(home, "/home", "/")  # all set
api.add_resource(category, "/category/<string:section>")  # all set
api.add_resource(item, "/item/<string:item>")  # all set
api.add_resource(Admins_Only, "/users")  #
api.add_resource(Carts, "/cart")  # all set
api.add_resource(Items, "/items")  # all set
api.add_resource(Login_Users, "/login/")  # all set
api.add_resource(New_User, "/signup/")  # all set
api.add_resource(token_renewal, "/refresh")
api.add_resource(Logout, "/logout")  # all set


if __name__ == "__main__":
    from db import db
    db.init_app(app)
    app.run(debug=True)