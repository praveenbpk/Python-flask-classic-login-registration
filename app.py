# Store this code in 'app.py' file

import json
import uuid
from flask import Flask, request, redirect, url_for, session, jsonify, make_response
from flask_restful import Resource, Api
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token,create_refresh_token,get_jwt_identity,jwt_required,get_jwt,JWTManager
import pymysql
import re
from blocklist import BLOCKLIST
app = Flask(__name__)
api = Api(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.config["BUNDLE_ERRORS"] = True


app.secret_key = "your secret key"


def mysqlconnect():
    # To connect MySQL database
    try:
        connection = pymysql.connect(
            host="localhost",
            user="root",
            password="User@123",
            db="userdata",
        )
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        return cursor, connection
    except Exception as e:
        return e


class UserRegister(Resource):
    def post(self):
        msg = ""
        cursor, connection = mysqlconnect()

        if (
            request.method == "POST"
            and "username" in request.form
            and "password" in request.form
            and "email" in request.form
        ):
            username = request.form["username"]
            password = request.form["password"]
            email = request.form["email"]
            cursor.execute("SELECT * FROM accounts WHERE email = % s", (email,))
            account = cursor.fetchone()
            if account:
                msg = "Account already exists !"
            elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                msg = "Invalid email address !"
            elif not re.match(r"[A-Za-z0-9]+", username):
                msg = "Username must contain only characters and numbers !"
            elif not username or not password or not email:
                msg = "Please fill out the form !"
            else:
                password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute(
                    "INSERT INTO accounts(username,password,email) VALUES ( % s, % s, % s)",
                    (
                        username,
                        password,
                        email,
                        
                    )
                )
                connection.commit()
                msg = "You have successfully registered !"
        return ({"message": msg}), 201


class UserLogin(Resource):        
    def post(self):
        msg = ""
        cursor, connection = mysqlconnect()
        if (
            request.method == "POST"
            and "email" in request.form
            and "password" in request.form
        ):
            email = request.form["email"]
            password = request.form["password"]
            cursor.execute(
                "SELECT * FROM accounts WHERE email  = % s",
                (
                    email
                ),
            )
            
            account = cursor.fetchone()
        if account:
            isPasscorrect = bcrypt.check_password_hash(account["password"],password)
            if isPasscorrect:
                print(account,'account')
                session["loggedin"] = True
                session["id"] = account["id"]
                session["email"] = account["email"]
                access_token = create_access_token(identity= account["id"],fresh=True)
                refresh_token =create_refresh_token(identity= account["id"])
                return {"access_token":access_token,
                        "refresh_token":refresh_token,
                        "user_name":account["username"],
                        "email":account["email"]
                        } , 201
        else:
            msg = "Unauthorized user"
            return ({"message": msg}), 401


class ForgetPassword(Resource):
    def post(self):
        msg = ""
        cursor, connection = mysqlconnect()
        if "login" in session:
            return redirect("/")
        if request.method == "POST":

            email = request.form["email"]

            token = str(uuid.uuid4())

            result = cursor.execute("SELECT * FROM accounts WHERE email = % s", [email])

            if result > 0:
                cursor, connection = mysqlconnect()
                cursor.execute(
                    "UPDATE accounts SET token = % s WHERE email =% s", [token, email]
                )

                connection.commit()
                cursor.close()
                msg = "Email already sent to your email"
                return msg
            else:
                msg = "email do not match"
                return json.dumps(msg), 401

        return json.dumps(msg)


class Reset(Resource):
    def post(self,token):
        print('welcome')
        msg = ""
        cursor, connection = mysqlconnect()
      
        if "login" in session:
            return redirect("/")
        if request.method == "POST":
            print(request.method,'drop')

            password = request.form["password"]
            token1 = str(uuid.uuid4())

            password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor, connection = mysqlconnect()
            cursor.execute("SELECT * FROM accounts WHERE token = % s", [token])
            user = cursor.fetchone
            if user :
                cursor, connection = mysqlconnect()
                cursor.execute(
                    "UPDATE accounts SET token = % s,password =% s WHERE token =% s", [token1,password,token]
                )
                connection.commit()   
                cursor.close()
                msg = "Your password successfully Updated"

                return json.dumps(msg), 201
            else:
                msg ='Your token is invalid'
                return redirect('/')
        
        
class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token =create_access_token(identity=current_user,fresh=False)
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"access_token": new_token} 

api.add_resource(UserRegister, "/register")
api.add_resource(UserLogin, "/login")
api.add_resource(ForgetPassword, "/forgot")
api.add_resource(Reset, "/reset/<token>")
api.add_resource(TokenRefresh,'/refresh')


if __name__ == "__main__":

    app.run( host ="0.0.0.0",port = 5000 debug=True)

    # Driver Code
if __name__ == "__main__":
    mysqlconnect()
