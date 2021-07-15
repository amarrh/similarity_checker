from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import bcrypt
import spacy
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.newdb
users = db["users"]

def userExist(username):
    if users.find({"Username": username}).count() > 0:
        return True
    else:
        return False
def invalidUsername(username):
    if users.find({"Username": username}).count() == 1:
        return False
    else:
        return True
def invalidPassword(username, password):
    hashed_pw = users.find({"Username": username})[0]["Password"]
    if bcrypt.hashpw(password.encode('utf-8'), hashed_pw) == hashed_pw:
        return False
    else:
        return True
def outOfTokens(username):
    tokens = users.find({"Username": username})[0]["Tokens"]
    if tokens > 0:
        return False
    else:
        return True
def decreaseTokens(username):
    tokens = users.find({"Username": username})[0]["Tokens"]
    users.update({"Username": username}, {
        "$set":{
            "Tokens": tokens-1
            }
        })
def invalidAdminPassword(password):
    hashed_pw = users.find({"Username": "admin"})[0]["Password"]

    if bcrypt.hashpw(password.encode('utf-8'), hashed_pw) == hashed_pw:
        return False
    else:
        return True

def refilTokens(username, tokens):
    oldTokens = users.find({"Username": username})[0]["Tokens"]
    users.update({"Username": username}, {
        "$set":{
            "Tokens": oldTokens + tokens
        }
    })


class Register(Resource):
    def post(self):
        dataP = request.get_json()

        username = dataP["username"]
        password = dataP["password"]

        if userExist(username):
            retJson = {
                "status": 301,
                "msg": "Username already exists."
            }
            return jsonify(retJson)

        password_h = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": password_h,
            "Tokens": 6
        })

        retJson = {
            "status": 200,
            "msg": "Successful."
        }
        return jsonify(retJson)


class Detect(Resource):
    def post(self):
        dataP = request.get_json()

        username = dataP["username"]
        password = dataP["password"]
        text1 = dataP["text1"]
        text2 = dataP["text2"]

        if invalidUsername(username):
            retJson = {
                "status": 301,
                "msg": "Invalid username."
            }
            return jsonify(retJson)

        if invalidPassword(username, password):
            retJson = {
                "status": 302,
                "msg": "Invalid password."
            }
            return jsonify(retJson)

        if outOfTokens(username):
            retJson = {
                "status": 303,
                "msg": "Out of tokens!"
            }
            return jsonify(retJson)

        nlp = spacy.load('en_core_web_sm') #natural language processing model, load modela koji radi provjeru slicnosti dokumenata
        text1 = nlp(text1) # iz stringa u nlp
        text2 = nlp(text2)

        ratio = text1.similarity(text2) # procent slicnosti, preko f-je similarity

        decreaseTokens(username)

        retJson = {
            "status": 200,
            "msg": "Similarity calculated.",
            "Similarity": ratio
        }

        return jsonify(retJson)


class Refill(Resource):
    def post(self):
        dataP = request.get_json()

        username = dataP["username"]
        password = dataP["password"]
        tokens = dataP["Tokens"]

        if invalidUsername(username):
            retJson = {
                "status": 301,
                "msg": "Invalid username."
            }
            return jsonify(retJson)

        if invalidAdminPassword(password):
            retJson = {
                "status": 304,
                "msg": "Invalid admin password."
            }
            return jsonify(retJson)

        refilTokens(username, tokens)

        retJson = {
            "status": 200,
            "msg": "Tokens added successfully."
        }
        return jsonify(retJson)


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")
api.add_resource(Refill, "/refill")


if __name__=="__main__":
    app.run(host="0.0.0.0")
