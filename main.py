from bson import json_util
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from jsonschema import validate, ValidationError
from flask_jwt_extended import create_access_token, JWTManager
import bcrypt
import json
import secrets

app = Flask(__name__)

app.config["MONGO_URI"] = "mongodb://localhost:27017/data"

app.config["JWT_SECRET_KEY"] = secrets.token_hex(32)
jwt = JWTManager(app)

mongo = PyMongo(app)

users = mongo.db.users
id_count = 1

with open('user-schema.json', 'r') as user_schema:
    schema = json.load(user_schema)


@app.route('/get_users', methods=["GET"])
def get_users():
    user_list = list(users.find({}))
    return jsonify({"users": json.loads(json_util.dumps(user_list))})


@app.route('/registration', methods=["POST"])
def registration():
    global id_count
    data = request.get_json()
    fullname = data.get("fullname")
    email = data.get("email")
    password = data.get("password")
    try:
        validate(data, schema)
    except ValidationError as e:
        return jsonify({"error": e}), 400

    existing_user = mongo.db.users.find_one({"email": email})
    if existing_user:
        return jsonify({"Error": "User with this email already registered"}), 409
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = {
        "id": id_count,
        "fullname": fullname,
        "email": email,
        "password": hashed_password
    }
    id_count += 1
    mongo.db.users.insert_one(new_user)
    return jsonify({"message": "User successfully registered"}), 201


@app.route('/login', methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    user = users.find_one({"email": email})
    print(f"Email: {email}")
    print(f"Hashed Password: {user['password']}")

    if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        access_token = create_access_token(identity=user["email"])
        return jsonify({"message": "Login successful", "access_token": access_token}), 200
    else:
        return jsonify({"error": "invalid email or password"}), 404


@app.route("/admin", methods=["POST"])
def add_role():
    data = request.get_json()
    id = data.get("id")
    role = data.get("role")

    if id and role:
        user = users.find_one({"id": id})
        if user:
            users.update_one({"id": id}, {"$set": {"role": role}})
            return jsonify({"message": f"user with this {id} id already have this role {role}"})
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "Invalid input"}), 400


if __name__ == "__main__":
    app.run(debug=True)
