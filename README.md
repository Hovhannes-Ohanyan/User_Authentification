# User_Authentification

Prerequisites

Python 3.x
MongoDB
Flask
Flask-PyMongo
Flask-JWT-Extended
bcrypt

Endpoints

POST /registration: Register a new user. Provide a JSON body with "fullname," "email," and "password."

POST /login: Log in with a registered user. Provide a JSON body with "email" and "password." You'll receive an access token upon successful login.

POST /admin: Add  the "role" field for a user. Provide a user ID and the  role to assign to the user.
