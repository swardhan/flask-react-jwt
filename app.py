import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token)
from passlib.apps import custom_app_context as pwd_context

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'secret'

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(32)) 
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

@app.route('/users/register', methods=['POST'])
def register():
	full_name = request.get_json()['full_name']
	username = request.get_json()['username']
	password = request.get_json()['password']

	if username is None or password is None or full_name is None:
	    abort(400)    # missing arguments
	if User.query.filter_by(username=username).first() is not None:
	    abort(400)    # existing user

	user = User(username=username, full_name=full_name)
	user.hash_password(password)

	result = {
		'full_name' : full_name,
		'username' : username,
	}

	db.session.add(user)
	db.session.commit()
	return jsonify({'result' : result})

@app.route('/users/login', methods=['POST'])
def login():
    username = request.get_json()['username']
    password = request.get_json()['password']
    result = ""
    user = User.query.filter_by(username=username).first()

    if user.verify_password(password):
        access_token = create_access_token(identity = {'full_name': user.full_name,'username': user.username})
        result = access_token
    else:
        result = jsonify({"error":"Invalid username and password"})
    
    return result

@app.route('/')
def index():
	return "Hello"

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        db.create_all()
    app.run(debug=True)