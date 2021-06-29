from flask import Flask, request, Response, jsonify, make_response, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import getpass
import uuid

app = Flask(__name__)

app.config['SECRET_KEY']='YOUR_SECRET_KEY_HERE'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///./users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 

db = SQLAlchemy(app)   

class Users(db.Model):  
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.Integer)  
  name = db.Column(db.String(50))
  password = db.Column(db.String(50))
  admin = db.Column(db.Boolean)
  token = db.Column(db.String(200))
  

if __name__ == '__main__':

    password = ''
    confirm = ' '
    while password != confirm:
        name = input("input username:")
        password = getpass.getpass('input password')
        confirm = getpass.getpass('input password again')

    hashed_password = generate_password_hash(password, method='sha256')
    try:
        new_user = Users(public_id=str(uuid.uuid4()), name=name, password=hashed_password, admin=False) 
        db.session.add(new_user)  
        db.session.commit()
        print(f'user {name} has been succefully added')   
    except Exception as e:
        print(f'exception message={str(e)}', file=sys.stdout)
