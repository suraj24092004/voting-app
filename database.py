from flask_sqlalchemy import SQLAlchemy
from flask import Flask

db = SQLAlchemy()

def init_db(app):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/voting.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    return app

# Tables
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    aadhaar = db.Column(db.String(12), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)  
    has_voted = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)  # ✅ OTP verification status
    otp_code = db.Column(db.String(6)) 
    face_encoding = db.Column(db.PickleType)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(100), nullable=False)
    votes = db.Column(db.Integer, default=0)


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
def init_db(app):
    db.init_app(app)
    with app.app_context():
     db.create_all()
   
