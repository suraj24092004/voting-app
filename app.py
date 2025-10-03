from flask import Flask, request, jsonify, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies, get_jwt
)
from datetime import timedelta, datetime, timezone
import bcrypt
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "change-this-secret-in-prod")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT config: store tokens in cookies (HttpOnly)
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "another-change-in-prod")
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # If you enable, frontend must handle CSRF token
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)   # short-lived access
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)      # longer refresh

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)

# Candidate model already exists in your app (assumed)
class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    party = db.Column(db.String(120))
    votes = db.Column(db.Integer, default=0)

# Create DB
with app.app_context():
    db.create_all()

# Helper: hash & check password
def hash_password(plain_password: str) -> bytes:
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())

def check_password(plain_password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed)

# When token is in blocklist (revoked)
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload.get("jti")
    token = TokenBlocklist.query.filter_by(jti=jti).first()
    return token is not None

# Register endpoint
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "username already exists"}), 409

    hashed = hash_password(password)
    user = User(username=username, password_hash=hashed, is_admin=False)
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "user created"}), 201

# Login endpoint (sets cookies)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not check_password(password, user.password_hash):
        return jsonify({"msg": "Bad username or password"}), 401

    additional_claims = {"is_admin": user.is_admin}
    access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=user.id)
    resp = jsonify({"msg": "login successful"})
    # set tokens in cookies (HttpOnly)
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    return resp, 200

# Refresh endpoint (uses refresh cookie)
@app.route('/token/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    user = User.query.get(identity)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    additional_claims = {"is_admin": user.is_admin}
    access_token = create_access_token(identity=identity, additional_claims=additional_claims)
    resp = jsonify({"msg": "token refreshed"})
    set_access_cookies(resp, access_token)
    return resp, 200

# Logout: revoke current access and refresh tokens
@app.route('/api/logout', methods=['POST'])
@jwt_required()  # needs a valid access cookie to logout
def logout():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    # Also try to revoke refresh token if passed (optional)
    resp = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(resp)
    return resp, 200

# Example protected admin route
@app.route('/admin')
@jwt_required()
def admin_panel():
    claims = get_jwt()
    if not claims.get('is_admin', False):
        return jsonify({"msg": "Admin only"}), 403
    # render admin UI template
    return render_template("admin.html")

# Example protected API returning results (accessible to admin only)
@app.route('/api/results_protected')
@jwt_required()
def results_protected():
    claims = get_jwt()
    if not claims.get('is_admin', False):
        return jsonify({"msg": "Admins only"}), 403
    candidates = Candidate.query.all()
    data = [{"name": c.name, "party": c.party, "votes": c.votes} for c in candidates]
    return jsonify(data)

# Public results (your existing endpoint can remain)
@app.route('/api/results')
def results():
    candidates = Candidate.query.all()
    data = [{"name": c.name, "party": c.party, "votes": c.votes} for c in candidates]
    return jsonify(data)

if __name__ == 'main':
    app.run(debug=True)