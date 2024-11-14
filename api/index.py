from flask import Flask, jsonify, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import shortuuid
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Link(db.Model):
    __tablename__ = 'links'
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_code = db.Column(db.String(10), unique=True, nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# API Routes
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    user = User(email=email)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'Registration successful!'}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        login_user(user)
        return jsonify({'message': 'Logged in successfully!'}), 200
    
    return jsonify({'error': 'Invalid email or password'}), 400

@app.route('/api/logout')
@login_required
def api_logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully!'}), 200

@app.route('/api/links', methods=['GET', 'POST'])
@login_required
def api_links():
    if request.method == 'POST':
        data = request.get_json()
        original_url = data.get('url')
        if not original_url:
            return jsonify({'error': 'Please enter a URL'}), 400
        
        short_code = shortuuid.uuid()[:6]
        new_link = Link(
            original_url=original_url,
            short_code=short_code
        )
        
        db.session.add(new_link)
        db.session.commit()
        
        return jsonify({'short_code': short_code}), 201
    
    links = Link.query.order_by(Link.created_at.desc()).all()
    return jsonify([{
        'id': link.id,
        'original_url': link.original_url,
        'short_code': link.short_code,
        'clicks': link.clicks,
        'created_at': link.created_at
    } for link in links]), 200

@app.route('/api/links/<short_code>', methods=['GET'])
def api_redirect_to_url(short_code):
    link = Link.query.filter_by(short_code=short_code).first_or_404()
    link.clicks += 1
    db.session.commit()
    return jsonify({
        'original_url': link.original_url,
        'clicks': link.clicks
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create all tables in Supabase
    app.run(debug=True)