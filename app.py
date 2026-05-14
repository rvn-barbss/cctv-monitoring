import os
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load local .env file (for your eyes only)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'super_secret_exam_key')

# --- 1. PostgreSQL Database Connection ---
# This links your code to the Railway PostgreSQL database
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- 2. Database Models (The Tables) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    username = db.Column(db.String(50))
    action = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))

# Initialize Database and Create Admin
with app.app_context():
    try:
        db.create_all()
        # Hidden credentials (stored in Railway Variables, not code)
        admin_user = os.environ.get('ADMIN_USER', 'admin')
        admin_pass = os.environ.get('ADMIN_PASS', 'password123')
        
        if not User.query.filter_by(username=admin_user).first():
            new_admin = User(username=admin_user, password_hash=generate_password_hash(admin_pass))
            db.session.add(new_admin)
            db.session.commit()
    except Exception as e:
        print(f"Database Init Error: {e}")

# --- 3. Login Management ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def record_activity(action, username="System"):
    """Saves security logs directly to PostgreSQL"""
    try:
        new_entry = AuditLog(
            username=username, 
            action=action, 
            ip_address=request.remote_addr
        )
        db.session.add(new_entry)
        db.session.commit()
    except Exception: pass

# --- 4. Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        # Intrusion detection: Check if account is locked
        if user and user.is_locked:
            record_activity(f"INTRUSION ALERT: Locked account access attempt", username)
            flash('Account locked due to multiple failed attempts')
            return render_template('login.html')

        if user and check_password_hash(user.password_hash, password):
            user.failed_attempts = 0
            db.session.commit()
            login_user(user)
            record_activity("LOGIN SUCCESS", username)
            return redirect(url_for('dashboard'))
        else:
            # THIS IS YOUR HONEYPOT: Logs every failed attempt to the database
            record_activity(f"FAILED LOGIN ATTEMPT: Incorrect credentials", username if user else "Unknown User")
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
            flash('Invalid credentials')
            
    return render_template('login.html')

@app.route('/get_logs')
@login_required
def get_logs():
    """Fetches the last 50 security events from PostgreSQL for the website tab"""
    logs = AuditLog.query.order_by(AuditLog.id.
