import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load local .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'super_secret_exam_key')

# --- 1. PostgreSQL Database Connection ---
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- 2. Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False) # New field to identify admins

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    username = db.Column(db.String(50))
    action = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))

# Initialize Database and Create Default Admin
with app.app_context():
    try:
        db.create_all()
        admin_user = os.environ.get('ADMIN_USER', 'admin')
        admin_pass = os.environ.get('ADMIN_PASS', 'password123')
        
        if not User.query.filter_by(username=admin_user).first():
            new_admin = User(
                username=admin_user, 
                password_hash=generate_password_hash(admin_pass),
                is_admin=True
            )
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

# --- 4. Core Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.is_locked:
            record_activity("INTRUSION ALERT: Locked account access attempt", username)
            flash('Account locked due to multiple failed attempts')
            return render_template('login.html')

        if user and check_password_hash(user.password_hash, password):
            user.failed_attempts = 0
            db.session.commit()
            login_user(user)
            record_activity("LOGIN SUCCESS", username)
            return redirect(url_for('dashboard'))
        else:
            record_activity("FAILED LOGIN ATTEMPT: Incorrect credentials", username if user else "Unknown User")
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
            flash('Invalid credentials')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    record_activity("ACCESSED LIVE CAMERA FEED", current_user.username)
    # Passing current user data to the frontend so you can show/hide admin panels
    return render_template('camera.html', is_admin=current_user.is_admin)

@app.route('/get_logs')
@login_required
def get_logs():
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(50).all()
    output = ""
    for log in logs:
        ph_time = log.timestamp + timedelta(hours=8)
        time_str = ph_time.strftime("%Y-%m-%d %H:%M:%S")
        output += f"[{time_str} UTC+8] {log.username} - {log.action} ({log.ip_address})\n"
    return output if output else "No activity recorded yet."

@app.route('/logout')
@login_required
def logout():
    record_activity("LOGOUT", current_user.username)
    logout_user()
    return redirect(url_for('login'))

# --- 5. Admin Management Routes ---

@app.route('/admin/manage_users', methods=['POST'])
@login_required
def manage_users():
    # Strict check to ensure only the admin can trigger these actions
    if not current_user.is_admin:
        abort(403)
        
    action = request.form.get('action')
    target_username = request.form.get('target_username')

    if action == 'add':
        password = request.form.get('password')
        if User.query.filter_by(username=target_username).first():
            flash("User already exists.")
        else:
            new_user = User(
                username=target_username, 
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            record_activity(f"ADMIN ACTION: Created user {target_username}", current_user.username)
            
    elif action == 'unlock':
        user = User.query.filter_by(username=target_username).first()
        if user:
            user.is_locked = False
            user.failed_attempts = 0
            db.session.commit()
            record_activity(f"ADMIN ACTION: Unlocked user {target_username}", current_user.username)
            
    elif action == 'delete':
        user = User.query.filter_by(username=target_username).first()
        if user and not user.is_admin: # Prevent admin from deleting themselves
            db.session.delete(user)
            db.session.commit()
            record_activity(f"ADMIN ACTION: Deleted user {target_username}", current_user.username)

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
