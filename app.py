import os
import csv
import io
import pyotp
import qrcode
from base64 import b64encode
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort, Response, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'super_secret_exam_key')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    logs = db.relationship('AuditLog', backref='user', lazy=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def record_activity(action, user_id=None):
    try:
        new_entry = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=request.remote_addr
        )
        db.session.add(new_entry)
        db.session.commit()
    except Exception:
        pass

with app.app_context():
    try:
        db.create_all()
        try:
            db.session.execute(text('SELECT is_admin FROM "user" LIMIT 1'))
        except Exception:
            db.session.rollback()
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN DEFAULT FALSE'))
            db.session.commit()
        
        try:
            db.session.execute(text('SELECT totp_secret FROM "user" LIMIT 1'))
        except Exception:
            db.session.rollback()
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN totp_secret VARCHAR(32)'))
            db.session.commit()

        admin_user = os.environ.get('ADMIN_USER', 'admin')
        admin_pass = os.environ.get('ADMIN_PASS', 'password123')
        
        master_admin = User.query.filter_by(username=admin_user).first()
        
        if not master_admin:
            new_admin = User(
                username=admin_user, 
                password_hash=generate_password_hash(admin_pass),
                is_admin=True
            )
            db.session.add(new_admin)
        else:
            master_admin.is_admin = True
            
        db.session.commit()
    except Exception:
        pass

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
            record_activity("INTRUSION ALERT: Locked account access attempt", user.id)
            flash('Account locked due to multiple failed attempts')
            return render_template('login.html')

        if user and check_password_hash(user.password_hash, password):
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('verify_2fa'))
        else:
            if user:
                record_activity("FAILED LOGIN ATTEMPT: Incorrect credentials", user.id)
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
            flash('Invalid credentials')
            
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['pre_2fa_user_id'])
    is_first_time = False
    
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()
        is_first_time = True
        
    totp = pyotp.TOTP(user.totp_secret)
    
    if request.method == 'POST':
        token = request.form.get('token')
        if totp.verify(token):
            user.failed_attempts = 0
            db.session.commit()
            login_user(user)
            session.permanent = True
            session.pop('pre_2fa_user_id', None)
            record_activity("LOGIN SUCCESS", user.id)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Authenticator Code')
            
    qr_b64 = None
    if is_first_time:
        provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="CCTV System")
        qr = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('2fa.html', qr_b64=qr_b64, is_first_time=is_first_time)

@app.route('/get_logs')
@login_required
def get_logs():
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(50).all()
    output = ""
    for log in logs:
        ph_time = log.timestamp + timedelta(hours=8)
        time_str = ph_time.strftime("%Y-%m-%d %H:%M:%S")
        username = log.user.username if log.user else "Unknown"
        output += f"[{time_str} UTC+8] {username} - {log.action} ({log.ip_address})\n"
    return output if output else "No activity recorded yet."

@app.route('/dashboard')
@login_required
def dashboard():
    record_activity("ACCESSED LIVE CAMERA FEED", current_user.id)
    all_users = User.query.all() if current_user.is_admin else []
    return render_template('camera.html', is_admin=current_user.is_admin, all_users=all_users)

@app.route('/logout')
@login_required
def logout():
    record_activity("LOGOUT", current_user.id)
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/manage_users', methods=['POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)
        
    action = request.form.get('action')
    target_username = request.form.get('target_username')

    if action == 'add':
        password = request.form.get('password')
        if User.query.filter_by(username=target_username).first():
            record_activity(f"ADMIN ACTION FAILED: Attempted to create duplicate user {target_username}", current_user.id)
        else:
            new_user = User(
                username=target_username, 
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            record_activity(f"ADMIN ACTION: Created user {target_username}", current_user.id)
            
    elif action == 'unlock':
        user = User.query.filter_by(username=target_username).first()
        if user:
            user.is_locked = False
            user.failed_attempts = 0
            db.session.commit()
            record_activity(f"ADMIN ACTION: Unlocked user {target_username}", current_user.id)
            
    elif action == 'delete':
        user = User.query.filter_by(username=target_username).first()
        if user and not user.is_admin:
            db.session.delete(user)
            db.session.commit()
            record_activity(f"ADMIN ACTION: Deleted user {target_username}", current_user.id)

    return redirect(url_for('dashboard'))

@app.route('/admin/export_logs')
@login_required
def export_logs():
    if not current_user.is_admin:
        abort(403)
        
    logs = AuditLog.query.order_by(AuditLog.id.desc()).all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Time (UTC)', 'Username', 'Action', 'IP Address'])
    for log in logs:
        username = log.user.username if log.user else "Unknown"
        cw.writerow([log.timestamp, username, log.action, log.ip_address])
        
    output = si.getvalue()
    record_activity("ADMIN ACTION: Exported logs to CSV", current_user.id)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=cctv_security_logs.csv"}
    )