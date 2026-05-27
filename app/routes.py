import os
import csv
import io
import pyotp
import qrcode
from base64 import b64encode
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, Response, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from app.models import User, AuditLog

main_bp = Blueprint('main', __name__)

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

@main_bp.route('/')
def index():
    return redirect(url_for('main.login'))

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.is_locked:
            record_activity("INTRUSION ALERT: Locked account access attempt", user.id)
            flash('Account locked due to multiple failed attempts', 'error')
            return render_template('login.html')

        if user and check_password_hash(user.password_hash, password):
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('main.verify_2fa'))
        else:
            if user:
                record_activity("FAILED LOGIN ATTEMPT: Incorrect credentials", user.id)
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
            flash('Invalid credentials', 'error')
            
    return render_template('login.html')

@main_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    if user:
        record_activity("PASSWORD RESET REQUESTED", user.id)
    flash('If that account exists, a reset request has been sent to the Master Admin.', 'success')
    return redirect(url_for('main.login'))

@main_bp.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('main.login'))
        
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
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid Authenticator Code', 'error')
            
    qr_b64 = None
    if is_first_time:
        provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="CCTV System")
        qr = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('2fa.html', qr_b64=qr_b64, is_first_time=is_first_time)

@main_bp.route('/get_logs')
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

@main_bp.route('/dashboard')
@login_required
def dashboard():
    record_activity("ACCESSED LIVE CAMERA FEED", current_user.id)
    all_users = User.query.all() if current_user.is_admin else []
    return render_template('camera.html', is_admin=current_user.is_admin, all_users=all_users)

@main_bp.route('/logout')
@login_required
def logout():
    record_activity("LOGOUT", current_user.id)
    logout_user()
    return redirect(url_for('main.login'))

@main_bp.route('/admin/manage_users', methods=['POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)
        
    action = request.form.get('action')
    target_username = request.form.get('target_username')

    if action == 'add':
        password = request.form.get('password')
        role = request.form.get('role')
        is_admin_role = True if role == 'admin' else False
        
        if User.query.filter_by(username=target_username).first():
            record_activity(f"ADMIN ACTION FAILED: Attempted to create duplicate user {target_username}", current_user.id)
        else:
            new_user = User(
                username=target_username, 
                password_hash=generate_password_hash(password),
                is_admin=is_admin_role
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
            
    elif action == 'reset':
        user = User.query.filter_by(username=target_username).first()
        if user:
            user.password_hash = generate_password_hash('default123')
            user.totp_secret = None
            user.is_locked = False
            user.failed_attempts = 0
            db.session.commit()
            record_activity(f"ADMIN ACTION: Reset password and 2FA for {target_username}", current_user.id)
            
    elif action == 'delete':
        user = User.query.filter_by(username=target_username).first()
        if user and not user.is_admin:
            db.session.delete(user)
            db.session.commit()
            record_activity(f"ADMIN ACTION: Deleted user {target_username}", current_user.id)

    return redirect(url_for('main.dashboard'))

@main_bp.route('/admin/export_logs')
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