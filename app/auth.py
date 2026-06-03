import io
import os
import pyotp
import qrcode
import requests
import re
from urllib.parse import unquote
from base64 import b64encode
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash
from app.extensions import db, limiter
from app.models import User, BlockedIP
from app.utils import record_activity

auth_bp = Blueprint('auth', __name__)

TOTP_MAX_ATTEMPTS = 5
MAX_IP_STRIKES = 10

def get_client_ip():
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP').strip()
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def add_ip_strike(custom_reason=None, force_ban=False):
    ip = get_client_ip()
    strikes = session.get('ip_strikes', 0) + 1 if not force_ban else MAX_IP_STRIKES
    session['ip_strikes'] = strikes
    
    if strikes >= MAX_IP_STRIKES or force_ban:
        reason_text = custom_reason if custom_reason else f"Auto-banned: {MAX_IP_STRIKES} failed login attempts"
        if not BlockedIP.query.filter_by(ip_address=ip).first():
            new_block = BlockedIP(ip_address=ip, reason=reason_text)
            db.session.add(new_block)
            db.session.commit()
            record_activity(f"FIREWALL AUTO-BAN: IP {ip} dropped. Reason: {reason_text}", None)
        return True
    return False

def detect_suspicious_payloads():
    patterns = [
        r"(?i)(union\s+select|select\s+\*|drop\s+table|insert\s+into)",
        r"(?i)(<script>|javascript:|onerror=|onload=)",
        r"(\.\./|\.\.\\|/etc/passwd|/bin/sh)",
        r"(?i)(--|#|\/\*).*"
    ]
    
    for key, value in request.form.items():
        if value:
            decoded_val = unquote(value)
            for pattern in patterns:
                if re.search(pattern, decoded_val):
                    return f"Payload matched threat signature in field '{key}'"
    return None

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        malicious_reason = detect_suspicious_payloads()
        if malicious_reason:
            record_activity(f"ATTACK DETECTED: {malicious_reason}", None)
            add_ip_strike(custom_reason=f"Auto-banned: Cyber Attack Attempt ({malicious_reason})", force_ban=True)
            return abort(403, description="ERR_ACCESS_DENIED: Critical security violation detected. Your IP has been banned.")

        turnstile_response = request.form.get('cf-turnstile-response')
        turnstile_secret = os.environ.get('TURNSTILE_SECRET')
        
        if turnstile_secret:
            verify_url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
            data = {
                'secret': turnstile_secret,
                'response': turnstile_response,
                'remoteip': get_client_ip()
            }
            resp = requests.post(verify_url, data=data).json()
            
            if not resp.get('success'):
                record_activity("FAILED LOGIN ATTEMPT: CAPTCHA validation failed", None)
                flash('Security validation failed.', 'error')
                return render_template('login.html')

        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.is_locked:
            record_activity("INTRUSION ALERT: Locked account access attempt", user.id)
            add_ip_strike()
            flash('Account locked due to multiple failed attempts', 'error')
            return render_template('login.html')

        if user and check_password_hash(user.password_hash, password):
            session['pre_2fa_user_id'] = user.id
            session['totp_attempts'] = 0
            session['ip_strikes'] = 0
            return redirect(url_for('auth.verify_2fa'))
        else:
            if user:
                record_activity("FAILED LOGIN ATTEMPT: Incorrect credentials", user.id)
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
            else:
                record_activity(f"FAILED LOGIN: Unknown user '{username}'", None)
            
            was_banned = add_ip_strike()
            if was_banned:
                return abort(403, description="ERR_ACCESS_DENIED: Your IP address has been permanently blacklisted due to brute-force detection.")
                
            flash('Invalid credentials', 'error')
            return render_template('login.html')
            
    return render_template('login.html')

@auth_bp.route('/forgot_password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    if user:
        record_activity("PASSWORD RESET REQUESTED", user.id)
    flash('If that account exists, a reset request has been sent to the Master Admin.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/verify_2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_2fa():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('auth.login'))

    user = User.query.get(session['pre_2fa_user_id'])
    
    if not user:
        session.pop('pre_2fa_user_id', None)
        return redirect(url_for('auth.login'))

    totp_attempts = session.get('totp_attempts', 0)
    if totp_attempts >= TOTP_MAX_ATTEMPTS:
        session.pop('pre_2fa_user_id', None)
        session.pop('totp_attempts', None)
        user.is_locked = True
        db.session.commit()
        record_activity("INTRUSION ALERT: TOTP brute-force lockout triggered", user.id)
        
        was_banned = add_ip_strike()
        if was_banned:
            return abort(403, description="ERR_ACCESS_DENIED: Your IP address has been permanently blacklisted due to brute-force detection.")
            
        flash('Too many failed 2FA attempts. Account locked.', 'error')
        return redirect(url_for('auth.login'))

    is_first_time = False
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()
        is_first_time = True

    totp = pyotp.TOTP(user.totp_secret)

    if request.method == 'POST':
        token = request.form.get('token')
        if totp.verify(token, valid_window=1):
            user.failed_attempts = 0
            db.session.commit()
            session.pop('pre_2fa_user_id', None)
            session.clear()
            session['_fresh'] = True
            login_user(user)
            session.permanent = True
            record_activity("LOGIN SUCCESS", user.id)
            return redirect(url_for('views.dashboard'))
        else:
            session['totp_attempts'] = totp_attempts + 1
            remaining = TOTP_MAX_ATTEMPTS - session['totp_attempts']
            record_activity("FAILED 2FA ATTEMPT", user.id)
            add_ip_strike()
            flash(f'Invalid Authenticator Code. {remaining} attempt(s) remaining.', 'error')

    qr_b64 = None
    if is_first_time:
        provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="CCTV System")
        qr = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = b64encode(buf.getvalue()).decode('utf-8')

    return render_template('2fa.html', qr_b64=qr_b64, is_first_time=is_first_time)

@auth_bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        record_activity("LOGOUT", current_user.id)
    session.pop('camera_logged', None)
    logout_user()
    return redirect(url_for('auth.login'))
