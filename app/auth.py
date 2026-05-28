import io
import pyotp
import qrcode
from base64 import b64encode
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash
from app.extensions import db, limiter
from app.models import User
from app.utils import record_activity

auth_bp = Blueprint('auth', __name__)

TOTP_MAX_ATTEMPTS = 5

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
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
            session['totp_attempts'] = 0
            return redirect(url_for('auth.verify_2fa'))
        else:
            if user:
                record_activity("FAILED LOGIN ATTEMPT: Incorrect credentials", user.id)
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
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

    totp_attempts = session.get('totp_attempts', 0)
    if totp_attempts >= TOTP_MAX_ATTEMPTS:
        session.pop('pre_2fa_user_id', None)
        session.pop('totp_attempts', None)
        if user:
            user.is_locked = True
            db.session.commit()
            record_activity("INTRUSION ALERT: TOTP brute-force lockout triggered", user.id)
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
        if totp.verify(token):
            user.failed_attempts = 0
            db.session.commit()

            pre_2fa_id = session.pop('pre_2fa_user_id', None)
            session.clear()
            session['_fresh'] = True

            login_user(user)
            session.permanent = True
            record_activity("LOGIN SUCCESS", user.id)
            return redirect(url_for('views.dashboard'))
        else:
            session['totp_attempts'] = totp_attempts + 1
            remaining = TOTP_MAX_ATTEMPTS - session['totp_attempts']
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