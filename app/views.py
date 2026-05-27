from datetime import timedelta
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app.models import User, AuditLog
from app.utils import record_activity

views_bp = Blueprint('views', __name__)

@views_bp.route('/')
def index():
    return redirect(url_for('auth.login'))

@views_bp.route('/dashboard')
@login_required
def dashboard():
    record_activity("ACCESSED LIVE CAMERA FEED", current_user.id)
    all_users = User.query.all() if current_user.is_admin else []
    return render_template('camera.html', is_admin=current_user.is_admin, all_users=all_users)

@views_bp.route('/get_logs')
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