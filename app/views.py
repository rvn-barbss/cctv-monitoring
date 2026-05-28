import os
from datetime import timedelta
from flask import Blueprint, render_template, redirect, url_for, session, abort, Response
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
    if not session.get('camera_logged'):
        record_activity("ACCESSED LIVE CAMERA FEED", current_user.id)
        session['camera_logged'] = True

    all_users = User.query.all() if current_user.is_admin else []
    
    # Restored the hardware bridge variable
    cam_url = os.environ.get('CAM_URL', '') 
    
    return render_template('camera.html', is_admin=current_user.is_admin, all_users=all_users, cam_url=cam_url)

@views_bp.route('/get_logs')
@login_required
def get_logs():
    if not current_user.is_admin:
        abort(403)

    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(50).all()
    lines = []
    for log in logs:
        ph_time = log.timestamp + timedelta(hours=8)
        time_str = ph_time.strftime("%Y-%m-%d %H:%M:%S")
        username = (log.user.username if log.user else "Unknown").replace('<', '&lt;').replace('>', '&gt;')
        action = log.action.replace('<', '&lt;').replace('>', '&gt;')
        ip = (log.ip_address or "").replace('<', '&lt;').replace('>', '&gt;')
        lines.append(f"[{time_str} UTC+8] {username} - {action} ({ip})")

    output = "\n".join(lines) if lines else "No activity recorded yet."
    return Response(output, mimetype='text/plain')