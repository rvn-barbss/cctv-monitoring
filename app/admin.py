import csv
import io
from flask import Blueprint, request, redirect, url_for, abort, Response
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from app.extensions import db
from app.models import User, AuditLog
from app.utils import record_activity

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin/manage_users', methods=['POST'])
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

    return redirect(url_for('views.dashboard'))

@admin_bp.route('/admin/export_logs')
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