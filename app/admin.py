import csv
import io
import secrets
import string
import re
from urllib.parse import unquote
from flask import Blueprint, request, redirect, url_for, abort, Response, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from app.extensions import db
from app.models import User, AuditLog, BlockedIP
from app.utils import record_activity

admin_bp = Blueprint('admin', __name__)

def _generate_temp_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def check_admin_payloads():
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
                    return f"Exploit string profile matched inside administration field '{key}'"
    return None

def enforce_ip_ban(reason_str):
    ip = request.remote_addr
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if not BlockedIP.query.filter_by(ip_address=ip).first():
        new_block = BlockedIP(ip_address=ip, reason=f"Privileged Panel Attack: {reason_str}")
        db.session.add(new_block)
        db.session.commit()
        record_activity(f"FIREWALL AUTO-BAN: IP {ip} dropped for admin panel exploit payload injection", current_user.id)

@admin_bp.route('/admin/manage_users', methods=['POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)

    exploit_found = check_admin_payloads()
    if exploit_found:
        enforce_ip_ban(exploit_found)
        return abort(403, description="CRITICAL SECURITY EXCEPTION: Dynamic Exploit Profile Execution Prevented.")

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

    elif action == 'edit_username':
        new_username = request.form.get('new_username', '').strip()
        user = User.query.filter_by(username=target_username).first()
        if user and new_username:
            if User.query.filter_by(username=new_username).first():
                record_activity(f"ADMIN ACTION FAILED: Username {new_username} already exists", current_user.id)
            else:
                old_username = user.username
                user.username = new_username
                db.session.commit()
                record_activity(f"ADMIN ACTION: Renamed user {old_username} to {new_username}", current_user.id)

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
            temp_password = _generate_temp_password()
            user.password_hash = generate_password_hash(temp_password)
            user.totp_secret = None
            user.is_locked = False
            user.failed_attempts = 0
            db.session.commit()
            record_activity(f"ADMIN ACTION: Reset password and 2FA for {target_username}", current_user.id)
            flash(
                f"Temporary password for {target_username}: {temp_password}  "
                f"— Copy it now, it will not be shown again.",
                'warning'
            )
            return redirect(url_for('views.dashboard'))

    elif action == 'delete':
        user = User.query.filter_by(username=target_username).first()
        if user and not user.is_admin:
            db.session.delete(user)
            db.session.commit()
            record_activity(f"ADMIN ACTION: Deleted user {target_username}", current_user.id)

    return redirect(url_for('views.dashboard'))

@admin_bp.route('/admin/manage_firewall', methods=['POST'])
@login_required
def manage_firewall():
    if not current_user.is_admin:
        abort(403)
        
    action = request.form.get('action')
    target_ip = request.form.get('ip_address', '').strip()
    
    if action == 'block':
        reason = request.form.get('reason', 'Suspicious Activity Detected')
        if not BlockedIP.query.filter_by(ip_address=target_ip).first():
            new_block = BlockedIP(ip_address=target_ip, reason=reason)
            db.session.add(new_block)
            db.session.commit()
            record_activity(f"FIREWALL: Blacklisted IP {target_ip} ({reason})", current_user.id)
            
    elif action == 'unblock':
        block_record = BlockedIP.query.filter_by(ip_address=target_ip).first()
        if block_record:
            db.session.delete(block_record)
            db.session.commit()
            record_activity(f"FIREWALL: Removed IP {target_ip} from blacklist", current_user.id)
            
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
