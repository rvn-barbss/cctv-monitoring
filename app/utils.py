from flask import request
from app.extensions import db
from app.models import AuditLog

def get_real_ip():
    # 1. Check Cloudflare's True IP header first
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP').strip()
    # 2. Fallback to standard proxy headers
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    # 3. Fallback to local address
    return request.remote_addr

def record_activity(action, user_id=None, event_code='SYS_EVENT', severity='INFO'):
    ip = get_real_ip()
        
    log = AuditLog(
        user_id=user_id, 
        action=action, 
        ip_address=ip,
        event_code=event_code,
        severity=severity
    )
    db.session.add(log)
    db.session.commit()