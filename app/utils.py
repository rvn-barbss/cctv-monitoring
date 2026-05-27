from flask import request
from app.extensions import db
from app.models import AuditLog

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