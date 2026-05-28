import logging
from flask import request
from app.extensions import db
from app.models import AuditLog

logger = logging.getLogger(__name__)


def record_activity(action, user_id=None):
    # ---------------------------------------------------------------
    # FIX: Do NOT silently swallow all exceptions. Log the error so
    # operations teams can detect when audit logging is broken.
    # Also roll back the session on failure to avoid leaving it dirty.
    # ---------------------------------------------------------------
    try:
        new_entry = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=request.remote_addr   # ProxyFix in __init__.py makes this accurate
        )
        db.session.add(new_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error("Failed to record audit log entry — action='%s' user_id=%s error=%s",
                     action, user_id, e)