from flask import request
from flask_login import current_user
from ipaddress import ip_address
from datetime import datetime, timedelta
from srht.database import db
from metasrht.types import AuditLogEntry

def audit_log(event_type, details=None, user=None):
    if not user:
        user = current_user
    if not user:
        return
    addr = request.headers.get("X-Real-IP") or request.remote_addr
    event = AuditLogEntry(user.id, event_type, ip_address(addr), details)
    db.session.add(event)

def expire_audit_logs():
    cutoff = datetime.now() - timedelta(days=14)
    AuditLogEntry.query.filter(AuditLogEntry.created <= cutoff) .delete()
    db.session.commit()
