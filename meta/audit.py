from flask import request
from flask_login import current_user
from ipaddress import ip_address
from meta.types import AuditLogEntry, EventType
from meta.db import db

def audit_log(event_type, details=None):
    if not current_user:
        return
    event = AuditLogEntry(current_user.id,
        event_type, ip_address(request.remote_addr),
        details)
    db.add(event)
