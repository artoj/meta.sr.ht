from datetime import datetime, timedelta
from flask import request
from ipaddress import ip_address
from metasrht.email import send_email
from metasrht.types import AuditLogEntry
from srht.config import cfg
from srht.database import db
from srht.oauth import current_user

def audit_log(event_type, details=None, user=None,
        email=False, subject=None, email_details=None):
    if not user:
        user = current_user
    if not user:
        return
    addr = request.access_route[-1]
    event = AuditLogEntry(user.id, event_type, ip_address(addr), details)
    db.session.add(event)
    if email:
        if user.pgp_key:
            encrypt_key = user.pgp_key.key
        else:
            encrypt_key = None
        send_email("audit_event", user.email, subject, headers={
            "From": f"{cfg('mail', 'smtp-from')}",
            "To": f"{user.username} <{user.email}>",
            "Reply-To": f"{cfg('sr.ht', 'owner-name')} <{cfg('sr.ht', 'owner-email')}>",
        }, user=user, encrypt_key=encrypt_key, email_details=email_details)

def expire_audit_logs():
    cutoff = datetime.now() - timedelta(days=14)
    AuditLogEntry.query.filter(AuditLogEntry.created <= cutoff) .delete()
    db.session.commit()
