from flask import Blueprint, request
from srht.validation import Validation
from metasrht.types import AuditLogEntry, SSHKey, PGPKey, UserType
from metasrht.audit import audit_log
from metasrht.oauth import oauth

api = Blueprint('api', __name__)

@api.route("/api/user/profile")
@oauth("profile:read")
def user_profile_GET(token):
    user = token.user
    return {
        "username": user.username,
        "email": user.email,
        "url": user.url,
        "location": user.location,
        "bio": user.bio,
        "paid": user.user_type in [UserType.active_paying, UserType.active_free, UserType.admin],
    }

@api.route("/api/user/audit-log")
@oauth("audit:read")
def user_audit_log_GET(token):
    start = request.args.get('start') or -1
    records = AuditLogEntry.query.filter(AuditLogEntry.user_id == token.user_id)
    if start != -1:
        records = records.filter(AuditLogEntry.id <= start)
    records = records.order_by(AuditLogEntry.id.desc()).limit(11).all()
    if len(records) != 11:
        next_id = -1
    else:
        next_id = records[-1].id
        records = records[:10]
    return {
        "next": next_id,
        "results": [
            {
                "id": r.id,
                "ip": str(r.ip_address),
                "action": r.event_type,
                "details": r.details,
                "created": r.created,
            } for r in records
        ]
    }

@api.route("/api/user/ssh-keys")
@oauth("keys:read")
def user_ssh_keys_GET(token):
    start = request.args.get('start') or -1
    records = SSHKey.query.filter(SSHKey.user_id == token.user_id)
    if start != -1:
        records = records.filter(SSHKey.id >= start)
    records = records.limit(11).all()
    if len(records) != 11:
        next_id = -1
    else:
        next_id = records[-1].id
        records = records[:10]
    return {
        "next": next_id,
        "results": [
            {
                "id": r.id,
                "key": r.key,
                "fingerprint": r.fingerprint,
                "comment": r.comment,
                "authorized": r.created,
                "last_used": r.last_used,
            } for r in records
        ]
    }

@api.route("/api/user/pgp-keys")
@oauth("keys:read")
def user_pgp_keys_GET(token):
    start = request.args.get('start') or -1
    records = PGPKey.query.filter(PGPKey.user_id == token.user_id)
    if start != -1:
        records = records.filter(PGPKey.id >= start)
    records = records.limit(11).all()
    if len(records) != 11:
        next_id = -1
    else:
        next_id = records[-1].id
        records = records[:10]
    return {
        "next": next_id,
        "results": [
            {
                "id": r.id,
                "key": r.key,
                "key_id": r.key_id,
                "email": r.email,
                "authorized": r.created,
            } for r in records
        ]
    }

@api.route("/api/ssh-key/<path:keyid>")
def ssh_key_get(keyid):
    key = SSHKey.query.filter(SSHKey.key.ilike("%" + keyid + "%"))
    if key.count() != 1:
        abort(404)
    key = key.first()
    return {
        "key": key.key,
        "fingerprint": key.fingerprint,
        "user": {
            "username": key.user.username
        }
    }
