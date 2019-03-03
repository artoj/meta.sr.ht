from flask import Blueprint, request, abort
from srht.api import paginated_response
from srht.database import db
from srht.oauth import oauth, current_token
from srht.validation import Validation, valid_url
from metasrht.audit import audit_log
from metasrht.types import AuditLogEntry, SSHKey, PGPKey
from metasrht.webhooks import UserWebhook
from datetime import datetime

user = Blueprint('api.user', __name__)

@user.route("/api/user/profile")
@oauth("profile:read")
def user_profile_GET():
    return current_token.user.to_dict(first_party=current_token.first_party)

@user.route("/api/user/profile", methods=["PUT"])
@oauth("profile:write")
def user_profile_PUT():
    valid = Validation(request)
    user = current_token.user
    user.update(valid, api=True)
    if not valid.ok:
        return valid.response
    db.session.commit()
    return user.to_dict()

@user.route("/api/user/audit-log")
@oauth("audit:read")
def user_audit_log_GET():
    return paginated_response(AuditLogEntry.id, AuditLogEntry.query
            .filter(AuditLogEntry.user_id == current_token.user_id))

@user.route("/api/user/ssh-keys")
@oauth("keys:read")
def user_ssh_keys_GET():
    return paginated_response(SSHKey.id,
            SSHKey.query.filter(SSHKey.user_id == current_token.user_id))

@user.route("/api/user/ssh-keys", methods=["POST"])
@oauth("keys:read")
def user_ssh_keys_POST():
    valid = Validation(request)
    key = SSHKey(current_token.user, valid)
    if not valid.ok:
        return valid.response
    db.session.add(key)
    db.session.commit()
    return key.to_dict(), 201

@user.route("/api/user/ssh-keys/<int:key_id>")
@oauth("keys:read")
def user_ssh_key_by_id_GET(key_id):
    key = (SSHKey.query
            .filter(SSHKey.id == key_id)
            .filter(SSHKey.user_id == current_token.user_id)).one_or_none()
    if not key:
        abort(404)
    return key.to_dict()

@user.route("/api/user/ssh-keys/<int:key_id>", methods=["PUT"])
@oauth("keys:read")
def user_ssh_key_by_id_PUT(key_id):
    key = (SSHKey.query
            .filter(SSHKey.id == key_id)
            .filter(SSHKey.user_id == current_token.user_id)).one_or_none()
    if not key:
        abort(404)
    # This endpoint is only used to update the "last updated" time for this key
    key.last_used = datetime.utcnow()
    db.session.commit()
    return key.to_dict()

@user.route("/api/user/ssh-keys/<int:key_id>", methods=["DELETE"])
@oauth("keys:read")
def user_ssh_key_by_id_DELETE(key_id):
    key = (SSHKey.query
            .filter(SSHKey.id == key_id)
            .filter(SSHKey.user_id == current_token.user_id)).one_or_none()
    if not key:
        abort(404)
    key.delete()
    db.session.commit()
    return {}, 204

@user.route("/api/user/pgp-keys")
@oauth("keys:read")
def user_pgp_keys_GET():
    return paginated_response(PGPKey.id,
            PGPKey.query.filter(PGPKey.user_id == current_token.user_id))

@user.route("/api/user/pgp-keys", methods=["POST"])
@oauth("keys:write")
def user_pgp_keys_POST():
    valid = Validation(request)
    key = PGPKey(current_token.user, valid)
    if not valid.ok:
        return valid.response
    db.session.add(key)
    db.session.commit()
    return key.to_dict(), 201

@user.route("/api/user/pgp-keys/<int:key_id>")
@oauth("keys:read")
def user_pgp_key_by_id(key_id):
    key = (PGPKey.query
            .filter(PGPKey.id == key_id)
            .filter(PGPKey.user_id == current_token.user_id)).one_or_none()
    if not key:
        abort(404)
    return key.to_dict()

@user.route("/api/user/pgp-keys/<int:key_id>", methods=["DELETE"])
@oauth("keys:write")
def user_pgp_key_by_id_DELETE(key_id):
    key = (PGPKey.query
            .filter(PGPKey.id == key_id)
            .filter(PGPKey.user_id == current_token.user_id)).one_or_none()
    if not key:
        abort(404)
    db.session.delete(key)
    db.session.commit()
    return {}, 204

UserWebhook.api_routes(blueprint=user, prefix="/api/user")
