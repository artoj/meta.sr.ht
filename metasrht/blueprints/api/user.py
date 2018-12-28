from flask import Blueprint, request
from srht.api import paginated_response
from srht.oauth import oauth
from metasrht.types import AuditLogEntry, SSHKey, PGPKey

user = Blueprint('api.user', __name__)

@user.route("/api/user/profile")
@oauth("profile:read")
def user_profile_GET(token):
    return token.user.to_dict(first_party=token.first_party)

@user.route("/api/user/audit-log")
@oauth("audit:read")
def user_audit_log_GET(token):
    return paginated_response(AuditLogEntry.id,
            AuditLogEntry.query.filter(AuditLogEntry.user_id == token.user_id))

@user.route("/api/user/ssh-keys")
@oauth("keys:read")
def user_ssh_keys_GET(token):
    return paginated_response(SSHKey.id,
            SSHKey.query.filter(SSHKey.user_id == token.user_id))

@user.route("/api/user/pgp-keys")
@oauth("keys:read")
def user_pgp_keys_GET(token):
    return paginated_response(PGPKey.id,
            PGPKey.query.filter(PGPKey.user_id == token.user_id))
