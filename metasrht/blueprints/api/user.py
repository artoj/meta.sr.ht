from flask import Blueprint
from srht.api import paginated_response
from srht.database import db
from srht.oauth import oauth, current_token
from metasrht.types import AuditLogEntry, SSHKey, PGPKey
from metasrht.webhooks import UserWebhook

user = Blueprint('api.user', __name__)

@user.route("/api/user/profile")
@oauth("profile:read")
def user_profile_GET():
    return current_token.user.to_dict(first_party=current_token.first_party)

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

@user.route("/api/user/pgp-keys")
@oauth("keys:read")
def user_pgp_keys_GET():
    return paginated_response(PGPKey.id,
            PGPKey.query.filter(PGPKey.user_id == current_token.user_id))

UserWebhook.api_routes(blueprint=user, prefix="/api/user")
