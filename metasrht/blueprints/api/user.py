from flask import Blueprint, request
from srht.api import paginated_response
from srht.database import db
from srht.oauth import oauth, current_token
from srht.validation import Validation
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

@user.route("/api/user/webhooks")
@oauth(None)
def user_webhooks_GET():
    query = (UserWebhook.Subscription.query
        .filter(UserWebhook.Subscription.client_id == current_token.client_id)
        .filter(UserWebhook.Subscription.user_id == current_token.user_id))
    return paginated_response(UserWebhook.Subscription.id, query)

@user.route("/api/user/webhooks", methods=["POST"])
@oauth(None)
def user_webhooks_POST():
    valid = Validation(request)
    sub = UserWebhook.Subscription(valid,
            current_token.client_id, current_token.user_id)
    if not valid.ok:
        return valid.response
    db.session.add(sub)
    db.session.commit()
    return sub.to_dict()
