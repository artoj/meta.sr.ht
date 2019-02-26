from flask import Blueprint, request
from srht.api import paginated_response
from srht.database import db
from srht.oauth import oauth, current_token
from srht.validation import Validation, valid_url
from metasrht.audit import audit_log
from metasrht.types import AuditLogEntry, SSHKey, PGPKey
from metasrht.webhooks import UserWebhook

user = Blueprint('api.user', __name__)

@user.route("/api/user/profile")
@oauth("profile:read")
def user_profile_GET():
    return current_token.user.to_dict(first_party=current_token.first_party)

@user.route("/api/user/profile", methods=["PUT"])
@oauth("profile:write")
def user_profile_PUT():
    valid = Validation(request)

    # TODO: Change email via API
    user = current_token.user
    url = valid.optional("url", user.url)
    location = valid.optional("location", user.location)
    bio = valid.optional("bio", user.bio)

    valid.expect(not url or 0 <= len(url) <= 256,
            "URL must fewer than 256 characters.", "url")
    valid.expect(not url or valid_url(url),
            "URL must be a valid http or https URL", "url")
    valid.expect(not location or 0 <= len(location) <= 256,
            "Location must fewer than 256 characters.", "location")
    valid.expect(not bio or 0 <= len(bio) <= 4096,
            "Bio must fewer than 4096 characters.", "bio")

    if not valid.ok:
        return valid.response

    user.url = url
    user.location = location
    user.bio = bio

    audit_log("updated profile (via API)")
    db.session.commit()
    UserWebhook.deliver(UserWebhook.Events.profile_update, user.to_dict(),
            UserWebhook.Subscription.user_id == user.id)

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

@user.route("/api/user/pgp-keys")
@oauth("keys:read")
def user_pgp_keys_GET():
    return paginated_response(PGPKey.id,
            PGPKey.query.filter(PGPKey.user_id == current_token.user_id))

UserWebhook.api_routes(blueprint=user, prefix="/api/user")
