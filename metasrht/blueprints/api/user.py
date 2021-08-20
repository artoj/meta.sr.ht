from flask import Blueprint, request, abort
from srht.api import paginated_response
from srht.database import db
from srht.graphql import exec_gql
from srht.oauth import oauth, current_token
from srht.validation import Validation
from metasrht.types import AuditLogEntry, SSHKey, PGPKey
from metasrht.webhooks import UserWebhook
from datetime import datetime

user = Blueprint('api_user', __name__)

@user.route("/api/user/profile")
@oauth("profile:read")
def user_profile_GET():
    return current_token.user.to_dict(first_party=current_token.first_party)

@user.route("/api/user/profile", methods=["PUT"])
@oauth("profile:write")
def user_profile_PUT():
    valid = Validation(request)
    user = current_token.user
    # TODO: Fetch user's preferred PGP key (not supported by GQL)
    resp = exec_gql("meta.sr.ht", """
        mutation UpdateProfile($input: UserInput!) {
            updateUser(input: $input) {
                canonicalName
                name: username
                email
                url
                location
                bio
            }
        }
    """, user=user, valid=valid, input=valid.source)
    if not valid.ok:
        return valid.response
    return resp["updateUser"]

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
@oauth("keys:write")
def user_ssh_keys_POST():
    valid = Validation(request)
    user = current_token.user
    key = valid.require("ssh-key")
    if not valid.ok:
        return valid.response
    resp = exec_gql("meta.sr.ht", """
        mutation CreateSSHKey($key: String!) {
            key: createSSHKey(key: $key) {
                id
                authorized: created
                comment
                fingerprint
                key
                owner: user {
                    canonicalName
                    name: username
                }
                last_used: lastUsed
            }
        }
    """, user=user, valid=valid, key=key)
    if not valid.ok:
        return valid.response
    return resp["key"]

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
@oauth("keys:write")
def user_ssh_key_by_id_DELETE(key_id):
    user = current_token.user
    resp = exec_gql("meta.sr.ht", """
        mutation DeleteSSHKey($key_id: Int!) {
            deleteSSHKey(id: $key_id) { id }
        }
    """, user=user, key_id=key_id)
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
    user = current_token.user
    key = valid.require("pgp-key")
    if not valid.ok:
        return valid.response
    resp = exec_gql("meta.sr.ht", """
        mutation CreatePGPKey($key: String!) {
            key: createPGPKey(key: $key) {
                id
                key
                key_id: fingerprint
                authorized: created
                owner: user {
                    canonicalName
                    name: username
                }
            }
        }
    """, user=user, valid=valid, key=key)
    if not valid.ok:
        return valid.response
    resp["key"]["email"] = "this_API_field_is_deprecated__parse_the_key_instead@example.org"
    return resp["key"]

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
    user = current_token.user
    resp = exec_gql("meta.sr.ht", """
        mutation DeletePGPKey($key_id: Int!) {
            deletePGPKey(id: $key_id) { id }
        }
    """, user=user, key_id=key_id)
    return {}, 204

UserWebhook.api_routes(blueprint=user, prefix="/api/user")
