from flask import Blueprint, request, g, abort
from functools import wraps
from metasrht.types import OAuthClient, OAuthToken, DelegatedScope
from srht.api import paginated_response
from srht.database import db
from srht.validation import Validation
import hashlib
import re

delegate = Blueprint('api.delegate', __name__)

@delegate.before_request
def authorize():
    valid = Validation(request)
    client_id = request.headers.get("X-OAuth-ID")
    client_secret = request.headers.get("X-OAuth-Secret")
    valid.expect(client_id and client_secret,
            "Required X-OAuth-ID and X-OAuth-Secret headers missing")
    if not valid.ok:
        return valid.response

    client = (OAuthClient.query
        .filter(OAuthClient.client_id == client_id).one_or_none())
    valid.expect(client is not None, "Unknown X-OAuth-ID")
    if not valid.ok:
        return valid.response

    client_secret_hash = hashlib.sha512(client_secret.encode()).hexdigest()
    valid.expect(client_secret_hash == client.client_secret_hash,
            "Incorrect X-OAuth-Secret")
    if not valid.ok:
        return valid.response

    valid.expect(client.preauthorized,
            "This feature is only available to first-party OAuth clients")
    if not valid.ok:
        return valid.response

    g.oauth_client = client

@delegate.route("/api/delegate/scopes")
def delegate_scopes_GET():
    return paginated_response(DelegatedScope.id, DelegatedScope.query.filter(
            DelegatedScope.client_id == g.oauth_client.id))

@delegate.route("/api/delegate/scopes", methods=["POST"])
def delegate_scopes_POST():
    valid = Validation(request)
    desc = valid.require("description", cls=str)
    name = valid.require("name", cls=str)
    writable = valid.require("writable", cls=bool)
    valid.expect(not name or re.match(r"^[a-z_]+$", name),
            "Lowercase characters and underscores only", field="name")
    if not valid.ok:
        return valid.response
    scope = (DelegatedScope.query\
        .filter(DelegatedScope.client_id == g.oauth_client.id)
        .filter(DelegatedScope.name == name)).one_or_none()
    valid.expect(scope is None,
            "A scope with this name already exists.", field="name")
    if not valid.ok:
        return valid.response
    scope = DelegatedScope(g.oauth_client, name, desc)
    scope.write = writable
    db.session.add(scope)
    db.session.commit()
    return scope.to_dict()

@delegate.route("/api/delegate/scopes/<int:scope_id>")
def delegate_scopes_id_GET(scope_id):
    scope = (DelegatedScope.query
            .filter(DelegatedScope.id == scope_id)).one_or_none()
    if not scope:
        abort(404)
    if scope.client_id != g.oauth_client.id:
        abort(401)
    return scope.to_dict()

@delegate.route("/api/delegate/scopes/<int:scope_id>", methods=["DELETE"])
def delegate_scopes_id_DELETE(scope_id):
    scope = (DelegatedScope.query
            .filter(DelegatedScope.id == scope_id)).one_or_none()
    if not scope:
        abort(404)
    if scope.client_id != g.oauth_client.id:
        abort(401)
    db.session.delete(scope)
    db.session.commit()
    return {}
