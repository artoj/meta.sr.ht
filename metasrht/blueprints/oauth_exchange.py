from flask import Blueprint, render_template, request, redirect
from datetime import datetime, timedelta
from metasrht.types import OAuthClient, OAuthToken, User, RevocationUrl
from metasrht.audit import audit_log
from metasrht.oauth import OAuthScope
from srht.database import db
from srht.flask import csrf_bypass
from srht.oauth import current_user, loginrequired
from srht.redis import redis
from srht.validation import Validation
import os
import json
import hashlib
import urllib

oauth_exchange = Blueprint('oauth_exchange', __name__)

def _oauth_redirect(redirect_uri, **params):
    parts = list(urllib.parse.urlparse(redirect_uri))
    parsed = urllib.parse.parse_qs(parts[4])
    parsed.update(params)
    parts[4] = urllib.parse.urlencode(parsed)
    return redirect(urllib.parse.urlunparse(parts))

def _oauth_exchange(client, scopes, state, redirect_uri):
    token = hashlib.sha512(os.urandom(8)).hexdigest()[:12]
    scopes = ','.join([str(s) for s in scopes])
    stash = {
        "user_id": current_user.id,
        "client_id": client.id,
        "scopes": scopes
    }
    redis.set(token, json.dumps(stash), ex=(15 * 60))

    redirect_params = {
        "exchange": token,
        "scopes": scopes,
    }
    if state:
        redirect_params["state"] = state

    if redirect_uri == "urn:ietf:wg:oauth:2.0:oob":
        return render_template("oauth-oob.html",
            exchange_token=token), 200

    return _oauth_redirect(redirect_uri, **redirect_params)

@oauth_exchange.route("/oauth/authorize")
@loginrequired
def oauth_authorize_GET():
    client_id = request.args.get('client_id')
    scopes = request.args.get('scopes')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()

    # workaround to enable rfc6749 interoperability
    if not scopes:
        scopes = request.args.get('scope')

    if not client_id or not client:
        return render_template("oauth-error.html",
                details="Unknown client ID"), 400

    if not redirect_uri:
        redirect_uri = client.redirect_uri

    if not client.redirect_uri.startswith(redirect_uri):
        return _oauth_redirect(redirect_uri, error='invalid_redirect',
                details='The URI provided must use be a subpath of your '
                    'configured redirect URI')

    try:
        scopes = set(OAuthScope(s) for s in scopes.split(','))
        if not OAuthScope('profile:read') in scopes:
            scopes.update([OAuthScope('profile:read')])
    except Exception as ex:
        return _oauth_redirect(redirect_uri,
                error='invalid_scope', details=ex.args[0])

    if redirect_uri != "urn:ietf:wg:oauth:2.0:oob":
        previous = (OAuthToken.query\
            .filter(OAuthToken.user_id == current_user.id)
            .filter(OAuthToken.client_id == client.id)
            .filter(OAuthToken.expires > datetime.utcnow())
        ).first()

        if previous:
            if set(previous.scopes) == scopes:
                return _oauth_exchange(client, scopes, state, redirect_uri)
        if client.preauthorized:
            return _oauth_exchange(client, scopes, state, redirect_uri)

    return render_template("oauth-authorize.html",
            client=client, scopes=scopes,
            redirect_uri=redirect_uri, state=state)

@oauth_exchange.route("/oauth/authorize", methods=["POST"])
@loginrequired
def oauth_authorize_POST():
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state')
    client = (OAuthClient.query
        .filter(OAuthClient.client_id == client_id)
    ).one_or_none()

    if not client_id or not client:
        return render_template("oauth-error.html",
                details="Unknown client ID"), 400

    if not redirect_uri:
        redirect_uri = client.redirect_uri

    if not client.redirect_uri.startswith(redirect_uri):
        return _oauth_redirect(redirect_uri,
                error='invalid_redirect',
                details='The URI provided must use be a subpath of your '
                    'configured redirect URI')

    if not "accept" in request.form:
        return _oauth_redirect(redirect_uri, error='user_declined',
                details='User declined to grant access to your application')

    scopes = set()

    for key in request.form:
        if key in [
                "client_id",
                "state",
                "redirect_uri",
                "accept",
                "_csrf_token"
            ]:
            continue
        value = request.form.get(key)
        if not value:
            continue
        try:
            scope = OAuthScope(key)
            scopes.update([str(scope)])
        except Exception as ex:
            return render_template("oauth-error.html", details=str(ex)), 400

    if not OAuthScope('profile:read') in scopes:
        scopes.update([OAuthScope('profile:read')])

    return _oauth_exchange(client, scopes, state, redirect_uri)

@csrf_bypass
@oauth_exchange.route("/oauth/exchange", methods=["POST"])
def oauth_exchange_POST():
    valid = Validation(request)
    client_id = valid.require('client_id')
    client_secret = valid.require('client_secret')
    exchange = valid.require('exchange')
    if not valid.ok:
        return valid.response

    client = (OAuthClient.query
        .filter(OAuthClient.client_id == client_id)).one_or_none()
    valid.expect(client, 'Unknown client ID')
    if not valid.ok:
        return valid.response

    client_secret_hash = hashlib.sha512(client_secret.encode()).hexdigest()
    valid.expect(client_secret_hash == client.client_secret_hash,
            'Invalid client secret')
    if not valid.ok:
        return valid.response

    stash = redis.get(exchange)
    valid.expect(stash, 'Exchange token expired')
    if not valid.ok:
        return valid.response

    stash = json.loads(stash.decode())
    redis.delete(exchange)

    user = stash.get('user_id')
    scopes = stash.get('scopes')
    user = User.query.filter(User.id == user).first()
    valid.expect(user, "Unknown user ID stored for "
        "this exchange token (this isn't supposed to happen")
    if not valid.ok:
        return valid.response

    previous = (OAuthToken.query
        .filter(OAuthToken.user_id == user.id)
        .filter(OAuthToken.client_id == client.id)
    ).one_or_none()
    if not previous:
        oauth_token = OAuthToken(user, client)
    else:
        oauth_token = previous
        previous.expires = datetime.utcnow() + timedelta(days=365)

    oauth_token.scopes = [OAuthScope(s) for s in scopes.split(",")]
    token = oauth_token.gen_token()
    if not client.preauthorized:
        audit_log("oauth token issued",
                "issued oauth token {} to client {}".format(
                    oauth_token.token_partial, client.client_id), user=user)
    if not previous:
        db.session.add(oauth_token)
    db.session.commit()

    return {
        "token": token,
        "expires": oauth_token.expires
    }

@csrf_bypass
@oauth_exchange.route("/oauth/token/<token>", methods=["POST"])
def oauth_token_legacy_POST(token):
    # TODO: Remove this once deployments are complete
    valid = Validation(request)
    client_id = valid.require("client_id")
    client_secret = valid.require("client_secret")
    revocation_url = valid.require("revocation_url")
    if not valid.ok:
        return valid.response

    client = (OAuthClient.query
        .filter(OAuthClient.client_id == client_id)
    ).one_or_none()
    if not client:
        return { "errors": [ { "reason": "404 not found" } ] }, 404

    client_secret_hash = hashlib.sha512(client_secret.encode()).hexdigest()
    valid.expect(client_secret_hash == client.client_secret_hash,
            "Invalid client secret")
    if not valid.ok:
        return valid.response

    h = hashlib.sha512(token.encode()).hexdigest()
    oauth_token = (OAuthToken.query
        .filter(OAuthToken.token_hash == h)
    ).one_or_none()
    valid.expect(oauth_token is not None
            and oauth_token.expires > datetime.utcnow(),
            "Invalid or expired OAuth token")
    if not valid.ok:
        return valid.response

    rev = (RevocationUrl.query
            .filter(RevocationUrl.token_id == oauth_token.id)
            .filter(RevocationUrl.client_id == client.id)).first()
    if not rev:
        rev = RevocationUrl(client, oauth_token, revocation_url)
        db.session.add(rev)
    else:
        rev.url = revocation_url
    db.session.commit()

    if oauth_token._scopes == "*":
        return { "expires": oauth_token.expires, "scopes": "*" }

    scopes = [
        str(s) for s in oauth_token.scopes
        if (s.client_id and s.client_id == client.client_id)
            or s == OAuthScope("profile:read")
    ]
    valid.expect(any(scopes), "Invalid or expired OAuth token")
    if not valid.ok:
        return valid.response

    scopes = ",".join(scopes)

    return {
        "expires": oauth_token.expires,
        "scopes": ",".join(str(s) for s in oauth_token.scopes)
    }

@csrf_bypass
@oauth_exchange.route("/oauth/token/verify", methods=["POST"])
def oauth_token_POST():
    valid = Validation(request)
    token = valid.require("oauth_token")
    client_id = valid.require("client_id")
    client_secret = valid.require("client_secret")
    revocation_url = valid.require("revocation_url")
    if not valid.ok:
        return valid.response

    client = (OAuthClient.query
        .filter(OAuthClient.client_id == client_id)
    ).one_or_none()
    if not client:
        return { "errors": [ { "reason": "404 not found" } ] }, 404

    client_secret_hash = hashlib.sha512(client_secret.encode()).hexdigest()
    valid.expect(client_secret_hash == client.client_secret_hash,
            "Invalid client secret")
    if not valid.ok:
        return valid.response

    h = hashlib.sha512(token.encode()).hexdigest()
    oauth_token = (OAuthToken.query
        .filter(OAuthToken.token_hash == h)
    ).one_or_none()
    valid.expect(oauth_token is not None
            and oauth_token.expires > datetime.utcnow(),
            "Invalid or expired OAuth token")
    if not valid.ok:
        return valid.response

    rev = (RevocationUrl.query
            .filter(RevocationUrl.token_id == oauth_token.id)
            .filter(RevocationUrl.client_id == client.id)).first()
    if not rev:
        rev = RevocationUrl(client, oauth_token, revocation_url)
        db.session.add(rev)
    else:
        rev.url = revocation_url
    db.session.commit()

    if oauth_token._scopes == "*":
        return { "expires": oauth_token.expires, "scopes": "*" }

    scopes = [
        str(s) for s in oauth_token.scopes
        if (s.client_id and s.client_id == client.client_id)
            or s == OAuthScope("profile:read")
    ]
    valid.expect(any(scopes), "Invalid or expired OAuth token")
    if not valid.ok:
        return valid.response

    scopes = ",".join(scopes)

    return {
        "expires": oauth_token.expires,
        "scopes": ",".join(str(s) for s in oauth_token.scopes)
    }
